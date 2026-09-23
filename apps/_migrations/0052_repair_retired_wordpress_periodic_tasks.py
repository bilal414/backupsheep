"""Repair Beat tasks shared with schedules retired by migration 0047.

Migration 0047 correctly disabled WordPress schedules, but a malformed legacy
database can point a surviving schedule at the same non-unique PeriodicTask FK.
In that case its blanket task disable leaves the surviving schedule row active
while its Beat task is paused.  The published migration may already be applied
and did not retain the task's prior enabled state, so keep it immutable and
never infer that the shared task is safe to resume.  Detach the retired rows,
pause an active surviving owner for explicit operator review, and fail closed
when ownership is ambiguous.
"""

import json

from django.db import migrations, transaction
from django.utils import timezone


ACTIVE = 1
PAUSED = 2
DELETE_REQUESTED = 3
WORDPRESS_CODE = "wordpress"
BACKUP_TASK = "run_scheduled_backup"


def _positive_schedule_id(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value and value == value.strip() and value.isdigit():
        result = int(value)
        return result if result > 0 else None
    return None


def _task_schedule_id(periodic_task):
    """Decode the one schedule identity accepted by the durable scheduler."""

    try:
        args = json.loads(periodic_task.args or "[]")
        kwargs = json.loads(periodic_task.kwargs or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(args, list) or len(args) > 1 or not isinstance(kwargs, dict):
        return None
    if set(kwargs) - {"schedule_id"}:
        return None

    positional = _positive_schedule_id(args[0]) if args else None
    keyword = (
        _positive_schedule_id(kwargs.get("schedule_id"))
        if "schedule_id" in kwargs
        else None
    )
    if positional is None and keyword is None:
        return None
    # A direct Celery invocation would bind schedule_id twice even when the
    # values match. Such a row is not a canonical, safely recoverable owner.
    if positional is not None and keyword is not None:
        return None
    return keyword if keyword is not None else positional


def _canonical_recurring_task(periodic_task, schedule):
    """Return whether a task is the deterministic recurring task for schedule."""

    if periodic_task.task != BACKUP_TASK or periodic_task.one_off:
        return False
    if (
        periodic_task.expires is not None
        or periodic_task.expire_seconds is not None
        or periodic_task.start_time is not None
    ):
        return False
    expected_name = (
        f"bs-s{schedule.pk}-n{schedule.node_id}"
        f"-a{schedule.node.connection.account_id}"
    )
    if periodic_task.name != expected_name:
        return False

    if schedule.type == "cron":
        if (
            periodic_task.crontab_id is None
            or periodic_task.interval_id is not None
            or periodic_task.clocked_id is not None
            or periodic_task.solar_id is not None
        ):
            return False
        crontab = periodic_task.crontab
        expected = (
            schedule.minute or "*",
            schedule.hour or "*",
            schedule.day_of_week or "*",
            schedule.day_of_month or "*",
            schedule.month_of_year or "*",
            schedule.timezone or "UTC",
        )
        actual = (
            crontab.minute,
            crontab.hour,
            crontab.day_of_week,
            crontab.day_of_month,
            crontab.month_of_year,
            str(crontab.timezone),
        )
        return actual == expected

    if schedule.type == "rate":
        if (
            periodic_task.interval_id is None
            or periodic_task.crontab_id is not None
            or periodic_task.clocked_id is not None
            or periodic_task.solar_id is not None
        ):
            return False
        interval = periodic_task.interval
        return (
            interval.every == schedule.rate_value
            and interval.period == schedule.rate_unit
        )

    # A disabled one-off task does not retain enough state to distinguish an
    # exhausted run from one that 0047 interrupted. Never re-enable it here.
    return False


def _refuse_ambiguous_task(periodic_task, retired, surviving, reason):
    retired_ids = [schedule.pk for schedule in retired]
    surviving_ids = [schedule.pk for schedule in surviving]
    raise RuntimeError(
        "Cannot safely repair shared PeriodicTask "
        f"{periodic_task.pk}: {reason}. Retired schedule ids={retired_ids}; "
        f"surviving schedule ids={surviving_ids}. Normalize the schedule/task "
        "ownership before retrying migration 0052."
    )


def repair_retired_wordpress_periodic_tasks(apps, schema_editor):
    CoreSchedule = apps.get_model("apps", "CoreSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTasks = apps.get_model("django_celery_beat", "PeriodicTasks")
    database = schema_editor.connection.alias

    with transaction.atomic(using=database):
        retired_task_ids = list(
            CoreSchedule.objects.using(database)
            .filter(node__connection__integration__code=WORDPRESS_CODE)
            .exclude(celery_periodic_task_id__isnull=True)
            .order_by("celery_periodic_task_id")
            .values_list("celery_periodic_task_id", flat=True)
            .distinct()
        )
        if not retired_task_ids:
            return

        tasks = {
            task.pk: task
            for task in PeriodicTask.objects.using(database)
            .select_for_update()
            .filter(pk__in=retired_task_ids)
            .order_by("pk")
        }
        schedules = list(
            CoreSchedule.objects.using(database)
            .select_related(
                "node__connection__integration",
                "node__connection__account",
            )
            .select_for_update()
            .filter(celery_periodic_task_id__in=tasks)
            .order_by("celery_periodic_task_id", "pk")
        )

        schedules_by_task = {}
        for schedule in schedules:
            schedules_by_task.setdefault(schedule.celery_periodic_task_id, []).append(
                schedule
            )

        # Build and validate every plan before changing any row. Although Django
        # runs migrations atomically on PostgreSQL, this also keeps direct repair
        # invocation all-or-nothing and makes the safety property explicit.
        plans = []
        for task_id in sorted(schedules_by_task):
            linked = schedules_by_task[task_id]
            retired = []
            surviving = []
            for schedule in linked:
                target = (
                    retired
                    if schedule.node.connection.integration.code == WORDPRESS_CODE
                    else surviving
                )
                target.append(schedule)
            if not retired or not surviving:
                continue

            periodic_task = tasks[task_id]
            if len(surviving) != 1:
                _refuse_ambiguous_task(
                    periodic_task,
                    retired,
                    surviving,
                    "more than one surviving schedule references the task",
                )
            owner = surviving[0]
            if _task_schedule_id(periodic_task) != owner.pk:
                _refuse_ambiguous_task(
                    periodic_task,
                    retired,
                    surviving,
                    "the durable task payload does not identify its surviving owner",
                )
            if not _canonical_recurring_task(periodic_task, owner):
                _refuse_ambiguous_task(
                    periodic_task,
                    retired,
                    surviving,
                    "the task is one-off, expired, delayed, or non-canonical",
                )
            if owner.status not in {ACTIVE, PAUSED, DELETE_REQUESTED}:
                _refuse_ambiguous_task(
                    periodic_task,
                    retired,
                    surviving,
                    f"the surviving schedule has unknown status {owner.status!r}",
                )
            plans.append((periodic_task, retired, owner))

        changed_at = timezone.now()
        for periodic_task, retired, owner in plans:
            if owner.status == ACTIVE:
                paused = (
                    CoreSchedule.objects.using(database)
                    .filter(
                        pk=owner.pk,
                        status=ACTIVE,
                        celery_periodic_task_id=periodic_task.pk,
                    )
                    .update(status=PAUSED, modified=changed_at)
                )
                if paused != 1:
                    raise RuntimeError(
                        "Surviving PeriodicTask ownership changed while migration "
                        "0052 held its repair locks."
                    )
            retired_ids = [schedule.pk for schedule in retired]
            detached = (
                CoreSchedule.objects.using(database)
                .filter(
                    pk__in=retired_ids,
                    celery_periodic_task_id=periodic_task.pk,
                )
                .update(
                    status=PAUSED,
                    celery_periodic_task_id=None,
                    modified=changed_at,
                )
            )
            if detached != len(retired_ids):
                raise RuntimeError(
                    "Shared PeriodicTask ownership changed while migration 0052 "
                    "held its repair locks."
                )
            # Migration 0047 did not retain the pre-retirement enabled value.
            # Keeping the shared task disabled is the only provenance-safe state;
            # an operator can explicitly resume the now-unshared schedule later.
            if periodic_task.enabled:
                updated = (
                    PeriodicTask.objects.using(database)
                    .filter(pk=periodic_task.pk, enabled=periodic_task.enabled)
                    .update(enabled=False, date_changed=changed_at)
                )
                if updated != 1:
                    raise RuntimeError(
                        "PeriodicTask state changed while migration 0052 held its "
                        "repair locks."
                    )

        # Historical migration models do not carry django-celery-beat's custom
        # save() hook, and 0047 used QuerySet.update(). Explicitly invalidate the
        # scheduler cache even when no shared task needed detaching, so a running
        # Beat process observes the retirement disablement.
        PeriodicTasks.objects.using(database).update_or_create(
            ident=1,
            defaults={"last_update": changed_at},
        )


class Migration(migrations.Migration):
    dependencies = [
        ("apps", "0051_alter_coreaccountgroup_options"),
    ]

    operations = [
        migrations.RunPython(
            repair_retired_wordpress_periodic_tasks,
            migrations.RunPython.noop,
        ),
    ]
