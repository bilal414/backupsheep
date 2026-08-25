"""Crash-safe django-celery-beat scheduler integration for BackupSheep.

django-celery-beat advances ``PeriodicTask.last_run_at`` in the in-memory
``ModelEntry`` and writes it later from ``DatabaseScheduler.sync``.  That is a
reasonable default for ordinary periodic tasks, but it leaves a scheduled
backup with a window in which Beat can crash after advancing the schedule and
before creating a durable BackupSheep request.

Only ``run_scheduled_backup`` is special-cased here.  For that task, Beat
reserves the occurrence and creates the ``CoreScheduleRun`` plus
``CoreBackupRequest`` rows in one database transaction.  The broker is touched
from an ``on_commit`` callback, so a crash or broker ambiguity leaves one
recoverable outbox row with one stable Celery task id.  All other periodic
tasks retain django-celery-beat's normal behavior.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import logging
import uuid

from django.db import transaction
from django.utils import timezone
from django_celery_beat.models import PeriodicTask
from django_celery_beat.schedulers import DatabaseScheduler, ModelEntry


logger = logging.getLogger(__name__)

BACKUP_SCHEDULE_TASK = "run_scheduled_backup"
SCHEDULE_TRIGGER = "schedule"


def _datetime_key(value):
    """Return an exact, timezone-normalized representation for identity checks."""
    if value is None:
        return "<none>"
    if timezone.is_naive(value):
        value = timezone.make_aware(value, datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc).isoformat()


def _schedule_id_from_values(args, kwargs):
    """Extract exactly one positive CoreSchedule id from task arguments."""
    args = list(args or ())
    kwargs = dict(kwargs or {})
    positional = args[0] if len(args) == 1 else None
    keyword = kwargs.get("schedule_id")
    if positional is None and keyword is None:
        return None
    if positional is not None and keyword is not None:
        try:
            if int(positional) != int(keyword):
                return None
        except (TypeError, ValueError):
            return None
    value = keyword if keyword is not None else positional
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _periodic_task_schedule_id(periodic_task):
    """Extract the schedule id from a durable PeriodicTask row."""
    try:
        args = json.loads(periodic_task.args or "[]")
    except (TypeError, ValueError, json.JSONDecodeError):
        args = None
    try:
        kwargs = json.loads(periodic_task.kwargs or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        kwargs = None
    if args is None or kwargs is None:
        return None
    return _schedule_id_from_values(args, kwargs)


def _same_datetime(left, right):
    return _datetime_key(left) == _datetime_key(right)


def _occurrence_id(*, schedule_id, periodic_task_id, sequence, baseline):
    """Build a stable, opaque occurrence id from durable schedule state.

    The baseline is the state observed before this occurrence was reserved.  It
    prevents a manual count reset from accidentally reusing an old sequence and
    avoids any wall-clock dedupe window.
    """
    material = "|".join(
        (
            str(schedule_id),
            str(periodic_task_id),
            str(sequence),
            _datetime_key(baseline["last_run_at"]),
            _datetime_key(baseline["date_changed"]),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return (
        f"periodic-schedule-{schedule_id}-task-{periodic_task_id}"
        f"-sequence-{sequence}-{digest}"
    )


class BackupModelEntry(ModelEntry):
    """ModelEntry that remembers the persisted pre-reservation state.

    ``ModelEntry.__init__`` fills a missing ``last_run_at`` with a synthetic
    value.  Capture the database value before calling it so first-run schedules
    can still be compared and assigned a durable identity.
    """

    def __init__(self, model, app=None):
        self._bs_persisted_last_run_at = getattr(model, "last_run_at", None)
        self._bs_persisted_total_run_count = getattr(
            model, "total_run_count", None
        )
        self._bs_persisted_date_changed = getattr(model, "date_changed", None)
        self._bs_persisted_enabled = getattr(model, "enabled", None)
        self._bs_persisted_one_off = getattr(model, "one_off", None)
        super().__init__(model, app=app)
        # This is the value used by Celery's due calculation.  It can differ
        # from the persisted value only when the row has never run.
        self._bs_entry_last_run_at = self.last_run_at

    def __next__(self):
        if self.task != BACKUP_SCHEDULE_TASK:
            return super().__next__()

        # django-celery-beat mutates ``self.model`` before it creates the next
        # entry.  Keep the original entry as the optimistic baseline so a
        # second Beat process can identify that another process already won the
        # same due event.  The copied model is never saved directly; the
        # scheduler transaction saves the locked database row.
        model = copy.copy(self.model)
        model.last_run_at = self._default_now()
        model.total_run_count = self.total_run_count + 1
        model.no_changes = True
        return self.__class__(model, app=self.app)


class BackupDatabaseScheduler(DatabaseScheduler):
    """DatabaseScheduler with a transactional path for scheduled backups."""

    Entry = BackupModelEntry

    @staticmethod
    def _is_backup_entry(entry):
        return getattr(entry, "task", None) == BACKUP_SCHEDULE_TASK

    @staticmethod
    def _entry_baseline(entry):
        last_run_at = getattr(entry, "_bs_persisted_last_run_at", None)
        total_run_count = getattr(entry, "_bs_persisted_total_run_count", None)
        date_changed = getattr(entry, "_bs_persisted_date_changed", None)
        enabled = getattr(entry, "_bs_persisted_enabled", None)
        one_off = getattr(entry, "_bs_persisted_one_off", None)
        try:
            total_run_count = int(total_run_count)
        except (TypeError, ValueError):
            return None
        if total_run_count < 0 or enabled is None or one_off is None:
            return None
        # With no durable timestamp, date_changed is the only durable seed from
        # which a first-run occurrence can be made unique.  Refuse to publish if
        # even that state is unavailable.
        if last_run_at is None and date_changed is None:
            return None
        return {
            "last_run_at": last_run_at,
            "total_run_count": total_run_count,
            "date_changed": date_changed,
            "enabled": bool(enabled),
            "one_off": bool(one_off),
        }

    @classmethod
    def _entry_schedule_id(cls, entry):
        return _schedule_id_from_values(entry.args, entry.kwargs)

    @classmethod
    def _make_next_entry(cls, entry):
        return next(entry)

    @classmethod
    def _reset_retry_entry(cls, retry_entry, original_entry, baseline):
        """Put a failed reservation's heap entry back on the same occurrence."""
        retry_entry.last_run_at = original_entry._bs_entry_last_run_at
        retry_entry.total_run_count = baseline["total_run_count"]
        retry_entry.model.last_run_at = original_entry._bs_entry_last_run_at
        retry_entry.model.total_run_count = baseline["total_run_count"]
        retry_entry.model.no_changes = False
        retry_entry._bs_persisted_last_run_at = baseline["last_run_at"]
        retry_entry._bs_persisted_total_run_count = baseline["total_run_count"]
        retry_entry._bs_persisted_date_changed = baseline["date_changed"]
        retry_entry._bs_persisted_enabled = baseline["enabled"]
        retry_entry._bs_persisted_one_off = baseline["one_off"]
        retry_entry._bs_entry_last_run_at = original_entry._bs_entry_last_run_at
        retry_entry._bs_occurrence_baseline = baseline
        retry_entry._bs_occurrence_id = getattr(
            original_entry, "_bs_occurrence_id", None
        )

    def reserve(self, entry):
        if not self._is_backup_entry(entry):
            return super().reserve(entry)

        baseline = self._entry_baseline(entry)
        schedule_id = self._entry_schedule_id(entry)
        entry._bs_occurrence_baseline = baseline
        entry._bs_schedule_id = schedule_id
        if baseline is None or schedule_id is None or not entry.model.pk:
            entry._bs_occurrence_error = (
                "A durable schedule baseline and schedule id are required."
            )
            # Advance only the in-memory heap entry.  The database remains
            # unchanged, so a restart retries the same occurrence.
            return self._make_next_entry(entry)

        sequence = baseline["total_run_count"] + 1
        entry._bs_occurrence_id = _occurrence_id(
            schedule_id=schedule_id,
            periodic_task_id=entry.model.pk,
            sequence=sequence,
            baseline=baseline,
        )
        entry._bs_next_entry = self._make_next_entry(entry)
        # Do not add this entry to DatabaseScheduler._dirty.  The transaction in
        # apply_entry is the authoritative persistence point; a later stale
        # sync must not overwrite a newer occurrence reserved by another Beat.
        return entry._bs_next_entry

    def _fresh_entry(self, periodic_task):
        try:
            fresh = PeriodicTask.objects.get(pk=periodic_task.pk)
        except PeriodicTask.DoesNotExist:
            return None
        return self.Entry(fresh, app=self.app)

    @staticmethod
    def _adopt_heap_entry(target, source):
        """Update the object already held by Celery's tick heap in place."""
        if target is None or source is None:
            return source
        target.__dict__.clear()
        target.__dict__.update(source.__dict__)
        return target

    def _schedule_state_matches(self, periodic_task, entry, baseline):
        if periodic_task.task != BACKUP_SCHEDULE_TASK:
            return False
        if periodic_task.enabled != baseline["enabled"]:
            return False
        if periodic_task.one_off != baseline["one_off"]:
            return False
        if periodic_task.total_run_count != baseline["total_run_count"]:
            return False
        if not _same_datetime(periodic_task.last_run_at, baseline["last_run_at"]):
            return False
        if baseline["last_run_at"] is None and not _same_datetime(
            periodic_task.date_changed, baseline["date_changed"]
        ):
            return False
        return _periodic_task_schedule_id(periodic_task) == entry._bs_schedule_id

    def _commit_occurrence(self, entry):
        """Create the audit/outbox and advance PeriodicTask atomically."""
        from apps._tasks.backup_dispatch import (
            _normalized_storage_ids,
            _opaque_request_key,
        )
        from apps.console.backup.models import CoreBackupRequest
        from apps.console.node.models import CoreSchedule, CoreScheduleRun

        baseline = entry._bs_occurrence_baseline
        occurrence_id = entry._bs_occurrence_id
        schedule_id = entry._bs_schedule_id
        with transaction.atomic():
            periodic_task = (
                PeriodicTask.objects.select_for_update()
                .get(pk=entry.model.pk)
            )
            if not self._schedule_state_matches(periodic_task, entry, baseline):
                return {
                    "kind": "stale",
                    "entry": self._fresh_entry(periodic_task),
                }

            try:
                schedule = (
                    CoreSchedule.objects.select_for_update()
                    .get(pk=schedule_id)
                )
            except CoreSchedule.DoesNotExist:
                fresh_entry = self._fresh_entry(periodic_task)
                if fresh_entry is not None:
                    fresh_entry.model.enabled = False
                return {"kind": "inactive", "entry": fresh_entry}
            if schedule.status != CoreSchedule.Status.ACTIVE:
                # Keep the local scheduler quiet until schedule_update() reflects
                # the pause in PeriodicTask.  No request or schedule advancement
                # is committed for an inactive schedule.
                fresh_entry = self._fresh_entry(periodic_task)
                if fresh_entry is not None:
                    fresh_entry.model.enabled = False
                return {"kind": "inactive", "entry": fresh_entry}

            request_key = _opaque_request_key(
                schedule.node_id, SCHEDULE_TRIGGER, occurrence_id
            )
            task_id = uuid.uuid5(uuid.NAMESPACE_URL, request_key).hex
            payload = {
                "node_id": int(schedule.node_id),
                "schedule_id": int(schedule.pk),
                "storage_ids": _normalized_storage_ids(schedule.storage_ids),
                "notes": str(schedule.notes)[:10000]
                if schedule.notes is not None
                else None,
                "resume": True,
            }
            CoreScheduleRun.objects.get_or_create(
                schedule=schedule,
                request_id=occurrence_id,
            )
            request, _ = CoreBackupRequest.objects.get_or_create(
                request_key=request_key,
                defaults={
                    "task_id": task_id,
                    "task_name": schedule.node.backup_task_name(),
                    "node": schedule.node,
                    "schedule": schedule,
                    # Preserve the FK snapshot without loading CoreMember into the
                    # Beat process. Its database principal intentionally cannot
                    # enumerate identities.
                    "requested_by_id": schedule.added_by_id,
                    "trigger": SCHEDULE_TRIGGER,
                    "payload": payload,
                    "next_dispatch_at": timezone.now(),
                },
            )
            if (
                request.task_id != task_id
                or request.node_id != schedule.node_id
                or request.schedule_id != schedule.pk
                or request.trigger != SCHEDULE_TRIGGER
            ):
                raise RuntimeError(
                    "The durable scheduled-backup identity is already owned by "
                    "a different request."
                )

            periodic_task.last_run_at = entry._bs_next_entry.last_run_at
            periodic_task.total_run_count = baseline["total_run_count"] + 1
            periodic_task.no_changes = True
            periodic_task.save(
                update_fields=["last_run_at", "total_run_count"]
            )
            return {"kind": "committed", "request_id": request.pk}

    @staticmethod
    def _publish_after_commit(request_id):
        try:
            from apps._tasks.backup_dispatch import publish_backup_request

            publish_backup_request(request_id, force=True)
        except Exception:
            # The outbox sweep is the recovery path if import/database/broker
            # failure prevents this immediate best-effort publication.
            logger.exception(
                "Scheduled backup outbox publication failed for request %s",
                request_id,
            )

    def apply_entry(self, entry, producer=None):
        if not self._is_backup_entry(entry):
            return super().apply_entry(entry, producer=producer)

        if getattr(entry, "_bs_occurrence_error", None):
            logger.error(
                "Not dispatching scheduled backup %s: %s",
                entry.name,
                entry._bs_occurrence_error,
            )
            return None
        if getattr(entry, "_bs_duplicate", False):
            return None

        try:
            result = self._commit_occurrence(entry)
        except Exception:
            # Keep the heap entry on the original durable baseline.  A database
            # outage or malformed row must retry the same occurrence in this
            # process; a process restart gets the same result from the DB state.
            retry_entry = getattr(entry, "_bs_next_entry", None)
            if retry_entry is not None and entry._bs_occurrence_baseline is not None:
                self._reset_retry_entry(
                    retry_entry, entry, entry._bs_occurrence_baseline
                )
            logger.exception("Could not reserve scheduled backup %s", entry.name)
            return None

        if result["kind"] == "committed":
            next_entry = getattr(entry, "_bs_next_entry", None)

            def publish_and_refresh():
                if next_entry is not None:
                    self._schedule[entry.name] = next_entry
                self._publish_after_commit(result["request_id"])

            # Register a single callback so the local heap map and broker
            # publication both follow the database commit.  A process crash
            # before either callback is harmless: the request recovery task sees
            # the committed outbox row.
            transaction.on_commit(publish_and_refresh)
            return None

        fresh_entry = result.get("entry")
        if fresh_entry is not None:
            # Scheduler.tick has already captured the object returned by
            # reserve() in a local variable.  Adopt the locked database state
            # into that same object, otherwise a stale Beat process would keep
            # suppressing every later occurrence from its old heap baseline.
            next_entry = self._adopt_heap_entry(
                getattr(entry, "_bs_next_entry", None), fresh_entry
            )
            self._schedule[entry.name] = next_entry
            if result["kind"] == "inactive":
                entry._bs_duplicate = True
        return None


# A descriptive alias makes local imports and operational diagnostics clearer.
DatabaseScheduler = BackupDatabaseScheduler
