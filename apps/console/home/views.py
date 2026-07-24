from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.views.generic import TemplateView
from croniter import croniter

from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreSchedule
from apps.console.utils.models import UtilBackup


def _next_run(schedule, now):
    """Return the next time a live schedule should run, if it is calculable."""
    try:
        if schedule.type == CoreSchedule.Type.ONETIME:
            return schedule.at_datetime if schedule.at_datetime and schedule.at_datetime > now else None
        if schedule.type == CoreSchedule.Type.RATE:
            seconds_by_unit = {
                CoreSchedule.RateUnit.MINUTES: 60,
                CoreSchedule.RateUnit.HOURS: 60 * 60,
                CoreSchedule.RateUnit.DAYS: 24 * 60 * 60,
            }
            interval_seconds = seconds_by_unit.get(schedule.rate_unit, 0) * (schedule.rate_value or 0)
            if not interval_seconds:
                return None
            base = (
                schedule.celery_periodic_task.last_run_at
                if schedule.celery_periodic_task and schedule.celery_periodic_task.last_run_at
                else schedule.created
            )
            elapsed = max(0, (now - base).total_seconds())
            return base + timedelta(seconds=((int(elapsed // interval_seconds) + 1) * interval_seconds))
        if schedule.type == CoreSchedule.Type.CRON:
            expression = " ".join(
                (
                    schedule.minute or "*",
                    schedule.hour or "*",
                    schedule.day_of_month or "*",
                    schedule.month_of_year or "*",
                    schedule.day_of_week or "*",
                )
            )
            return croniter(expression, now).get_next(type(now))
    except (TypeError, ValueError):
        return None
    return None


def _set_backup_node(backups):
    """Attach a presentation-only node attribute to each polymorphic backup."""
    from apps.console.account.models import get_backup_models

    node_attr_by_model = dict(get_backup_models())
    for backup in backups:
        node_attr = node_attr_by_model.get(type(backup))
        backup.dashboard_node = getattr(backup, node_attr).node if node_attr else None
    return backups


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "console/home/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        member = self.request.user.member
        account = member.get_current_account()
        nodes = visible_nodes(member)
        node_ids = list(nodes.values_list("id", flat=True))
        now = timezone.now()

        recent_backups = _set_backup_node(
            account.get_all_backups(status=None, limit=6, node_ids=node_ids)
        )
        failed_backups = _set_backup_node(
            account.get_all_backups(
                status=(
                    UtilBackup.Status.FAILED,
                    UtilBackup.Status.MAX_RETRY_FAILED,
                    UtilBackup.Status.UPLOAD_FAILED,
                    UtilBackup.Status.STORAGE_VALIDATION_FAILED,
                    UtilBackup.Status.TIMEOUT,
                ),
                limit=4,
                node_ids=node_ids,
            )
        )
        schedules = (
            CoreSchedule.objects.filter(
                node_id__in=node_ids, status=CoreSchedule.Status.ACTIVE
            )
            .select_related("node", "celery_periodic_task")
        )
        upcoming_schedules = []
        for schedule in schedules:
            schedule.next_run = _next_run(schedule, now)
            if schedule.next_run:
                upcoming_schedules.append(schedule)
        upcoming_schedules.sort(key=lambda schedule: schedule.next_run)

        activity = CoreLog.objects.filter(account=account)
        if not member.is_primary_account:
            activity = activity.filter(data__node_id__in=node_ids)

        context["member"] = member
        context["account"] = account
        context["visible_node_count"] = len(node_ids)
        context["active_schedule_count"] = schedules.count()
        context["recent_backups"] = recent_backups
        context["failed_backups"] = failed_backups
        context["upcoming_schedules"] = upcoming_schedules[:5]
        context["recent_activity"] = activity.order_by("-created")[:6]
        context["storage_used"] = account.storage_used() if member.is_primary_account else None
        context["heading"] = "Dashboard"
        context["active_url"] = "dashboard"
        return self.render_to_response(context)
