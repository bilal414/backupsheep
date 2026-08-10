from django.db.models import Q
from django.views.generic import TemplateView
from django.core.paginator import Paginator
from django.core.exceptions import ObjectDoesNotExist

from apps.console.log.models import CoreLog
from apps.api.v1.utils.api_helpers import visible_nodes
from django.contrib.auth.mixins import AccessMixin, LoginRequiredMixin


def _positive_int(value, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _optional_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_backup(log):
    """Resolve a backup for display without letting a legacy row break the page."""
    try:
        return log.backup
    except (AttributeError, ObjectDoesNotExist):
        return None


class LogView(LoginRequiredMixin, TemplateView):
    template_name = "console/log/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        p_no = _positive_int(self.request.GET.get("p_no", 1), 1)
        p_size = min(_positive_int(self.request.GET.get("p_size", 50), 50), 100)
        node = self.request.GET.get("node")
        backup = self.request.GET.get("backup")
        integration = self.request.GET.get("integration")
        message = self.request.GET.get("message")
        error = self.request.GET.get("error")
        log_type = self.request.GET.get("type")

        node_id = _optional_int(node)
        backup_id = _optional_int(backup)
        integration_id = _optional_int(integration)
        if node is not None and node_id is None:
            node = None
        if backup is not None and backup_id is None:
            backup = None
        if integration is not None and integration_id is None:
            integration = None

        member = self.request.user.member
        query = Q(account=member.get_current_account())
        if not member.is_primary_account:
            query &= Q(data__node_id__in=visible_nodes(member).values_list("id", flat=True))

        if node_id is not None:
            query &= Q(data__node_id=node_id)

        if backup_id is not None:
            query &= Q(data__backup_id=backup_id)

        if integration_id is not None:
            query &= Q(data__connection_id=integration_id)

        # Free-text substring search inside the JSON payload.
        if message:
            query &= Q(data__message__icontains=message)

        if error:
            query &= Q(data__error__icontains=error)

        # Activity type filter (CoreLog.Type value); ignore non-numeric input.
        if log_type:
            try:
                query &= Q(type=int(log_type))
            except (TypeError, ValueError):
                log_type = None

        logs = CoreLog.objects.filter(query).order_by("-created")

        context["heading"] = "Logs"
        context["active_url"] = "logs"
        context["account"] = member.get_current_account()
        context["node"] = node
        context["backup"] = backup
        context["logs_count"] = logs.count()
        context["integration"] = integration
        context["message"] = message
        context["error"] = error
        context["type"] = log_type
        context["log_types"] = CoreLog.Type.choices

        paginator = Paginator(logs, p_size)
        page = paginator.get_page(p_no)
        for log in page.object_list:
            # CoreLog.backup predates durable activity rows and assumes the
            # referenced connection still exists. Historical rows can outlive
            # that connection, so expose a safe presentation-only value.
            log.console_backup = _safe_backup(log)
        context["page"] = page
        context["elided_page_range"] = page.paginator.get_elided_page_range(page.number)
        return self.render_to_response(context)
