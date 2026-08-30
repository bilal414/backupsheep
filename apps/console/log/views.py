from datetime import datetime, time, timedelta
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db.models import CharField, Q, Subquery
from django.db.models.fields.json import KT
from django.db.models.functions import Cast
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.generic import TemplateView

from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.connection.models import CoreConnection
from apps.console.log.models import CoreLog


ACTIVITY_PAGE_SIZES = (25, 50, 100)
MAX_SEARCH_LENGTH = 200
MAX_ACTOR_LENGTH = 320


def _positive_int(value, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _optional_int(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _bounded_text(value, maximum, errors, label):
    value = str(value or "").strip()
    if len(value) > maximum:
        errors.append(f"{label} was limited to {maximum} characters.")
        value = value[:maximum]
    return value


def _member_timezone(member):
    name = str(getattr(member, "timezone", None) or "UTC")
    try:
        return name, ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return "UTC", ZoneInfo("UTC")


def _date_boundary(value, timezone_info, *, end=False):
    parsed = parse_date(str(value or ""))
    if parsed is None:
        return None
    if end:
        parsed += timedelta(days=1)
    return datetime.combine(parsed, time.min, tzinfo=timezone_info)


class LogView(LoginRequiredMixin, TemplateView):
    template_name = "console/log/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors = []
        member = request.user.member
        membership = member.get_active_current_membership()
        account = membership.account if membership is not None else None
        scoped_nodes = visible_nodes(member)

        node_raw = request.GET.get("node")
        backup_raw = request.GET.get("backup")
        integration_raw = request.GET.get("integration")
        node_id = _optional_int(node_raw)
        backup_id = _optional_int(backup_raw)
        integration_id = _optional_int(integration_raw)
        if node_raw and node_id is None:
            errors.append("The source scope was ignored because its identifier is invalid.")
        if backup_raw and backup_id is None:
            errors.append("The backup scope was ignored because its identifier is invalid.")
        if integration_raw and integration_id is None:
            errors.append("The connection scope was ignored because its identifier is invalid.")

        query_text = _bounded_text(
            request.GET.get("q"), MAX_SEARCH_LENGTH, errors, "Search"
        )
        actor = _bounded_text(
            request.GET.get("actor"), MAX_ACTOR_LENGTH, errors, "Actor"
        )
        # Preserve legacy drill-down URLs while the redesigned form exposes a
        # single safer and more useful search field.
        message = _bounded_text(
            request.GET.get("message"), MAX_SEARCH_LENGTH, errors, "Message filter"
        )
        error = _bounded_text(
            request.GET.get("error"), MAX_SEARCH_LENGTH, errors, "Error filter"
        )

        log_type = str(request.GET.get("type") or "").strip()
        valid_types = {str(value) for value in CoreLog.Type.values}
        if log_type and log_type not in valid_types:
            errors.append("The selected event category was ignored.")
            log_type = ""

        outcome = str(request.GET.get("outcome") or "").strip()
        valid_outcomes = {value for value, _label in CoreLog.OUTCOME_CHOICES}
        if outcome and outcome not in valid_outcomes:
            errors.append("The selected outcome was ignored.")
            outcome = ""

        timezone_name, member_tz = _member_timezone(member)
        date_from = str(request.GET.get("date_from") or "").strip()
        date_to = str(request.GET.get("date_to") or "").strip()
        date_from_boundary = _date_boundary(date_from, member_tz)
        date_to_boundary = _date_boundary(date_to, member_tz, end=True)
        if date_from and date_from_boundary is None:
            errors.append("The start date was ignored. Use YYYY-MM-DD.")
            date_from = ""
        if date_to and date_to_boundary is None:
            errors.append("The end date was ignored. Use YYYY-MM-DD.")
            date_to = ""
        if (
            date_from_boundary is not None
            and date_to_boundary is not None
            and date_from_boundary >= date_to_boundary
        ):
            errors.append("The start date must be on or before the end date.")
            date_from = ""
            date_to = ""
            date_from_boundary = None
            date_to_boundary = None

        log_queryset = CoreLog.objects.all()
        query = Q(account=account)
        if membership is None:
            query &= Q(pk__in=[])
        elif not membership.primary:
            # Transitional visibility: resource events follow canonical source
            # scope, while a member retains their own account/auth activity. A
            # typed event-scope column should eventually replace the JSON key.
            # KeyTextTransform safely normalizes both historical JSON numbers and
            # strings to text. Cast only trusted CoreNode PKs to text; never cast
            # arbitrary legacy JSON to an integer inside PostgreSQL.
            visible_node_ids_as_text = scoped_nodes.annotate(
                activity_scope_node_id=Cast("id", output_field=CharField())
            ).values("activity_scope_node_id")
            log_queryset = log_queryset.annotate(
                activity_node_id_text=KT("data__node_id")
            )
            resource_events = Q(
                activity_node_id_text__in=Subquery(visible_node_ids_as_text)
            )
            own_identity_events = (
                Q(type__in=(CoreLog.Type.AUTH, CoreLog.Type.MEMBER))
                & Q(data__actor_email__iexact=request.user.email)
                & Q(data__node_id__isnull=True)
                & Q(data__connection_id__isnull=True)
                & Q(data__backup_id__isnull=True)
            )
            query &= resource_events | own_identity_events

        if node_id is not None:
            query &= Q(data__node_id=node_id)
        if backup_id is not None:
            query &= Q(data__backup_id=backup_id)
        if integration_id is not None:
            query &= Q(data__connection_id=integration_id)

        if query_text:
            query &= (
                Q(data__message__icontains=query_text)
                | Q(data__error__icontains=query_text)
                | Q(data__actor_email__icontains=query_text)
                | Q(data__node_name__icontains=query_text)
                | Q(data__connection_name__icontains=query_text)
                | Q(data__backup_name__icontains=query_text)
                | Q(data__correlation_id__icontains=query_text)
                | Q(data__request_id__icontains=query_text)
                | Q(data__action__icontains=query_text)
            )
        if actor:
            query &= Q(data__actor_email__icontains=actor)
        if message:
            query &= Q(data__message__icontains=message)
        if error:
            query &= Q(data__error__icontains=error)
        if log_type:
            query &= Q(type=int(log_type))
        if outcome:
            query &= CoreLog.outcome_query(outcome)
        if date_from_boundary is not None:
            query &= Q(created__gte=date_from_boundary)
        if date_to_boundary is not None:
            query &= Q(created__lt=date_to_boundary)

        requested_page_size = _positive_int(request.GET.get("p_size"), 50)
        page_size = (
            requested_page_size
            if requested_page_size in ACTIVITY_PAGE_SIZES
            else 50
        )
        if request.GET.get("p_size") and requested_page_size not in ACTIVITY_PAGE_SIZES:
            errors.append("The page size was reset to 50.")

        logs = log_queryset.filter(query).order_by("-created", "-id")
        paginator = Paginator(logs, page_size)
        page = paginator.get_page(_positive_int(request.GET.get("p_no"), 1))
        page.object_list = list(page.object_list)

        page_node_ids = {
            _optional_int(CoreLog.safe_data(log).get("node_id"))
            for log in page.object_list
        }
        page_node_ids.discard(None)
        nodes_by_id = {
            node.pk: node
            for node in scoped_nodes.filter(pk__in=page_node_ids).select_related(
                "connection__integration"
            )
        }
        page_connection_ids = {
            _optional_int(CoreLog.safe_data(log).get("connection_id"))
            for log in page.object_list
        }
        page_connection_ids.discard(None)
        connections_by_id = {
            connection.pk: connection
            for connection in CoreConnection.objects.filter(
                account=account,
                pk__in=page_connection_ids,
            ).select_related("integration")
        }
        CoreLog.attach_presentations(
            page.object_list,
            nodes_by_id=nodes_by_id,
            connections_by_id=connections_by_id,
        )

        scope_chips = []
        if node_id is not None:
            scoped_node = scoped_nodes.filter(pk=node_id).only("id", "name").first()
            scope_chips.append(
                {
                    "label": "Source",
                    "value": scoped_node.name if scoped_node else f"ID {node_id}",
                }
            )
        if backup_id is not None:
            scope_chips.append({"label": "Backup", "value": f"ID {backup_id}"})
        if integration_id is not None:
            scope_chips.append(
                {"label": "Connection", "value": f"ID {integration_id}"}
            )

        # Rebuild link state from validated, allowlisted values. This keeps
        # malformed or attacker-supplied query keys out of every pagination URL.
        scope_params = {
            "node": node_id,
            "backup": backup_id,
            "integration": integration_id,
        }
        filter_params = {
            "q": query_text,
            "actor": actor,
            "message": message,
            "error": error,
            "type": log_type,
            "outcome": outcome,
            "date_from": date_from,
            "date_to": date_to,
        }
        page_preference = {"p_size": page_size} if page_size != 50 else {}

        def encoded_params(*groups):
            values = {}
            for group in groups:
                values.update(
                    {
                        key: value
                        for key, value in group.items()
                        if value not in (None, "")
                    }
                )
            return urlencode(values)

        pagination_query = encoded_params(
            scope_params,
            filter_params,
            page_preference,
        )
        # Page size is a viewing preference, not a result filter, so clearing
        # filters retains a non-default preference along with drill-down scope.
        clear_query = encoded_params(scope_params, page_preference)

        filters_active = any(
            (
                query_text,
                actor,
                message,
                error,
                log_type,
                outcome,
                date_from,
                date_to,
            )
        )
        filter_count = sum(
            bool(value)
            for value in (
                query_text,
                actor,
                message,
                error,
                log_type,
                outcome,
                date_from,
                date_to,
            )
        )

        context.update(
            {
                "heading": "Activity",
                "content_owns_h1": True,
                "shell_heading": "Activity",
                "active_url": "logs",
                "account": account,
                "member": member,
                "membership": membership,
                "scope_mode": (
                    "full" if membership is not None and membership.primary else "assigned"
                ),
                "visible_source_count": scoped_nodes.count(),
                "retention_days": getattr(settings, "LOG_RETENTION_DAYS", 30),
                "timezone_name": timezone_name,
                "generated_at": timezone.now(),
                "scope_chips": scope_chips,
                "node": node_id,
                "backup": backup_id,
                "integration": integration_id,
                "logs_count": paginator.count,
                "page": page,
                "page_size": page_size,
                "page_sizes": ACTIVITY_PAGE_SIZES,
                "elided_page_range": paginator.get_elided_page_range(page.number),
                "pagination_query": pagination_query,
                "clear_filters_query": clear_query,
                "filter_errors": errors,
                "filters_active": filters_active,
                "filter_count": filter_count,
                "filters": {
                    "q": query_text,
                    "actor": actor,
                    "message": message,
                    "error": error,
                    "type": log_type,
                    "outcome": outcome,
                    "date_from": date_from,
                    "date_to": date_to,
                },
                "log_types": [
                    (str(value), CoreLog.TYPE_PRESENTATION[value][0])
                    for value in CoreLog.Type.values
                ],
                "outcome_choices": CoreLog.OUTCOME_CHOICES,
            }
        )
        return self.render_to_response(context)
