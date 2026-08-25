import csv

import pytz
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db.models import Count, F, Max, Q, Window
from django.db.models.functions import RowNumber
from django.http import StreamingHttpResponse
from django.views.generic import DetailView, TemplateView

from apps.api.v1.utils.api_helpers import visible_nodes
from apps.api.v1.utils.api_permissions import member_has_perm, permitted_nodes
from apps.console.account.models import get_backup_models
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup
from backupsheep.source_recovery_policy import (
    SOURCE_RECOVERY_UNAVAILABLE_MESSAGE,
    source_backup_creation_available,
)


SOURCE_TYPE_FILTERS = (
    ("server", CoreNode.Type.CLOUD, "Servers"),
    ("volume", CoreNode.Type.VOLUME, "Volumes"),
    ("website", CoreNode.Type.WEBSITE, "Websites"),
    ("database", CoreNode.Type.DATABASE, "Databases"),
    ("saas", CoreNode.Type.SAAS, "SaaS"),
)

SOURCE_READY_STATES = (CoreNode.Status.ACTIVE, CoreNode.Status.BACKUP_READY)
SOURCE_REVIEW_STATES = (
    CoreNode.Status.BACKUP_RETRYING,
    CoreNode.Status.SUSPENDED,
    CoreNode.Status.PAUSED,
    CoreNode.Status.PAUSED_MAX_RETRIES,
    CoreNode.Status.DELETE_REQUESTED,
    CoreNode.Status.DELETE_COMPLETED,
)
CONNECTION_REVIEW_STATES = (
    CoreConnection.Status.PENDING,
    CoreConnection.Status.SUSPENDED,
    CoreConnection.Status.PAUSED,
    CoreConnection.Status.DELETE_REQUESTED,
    CoreConnection.Status.TOKEN_REFRESH_FAIL,
)
SOURCE_PAGE_SIZES = (10, 25, 50, 100)
SOURCE_SORTS = {
    "-created": ("-created", "-id"),
    "name": ("name", "id"),
    "provider": ("connection__integration__name", "connection__name", "name", "id"),
    "state": ("status", "name", "id"),
}

OPERATION_INCIDENT_STATES = frozenset(
    (
        UtilBackup.Status.FAILED,
        UtilBackup.Status.MAX_RETRY_FAILED,
        UtilBackup.Status.UPLOAD_FAILED,
        UtilBackup.Status.DELETE_FAILED,
        UtilBackup.Status.DELETE_FAILED_NOT_FOUND,
        UtilBackup.Status.DELETE_MAX_RETRY_FAILED,
        UtilBackup.Status.TIMEOUT,
        UtilBackup.Status.STORAGE_VALIDATION_FAILED,
    )
)
OPERATION_ATTENTION_STATES = frozenset(
    (
        UtilBackup.Status.PARTIAL,
        UtilBackup.Status.RETRYING,
        UtilBackup.Status.DELETE_REQUESTED,
        UtilBackup.Status.DELETE_IN_PROGRESS,
    )
)


def _allowed_int(value, allowed, default=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed in allowed else default


def _csv_cell(value):
    """Neutralize spreadsheet formula prefixes without hiding source text."""
    text = "" if value is None else str(value)
    candidate = text.lstrip(" \t\r\n")
    if candidate.startswith(("=", "+", "-", "@")) or text.startswith(
        ("\t", "\r", "\n")
    ):
        return f"'{text}"
    return text


class _CsvEcho:
    def write(self, value):
        return value


def _operation_tone(status):
    if status == UtilBackup.Status.COMPLETE:
        return "verified"
    if status in OPERATION_INCIDENT_STATES:
        return "incident"
    if status in OPERATION_ATTENTION_STATES:
        return "attention"
    if status in UtilBackup.ACTIVE_STATUSES:
        return "active"
    return "neutral"


def _source_state_tone(node):
    if node.status in SOURCE_READY_STATES:
        return "available"
    if node.status == CoreNode.Status.BACKUP_IN_PROGRESS:
        return "active"
    if node.status in (
        CoreNode.Status.BACKUP_RETRYING,
        CoreNode.Status.PAUSED,
        CoreNode.Status.PAUSED_MAX_RETRIES,
    ):
        return "attention"
    if node.status in (
        CoreNode.Status.SUSPENDED,
        CoreNode.Status.DELETE_REQUESTED,
        CoreNode.Status.DELETE_COMPLETED,
    ):
        return "incident"
    return "neutral"


def _connection_state_tone(connection):
    if connection.status == CoreConnection.Status.ACTIVE:
        return "available"
    if connection.status in (
        CoreConnection.Status.SUSPENDED,
        CoreConnection.Status.DELETE_REQUESTED,
        CoreConnection.Status.TOKEN_REFRESH_FAIL,
    ):
        return "incident"
    if connection.status in (
        CoreConnection.Status.PENDING,
        CoreConnection.Status.PAUSED,
    ):
        return "attention"
    return "neutral"


def _attach_source_evidence(nodes):
    """Attach bounded, presentation-only operation evidence to page sources.

    Backup history is polymorphic. Query each concrete backup table once for the
    nodes on this page, rather than calling CoreNode's per-row helpers. The
    newest record is ordered by initiation time; a separate correlated value
    records the last fully COMPLETE operation. Neither is labelled recovery
    proof.
    """
    node_by_id = {node.id: node for node in nodes}
    latest_by_node = {}
    complete_started_at_by_node = {}

    if node_by_id:
        integration_codes = {
            node.connection.integration.code for node in node_by_id.values()
        }
        for model, node_attr in get_backup_models():
            # A page normally contains only one or two provider families. Avoid
            # touching every concrete backup table when none of its nodes can
            # appear in this page. Vultr compute and managed databases share a
            # connection integration code, so both bounded queries remain valid.
            if node_attr not in integration_codes and not (
                node_attr == "vultr_database" and "vultr" in integration_codes
            ):
                continue
            node_id_path = f"{node_attr}__node_id"
            operations = (
                model.objects.filter(**{f"{node_id_path}__in": node_by_id})
                .annotate(
                    _source_node_id=F(node_id_path),
                    _source_rank=Window(
                        expression=RowNumber(),
                        partition_by=[F(node_id_path)],
                        order_by=(F("created").desc(), F("pk").desc()),
                    ),
                )
                .filter(_source_rank=1)
                .only("id", "status", "created", "modified")
            )
            for operation in operations:
                node_id = operation._source_node_id
                current = latest_by_node.get(node_id)
                if current is None or operation.created > current.created:
                    latest_by_node[node_id] = operation
            completed_records = (
                model.objects.filter(
                    **{
                        f"{node_id_path}__in": node_by_id,
                        "status": UtilBackup.Status.COMPLETE,
                    }
                )
                .values(node_id_path)
                .annotate(last_started_at=Max("created"))
            )
            for record in completed_records:
                node_id = record[node_id_path]
                started_at = record["last_started_at"]
                if started_at and (
                    node_id not in complete_started_at_by_node
                    or started_at > complete_started_at_by_node[node_id]
                ):
                    complete_started_at_by_node[node_id] = started_at

    for node in nodes:
        node.latest_operation = latest_by_node.get(node.id)
        node.latest_operation_tone = (
            _operation_tone(node.latest_operation.status)
            if node.latest_operation
            else "neutral"
        )
        node.last_complete_started_at = complete_started_at_by_node.get(node.id)
        node.source_state_tone = _source_state_tone(node)
        node.connection_state_tone = _connection_state_tone(node.connection)
        node.can_request_operation = (
            node.status in SOURCE_READY_STATES
            and node.connection.status == CoreConnection.Status.ACTIVE
            and source_backup_creation_available(
                node.connection.integration.code
            )
        )
    return nodes


class NodeView(LoginRequiredMixin, TemplateView):
    template_name = "console/node/index.html"

    def _scoped_nodes(self):
        return visible_nodes(self.request.user.member).select_related(
            "connection__integration",
            "connection__location",
            "added_by__user",
        )

    def _filtered_nodes(self, scoped_nodes):
        request = self.request
        search = (request.GET.get("q") or "").strip()
        source_type = request.GET.get("type") or ""
        legacy_type = _allowed_int(
            request.GET.get("s_type"),
            {choice.value for choice in CoreNode.Type},
        )
        if source_type not in {item[0] for item in SOURCE_TYPE_FILTERS}:
            source_type = next(
                (
                    slug
                    for slug, value, _label in SOURCE_TYPE_FILTERS
                    if value == legacy_type
                ),
                "",
            )

        source_status = _allowed_int(
            request.GET.get("status") or request.GET.get("s_status"),
            {choice.value for choice in CoreNode.Status},
        )
        schedule = request.GET.get("schedule") or ""
        if schedule not in ("active", "missing"):
            schedule = ""
        owner_id = _allowed_int(
            request.GET.get("owner"),
            set(
                scoped_nodes.exclude(added_by_id=None).values_list(
                    "added_by_id", flat=True
                )
            ),
        )
        sort = request.GET.get("sort") or "-created"
        if sort not in SOURCE_SORTS:
            sort = "-created"

        nodes = scoped_nodes.annotate(
            active_schedule_count=Count(
                "schedules",
                filter=Q(schedules__status=CoreSchedule.Status.ACTIVE),
                distinct=True,
            )
        )
        if search:
            nodes = nodes.filter(
                Q(name__icontains=search)
                | Q(connection__name__icontains=search)
                | Q(connection__integration__name__icontains=search)
                | Q(connection__location__name__icontains=search)
                | Q(connection__location__location__icontains=search)
            )

        # Preserve legacy deep links while the UI moves to one unified search.
        if request.GET.get("s_node"):
            nodes = nodes.filter(name__icontains=request.GET["s_node"])
        if request.GET.get("s_integration"):
            nodes = nodes.filter(
                Q(connection__name__icontains=request.GET["s_integration"])
                | Q(
                    connection__integration__name__icontains=request.GET[
                        "s_integration"
                    ]
                )
            )
        if request.GET.get("s_endpoint"):
            nodes = nodes.filter(
                Q(
                    connection__location__name__icontains=request.GET[
                        "s_endpoint"
                    ]
                )
                | Q(
                    connection__location__location__icontains=request.GET[
                        "s_endpoint"
                    ]
                )
            )

        type_value = next(
            (
                value
                for slug, value, _label in SOURCE_TYPE_FILTERS
                if slug == source_type
            ),
            None,
        )
        if type_value is not None:
            nodes = nodes.filter(type=type_value)
        if source_status is not None:
            nodes = nodes.filter(status=source_status)
        if schedule == "active":
            nodes = nodes.filter(active_schedule_count__gt=0)
        elif schedule == "missing":
            nodes = nodes.filter(active_schedule_count=0)
        if owner_id is not None:
            nodes = nodes.filter(added_by_id=owner_id)

        self.filter_state = {
            "q": search,
            "type": source_type,
            "status": str(source_status) if source_status is not None else "",
            "schedule": schedule,
            "owner": str(owner_id) if owner_id is not None else "",
            "sort": sort,
        }
        return nodes.order_by(*SOURCE_SORTS[sort])

    def _export_csv(self, nodes):
        def rows():
            writer = csv.writer(_CsvEcho())
            yield writer.writerow(
                (
                    "Source ID",
                    "Source name",
                    "Type",
                    "Source state",
                    "Connection",
                    "Connection state",
                    "Provider",
                    "Endpoint",
                    "Active schedules",
                    "Added by",
                    "Added at",
                )
            )
            for node in nodes.iterator(chunk_size=500):
                location = node.connection.location
                owner = node.added_by.user.email if node.added_by_id else ""
                yield writer.writerow(
                    tuple(
                        _csv_cell(value)
                        for value in (
                            node.uuid_str,
                            node.name,
                            node.get_type_display(),
                            node.get_status_display(),
                            node.connection.name,
                            node.connection.get_status_display(),
                            node.connection.integration.name,
                            location.location if location else "",
                            node.active_schedule_count,
                            owner,
                            node.created.isoformat(),
                        )
                    )
                )

        response = StreamingHttpResponse(
            rows(), content_type="text/csv; charset=utf-8"
        )
        response["Content-Disposition"] = (
            'attachment; filename="backupsheep-sources.csv"'
        )
        response["Cache-Control"] = "private, no-store"
        return response

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        member = request.user.member
        scoped_nodes = self._scoped_nodes()
        nodes = self._filtered_nodes(scoped_nodes)
        if request.GET.get("export") == "csv":
            return self._export_csv(nodes)

        summary = scoped_nodes.aggregate(
            total=Count("id", distinct=True),
            scheduled=Count(
                "id",
                filter=Q(schedules__status=CoreSchedule.Status.ACTIVE),
                distinct=True,
            ),
            state_review=Count(
                "id",
                filter=(
                    Q(status__in=SOURCE_REVIEW_STATES)
                    | Q(connection__status__in=CONNECTION_REVIEW_STATES)
                ),
                distinct=True,
            ),
            clouds=Count(
                "id", filter=Q(type=CoreNode.Type.CLOUD), distinct=True
            ),
            volumes=Count(
                "id", filter=Q(type=CoreNode.Type.VOLUME), distinct=True
            ),
            websites=Count(
                "id", filter=Q(type=CoreNode.Type.WEBSITE), distinct=True
            ),
            databases=Count(
                "id", filter=Q(type=CoreNode.Type.DATABASE), distinct=True
            ),
            saas=Count("id", filter=Q(type=CoreNode.Type.SAAS), distinct=True),
        )
        summary["unscheduled"] = summary["total"] - summary["scheduled"]

        filtered_count = nodes.count()

        page_size = _allowed_int(
            request.GET.get("p_size"), set(SOURCE_PAGE_SIZES), 10
        )
        paginator = Paginator(nodes, page_size)
        page = paginator.get_page(request.GET.get("p_no") or 1)
        page.object_list = _attach_source_evidence(list(page.object_list))
        page_node_ids = [node.id for node in page.object_list]
        operation_node_ids = set(
            permitted_nodes(request, "backup_create")
            .filter(id__in=page_node_ids)
            .values_list("id", flat=True)
        )
        for node in page.object_list:
            node.source_protection_available = source_backup_creation_available(
                node.connection.integration.code
            )
            node.can_run_operation = (
                node.source_protection_available
                and node.can_request_operation
                and node.id in operation_node_ids
            )

        query = request.GET.copy()
        query.pop("p_no", None)
        query.pop("export", None)
        pagination_query = query.urlencode()
        query["export"] = "csv"

        type_query = request.GET.copy()
        for key in ("p_no", "export", "type", "s_type"):
            type_query.pop(key, None)
        all_types_query = type_query.urlencode()

        owners = (
            scoped_nodes.exclude(added_by_id=None)
            .values(
                "added_by_id",
                "added_by__user__first_name",
                "added_by__user__last_name",
                "added_by__user__email",
            )
            .distinct()
            .order_by("added_by__user__email")
        )
        count_keys = {
            CoreNode.Type.CLOUD: "clouds",
            CoreNode.Type.VOLUME: "volumes",
            CoreNode.Type.WEBSITE: "websites",
            CoreNode.Type.DATABASE: "databases",
            CoreNode.Type.SAAS: "saas",
        }
        type_filters = []
        for slug, value, label in SOURCE_TYPE_FILTERS:
            item_query = type_query.copy()
            item_query["type"] = slug
            type_filters.append(
                {
                    "slug": slug,
                    "label": label,
                    "count": summary[count_keys[value]],
                    "query": item_query.urlencode(),
                }
            )

        can_run_backups = member_has_perm(request, "backup_create")
        can_manage_sources = member_has_perm(
            request, "node_changes"
        ) and member_has_perm(request, "integration_changes")
        storage_list = CoreStorage.objects.none()
        if can_run_backups:
            storage_list = (
                CoreStorage.objects.filter(
                    account=member.get_current_account(),
                    status=CoreStorage.Status.ACTIVE,
                )
                .select_related("type")
                .order_by("type__position", "name")
            )

        context.update(
            {
                "heading": "Sources",
                "active_url": "nodes",
                "member": member,
                "account": member.get_current_account(),
                "summary": summary,
                "node_count": summary["total"],
                "filtered_count": filtered_count,
                "type_filters": type_filters,
                "all_types_query": all_types_query,
                "page": page,
                "page_sizes": SOURCE_PAGE_SIZES,
                "elided_page_range": paginator.get_elided_page_range(page.number),
                "pagination_query": pagination_query,
                "export_query": query.urlencode(),
                "filters": self.filter_state,
                "filters_active": any(
                    self.filter_state[key]
                    for key in ("q", "type", "status", "schedule", "owner")
                )
                or self.filter_state["sort"] != "-created"
                or page_size != 10,
                "advanced_filters_active": any(
                    self.filter_state[key]
                    for key in ("status", "schedule", "owner")
                )
                or self.filter_state["sort"] != "-created"
                or page_size != 10,
                "owners": owners,
                "can_run_backups": can_run_backups,
                "can_manage_sources": can_manage_sources,
                "storage_list": storage_list,
            }
        )
        return self.render_to_response(context)


class NodeDetailView(LoginRequiredMixin, DetailView):
    model = CoreNode
    template_name = "console/node/detail.html"
    permission_denied_message = "You don't have access to this source"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        member = self.request.user.member
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        list_all_backups = self.request.GET.get("list_all_backups", False)

        if list_all_backups in ("true", "True"):
            list_all_backups = True
        page = Paginator(
            self.get_object().list_backups(list_all_backups).order_by("-created"),
            p_size,
        ).page(p_no)

        storage_list = (
            CoreStorage.objects.filter(account=member.get_current_account())
            .exclude(status=CoreStorage.Status.PAUSED)
            .order_by("type__position")
        )

        context[
            "heading"
        ] = f"{self.get_object().get_type_display()} | {self.get_object().get_integration_alt_name()} | {self.get_object().name}"
        context["active_url"] = "nodes"
        context["page"] = page
        context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
        context["storage_list"] = storage_list
        context["timezones"] = pytz.all_timezones
        context["list_all_backups"] = list_all_backups
        context["backup_count"] = self.get_object().list_backups(list_all_backups).count()
        node = self.get_object()
        context["is_vultr_managed_database"] = (
            node.connection.integration.code == "vultr"
            and hasattr(node, "vultr_database")
        )
        context["source_backup_creation_available"] = (
            source_backup_creation_available(
                node.connection.integration.code
            )
        )
        context["source_recovery_unavailable_message"] = (
            SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
        )
        return context

    def get_queryset(self, **kwargs):
        return visible_nodes(self.request.user.member)
