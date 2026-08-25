from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.api.v1.cloud.vultr.filters import CoreCloudVultrFilter
from apps.api.v1.cloud.vultr.permissions import CoreCloudVultrViewPermissions
from apps.api.v1.cloud.vultr.serializers import CoreCloudVultrReadSerializer, CoreCloudVultrWriteSerializer
from apps.api.v1.utils.api_filters import DateRangeFilter, scope_direct_node_queryset
from apps.api.v1.utils.api_helpers import visible_connections
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreDatabaseBackup, CoreVultrBackup
from apps.console.connection.models import CoreAuthDatabase, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode, CoreVultr
from rest_framework import status

from apps.console.utils.models import UtilBackup
from apps.console.vultr_monitoring import (
    VultrMonitoringError,
    list_instance_backups,
    vultr_monitoring_public_message,
)


class CoreCloudVultrView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreCloudVultrViewPermissions,)
    read_serializer_class = CoreCloudVultrReadSerializer
    write_serializer_class = CoreCloudVultrWriteSerializer
    all_fields = [f.name for f in CoreVultr._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreCloudVultrFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= Q(node__connection__integration__code="vultr")
        queryset = CoreVultr.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="vultr")
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        regions = visible_connections(member).filter(query).values(
            "id",
            "name",
            "location_id",
            "location__name",
            "location__image_url",
        )
        return Response(regions)

    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= Q(node__connection__integration__code="vultr")
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        nodes = scope_direct_node_queryset(request, CoreVultr.objects.filter(query))
        all_totals = {
            "nodes": nodes.count(),
            "backups": CoreVultrBackup.objects.filter(vultr__in=nodes, status=UtilBackup.Status.COMPLETE).count(),
            "storage": 0,
            "in_progress": CoreVultrBackup.objects.filter(
                vultr__in=nodes, status__in=UtilBackup.ACTIVE_STATUSES
            ).count(),
        }
        return Response(all_totals)

    @action(detail=True, methods=["get"], url_path="automatic-backups")
    def automatic_backups(self, request, pk=None):
        """Return read-only status for Vultr-managed instance backups.

        BackupSheep-owned snapshots remain in ``CoreVultrBackup``.  This endpoint
        only observes provider-managed automatic backups and never changes their
        schedule or retention.
        """

        instance = self.get_object()
        if instance.node.type != CoreNode.Type.CLOUD:
            return Response(
                {"detail": "Automatic backups are only available for Vultr instances."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            backups = list_instance_backups(
                instance.node.connection.auth_vultr,
                instance_id=instance.unique_id,
            )
        except VultrMonitoringError as error:
            payload = {
                "detail": vultr_monitoring_public_message(
                    error.classification, error.status_code
                ),
                "classification": error.classification,
            }
            if error.status_code == 429:
                response_status = status.HTTP_429_TOO_MANY_REQUESTS
            elif error.classification in {"transient_timeout", "transient_unavailable", "provider_unavailable"}:
                response_status = status.HTTP_503_SERVICE_UNAVAILABLE
            elif error.classification == "authentication":
                response_status = status.HTTP_502_BAD_GATEWAY
            else:
                response_status = status.HTTP_502_BAD_GATEWAY
            return Response(payload, status=response_status)
        return Response({"instance_id": instance.unique_id, "backups": backups})
