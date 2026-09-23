from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.cloud.lightsail_database.filters import (
    CoreCloudLightsailDatabaseFilter,
)
from apps.api.v1.cloud.lightsail_database.permissions import (
    CoreCloudLightsailDatabaseViewPermissions,
)
from apps.api.v1.cloud.lightsail_database.serializers import (
    CoreCloudLightsailDatabaseReadSerializer,
    CoreCloudLightsailDatabaseWriteSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter, scope_direct_node_queryset
from apps.api.v1.utils.api_helpers import visible_connections
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreLightsailBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreLightsail, CoreNode
from apps.console.utils.models import UtilBackup


class CoreCloudLightsailDatabaseView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreCloudLightsailDatabaseViewPermissions,
    )
    read_serializer_class = CoreCloudLightsailDatabaseReadSerializer
    write_serializer_class = CoreCloudLightsailDatabaseWriteSerializer
    all_fields = [field.name for field in CoreLightsail._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreCloudLightsailDatabaseFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= Q(node__connection__integration__code="lightsail")
        query &= Q(resource_type=CoreLightsail.ResourceType.DATABASE)
        return CoreLightsail.objects.filter(query)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(
            account=member.get_current_account(), integration__code="lightsail"
        )
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        return Response(
            visible_connections(member).filter(query).values(
                "id",
                "name",
                "location_id",
                "location__name",
                "location__image_url",
                "auth_lightsail__region__name",
                "auth_lightsail__region__code",
            )
        )

    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= Q(node__connection__integration__code="lightsail")
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(resource_type=CoreLightsail.ResourceType.DATABASE)
        nodes = scope_direct_node_queryset(request, CoreLightsail.objects.filter(query))
        return Response(
            {
                "nodes": nodes.count(),
                "backups": CoreLightsailBackup.objects.filter(
                    lightsail__in=nodes, status=UtilBackup.Status.COMPLETE
                ).count(),
                "storage": 0,
                "in_progress": CoreLightsailBackup.objects.filter(
                    lightsail__in=nodes,
                    status__in=UtilBackup.ACTIVE_STATUSES,
                ).count(),
            }
        )
