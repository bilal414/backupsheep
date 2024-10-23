from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.console.api.v1.cloud.google_cloud.filters import CoreCloudGoogleCloudFilter
from apps.console.api.v1.cloud.google_cloud.permissions import CoreCloudGoogleCloudViewPermissions
from apps.console.api.v1.cloud.google_cloud.serializers import (
    CoreCloudGoogleCloudReadSerializer,
    CoreCloudGoogleCloudWriteSerializer,
)
from apps.console.api.v1.utils.api_filters import DateRangeFilter
from apps.console.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreGoogleCloudBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreGoogleCloud
from rest_framework import status

from apps.console.utils.models import UtilBackup


class CoreCloudGoogleCloudView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreCloudGoogleCloudViewPermissions,
    )
    read_serializer_class = CoreCloudGoogleCloudReadSerializer
    write_serializer_class = CoreCloudGoogleCloudWriteSerializer
    all_fields = [f.name for f in CoreGoogleCloud._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreCloudGoogleCloudFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= Q(node__connection__integration__code="google_cloud")
        queryset = CoreGoogleCloud.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="google_cloud")
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        regions = CoreConnection.objects.filter(query).values(
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
        query &= Q(node__connection__integration__code="google_cloud")
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        nodes = CoreGoogleCloud.objects.filter(query)
        all_totals = {
            "nodes": nodes.count(),
            "backups": CoreGoogleCloudBackup.objects.filter(
                google_cloud__in=nodes, status=UtilBackup.Status.COMPLETE
            ).count(),
            "storage": 0,
            "in_progress": 0,
        }
        return Response(all_totals)
