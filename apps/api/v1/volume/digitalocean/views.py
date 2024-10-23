from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.console.api.v1.volume.digitalocean.filters import CoreVolumeDigitalOceanFilter
from apps.console.api.v1.volume.digitalocean.permissions import CoreVolumeDigitalOceanViewPermissions
from apps.console.api.v1.volume.digitalocean.serializers import CoreVolumeDigitalOceanReadSerializer, CoreVolumeDigitalOceanWriteSerializer
from apps.console.api.v1.utils.api_filters import DateRangeFilter
from apps.console.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreDatabaseBackup, CoreDigitalOceanBackup
from apps.console.connection.models import CoreAuthDatabase, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode, CoreDigitalOcean
from rest_framework import status

from apps.console.utils.models import UtilBackup


class CoreVolumeDigitalOceanView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreVolumeDigitalOceanViewPermissions,)
    read_serializer_class = CoreVolumeDigitalOceanReadSerializer
    write_serializer_class = CoreVolumeDigitalOceanWriteSerializer
    all_fields = [f.name for f in CoreDigitalOcean._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreVolumeDigitalOceanFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.VOLUME)
        query &= Q(node__connection__integration__code="digitalocean")
        queryset = CoreDigitalOcean.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="digitalocean")
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        query &= ~Q(status=CoreConnection.Status.TOKEN_REFRESH_FAIL)
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
        query &= Q(node__connection__integration__code="digitalocean")
        query &= Q(node__type=CoreNode.Type.VOLUME)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        nodes = CoreDigitalOcean.objects.filter(query)
        all_totals = {
            "nodes": nodes.count(),
            "backups": CoreDigitalOceanBackup.objects.filter(digitalocean__in=nodes, status=UtilBackup.Status.COMPLETE).count(),
            "storage": 0,
            "in_progress": 0,
        }
        return Response(all_totals)

