from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.cloud.oracle.filters import CoreCloudOracleFilter
from apps.api.v1.cloud.oracle.permissions import CoreCloudOracleViewPermissions
from apps.api.v1.cloud.oracle.serializers import (
    CoreCloudOracleReadSerializer,
    CoreCloudOracleWriteSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreOracleBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreOracle
from apps.console.utils.models import UtilBackup


class CoreCloudOracleView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreCloudOracleViewPermissions)
    read_serializer_class = CoreCloudOracleReadSerializer
    write_serializer_class = CoreCloudOracleWriteSerializer
    filter_backends = (
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    )
    filterset_class = CoreCloudOracleFilter
    search_fields = [field.name for field in CoreOracle._meta.get_fields()]

    def get_queryset(self):
        member = self.request.user.member
        return CoreOracle.objects.filter(
            node__connection__account=member.get_current_account(),
            node__connection__integration__code="oracle",
            node__type=CoreNode.Type.CLOUD,
        ).exclude(node__status=CoreNode.Status.DELETE_REQUESTED)

    def destroy(self, request, *args, **kwargs):
        self.get_object().node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = request.user.member
        query = Q(
            account=member.get_current_account(), integration__code="oracle"
        ) & ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        return Response(
            CoreConnection.objects.filter(query).values(
                "id",
                "name",
                "location_id",
                "location__name",
                "location__image_url",
            )
        )

    @action(detail=False)
    def totals(self, request):
        nodes = self.get_queryset()
        return Response(
            {
                "nodes": nodes.count(),
                "backups": CoreOracleBackup.objects.filter(
                    oracle__in=nodes, status=UtilBackup.Status.COMPLETE
                ).count(),
                "storage": 0,
                "in_progress": CoreOracleBackup.objects.filter(
                    oracle__in=nodes, status__in=UtilBackup.ACTIVE_STATUSES
                ).count(),
            }
        )
