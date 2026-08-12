from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.cloud.upcloud.filters import CoreCloudUpCloudFilter
from apps.api.v1.cloud.upcloud.permissions import CoreCloudUpCloudViewPermissions
from apps.api.v1.cloud.upcloud.serializers import (
    CoreCloudUpCloudReadSerializer,
    CoreCloudUpCloudWriteSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreUpCloudBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreUpCloud
from apps.console.utils.models import UtilBackup


class CoreCloudUpCloudView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreCloudUpCloudViewPermissions)
    read_serializer_class = CoreCloudUpCloudReadSerializer
    write_serializer_class = CoreCloudUpCloudWriteSerializer
    all_fields = [field.name for field in CoreUpCloud._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreCloudUpCloudFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= Q(node__connection__integration__code="upcloud")
        return CoreUpCloud.objects.filter(query)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(
            account=member.get_current_account(),
            integration__code="upcloud",
        )
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        query &= ~Q(status=CoreConnection.Status.TOKEN_REFRESH_FAIL)
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
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= Q(node__connection__integration__code="upcloud")
        query &= Q(node__type=CoreNode.Type.CLOUD)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        nodes = CoreUpCloud.objects.filter(query)
        return Response(
            {
                "nodes": nodes.count(),
                "backups": CoreUpCloudBackup.objects.filter(
                    upcloud__in=nodes,
                    status=UtilBackup.Status.COMPLETE,
                ).count(),
                "storage": 0,
                "in_progress": CoreUpCloudBackup.objects.filter(
                    upcloud__in=nodes,
                    status__in=UtilBackup.ACTIVE_STATUSES,
                ).count(),
            }
        )
