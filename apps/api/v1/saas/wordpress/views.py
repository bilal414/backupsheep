import secrets

from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.api.v1.saas.wordpress.filters import CoreWordPressFilter
from apps.api.v1.saas.wordpress.permissions import CoreWordPressViewPermissions
from apps.api.v1.saas.wordpress.serializers import (
    CoreWordPressReadSerializer,
    CoreWordPressWriteSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter, scope_direct_node_queryset
from apps.api.v1.utils.api_helpers import visible_connections
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreDatabaseBackup, CoreWordPressBackup
from apps.console.connection.models import CoreAuthDatabase, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode, CoreWordPress
from rest_framework import status

from apps.console.utils.models import UtilBackup


class CoreWordPressView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreWordPressViewPermissions,
    )
    read_serializer_class = CoreWordPressReadSerializer
    write_serializer_class = CoreWordPressWriteSerializer
    all_fields = [f.name for f in CoreWordPress._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreWordPressFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= Q(node__type=CoreNode.Type.SAAS)
        query &= Q(node__connection__integration__code="wordpress")
        queryset = CoreWordPress.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="wordpress")
        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        query &= ~Q(status=CoreConnection.Status.TOKEN_REFRESH_FAIL)
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
        query &= Q(node__connection__integration__code="wordpress")
        query &= Q(node__type=CoreNode.Type.SAAS)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        nodes = scope_direct_node_queryset(request, CoreWordPress.objects.filter(query))
        all_totals = {
            "nodes": nodes.count(),
            "backups": CoreWordPressBackup.objects.filter(
                wordpress__in=nodes, status=UtilBackup.Status.COMPLETE
            ).count(),
            "storage": 0,
            "in_progress": CoreWordPressBackup.objects.filter(
                wordpress__in=nodes, status__in=UtilBackup.ACTIVE_STATUSES
            ).count(),
        }
        return Response(all_totals)

    @action(detail=False)
    def generate_key(self, request):
        key = secrets.token_urlsafe(32)
        return Response({"key": key})
