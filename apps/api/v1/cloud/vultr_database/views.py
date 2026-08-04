from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.cloud.vultr_database.filters import CoreVultrDatabaseFilter
from apps.api.v1.cloud.vultr_database.permissions import CoreVultrDatabaseViewPermissions
from apps.api.v1.cloud.vultr_database.serializers import (
    CoreVultrDatabaseReadSerializer,
    CoreVultrDatabaseWriteSerializer,
)
from apps.console.backup.models import CoreVultrDatabaseBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreVultrDatabase
from apps.console.utils.models import UtilBackup


class CoreVultrDatabaseView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreVultrDatabaseViewPermissions)
    read_serializer_class = CoreVultrDatabaseReadSerializer
    write_serializer_class = CoreVultrDatabaseWriteSerializer
    serializer_class = CoreVultrDatabaseReadSerializer
    filter_backends = [DjangoFilterBackend, DatatablesFilterBackend, SearchFilter]
    filterset_class = CoreVultrDatabaseFilter
    search_fields = ["name", "unique_id", "engine", "region", "plan", "provider_status"]

    def get_serializer_class(self):
        return self.write_serializer_class if self.request.method in {"POST", "PUT", "PATCH"} else self.read_serializer_class

    def get_queryset(self):
        account = self.request.user.member.get_current_account()
        return CoreVultrDatabase.objects.filter(
            Q(node__connection__account=account)
            & ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
            & Q(node__connection__integration__code="vultr")
        )

    def destroy(self, request, *args, **kwargs):
        self.get_object().node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["get"])
    def connections(self, request):
        account = request.user.member.get_current_account()
        return Response(
            CoreConnection.objects.filter(account=account, integration__code="vultr")
            .values("id", "name", "location_id", "location__name", "location__image_url")
        )

    @action(detail=False, methods=["get"])
    def totals(self, request):
        nodes = self.get_queryset()
        return Response(
            {
                "nodes": nodes.count(),
                "backups": CoreVultrDatabaseBackup.objects.filter(
                    vultr_database__in=nodes, status=UtilBackup.Status.COMPLETE
                ).count(),
                "storage": 0,
                "in_progress": CoreVultrDatabaseBackup.objects.filter(
                    vultr_database__in=nodes, status__in=UtilBackup.ACTIVE_STATUSES
                ).count(),
            }
        )
