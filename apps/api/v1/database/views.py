from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.console.api.v1.database.filters import CoreDatabaseFilter
from apps.console.api.v1.database.permissions import CoreDatabaseViewPermissions
from apps.console.api.v1.database.serializers import (
    CoreDatabaseReadSerializer,
    CoreDatabaseWriteSerializer,
)
from apps.console.api.v1.utils.api_filters import DateRangeFilter
from apps.console.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.models import CoreDatabaseBackup
from apps.console.connection.models import CoreAuthDatabase, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode
from rest_framework import status

from apps.console.utils.models import UtilBackup


class CoreDatabaseView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreDatabaseViewPermissions,)
    read_serializer_class = CoreDatabaseReadSerializer
    write_serializer_class = CoreDatabaseWriteSerializer
    all_fields = [f.name for f in CoreDatabase._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreDatabaseFilter
    search_fields = all_fields

    def get_queryset(self):
        db_type = None
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())

        if self.request.query_params.get("type_code") == "mariadb":
            db_type = CoreAuthDatabase.DatabaseType.MARIADB
        elif self.request.query_params.get("type_code") == "mysql":
            db_type = CoreAuthDatabase.DatabaseType.MYSQL
        elif self.request.query_params.get("type_code") == "postgresql":
            db_type = CoreAuthDatabase.DatabaseType.POSTGRESQL

        if db_type:
            query &= Q(node__connection__auth_database__type=db_type)
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        queryset = CoreDatabase.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.node.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=False, methods=["get"])
    def connections(self, request):
        db_type = None
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="database")

        if self.request.query_params.get("type_code") == "mariadb":
            db_type = CoreAuthDatabase.DatabaseType.MARIADB
        elif self.request.query_params.get("type_code") == "mysql":
            db_type = CoreAuthDatabase.DatabaseType.MYSQL
        elif self.request.query_params.get("type_code") == "postgresql":
            db_type = CoreAuthDatabase.DatabaseType.POSTGRESQL
        if db_type:
            query &= Q(auth_database__type=db_type)

        query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        regions = CoreConnection.objects.filter(query).values(
            "id",
            "name",
            "auth_database__all_databases",
            "auth_database__database_name",
            "location_id",
            "location__name",
            "location__image_url",
        )
        return Response(regions)

    @action(detail=False)
    def totals(self, request):
        db_type = None
        member = self.request.user.member
        query = Q(node__connection__account=member.get_current_account())

        if self.request.query_params.get("type_code") == "mariadb":
            db_type = CoreAuthDatabase.DatabaseType.MARIADB
        elif self.request.query_params.get("type_code") == "mysql":
            db_type = CoreAuthDatabase.DatabaseType.MYSQL
        elif self.request.query_params.get("type_code") == "postgresql":
            db_type = CoreAuthDatabase.DatabaseType.POSTGRESQL
        if db_type:
            query &= Q(
                node__connection__auth_database__type=db_type
            )
        query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        databases = CoreDatabase.objects.filter(query)
        all_totals = {
            "nodes": databases.count(),
            "backups": CoreDatabaseBackup.objects.filter(
                database__in=databases,
                status=UtilBackup.Status.COMPLETE
            ).count(),
            "storage": 0,
            "in_progress": CoreNode.objects.filter(
                database__in=databases, status=CoreNode.Status.BACKUP_IN_PROGRESS
            ).count(),
        }
        return Response(all_totals)
