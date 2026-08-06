from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.backup.vultr_database.filters import CoreVultrDatabaseBackupFilter
from apps.api.v1.backup.mixins import VisibleNodeBackupMixin
from apps.api.v1.backup.vultr_database.permissions import CoreVultrDatabaseBackupViewPermissions
from apps.api.v1.backup.vultr_database.serializers import CoreVultrDatabaseBackupSerializer
from apps.console.backup.models import CoreVultrDatabaseBackup, CoreVultrDatabaseRestore
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup


class CoreVultrDatabaseBackupView(VisibleNodeBackupMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreVultrDatabaseBackupViewPermissions)
    serializer_class = CoreVultrDatabaseBackupSerializer
    backup_model = CoreVultrDatabaseBackup
    backup_node_relation = "vultr_database"
    filter_backends = [DjangoFilterBackend, DatatablesFilterBackend, SearchFilter]
    filterset_class = CoreVultrDatabaseBackupFilter
    search_fields = ["name", "uuid", "provider_backup_id", "provider_status"]

    def destroy(self, request, *args, **kwargs):
        self.get_object().soft_delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        backup = self.get_object()
        if backup.status != UtilBackup.Status.COMPLETE:
            return Response(
                {"detail": "Only a completed Vultr managed-database backup can be restored."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        params = dict(request.data or {})
        label = params.pop("label", None) or f"restore-{backup.uuid}"
        restore = CoreVultrDatabaseRestore.objects.create(
            backup=backup,
            name=label,
            params=params,
            status=CoreVultrDatabaseRestore.Status.PENDING,
        )
        from apps._tasks.integration.vultr_database import restore_vultr_database

        restore.celery_task_id = restore_vultr_database.apply_async(args=[restore.id]).id
        restore.save(update_fields=["celery_task_id", "modified"])
        return Response({"id": restore.id, "status": restore.status}, status=status.HTTP_202_ACCEPTED)
