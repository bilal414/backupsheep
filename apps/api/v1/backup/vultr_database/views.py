import hashlib

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
from apps.api.v1.backup.vultr_database.restore_requests import (
    VultrDatabaseRestoreRequestConflict,
    create_or_replay_vultr_database_restore,
)
from apps.api.v1.node.serializers import CoreVultrDatabaseRestoreSerializer
from apps.console.backup.models import CoreVultrDatabaseBackup, CoreVultrDatabaseRestore
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps._tasks.exceptions import (
    RestoreConfirmationRequired,
    RestoreCreateError,
    RestoreMissingParams,
)


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
    def cancel(self, request, *args, **kwargs):
        self.get_object().cancel()
        return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        from apps.api.v1.node.views import (
            _cloud_restore_request_identity,
            _normalize_cloud_restore_params,
        )

        backup = self.get_object()
        if backup.status != UtilBackup.Status.COMPLETE:
            return Response(
                {"detail": "Only a completed Vultr managed-database backup can be restored."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if request.data.get("confirm") is not True:
            raise RestoreConfirmationRequired(
                'Pass "confirm": true to fork a new Vultr managed database. '
                "The source cluster is never modified."
            )
        raw_name = request.data.get("name", request.data.get("label"))
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise RestoreMissingParams("A restore name is required.")
        name = raw_name.strip()
        if len(name) > 255 or any(
            ord(character) < 32 or ord(character) == 127 for character in name
        ):
            raise RestoreMissingParams("The restore name is invalid.")

        if "params" in request.data:
            raw_params = request.data.get("params")
        else:
            raw_params = {
                key: request.data[key]
                for key in ("type", "region", "plan", "date", "time")
                if key in request.data
            }
        params = _normalize_cloud_restore_params(raw_params)
        if params is None:
            raise RestoreMissingParams("The provider parameters are invalid.")

        node = backup.vultr_database.node
        correlation_id, request_fingerprint, idempotency_key, key_source = (
            _cloud_restore_request_identity(
                node,
                request,
                {
                    "node_id": node.id,
                    "backup_id": backup.id,
                    "name": name,
                    "params": params,
                },
            )
        )
        if correlation_id is None or key_source == "generated":
            raise RestoreMissingParams(
                "An Idempotency-Key header or request_id is required."
            )
        request_metadata = {
            "api_request": {
                "fingerprint": request_fingerprint,
                "key_source": key_source,
                "payload_version": 1,
                "idempotency_key_sha256": hashlib.sha256(
                    idempotency_key.encode("utf-8")
                ).hexdigest(),
            }
        }
        try:
            restore, created = create_or_replay_vultr_database_restore(
                node=node,
                backup=backup,
                name=name,
                params=params,
                correlation_id=correlation_id,
                request_fingerprint=request_fingerprint,
                request_metadata=request_metadata,
            )
        except VultrDatabaseRestoreRequestConflict:
            return Response(
                {
                    "detail": (
                        "This idempotency key belongs to a different restore request."
                    ),
                    "code": "restore_idempotency_conflict",
                },
                status=status.HTTP_409_CONFLICT,
            )
        except Exception:
            if CoreVultrDatabaseRestore.objects.filter(
                correlation_id=correlation_id,
                celery_task_id__gt="",
            ).exists():
                raise RestoreCreateError(
                    "The restore request was saved and will be retried automatically."
                )
            raise RestoreCreateError(
                "The restore request could not be accepted. Please retry safely."
            )

        response_data = dict(CoreVultrDatabaseRestoreSerializer(restore).data)
        response_data["idempotent_replay"] = not created
        return Response(
            response_data,
            status=(status.HTTP_201_CREATED if created else status.HTTP_200_OK),
        )
