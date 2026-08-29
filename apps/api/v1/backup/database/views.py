import hashlib
import json
import re
from datetime import timedelta
from functools import partial

import arrow
import boto3
import pytz
from botocore.config import Config
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.timezone import get_current_timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response
from apps.api.v1.utils.boto import bounded_boto3_client

from apps._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    DownloadMissingParams,
    DownloadStoragePointNotFound,
    DownloadStoragePointError, StoragePointError,
    RestoreBackupNotFound,
    RestoreConfirmationRequired,
    RestoreCreateError,
    RestoreStoragePointNotFound,
    RestoreStoragePointRequired,
)
from apps.api.v1.backup.database.filters import CoreDatabaseBackupFilter
from apps.api.v1.backup.mixins import VisibleNodeBackupMixin
from apps.api.v1.backup.logical_restore_requests import (
    LogicalRestoreActiveExists,
    LogicalRestoreRequestConflict,
    LogicalRestoreRequestInvalid,
    LogicalRestoreStoragePointInvalid,
    create_or_replay_logical_restore,
    logical_restore_request_identity,
    logical_restore_request_metadata,
    logical_restore_storage_point_id,
)
from apps.api.v1.backup.database.permissions import (
    CoreDatabaseBackupViewPermissions,
)
from apps.api.v1.backup.database.serializers import (
    CoreDatabaseBackupSerializer,
    CoreDatabaseBackupStoragePointsSerializer,
    CoreDatabaseRestoreSerializer,
    _DATABASE_RESTORE_MANUAL_RESUME_HISTORY_LIMIT,
    _DATABASE_RESTORE_MANUAL_RESUME_MAX_COUNT,
    database_restore_verification_resume_mode,
)
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_helpers import get_start_end_of_previous_day
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
)
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from rest_framework import status

from google.cloud import storage as gc_storage
from google.oauth2 import service_account


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


_RESTORE_MAX_DATABASE_IDENTIFIER_LENGTH = 63


def _restore_identifier(value, field):
    """Validate an API-provided database identifier without exposing secrets."""
    value = "" if value is None else str(value)
    if (
        not value
        or len(value) > _RESTORE_MAX_DATABASE_IDENTIFIER_LENGTH
        or re.search(r"[\s;&|`$<>(){}\[\]\\'\"!*?~#/]", value)
    ):
        raise RestoreConfirmationRequired(
            f"{field} is not a safe database identifier for restore."
        )
    return value


def _restore_target_name(restore, source_database):
    source_database = _restore_identifier(source_database, "source database")
    correlation = str(restore.correlation_id).replace("-", "")
    digest = hashlib.sha256(source_database.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", source_database).strip("_").lower()
    slug = slug[:22] or "database"
    return f"bs_restore_{correlation[:12]}_{slug}_{digest}"[:_RESTORE_MAX_DATABASE_IDENTIFIER_LENGTH]


def _known_database_restore_sources(backup):
    """Return source DB names known without opening the stored archive.

    ``all_databases`` is intentionally represented as unknown.  The worker
    locks the final mapping after the archive has been fully validated.
    """
    database = backup.database
    auth = database.node.connection.auth_database
    if bool(getattr(backup, "all_databases", False)) or bool(database.all_databases):
        return None
    if bool(getattr(backup, "tables", None)) or bool(getattr(backup, "all_tables", False)) or bool(database.all_tables):
        return [_restore_identifier(auth.database_name, "source database")]
    configured = list(database.databases or [])
    if configured:
        return sorted({_restore_identifier(value, "source database") for value in configured})
    return [_restore_identifier(auth.database_name, "source database")]


def _canonical_target_mapping(mapping):
    return json.dumps(dict(sorted(mapping.items())), sort_keys=True, separators=(",", ":"))


def _in_place_confirmation(mapping):
    return f"IN_PLACE_RESTORE_TO:{_canonical_target_mapping(mapping)}"


def _restore_request_state(backup, restore, request_data):
    """Build immutable restore parameters before Celery is dispatched."""
    mode = str(request_data.get("mode") or "fork").strip().lower()
    if mode not in {"fork", "in_place"}:
        raise RestoreConfirmationRequired("mode must be fork or in_place.")

    known_sources = _known_database_restore_sources(backup)
    if mode == "fork":
        # Fork targets are deterministic but all-database archives are only
        # knowable after the ZIP has passed full validation in the worker.
        mapping = None
        if known_sources:
            mapping = {
                source: _restore_target_name(restore, source)
                for source in known_sources
            }
        params = {
            "mode": "fork",
            "target_mapping": mapping,
            "mapping_locked": bool(mapping),
            "source_backup_uuid": str(backup.uuid),
        }
        metadata = {
            "mode": "fork",
            "mapping_state": "locked" if mapping else "pending_archive_validation",
            "target_checkpoints": {},
        }
        if mapping:
            metadata["source_to_target"] = dict(mapping)
        return params, metadata

    raw_mapping = request_data.get("target_mapping")
    if not isinstance(raw_mapping, dict) or not raw_mapping:
        raise RestoreConfirmationRequired(
            "in_place requires target_mapping and an exact target_confirmation."
        )
    mapping = {}
    for source, target in sorted(raw_mapping.items(), key=lambda pair: str(pair[0])):
        source = _restore_identifier(source, "source database")
        target = _restore_identifier(target, "target database")
        if target in mapping.values():
            raise RestoreConfirmationRequired("target_mapping contains duplicate targets.")
        mapping[source] = target
    if known_sources and set(mapping) != set(known_sources):
        raise RestoreConfirmationRequired(
            "in_place target_mapping must name exactly the databases selected by this backup."
        )
    expected_confirmation = _in_place_confirmation(mapping)
    if request_data.get("target_confirmation") != expected_confirmation:
        raise RestoreConfirmationRequired(
            "target_confirmation must exactly match the requested source-to-target mapping."
        )
    params = {
        "mode": "in_place",
        "target_mapping": dict(mapping),
        "mapping_locked": True,
        "target_confirmation": expected_confirmation,
        "source_backup_uuid": str(backup.uuid),
    }
    metadata = {
        "mode": "in_place",
        "mapping_state": "locked",
        "source_to_target": dict(mapping),
        "target_checkpoints": {},
    }
    return params, metadata


class CoreDatabaseBackupView(VisibleNodeBackupMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreDatabaseBackupViewPermissions)
    serializer_class = CoreDatabaseBackupSerializer
    backup_model = CoreDatabaseBackup
    backup_node_relation = "database"
    backup_delete_model_key = "database"
    all_fields = [f.name for f in CoreDatabaseBackup._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreDatabaseBackupFilter
    search_fields = all_fields

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        return self.request_backup_delete(instance)

    @action(detail=True, methods=["post"])
    def cancel(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.cancel()
        return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True, methods=["post"])
    def retry(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.retry()
        return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True)
    def download(self, request, pk=None):
        storage_point_id = self.request.query_params.get("storage_point_id")
        if storage_point_id:
            # Resolve the scoped object before the provider-error wrapper so a
            # hidden/nonexistent backup remains a normal DRF 404.
            backup = self.get_object()
            try:
                storage_point = (
                    backup.stored_database_backups.filter(
                        id=storage_point_id,
                        backup__status=CoreDatabaseBackup.Status.COMPLETE,
                        status=(
                            CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE
                        ),
                        storage_file_id__isnull=False,
                    )
                    .exclude(storage_file_id="")
                    .first()
                )
                if storage_point is not None:
                    if not storage_point.direct_download_permitted():
                        return Response(
                            {
                                "code": "direct_download_not_permitted",
                                "detail": (
                                    "Direct browser download is unavailable for this protected artifact. "
                                    "Use an authenticated restore or controlled export workflow."
                                ),
                            },
                            status=status.HTTP_409_CONFLICT,
                        )
                    download_url = storage_point.generate_download_url()
                    _log_activity(
                        request,
                        CoreLog.Type.BACKUP,
                        {
                            "message": f"Download URL generated for backup '{backup.uuid_str}'.",
                            "action": "download",
                            "actor_email": request.user.email,
                            "backup_id": backup.id,
                            "backup_name": backup.name,
                            "node_id": backup.database.node_id,
                            "node_name": backup.database.node.name,
                            "connection_id": backup.database.node.connection_id,
                            "connection_name": backup.database.node.connection.name,
                        },
                    )
                    return Response({"url": download_url, "expire_in": int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))}, status=status.HTTP_201_CREATED)
                raise DownloadStoragePointNotFound()
            except DownloadStoragePointNotFound:
                raise
            except Exception:
                # Provider/client exception bodies can contain endpoint details
                # or credentials; keep the API contract generic.
                raise DownloadStoragePointError()
        else:
            raise DownloadMissingParams()

    @action(detail=True)
    def storage_points(self, request, pk=None):
        try:
            backup = self.get_object()
            storage_points = CoreDatabaseBackupStoragePointsSerializer(backup.stored_database_backups.all(), many=True).data
            return Response(storage_points, status=status.HTTP_200_OK)
        except Exception:
            raise StoragePointError()

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        from apps._tasks.integration.restore import restore_database_backup

        backup = self.get_object()

        if request.data.get("confirm") is not True:
            raise RestoreConfirmationRequired(
                'Pass "confirm": true to start a restore. The default mode creates a new database fork.'
            )
        if backup.status != CoreDatabaseBackup.Status.COMPLETE:
            raise RestoreBackupNotFound()

        stored_backups = backup.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id__isnull=False,
        ).exclude(storage_file_id="")
        try:
            storage_point_id = logical_restore_storage_point_id(request.data)
        except LogicalRestoreStoragePointInvalid:
            raise ValidationError(
                {
                    "storage_point_id": [
                        "Must be a positive JSON integer."
                    ]
                }
            )
        if storage_point_id is not None:
            stored_backup = stored_backups.filter(id=storage_point_id).first()
            if stored_backup is None:
                raise RestoreStoragePointNotFound()
        else:
            if stored_backups.count() != 1:
                raise RestoreStoragePointRequired()
            stored_backup = stored_backups.first()

        # Derive fork names from the durable request correlation before the row
        # is inserted. Concurrent retries therefore calculate the same immutable
        # target mapping and race on one database uniqueness boundary.
        try:
            request_identity = logical_restore_request_identity(
                request.data,
                restore_kind="database",
                backup_id=backup.id,
            )
            restore_seed = CoreDatabaseRestore(
                backup=backup,
                storage_point=stored_backup,
                correlation_id=request_identity.correlation_id,
            )
            params, metadata = _restore_request_state(
                backup, restore_seed, request.data
            )
            request_fingerprint, api_request_metadata = (
                logical_restore_request_metadata(
                    request_identity,
                    restore_kind="database",
                    backup_id=backup.id,
                    storage_point_id=stored_backup.id,
                    options=params,
                )
            )
        except LogicalRestoreRequestInvalid:
            raise ValidationError(
                {
                    "request_id": [
                        "Must be a canonical RFC 4122 version 4 UUID."
                    ]
                }
            )

        metadata = dict(metadata)
        metadata["api_request"] = api_request_metadata
        task_id = f"database-restore-{request_identity.correlation_id.hex}"
        try:
            restore, created = create_or_replay_logical_restore(
                restore_model=CoreDatabaseRestore,
                backup=backup,
                storage_point=stored_backup,
                correlation_id=request_identity.correlation_id,
                request_fingerprint=request_fingerprint,
                request_metadata=api_request_metadata,
                create_fields={
                    "name": f"Restore of {backup.uuid}",
                    "params": params,
                    "execution_metadata": metadata,
                    "execution_phase": "pending",
                    "progress_unit": "databases",
                    "celery_task_id": task_id,
                },
            )
        except LogicalRestoreRequestConflict:
            return Response(
                {
                    "detail": (
                        "This request_id belongs to a different restore request."
                    ),
                    "code": "restore_idempotency_conflict",
                },
                status=status.HTTP_409_CONFLICT,
            )
        except LogicalRestoreActiveExists:
            return Response(
                {
                    "detail": (
                        "A restore is already active for this source."
                    ),
                    "code": "active_restore_exists",
                },
                status=status.HTTP_409_CONFLICT,
            )

        if created:
            try:
                restore_database_backup.apply_async(
                    task_id=task_id,
                    kwargs={
                        "node_id": backup.database.node.id,
                        "backup_id": backup.id,
                        "restore_id": restore.id,
                    }
                )
            except Exception:
                # Never return broker/client exception bodies; they can contain
                # connection details or credentials from a misconfigured worker.
                raise RestoreCreateError()

        return Response(
            CoreDatabaseRestoreSerializer(restore).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def resume_restore(self, request, pk=None):
        """Resume verification for one proven existing logical fork.

        This action never starts a new restore request.  The locked durable row
        is the idempotency boundary: once it is active, every repeated request
        is a no-op and the restore worker reuses the original target mapping
        and checkpoints to reconcile the provider-side marker.
        """
        from apps._tasks.integration.restore import restore_database_backup

        backup = self.get_object()
        raw_restore_id = request.data.get("restore_id")
        if isinstance(raw_restore_id, bool):
            raw_restore_id = None
        try:
            restore_id = int(raw_restore_id)
        except (TypeError, ValueError, OverflowError):
            restore_id = 0
        if restore_id < 1:
            return Response(
                {
                    "code": "restore_id_required",
                    "detail": "A valid restore_id is required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        queued = False
        resume_sequence = None
        restore = None
        task_id = None
        try:
            with transaction.atomic():
                database = backup.database
                # Restore creation takes this same destination row lock. Keep
                # manual verification resumes in that lane so a failed restore
                # cannot be reactivated while another recovery point for this
                # logical database is already pending or in progress.
                type(database).objects.select_for_update().only("pk").get(
                    pk=database.pk
                )
                restore = (
                    CoreDatabaseRestore.objects.select_for_update()
                    .filter(pk=restore_id, backup=backup)
                    .first()
                )
                if restore is None:
                    return Response(
                        {
                            "code": "restore_not_found",
                            "detail": "The restore was not found for this backup.",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

                if restore.status == CoreDatabaseRestore.Status.IN_PROGRESS:
                    response_data = dict(CoreDatabaseRestoreSerializer(restore).data)
                    response_data.update(
                        {
                            "idempotent_replay": True,
                            "manual_resume_enqueued": False,
                            "code": "restore_resume_already_active",
                        }
                    )
                    return Response(response_data, status=status.HTTP_200_OK)

                if restore.status == CoreDatabaseRestore.Status.COMPLETE:
                    return Response(
                        {
                            "code": "restore_already_complete",
                            "detail": "The restore is already complete and was not changed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                if restore.status != CoreDatabaseRestore.Status.FAILED:
                    return Response(
                        {
                            "code": "restore_not_failed",
                            "detail": "Only failed logical restores can be resumed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                terminal_statuses = {
                    CoreDatabaseRestore.Status.COMPLETE,
                    CoreDatabaseRestore.Status.FAILED,
                }
                if (
                    CoreDatabaseRestore.objects.select_for_update()
                    .filter(backup__database_id=database.pk)
                    .exclude(pk=restore.pk)
                    .exclude(status__in=terminal_statuses)
                    .exists()
                ):
                    return Response(
                        {
                            "detail": (
                                "A restore is already active for this source."
                            ),
                            "code": "active_restore_exists",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                resume_mode = database_restore_verification_resume_mode(restore)
                if not resume_mode:
                    return Response(
                        {
                            "code": "restore_resume_not_safe",
                            "detail": (
                                "This failed restore does not contain the exact durable "
                                "fork mapping and checkpoint evidence required for safe verification."
                            ),
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                metadata = dict(restore.execution_metadata or {})
                raw_count = metadata.get("manual_resume_count", 0)
                if isinstance(raw_count, bool) or (
                    raw_count not in (None, "")
                    and not isinstance(raw_count, (int, str))
                ):
                    return Response(
                        {
                            "code": "restore_resume_state_invalid",
                            "detail": "The restore's bounded resume history is invalid.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                if raw_count in (None, ""):
                    previous_count = 0
                elif isinstance(raw_count, str) and not raw_count.isdecimal():
                    return Response(
                        {
                            "code": "restore_resume_state_invalid",
                            "detail": "The restore's bounded resume history is invalid.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                else:
                    try:
                        previous_count = int(raw_count)
                    except (TypeError, ValueError, OverflowError):
                        return Response(
                            {
                                "code": "restore_resume_state_invalid",
                                "detail": "The restore's bounded resume history is invalid.",
                            },
                            status=status.HTTP_409_CONFLICT,
                        )
                if previous_count < 0:
                    return Response(
                        {
                            "code": "restore_resume_state_invalid",
                            "detail": "The restore's bounded resume history is invalid.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                if previous_count >= _DATABASE_RESTORE_MANUAL_RESUME_MAX_COUNT:
                    return Response(
                        {
                            "code": "restore_manual_resume_limit_reached",
                            "detail": "This restore has reached its safe manual-resume limit.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                resume_sequence = previous_count + 1
                task_id = f"database-restore-resume-{restore.id}-{resume_sequence}"
                resumed_at = timezone.now().isoformat()
                history = metadata.get("manual_resume_history")
                if history is None:
                    history = []
                elif not isinstance(history, list) or any(
                    not isinstance(item, dict) for item in history
                ):
                    return Response(
                        {
                            "code": "restore_resume_state_invalid",
                            "detail": "The restore's bounded resume history is invalid.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                history.append(
                    {
                        "sequence": resume_sequence,
                        "requested_at": resumed_at,
                        "mode": resume_mode,
                        "task_id": task_id,
                    }
                )
                metadata["manual_resume_count"] = resume_sequence
                metadata["manual_resume_at"] = resumed_at
                metadata["manual_resume_task_id"] = task_id
                metadata["manual_resume_history"] = history[
                    -_DATABASE_RESTORE_MANUAL_RESUME_HISTORY_LIMIT:
                ]
                metadata.pop("failed_notification_enqueued_at", None)
                if restore.celery_task_id and not metadata.get("root_celery_task_id"):
                    metadata["root_celery_task_id"] = restore.celery_task_id

                # Only presentation/error rollups are cleared.  The fork mode,
                # target mapping, archive identity, and checkpoints are copied
                # unchanged and remain authoritative to the restore engine.
                params = dict(restore.params or {})
                params.pop("_bs_last_error_code", None)
                params.pop("_bs_last_error_category", None)
                restore.params = params
                restore.execution_metadata = metadata
                restore.status = CoreDatabaseRestore.Status.IN_PROGRESS
                restore.execution_phase = "database_reconciling"
                restore.error = None
                restore.last_error_code = ""
                restore.next_retry_at = None
                restore.lease_owner = ""
                restore.lease_token = None
                restore.lease_expires_at = None
                restore.heartbeat_at = None
                restore.save(
                    update_fields=[
                        "params",
                        "execution_metadata",
                        "status",
                        "execution_phase",
                        "error",
                        "last_error_code",
                        "next_retry_at",
                        "lease_owner",
                        "lease_token",
                        "lease_expires_at",
                        "heartbeat_at",
                        "modified",
                    ]
                )
                _log_activity(
                    request,
                    CoreLog.Type.RESTORE,
                    {
                        "message": "Logical restore verification resumed.",
                        "action": "database_restore_resume_verification",
                        "actor_email": request.user.email,
                        "restore_id": restore.id,
                        "restore_name": restore.name,
                        "backup_id": backup.id,
                        "backup_name": backup.name,
                        "resume_sequence": resume_sequence,
                        "resume_mode": resume_mode,
                    },
                )
                queued = True
                transaction.on_commit(
                    partial(
                        restore_database_backup.apply_async,
                        task_id=task_id,
                        kwargs={
                            "node_id": backup.database.node.id,
                            "backup_id": backup.id,
                            "restore_id": restore.id,
                        },
                    )
                )
        except Exception:
            # The durable transition is intentionally retained if the broker
            # acknowledgement is lost.  The normal restore recovery scheduler
            # will redeliver this same row; no provider/database request is
            # issued by this error path.
            if queued and resume_sequence is not None:
                durable = (
                    CoreDatabaseRestore.objects.filter(
                        pk=restore_id,
                        backup=backup,
                        execution_metadata__manual_resume_count=resume_sequence,
                    )
                    .first()
                )
                if durable is not None:
                    response_data = dict(CoreDatabaseRestoreSerializer(durable).data)
                    terminal = durable.status in {
                        CoreDatabaseRestore.Status.COMPLETE,
                        CoreDatabaseRestore.Status.FAILED,
                    }
                    response_data.update(
                        {
                            "idempotent_replay": False,
                            "manual_resume_enqueued": False,
                            "resume_sequence": resume_sequence,
                            "code": (
                                "restore_resume_reconciled"
                                if terminal
                                else "restore_resume_saved_for_recovery"
                            ),
                        }
                    )
                    return Response(
                        response_data,
                        status=(
                            status.HTTP_200_OK
                            if terminal
                            else status.HTTP_202_ACCEPTED
                        ),
                    )
            raise RestoreCreateError(
                "The restore resume request could not be accepted. Please retry safely."
            )

        response_data = dict(CoreDatabaseRestoreSerializer(restore).data)
        response_data.update(
            {
                "idempotent_replay": False,
                "manual_resume_enqueued": True,
                "resume_sequence": resume_sequence,
            }
        )
        return Response(response_data, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["get"])
    def restores(self, request, pk=None):
        backup = self.get_object()
        if request.query_params.get("scope") == "source":
            # Logical database restores share one destination lane across all
            # recovery points for this configured database. Keep the operator
            # ledger aligned with that server-side concurrency boundary.
            restores = CoreDatabaseRestore.objects.filter(
                Q(backup=backup)
                | Q(
                    backup__database_id=backup.database_id,
                    status__in=(
                        CoreDatabaseRestore.Status.PENDING,
                        CoreDatabaseRestore.Status.IN_PROGRESS,
                    ),
                )
            )
        else:
            restores = backup.restores.all()
        restores = restores.select_related("backup").order_by("-created")
        return Response(CoreDatabaseRestoreSerializer(restores, many=True).data)

    @action(detail=True)
    def download_transfer_log(self, request, pk=None):
        backup = self.get_object()
        # Self-hosted builds keep database run logs on the database lane's private
        # _storage volume (pruned by delete_old_database_logs); the historical
        # remote-log-bucket retrieval below is dead SaaS
        # infrastructure referencing settings that no longer exist. Return a clean message
        # instead of crashing. (See docs/troubleshooting.md.)
        return Response(
            {"detail": "Transfer log download is not available in the self-hosted build."},
            status=status.HTTP_404_NOT_FOUND,
        )

        date = parse_datetime("2023-01-01 19:0:0.000 -0000")
        date_aws_s3 = parse_datetime("2023-01-28 20:00:0.000 -0000")
        date_google_cloud = parse_datetime("2023-05-02 16:00:0.000 -0000")

        # NEW
        if backup.created > date_google_cloud:
            service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
            credentials = service_account.Credentials.from_service_account_info(service_key_json)
            storage_client = gc_storage.Client(credentials=credentials)
            bucket = storage_client.bucket(settings.AWS_S3_LOGS_BUCKET)
            blob = bucket.blob(f"{backup.uuid_str}.log")
            url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(hours=24),
                method="GET",
            )
            return Response({"url": url, "expire_in": int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))}, status=status.HTTP_201_CREATED)
        elif backup.created > date_aws_s3:
            s3_endpoint = f"https://{settings.AWS_S3_LOGS_ENDPOINT}"

            if "fra.idrivee" in s3_endpoint:
                access_key = settings.IDRIVE_FRA_ACCESS_KEY
                secret_key = settings.IDRIVE_FRA_SECRET_ACCESS_KEY
            else:
                access_key = settings.AWS_S3_ACCESS_KEY
                secret_key = settings.AWS_S3_SECRET_ACCESS_KEY

            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=s3_endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                config=Config(region_name=settings.AWS_S3_LOGS_REGION, signature_version="v4")
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_S3_LOGS_BUCKET,
                    "Key": f"{backup.uuid_str}.log",
                },
                ExpiresIn=int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600)),
            )
            return Response({"url": response, "expire_in": int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))}, status=status.HTTP_201_CREATED)
        elif date < backup.created < date_aws_s3:
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=settings.LOGS_S3_ENDPOINT,
                aws_access_key_id=settings.LOGS_S3_ACCESS_KEY_ID,
                aws_secret_access_key=settings.LOGS_S3_SECRET_ACCESS_KEY,
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.LOGS_S3_BUCKET,
                    "Key": f"{backup.uuid_str}.log",
                },
                ExpiresIn=int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600)),
            )
            response = response.replace(f"{settings.LOGS_S3_ENDPOINT}/logs", "https://logs.backupsheep.com")
            return Response({"url": response, "expire_in": int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))}, status=status.HTTP_201_CREATED)
        else:
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=settings.CEPH_S3_ENDPOINT,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_LOGS_BUCKET,
                    "Key": f"{backup.uuid_str}.log",
                },
                ExpiresIn=int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600)),
            )
            return Response({"url": response, "expire_in": int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))}, status=status.HTTP_201_CREATED)

    @action(detail=False)
    def highcharts(self, request):
        graph = {"categories": [], "series": []}
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)

        start_time = arrow.get(get_start_end_of_previous_day(days=30)["start_time"])
        end_time = arrow.get(get_start_end_of_previous_day(days=0)["start_time"])

        temp_data = []
        for r in arrow.Arrow.span_range("day", start_time.astimezone(timezone), end_time.astimezone(timezone)):
            backup_count = self.get_queryset().filter(
                created__gte=r[0].datetime,
                created__lte=r[1].datetime,
            ).count()

            temp_data.append(backup_count)

        graph["series"].append(
            {
                "name": "Database",
                "data": temp_data,
                "visible": True,
            }
        )

        # we need labels for the days.
        for r in arrow.Arrow.span_range("day", start_time, end_time):
            graph["categories"].append(r[0].format("MM/DD/YY"))

        return Response(graph)
