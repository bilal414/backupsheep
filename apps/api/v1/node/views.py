import hashlib
import hmac
import json
import math
import os
import shutil
import unicodedata
import uuid
from collections.abc import Mapping
from functools import partial

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.utils.api_helpers import visible_nodes
from apps.api.v1.utils.api_permissions import MemberGroupPermissions
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from .filters import CoreNodeFilter
from .serializers import CoreCloudRestoreSerializer, CoreNodeSerializer
from apps._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    SnapshotCreateNodeValidationFailed,
    SnapshotCreateNodeNotActive, NodeValidationFailed,
    RestoreMissingParams,
    RestoreBackupNotFound,
    RestoreUnsupportedNode,
    RestoreCreateError,
    RestoreConfirmationRequired,
)
from apps._tasks.integration.basecamp import backup_basecamp
from apps._tasks.integration.website import backup_website
from ..utils.api_filters import DateRangeFilter
from apps._tasks.helper.tasks import node_delete_requested


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


_CLOUD_RESTORE_ALLOWED_FIELDS = frozenset(
    {"backup_id", "name", "params", "confirm", "request_id"}
)
_CLOUD_RESTORE_MAX_NAME_LENGTH = 255
_CLOUD_RESTORE_MAX_KEY_LENGTH = 255
_CLOUD_RESTORE_MAX_BACKUP_ID = 2**63 - 1
_CLOUD_RESTORE_MAX_PARAM_DEPTH = 16
_CLOUD_RESTORE_MAX_PARAM_ITEMS = 1000
_CLOUD_RESTORE_MAX_PARAM_BYTES = 64 * 1024
_CLOUD_RESTORE_MISSING = object()
_CLOUD_RESTORE_MANUAL_RESUME_MAX_COUNT = 1000
_CLOUD_RESTORE_MANUAL_RESUME_HISTORY_LIMIT = 10


def _normalize_cloud_restore_params(value):
    """Return a canonical JSON-safe provider parameter mapping.

    Restore parameters are persisted and later interpreted by provider
    adapters.  Rejecting non-JSON values and reserved internal keys here keeps
    callers from forging the provider reconciliation markers that workers use
    for crash-safe adoption.
    """
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        return None

    budget = {"items": 0}

    def normalize(item, depth=0):
        if depth > _CLOUD_RESTORE_MAX_PARAM_DEPTH:
            raise ValueError
        budget["items"] += 1
        if budget["items"] > _CLOUD_RESTORE_MAX_PARAM_ITEMS:
            raise ValueError
        if isinstance(item, Mapping):
            normalized = {}
            for raw_key, raw_value in item.items():
                if not isinstance(raw_key, str):
                    raise ValueError
                key = unicodedata.normalize("NFKC", raw_key)
                if not key or key.startswith("_") or key in normalized:
                    raise ValueError
                normalized[key] = normalize(raw_value, depth + 1)
            return normalized
        if isinstance(item, (list, tuple)):
            return [normalize(child, depth + 1) for child in item]
        if isinstance(item, str):
            return unicodedata.normalize("NFKC", item)
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float) and math.isfinite(item):
            return item
        raise ValueError

    try:
        normalized = normalize(value)
        # Validate canonical serialization once here.  In particular, this
        # rejects values such as NaN even if a non-standard test client passes
        # them directly instead of through a JSON parser.
        canonical = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        if len(canonical.encode("utf-8")) > _CLOUD_RESTORE_MAX_PARAM_BYTES:
            raise ValueError
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None
    return normalized


def _normalize_cloud_restore_request(request):
    """Validate and normalize the immutable portion of a cloud restore POST."""
    data = request.data
    if not isinstance(data, Mapping):
        return None
    try:
        if set(data.keys()) - _CLOUD_RESTORE_ALLOWED_FIELDS:
            return None
    except TypeError:
        return None

    raw_backup_id = data.get("backup_id", _CLOUD_RESTORE_MISSING)
    if isinstance(raw_backup_id, bool):
        return None
    if isinstance(raw_backup_id, int):
        backup_id = raw_backup_id
    elif isinstance(raw_backup_id, str) and raw_backup_id.strip().isdigit():
        backup_id = int(raw_backup_id.strip())
    else:
        return None
    if backup_id < 1 or backup_id > _CLOUD_RESTORE_MAX_BACKUP_ID:
        return None

    raw_name = data.get("name", _CLOUD_RESTORE_MISSING)
    if not isinstance(raw_name, str):
        return None
    name = unicodedata.normalize("NFKC", raw_name).strip()
    if (
        not name
        or len(name) > _CLOUD_RESTORE_MAX_NAME_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        return None

    params = _normalize_cloud_restore_params(data.get("params"))
    if params is None:
        return None
    return backup_id, name, params


def _cloud_restore_idempotency_key(request):
    """Return a normalized opaque key and its explicit source.

    The HTTP header wins whenever it is present, including when it is empty or
    malformed.  That prevents a proxy/client disagreement from silently
    switching a retry to a different body request_id.
    """
    header_marker = object()
    supplied = request.META.get("HTTP_IDEMPOTENCY_KEY", header_marker)
    source = "header"
    if supplied is header_marker:
        if "request_id" in request.data:
            supplied = request.data.get("request_id")
            source = "body"
        else:
            supplied = uuid.uuid4().hex
            source = "generated"
    if not isinstance(supplied, str):
        return None, None
    key = unicodedata.normalize("NFKC", supplied).strip()
    if (
        not key
        or len(key) > _CLOUD_RESTORE_MAX_KEY_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in key)
    ):
        return None, None
    return key, source


def _cloud_restore_request_identity(node, request, payload=None):
    """Return a stable correlation id and immutable request fingerprint.

    A browser can retry a POST after losing the response.  Mapping the caller's
    idempotency key into a node-scoped UUID lets the database enforce one restore
    row without adding a provider mutation or trusting the message broker to
    deduplicate deliveries.
    """
    key, key_source = _cloud_restore_idempotency_key(request)
    if key is None:
        return None, None, None, None
    correlation_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"backupsheep:cloud-restore:node:{node.id}:{key}",
    )
    payload = payload or {
        "node_id": node.id,
        "backup_id": request.data.get("backup_id"),
        "name": request.data.get("name"),
        "params": request.data.get("params") or {},
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError):
        return None, None, None, None
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return correlation_id, fingerprint, key, key_source


class CoreNodeView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberGroupPermissions,)
    action_permissions = {
        "create": "node_changes",
        "update": "node_changes",
        "partial_update": "node_changes",
        "destroy": "node_changes",
        "pause": "node_changes",
        "resume": "node_changes",
        "delete": "node_changes",
        "reset_incremental": "node_changes",
        "take_snapshot": "backup_create",
        "restore_backup": "backup_create",
        "resume_restore": "backup_create",
    }
    serializer_class = CoreNodeSerializer
    all_fields = [f.name for f in CoreNode._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreNodeFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        return visible_nodes(member)

    def perform_create(self, serializer):
        node = serializer.save()
        _log_activity(
            self.request,
            CoreLog.Type.NODE,
            {
                "message": f"Node '{node.name}' created.",
                "action": "create",
                "actor_email": self.request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )

    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        nodes = visible_nodes(member)

        all_totals = {
            "combined": {
                "cloud": nodes.filter(type=CoreNode.Type.CLOUD).count(),
                "volume": nodes.filter(type=CoreNode.Type.VOLUME).count(),
                "website": nodes.filter(type=CoreNode.Type.WEBSITE).count(),
                "database": nodes.filter(type=CoreNode.Type.DATABASE).count(),
                "saas": nodes.filter(type=CoreNode.Type.SAAS).count(),
                "nodes": nodes.count(),
            }
        }
        return Response(all_totals)

    @action(detail=True, methods=["post"])
    def take_snapshot(self, request, pk=None):
        from apps._tasks.backup_dispatch import (
            backup_request_status,
            create_backup_request,
        )

        node = self.get_object()
        notes = self.request.data.get("notes")
        storage_point_ids = self.request.data.get("storage_point_ids")

        if not node.backup_ready_to_initiate():
            raise SnapshotCreateNodeNotActive(
                message="The node must be in ACTIVE status before you can request a snapshot."
            )
        elif node.type == CoreNode.Type.WEBSITE or node.type == CoreNode.Type.DATABASE or node.type == CoreNode.Type.SAAS:
            if not storage_point_ids:
                raise SnapshotCreateMissingParams()
        elif node.type == CoreNode.Type.CLOUD:
            node_type_object = getattr(node, node.connection.integration.code)
            if "validate" in dir(node_type_object):
                if not node_type_object.validate():
                    raise SnapshotCreateNodeValidationFailed()
        elif node.type == CoreNode.Type.VOLUME:
            node_type_object = getattr(node, node.connection.integration.code)
            if "validate" in dir(node_type_object):
                if not node_type_object.validate():
                    raise SnapshotCreateNodeValidationFailed()

        try:
            node = self.get_object()
            # backup_google_cloud(node.id, storage_ids=storage_point_ids)
            # backup_basecamp(node.id, storage_ids=storage_point_ids)
            # backup_website(node.id, storage_ids=storage_point_ids)

            idempotency_key = (
                request.headers.get("Idempotency-Key")
                or self.request.data.get("request_id")
            )
            backup_request = create_backup_request(
                node=node,
                storage_ids=storage_point_ids,
                notes=notes,
                requested_by=request.user.member,
                trigger="on_demand",
                idempotency_key=idempotency_key,
            )
            return Response(
                {
                    "detail": "Backup request accepted and durably queued.",
                    "backup_request": backup_request_status(backup_request),
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception:
            raise SnapshotCreateError(
                "The backup request could not be accepted. Please retry safely."
            )

    @action(detail=True, methods=["get"])
    def backup_request_status(self, request, pk=None):
        from apps._tasks.backup_dispatch import backup_request_status
        from apps.console.backup.models import CoreBackupRequest

        node = self.get_object()
        request_id = str(request.query_params.get("request_id") or "").strip()
        try:
            request_uuid = uuid.UUID(request_id)
        except (TypeError, ValueError):
            return Response(
                {"detail": "Backup request was not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        backup_request = CoreBackupRequest.objects.filter(
            node=node, correlation_id=request_uuid
        ).first()
        if backup_request is None:
            return Response(
                {"detail": "Backup request was not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(backup_request_status(backup_request))

    @action(detail=True, methods=["post"])
    def restore_backup(self, request, pk=None):
        from apps.console.backup.models import CoreCloudRestore
        from apps.console.utils.models import UtilBackup
        from apps._tasks.integration.restore import restore_cloud_backup

        node = self.get_object()
        if not isinstance(request.data, Mapping):
            raise RestoreMissingParams()
        normalized_request = _normalize_cloud_restore_request(request)
        if normalized_request is None:
            raise RestoreMissingParams()
        backup_id, name, params = normalized_request

        if node.type not in (CoreNode.Type.CLOUD, CoreNode.Type.VOLUME):
            raise RestoreUnsupportedNode()

        if request.data.get("confirm") is not True:
            raise RestoreConfirmationRequired(
                'Pass "confirm": true to create a new provider restore target. '
                "Existing provider resources are not changed, but the new resource may incur charges."
            )

        backup = node.get_cloud_backup(backup_id)
        if backup is None or backup.status != UtilBackup.Status.COMPLETE:
            raise RestoreBackupNotFound()

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
        if correlation_id is None:
            raise RestoreMissingParams(
                "The restore request id and provider parameters must be valid JSON values."
            )

        request_metadata = {
            "api_request": {
                "fingerprint": request_fingerprint,
                "key_source": key_source,
                "payload_version": 1,
                # Persist a digest instead of the caller's raw key.  Idempotency
                # keys sometimes contain session or integration identifiers.
                "idempotency_key_sha256": hashlib.sha256(
                    idempotency_key.encode("utf-8")
                ).hexdigest(),
            }
        }

        created = False
        dispatch_required = False
        try:
            with transaction.atomic():
                # Lock an existing row before comparing its immutable request
                # identity. If no row exists, the unique correlation_id
                # constraint arbitrates concurrent creators; the nested atomic
                # block keeps a losing IntegrityError inside a savepoint so the
                # winner can then be locked and replayed safely.
                restore = (
                    CoreCloudRestore.objects.select_for_update()
                    .filter(correlation_id=correlation_id)
                    .first()
                )
                if restore is None:
                    try:
                        with transaction.atomic():
                            restore = CoreCloudRestore.objects.create(
                                node=node,
                                correlation_id=correlation_id,
                                backup_id=backup.id,
                                name=name,
                                params=params,
                                execution_metadata=request_metadata,
                            )
                        created = True
                    except IntegrityError:
                        # A concurrent delivery may win the UUID uniqueness
                        # race. The following row lock serializes the replay.
                        restore = CoreCloudRestore.objects.select_for_update().get(
                            correlation_id=correlation_id
                        )

                stored_metadata = dict(restore.execution_metadata or {})
                stored_request = dict(stored_metadata.get("api_request") or {})
                # CoreCloudRestore.request_fingerprint is reserved for the
                # provider mutation/adoption witness and legitimately changes
                # when the provider adapter prepares a restore. Keep the HTTP
                # idempotency fingerprint in its own immutable metadata slot so
                # a lost-response replay still succeeds after provider work starts.
                stored_fingerprint = stored_request.get("fingerprint")
                if not created and not stored_fingerprint:
                    legacy_payload = {
                        "node_id": restore.node_id,
                        "backup_id": restore.backup_id,
                        "name": restore.name,
                        "params": restore.params or {},
                    }
                    stored_fingerprint = hashlib.sha256(
                        json.dumps(
                            legacy_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                            allow_nan=False,
                        ).encode("utf-8")
                    ).hexdigest()
                if (
                    restore.node_id != node.id
                    or restore.backup_id != backup.id
                    or not hmac.compare_digest(
                        str(stored_fingerprint or ""), request_fingerprint
                    )
                ):
                    return Response(
                        {
                            "detail": (
                                "This idempotency key belongs to a different restore request."
                            ),
                            "code": "restore_idempotency_conflict",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                task_id = restore.celery_task_id or (
                    f"cloud-restore-{restore.id}-{correlation_id.hex}"
                )
                if not restore.celery_task_id:
                    restore.celery_task_id = task_id
                    restore.save(update_fields=["celery_task_id", "modified"])
                    dispatch_required = True
                if created or dispatch_required:
                    transaction.on_commit(
                        partial(
                            restore_cloud_backup.apply_async,
                            task_id=task_id,
                            kwargs={
                                "node_id": node.id,
                                "backup_id": backup.id,
                                "restore_id": restore.id,
                            },
                        )
                    )
        except Exception:
            # A broker error can be raised by the post-commit callback. Check
            # durable state without trusting the exception text, which may
            # contain broker URLs or credentials.
            try:
                request_was_saved = CoreCloudRestore.objects.filter(
                    correlation_id=correlation_id,
                    celery_task_id__gt="",
                ).exists()
            except Exception:
                request_was_saved = False
            if request_was_saved:
                # The recovery scheduler redelivers stale pending rows using
                # the committed restore id and provider reconciliation fence.
                raise RestoreCreateError(
                    "The restore request was saved and will be retried automatically."
                )
            raise RestoreCreateError(
                "The restore request could not be accepted. Please retry safely."
            )

        if created:
            _log_activity(
                request,
                CoreLog.Type.RESTORE,
                {
                    "message": f"Restore '{restore.name}' requested for node '{node.name}'.",
                    "action": "restore_create",
                    "actor_email": request.user.email,
                    "restore_id": restore.id,
                    "restore_name": restore.name,
                    "node_id": node.id,
                    "node_name": node.name,
                    "backup_id": backup.id,
                    "backup_name": backup.name,
                },
            )
        response_data = dict(CoreCloudRestoreSerializer(restore).data)
        response_data["idempotent_replay"] = not created
        return Response(
            response_data,
            status=(status.HTTP_201_CREATED if created else status.HTTP_200_OK),
        )

    @action(detail=True, methods=["post"])
    def resume_restore(self, request, pk=None):
        """Resume read-only provider verification for one existing target.

        This action is deliberately separate from ``restore_backup``.  It may
        only move a failed/manual-review row with an already persisted provider
        pointer back to polling; it never invokes a provider create/restore
        endpoint.  The row lock and durable manual-resume sequence make two
        operator clicks converge on one Celery delivery.
        """
        from apps._tasks.integration.restore import poll_cloud_restore
        from apps.console.backup.models import CoreCloudRestore

        node = self.get_object()
        if not isinstance(request.data, Mapping) or set(request.data.keys()) != {
            "restore_id"
        }:
            return Response(
                {
                    "code": "restore_id_required",
                    "detail": "A single restore_id is required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

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
        task_id = None
        restore = None
        try:
            with transaction.atomic():
                # The node came from the account/group-scoped queryset above.
                # Requiring the restore to point back to that exact node prevents
                # an authenticated member from probing or operating another
                # account's restore by primary key.
                restore = (
                    CoreCloudRestore.objects.select_for_update()
                    .filter(pk=restore_id, node=node)
                    .first()
                )
                if restore is None:
                    return Response(
                        {
                            "code": "restore_not_found",
                            "detail": "The restore was not found for this node.",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

                # A second click after the first transaction committed is a
                # successful no-op. It must not create a second poll message or
                # increment the bounded operator history.
                if restore.status == CoreCloudRestore.Status.IN_PROGRESS:
                    response_data = dict(CoreCloudRestoreSerializer(restore).data)
                    response_data.update(
                        {
                            "idempotent_replay": True,
                            "manual_resume_enqueued": False,
                            "code": "restore_resume_already_active",
                        }
                    )
                    return Response(response_data, status=status.HTTP_200_OK)

                if restore.status == CoreCloudRestore.Status.COMPLETE:
                    return Response(
                        {
                            "code": "restore_already_complete",
                            "detail": "The restore is already complete and was not changed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                if not (
                    restore.status == CoreCloudRestore.Status.FAILED
                    and restore.operation_phase
                    == CoreCloudRestore.OperationPhase.MANUAL_REVIEW
                ):
                    return Response(
                        {
                            "code": "restore_not_manual_review",
                            "detail": "Only failed restores awaiting manual review can be resumed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                provider_pointer = str(
                    restore.resource_id or restore.provider_job_id or ""
                ).strip()
                if not provider_pointer:
                    return Response(
                        {
                            "code": "restore_provider_pointer_missing",
                            "detail": "This failed restore has no provider target to verify safely.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                metadata = dict(restore.execution_metadata or {})
                try:
                    previous_count = int(
                        metadata.get("manual_resume_count") or 0
                    )
                except (TypeError, ValueError, OverflowError):
                    previous_count = 0
                previous_count = max(0, previous_count)
                if previous_count >= _CLOUD_RESTORE_MANUAL_RESUME_MAX_COUNT:
                    return Response(
                        {
                            "code": "restore_manual_resume_limit_reached",
                            "detail": "This restore has reached its safe manual-resume limit.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                resume_sequence = previous_count + 1
                resumed_at = timezone.now().isoformat()
                history = metadata.get("manual_resume_history")
                if not isinstance(history, list):
                    history = []
                history = [item for item in history if isinstance(item, dict)]
                history.append(
                    {
                        "sequence": resume_sequence,
                        "requested_at": resumed_at,
                    }
                )
                metadata["manual_resume_count"] = resume_sequence
                metadata["manual_resume_at"] = resumed_at
                metadata["manual_resume_history"] = history[
                    -_CLOUD_RESTORE_MANUAL_RESUME_HISTORY_LIMIT:
                ]
                params = dict(restore.params or {})
                # These are presentation/error rollups, not provider identity
                # witnesses.  Keeping a terminal code while the exact target is
                # actively being verified makes the UI report a failure and a
                # running restore at the same time.
                params.pop("_bs_last_error_code", None)
                params.pop("_bs_last_error_category", None)
                # Keep the original request task identity available even after
                # a poll delivery claims a worker lease. The model field itself
                # is intentionally not rewritten by this operator action.
                if restore.celery_task_id and not metadata.get("root_celery_task_id"):
                    metadata["root_celery_task_id"] = restore.celery_task_id

                task_id = f"cloud-restore-resume-{restore.id}-{resume_sequence}"
                restore.execution_metadata = metadata
                restore.params = params
                restore.status = CoreCloudRestore.Status.IN_PROGRESS
                restore.operation_phase = CoreCloudRestore.OperationPhase.POLLING
                restore.execution_phase = "provider_polling"
                restore.error = None
                restore.last_error_code = ""
                restore.next_retry_at = None
                # Fence any stale failed-worker lease before the read-only poll
                # is delivered. The poll task will claim a fresh lease.
                restore.lease_owner = ""
                restore.lease_token = None
                restore.lease_expires_at = None
                restore.heartbeat_at = None
                restore.save(
                    update_fields=[
                        "execution_metadata",
                        "params",
                        "status",
                        "operation_phase",
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
                        "message": f"Restore verification resumed for node '{node.name}'.",
                        "action": "restore_resume_verification",
                        "actor_email": request.user.email,
                        "restore_id": restore.id,
                        "restore_name": restore.name,
                        "node_id": node.id,
                        "node_name": node.name,
                        "resume_sequence": resume_sequence,
                    },
                )
                queued = True
                transaction.on_commit(
                    partial(
                        poll_cloud_restore.apply_async,
                        task_id=task_id,
                        args=[node.id, restore.id],
                    )
                )
        except Exception:
            # The database transition is committed before on_commit callbacks
            # publish to Celery. If the broker acknowledgement is lost, leave
            # the active row for resume_in_progress_restores and return only a
            # safe recovery message; a repeat click remains idempotent.
            if queued and resume_sequence is not None:
                durable = (
                    CoreCloudRestore.objects.filter(
                        pk=restore_id,
                        node=node,
                        execution_metadata__manual_resume_count=resume_sequence,
                    )
                    .first()
                )
                if durable is not None:
                    response_data = dict(CoreCloudRestoreSerializer(durable).data)
                    terminal = durable.status in {
                        CoreCloudRestore.Status.COMPLETE,
                        CoreCloudRestore.Status.FAILED,
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

        response_data = dict(CoreCloudRestoreSerializer(restore).data)
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
        from apps.console.backup.models import CoreCloudRestore

        node = self.get_object()
        restores = CoreCloudRestore.objects.filter(node=node).order_by("-created")
        return Response(CoreCloudRestoreSerializer(restores, many=True).data)

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        node = self.get_object()
        node.status = CoreNode.Status.PAUSED
        node.save()
        _log_activity(
            request,
            CoreLog.Type.NODE,
            {
                "message": f"Node '{node.name}' paused.",
                "action": "pause",
                "actor_email": request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )
        data = self.get_serializer(node).data
        data["detail"] = "Node is paused."
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        node = self.get_object()
        node.status = CoreNode.Status.ACTIVE
        node.save()
        _log_activity(
            request,
            CoreLog.Type.NODE,
            {
                "message": f"Node '{node.name}' resumed.",
                "action": "resume",
                "actor_email": request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )
        data = self.get_serializer(node).data
        data["detail"] = "Node is resumed."
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def delete(self, request, pk=None):
        node = self.get_object()
        node.status = CoreNode.Status.DELETE_REQUESTED
        node.save()

        """
        Delete Node
        """
        node_delete_requested.apply_async(
            args=[node.id],
        )

        _log_activity(
            request,
            CoreLog.Type.NODE,
            {
                "message": f"Node '{node.name}' delete requested.",
                "action": "delete",
                "actor_email": request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )
        return Response({"detail": "Node will be deleted soon."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reset_incremental(self, request, pk=None):
        node = self.get_object()
        # Wipe the per-node local mirror cache (and its fingerprint) so the next
        # incremental backup re-downloads everything. Confined to _storage.
        storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
        cache_base = os.path.realpath(os.path.join(storage_dir, "website_cache", node.uuid_str))
        if cache_base != storage_dir and os.path.commonpath([storage_dir, cache_base]) == storage_dir:
            shutil.rmtree(cache_base, ignore_errors=True)
            try:
                os.remove(cache_base + ".meta.json")
            except FileNotFoundError:
                pass
        _log_activity(
            request,
            CoreLog.Type.NODE,
            {
                "message": f"Incremental backups reset for node '{node.name}'.",
                "action": "reset_incremental",
                "actor_email": request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )
        return Response({"detail": "We have reset the incremental backups. Your next backup will be a full backup."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        try:
            validation = self.get_object().validate()
            if validation:
                return Response({"detail": "Validation passed. Node is good for backups."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Validation failed. Backups will fail. Check if node exists and status is active."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise NodeValidationFailed(e.__str__())
