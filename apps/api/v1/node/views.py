import hashlib
import hmac
import json
import math
import re
import unicodedata
import uuid
from collections.abc import Mapping
from functools import partial

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
from .serializers import (
    CoreCloudRestoreSerializer,
    CoreNodeSerializer,
    CoreVultrDatabaseRestoreSerializer,
)
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
from apps._tasks.helper.tasks import (
    LOCAL_NODE_INTEGRATIONS,
    delete_cloud_node_requested,
    delete_local_node_requested,
    reset_incremental_cache,
)
from backupsheep.source_recovery_policy import require_source_backup_creation


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


_CLOUD_RESTORE_ALLOWED_FIELDS = frozenset(
    {"backup_id", "name", "params", "confirm", "request_id", "recovery_id"}
)
_CLOUD_RESTORE_MAX_NAME_LENGTH = 255
_CLOUD_RESTORE_MAX_KEY_LENGTH = 255
_CLOUD_RESTORE_MAX_BACKUP_ID = 2**63 - 1
_CLOUD_RESTORE_MAX_PARAM_DEPTH = 16
_CLOUD_RESTORE_MAX_PARAM_ITEMS = 1000
_CLOUD_RESTORE_MAX_PARAM_BYTES = 64 * 1024
_CLOUD_RESTORE_MISSING = object()
_CLOUD_RESTORE_INVALID = object()
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


_ORACLE_RESTORE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_ORACLE_RESTORE_SHAPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_ORACLE_RESTORE_OCID_RE = re.compile(
    r"ocid1\.[a-z0-9-]+\.[A-Za-z0-9._:-]{1,1000}\Z"
)


def _oracle_restore_rejected():
    raise RestoreMissingParams(
        "Oracle restore parameters must prove the exact source backup and stay "
        "within the linked resource's discovered compartment and availability domain."
    )


def _oracle_restore_ocid(value, resource_type):
    if not isinstance(value, str):
        _oracle_restore_rejected()
    value = value.strip()
    if not _ORACLE_RESTORE_OCID_RE.fullmatch(value):
        _oracle_restore_rejected()
    if not value.startswith(f"ocid1.{resource_type}."):
        _oracle_restore_rejected()
    return value


def _validate_oracle_restore_request(node, backup, name, params):
    """Validate the immutable Oracle restore scope before creating a row.

    OCI restore requests are deliberately narrower than the generic cloud
    restore payload.  The linked node's discovery metadata is the scope
    authority; a caller cannot redirect a restore to another compartment or
    availability domain, nor forge the source backup witness that the worker
    will use for provider reconciliation.
    """

    if node.connection.integration.code != "oracle":
        return params
    if node.type not in (CoreNode.Type.CLOUD, CoreNode.Type.VOLUME):
        _oracle_restore_rejected()
    if not isinstance(params, dict):
        _oracle_restore_rejected()
    oracle = getattr(node, "oracle", None)
    oracle_metadata = dict(getattr(oracle, "metadata", None) or {})
    expected_compartment = _oracle_restore_ocid(
        oracle_metadata.get("_bs_compartment_id"), "compartment"
    )
    expected_ad = oracle_metadata.get("_bs_availability_domain")
    if (
        not isinstance(expected_ad, str)
        or not expected_ad.strip()
        or len(expected_ad.strip()) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in expected_ad)
    ):
        _oracle_restore_rejected()
    expected_ad = expected_ad.strip()

    if (
        not isinstance(name, str)
        or not _ORACLE_RESTORE_NAME_RE.fullmatch(name)
    ):
        _oracle_restore_rejected()

    required_fields = {"compartment_id", "availability_domain"}
    if node.type == CoreNode.Type.CLOUD:
        allowed_fields = required_fields | {
            "shape",
            "subnet_id",
            "assign_public_ip",
        }
    else:
        allowed_fields = required_fields
    if set(params) - allowed_fields or not required_fields.issubset(params):
        _oracle_restore_rejected()

    supplied_compartment = _oracle_restore_ocid(
        params.get("compartment_id"), "compartment"
    )
    supplied_ad = params.get("availability_domain")
    if not isinstance(supplied_ad, str) or supplied_ad.strip() != expected_ad:
        _oracle_restore_rejected()
    if supplied_compartment != expected_compartment:
        _oracle_restore_rejected()

    if node.type == CoreNode.Type.CLOUD:
        shape = params.get("shape")
        subnet_id = _oracle_restore_ocid(params.get("subnet_id"), "subnet")
        if not isinstance(shape, str) or not _ORACLE_RESTORE_SHAPE_RE.fullmatch(
            shape.strip()
        ):
            _oracle_restore_rejected()
        if "assign_public_ip" in params and not isinstance(
            params["assign_public_ip"], bool
        ):
            _oracle_restore_rejected()
        params = dict(params)
        params["compartment_id"] = supplied_compartment
        params["availability_domain"] = expected_ad
        params["shape"] = shape.strip()
        params["subnet_id"] = subnet_id
    else:
        params = dict(params)
        params["compartment_id"] = supplied_compartment
        params["availability_domain"] = expected_ad

    from apps._tasks.integration.oracle import oracle_retry_token

    state = backup.get_execution_state(create=False)
    provider_metadata = dict(state.provider_metadata or {}) if state else {}
    witness = provider_metadata.get("witness")
    marker = str(getattr(backup, "uuid_str", "") or "").strip()
    source_id = str(getattr(oracle, "unique_id", "") or "").strip()
    request_token = oracle_retry_token(marker) if marker else ""
    if (
        not state
        or not isinstance(witness, dict)
        or witness.get("provider") != "oracle"
        or str(witness.get("marker") or "") != marker
        or str(witness.get("source_id") or "") != source_id
        or str(witness.get("compartment_id") or "") != expected_compartment
        or str(witness.get("request_token") or "") != request_token
        or str(state.provider_resource_id or "") != str(backup.unique_id or "")
        or str(state.provider_idempotency_key or "") != request_token
    ):
        _oracle_restore_rejected()

    if node.type == CoreNode.Type.CLOUD:
        if (
            witness.get("resource_type") != "compute_image"
            or not str(backup.unique_id or "").startswith("ocid1.image.")
        ):
            _oracle_restore_rejected()
    else:
        volume_type = str(witness.get("volume_type") or "")
        expected_volume_type = str(
            oracle_metadata.get("_bs_vol_type") or ""
        ).casefold()
        expected_backup_type = (
            "bootvolumebackup" if volume_type == "boot" else "volumebackup"
        )
        if (
            volume_type not in {"boot", "block"}
            or volume_type != expected_volume_type
            or not str(backup.unique_id or "").startswith(
                f"ocid1.{expected_backup_type}."
            )
        ):
            _oracle_restore_rejected()
    return params


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


def _cloud_restore_recovery_id(request):
    """Return the browser's canonical, non-secret recovery identifier.

    ``crypto.randomUUID()`` produces a lowercase RFC4122 version-4 UUID. Keep
    this contract strict so the public adoption key cannot contain arbitrary
    caller text or a provider/API secret. The value is independent from the
    opaque idempotency key used to derive the node-scoped UUIDv5 correlation.
    """
    raw = request.data.get("recovery_id", _CLOUD_RESTORE_MISSING)
    if raw is _CLOUD_RESTORE_MISSING:
        return None
    if not isinstance(raw, str):
        return _CLOUD_RESTORE_INVALID
    try:
        parsed = uuid.UUID(raw)
    except (AttributeError, TypeError, ValueError):
        return _CLOUD_RESTORE_INVALID
    if (
        parsed.version != 4
        or parsed.variant != uuid.RFC_4122
        or str(parsed) != raw
    ):
        return _CLOUD_RESTORE_INVALID
    return str(parsed)


def _cloud_restore_request_identity(node, request, payload=None):
    """Return a stable correlation id, fingerprint, and safe recovery id.

    A browser can retry a POST after losing the response.  Mapping the caller's
    idempotency key into a node-scoped UUID lets the database enforce one restore
    row without adding a provider mutation or trusting the message broker to
    deduplicate deliveries. The independent recovery id is included in the
    immutable request fingerprint and is safe to return to the browser for
    exact lost-response adoption.
    """
    key, key_source = _cloud_restore_idempotency_key(request)
    recovery_id = _cloud_restore_recovery_id(request)
    if key is None or recovery_id is _CLOUD_RESTORE_INVALID:
        return None, None, None, None, None
    correlation_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"backupsheep:cloud-restore:node:{node.id}:{key}",
    )
    payload = dict(payload or {
        "node_id": node.id,
        "backup_id": request.data.get("backup_id"),
        "name": request.data.get("name"),
        "params": request.data.get("params") or {},
    })
    # Preserve the pre-recovery_id canonical bytes for legacy clients and rows.
    # A supplied strict UUID is the only value that becomes part of the new
    # immutable identity.
    if recovery_id is not None:
        payload["recovery_id"] = recovery_id
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError):
        return None, None, None, None, None
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return correlation_id, fingerprint, key, key_source, recovery_id


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
        "validate": "backup_create",
        "take_snapshot": "backup_create",
        "restore_backup": "backup_restore",
        "resume_restore": "backup_restore",
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
        # While the storage worker owns deletion, no interactive endpoint may
        # resume/update the node and race its provider or Local Storage cleanup.
        # A protected backup restores the node to visible PAUSED state.
        return visible_nodes(member).exclude(status=CoreNode.Status.DELETE_REQUESTED)

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
        require_source_backup_creation(node.connection.integration.code)
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
        from apps.console.backup.models import (
            CoreCloudRestore,
            CoreVultrDatabaseRestore,
        )
        from apps.console.utils.models import UtilBackup
        from apps._tasks.integration.restore import restore_cloud_backup
        from apps.api.v1.backup.vultr_database.restore_requests import (
            VultrDatabaseRestoreRequestConflict,
            create_or_replay_vultr_database_restore,
        )

        node = self.get_object()
        is_vultr_managed_database = (
            node.connection.integration.code == "vultr"
            and hasattr(node, "vultr_database")
        )
        if not isinstance(request.data, Mapping):
            raise RestoreMissingParams()
        normalized_request = _normalize_cloud_restore_request(request)
        if normalized_request is None:
            raise RestoreMissingParams()
        backup_id, name, params = normalized_request

        if (
            node.type not in (CoreNode.Type.CLOUD, CoreNode.Type.VOLUME)
            and not is_vultr_managed_database
        ):
            raise RestoreUnsupportedNode()

        if request.data.get("confirm") is not True:
            raise RestoreConfirmationRequired(
                'Pass "confirm": true to create a new provider restore target. '
                "Existing provider resources are not changed, but the new resource may incur charges."
            )

        backup = node.get_cloud_backup(backup_id)
        if backup is None or backup.status != UtilBackup.Status.COMPLETE:
            raise RestoreBackupNotFound()
        if node.connection.integration.code == "oracle":
            params = _validate_oracle_restore_request(node, backup, name, params)

        (
            correlation_id,
            request_fingerprint,
            idempotency_key,
            key_source,
            recovery_id,
        ) = (
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

        api_request_metadata = {
            "fingerprint": request_fingerprint,
            "key_source": key_source,
            "payload_version": 1,
            # Persist a digest instead of the caller's raw key. Idempotency
            # keys sometimes contain session or integration identifiers.
            "idempotency_key_sha256": hashlib.sha256(
                idempotency_key.encode("utf-8")
            ).hexdigest(),
        }
        if recovery_id is not None:
            # This is the browser-generated public adoption key. It is
            # strict/canonical by construction; never store the raw
            # Idempotency-Key, only its digest above.
            api_request_metadata["recovery_id"] = recovery_id
        request_metadata = {"api_request": api_request_metadata}

        if is_vultr_managed_database:
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
                try:
                    request_was_saved = CoreVultrDatabaseRestore.objects.filter(
                        correlation_id=correlation_id,
                        celery_task_id__gt="",
                    ).exists()
                except Exception:
                    request_was_saved = False
                if request_was_saved:
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
            response_data = dict(
                CoreVultrDatabaseRestoreSerializer(restore).data
            )
            response_data["idempotent_replay"] = not created
            return Response(
                response_data,
                status=(
                    status.HTTP_201_CREATED if created else status.HTTP_200_OK
                ),
            )

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

    def _resume_vultr_database_restore(self, request, node, restore_id):
        """Resume read-only verification for one known Vultr fork target."""

        from apps._tasks.integration.vultr_database import (
            poll_vultr_database_restore,
        )
        from apps.console.backup.models import CoreVultrDatabaseRestore

        queued = False
        resume_sequence = None
        restore = None
        try:
            with transaction.atomic():
                restore = (
                    CoreVultrDatabaseRestore.objects.select_for_update()
                    .filter(
                        pk=restore_id,
                        backup__vultr_database__node=node,
                    )
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
                if restore.status == CoreVultrDatabaseRestore.Status.IN_PROGRESS:
                    response_data = dict(
                        CoreVultrDatabaseRestoreSerializer(restore).data
                    )
                    response_data.update(
                        {
                            "idempotent_replay": True,
                            "manual_resume_enqueued": False,
                            "code": "restore_resume_already_active",
                        }
                    )
                    return Response(response_data, status=status.HTTP_200_OK)
                if restore.status == CoreVultrDatabaseRestore.Status.COMPLETE:
                    return Response(
                        {
                            "code": "restore_already_complete",
                            "detail": "The restore is already complete and was not changed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                if not (
                    restore.status == CoreVultrDatabaseRestore.Status.FAILED
                    and restore.execution_phase == "manual_review"
                ):
                    return Response(
                        {
                            "code": "restore_not_manual_review",
                            "detail": "Only failed restores awaiting manual review can be resumed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
                if not str(
                    restore.resource_id or restore.provider_job_id or ""
                ).strip():
                    return Response(
                        {
                            "code": "restore_provider_pointer_missing",
                            "detail": "This failed restore has no provider target to verify safely.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                metadata = dict(restore.execution_metadata or {})
                try:
                    previous_count = max(
                        0, int(metadata.get("manual_resume_count") or 0)
                    )
                except (TypeError, ValueError, OverflowError):
                    previous_count = 0
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
                    {"sequence": resume_sequence, "requested_at": resumed_at}
                )
                metadata["manual_resume_count"] = resume_sequence
                metadata["manual_resume_at"] = resumed_at
                metadata["manual_resume_history"] = history[
                    -_CLOUD_RESTORE_MANUAL_RESUME_HISTORY_LIMIT:
                ]
                if restore.celery_task_id and not metadata.get(
                    "root_celery_task_id"
                ):
                    metadata["root_celery_task_id"] = restore.celery_task_id

                task_id = f"vultr-db-restore-resume-{restore.id}-{resume_sequence}"
                restore.execution_metadata = metadata
                restore.status = CoreVultrDatabaseRestore.Status.IN_PROGRESS
                restore.execution_phase = "vultr_database_poll"
                restore.provider_status = "reconciling"
                restore.error = None
                restore.last_error_code = ""
                restore.next_retry_at = None
                restore.lease_owner = ""
                restore.lease_token = None
                restore.lease_expires_at = None
                restore.heartbeat_at = None
                restore.save(
                    update_fields=[
                        "execution_metadata",
                        "status",
                        "execution_phase",
                        "provider_status",
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
                queued = True
                transaction.on_commit(
                    partial(
                        poll_vultr_database_restore.apply_async,
                        task_id=task_id,
                        args=[restore.id],
                    )
                )
        except Exception:
            if queued and resume_sequence is not None:
                durable = CoreVultrDatabaseRestore.objects.filter(
                    pk=restore_id,
                    backup__vultr_database__node=node,
                    execution_metadata__manual_resume_count=resume_sequence,
                ).first()
                if durable is not None:
                    response_data = dict(
                        CoreVultrDatabaseRestoreSerializer(durable).data
                    )
                    response_data.update(
                        {
                            "idempotent_replay": False,
                            "manual_resume_enqueued": False,
                            "resume_sequence": resume_sequence,
                            "code": "restore_resume_saved_for_recovery",
                        }
                    )
                    return Response(
                        response_data, status=status.HTTP_202_ACCEPTED
                    )
            raise RestoreCreateError(
                "The restore resume request could not be accepted. Please retry safely."
            )

        response_data = dict(CoreVultrDatabaseRestoreSerializer(restore).data)
        response_data.update(
            {
                "idempotent_replay": False,
                "manual_resume_enqueued": True,
                "resume_sequence": resume_sequence,
            }
        )
        return Response(response_data, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["post"])
    def resume_restore(self, request, pk=None):
        """Resume read-only provider verification for one durable request.

        This action is deliberately separate from ``restore_backup``. It moves
        one failed row back to the existing provider state machine. Most modes
        are read-only polling/reconciliation. A strictly proven UpCloud server
        request that the provider definitively rejected may retry that same row
        after a complete zero-match scan. The row lock and durable sequence make
        two operator clicks converge on one Celery delivery.
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

        if (
            node.connection.integration.code == "vultr"
            and hasattr(node, "vultr_database")
        ):
            return self._resume_vultr_database_restore(
                request, node, restore_id
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

                if restore.status != CoreCloudRestore.Status.FAILED:
                    return Response(
                        {
                            "code": "restore_not_failed",
                            "detail": "Only failed restores can be resumed.",
                        },
                        status=status.HTTP_409_CONFLICT,
                    )

                resume_mode = restore.verification_resume_mode
                if not resume_mode:
                    return Response(
                        {
                            "code": "restore_not_safely_resumable",
                            "detail": (
                                "This failed restore has no exact provider target, "
                                "unknown-outcome identity, or proven rejected request "
                                "that can be resumed safely."
                            ),
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
                        "mode": resume_mode,
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
                if resume_mode in {"provider_reconciliation", "provider_retry"}:
                    restore.operation_phase = (
                        CoreCloudRestore.OperationPhase.RECONCILING
                    )
                    restore.execution_phase = "provider_reconciling"
                else:
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
                        "resume_mode": resume_mode,
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
                "resume_mode": resume_mode,
            }
        )
        return Response(response_data, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["get"])
    def restores(self, request, pk=None):
        from apps.console.backup.models import (
            CoreCloudRestore,
            CoreVultrDatabaseRestore,
        )

        node = self.get_object()
        if (
            node.connection.integration.code == "vultr"
            and hasattr(node, "vultr_database")
        ):
            restores = CoreVultrDatabaseRestore.objects.filter(
                backup__vultr_database__node=node
            ).order_by("-created")
            return Response(
                CoreVultrDatabaseRestoreSerializer(restores, many=True).data
            )
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
        require_source_backup_creation(node.connection.integration.code)
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
        with transaction.atomic():
            # Serialize schedule removal and the durable deletion phase. Only the
            # web control plane has Beat DML; no compromised worker can erase or
            # rewrite a universal scheduler row while deleting a node.
            node = (
                CoreNode.objects.select_for_update()
                .select_related("connection__integration")
                .get(pk=node.pk)
            )
            for schedule in node.schedules.select_related(
                "celery_periodic_task"
            ).order_by("pk"):
                schedule.schedule_delete()
                schedule.delete()
            node.status = CoreNode.Status.DELETE_REQUESTED
            node.flag_delete_node = True
            node.save(
                update_fields=["status", "flag_delete_node", "modified"]
            )
            deletion_task = (
                delete_local_node_requested
                if node.connection.integration.code in LOCAL_NODE_INTEGRATIONS
                else delete_cloud_node_requested
            )
            node_id = node.pk

        def publish_delete():
            try:
                # Only the already-authorized row id crosses the broker boundary.
                # Lane-specific sweeps recover a failed publication from the
                # durable status + flag_delete_node phase.
                deletion_task.apply_async(args=[node_id])
            except Exception:
                pass

        transaction.on_commit(publish_delete)

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
        return Response(
            {"detail": "Node deletion was scheduled on its isolated worker."},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"])
    def reset_incremental(self, request, pk=None):
        node = self.get_object()
        if node.type != CoreNode.Type.WEBSITE:
            return Response(
                {"detail": "Incremental cache reset is available only for website nodes."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # The HTTP role has no source workdir. Dispatch the exact cache mutation to
        # the files worker, which exclusively owns the website mirror and its lock.
        reset_incremental_cache.apply_async(args=[node.pk])
        _log_activity(
            request,
            CoreLog.Type.NODE,
            {
                "message": f"Incremental backup cache reset scheduled for node '{node.name}'.",
                "action": "reset_incremental",
                "actor_email": request.user.email,
                "node_id": node.id,
                "node_name": node.name,
                "connection_id": node.connection_id,
                "connection_name": node.connection.name,
            },
        )
        return Response(
            {
                "detail": (
                    "Incremental cache reset scheduled. Your next backup will be "
                    "a full backup after the files worker applies it."
                )
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def validate(self, request, pk=None):
        try:
            validation = self.get_object().validate()
            if validation:
                return Response(
                    {
                        "detail": (
                            "The provider source is currently reachable and active. "
                            "No backup or recovery was tested."
                        )
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "detail": (
                            "The provider source could not be confirmed reachable and active. "
                            "Review its current existence, status, and access before retrying."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            raise NodeValidationFailed(e.__str__())
