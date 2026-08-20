import re
import uuid
from datetime import timezone as datetime_timezone

from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from rest_framework import serializers

from apps.console.backup.models import CoreBackupArtifact, CoreBackupExecution
from apps.console.node.models import CoreWebsite, CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorageType, CoreStorage
from apps.console.utils.models import UtilBackup


_PUBLIC_RECONCILIATION_STATES = {
    "none",
    "required",
    "in_progress",
    "resolved",
    "manual_review",
}
_PUBLIC_PHASES = {
    "pending",
    "preparing",
    "capturing",
    "source_ready",
    "validating",
    "uploading",
    "reconciling",
    "polling",
    "restoring",
    "retrying",
    "complete",
    "failed",
    "manual_review",
    "cancelled",
    "in_progress",
    "website_mirroring",
    "website_enumerating",
    "website_archiving",
    "website_archive_publishing",
    "unknown",
}
_PUBLIC_BACKUP_STAGES = {
    "website_mirroring",
    "website_enumerating",
    "website_archiving",
    "website_archive_publishing",
}

# Legacy backup/restore rows pre-date the durable execution ledger. Their parent
# status is still authoritative for terminal outcomes, and a few intermediate
# statuses describe a product stage more precisely than substring matching can.
_LEGACY_STATUS_PHASES = {
    "pending": "pending",
    "in_progress": "in_progress",
    "complete": "complete",
    "failed": "failed",
    "retrying": "retrying",
    "started": "preparing",
    "max_retries_failed": "failed",
    "ready_for_upload": "source_ready",
    "upload_in_progress": "uploading",
    "upload_complete": "validating",
    "upload_validation": "validating",
    "partial": "complete",
    "partial_some_destinations_failed": "complete",
    "upload_failed": "failed",
    "delete_requested": "preparing",
    "delete_in_progress": "in_progress",
    "delete_completed": "complete",
    "delete_failed": "failed",
    "delete_failed_not_found": "failed",
    "delete_max_retries_failed": "failed",
    "download_in_progress": "capturing",
    "download_complete": "source_ready",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "timeout": "failed",
    "storage_validation_failed": "failed",
}
_TERMINAL_STATUS_PHASES = {
    status: phase
    for status, phase in _LEGACY_STATUS_PHASES.items()
    if status
    in {
        "complete",
        "failed",
        "max_retries_failed",
        "partial",
        "partial_some_destinations_failed",
        "upload_failed",
        "delete_completed",
        "delete_failed",
        "delete_failed_not_found",
        "delete_max_retries_failed",
        "cancelled",
        "canceled",
        "timeout",
        "storage_validation_failed",
    }
}
_AUTHORITATIVE_ACTIVE_STATUS_PHASES = {
    "ready_for_upload": "source_ready",
    "download_complete": "source_ready",
    "upload_in_progress": "uploading",
    "upload_complete": "validating",
    "upload_validation": "validating",
}
# Restore engines persist detailed component checkpoints while the parent
# restore row is still active.  In particular, ``database_complete`` and
# ``website_complete`` mean that one component finished; they are not terminal
# restore outcomes.  Keep these aliases explicit so substring matching cannot
# stop a polling client before the parent status becomes terminal.
_DURABLE_RESTORE_PHASE_ALIASES = {
    "archive_validated": "validating",
    "database_permissions_verified": "validating",
    "database_ready": "validating",
    "database_importing": "restoring",
    "database_importing_file": "restoring",
    "database_replaying": "restoring",
    "database_adopted": "restoring",
    "database_complete": "restoring",
    "database_restore_complete": "restoring",
    "website_transferring": "restoring",
    "website_staging": "restoring",
    "website_staged": "restoring",
    "website_publishing": "restoring",
    "website_cleanup_pending": "restoring",
    "website_complete": "restoring",
}
_PUBLIC_PROVIDER_STATUSES = {
    "active",
    "archive",
    "available",
    "archived",
    "backing-up",
    "cancelled",
    "canceled",
    "complete",
    "completed",
    "configuring-enhanced-monitoring",
    "configuring-iam-database-auth",
    "configuring-log-exports",
    "converting-to-vpc",
    "created",
    "creating",
    "degraded",
    "delete-precheck",
    "deleted",
    "deleting",
    "destroyed",
    "error",
    "failed",
    "in-use",
    "in_progress",
    "inaccessible-encryption-credentials",
    "inaccessible-encryption-credentials-recoverable",
    "incompatible-create",
    "incompatible-network",
    "incompatible-option-group",
    "incompatible-parameters",
    "incompatible-restore",
    "insufficient-capacity",
    "installing",
    "locked",
    "maintenance",
    "modifying",
    "moving-to-vpc",
    "new",
    "not_found",
    "off",
    "offline",
    "online",
    "pending",
    "polling",
    "provisioning",
    "queued",
    "rate_limited",
    "ready",
    "rebooting",
    "reconciling",
    "renaming",
    "resetting-master-credentials",
    "restore-error",
    "restoring",
    "running",
    "started",
    "starting",
    "stopped",
    "stopping",
    "storage-config-upgrade",
    "storage-full",
    "storage-initialization",
    "storage-optimization",
    "succeeded",
    "success",
    "suspended",
    "terminal_failure",
    "terminated",
    "terminating",
    "timeout",
    "transient_outage",
    "unknown",
    "updating",
    "upgrade-failed",
    "upgrading",
}
_PUBLIC_RECONCILIATION_REASONS = {
    "duplicate_provider_match",
    "provider_create_outcome_unknown",
    "provider_ownership_mismatch",
    "provider_reconciled",
    "provider_reconciliation_exhausted",
    "provider_reconciliation_required",
    "provider_restore_ambiguous",
    "stale_execution_lease",
    "stale_legacy_execution_lease",
    "stale_upload_lease",
    "storage_reconciliation_required",
}
_PUBLIC_PROGRESS_UNITS = {
    "bytes",
    "chunks",
    "databases",
    "destinations",
    "files",
    "objects",
    "parts",
    "paths",
    "records",
    "resources",
    "rows",
    "snapshots",
    "tables",
}
_PUBLIC_CHECKSUM_ALGORITHMS = {
    "crc32",
    "content-md5",
    "etag",
    "md5",
    "sha1",
    "sha-1",
    "sha256",
    "sha-256",
}
_PUBLIC_ERROR_CODES = set(UtilBackup.EXECUTION_ERROR_MESSAGES) | {
    "ARCHIVE_VALIDATION_FAILED",
    "ARTIFACT_RECORD_MISSING",
    "BACKUP_FAILED",
    "BACKUP_TIMEOUT",
    "CLIENT_FAILED",
    "CLIENT_OR_KEY_MISSING",
    "CLIENT_REJECTED",
    "CLIENT_TIMEOUT",
    "CLIENT_UNAVAILABLE",
    "CONFIGURATION_INVALID",
    "CONNECTION_NOT_READY",
    "CONNECTION_REFUSED",
    "CONNECTION_VALIDATION_FAILED",
    "DATABASE_COMMAND_TIMEOUT",
    "DATABASE_CONNECT_TIMEOUT",
    "DATABASE_RESTORE_PERMISSION_DENIED",
    "DATABASE_VALIDATION_COMMAND_TIMEOUT",
    "DNS_FAILURE",
    "DROPBOX_API_TIMEOUT",
    "DUPLICATE_MATCH",
    "EXECUTION_ERROR",
    "HOST_KEY_CHANGED",
    "HOST_KEY_UNKNOWN",
    "INTEGRITY_MISMATCH",
    "INVALID_BACKUP_ID",
    "INVALID_PROVIDER_PATH",
    "MALFORMED_RESPONSE",
    "MYSQL_CREATE_OUTCOME_UNKNOWN",
    "MYSQL_SSH_CLOSE_FAILED",
    "NODE_NOT_READY",
    "NOT_FOUND",
    "PCLOUD_API_TIMEOUT",
    "PERMISSION_DENIED",
    "POSTGRES_CREATE_OUTCOME_UNKNOWN",
    "POSTGRES_SSH_CLOSE_FAILED",
    "PROVIDER_AUTH_FAILED",
    "PROVIDER_CLIENT_ERROR",
    "PROVIDER_CONFLICT",
    "PROVIDER_CREATE_OUTCOME_UNKNOWN",
    "PROVIDER_DUPLICATE_MATCH",
    "PROVIDER_FAILED",
    "PROVIDER_FAILURE",
    "PROVIDER_HTTP_READ_TIMEOUT",
    "PROVIDER_MALFORMED_RESPONSE",
    "PROVIDER_NOT_FOUND",
    "PROVIDER_OWNERSHIP_MISMATCH",
    "PROVIDER_RATE_LIMIT",
    "PROVIDER_RECONCILIATION_EXHAUSTED",
    "PROVIDER_RECONCILIATION_REQUIRED",
    "PROVIDER_REQUEST_FAILED",
    "PROVIDER_RESTORE_AMBIGUOUS",
    "PROVIDER_RESTORE_FAILED",
    "PROVIDER_RESTORE_TIMEOUT",
    "PROVIDER_RESTORE_UNSUPPORTED",
    "PROVIDER_TIMEOUT",
    "PROVIDER_TRANSIENT_FAILURE",
    "PROVIDER_TRANSIENT_OUTAGE",
    "PROVIDER_UNKNOWN_OUTCOME",
    "QUOTA_EXCEEDED",
    "RATE_LIMITED",
    "RESTORE_ARCHIVE_NOT_READY",
    "RESTORE_FAILED",
    "RESTORE_INTEGRITY_FAILED",
    "RESTORE_RECONCILIATION_REQUIRED",
    "RESTORE_RETRIES_EXHAUSTED",
    "RESTORE_SOURCE_UNAVAILABLE",
    "RESTORE_TARGET_REJECTED",
    "RESTORE_TIMEOUT",
    "RESTORE_TRANSIENT_FAILURE",
    "SFTP_CLEANUP_FAILED",
    "SOURCE_ARTIFACT_INVALID",
    "SOURCE_ARTIFACT_MISSING",
    "SOURCE_EXPORT_FAILED",
    "SSH_COMMAND_FAILED",
    "SSH_COMMAND_REJECTED",
    "STORAGE_AUTH_FAILED",
    "STORAGE_BACKEND_UNSUPPORTED",
    "STORAGE_DESTINATION_NOT_FOUND",
    "STORAGE_INTEGRITY_FAILED",
    "STORAGE_QUOTA_EXCEEDED",
    "STORAGE_RATE_LIMITED",
    "STORAGE_RECONCILIATION_REQUIRED",
    "STORAGE_RETRIES_EXHAUSTED",
    "STORAGE_TIMEOUT",
    "STORAGE_TRANSIENT_FAILURE",
    "STORAGE_UPLOAD_FAILED",
    "UPLOAD_FAILED_FILE_NOT_FOUND",
    "UNKNOWN",
    "VULTR_API_TIMEOUT",
    "VULTR_REQUEST_TIMEOUT",
    "WORKER_DISK_FULL",
    "WORKER_LEASE_LOST",
}
_RESTORE_HIDDEN_FIELDS = {
    # These are durable coordination data, never operator API data.
    "lease_owner",
    "lease_token",
    "lease_expires_at",
    "heartbeat_at",
    "worker_name",
    "execution_metadata",
    "provider_metadata",
}
_GENERIC_ERROR_MESSAGE = (
    "The operation could not be completed. Review secured diagnostics using "
    "the correlation ID."
)
_PUBLIC_ERROR_MESSAGES = {
    "DATABASE_RESTORE_PERMISSION_DENIED": (
        "The configured database account lacks privileges required for a safe fork "
        "restore. Grant PostgreSQL CREATEDB or MySQL/MariaDB CREATE and DROP globally "
        "or with a matching target/database grant, "
        "or choose an explicit in-place restore target. No target was changed."
    ),
    "RESTORE_RECONCILIATION_REQUIRED": (
        "The restore state is ambiguous, so automatic destination writes were "
        "stopped. Review the exact ownership and checkpoint evidence before retrying."
    ),
}


def _isoformat(value):
    if value is None:
        return None
    if timezone.is_naive(value):
        value = timezone.make_aware(value, datetime_timezone.utc)
    return value.isoformat()


def _safe_token(value, *, max_length=64):
    """Return a bounded public token, never arbitrary provider text."""
    if value in (None, ""):
        return None
    token = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0," + str(max_length - 1) + r"}", token):
        return None
    return token


def _public_status(obj):
    value = getattr(obj, "status", None)
    try:
        field = obj._meta.get_field("status")
        for choice_value, label in field.flatchoices:
            if str(choice_value) == str(value):
                token = re.sub(r"[^a-z0-9]+", "_", str(label).lower()).strip("_")
                return token or "unknown"
    except (AttributeError, LookupError):
        pass
    return _safe_token(value) or "unknown"


def _public_phase(value, fallback="unknown"):
    raw = _safe_token(value, max_length=64)
    if not raw:
        raw = _safe_token(fallback, max_length=64)
    if not raw:
        return "unknown"
    if raw in _PUBLIC_PHASES:
        return raw
    durable_restore_phase = _DURABLE_RESTORE_PHASE_ALIASES.get(raw)
    if durable_restore_phase:
        return durable_restore_phase
    legacy_phase = _LEGACY_STATUS_PHASES.get(raw)
    if legacy_phase:
        return legacy_phase
    if "download" in raw and "complete" in raw:
        return "source_ready"
    if "upload" in raw and "complete" in raw:
        return "validating"
    if any(token in raw for token in ("manual", "review")):
        return "manual_review"
    if any(token in raw for token in ("cancel", "abort")):
        return "cancelled"
    if any(token in raw for token in ("fail", "error", "timeout")):
        return "failed"
    if any(token in raw for token in ("complete", "success", "available")):
        return "complete"
    if any(token in raw for token in ("retry", "backoff")):
        return "retrying"
    if any(token in raw for token in ("reconcil", "unknown")):
        return "reconciling"
    if any(token in raw for token in ("poll", "check")):
        return "polling"
    if any(token in raw for token in ("restore", "import", "extract")):
        return "restoring"
    if any(token in raw for token in ("upload", "transfer", "destination")):
        return "uploading"
    if any(token in raw for token in ("valid", "verify", "checksum")):
        return "validating"
    if any(token in raw for token in ("snapshot", "capture", "dump", "create")):
        return "capturing"
    if any(token in raw for token in ("start", "prepare", "connect", "queue")):
        return "preparing"
    return "in_progress"


def _execution_phase(legacy_status, phase_value=None):
    """Return a non-contradictory public phase for a durable or legacy row."""
    status_token = _safe_token(legacy_status, max_length=64) or "unknown"
    if status_token in _TERMINAL_STATUS_PHASES:
        return _TERMINAL_STATUS_PHASES[status_token]
    if status_token in _AUTHORITATIVE_ACTIVE_STATUS_PHASES:
        return _AUTHORITATIVE_ACTIVE_STATUS_PHASES[status_token]

    phase_token = _safe_token(phase_value, max_length=64)
    if phase_token:
        return _public_phase(phase_token)
    return _LEGACY_STATUS_PHASES.get(status_token, "unknown")


def _safe_error_code(value):
    if value in (None, ""):
        return None
    code = str(value).strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", code):
        return "EXECUTION_ERROR"
    if code in _PUBLIC_ERROR_CODES:
        return code
    # Legacy rows may contain an exception body in this column.  Collapse it to
    # one categorized value instead of returning attacker/provider-controlled text.
    return "EXECUTION_ERROR"


def _safe_error_message(code):
    if not code:
        return None
    return _PUBLIC_ERROR_MESSAGES.get(
        code,
        UtilBackup.EXECUTION_ERROR_MESSAGES.get(code, _GENERIC_ERROR_MESSAGE),
    )


def _safe_provider_status(value):
    token = _safe_token(value)
    if token is None:
        return None
    return token if token in _PUBLIC_PROVIDER_STATUSES else "unknown"


def _safe_reconciliation_state(value):
    token = _safe_token(value, max_length=24)
    return token if token in _PUBLIC_RECONCILIATION_STATES else "none"


def _safe_reconciliation_reason(value):
    token = _safe_token(value, max_length=128)
    return token if token in _PUBLIC_RECONCILIATION_REASONS else None


def _safe_recovery_id(value):
    """Expose only the canonical browser recovery UUID, never arbitrary text."""
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return None
    if (
        parsed.version != 4
        or parsed.variant != uuid.RFC_4122
        or str(parsed) != value
    ):
        return None
    return str(parsed)


def _restore_recovery_id(obj):
    metadata = getattr(obj, "execution_metadata", None)
    if not isinstance(metadata, dict):
        return None
    api_request = metadata.get("api_request")
    if not isinstance(api_request, dict):
        return None
    return _safe_recovery_id(api_request.get("recovery_id"))


def _safe_progress(completed, total, unit):
    try:
        completed = max(0, int(completed or 0))
    except (TypeError, ValueError):
        completed = 0
    if total in (None, ""):
        safe_total = None
    else:
        try:
            safe_total = max(completed, int(total))
        except (TypeError, ValueError):
            safe_total = None
    unit_token = _safe_token(unit, max_length=32)
    return {
        "completed": completed,
        "total": safe_total,
        "unit": unit_token if unit_token in _PUBLIC_PROGRESS_UNITS else None,
    }


def _safe_artifact(state, artifact=None):
    verified_at = getattr(state, "artifact_verified_at", None) if state else None
    byte_count = getattr(state, "artifact_bytes", 0) if state else 0
    checksum_algorithm = (
        getattr(state, "artifact_checksum_algorithm", "") if state else ""
    )
    if artifact is not None:
        verified_at = verified_at or getattr(artifact, "verified_at", None)
        if not byte_count:
            byte_count = getattr(artifact, "byte_count", 0)
        checksum_algorithm = checksum_algorithm or getattr(
            artifact, "checksum_algorithm", ""
        )
    if not verified_at and not byte_count and not checksum_algorithm:
        return None
    try:
        byte_count = max(0, int(byte_count or 0))
    except (TypeError, ValueError):
        byte_count = 0
    checksum_token = _safe_token(checksum_algorithm, max_length=32)
    return {
        "verified_at": _isoformat(verified_at),
        "bytes": byte_count,
        "checksum_algorithm": (
            checksum_token
            if checksum_token in _PUBLIC_CHECKSUM_ALGORITHMS
            else None
        ),
    }


def _execution_state_for(obj):
    if getattr(obj, "_api_execution_state_loaded", False):
        return getattr(obj, "_api_execution_state", None)
    state = None
    if getattr(obj, "pk", None):
        content_type = ContentType.objects.get_for_model(
            obj, for_concrete_model=False
        )
        state = (
            CoreBackupExecution.objects.filter(
                backup_content_type=content_type,
                backup_object_id=obj.pk,
            )
            .order_by("-modified", "-pk")
            .first()
        )
    setattr(obj, "_api_execution_state", state)
    setattr(obj, "_api_execution_state_loaded", True)
    return state


def _artifact_for(obj):
    if getattr(obj, "_api_artifact_loaded", False):
        return getattr(obj, "_api_artifact", None)
    artifact = None
    if getattr(obj, "pk", None):
        content_type = ContentType.objects.get_for_model(
            obj, for_concrete_model=False
        )
        artifact = (
            CoreBackupArtifact.objects.filter(
                backup_content_type=content_type,
                backup_object_id=obj.pk,
                role=CoreBackupArtifact.Role.SOURCE,
                verified_at__isnull=False,
            )
            .order_by("-verified_at", "-pk")
            .first()
        )
    setattr(obj, "_api_artifact", artifact)
    setattr(obj, "_api_artifact_loaded", True)
    return artifact


def _backup_execution_status(obj, state=None, artifact=None):
    state = _execution_state_for(obj) if state is None else state
    artifact = _artifact_for(obj) if artifact is None else artifact
    legacy_status = _public_status(obj)
    error_code = _safe_error_code(getattr(state, "last_error_code", None))
    provider_status = _safe_provider_status(
        getattr(state, "provider_status", None)
    )
    if provider_status is None:
        provider_status = _safe_provider_status(getattr(obj, "provider_status", None))
    if provider_status is None:
        provider_status = _safe_provider_status(getattr(obj, "provider_state", None))
    reconciliation_state = _safe_reconciliation_state(
        getattr(state, "reconciliation_state", None) if state else None
    )
    reconciliation_reason = _safe_reconciliation_reason(
        getattr(state, "reconciliation_reason", None) if state else None
    )
    attempts = getattr(state, "attempt_count", None) if state else None
    if attempts is None:
        attempts = getattr(obj, "attempt_no", None) or 0
    try:
        attempts = max(0, int(attempts))
    except (TypeError, ValueError):
        attempts = 0
    phase_value = getattr(state, "phase", None) if state else None
    execution_metadata = getattr(state, "metadata", None) if state else None
    if isinstance(execution_metadata, dict):
        public_stage = _safe_token(execution_metadata.get("public_stage"))
        if public_stage in _PUBLIC_BACKUP_STAGES:
            phase_value = public_stage
    return {
        "durable": bool(state),
        "correlation_id": str(state.correlation_id) if state else None,
        "status": legacy_status,
        "phase": _execution_phase(
            legacy_status,
            phase_value,
        ),
        "last_error_code": error_code,
        "last_error_message": _safe_error_message(error_code),
        "last_error_at": _isoformat(
            getattr(state, "last_error_at", None) if state else None
        ),
        "next_retry_at": _isoformat(
            getattr(state, "next_retry_at", None) if state else None
        ),
        "attempts": attempts,
        "progress": _safe_progress(
            getattr(state, "progress_completed", 0) if state else 0,
            getattr(state, "progress_total", None) if state else None,
            getattr(state, "progress_unit", None) if state else None,
        ),
        "artifact": _safe_artifact(state, artifact),
        "reconciliation": {
            "state": reconciliation_state,
            "reason": reconciliation_reason,
        },
        "provider_status": provider_status,
    }


def _restore_params(obj):
    """Expose only stable, non-secret restore choices."""
    raw = getattr(obj, "params", None)
    if not isinstance(raw, dict):
        return {}
    result = {}
    mode = _safe_token(raw.get("mode"), max_length=16)
    if mode in {"fork", "in_place"}:
        result["mode"] = mode
    if "mapping_locked" in raw:
        result["mapping_locked"] = bool(raw.get("mapping_locked"))
    if "delete" in raw:
        result["delete"] = bool(raw.get("delete"))
    mapping = raw.get("target_mapping")
    if isinstance(mapping, dict):
        safe_mapping = {}
        for source, target in mapping.items():
            source = _safe_token(source, max_length=63)
            target = _safe_token(target, max_length=63)
            if source and target:
                safe_mapping[source] = target
        if safe_mapping:
            result["target_mapping"] = safe_mapping
    return result


def _restore_execution_status(obj):
    legacy_status = _public_status(obj)
    phase_value = getattr(obj, "execution_phase", None) or getattr(
        obj, "operation_phase", None
    )
    raw_params = getattr(obj, "params", None)
    provider_status = _safe_provider_status(getattr(obj, "provider_status", None))
    if provider_status is None and isinstance(raw_params, dict):
        provider_status = _safe_provider_status(raw_params.get("_bs_provider_status"))
    error_code = _safe_error_code(getattr(obj, "last_error_code", None))
    if error_code is None and isinstance(raw_params, dict):
        error_code = _safe_error_code(raw_params.get("_bs_last_error_code"))
    if error_code is None and getattr(obj, "error", None):
        error_code = "RESTORE_FAILED"
    reconciliation_state = _safe_reconciliation_state(
        getattr(obj, "reconciliation_state", None)
    )
    if reconciliation_state == "none":
        phase_token = _safe_token(phase_value)
        if phase_token and "manual" in phase_token:
            reconciliation_state = "manual_review"
        elif phase_token and any(
            token in phase_token for token in ("reconcil", "unknown")
        ):
            reconciliation_state = "required"
    reason = _safe_reconciliation_reason(
        getattr(obj, "reconciliation_reason", None)
    )
    if reason is None and reconciliation_state != "none":
        reason = _safe_reconciliation_reason(error_code)
    try:
        attempts = max(0, int(getattr(obj, "attempt_count", 0) or 0))
    except (TypeError, ValueError):
        attempts = 0
    return {
        "durable": bool(getattr(obj, "pk", None)),
        "correlation_id": (
            str(obj.correlation_id) if getattr(obj, "correlation_id", None) else None
        ),
        "recovery_id": _restore_recovery_id(obj),
        "status": legacy_status,
        "phase": _execution_phase(legacy_status, phase_value),
        "last_error_code": error_code,
        "last_error_message": _safe_error_message(error_code),
        "last_error_at": _isoformat(getattr(obj, "last_error_at", None)),
        "next_retry_at": _isoformat(getattr(obj, "next_retry_at", None)),
        "attempts": attempts,
        "progress": _safe_progress(
            getattr(obj, "progress_completed", 0),
            getattr(obj, "progress_total", None),
            getattr(obj, "progress_unit", None),
        ),
        "artifact": None,
        "reconciliation": {
            "state": reconciliation_state,
            "reason": reason,
        },
        "provider_status": provider_status,
    }


class BackupExecutionStatusListSerializer(serializers.ListSerializer):
    """Bulk-load generic execution/artifact rows for backup list endpoints."""

    def to_representation(self, data):
        items = list(data)
        if items:
            content_type = ContentType.objects.get_for_model(
                items[0], for_concrete_model=False
            )
            object_ids = [item.pk for item in items if getattr(item, "pk", None)]
            states = CoreBackupExecution.objects.filter(
                backup_content_type=content_type,
                backup_object_id__in=object_ids,
            ).order_by("-modified", "-pk")
            state_by_id = {}
            for state in states:
                state_by_id.setdefault(state.backup_object_id, state)
            artifacts = CoreBackupArtifact.objects.filter(
                backup_content_type=content_type,
                backup_object_id__in=object_ids,
                role=CoreBackupArtifact.Role.SOURCE,
                verified_at__isnull=False,
            ).order_by("-verified_at", "-pk")
            artifact_by_id = {}
            for artifact in artifacts:
                artifact_by_id.setdefault(artifact.backup_object_id, artifact)
            for item in items:
                item._api_execution_state = state_by_id.get(item.pk)
                item._api_execution_state_loaded = True
                item._api_artifact = artifact_by_id.get(item.pk)
                item._api_artifact_loaded = True
        return super().to_representation(items)


class SafeProviderMetadataMixin:
    """Keep legacy response shape without returning provider response bodies."""

    def get_fields(self):
        fields = super().get_fields()
        if "metadata" in fields:
            field = serializers.SerializerMethodField(
                method_name="get_safe_metadata", read_only=True
            )
            field.bind("metadata", self)
            fields["metadata"] = field
        return fields

    @staticmethod
    def get_safe_metadata(_obj):
        return {}


class BackupExecutionStatusMixin(SafeProviderMetadataMixin):
    class Meta:
        list_serializer_class = BackupExecutionStatusListSerializer

    def get_fields(self):
        fields = super().get_fields()
        if "execution_status" not in fields:
            field = serializers.SerializerMethodField(read_only=True)
            field.bind("execution_status", self)
            fields["execution_status"] = field
        return fields

    def get_execution_status(self, obj):
        return _backup_execution_status(obj)


class RestoreExecutionStatusMixin(SafeProviderMetadataMixin):
    def get_fields(self):
        fields = super().get_fields()
        method_fields = {
            "execution_status": "get_execution_status",
            "params": "get_params",
            "error": "get_error",
        }
        for name, method_name in method_fields.items():
            if name not in fields:
                continue
            field = serializers.SerializerMethodField(
                method_name=method_name, read_only=True
            )
            field.bind(name, self)
            fields[name] = field
        if "execution_status" not in fields:
            field = serializers.SerializerMethodField(
                method_name="get_execution_status", read_only=True
            )
            field.bind("execution_status", self)
            fields["execution_status"] = field
        return fields

    def get_execution_status(self, obj):
        return _restore_execution_status(obj)

    @staticmethod
    def get_params(obj):
        return _restore_params(obj)

    @staticmethod
    def get_error(obj):
        code = _safe_error_code(getattr(obj, "last_error_code", None))
        if code is None and isinstance(getattr(obj, "params", None), dict):
            code = _safe_error_code(obj.params.get("_bs_last_error_code"))
        if code is None and getattr(obj, "error", None):
            code = "RESTORE_FAILED"
        return _safe_error_message(code)

    def get_default_field_names(self, declared_fields, model_info):
        names = super().get_default_field_names(declared_fields, model_info)
        return [name for name in names if name not in _RESTORE_HIDDEN_FIELDS]

    def get_field_names(self, declared_fields, info):
        names = super().get_field_names(declared_fields, info)
        if names is None:
            return names
        return [name for name in names if name not in _RESTORE_HIDDEN_FIELDS]


class CoreBackupScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreSchedule
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "notes",
        )


class CoreStorageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageType
        fields = "__all__"


class CoreBackupStorageSerializer(serializers.ModelSerializer):
    type = CoreStorageTypeSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreStorage
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()
