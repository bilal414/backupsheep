import datetime
import fcntl
import hashlib
import json
import humanfriendly
import os
import re
import pytz
from apps.api.v1.utils.http import request_timeout, requests
import shutil
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import quote
from celery import chord
from django.conf import settings
from django.db import models, transaction
from django.db.models import UniqueConstraint
from django.utils import timezone
from django.utils.text import slugify
from django.utils.timezone import get_current_timezone
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from model_utils.models import TimeStampedModel
from ovh import InvalidCredential, ResourceConflictError
from sentry_sdk import capture_exception, capture_message

from apps.console.storage.models import CoreStorage
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeBackupStatusCheckTimeOutError,
    NodeBackupStatusCheckCallError,
    NodeConnectionError,
)
import humanize

from apps.api.v1.utils.api_helpers import get_error, mkdir_p
from ..backup.models import CoreDatabaseBackupStoragePoints
from ..connection.models import CoreConnection
from ..member.models import CoreMember
from ..vultr import (
    iter_vultr_collection,
    record_snapshot_ownership,
    snapshot_matches_with_recorded_source,
    vultr_request_timeout,
)


from ..utils.models import UtilBackup, UtilCloud
from botocore.exceptions import ClientError


class _RestoreProviderError(ValueError):
    """Internal exception whose text is always safe to expose to the user."""

    def __init__(self, code, *, retryable=False, unknown_outcome=False):
        self.code = str(code)
        self.retryable = bool(retryable)
        self.unknown_outcome = bool(unknown_outcome)
        super().__init__(_RESTORE_ERROR_MESSAGES.get(self.code, _RESTORE_ERROR_MESSAGES["PROVIDER_REQUEST_FAILED"]))


_RESTORE_ERROR_MESSAGES = {
    "PROVIDER_NOT_FOUND": "The provider could not find the restore source or target.",
    "PROVIDER_AUTH_FAILED": "The provider rejected the restore credentials. Reconnect the cloud account.",
    "PROVIDER_RATE_LIMIT": "The provider rate-limited the restore request. We will retry shortly.",
    "PROVIDER_TIMEOUT": "The provider restore request timed out. Its outcome is being reconciled before retrying.",
    "PROVIDER_TRANSIENT_OUTAGE": "The provider is temporarily unavailable. We will retry the restore.",
    "PROVIDER_MALFORMED_RESPONSE": "The provider returned an invalid restore response. Manual review is required.",
    "PROVIDER_FAILED": "The provider reported a terminal restore failure.",
    "PROVIDER_OWNERSHIP_MISMATCH": "The provider target did not match this BackupSheep restore. Manual review is required.",
    "PROVIDER_DUPLICATE_MATCH": "Multiple provider resources matched this restore. Manual review is required.",
    "PROVIDER_UNKNOWN_OUTCOME": "The provider accepted an uncertain restore request. We are reconciling it before retrying.",
    "PROVIDER_RECONCILIATION_REQUIRED": "The restore outcome is unknown and no unique provider target was found. Manual review is required.",
    "PROVIDER_REQUEST_FAILED": "The provider restore request failed.",
}


# Notification data is an external/public contract.  Keep this allowlist local to
# the node boundary so a provider exception can never become an account-log or
# email payload merely because a new SDK exposes a ``code`` or ``detail`` field.
_BACKUP_NOTIFICATION_MESSAGES = {
    "CONNECTION_NOT_READY": "The cloud connection is not ready for backups.",
    "NODE_NOT_READY": "The node is not ready for a backup.",
    "CONNECTION_VALIDATION_FAILED": "BackupSheep could not validate the destination connection.",
    "BACKUP_FAILED": "The backup could not be completed.",
    "BACKUP_TIMEOUT": "The backup worker reached its time limit.",
    "BACKUP_STATUS_TIMEOUT": "The provider backup status could not be confirmed before the timeout.",
    "AUTH_FAILED": "The destination rejected the configured credentials.",
    "HOST_KEY_CHANGED": "The server identity changed and the connection was refused.",
    "HOST_KEY_UNKNOWN": "The server identity has not been reviewed.",
    "KEY_PASSPHRASE_REQUIRED": "The private key requires a passphrase.",
    "CONNECTION_REFUSED": "The destination refused the network connection.",
    "DNS_FAILURE": "The destination hostname could not be resolved.",
    "TCP_TIMEOUT": "The destination did not respond before the connection timeout.",
    "CLIENT_OR_KEY_MISSING": "A required backup client or managed key is unavailable on the worker.",
    "PERMISSION_DENIED": "The destination account lacks the required backup permission.",
    "TLS_REQUIRED": "The destination requires an SSL/TLS connection.",
    "WORKER_DISK_FULL": "The backup worker does not have enough free disk space.",
    "ARCHIVE_VALIDATION_FAILED": "The generated backup archive failed integrity validation.",
    "SOURCE_EXPORT_FAILED": "The source export failed.",
    "PROVIDER_NOT_FOUND": "The provider could not find the backup source or target.",
    "PROVIDER_AUTH_FAILED": "The provider rejected the configured credentials or permissions.",
    "PROVIDER_RATE_LIMIT": "The provider rate limit was reached.",
    "PROVIDER_TIMEOUT": "The provider request timed out.",
    "PROVIDER_TRANSIENT_OUTAGE": "The provider is temporarily unavailable.",
    "PROVIDER_FAILED": "The provider reported a terminal failure.",
    "PROVIDER_REQUEST_FAILED": "The provider rejected the backup request.",
    "PROVIDER_CLIENT_ERROR": "The provider client could not complete the backup request.",
    "PROVIDER_OWNERSHIP_MISMATCH": "Provider ownership verification failed.",
    "PROVIDER_MALFORMED_RESPONSE": "The provider returned an invalid backup response.",
    "PROVIDER_DUPLICATE_MATCH": "Multiple provider resources matched this backup; manual review is required.",
    "PROVIDER_RECONCILIATION_REQUIRED": "The provider operation requires reconciliation before another request.",
    "PROVIDER_UNSUPPORTED_RESOURCE": "The provider does not support native backups for this resource type.",
    "STORAGE_UPLOAD_FAILED": "The storage upload could not be completed.",
    "STORAGE_AUTH_FAILED": "The storage destination rejected the configured credentials or permissions.",
    "STORAGE_DESTINATION_NOT_FOUND": "The configured storage destination was not found.",
    "STORAGE_QUOTA_EXCEEDED": "The destination does not have enough available storage capacity.",
    "STORAGE_RATE_LIMITED": "The storage provider rate limit was reached.",
    "STORAGE_TIMEOUT": "The storage operation timed out.",
    "STORAGE_TRANSIENT_FAILURE": "The storage provider is temporarily unavailable.",
    "STORAGE_INTEGRITY_FAILED": "The uploaded object failed integrity verification.",
    "SOURCE_ARTIFACT_INVALID": "The local backup artifact failed integrity validation.",
    "SOURCE_ARTIFACT_MISSING": "The committed local backup artifact is no longer available.",
    "STORAGE_RECONCILIATION_REQUIRED": "The storage operation requires reconciliation before it can continue.",
    "WORKER_LEASE_LOST": "This worker lost ownership of the backup execution lease.",
}

_BACKUP_NOTIFICATION_REMEDIATIONS = {
    "CONNECTION_NOT_READY": "Reconnect or validate the cloud connection, then retry the backup.",
    "NODE_NOT_READY": "Ensure the node is active and retry the backup.",
    "CONNECTION_VALIDATION_FAILED": "Review the destination configuration and worker connectivity, then validate again.",
    "BACKUP_FAILED": "Review the backup execution using the correlation ID and retry after correcting the reported condition.",
    "BACKUP_TIMEOUT": "Review worker capacity and backup scope, then retry; durable execution state remains available for recovery.",
    "BACKUP_STATUS_TIMEOUT": "Wait for provider recovery and inspect the durable backup status before retrying.",
    "AUTH_FAILED": "Check the configured credentials and authentication mode, then validate again.",
    "HOST_KEY_CHANGED": "Verify the server identity out of band before replacing the reviewed host key.",
    "HOST_KEY_UNKNOWN": "Verify the server fingerprint out of band and approve it before retrying.",
    "KEY_PASSPHRASE_REQUIRED": "Configure the private-key passphrase and validate again.",
    "CONNECTION_REFUSED": "Confirm the service is running and its firewall allows the BackupSheep worker.",
    "DNS_FAILURE": "Check the hostname and DNS records, then retry.",
    "TCP_TIMEOUT": "Allow the BackupSheep worker through the firewall and confirm the configured port is reachable.",
    "CLIENT_OR_KEY_MISSING": "Install the required client or managed key on every relevant worker.",
    "PERMISSION_DENIED": "Grant the minimum read/export permissions required for this backup and validate again.",
    "TLS_REQUIRED": "Enable SSL/TLS for this connection and validate again.",
    "WORKER_DISK_FULL": "Free worker disk space or move the workload to a worker with sufficient capacity.",
    "ARCHIVE_VALIDATION_FAILED": "Retry the export and inspect the durable execution using the correlation ID.",
    "SOURCE_EXPORT_FAILED": "Review secured diagnostics using the correlation ID and retry the source export.",
    "PROVIDER_NOT_FOUND": "Confirm the source or target still exists and retry after provider recovery.",
    "PROVIDER_AUTH_FAILED": "Reconnect the cloud account with the minimum required permissions.",
    "PROVIDER_RATE_LIMIT": "Wait for the provider retry window and allow the durable task to resume.",
    "PROVIDER_TIMEOUT": "Wait for provider recovery and reconcile the durable operation before retrying.",
    "PROVIDER_TRANSIENT_OUTAGE": "Wait for provider recovery; the durable operation can be reconciled before retrying.",
    "PROVIDER_FAILED": "Review the provider operation using the correlation ID and correct the provider-side condition.",
    "PROVIDER_REQUEST_FAILED": "Review the provider operation using the correlation ID and retry when safe.",
    "PROVIDER_CLIENT_ERROR": "Update or reconnect the provider client configuration and retry.",
    "PROVIDER_OWNERSHIP_MISMATCH": "Stop and review provider ownership before retrying this backup.",
    "PROVIDER_MALFORMED_RESPONSE": "Review the provider API response in secured diagnostics and retry after validation.",
    "PROVIDER_DUPLICATE_MATCH": "Do not create another provider resource until the duplicate resources are reviewed.",
    "PROVIDER_RECONCILIATION_REQUIRED": "Review the durable reconciliation record before retrying this provider operation.",
    "STORAGE_UPLOAD_FAILED": "Review the storage integration and retry the upload.",
    "STORAGE_AUTH_FAILED": "Reconnect the storage integration with the minimum required permissions.",
    "STORAGE_DESTINATION_NOT_FOUND": "Verify the configured storage destination and retry.",
    "STORAGE_QUOTA_EXCEEDED": "Free storage capacity or select a destination with sufficient capacity.",
    "STORAGE_RATE_LIMITED": "Wait for the storage provider retry window and allow the task to resume.",
    "STORAGE_TIMEOUT": "Wait for storage provider recovery and reconcile the upload before retrying.",
    "STORAGE_TRANSIENT_FAILURE": "Wait for storage provider recovery and retry the upload.",
    "STORAGE_INTEGRITY_FAILED": "Do not restore this copy; retry the upload and verify its checksum.",
    "SOURCE_ARTIFACT_INVALID": "Retry the source export and verify its integrity before upload.",
    "SOURCE_ARTIFACT_MISSING": "Recreate the source artifact and retry the backup.",
    "STORAGE_RECONCILIATION_REQUIRED": "Reconcile the storage operation before starting another upload.",
    "WORKER_LEASE_LOST": "Allow the durable recovery task to reconcile the backup before retrying.",
}

_BACKUP_NOTIFICATION_SAFE_CODES = frozenset(_BACKUP_NOTIFICATION_MESSAGES)


def _restore_status(name):
    from apps.console.backup.models import CoreCloudRestore

    return getattr(CoreCloudRestore.Status, name)


def _restore_phase(name):
    from apps.console.backup.models import CoreCloudRestore

    return getattr(CoreCloudRestore.OperationPhase, name)


def _restore_message(code):
    return _RESTORE_ERROR_MESSAGES.get(code, _RESTORE_ERROR_MESSAGES["PROVIDER_REQUEST_FAILED"])


def _restore_params(restore):
    return dict(restore.params) if isinstance(restore.params, dict) else {}


def _restore_marker_value(restore):
    """Return a stable provider marker without putting secrets in provider data."""
    existing = str(getattr(restore, "restore_marker", "") or "").strip()
    if existing:
        return existing[:128]
    identity = getattr(restore, "pk", None) or getattr(restore, "correlation_id", None)
    identity = str(identity or getattr(restore, "name", "restore"))
    return f"backupsheep-restore-{identity}"[:128]


def _restore_fingerprint(provider, source_id, target_kind, restore, params):
    payload = {
        "provider": str(provider),
        "source_id": str(source_id),
        "target_kind": str(target_kind),
        "restore_id": str(getattr(restore, "pk", "")),
        # The caller controls restore params; the fingerprint is only an
        # idempotency witness and is never sent to a provider as a secret.
        "params": params,
    }
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _prepare_cloud_restore(restore, *, provider, source_id, target_kind, target_name=None):
    """Persist the restore identity before any non-idempotent provider call."""
    params = _restore_params(restore)
    stored_marker = str(params.get("_bs_provider_name") or "").strip()
    row_marker = str(getattr(restore, "restore_marker", "") or "").strip()
    if stored_marker and row_marker and stored_marker != row_marker:
        raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    marker = (stored_marker or row_marker or _restore_marker_value(restore))[:128]
    # Providers without a native idempotency header use this deterministic provider
    # name as the immutable adoption marker. Keep the user-facing restore name in the
    # row, but never rely on a caller-chosen display name for crash recovery.
    params.setdefault("_bs_provider_name", marker)
    identity = dict(params.get("_backupsheep_restore") or {})
    identity.update(
        {
            "provider": str(provider),
            "source_id": str(source_id),
            "target_kind": str(target_kind),
            # When an adapter has already derived the provider's real target
            # identifier, preserve it as the reconciliation identity. The
            # separate provider-name marker remains the cross-provider
            # idempotency/ownership tag and must not replace an explicit target.
            "target_name": str(target_name or params.get("_bs_provider_name") or restore.name),
            "marker": marker,
        }
    )
    params["_backupsheep_restore"] = identity
    params.setdefault("_bs_create_outcome_unknown", False)
    # New restore requests must prove the marker/source relationship when the
    # provider exposes those fields. Legacy rows without this flag retain their
    # exact resource-id polling compatibility.
    params["_bs_marker_required"] = True
    fingerprint = _restore_fingerprint(provider, source_id, target_kind, restore, params)
    fields = []
    if getattr(restore, "restore_marker", "") != marker:
        restore.restore_marker = marker
        fields.append("restore_marker")
    if getattr(restore, "request_fingerprint", "") != fingerprint:
        restore.request_fingerprint = fingerprint
        fields.append("request_fingerprint")
    if restore.params != params:
        restore.params = params
        fields.append("params")
    restore.operation_phase = _restore_phase("RECONCILING")
    fields.append("operation_phase")
    if fields:
        fields = list(dict.fromkeys(fields + ["modified"]))
        restore.save(update_fields=fields)
    return marker, params


def _restore_unknown_outcome(restore, *, code="PROVIDER_UNKNOWN_OUTCOME"):
    """Fence a possibly accepted mutation so a retry must reconcile first."""
    params = _restore_params(restore)
    params["_bs_create_outcome_unknown"] = True
    params["_bs_last_error_code"] = code
    params["_bs_last_error_category"] = "transient" if code in {
        "PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_OUTAGE"
    } else "unknown_outcome"
    restore.params = params
    restore.operation_phase = _restore_phase("CREATE_UNKNOWN")
    restore.error = _restore_message(code)
    if hasattr(restore, "last_error_code"):
        restore.last_error_code = code
    restore.status = _restore_status("IN_PROGRESS")
    restore.save(update_fields=["params", "operation_phase", "error", "status", "modified"] + (["last_error_code"] if hasattr(restore, "last_error_code") else []))


def _restore_safe_failure(restore, code, *, manual_review=False):
    params = _restore_params(restore)
    if code in {
        "PROVIDER_AUTH_FAILED",
        "PROVIDER_NOT_FOUND",
        "PROVIDER_RATE_LIMIT",
        "PROVIDER_REQUEST_FAILED",
        "PROVIDER_FAILED",
    }:
        params["_bs_create_outcome_unknown"] = False
    else:
        params["_bs_create_outcome_unknown"] = bool(params.get("_bs_create_outcome_unknown"))
    params["_bs_last_error_code"] = code
    params["_bs_last_error_category"] = "manual_review" if manual_review else "terminal"
    restore.params = params
    restore.error = _restore_message(code)
    restore.status = _restore_status("FAILED")
    restore.operation_phase = _restore_phase("MANUAL_REVIEW" if manual_review else "FAILED")
    if hasattr(restore, "last_error_code"):
        restore.last_error_code = code
    fields = ["params", "error", "status", "operation_phase", "modified"]
    if hasattr(restore, "last_error_code"):
        fields.append("last_error_code")
    restore.save(update_fields=fields)
    return _restore_status("FAILED")


def _restore_adopt(restore, resource_id, *, provider_status=None, params_update=None, marker_verified=True):
    resource_id = str(resource_id or "").strip()
    if not resource_id:
        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True)
    params = _restore_params(restore)
    params.update(params_update or {})
    params["_bs_create_outcome_unknown"] = False
    params["_bs_marker_verified"] = bool(marker_verified)
    if provider_status is not None:
        params["_bs_provider_status"] = str(provider_status)[:64]
    restore.resource_id = resource_id
    restore.params = params
    restore.status = _restore_status("IN_PROGRESS")
    restore.operation_phase = _restore_phase("POLLING")
    restore.error = ""
    fields = ["resource_id", "params", "status", "operation_phase", "error", "modified"]
    if getattr(restore, "provider_job_id", None) is not None:
        fields.append("provider_job_id")
    restore.save(update_fields=list(dict.fromkeys(fields)))
    return resource_id


def _restore_begin_mutation(restore):
    params = _restore_params(restore)
    params["_bs_create_outcome_unknown"] = True
    params["_bs_mutation_started_at"] = timezone.now().isoformat()
    restore.params = params
    restore.operation_phase = _restore_phase("CREATE_UNKNOWN")
    restore.save(update_fields=["params", "operation_phase", "modified"])


def _restore_clear_unknown(restore):
    params = _restore_params(restore)
    params["_bs_create_outcome_unknown"] = False
    restore.params = params
    restore.save(update_fields=["params", "modified"])


def _restore_unknown(restore):
    return bool(_restore_params(restore).get("_bs_create_outcome_unknown"))


def _restore_record_scan(restore, *, item_count, match_count):
    """Persist bounded inventory proof used to explain a fenced restore retry."""
    params = _restore_params(restore)
    params["_bs_reconciliation"] = {
        "scan_complete": True,
        "scan_item_count": int(item_count),
        "scan_match_count": int(match_count),
    }
    restore.params = params
    restore.save(update_fields=["params", "modified"])


def _restore_candidates(restore, candidates, *, source_id=None, marker=None, id_key="id", marker_match=None, source_match=None):
    """Adopt exactly one owned candidate, or fail closed on ambiguity."""
    candidates = list(candidates or [])
    matched = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if marker_match and marker_match(candidate, marker):
            matched.append(candidate)
        elif not marker_match and candidate.get("name") == getattr(restore, "name", None):
            matched.append(candidate)
    if len(matched) > 1:
        _restore_safe_failure(restore, "PROVIDER_DUPLICATE_MATCH", manual_review=True)
        raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
    if not matched:
        if _restore_unknown(restore):
            _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
            raise _RestoreProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        return None
    candidate = matched[0]
    if source_match and not source_match(candidate, source_id):
        _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    resource_id = (
        candidate.get(id_key)
        or candidate.get("uuid")
        or candidate.get("name")
        or candidate.get("InstanceId")
        or candidate.get("VolumeId")
        or candidate.get("DBInstanceIdentifier")
    )
    if str(resource_id) == str(source_id):
        _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    _restore_adopt(restore, resource_id, provider_status=candidate.get("status"), marker_verified=True)
    return candidate


def _restore_tags(tags):
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    result = {}
    for item in tags or []:
        if isinstance(item, dict) and item.get("Key") is not None:
            result[str(item["Key"])] = str(item.get("Value", ""))
        elif isinstance(item, str):
            result[item] = item
    return result


def _restore_marker_matches(resource, marker):
    tags = _restore_tags(
        resource.get("tags")
        or resource.get("Tags")
        or resource.get("TagList")
        or resource.get("labels")
        or resource.get("freeformTags")
        or resource.get("freeform_tags")
    )
    values = set(tags) | set(tags.values())
    return str(marker) in values or str(marker) in {f"backupsheep.restore:{marker}", f"BackupSheepRestore:{marker}"}


def _restore_source_matches(resource, source_id, *keys):
    expected = str(source_id)
    values = []
    for key in keys:
        value = resource.get(key)
        if isinstance(value, dict):
            values.extend(value.values())
        elif isinstance(value, list):
            values.extend(value)
        else:
            values.append(value)
    values = {str(value) for value in values if value is not None}
    # Some providers omit the source field after creation. In that case the
    # provider-side marker remains the ownership proof for new restores.
    return not values or expected in values or any(expected in value for value in values)


def _restore_http_class(response, *, mutation=False):
    if response is None or not hasattr(response, "status_code"):
        return _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
    status = int(getattr(response, "status_code", 0) or 0)
    if 200 <= status < 300:
        return None
    if status in {401, 403}:
        return _RestoreProviderError("PROVIDER_AUTH_FAILED")
    if status == 404:
        return _RestoreProviderError("PROVIDER_NOT_FOUND")
    if status == 429:
        return _RestoreProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if status in {408, 425, 500, 502, 503, 504}:
        return _RestoreProviderError(
            "PROVIDER_TIMEOUT" if status in {408, 504} else "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
        )
    return _RestoreProviderError("PROVIDER_FAILED")


def _restore_sdk_status(response, *, mutation=False):
    status = int(getattr(response, "status", 0) or 0)
    if 200 <= status < 300:
        return None
    if status in {401, 403}:
        return _RestoreProviderError("PROVIDER_AUTH_FAILED")
    if status == 404:
        return _RestoreProviderError("PROVIDER_NOT_FOUND")
    if status == 429:
        return _RestoreProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if status in {408, 425, 500, 502, 503, 504}:
        return _RestoreProviderError(
            "PROVIDER_TIMEOUT" if status in {408, 504} else "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
        )
    return _RestoreProviderError("PROVIDER_FAILED")


def _restore_exception(error, *, mutation=False):
    """Classify provider SDK/HTTP exceptions without retaining their text."""
    if isinstance(error, _RestoreProviderError):
        return error
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return _RestoreProviderError(
            "PROVIDER_MALFORMED_RESPONSE",
            unknown_outcome=mutation,
        )
    name = error.__class__.__name__.lower()
    if "credential" in name or "auth" in name or "unauthorized" in name:
        return _RestoreProviderError("PROVIDER_AUTH_FAILED")
    if "notfound" in name or "not_found" in name:
        return _RestoreProviderError("PROVIDER_NOT_FOUND")
    if "timeout" in name or "timedout" in name:
        return _RestoreProviderError("PROVIDER_TIMEOUT", retryable=True, unknown_outcome=mutation)
    if "throttl" in name or "ratelimit" in name or "too_many" in name:
        return _RestoreProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if isinstance(error, ClientError):
        response = error.response or {}
        error_data = response.get("Error") or {}
        code = str(error_data.get("Code") or "").lower()
        status = int(response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0)
        if code in {"accessdenied", "accessdeniedexception", "expiredtoken", "invalidclienttokenid", "signaturedoesnotmatch", "unauthorizedoperation", "unrecognizedclientexception"} or status in {401, 403}:
            return _RestoreProviderError("PROVIDER_AUTH_FAILED")
        if code in {"resourcenotfoundexception", "notfound", "notfoundexception", "dbinstancenotfound", "dbsnapshotnotfound", "dbsnapshotnotfoundfault", "invalidsnapshot.notfound"} or status == 404:
            return _RestoreProviderError("PROVIDER_NOT_FOUND")
        if code in {"throttling", "throttlingexception", "requestlimitexceeded", "limitexceededexception", "toomanyrequestsexception"} or status == 429:
            return _RestoreProviderError("PROVIDER_RATE_LIMIT", retryable=True)
        if status in {408, 425, 500, 502, 503, 504} or code in {"internalerror", "serviceunavailable", "requesttimeout", "requesttimeoutexception"}:
            return _RestoreProviderError("PROVIDER_TRANSIENT_OUTAGE", retryable=True, unknown_outcome=mutation)
    if "connection" in name or "tempor" in name or "unavailable" in name:
        return _RestoreProviderError("PROVIDER_TRANSIENT_OUTAGE", retryable=True, unknown_outcome=mutation)
    status = int(getattr(error, "status", 0) or 0)
    if status:
        return _restore_sdk_status(SimpleNamespace(status=status), mutation=mutation)
    return _RestoreProviderError("PROVIDER_FAILED")


def _restore_handle_error(restore, error, *, mutation=False, raise_terminal=True):
    classified = _restore_exception(error, mutation=mutation)
    if classified.retryable:
        if classified.unknown_outcome or mutation:
            _restore_unknown_outcome(restore, code=classified.code)
        else:
            params = _restore_params(restore)
            params["_bs_last_error_code"] = classified.code
            params["_bs_last_error_category"] = "retryable"
            restore.params = params
            restore.error = _restore_message(classified.code)
            restore.status = _restore_status("IN_PROGRESS")
            restore.save(update_fields=["params", "error", "status", "modified"])
        if raise_terminal:
            return _restore_status("IN_PROGRESS")
        return _restore_status("IN_PROGRESS")
    _restore_safe_failure(restore, classified.code, manual_review=classified.code in {
        "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
    })
    if raise_terminal:
        raise classified
    return _restore_status("FAILED")


def _restore_verify_target(restore, resource, *, source_id=None, marker=None, source_keys=(), marker_required=None):
    if not isinstance(resource, dict):
        _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        return False
    resource_id = resource.get("id") or resource.get("uuid") or resource.get("name") or resource.get("InstanceId") or resource.get("VolumeId") or resource.get("DBInstanceIdentifier")
    if source_id is not None and str(resource_id) == str(source_id):
        _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        return False
    marker_required = bool(marker_required if marker_required is not None else _restore_params(restore).get("_bs_marker_required"))
    has_marker_fields = any(
        key in resource
        for key in (
            "tags",
            "Tags",
            "TagList",
            "labels",
            "freeformTags",
            "freeform_tags",
        )
    )
    if marker and marker_required and has_marker_fields and not _restore_marker_matches(resource, marker):
        _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        return False
    if marker and marker_required and not has_marker_fields and resource.get("name"):
        if str(resource.get("name")) != str(getattr(restore, "name", "")):
            _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
            return False
    if source_id is not None and source_keys and not _restore_source_matches(resource, source_id, *source_keys):
        _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        return False
    return True


_VULTR_SAFE_MESSAGES = {
    "PROVIDER_NOT_FOUND": "Vultr could not find the requested source or target.",
    "PROVIDER_AUTH_FAILED": "Vultr rejected the configured credentials or permissions.",
    "PROVIDER_RATE_LIMIT": "Vultr rate-limited the request; BackupSheep will resume automatically.",
    "PROVIDER_TIMEOUT": "The Vultr request timed out; BackupSheep is reconciling its outcome.",
    "PROVIDER_TRANSIENT_OUTAGE": "Vultr is temporarily unavailable; BackupSheep will resume automatically.",
    "PROVIDER_MALFORMED_RESPONSE": "Vultr returned an invalid response; manual review may be required.",
    "PROVIDER_FAILED": "Vultr reported a terminal failure.",
    "PROVIDER_REQUEST_FAILED": "The Vultr request could not be completed.",
    "PROVIDER_OWNERSHIP_MISMATCH": "The Vultr resource failed ownership verification; manual review is required.",
    "PROVIDER_DUPLICATE_MATCH": "Multiple Vultr resources matched; manual review is required.",
    "PROVIDER_RECONCILIATION_REQUIRED": "The Vultr operation has no unique adopted resource; manual review is required.",
}


def _vultr_safe_message(code):
    return _VULTR_SAFE_MESSAGES.get(
        str(code or "PROVIDER_REQUEST_FAILED"),
        _VULTR_SAFE_MESSAGES["PROVIDER_REQUEST_FAILED"],
    )


def _vultr_backup_failure(node, backup, code):
    """Build a public-safe backup exception while retaining its stable code."""
    failure = NodeBackupFailedError(
        node,
        backup.uuid_str,
        backup.attempt_no,
        backup.type,
        message=_vultr_safe_message(code),
    )
    # NodeBackupFailedError predates the safe notification contract. Attach the
    # allowlisted code without changing that shared exception module.
    failure.error_code = str(code)
    return failure


def _raise_vultr_backup_failure(node, backup, code, *, cause=None):
    failure = _vultr_backup_failure(node, backup, code)
    if cause is not None:
        raise failure from cause
    raise failure


def _record_restore_retryable_error(restore, code):
    """Persist a code/message pair without provider response text."""
    params = _restore_params(restore)
    params["_bs_last_error_code"] = str(code)
    params["_bs_last_error_category"] = "retryable"
    restore.params = params
    restore.error = _restore_message(code)
    restore.status = _restore_status("IN_PROGRESS")
    restore.operation_phase = _restore_phase("POLLING")
    fields = ["params", "error", "status", "operation_phase", "modified"]
    if hasattr(restore, "last_error_code"):
        restore.last_error_code = str(code)
        fields.append("last_error_code")
    restore.save(update_fields=list(dict.fromkeys(fields)))


def _safe_vultr_record(record):
    """Persist only bounded, non-secret Vultr resource identity fields."""
    if not isinstance(record, dict):
        return {}
    allowed = {
        "id", "instance_id", "block_id", "snapshot_id", "description", "label",
        "status", "state", "size", "size_gb", "region", "plan", "type", "date",
        "time", "date_created", "created_at", "updated_at", "tags", "source_id",
        "source_database_id", "database_id", "parent_id", "job_id", "operation_id",
    }
    result = {}
    for key in allowed:
        if key not in record:
            continue
        value = record[key]
        if key == "tags" and isinstance(value, list):
            result[key] = [str(item)[:128] for item in value[:128]]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = str(value)[:512] if isinstance(value, str) else value
    return result


def _vultr_same_region(actual, expected):
    if actual in (None, "") or expected in (None, ""):
        return True
    return str(actual).casefold() == str(expected).casefold()


class _BackupProviderError(RuntimeError):
    """Internal provider error with a stable, secret-free failure contract."""

    def __init__(self, code, *, retryable=False, unknown_outcome=False, manual_review=False):
        self.code = str(code or "PROVIDER_FAILED")
        self.retryable = bool(retryable)
        self.unknown_outcome = bool(unknown_outcome)
        self.manual_review = bool(manual_review)
        super().__init__(
            _BACKUP_NOTIFICATION_MESSAGES.get(
                self.code,
                _BACKUP_NOTIFICATION_MESSAGES["PROVIDER_FAILED"],
            )
        )


def _backup_provider_response_error(response, *, mutation=False):
    """Classify a provider response without retaining its body or headers."""
    # OVH's SDK returns decoded dictionaries while UpCloud's requests wrapper
    # returns Response objects.  A decoded payload has no HTTP status to
    # classify, so it is a successful transport response and must be validated
    # by the caller as a provider payload instead.
    if isinstance(response, (dict, list)):
        return None
    if response is None or not hasattr(response, "status_code"):
        return _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
    status = int(getattr(response, "status_code", 0) or 0)
    if 200 <= status < 300:
        return None
    if status in {401, 403}:
        return _BackupProviderError("PROVIDER_AUTH_FAILED")
    if status == 404:
        return _BackupProviderError("PROVIDER_NOT_FOUND")
    if status == 429:
        return _BackupProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if status in {408, 425, 500, 502, 503, 504} or status >= 500:
        return _BackupProviderError(
            "PROVIDER_TIMEOUT" if status in {408, 504} else "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
        )
    return _BackupProviderError("PROVIDER_REQUEST_FAILED")


def _backup_provider_exception(error, *, mutation=False):
    """Map provider SDK/HTTP exceptions to the existing safe backup codes."""
    if isinstance(error, _BackupProviderError):
        return error
    if isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
        return _BackupProviderError(
            "PROVIDER_TIMEOUT", retryable=True, unknown_outcome=mutation
        )
    if isinstance(error, requests.exceptions.ConnectionError):
        return _BackupProviderError(
            "PROVIDER_TRANSIENT_OUTAGE", retryable=True, unknown_outcome=mutation
        )
    if isinstance(error, InvalidCredential):
        return _BackupProviderError("PROVIDER_AUTH_FAILED")

    status = getattr(error, "status_code", None) or getattr(error, "status", None)
    if status:
        classified = _backup_provider_response_error(
            SimpleNamespace(status_code=status), mutation=mutation
        )
        if classified:
            return classified

    name = error.__class__.__name__.lower()
    if any(token in name for token in ("credential", "unauthorized", "forbidden", "auth")):
        return _BackupProviderError("PROVIDER_AUTH_FAILED")
    if any(token in name for token in ("notfound", "not_found", "doesnotexist")):
        return _BackupProviderError("PROVIDER_NOT_FOUND")
    if any(token in name for token in ("ratelimit", "throttl", "too_many")):
        return _BackupProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if any(token in name for token in ("timeout", "timedout")):
        return _BackupProviderError(
            "PROVIDER_TIMEOUT", retryable=True, unknown_outcome=mutation
        )
    if any(token in name for token in ("connection", "unavailable", "tempor")):
        return _BackupProviderError(
            "PROVIDER_TRANSIENT_OUTAGE", retryable=True, unknown_outcome=mutation
        )
    if isinstance(error, (ValueError, KeyError, TypeError, json.JSONDecodeError)):
        return _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=mutation, manual_review=True
        )
    return _BackupProviderError(
        "PROVIDER_FAILED", unknown_outcome=mutation and isinstance(error, ResourceConflictError)
    )


def _backup_execution_fence(backup):
    """Return the current durable execution row and its optional fencing token."""
    state = backup.get_execution_state(create=True)
    if state is None or not state.lease_token:
        return state, {}
    return state, {
        "lease_owner": state.lease_owner,
        "lease_token": state.lease_token,
    }


def _backup_scope_fingerprint(provider, source_id, resource_type, scope):
    payload = {
        "provider": str(provider),
        "source_id": str(source_id),
        "resource_type": str(resource_type),
        "scope": dict(scope or {}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _backup_request_marker(backup):
    """Return the execution-owned marker, never a mutable display value."""
    state = backup.get_execution_state(create=True)
    marker = getattr(state, "provider_idempotency_key", None) if state else None
    marker = marker or backup.uuid_str or f"backupsheep-backup-{backup.pk}"
    return str(marker)[:128]


def _backup_provider_witness(backup, *, provider, source_id, resource_type, scope, source=None):
    """Build the immutable, bounded source/scope witness stored before mutation."""
    scope = {
        str(key): str(value)[:255]
        for key, value in (scope or {}).items()
        if value not in (None, "")
    }
    witness = {
        "provider": str(provider)[:64],
        "marker": _backup_request_marker(backup),
        "source_id": str(source_id)[:255],
        "resource_type": str(resource_type)[:64],
        "scope": scope,
        "scope_fingerprint": _backup_scope_fingerprint(
            provider, source_id, resource_type, scope
        ),
    }
    if isinstance(source, dict):
        for key in (
            "projectId", "project_id", "tenantId", "tenant_id", "accountId", "account_id",
            "region", "zone", "availability_zone",
        ):
            value = source.get(key)
            if value not in (None, ""):
                witness[f"source_{key}"] = str(value)[:255]
    return witness


def _backup_safe_identity(resource, *, id_keys=(), value_keys=()):
    """Keep only bounded provider identity fields in durable backup metadata."""
    if not isinstance(resource, dict):
        return {}
    keys = tuple(id_keys) + tuple(value_keys) + (
        "name", "title", "description", "status", "state", "size", "size_gigabytes",
        "region", "zone", "origin", "source_id", "sourceId", "instanceId", "volumeId",
        "uuid", "id", "projectId", "project_id", "type", "created_at",
    )
    result = {}
    for key in dict.fromkeys(keys):
        if key not in resource:
            continue
        value = resource.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[str(key)[:64]] = str(value)[:512] if isinstance(value, str) else value
    return result


def _backup_execution_metadata(backup):
    state = backup.get_execution_state(create=True)
    metadata = dict(state.provider_metadata or {}) if state else {}
    return state, metadata


def _backup_record_provider_witness(
    backup,
    witness,
    *,
    provider_status="reconciling",
    metadata=None,
    reconciliation_state=None,
    reconciliation_reason=None,
):
    """Persist marker and source/scope evidence through the fenced execution row."""
    state, fence = _backup_execution_fence(backup)
    provider_metadata = {
        "witness": dict(witness),
        "marker": witness.get("marker"),
        "source_id": witness.get("source_id"),
        "resource_type": witness.get("resource_type"),
        "scope": dict(witness.get("scope") or {}),
        "scope_fingerprint": witness.get("scope_fingerprint"),
    }
    provider_metadata.update(dict(metadata or {}))
    saved = backup.record_provider_reference(
        idempotency_key=witness.get("marker"),
        provider_status=provider_status,
        metadata=provider_metadata,
        **fence,
    )
    if fence and saved is None:
        raise _BackupProviderError("WORKER_LEASE_LOST", manual_review=True)
    if reconciliation_state:
        from apps.console.backup.models import CoreBackupExecution

        saved = backup.set_reconciliation_state(
            reconciliation_state=reconciliation_state,
            reason=reconciliation_reason,
            metadata=dict(metadata or {}),
            **fence,
        )
        if fence and saved is None:
            raise _BackupProviderError("WORKER_LEASE_LOST", manual_review=True)
    return saved or state


def _backup_mark_create_started(backup, witness):
    from apps.console.backup.models import CoreBackupExecution

    return _backup_record_provider_witness(
        backup,
        witness,
        provider_status="create_requested",
        metadata={
            "create_attempted": True,
            "outcome_unknown": True,
            "create_started_at": timezone.now().isoformat(),
        },
        reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
        reconciliation_reason="provider_create_outcome_unknown",
    )


def _backup_record_create_failure(
    backup,
    witness,
    error,
    *,
    scan_metadata=None,
):
    """Persist a classified provider result and never the provider exception text."""
    from apps.console.backup.models import CoreBackupExecution

    classified = _backup_provider_exception(error, mutation=bool(getattr(error, "unknown_outcome", False)))
    state, current = _backup_execution_metadata(backup)
    attempted = bool(current.get("create_attempted"))
    unknown = bool(getattr(classified, "unknown_outcome", False) or attempted)
    retryable = bool(getattr(classified, "retryable", False))
    manual_review = bool(
        getattr(classified, "manual_review", False)
        or classified.code in {
            "PROVIDER_DUPLICATE_MATCH",
            "PROVIDER_RECONCILIATION_REQUIRED",
            "PROVIDER_OWNERSHIP_MISMATCH",
            "PROVIDER_MALFORMED_RESPONSE",
            "WORKER_LEASE_LOST",
        }
    )
    if classified.code in {
        "PROVIDER_AUTH_FAILED",
        "PROVIDER_NOT_FOUND",
        "PROVIDER_RATE_LIMIT",
        "PROVIDER_REQUEST_FAILED",
    } and not getattr(classified, "unknown_outcome", False):
        # A definitive provider rejection is not evidence that a mutation
        # happened. Leave the witness reusable after the retry window while
        # retaining the safe error code. Timeouts and 5xx responses stay fenced.
        unknown = False
        attempted = False
    metadata = {
        "create_attempted": attempted,
        "outcome_unknown": unknown,
        "last_error_code": classified.code,
    }
    # Preserve the completed inventory proof when the final outcome is a
    # duplicate, ownership failure, or zero-match unknown.  The failure record
    # must explain what was reconciled without retaining provider response text.
    for key in ("scan_page_count", "scan_item_count", "scan_match_count", "scan_complete"):
        if key in current:
            metadata[key] = current[key]
    metadata.update(dict(scan_metadata or {}))
    fence = {}
    if state is not None and state.lease_token:
        fence = {"lease_owner": state.lease_owner, "lease_token": state.lease_token}
    saved = backup.record_provider_reference(
        idempotency_key=witness.get("marker"),
        provider_status=classified.code,
        metadata={**{
            "witness": dict(witness),
            "marker": witness.get("marker"),
            "source_id": witness.get("source_id"),
            "scope": dict(witness.get("scope") or {}),
        }, **metadata},
        **fence,
    )
    if fence and saved is None:
        return classified
    saved = backup.record_execution_error(
        code=classified.code,
        message=_BACKUP_NOTIFICATION_MESSAGES.get(
            classified.code,
            _BACKUP_NOTIFICATION_MESSAGES["PROVIDER_FAILED"],
        ),
        retryable=retryable,
        reconciliation_reason=(
            "provider_create_outcome_unknown" if unknown else
            "provider_manual_review" if manual_review else ""
        ),
        reconciliation_metadata=metadata,
        **fence,
    )
    if fence and saved is None:
        return classified
    if manual_review:
        saved = backup.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
            reason=classified.code,
            metadata=metadata,
            **fence,
        )
        if fence and saved is None:
            return classified
    elif not unknown:
        saved = backup.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
            reason=classified.code,
            metadata=metadata,
            **fence,
        )
        if fence and saved is None:
            return classified
    backup.status = (
        UtilBackup.Status.IN_PROGRESS
        if retryable and not manual_review
        else UtilBackup.Status.FAILED
    )
    safe_metadata = dict(backup.metadata) if isinstance(backup.metadata, dict) else {}
    safe_metadata.update({"_bs_provider": witness.get("provider"), "_bs_marker": witness.get("marker")})
    safe_metadata["_bs_last_error_code"] = classified.code
    safe_metadata["_bs_reconciliation"] = metadata
    backup.metadata = safe_metadata
    backup.save(update_fields=["status", "metadata", "modified"])
    return classified


def _backup_raise_node_error(node, backup, classified):
    """Raise the existing public exception with a fixed, allowlisted message."""
    failure = NodeBackupFailedError(
        node,
        backup.uuid_str,
        backup.attempt_no,
        backup.type,
        message=_BACKUP_NOTIFICATION_MESSAGES.get(
            classified.code,
            _BACKUP_NOTIFICATION_MESSAGES["PROVIDER_FAILED"],
        ),
    )
    failure.error_code = classified.code
    failure.retryable = bool(getattr(classified, "retryable", False))
    failure.unknown_outcome = bool(getattr(classified, "unknown_outcome", False))
    raise failure


def _backup_adopt_provider_resource(
    backup,
    resource,
    *,
    witness,
    provider,
    id_keys=("id", "uuid"),
):
    """Persist a single provider resource and its execution pointer atomically enough for recovery."""
    if not isinstance(resource, dict):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True)
    resource_id = next(
        (resource.get(key) for key in id_keys if resource.get(key) not in (None, "")),
        None,
    )
    if resource_id in (None, ""):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True)
    if str(resource_id) == str(witness.get("source_id")):
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)

    safe_record = _backup_safe_identity(resource, id_keys=id_keys)
    safe_record.update(
        {
            "_bs_provider": str(provider)[:64],
            "_bs_marker": witness.get("marker"),
            "_bs_source_id": witness.get("source_id"),
            "_bs_scope": dict(witness.get("scope") or {}),
            "_bs_scope_fingerprint": witness.get("scope_fingerprint"),
            "_bs_ownership_verified": True,
        }
    )
    # Claim the current execution fence before touching the backup row.  The
    # execution ledger receives the provider ID first, so a worker crash between
    # the ledger write and the model save still leaves a recovery pointer and
    # cannot justify a second provider mutation.
    _state, fence = _backup_execution_fence(backup)
    operation_id = next(
        (
            resource.get(key)
            for key in ("actionId", "action_id", "operationId", "operation_id", "jobId", "job_id")
            if resource.get(key) not in (None, "")
        ),
        None,
    )
    saved = backup.record_provider_reference(
        operation_id=operation_id,
        resource_id=str(resource_id)[:255],
        idempotency_key=witness.get("marker"),
        provider_status=str(resource.get("status") or resource.get("state") or "accepted")[:64],
        metadata={
            "witness": dict(witness),
            "resource": safe_record,
            "create_attempted": True,
            "outcome_unknown": False,
            "adopted": True,
        },
        **fence,
    )
    if fence and saved is None:
        raise _BackupProviderError("WORKER_LEASE_LOST", manual_review=True)

    update_fields = ["unique_id", "metadata", "modified"]
    backup.unique_id = str(resource_id)[:255]
    if operation_id is not None and hasattr(backup, "action_id"):
        backup.action_id = str(operation_id)[:255]
        update_fields.insert(1, "action_id")
    if hasattr(backup, "size_gigabytes"):
        size = resource.get("size_gigabytes")
        if size is None:
            size = resource.get("size")
        if size is not None:
            backup.size_gigabytes = size
            update_fields.insert(1, "size_gigabytes")
    backup.metadata = safe_record
    backup.save(update_fields=list(dict.fromkeys(update_fields)))
    from apps.console.backup.models import CoreBackupExecution

    saved = backup.set_reconciliation_state(
        reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
        reason="provider_resource_adopted",
        metadata={
            "match_count": 1,
            "resource_id_persisted": True,
            "ownership_verified": True,
        },
        **fence,
    )
    if fence and saved is None:
        raise _BackupProviderError("WORKER_LEASE_LOST", manual_review=True)
    return backup.unique_id


def _collection_items_and_next(payload, item_keys):
    """Extract a provider collection and a bounded page/cursor continuation."""
    if isinstance(payload, list):
        return payload, None
    if not isinstance(payload, dict):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)

    containers = [payload]
    for key in ("data", "meta", "pagination", "links", "storages", "snapshots"):
        value = payload.get(key)
        if isinstance(value, dict):
            containers.append(value)
    items = None
    for container in containers:
        for key in item_keys:
            value = container.get(key)
            if isinstance(value, list):
                items = value
                break
            if isinstance(value, dict) and key in {"storage", "snapshot", "item", "resource"}:
                items = [value]
                break
        if items is not None:
            break
    if items is None:
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)

    next_info = None
    next_keys = (
        ("next", "next"), ("next_url", "href"), ("nextLink", "href"),
        ("next_page", "page"), ("nextPage", "page"),
        ("next_cursor", "cursor"), ("nextCursor", "cursor"),
        ("next_page_token", "cursor"), ("nextPageToken", "cursor"),
    )
    for container in containers:
        for key, kind in next_keys:
            value = container.get(key)
            if value not in (None, "", False):
                if isinstance(value, dict):
                    if value.get("href") or value.get("url"):
                        kind = "href"
                        value = value.get("href") or value.get("url")
                    elif value.get("cursor") not in (None, ""):
                        kind = "cursor"
                        value = value.get("cursor")
                    else:
                        kind = "page"
                        value = value.get("page")
                elif kind == "next":
                    # A bare ``next`` token is a cursor unless the provider
                    # explicitly gives us a numeric page value.
                    kind = "page" if isinstance(value, int) else "cursor"
                if value not in (None, "", False):
                    next_info = (kind, value)
                    break
        if next_info:
            break

    # Some APIs expose only page/limit/total. Derive the next page when the response
    # proves that more objects exist; never guess from an object count alone.
    if next_info is None:
        page = None
        limit = None
        total = None
        for container in containers:
            page = page if page is not None else container.get("page")
            limit = limit if limit is not None else container.get("limit") or container.get("per_page") or container.get("perPage")
            total = total if total is not None else container.get("total") or container.get("count")
        try:
            page = int(page) if page is not None else None
            limit = int(limit) if limit is not None else None
            total = int(total) if total is not None else None
        except (TypeError, ValueError):
            page = limit = total = None
        if page is not None and limit and total is not None and page * limit < total:
            next_info = ("page", page + 1)
    return items, next_info


def _collection_next_path(path, next_info):
    kind, value = next_info
    if kind == "href" and isinstance(value, str):
        return value
    parameter = "cursor" if kind == "cursor" else "page"
    return f"{path}{'&' if '?' in path else '?'}{parameter}={quote(str(value), safe='')}"


def _iter_provider_collection(client, path, item_keys, *, stats=None):
    """Yield every provider page and fail closed on repeated/malformed cursors."""
    current_path = path
    seen_paths = set()
    while True:
        if current_path in seen_paths:
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        seen_paths.add(current_path)
        if isinstance(stats, dict):
            stats["page_count"] = int(stats.get("page_count", 0)) + 1
        payload = client.get(current_path)
        response_error = _backup_provider_response_error(payload)
        if response_error is not None:
            raise response_error
        if not isinstance(payload, (dict, list)) and callable(getattr(payload, "json", None)):
            try:
                payload = payload.json()
            except Exception:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                ) from None
        items, next_info = _collection_items_and_next(payload, item_keys)
        for item in items:
            yield item
        if next_info is None:
            return
        next_path = _collection_next_path(path, next_info)
        if next_path in seen_paths:
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        current_path = next_path


class _UpCloudCollectionClient:
    """Adapt the shared page walker to UpCloud's requests-based API."""

    def __init__(self, auth):
        self.auth = auth

    def get(self, path):
        return requests.get(
            path,
            auth=self.auth,
            verify=True,
            timeout=request_timeout(),
            headers={"content-type": "application/json"},
        )


def _identity_values(resource, keys):
    values = []
    for key in keys:
        if key not in resource:
            continue
        value = resource.get(key)
        if isinstance(value, dict):
            value = value.get("id") or value.get("uuid") or value.get("name")
        if isinstance(value, list):
            values.extend(str(item) for item in value if item not in (None, ""))
        elif value not in (None, ""):
            values.append(str(value))
    return values


def _strict_provider_candidate(
    resource,
    *,
    marker,
    source_id,
    source_keys,
    scope=None,
    scope_keys=(),
    require_source=True,
    scope_proven=False,
):
    """Return ``True`` only for a fully owned marker/source/scope candidate."""
    if not isinstance(resource, dict):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
    if source_id in (None, ""):
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    marker_values = _identity_values(
        resource, ("name", "title", "description", "snapshotName", "displayName")
    )
    if not marker_values or str(marker) not in marker_values:
        return False
    source_values = _identity_values(resource, source_keys)
    if require_source and not source_values:
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    if source_values and str(source_id) not in source_values:
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    for expected_key, actual_keys in scope_keys:
        expected = (scope or {}).get(expected_key)
        if expected in (None, ""):
            continue
        actual_values = _identity_values(resource, actual_keys)
        if not actual_values and scope_proven:
            # A provider collection path can be an immutable scope witness (the
            # OVH endpoint is project+region scoped).  Still reject a field that
            # is present but contradicts that endpoint boundary.
            continue
        if not actual_values or str(expected) not in actual_values:
            raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    return True


def _strict_restore_candidate(resource, **identity):
    """Translate strict ownership failures into the restore error contract."""
    try:
        return _strict_provider_candidate(resource, **identity)
    except _BackupProviderError as error:
        raise _RestoreProviderError(
            error.code,
            retryable=error.retryable,
            unknown_outcome=error.unknown_outcome,
        ) from None


class CoreServerStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_server_status"


class CoreServerType(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_server_type"


class CoreDigitalOcean(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="digitalocean", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_digitalocean"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_digitalocean.get_client()
        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                r_json = result.json()
                if r_json.get("droplet"):
                    server = r_json.get("droplet")
                    if server.get("status") == "active" and not server.get("locked"):
                        node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_digitalocean.get_client()

            def existing_snapshot(resource_type):
                params = {"resource_type": resource_type, "per_page": 200, "page": 1}
                snapshots = []
                while True:
                    response = requests.get(
                        f"{settings.DIGITALOCEAN_API}/v2/snapshots",
                        headers=client,
                        params=params,
                        verify=True,
                    )
                    if response.status_code != 200:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            "Unable to verify existing DigitalOcean snapshots before creating a new one.",
                        )
                    payload = response.json()
                    # DigitalOcean returns ``snapshots: null`` when the account
                    # has no snapshots of the requested resource type. Treat
                    # that valid empty response exactly like ``[]``.
                    snapshots.extend(payload.get("snapshots") or [])
                    total = (payload.get("meta") or {}).get("total", len(snapshots))
                    if len(snapshots) >= total:
                        break
                    params["page"] += 1
                return next(
                    (item for item in snapshots if item.get("name") == backup.uuid_str),
                    None,
                )

            if self.node.type == CoreNode.Type.CLOUD:
                # The create request can succeed before Celery persists action_id.
                # Snapshot names are unique per BackupSheep backup, so recover it
                # before sending another droplet action.
                existing = existing_snapshot("droplet")
                if existing:
                    backup.unique_id = existing.get("id")
                    backup.size_gigabytes = existing.get("size_gigabytes")
                    backup.save()
                    return
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    droplet = result.json()["droplet"]
                    if droplet["status"] == "active" or droplet["status"] == "new":
                        droplet_data = {"type": "snapshot", "name": backup.uuid_str}
                        result = requests.post(
                            f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}/actions",
                            headers=client,
                            json=droplet_data,
                            verify=True,
                        )
                        if result.status_code == 201:
                            action = result.json()["action"]
                            backup.action_id = action.get("id")
                            backup.save()
                        elif result.status_code == 422:
                            raise NodeBackupFailedError(
                                self.node,
                                backup.uuid_str, backup.attempt_no, backup.type,
                                "Droplet is locked by another action. We will try again shortly.",
                            )
                        else:
                            raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                        f"API call returned with status {result.status_code}")
                    else:
                        raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                    f"Droplet status is {droplet['status']}")
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. Please reconnect your account to refresh authentication token.",
                    )
                else:
                    raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                f"API call returned with status {result.status_code}")

            elif self.node.type == CoreNode.Type.VOLUME:
                volume_data = {"name": backup.uuid_str}

                existing = existing_snapshot("volume")
                if existing:
                    backup.unique_id = existing.get("id")
                    backup.size_gigabytes = existing.get(
                        "min_disk_size", existing.get("size_gigabytes")
                    )
                    backup.save()
                    return

                result = requests.post(
                    f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}/snapshots",
                    headers=client,
                    json=volume_data,
                    verify=True,
                )

                if result.status_code == 201:
                    snapshot = result.json()["snapshot"]
                    backup.unique_id = snapshot["id"]
                    backup.size_gigabytes = snapshot["min_disk_size"]
                    backup.save()
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. Please reconnect your account to refresh authentication token.",
                    )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        f"API call returned with status {result.status_code}",
                    )
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )

    def _find_restore_resource(self, client, restore, marker):
        """Find a single tagged target without guessing across pages."""
        resource_type = "droplets" if self.node.type == CoreNode.Type.CLOUD else "volumes"
        response = requests.get(
            f"{settings.DIGITALOCEAN_API}/v2/{resource_type}",
            headers=client,
            params={"tag_name": marker, "per_page": 200},
            verify=True,
        )
        problem = _restore_http_class(response)
        if problem:
            if problem.code == "PROVIDER_NOT_FOUND":
                return []
            raise problem
        try:
            payload = response.json()
        except Exception:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if not isinstance(payload, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        resources = payload.get(resource_type)
        if not isinstance(resources, list):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        meta = payload.get("meta") or {}
        total = meta.get("total")
        # DigitalOcean exposes page-based lists, not a cursor. A unique tag is
        # the exact lookup; if it somehow spans pages, fail closed rather than
        # silently reintroducing page-number reconciliation.
        if total is not None and int(total) > len(resources):
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return resources

    def _find_aws_backup_restore_job(self, client, *, recovery_point_arn, target_id):
        jobs = []
        token = None
        seen = set()
        while True:
            request = {"RecoveryPointArn": recovery_point_arn, "MaxResults": 100}
            if token:
                request["NextToken"] = token
            response = client.list_restore_jobs(**request)
            if not isinstance(response, dict):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            page = response.get("RestoreJobs") or []
            if not isinstance(page, list):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            jobs.extend(
                item for item in page
                if isinstance(item, dict)
                and str(item.get("RecoveryPointArn") or recovery_point_arn) == str(recovery_point_arn)
                and str(target_id) in str(item.get("CreatedResourceArn") or item.get("ResourceArn") or "")
            )
            next_token = response.get("NextToken")
            if not next_token:
                break
            if next_token in seen:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            seen.add(next_token)
            token = next_token
        if len(jobs) > 1:
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return jobs

    @staticmethod
    def _aws_restore_instances(response):
        if not isinstance(response, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        result = []
        for reservation in response.get("Reservations") or []:
            if not isinstance(reservation, dict):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            instances = reservation.get("Instances") or []
            if not isinstance(instances, list):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            result.extend(instances)
        return result

    def _aws_find_restore_resource(self, client, *, marker, source_id, resource_type):
        tag_filter = [{"Name": "tag:BackupSheepRestore", "Values": [marker]}]
        if resource_type == "instance":
            return self._aws_restore_instances(client.describe_instances(Filters=tag_filter))
        response = client.describe_volumes(Filters=tag_filter)
        if not isinstance(response, dict) or not isinstance(response.get("Volumes"), list):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        return response["Volumes"]

    def _restore_snapshot_aws(self, backup, restore):
        params = _restore_params(restore)
        auth = self.node.connection.auth_aws
        if self.resource_type in {self.ResourceType.S3, self.ResourceType.DYNAMODB}:
            from apps._tasks.integration.aws_backup import idempotency_token, start_restore_job

            backup_metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
            aws_backup = backup_metadata.get("_aws_backup") or {}
            recovery_point_arn = aws_backup.get("recovery_point_arn")
            if not recovery_point_arn:
                _restore_safe_failure(restore, "PROVIDER_NOT_FOUND")
                raise _RestoreProviderError("PROVIDER_NOT_FOUND")
            if self.resource_type == self.ResourceType.S3:
                target_id = str(params.get("destination_bucket_name") or "").strip()
                if not target_id:
                    _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE")
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                target_kind = "s3"
            else:
                target_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(params.get("target_table_name") or restore.name or ""))
                if not 3 <= len(target_id) <= 255:
                    _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE")
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                target_kind = "dynamodb"
            marker, params = _prepare_cloud_restore(
                restore,
                provider="aws_backup",
                source_id=recovery_point_arn,
                target_kind=target_kind,
                target_name=target_id,
            )
            if restore.provider_job_id:
                return
            client = auth.get_client("s3" if target_kind == "s3" else "dynamodb")
            try:
                if _restore_unknown(restore):
                    jobs = self._find_aws_backup_restore_job(
                        auth.get_client("backup"),
                        recovery_point_arn=recovery_point_arn,
                        target_id=target_id,
                    )
                    if not jobs:
                        return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                    job = jobs[0]
                    job_id = job.get("RestoreJobId")
                    if not job_id:
                        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                    params["_aws_backup_restore_metadata"] = dict(params.get("_aws_backup_restore_metadata") or {})
                    params["_aws_backup_restore_metadata"]["BackupSheepRestoreMarker"] = marker
                    _restore_adopt(
                        restore,
                        target_id,
                        provider_status=job.get("Status"),
                        params_update=params,
                    )
                    restore.provider_job_id = str(job_id)
                    restore.save(update_fields=["provider_job_id", "modified"])
                    return

                if target_kind == "s3":
                    preflight = getattr(self, "_aws_s3_restore_destination_preflight", None)
                    if callable(preflight):
                        preflight(client, backup, restore, target_id)
                    else:
                        client.head_bucket(Bucket=target_id)
                        if client.get_bucket_versioning(Bucket=target_id).get("Status") != "Enabled":
                            raise _RestoreProviderError("PROVIDER_FAILED")
                    restore_metadata = {"DestinationBucketName": target_id}
                    for key in ("EncryptionType", "KMSKey", "ItemsToRestore", "RestoreLatestVersionsUpTo", "RestoreTime"):
                        if key in params and params[key] is not None:
                            value = params[key]
                            restore_metadata[key] = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
                    restore_metadata["RestoreACLs"] = "true" if str(params.get("RestoreACLs")).lower() in {"true", "1"} else "false"
                else:
                    try:
                        client.describe_table(TableName=target_id)
                    except ClientError as error:
                        classified = _restore_exception(error)
                        if classified.code != "PROVIDER_NOT_FOUND":
                            raise classified
                    else:
                        _restore_safe_failure(restore, "PROVIDER_FAILED", manual_review=True)
                        raise _RestoreProviderError("PROVIDER_FAILED")
                    restore_metadata = {"TargetTableName": target_id}
                    for key in ("EncryptionType", "KmsMasterKeyArn"):
                        if key in params and params[key] is not None:
                            restore_metadata[key] = str(params[key])

                token = idempotency_token("restore", restore.id)
                params["_aws_backup_restore_metadata"] = restore_metadata
                params["_aws_backup_restore_token"] = token
                _restore_begin_mutation(restore)
                response = start_restore_job(
                    auth,
                    self.resource_type,
                    recovery_point_arn,
                    restore_metadata,
                    token,
                )
                job_id = response.get("RestoreJobId") if isinstance(response, dict) else None
                if not job_id:
                    _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                    return _restore_status("IN_PROGRESS")
                _restore_adopt(
                    restore,
                    target_id,
                    provider_status="created",
                    params_update=params,
                )
                restore.provider_job_id = str(job_id)
                restore.save(update_fields=["provider_job_id", "modified"])
                return
            except Exception as error:
                if isinstance(error, _RestoreProviderError):
                    if error.retryable:
                        return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                    _restore_safe_failure(restore, error.code, manual_review=error.code in {
                        "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                    })
                    raise
                return _restore_handle_error(restore, error, mutation=True)

        target_kind = "instance" if self.node.type == CoreNode.Type.CLOUD else "volume"
        marker, params = _prepare_cloud_restore(
            restore,
            provider="aws_ec2",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return
        client = auth.get_client()
        try:
            if _restore_unknown(restore):
                candidates = self._aws_find_restore_resource(
                    client, marker=marker, source_id=backup.unique_id, resource_type=target_kind
                )
                if len(candidates) != 1:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                candidate = _restore_candidates(
                    restore,
                    candidates,
                    source_id=backup.unique_id,
                    marker=marker,
                    marker_match=lambda item, value: _restore_marker_matches(item, value),
                    source_match=lambda item, source: _restore_source_matches(
                        item, source, "ImageId", "SnapshotId", "snapshot_id"
                    ),
                )
                if candidate:
                    return

            if target_kind == "instance":
                source_configuration = self._aws_restore_source_configuration(
                    client, backup, "instance"
                )
                effective_configuration = dict(source_configuration)
                for key in (
                    "instance_type",
                    "subnet_id",
                    "security_group_ids",
                    "key_name",
                ):
                    if key in params:
                        effective_configuration[key] = params[key]
                effective_configuration = self._aws_normalize_restore_source_configuration(
                    effective_configuration,
                    source_type="instance",
                    source_id=self.unique_id,
                )
                params["_bs_source_configuration"] = source_configuration
                restore.params = params
                restore.save(update_fields=["params", "modified"])
                instance_data = {
                    "ImageId": backup.unique_id,
                    "MinCount": 1,
                    "MaxCount": 1,
                    "InstanceType": effective_configuration["instance_type"],
                    "TagSpecifications": [{
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": restore.name},
                            {"Key": "BackupSheepRestore", "Value": marker},
                            {"Key": "BackupSheepSource", "Value": str(backup.unique_id)},
                        ],
                    }],
                }
                if effective_configuration.get("key_name"):
                    instance_data["KeyName"] = effective_configuration["key_name"]
                if effective_configuration.get("subnet_id"):
                    instance_data["SubnetId"] = effective_configuration["subnet_id"]
                if effective_configuration.get("security_group_ids"):
                    instance_data["SecurityGroupIds"] = effective_configuration[
                        "security_group_ids"
                    ]
                _restore_begin_mutation(restore)
                response = client.run_instances(**instance_data)
                instances = response.get("Instances") if isinstance(response, dict) else None
                resource_id = instances[0].get("InstanceId") if isinstance(instances, list) and len(instances) == 1 and isinstance(instances[0], dict) else None
                if not resource_id:
                    _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                    return _restore_status("IN_PROGRESS")
                _restore_adopt(restore, resource_id, provider_status="pending")
                return

            source_configuration = self._aws_restore_source_configuration(
                client, backup, "volume"
            )
            availability_zone = params.get(
                "availability_zone",
                source_configuration["availability_zone"],
            )
            effective_configuration = self._aws_normalize_restore_source_configuration(
                {
                    **source_configuration,
                    "availability_zone": availability_zone,
                },
                source_type="volume",
                source_id=self.unique_id,
            )
            params["_bs_source_configuration"] = source_configuration
            restore.params = params
            restore.save(update_fields=["params", "modified"])
            _restore_begin_mutation(restore)
            response = client.create_volume(
                AvailabilityZone=effective_configuration["availability_zone"],
                SnapshotId=backup.unique_id,
                TagSpecifications=[{
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "BackupSheepRestore", "Value": marker},
                        {"Key": "BackupSheepSource", "Value": str(backup.unique_id)},
                    ],
                }],
            )
            resource_id = response.get("VolumeId") if isinstance(response, dict) else None
            if not resource_id:
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            _restore_adopt(restore, resource_id, provider_status="creating")
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_aws(self, restore):
        auth = self.node.connection.auth_aws
        params = _restore_params(restore)
        if self.resource_type in {self.ResourceType.S3, self.ResourceType.DYNAMODB}:
            from apps._tasks.integration.aws_backup import describe_restore_job

            if not restore.provider_job_id:
                if not _restore_unknown(restore):
                    return _restore_status("IN_PROGRESS")
                metadata = params.get("_backupsheep_restore") or {}
                try:
                    jobs = self._find_aws_backup_restore_job(
                        auth.get_client("backup"),
                        recovery_point_arn=metadata.get("source_id"),
                        target_id=restore.resource_id or metadata.get("target_name"),
                    )
                    if len(jobs) != 1:
                        return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                    restore.provider_job_id = str(jobs[0].get("RestoreJobId") or "")
                    if not restore.provider_job_id:
                        return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                    restore.save(update_fields=["provider_job_id", "modified"])
                except Exception as error:
                    return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)
            try:
                result = describe_restore_job(auth, restore.provider_job_id)
                if not isinstance(result, dict):
                    return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                state = str(result.get("Status") or "").upper()
                if state == "COMPLETED":
                    target = restore.resource_id
                    if self.resource_type == self.ResourceType.S3:
                        auth.get_client("s3").head_bucket(Bucket=target)
                    else:
                        dynamodb = auth.get_client("dynamodb")
                        response = dynamodb.describe_table(TableName=target)
                        if not isinstance(response, dict) or not isinstance(
                            response.get("Table"), dict
                        ):
                            raise _RestoreProviderError(
                                "PROVIDER_MALFORMED_RESPONSE"
                            )
                        table = response["Table"]
                        table_status = str(table.get("TableStatus") or "").upper()
                        if table_status in {"CREATING", "UPDATING"}:
                            return _restore_status("IN_PROGRESS")
                        if table_status != "ACTIVE":
                            if table_status in {
                                "DELETING",
                                "INACCESSIBLE_ENCRYPTION_CREDENTIALS",
                                "ARCHIVING",
                                "ARCHIVED",
                                "REPLICATION_NOT_AUTHORIZED",
                            }:
                                return _restore_safe_failure(
                                    restore, "PROVIDER_FAILED"
                                )
                            raise _RestoreProviderError(
                                "PROVIDER_MALFORMED_RESPONSE"
                            )
                        if not self._aws_dynamodb_restore_ownership_verified(
                            auth,
                            dynamodb,
                            restore,
                            result,
                            table,
                        ):
                            return _restore_status("IN_PROGRESS")
                    restore.operation_phase = _restore_phase("COMPLETE")
                    restore.save(update_fields=["operation_phase", "modified"])
                    return _restore_status("COMPLETE")
                if state in {"FAILED", "ABORTED", "EXPIRED"}:
                    return _restore_safe_failure(restore, "PROVIDER_FAILED")
                if state not in {"PENDING", "RUNNING", "PARTIAL"}:
                    return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                return _restore_status("IN_PROGRESS")
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

        client = auth.get_client()
        source_id = (params.get("_backupsheep_restore") or {}).get("source_id")
        marker = _restore_marker_value(restore)
        if not restore.resource_id:
            return _restore_status("IN_PROGRESS")
        try:
            if self.node.type == CoreNode.Type.CLOUD:
                response = client.describe_instances(InstanceIds=[restore.resource_id])
                instances = self._aws_restore_instances(response)
                if len(instances) != 1:
                    return _restore_safe_failure(restore, "PROVIDER_NOT_FOUND")
                instance = instances[0]
                if not _restore_verify_target(restore, instance, source_id=source_id, marker=marker, source_keys=("ImageId",)):
                    return _restore_status("FAILED")
                state = (instance.get("State") or {}).get("Name")
                if state == "running":
                    restore.operation_phase = _restore_phase("COMPLETE")
                    restore.save(update_fields=["operation_phase", "modified"])
                    return _restore_status("COMPLETE")
                if state in {"terminated", "shutting-down"}:
                    return _restore_safe_failure(restore, "PROVIDER_FAILED")
                if state not in {"pending", "stopped", "stopping", "starting", "running"}:
                    return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                return _restore_status("IN_PROGRESS")
            response = client.describe_volumes(VolumeIds=[restore.resource_id])
            volumes = response.get("Volumes") if isinstance(response, dict) else None
            if not isinstance(volumes, list) or len(volumes) != 1:
                return _restore_safe_failure(restore, "PROVIDER_NOT_FOUND")
            volume = volumes[0]
            if not _restore_verify_target(restore, volume, source_id=source_id, marker=marker, source_keys=("SnapshotId",)):
                return _restore_status("FAILED")
            state = volume.get("State")
            if state == "available":
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if state in {"error", "deleted"}:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if state not in {"creating", "available", "in-use"}:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_digitalocean.get_client()
        target_kind = "droplet" if self.node.type == CoreNode.Type.CLOUD else "volume"
        marker, params = _prepare_cloud_restore(
            restore,
            provider="digitalocean",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return

        if _restore_unknown(restore):
            try:
                candidate = self._find_restore_resource(client, restore, marker)
                if candidate:
                    resource = _restore_candidates(
                        restore,
                        candidate,
                        source_id=backup.unique_id,
                        marker=marker,
                        marker_match=lambda item, value: _restore_marker_matches(item, value),
                        source_match=lambda item, source: _restore_source_matches(
                            item, source, "image", "image_id", "snapshot_id"
                        ),
                    )
                    if resource:
                        return
                _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                raise _RestoreProviderError("PROVIDER_RECONCILIATION_REQUIRED")
            except Exception as error:
                if isinstance(error, _RestoreProviderError):
                    if error.code in {"PROVIDER_RATE_LIMIT", "PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_OUTAGE"}:
                        _restore_handle_error(restore, error, mutation=False)
                        return _restore_status("IN_PROGRESS")
                    raise
                _restore_handle_error(restore, error, mutation=False)
                return _restore_status("IN_PROGRESS")

        try:
            if self.node.type == CoreNode.Type.CLOUD:
                size = params.get("size")
                if not size:
                    result = requests.get(
                        f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                        headers=client,
                        verify=True,
                    )
                    problem = _restore_http_class(result)
                    if problem:
                        return _restore_handle_error(restore, problem, mutation=False)
                    payload = result.json()
                    size = (payload.get("droplet") or {}).get("size_slug")
                    if not size:
                        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                droplet_data = {
                    "name": restore.name,
                    "size": size,
                    "image": int(backup.unique_id),
                    "tags": list(dict.fromkeys([*(params.get("tags") or []), marker])),
                }
                if params.get("region"):
                    droplet_data["region"] = params.get("region")
                if params.get("ssh_keys"):
                    droplet_data["ssh_keys"] = params.get("ssh_keys")
                _restore_begin_mutation(restore)
                result = requests.post(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets",
                    headers=client,
                    json=droplet_data,
                    verify=True,
                )
                problem = _restore_http_class(result, mutation=True)
                if problem:
                    if problem.code == "PROVIDER_RATE_LIMIT":
                        _restore_clear_unknown(restore)
                        return _restore_handle_error(restore, problem, mutation=False)
                    return _restore_handle_error(restore, problem, mutation=True)
                payload = result.json()
                droplet = payload.get("droplet") if isinstance(payload, dict) else None
                resource_id = droplet.get("id") if isinstance(droplet, dict) else None
                if not resource_id:
                    _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                    return _restore_status("IN_PROGRESS")
                _restore_adopt(restore, resource_id, provider_status=droplet.get("status"), params_update={"size": size})
                return

            if self.node.type == CoreNode.Type.VOLUME:
                region = params.get("region")
                if not region:
                    result = requests.get(
                        f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}",
                        headers=client,
                        verify=True,
                    )
                    problem = _restore_http_class(result)
                    if problem:
                        return _restore_handle_error(restore, problem, mutation=False)
                    payload = result.json()
                    region = ((payload.get("volume") or {}).get("region") or {}).get("slug")
                    if not region:
                        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                volume_data = {
                    "name": restore.name,
                    "region": region,
                    "snapshot_id": backup.unique_id,
                    "tags": list(dict.fromkeys([*(params.get("tags") or []), marker])),
                }
                _restore_begin_mutation(restore)
                result = requests.post(
                    f"{settings.DIGITALOCEAN_API}/v2/volumes",
                    headers=client,
                    json=volume_data,
                    verify=True,
                )
                problem = _restore_http_class(result, mutation=True)
                if problem:
                    if problem.code == "PROVIDER_RATE_LIMIT":
                        _restore_clear_unknown(restore)
                        return _restore_handle_error(restore, problem, mutation=False)
                    return _restore_handle_error(restore, problem, mutation=True)
                payload = result.json()
                volume = payload.get("volume") if isinstance(payload, dict) else None
                resource_id = volume.get("id") if isinstance(volume, dict) else None
                if not resource_id:
                    _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                    return _restore_status("IN_PROGRESS")
                _restore_adopt(restore, resource_id, provider_status=volume.get("status"), params_update={"region": region})
                return

            return _restore_safe_failure(restore, "PROVIDER_FAILED")
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.code == "PROVIDER_MALFORMED_RESPONSE" and _restore_unknown(restore):
                    _restore_unknown_outcome(restore, code=error.code)
                    return _restore_status("IN_PROGRESS")
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {"PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH"})
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def check_restore(self, restore):
        client = self.node.connection.auth_digitalocean.get_client()
        marker = _restore_marker_value(restore)
        if not restore.resource_id:
            if not _restore_unknown(restore):
                return _restore_status("IN_PROGRESS")
            try:
                candidate = self._find_restore_resource(client, restore, marker)
                if len(candidate) != 1:
                    _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                    return _restore_status("FAILED")
                resource = _restore_candidates(
                    restore,
                    candidate,
                    source_id=restore.params.get("_backupsheep_restore", {}).get("source_id") if isinstance(restore.params, dict) else None,
                    marker=marker,
                    marker_match=lambda item, value: _restore_marker_matches(item, value),
                    source_match=lambda item, source: _restore_source_matches(item, source, "image", "image_id", "snapshot_id"),
                )
                return self.check_restore(restore) if resource else _restore_status("FAILED")
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

        try:
            if self.node.type == CoreNode.Type.CLOUD:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets/{restore.resource_id}",
                    headers=client,
                    verify=True,
                )
                problem = _restore_http_class(result)
                if problem:
                    return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
                payload = result.json()
                droplet = payload.get("droplet") if isinstance(payload, dict) else None
                if not droplet or not _restore_verify_target(
                    restore, droplet, source_id=(restore.params or {}).get("_backupsheep_restore", {}).get("source_id"),
                    marker=marker, source_keys=("image", "image_id", "snapshot_id")
                ):
                    return _restore_status("FAILED")
                status = droplet.get("status")
                if status == "active":
                    restore.operation_phase = _restore_phase("COMPLETE")
                    restore.save(update_fields=["operation_phase", "modified"])
                    return _restore_status("COMPLETE")
                if status in {"error", "deleting", "destroyed"}:
                    return _restore_safe_failure(restore, "PROVIDER_FAILED")
                if status not in {"new", "off", "active"}:
                    return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                return _restore_status("IN_PROGRESS")

            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/volumes/{restore.resource_id}",
                headers=client,
                verify=True,
            )
            problem = _restore_http_class(result)
            if problem:
                return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
            payload = result.json()
            volume = payload.get("volume") if isinstance(payload, dict) else None
            if not volume or not _restore_verify_target(
                restore, volume, source_id=(restore.params or {}).get("_backupsheep_restore", {}).get("source_id"),
                marker=marker, source_keys=("snapshot_id", "snapshot")
            ):
                return _restore_status("FAILED")
            if volume.get("id"):
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)


class CoreHetzner(UtilCloud):
    # This is deliberately a BackupSheep-owned label.  It lets a retry recover a
    # server that Hetzner created when the HTTP response was lost before Django
    # persisted ``restore.resource_id``.  The prefix is not reserved by Hetzner.
    RESTORE_LABEL_KEY = "backupsheep.restore"
    BACKUP_LABEL_KEY = "backupsheep.backup"
    BACKUP_SOURCE_LABEL_KEY = "backupsheep.source"
    BACKUP_ACCOUNT_LABEL_KEY = "backupsheep.account"
    BACKUP_CONNECTION_LABEL_KEY = "backupsheep.connection"
    API_PAGE_SIZE = 50
    API_MAX_PAGES = 1000

    node = models.OneToOneField(
        "CoreNode", related_name="hetzner", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_hetzner"

    @classmethod
    def _next_page(cls, payload):
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        return pagination.get("next_page")

    @classmethod
    def _list_resources(cls, client, path, resource_key, params=None, stats=None):
        """Return all pages for a Hetzner collection endpoint.

        Hetzner's Cloud API caps ``per_page`` at 50.  The old integration only
        inspected the first page, which could miss a matching snapshot and either
        surface incomplete inventory or create a duplicate backup.
        """
        items = []
        page = 1
        seen_pages = set()
        request_params = dict(params or {})
        while True:
            if page in seen_pages or len(seen_pages) >= cls.API_MAX_PAGES:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            seen_pages.add(page)
            request_params.update({"page": page, "per_page": cls.API_PAGE_SIZE})
            response = requests.get(
                f"{settings.HETZNER_API}/v1/{path}",
                params=request_params,
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            problem = _backup_provider_response_error(response)
            if problem is not None:
                raise problem
            try:
                payload = response.json()
            except Exception:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                ) from None
            page_items = payload.get(resource_key) if isinstance(payload, dict) else None
            pagination = (payload.get("meta") or {}).get("pagination") if isinstance(payload, dict) else None
            if not isinstance(page_items, list) or not isinstance(pagination, dict):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            items.extend(page_items)
            if isinstance(stats, dict):
                stats["page_count"] = len(seen_pages)
                stats["item_count"] = len(items)
            next_page = cls._next_page(payload)
            if not next_page:
                return items
            if isinstance(next_page, bool):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            try:
                next_page = int(next_page)
            except (TypeError, ValueError):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                ) from None
            if next_page <= page or next_page in seen_pages:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            page = next_page

    @classmethod
    def _find_snapshot_by_description(cls, client, description):
        matches = [
            image
            for image in cls._list_resources(
                client,
                "images",
                "images",
                {"type": "snapshot"},
            )
            if image.get("description") == description
        ]
        if len(matches) > 1:
            raise ValueError(
                f"Hetzner returned multiple snapshots for BackupSheep backup {description}; "
                "refusing to guess which resource to use."
            )
        return matches[0] if matches else None

    def _backup_scope(self):
        return {
            # The Hetzner token is project scoped. Persist the local account and
            # connection boundary into both the witness and provider labels so a
            # different connected project can never adopt this request silently.
            "account_id": str(self.node.connection.account_id),
            "connection_id": str(self.node.connection_id),
        }

    @classmethod
    def _backup_labels(cls, witness):
        scope = dict(witness.get("scope") or {})
        return {
            cls.BACKUP_LABEL_KEY: str(witness.get("marker") or "")[:63],
            cls.BACKUP_SOURCE_LABEL_KEY: str(witness.get("source_id") or "")[:63],
            cls.BACKUP_ACCOUNT_LABEL_KEY: str(scope.get("account_id") or "")[:63],
            cls.BACKUP_CONNECTION_LABEL_KEY: str(scope.get("connection_id") or "")[:63],
        }

    @classmethod
    def _snapshot_owned(cls, image, witness, *, resource_id=None):
        if not isinstance(image, dict):
            return False
        if resource_id is not None and str(image.get("id") or "") != str(resource_id):
            return False
        created_from = image.get("created_from")
        if isinstance(created_from, dict):
            created_from = created_from.get("id")
        if (
            image.get("type") != "snapshot"
            or str(image.get("description") or "") != str(witness.get("marker") or "")
            or str(created_from or "") != str(witness.get("source_id") or "")
        ):
            return False
        labels = image.get("labels")
        expected = cls._backup_labels(witness)
        return isinstance(labels, dict) and all(
            str(labels.get(key) or "") == value and bool(value)
            for key, value in expected.items()
        )

    def _backup_source_witness(self, client, backup):
        response = requests.get(
            f"{settings.HETZNER_API}/v1/servers/{self.unique_id}",
            headers=client,
            verify=True,
            timeout=request_timeout(),
        )
        problem = _backup_provider_response_error(response)
        if problem is not None:
            raise problem
        try:
            payload = response.json()
        except Exception:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            ) from None
        source = payload.get("server") if isinstance(payload, dict) else None
        if (
            not isinstance(source, dict)
            or str(source.get("id") or "") != str(self.unique_id)
            or str(source.get("status") or "").lower() not in {"running", "off"}
            or bool(source.get("locked"))
        ):
            raise _BackupProviderError(
                "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
            )
        return _backup_provider_witness(
            backup,
            provider="hetzner",
            source_id=self.unique_id,
            resource_type="instance",
            scope=self._backup_scope(),
            source=source,
        ), source

    def _backup_candidates(self, client, witness):
        stats = {}
        items = self._list_resources(
            client,
            "images",
            "images",
            {
                "type": "snapshot",
                "label_selector": (
                    f"{self.BACKUP_LABEL_KEY}={witness['marker']}"
                ),
            },
            stats=stats,
        )
        marked = [
            image
            for image in items
            if isinstance(image, dict)
            and str(image.get("description") or "") == str(witness["marker"])
        ]
        if any(not isinstance(image, dict) for image in items):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        matches = [image for image in marked if self._snapshot_owned(image, witness)]
        if marked and len(matches) != len(marked):
            raise _BackupProviderError(
                "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
            )
        return matches, stats.get("page_count", 0), stats.get("item_count", 0)

    @classmethod
    def _find_restore_server(cls, client, restore_id):
        # The label selector is an exact provider-side reconciliation key. Do
        # not walk mutable page numbers: if a supposedly unique selector spans
        # pages, fail closed and require manual review.
        response = requests.get(
            f"{settings.HETZNER_API}/v1/servers",
            headers=client,
            params={
                "label_selector": f"{cls.RESTORE_LABEL_KEY}={restore_id}",
                "per_page": cls.API_PAGE_SIZE,
            },
            verify=True,
            timeout=request_timeout(),
        )
        problem = _restore_http_class(response)
        if problem:
            if problem.code == "PROVIDER_NOT_FOUND":
                return None
            raise problem
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("servers"), list):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        if pagination.get("next_page"):
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        servers = payload["servers"]
        if len(servers) > 1:
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return servers[0] if servers else None

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_hetzner.get_client()
        result = requests.get(
            f"{settings.HETZNER_API}/v1/servers/{self.unique_id}",
            headers=client,
            verify=True,
            timeout=request_timeout(),
        )
        if result.status_code == 200:
            r_json = result.json()
            if r_json.get("server"):
                server = r_json.get("server")
                # Snapshots can be taken from a powered-on or powered-off server.
                # A validation check must reject transitional/locked servers, but
                # should not make a valid powered-off source impossible to back up.
                if server.get("status") in {"running", "off"} and not server.get("locked"):
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        witness = None
        mutation_started = False
        try:
            if self.node.type != CoreNode.Type.CLOUD:
                raise _BackupProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
            client = self.node.connection.auth_hetzner.get_client()
            witness, _source = self._backup_source_witness(client, backup)
            _backup_record_provider_witness(
                backup, witness, provider_status="reconciling"
            )
            matches, page_count, item_count = self._backup_candidates(client, witness)
            _backup_record_provider_witness(
                backup,
                witness,
                provider_status="reconciled",
                metadata={
                    "scan_page_count": page_count,
                    "scan_item_count": item_count,
                    "scan_match_count": len(matches),
                    "scan_complete": True,
                },
            )
            if len(matches) > 1:
                raise _BackupProviderError(
                    "PROVIDER_DUPLICATE_MATCH", manual_review=True
                )
            if matches:
                _backup_adopt_provider_resource(
                    backup,
                    matches[0],
                    witness=witness,
                    provider="hetzner",
                    id_keys=("id",),
                )
                return

            _state, provider_metadata = _backup_execution_metadata(backup)
            if provider_metadata.get("create_attempted") or provider_metadata.get(
                "outcome_unknown"
            ):
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )

            _backup_mark_create_started(backup, witness)
            mutation_started = True
            response = requests.post(
                f"{settings.HETZNER_API}/v1/servers/{self.unique_id}/actions/create_image",
                json={
                    "description": witness["marker"],
                    "type": "snapshot",
                    "labels": self._backup_labels(witness),
                },
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            problem = _backup_provider_response_error(response, mutation=True)
            if problem is not None:
                raise problem
            try:
                payload = response.json()
            except Exception:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE",
                    unknown_outcome=True,
                    manual_review=True,
                ) from None
            image = payload.get("image") if isinstance(payload, dict) else None
            action = payload.get("action") if isinstance(payload, dict) else None
            if not isinstance(image, dict) or not isinstance(action, dict):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE",
                    unknown_outcome=True,
                    manual_review=True,
                )
            if not action.get("id") or str(action.get("status") or "").lower() not in {
                "running", "success"
            }:
                raise _BackupProviderError(
                    "PROVIDER_FAILED"
                    if str(action.get("status") or "").lower() == "error"
                    else "PROVIDER_MALFORMED_RESPONSE",
                    unknown_outcome=True,
                    manual_review=True,
                )
            if not image.get("id") or not self._snapshot_owned(image, witness):
                raise _BackupProviderError(
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    unknown_outcome=True,
                    manual_review=True,
                )
            resource = dict(image)
            resource["action_id"] = str(action["id"])
            resource["size_gigabytes"] = image.get("disk_size")
            _backup_adopt_provider_resource(
                backup,
                resource,
                witness=witness,
                provider="hetzner",
                id_keys=("id",),
            )
        except Exception as error:
            if witness is None:
                witness = _backup_provider_witness(
                    backup,
                    provider="hetzner",
                    source_id=self.unique_id,
                    resource_type="instance",
                    scope=self._backup_scope(),
                )
            classified = _backup_provider_exception(
                error, mutation=mutation_started
            )
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_hetzner.get_client()
            params = restore.params or {}

            marker, params = _prepare_cloud_restore(
                restore,
                provider="hetzner",
                source_id=backup.unique_id,
                target_kind="server",
                target_name=restore.name,
            )

            # A redelivered task must never create a second server after the first
            # create request has already been committed locally.
            if restore.resource_id:
                return

            # If the worker died after Hetzner accepted POST /servers but before the
            # response was persisted, adopt the server by its BackupSheep-owned
            # label instead of issuing a second non-idempotent request.
            try:
                existing = self._find_restore_server(client, restore.id)
                if existing:
                    if not _restore_verify_target(
                        restore,
                        existing,
                        source_id=backup.unique_id,
                        marker=str(restore.id),
                        source_keys=("image", "image_id"),
                    ):
                        raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
                    _restore_adopt(
                        restore,
                        existing.get("id"),
                        provider_status=existing.get("status"),
                        params_update={"provider_status": existing.get("status")} if existing.get("status") else {},
                    )
                    return
                if _restore_unknown(restore):
                    _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                    raise _RestoreProviderError("PROVIDER_RECONCILIATION_REQUIRED")
            except Exception as error:
                if isinstance(error, _RestoreProviderError):
                    raise
                _restore_handle_error(restore, error, mutation=False)
                return

            server_data = {
                "name": restore.name,
                "image": int(backup.unique_id),
                "labels": {
                    **(params.get("labels") or {}),
                    self.RESTORE_LABEL_KEY: str(restore.id),
                    "backupsheep.source": str(backup.unique_id),
                },
            }

            server_type = params.get("server_type")
            source_server = None
            if not server_type:
                # Fall back to the source server's server type
                result = requests.get(
                    f"{settings.HETZNER_API}/v1/servers/{self.unique_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                if result.status_code == 200:
                    try:
                        source_server = result.json()["server"]
                        if str(source_server.get("id") or "") != str(self.unique_id):
                            raise KeyError("source")
                        server_type = source_server["server_type"]["name"]
                    except (KeyError, TypeError):
                        raise _RestoreProviderError(
                            "PROVIDER_MALFORMED_RESPONSE"
                        ) from None
                else:
                    problem = _restore_http_class(result)
                    raise problem or _RestoreProviderError(
                        "PROVIDER_REQUEST_FAILED"
                    )
            server_data["server_type"] = server_type

            if params.get("location"):
                server_data["location"] = params.get("location")
            elif source_server and source_server.get("location", {}).get("name"):
                # Keep the restore in the source network zone unless the caller
                # explicitly selects another location.
                server_data["location"] = source_server["location"]["name"]
            if params.get("ssh_keys"):
                server_data["ssh_keys"] = params.get("ssh_keys")

            _restore_begin_mutation(restore)
            result = requests.post(
                f"{settings.HETZNER_API}/v1/servers",
                json=server_data,
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            problem = _restore_http_class(result, mutation=True)
            if problem:
                if problem.code == "PROVIDER_RATE_LIMIT":
                    _restore_clear_unknown(restore)
                    return _restore_handle_error(restore, problem, mutation=False)
                return _restore_handle_error(restore, problem, mutation=True)
            payload = result.json()
            server = payload.get("server") if isinstance(payload, dict) else None
            action = payload.get("action") if isinstance(payload, dict) else None
            if not isinstance(server, dict) or not server.get("id"):
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            if isinstance(action, dict) and action.get("status") == "error":
                _restore_clear_unknown(restore)
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            action_id = action.get("id") if isinstance(action, dict) else None
            _restore_adopt(
                restore,
                server["id"],
                provider_status=server.get("status"),
                params_update={"action_id": action_id} if action_id else {},
            )
        except Exception as e:
            if isinstance(e, _RestoreProviderError):
                if e.retryable:
                    return _restore_handle_error(restore, e, mutation=e.unknown_outcome)
                _restore_safe_failure(restore, e.code, manual_review=e.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, e, mutation=True)

    def check_restore(self, restore):
        client = self.node.connection.auth_hetzner.get_client()
        if not restore.resource_id:
            if not _restore_unknown(restore):
                return _restore_status("IN_PROGRESS")
            try:
                existing = self._find_restore_server(client, restore.id)
                if not existing:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                if not _restore_verify_target(
                    restore,
                    existing,
                    source_id=(_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                    marker=str(restore.id),
                    source_keys=("image", "image_id"),
                ):
                    return _restore_status("FAILED")
                _restore_adopt(restore, existing.get("id"), provider_status=existing.get("status"))
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

        action_id = (_restore_params(restore)).get("action_id")
        if action_id:
            try:
                action_result = requests.get(
                    f"{settings.HETZNER_API}/v1/actions/{action_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                problem = _restore_http_class(action_result)
                if problem:
                    return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
                payload = action_result.json()
                action = payload.get("action") if isinstance(payload, dict) else None
                if not isinstance(action, dict) or not action.get("status"):
                    return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
                if action.get("status") == "error":
                    return _restore_safe_failure(restore, "PROVIDER_FAILED")
                if action.get("status") != "success":
                    return _restore_status("IN_PROGRESS")
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

        try:
            result = requests.get(
                f"{settings.HETZNER_API}/v1/servers/{restore.resource_id}",
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            problem = _restore_http_class(result)
            if problem:
                return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
            payload = result.json()
            server = payload.get("server") if isinstance(payload, dict) else None
            if not _restore_verify_target(
                restore,
                server,
                source_id=(_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                marker=str(restore.id),
                source_keys=("image", "image_id"),
            ):
                return _restore_status("FAILED")
            status = server.get("status") if isinstance(server, dict) else None
            if status == "running":
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if status in {"deleting", "unknown", "error"}:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if status not in {"initializing", "starting", "off", "running"}:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)


class CoreUpCloud(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="upcloud", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_upcloud"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_upcloud.get_client()
        result = requests.get(
            f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
            auth=client,
            verify=True,
            timeout=request_timeout(),
            headers={"content-type": "application/json"}
        )
        if result.status_code == 200:
            r_json = result.json()
            if r_json.get("storage"):
                storage = r_json.get("storage")
                if storage.get("state") == "online":
                    node_ok = True
        return node_ok

    def _upcloud_source_witness(self, client, backup):
        result = requests.get(
            f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
            auth=client,
            verify=True,
            timeout=request_timeout(),
            headers={"content-type": "application/json"},
        )
        problem = _backup_provider_response_error(result)
        if problem:
            raise problem
        try:
            payload = result.json()
        except Exception:
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True) from None
        storage = payload.get("storage") if isinstance(payload, dict) else None
        if not isinstance(storage, dict):
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        source_uuid = storage.get("uuid")
        zone = storage.get("zone")
        if not source_uuid or str(source_uuid) != str(self.unique_id) or not zone:
            raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        witness = _backup_provider_witness(
            backup,
            provider="upcloud",
            source_id=self.unique_id,
            resource_type="storage",
            scope={"zone": zone},
            source=storage,
        )
        return witness, storage

    def _upcloud_backup_candidates(self, client, backup, witness):
        scan = {}
        items = list(
            _iter_provider_collection(
                _UpCloudCollectionClient(client),
                f"{settings.UPCLOUD_API}/storage/backup",
                ("storage", "storages", "items", "resources", "data"),
                stats=scan,
            )
        )
        matches = []
        for item in items:
            if _strict_provider_candidate(
                item,
                marker=witness.get("marker"),
                source_id=self.unique_id,
                source_keys=("origin", "source_uuid", "parent_uuid"),
                scope=witness.get("scope"),
                scope_keys=(("zone", ("zone", "region")),),
            ):
                matches.append(item)
        return matches, scan.get("page_count", 0), len(items)

    def _create_upcloud_snapshot(self, backup, *, client):
        resource_type = "storage" if self.node.type == CoreNode.Type.VOLUME else "server"
        if self.node.type != CoreNode.Type.VOLUME:
            classified = _BackupProviderError("PROVIDER_FAILED")
            witness = _backup_provider_witness(
                backup,
                provider="upcloud",
                source_id=self.unique_id,
                resource_type=resource_type,
                scope={},
            )
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)
        witness = None
        try:
            witness, _source = self._upcloud_source_witness(client, backup)
            _backup_record_provider_witness(backup, witness, provider_status="reconciling")
            matches, page_count, item_count = self._upcloud_backup_candidates(client, backup, witness)
            _backup_record_provider_witness(
                backup,
                witness,
                provider_status="reconciled",
                metadata={
                    "scan_page_count": page_count,
                    "scan_item_count": item_count,
                    "scan_match_count": len(matches),
                    "scan_complete": True,
                },
            )
            if len(matches) > 1:
                raise _BackupProviderError("PROVIDER_DUPLICATE_MATCH", manual_review=True)
            if matches:
                _backup_adopt_provider_resource(
                    backup,
                    matches[0],
                    witness=witness,
                    provider="upcloud",
                    id_keys=("uuid", "id"),
                )
                return
            _state, provider_metadata = _backup_execution_metadata(backup)
            if provider_metadata.get("create_attempted") or provider_metadata.get("outcome_unknown"):
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )
            _backup_mark_create_started(backup, witness)
            result = requests.post(
                f"{settings.UPCLOUD_API}/storage/{self.unique_id}/backup",
                json={"storage": {"title": witness.get("marker")}},
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"content-type": "application/json"},
            )
            problem = _backup_provider_response_error(result, mutation=True)
            if problem:
                raise problem
            try:
                payload = result.json()
            except Exception:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True, manual_review=True
                ) from None
            storage = payload.get("storage") if isinstance(payload, dict) else None
            if not isinstance(storage, dict) or not storage.get("uuid"):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True, manual_review=True
                )
            if not _strict_provider_candidate(
                storage,
                marker=witness.get("marker"),
                source_id=self.unique_id,
                source_keys=("origin", "source_uuid", "parent_uuid"),
                scope=witness.get("scope"),
                scope_keys=(("zone", ("zone", "region")),),
            ):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True, manual_review=True
                )
            _backup_adopt_provider_resource(
                backup,
                storage,
                witness=witness,
                provider="upcloud",
                id_keys=("uuid", "id"),
            )
        except Exception as error:
            classified = _backup_provider_exception(
                error,
                mutation=bool(getattr(error, "unknown_outcome", False)),
            )
            _backup_record_create_failure(
                backup,
                witness or _backup_provider_witness(
                    backup,
                    provider="upcloud",
                    source_id=self.unique_id,
                    resource_type=resource_type,
                    scope={},
                ),
                classified,
                scan_metadata={"phase": "create"},
            )
            _backup_raise_node_error(self.node, backup, classified)

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_upcloud.get_client()
            return self._create_upcloud_snapshot(backup, client=client)
        except NodeBackupFailedError:
            raise
        except Exception as error:
            witness = _backup_provider_witness(
                backup,
                provider="upcloud",
                source_id=self.unique_id,
                resource_type="storage" if self.node.type == CoreNode.Type.VOLUME else "server",
                scope={},
            )
            classified = _backup_provider_exception(error)
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)

    def _find_restore_storage(self, client, restore, source_id):
        try:
            resources = list(
                _iter_provider_collection(
                    _UpCloudCollectionClient(client),
                    f"{settings.UPCLOUD_API}/storage/normal",
                    ("storage", "storages", "items", "resources", "data"),
                )
            )
        except _BackupProviderError as error:
            raise _RestoreProviderError(
                error.code,
                retryable=error.retryable,
                unknown_outcome=error.unknown_outcome,
            ) from None
        params = _restore_params(restore)
        marker = str(params.get("_bs_provider_name") or _restore_marker_value(restore))
        expected_zone = params.get("zone")
        matches = []
        for item in resources:
            if _strict_restore_candidate(
                item,
                marker=marker,
                source_id=source_id,
                source_keys=("origin", "source_uuid", "parent_uuid"),
                scope={"zone": expected_zone},
                scope_keys=(("zone", ("zone", "region")),),
            ):
                matches.append(item)
        _restore_record_scan(
            restore,
            item_count=len(resources),
            match_count=len(matches),
        )
        if len(matches) > 1:
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return matches

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_upcloud.get_client()
        if self.node.type != CoreNode.Type.VOLUME:
            _restore_safe_failure(restore, "PROVIDER_FAILED")
            raise _RestoreProviderError("PROVIDER_FAILED")

        marker, params = _prepare_cloud_restore(
            restore,
            provider="upcloud",
            source_id=backup.unique_id,
            target_kind="storage",
            target_name=restore.name,
        )
        if restore.resource_id:
            return

        try:
            zone = params.get("zone")
            tier = params.get("tier")
            if not zone:
                result = requests.get(
                    f"{settings.UPCLOUD_API}/storage/{backup.unique_id}",
                    auth=client,
                    verify=True,
                    timeout=request_timeout(),
                    headers={"content-type": "application/json"},
                )
                problem = _restore_http_class(result)
                if problem:
                    return _restore_handle_error(restore, problem, mutation=False)
                try:
                    payload = result.json()
                except Exception:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                source_storage = payload.get("storage") if isinstance(payload, dict) else None
                if not isinstance(source_storage, dict) or str(source_storage.get("uuid") or backup.unique_id) != str(backup.unique_id):
                    raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
                zone = source_storage.get("zone")
                if not zone:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                params["zone"] = zone
                restore.params = params
                restore.save(update_fields=["params", "modified"])

            existing = self._find_restore_storage(client, restore, backup.unique_id)
            if existing:
                candidate = existing[0]
                _restore_adopt(
                    restore,
                    candidate.get("uuid") or candidate.get("id"),
                    provider_status=candidate.get("state"),
                    params_update={
                        "zone": zone,
                        "_bs_source_verified": True,
                        "_bs_scope_verified": True,
                    },
                )
                return
            elif _restore_unknown(restore):
                _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                raise _RestoreProviderError("PROVIDER_RECONCILIATION_REQUIRED")

            provider_name = str(params.get("_bs_provider_name") or marker)
            storage_data = {"storage": {"zone": zone, "title": provider_name}}
            if tier:
                storage_data["storage"]["tier"] = tier
            # UpCloud has no universal idempotency header. The durable title and
            # local marker are the reconciliation contract for the clone.
            _restore_begin_mutation(restore)
            result = requests.post(
                f"{settings.UPCLOUD_API}/storage/{backup.unique_id}/clone",
                data=json.dumps(storage_data),
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"content-type": "application/json"},
            )
            problem = _restore_http_class(result, mutation=True)
            if problem:
                if problem.code == "PROVIDER_RATE_LIMIT":
                    _restore_clear_unknown(restore)
                    return _restore_handle_error(restore, problem, mutation=False)
                return _restore_handle_error(restore, problem, mutation=True)
            payload = result.json()
            storage = payload.get("storage") if isinstance(payload, dict) else None
            resource_id = storage.get("uuid") if isinstance(storage, dict) else None
            if not resource_id:
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            if not _strict_restore_candidate(
                storage,
                marker=provider_name,
                source_id=backup.unique_id,
                source_keys=("origin", "source_uuid", "parent_uuid"),
                scope={"zone": zone},
                scope_keys=(("zone", ("zone", "region")),),
            ):
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            _restore_adopt(
                restore,
                resource_id,
                provider_status=storage.get("state"),
                params_update={
                    "zone": storage.get("zone", zone),
                    "_bs_source_verified": True,
                    "_bs_scope_verified": True,
                },
            )
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def check_restore(self, restore):
        client = self.node.connection.auth_upcloud.get_client()
        if not restore.resource_id:
            if not _restore_unknown(restore):
                return _restore_status("IN_PROGRESS")
            try:
                candidate = self._find_restore_storage(
                    client,
                    restore,
                    (_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                )
                if len(candidate) != 1:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                item = candidate[0]
                _restore_adopt(
                    restore,
                    item.get("uuid") or item.get("id"),
                    provider_status=item.get("state"),
                    params_update={
                        "_bs_source_verified": True,
                        "_bs_scope_verified": True,
                    },
                )
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)
        try:
            result = requests.get(
                f"{settings.UPCLOUD_API}/storage/{restore.resource_id}",
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"content-type": "application/json"},
            )
            problem = _restore_http_class(result)
            if problem:
                return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
            payload = result.json()
            storage = payload.get("storage") if isinstance(payload, dict) else None
            if not isinstance(storage, dict):
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            params = _restore_params(restore)
            provider_name = str(params.get("_bs_provider_name") or _restore_marker_value(restore))
            try:
                if not _strict_provider_candidate(
                    storage,
                    marker=provider_name,
                    source_id=(params.get("_backupsheep_restore") or {}).get("source_id"),
                    source_keys=("origin", "source_uuid", "parent_uuid"),
                    scope={"zone": params.get("zone")},
                    scope_keys=(("zone", ("zone", "region")),),
                ):
                    return _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
            except _BackupProviderError as identity_error:
                return _restore_safe_failure(restore, identity_error.code, manual_review=True)
            state = storage.get("state")
            if state == "online":
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if state == "error":
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if state not in {"cloning", "maintenance", "offline", "online"}:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)


class _OVHRegionMixin:
    """Build region-scoped OVH Public Cloud API paths.

    OVH's current Public Cloud API scopes compute, volume, and snapshot
    resources by region. Older BackupSheep rows may not have the region in
    their metadata, so resolve it once by probing the project's regions and
    persist the result before making a mutating request.
    """

    def _metadata_region(self):
        metadata = self.metadata if isinstance(self.metadata, dict) else {}
        for key in ("_bs_region", "region"):
            region = metadata.get(key)
            if isinstance(region, dict):
                region = region.get("name") or region.get("region") or region.get("id")
            if region:
                return str(region)
        return None

    def _persist_region(self, region):
        region = str(region)
        metadata = dict(self.metadata) if isinstance(self.metadata, dict) else {}
        if metadata.get("_bs_region") == region:
            return region
        metadata["_bs_region"] = region
        self.metadata = metadata
        self.save(update_fields=["metadata", "modified"])
        return region

    @staticmethod
    def _region_name(value):
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            value = value.get("name") or value.get("region") or value.get("id")
            if value:
                return str(value)
        return None

    def _ovh_region(self, client, resource_type):
        region = self._metadata_region()
        if region:
            return region

        project_path = f"/cloud/project/{self.project_id}"
        try:
            regions = client.get(f"{project_path}/region")
        except Exception:
            regions = []
        for region_value in regions if isinstance(regions, list) else []:
            region = self._region_name(region_value)
            if not region:
                continue
            try:
                resource = client.get(
                    f"{project_path}/region/{region}/{resource_type}/{self.unique_id}"
                )
            except Exception:
                continue
            if resource:
                return self._persist_region(resource.get("region") or region)

        # Last-chance compatibility lookup for rows created before OVH added
        # region-qualified routes. This path is never used for new rows once
        # the region has been discovered and persisted.
        try:
            resource = client.get(f"{project_path}/{resource_type}/{self.unique_id}")
        except Exception:
            resource = None
        if resource:
            region = resource.get("region")
            if region:
                return self._persist_region(region)
        raise ValueError(
            f"Unable to determine the OVH region for {resource_type} {self.unique_id}."
        )

    def _ovh_resource_path(self, client, resource_type, resource_id=None):
        region = self._ovh_region(client, resource_type)
        resource_id = resource_id or self.unique_id
        return f"/cloud/project/{self.project_id}/region/{region}/{resource_type}/{resource_id}"

    def _ovh_snapshot_path(self, client, resource_type, snapshot_id=None):
        region = self._ovh_region(client, resource_type)
        snapshot_path = "snapshot" if resource_type == "instance" else "volume/snapshot"
        path = f"/cloud/project/{self.project_id}/region/{region}/{snapshot_path}"
        return f"{path}/{snapshot_id}" if snapshot_id else path

    def _ovh_source_witness(self, backup, client, resource_type, region):
        """Verify and persist the exact OVH project/region/source before POST."""
        if not self.project_id or not self.unique_id or not region:
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        source_path = (
            f"/cloud/project/{self.project_id}/region/{region}/"
            f"{resource_type}/{self.unique_id}"
        )
        source = client.get(source_path)
        response_error = _backup_provider_response_error(source)
        if response_error is not None:
            raise response_error
        if not isinstance(source, dict):
            raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
        source_id = source.get("id") or source.get("uuid")
        if not source_id or str(source_id) != str(self.unique_id):
            raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        actual_region = source.get("region") or source.get("zone")
        if actual_region not in (None, "") and str(actual_region) != str(region):
            raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
        scope = {"project_id": self.project_id, "region": region}
        return _backup_provider_witness(
            backup,
            provider="ovh",
            source_id=self.unique_id,
            resource_type=resource_type,
            scope=scope,
            source=source,
        ), source

    def _ovh_backup_candidates(self, client, backup, resource_type, region, *, witness=None):
        path = (
            f"/cloud/project/{self.project_id}/region/{region}/"
            f"{'snapshot' if resource_type == 'instance' else 'volume/snapshot'}"
        )
        scan = {}
        items = list(
            _iter_provider_collection(
                client,
                path,
                ("snapshots", "snapshot", "items", "resources", "data"),
                stats=scan,
            )
        )
        scope = {"project_id": self.project_id, "region": region}
        matches = []
        marker = (witness or {}).get("marker") or _backup_request_marker(backup)
        for item in items:
            if not isinstance(item, dict):
                raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            if _strict_provider_candidate(
                item,
                marker=marker,
                source_id=self.unique_id,
                source_keys=(
                    "instanceId", "volumeId", "sourceId", "source_id", "origin",
                ),
                scope=scope,
                scope_keys=(
                    ("region", ("region", "zone")),
                    ("project_id", ("projectId", "project_id", "project")),
                ),
                scope_proven=True,
            ):
                matches.append(item)
        return matches, scan.get("page_count", 0), len(items)

    def _create_ovh_snapshot(self, backup, *, client, provider):
        """Crash-safe OVH snapshot creation shared by CA/EU/US adapters."""
        resource_type = "instance" if self.node.type == CoreNode.Type.CLOUD else "volume"
        if self.node.type not in {CoreNode.Type.CLOUD, CoreNode.Type.VOLUME}:
            classified = _BackupProviderError("PROVIDER_FAILED")
            _backup_record_create_failure(
                backup,
                _backup_provider_witness(
                    backup,
                    provider=provider,
                    source_id=self.unique_id,
                    resource_type=resource_type,
                    scope={"project_id": self.project_id},
                ),
                classified,
            )
            _backup_raise_node_error(self.node, backup, classified)
        try:
            region = self._metadata_region() or self._ovh_region(client, resource_type)
            if not region:
                raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            # The source GET and witness persistence are deliberately before the
            # first collection scan and POST.
            witness, _source = self._ovh_source_witness(
                backup, client, resource_type, region
            )
            _backup_record_provider_witness(backup, witness, provider_status="reconciling")

            matches, page_count, item_count = self._ovh_backup_candidates(
                client, backup, resource_type, region, witness=witness
            )
            _backup_record_provider_witness(
                backup,
                witness,
                provider_status="reconciled",
                metadata={
                    "scan_page_count": page_count,
                    "scan_item_count": item_count,
                    "scan_match_count": len(matches),
                    "scan_complete": True,
                },
            )
            if len(matches) > 1:
                raise _BackupProviderError(
                    "PROVIDER_DUPLICATE_MATCH", manual_review=True
                )
            if matches:
                _backup_adopt_provider_resource(
                    backup,
                    matches[0],
                    witness=witness,
                    provider=provider,
                    id_keys=("id", "uuid"),
                )
                return

            _state, provider_metadata = _backup_execution_metadata(backup)
            if provider_metadata.get("create_attempted") or provider_metadata.get("outcome_unknown"):
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )

            _backup_mark_create_started(backup, witness)
            path = (
                f"/cloud/project/{self.project_id}/region/{region}/"
                f"{resource_type}/snapshot" if resource_type == "instance" else
                f"/cloud/project/{self.project_id}/region/{region}/volume/snapshot"
            )
            request = (
                {"snapshotName": witness.get("marker")}
                if resource_type == "instance"
                else {"name": witness.get("marker")}
            )
            response = client.post(path, **request)
            response_error = _backup_provider_response_error(response, mutation=True)
            if response_error is not None:
                raise response_error
            if not isinstance(response, dict):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True, manual_review=True
                )
            resource_id = response.get("id") or response.get("uuid") or response.get("snapshotId")
            if not resource_id:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True, manual_review=True
                )
            _backup_adopt_provider_resource(
                backup,
                response,
                witness=witness,
                provider=provider,
                id_keys=("id", "uuid", "snapshotId"),
            )
        except Exception as error:
            classified = _backup_provider_exception(
                error,
                mutation=bool(getattr(error, "unknown_outcome", False)),
            )
            _backup_record_create_failure(backup, locals().get("witness") or _backup_provider_witness(
                backup,
                provider=provider,
                source_id=self.unique_id,
                resource_type=resource_type,
                scope={"project_id": self.project_id, "region": locals().get("region")},
            ), classified, scan_metadata={"phase": "create"})
            _backup_raise_node_error(self.node, backup, classified)

    def _ovh_restore_collection(self, client, resource_type, region):
        try:
            return list(
                _iter_provider_collection(
                    client,
                    f"/cloud/project/{self.project_id}/region/{region}/{resource_type}",
                    (resource_type, "instances", "volumes", "resources", "items", "data"),
                )
            )
        except _BackupProviderError as error:
            raise _RestoreProviderError(
                error.code,
                retryable=error.retryable,
                unknown_outcome=error.unknown_outcome,
            ) from None

    def _find_ovh_restore_resource(self, client, restore, resource_type, region):
        resources = self._ovh_restore_collection(client, resource_type, region)
        identity = (_restore_params(restore).get("_backupsheep_restore") or {})
        source_id = identity.get("source_id")
        marker = str(
            (_restore_params(restore).get("_bs_provider_name") or _restore_marker_value(restore))
        )
        scope = {"project_id": self.project_id, "region": region}
        source_keys = (
            "imageId", "image_id", "snapshotId", "snapshot_id", "sourceSnapshotId",
        )
        matches = []
        for item in resources:
            if _strict_restore_candidate(
                item,
                marker=marker,
                source_id=source_id,
                source_keys=source_keys,
                scope=scope,
                scope_keys=(
                    ("region", ("region", "zone")),
                    ("project_id", ("projectId", "project_id", "project")),
                ),
                scope_proven=True,
            ):
                matches.append(item)
        _restore_record_scan(
            restore,
            item_count=len(resources),
            match_count=len(matches),
        )
        if len(matches) > 1:
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return matches

    def _restore_snapshot_ovh(self, backup, restore, *, client, provider):
        import math

        target_kind = "instance" if self.node.type == CoreNode.Type.CLOUD else "volume"
        marker, params = _prepare_cloud_restore(
            restore,
            provider=provider,
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return
        if self.node.type not in {CoreNode.Type.CLOUD, CoreNode.Type.VOLUME}:
            _restore_safe_failure(restore, "PROVIDER_FAILED")
            raise _RestoreProviderError("PROVIDER_FAILED")

        try:
            resource_type = "instance" if self.node.type == CoreNode.Type.CLOUD else "volume"
            region = params.get("region") or self._ovh_region(client, resource_type)
            if params.get("region") != region:
                params["region"] = region
                restore.params = params
                restore.save(update_fields=["params", "modified"])
            existing = self._find_ovh_restore_resource(client, restore, resource_type, region)
            if existing:
                candidate = existing[0]
                _restore_adopt(
                    restore,
                    candidate.get("id") or candidate.get("uuid"),
                    provider_status=candidate.get("status"),
                    params_update={
                        "region": region,
                        "_bs_source_verified": True,
                        "_bs_scope_verified": True,
                    },
                )
                return
            elif _restore_unknown(restore):
                _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                raise _RestoreProviderError("PROVIDER_RECONCILIATION_REQUIRED")

            provider_name = str(params.get("_bs_provider_name") or marker)
            request = {"name": provider_name, "region": region}
            if self.node.type == CoreNode.Type.CLOUD:
                flavor_id = params.get("flavor_id")
                if not flavor_id:
                    source = client.get(self._ovh_resource_path(client, "instance"))
                    source_error = _backup_provider_response_error(source)
                    if source_error is not None:
                        raise _RestoreProviderError(
                            source_error.code,
                            retryable=source_error.retryable,
                            unknown_outcome=source_error.unknown_outcome,
                        )
                    if not isinstance(source, dict) or str(source.get("id") or self.unique_id) != str(self.unique_id):
                        raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
                    flavor_id = source.get("flavorId") if isinstance(source, dict) else None
                if not flavor_id:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                request.update({"flavorId": flavor_id, "imageId": backup.unique_id})
                path = f"/cloud/project/{self.project_id}/region/{region}/instance"
            else:
                size = params.get("size")
                volume_type = params.get("type")
                if not size or not volume_type:
                    source = client.get(self._ovh_resource_path(client, "volume"))
                    if isinstance(source, dict):
                        size = size or source.get("size")
                        volume_type = volume_type or source.get("type")
                if backup.size_gigabytes:
                    size = max(int(size), math.ceil(backup.size_gigabytes))
                if not size or not volume_type:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                request.update({"size": size, "type": volume_type, "snapshotId": backup.unique_id})
                path = f"/cloud/project/{self.project_id}/region/{region}/volume"

            _restore_begin_mutation(restore)
            response = client.post(path, **request)
            response_error = _backup_provider_response_error(response, mutation=True)
            if response_error is not None:
                raise _RestoreProviderError(
                    response_error.code,
                    retryable=response_error.retryable,
                    unknown_outcome=response_error.unknown_outcome,
                )
            if not isinstance(response, dict) or not response.get("id"):
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            _restore_adopt(
                restore,
                response["id"],
                provider_status=response.get("status") or "creating",
                params_update={
                    "region": region,
                    "_bs_source_verified": True,
                    "_bs_scope_verified": True,
                },
            )
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_ovh(self, restore, *, client):
        params = _restore_params(restore)
        region = params.get("region")
        resource_type = "instance" if self.node.type == CoreNode.Type.CLOUD else "volume"
        try:
            if not restore.resource_id:
                if not _restore_unknown(restore):
                    return _restore_status("IN_PROGRESS")
                region = region or self._ovh_region(client, resource_type)
                candidates = self._find_ovh_restore_resource(client, restore, resource_type, region)
                if len(candidates) != 1:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                candidate = candidates[0]
                _restore_adopt(
                    restore,
                    candidate.get("id") or candidate.get("uuid"),
                    provider_status=candidate.get("status"),
                    params_update={
                        "region": region,
                        "_bs_source_verified": True,
                        "_bs_scope_verified": True,
                    },
                )
                return _restore_status("IN_PROGRESS")

            region = region or self._ovh_region(client, resource_type)
            response = client.get(
                f"/cloud/project/{self.project_id}/region/{region}/{resource_type}/{restore.resource_id}"
            )
            if not isinstance(response, dict):
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            source_id = (params.get("_backupsheep_restore") or {}).get("source_id")
            provider_name = str(params.get("_bs_provider_name") or _restore_marker_value(restore))
            try:
                if not _strict_provider_candidate(
                    response,
                    marker=provider_name,
                    source_id=source_id,
                    source_keys=(
                        "imageId", "image_id", "snapshotId", "snapshot_id", "sourceSnapshotId",
                    ),
                    scope={"project_id": self.project_id, "region": region},
                    scope_keys=(
                        ("region", ("region", "zone")),
                        ("project_id", ("projectId", "project_id", "project")),
                    ),
                    scope_proven=True,
                ):
                    return _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
            except _BackupProviderError as identity_error:
                _restore_safe_failure(restore, identity_error.code, manual_review=True)
                return _restore_status("FAILED")
            status = str(response.get("status") or "")
            complete = "ACTIVE" if resource_type == "instance" else "available"
            if status == complete:
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if status.lower() in {"error", "failed", "destroyed", "deleted"}:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if not status:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)


class CoreOVHCA(_OVHRegionMixin, UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_ca", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_ca"

    def validate(self):
        try:
            client = self.node.connection.auth_ovh_ca.get_client()
            if self.node.type == CoreNode.Type.CLOUD:
                ovh_response = client.get(self._ovh_resource_path(client, "instance"))
                return ovh_response.get("status") == "ACTIVE"
            if self.node.type == CoreNode.Type.VOLUME:
                ovh_response = client.get(self._ovh_resource_path(client, "volume"))
                return ovh_response.get("status") in {"available", "in-use"}
        except Exception:
            return False
        return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_ovh_ca.get_client()
            return self._create_ovh_snapshot(backup, client=client, provider="ovh_ca")
        except NodeBackupFailedError:
            raise
        except Exception as error:
            witness = _backup_provider_witness(
                backup,
                provider="ovh_ca",
                source_id=self.unique_id,
                resource_type="instance" if self.node.type == CoreNode.Type.CLOUD else "volume",
                scope={"project_id": self.project_id, "region": self._metadata_region()},
            )
            classified = _backup_provider_exception(error)
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_ovh_ca.get_client()
            return self._restore_snapshot_ovh(
                backup,
                restore,
                client=client,
                provider="ovh_ca",
            )
        except _RestoreProviderError:
            raise
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False)

    def check_restore(self, restore):
        try:
            client = self.node.connection.auth_ovh_ca.get_client()
            return self._check_restore_ovh(restore, client=client)
        except Exception as error:
            return _restore_handle_error(
                restore, error, mutation=False, raise_terminal=False
            )


class CoreOVHEU(_OVHRegionMixin, UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_eu", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_eu"

    def validate(self):
        try:
            client = self.node.connection.auth_ovh_eu.get_client()
            if self.node.type == CoreNode.Type.CLOUD:
                ovh_response = client.get(self._ovh_resource_path(client, "instance"))
                return ovh_response.get("status") == "ACTIVE"
            if self.node.type == CoreNode.Type.VOLUME:
                ovh_response = client.get(self._ovh_resource_path(client, "volume"))
                return ovh_response.get("status") in {"available", "in-use"}
        except Exception:
            return False
        return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_ovh_eu.get_client()
            return self._create_ovh_snapshot(backup, client=client, provider="ovh_eu")
        except NodeBackupFailedError:
            raise
        except Exception as error:
            witness = _backup_provider_witness(
                backup,
                provider="ovh_eu",
                source_id=self.unique_id,
                resource_type="instance" if self.node.type == CoreNode.Type.CLOUD else "volume",
                scope={"project_id": self.project_id, "region": self._metadata_region()},
            )
            classified = _backup_provider_exception(error)
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_ovh_eu.get_client()
            return self._restore_snapshot_ovh(
                backup,
                restore,
                client=client,
                provider="ovh_eu",
            )
        except _RestoreProviderError:
            raise
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False)

    def check_restore(self, restore):
        try:
            client = self.node.connection.auth_ovh_eu.get_client()
            return self._check_restore_ovh(restore, client=client)
        except Exception as error:
            return _restore_handle_error(
                restore, error, mutation=False, raise_terminal=False
            )


class CoreOVHUS(_OVHRegionMixin, UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_us", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_us"

    def validate(self):
        try:
            client = self.node.connection.auth_ovh_us.get_client()
            if self.node.type == CoreNode.Type.CLOUD:
                ovh_response = client.get(self._ovh_resource_path(client, "instance"))
                return ovh_response.get("status") == "ACTIVE"
            if self.node.type == CoreNode.Type.VOLUME:
                ovh_response = client.get(self._ovh_resource_path(client, "volume"))
                return ovh_response.get("status") in {"available", "in-use"}
        except Exception:
            return False
        return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_ovh_us.get_client()
            return self._create_ovh_snapshot(backup, client=client, provider="ovh_us")
        except NodeBackupFailedError:
            raise
        except Exception as error:
            witness = _backup_provider_witness(
                backup,
                provider="ovh_us",
                source_id=self.unique_id,
                resource_type="instance" if self.node.type == CoreNode.Type.CLOUD else "volume",
                scope={"project_id": self.project_id, "region": self._metadata_region()},
            )
            classified = _backup_provider_exception(error)
            _backup_record_create_failure(backup, witness, classified)
            _backup_raise_node_error(self.node, backup, classified)

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_ovh_us.get_client()
            return self._restore_snapshot_ovh(
                backup,
                restore,
                client=client,
                provider="ovh_us",
            )
        except _RestoreProviderError:
            raise
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False)

    def check_restore(self, restore):
        try:
            client = self.node.connection.auth_ovh_us.get_client()
            return self._check_restore_ovh(restore, client=client)
        except Exception as error:
            return _restore_handle_error(
                restore, error, mutation=False, raise_terminal=False
            )


class CoreAWS(UtilCloud):
    class ResourceType(models.TextChoices):
        INSTANCE = "instance", "EC2 Instance"
        VOLUME = "volume", "EBS Volume"
        S3 = "s3", "S3 Bucket"
        DYNAMODB = "dynamodb", "DynamoDB Table"

    node = models.OneToOneField(
        "CoreNode", related_name="aws", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    resource_type = models.CharField(
        max_length=32,
        choices=ResourceType.choices,
        default=ResourceType.INSTANCE,
    )
    no_reboot = models.BooleanField(default=True)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws"

    def validate(self):
        node_ok = False
        try:
            auth = self.node.connection.auth_aws

            if self.resource_type == self.ResourceType.S3:
                client = auth.get_client("s3")
                client.head_bucket(Bucket=self.unique_id)
                versioning = client.get_bucket_versioning(Bucket=self.unique_id)
                node_ok = versioning.get("Status") == "Enabled"
            elif self.resource_type == self.ResourceType.DYNAMODB:
                client = auth.get_client("dynamodb")
                table = client.describe_table(TableName=self.unique_id).get("Table") or {}
                node_ok = table.get("TableStatus") in {"ACTIVE", "UPDATING"}
            elif self.node.type == CoreNode.Type.CLOUD:
                client = auth.get_client()
                response = client.describe_instances(
                    InstanceIds=[self.unique_id],
                )
                if response.get("Reservations"):
                    instance = response.get("Reservations")[0]["Instances"][0]
                    if instance.get("State", {}).get("Name") == "running" or instance.get("State", {}).get(
                            "Name") == "stopped":
                        node_ok = True
            elif self.node.type == CoreNode.Type.VOLUME:
                client = auth.get_client()
                response = client.describe_volumes(
                    VolumeIds=[self.unique_id],
                )
                volume = response.get("Volumes")[0]
                if volume.get("State") == "available" or volume.get("State") == "in-use":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        try:
            auth = self.node.connection.auth_aws

            if self.resource_type in {self.ResourceType.S3, self.ResourceType.DYNAMODB}:
                from apps._tasks.integration.aws_backup import (
                    idempotency_token,
                    resource_arn,
                    start_backup_job,
                )

                response = start_backup_job(
                    auth,
                    self.resource_type,
                    self.unique_id,
                    auth.backup_vault_name,
                    idempotency_token("backup", backup.uuid_str),
                    {"BackupSheepBackup": backup.uuid_str},
                )
                job_id = response.get("BackupJobId")
                if not job_id:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        "AWS Backup did not return a BackupJobId.",
                    )
                metadata = dict(backup.metadata) if isinstance(backup.metadata, dict) else {}
                aws_backup = dict(metadata.get("_aws_backup") or {})
                aws_backup.update(
                    {
                        "job_id": job_id,
                        "resource_type": self.resource_type,
                        "resource_arn": resource_arn(
                            auth, self.resource_type, self.unique_id
                        ),
                        "vault_name": auth.backup_vault_name or "Default",
                    }
                )
                metadata["_aws_backup"] = aws_backup
                backup.unique_id = job_id
                backup.metadata = metadata
                backup.save(update_fields=["unique_id", "metadata", "modified"])
                return

            # EC2 AMIs and EBS snapshots are owned by the durable backup row.
            # It persists the immutable request witness, provider pointer,
            # reconciliation state, and fencing token around every mutation.
            return backup.create_snapshot(task_id=backup.celery_task_id or None)
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )

    # The provider-agnostic AWS restore implementation is defined once above
    # the provider classes; bind its helpers here so EC2, EBS, S3, and DynamoDB
    # all share the same fenced reconciliation contract.
    _find_aws_backup_restore_job = CoreDigitalOcean._find_aws_backup_restore_job
    _aws_restore_instances = staticmethod(CoreDigitalOcean._aws_restore_instances)
    _aws_find_restore_resource = CoreDigitalOcean._aws_find_restore_resource
    _restore_snapshot_aws = CoreDigitalOcean._restore_snapshot_aws
    _check_restore_aws = CoreDigitalOcean._check_restore_aws

    @staticmethod
    def _aws_normalize_restore_source_configuration(
        configuration, *, source_type, source_id
    ):
        if not isinstance(configuration, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if str(configuration.get("source_type") or "") != str(source_type):
            raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        if str(configuration.get("source_id") or "") != str(source_id):
            raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        normalized = {
            "schema": 1,
            "source_type": str(source_type),
            "source_id": str(source_id),
        }
        if source_type == "instance":
            instance_type = str(configuration.get("instance_type") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}", instance_type):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            subnet_id = str(configuration.get("subnet_id") or "").strip()
            if subnet_id and not re.fullmatch(
                r"subnet-[0-9A-Fa-f]{8,32}", subnet_id
            ):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            security_group_ids = configuration.get("security_group_ids")
            if security_group_ids is None:
                security_group_ids = []
            if not isinstance(security_group_ids, list) or len(security_group_ids) > 32:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            normalized_groups = []
            for group_id in security_group_ids:
                group_id = str(group_id or "").strip()
                if not re.fullmatch(r"sg-[0-9A-Fa-f]{8,32}", group_id):
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                if group_id not in normalized_groups:
                    normalized_groups.append(group_id)
            key_name = str(configuration.get("key_name") or "").strip()
            if len(key_name) > 255 or any(ord(value) < 32 for value in key_name):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            normalized.update(
                {
                    "instance_type": instance_type,
                    "subnet_id": subnet_id,
                    "security_group_ids": normalized_groups,
                    "key_name": key_name,
                }
            )
            return normalized

        availability_zone = str(
            configuration.get("availability_zone") or ""
        ).strip()
        if not availability_zone or not re.fullmatch(
            r"[A-Za-z0-9-]{3,64}", availability_zone
        ):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        normalized["availability_zone"] = availability_zone
        return normalized

    def _aws_restore_source_configuration(self, client, backup, source_type):
        source_id = str(self.unique_id or "")
        state = backup.get_execution_state(create=False)
        provider_metadata = (
            dict(state.provider_metadata or {}) if state is not None else {}
        )
        stored = provider_metadata.get("source_configuration")
        if stored is not None:
            return self._aws_normalize_restore_source_configuration(
                stored,
                source_type=source_type,
                source_id=source_id,
            )

        # Compatibility for backups created before source configuration was
        # durable. Read the still-existing source once and persist the resulting
        # safe witness on the restore row before any provider mutation.
        if source_type == "instance":
            response = client.describe_instances(InstanceIds=[source_id])
            instances = self._aws_restore_instances(response)
            if (
                len(instances) != 1
                or str(instances[0].get("InstanceId") or "") != source_id
            ):
                raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            source = instances[0]
            configuration = {
                "source_type": "instance",
                "source_id": source_id,
                "instance_type": source.get("InstanceType"),
                "subnet_id": source.get("SubnetId") or "",
                "security_group_ids": [
                    group.get("GroupId")
                    for group in source.get("SecurityGroups") or []
                    if isinstance(group, dict)
                ],
                "key_name": source.get("KeyName") or "",
            }
        else:
            response = client.describe_volumes(VolumeIds=[source_id])
            volumes = response.get("Volumes") if isinstance(response, dict) else None
            if (
                not isinstance(volumes, list)
                or len(volumes) != 1
                or str(volumes[0].get("VolumeId") or "") != source_id
            ):
                raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            configuration = {
                "source_type": "volume",
                "source_id": source_id,
                "availability_zone": volumes[0].get("AvailabilityZone"),
            }
        return self._aws_normalize_restore_source_configuration(
            configuration,
            source_type=source_type,
            source_id=source_id,
        )

    @staticmethod
    def _aws_dynamodb_restore_tags(client, table_arn):
        """Read every DynamoDB tag page with bounded cursor-loop guards."""
        tags = {}
        token = None
        seen_tokens = set()
        for _page_number in range(100):
            request = {"ResourceArn": table_arn}
            if token:
                request["NextToken"] = token
            response = client.list_tags_of_resource(**request)
            if not isinstance(response, dict):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            page = response.get("Tags")
            if not isinstance(page, list) or len(page) > 50:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            for item in page:
                if not isinstance(item, dict):
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                key = item.get("Key")
                value = item.get("Value")
                if not isinstance(key, str) or not isinstance(value, str):
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                if key in tags:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                tags[key] = value
            next_token = response.get("NextToken")
            if next_token in (None, ""):
                return tags
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            seen_tokens.add(next_token)
            token = next_token
        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")

    @staticmethod
    def _aws_dynamodb_restore_table_identity(auth, table, target_name):
        if not isinstance(table, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        table_name = str(table.get("TableName") or "")
        table_arn = str(table.get("TableArn") or "")
        match = re.fullmatch(
            r"arn:(?P<partition>[a-z0-9-]+):dynamodb:"
            r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
            r"table/(?P<table>[A-Za-z0-9_.-]{3,255})",
            table_arn,
        )
        if not match:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        account_id = str(
            (auth.get_client("sts").get_caller_identity() or {}).get("Account")
            or ""
        )
        if not re.fullmatch(r"[0-9]{12}", account_id):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if (
            table_name != str(target_name)
            or match.group("table") != str(target_name)
            or match.group("region") != str(auth.region.code)
            or match.group("account") != account_id
        ):
            raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        return table_arn, account_id

    def _aws_dynamodb_restore_ownership_verified(
        self,
        auth,
        client,
        restore,
        job,
        table,
    ):
        """Tag and verify a completed DynamoDB restore before adopting success.

        AWS Backup creates the table but does not propagate application ownership
        tags. The table ARN and restore-job identity are therefore verified first;
        only then is an idempotent tag mutation permitted. A crash or lost response
        is safe because every retry reads the exact ARN before applying the same
        key/value pair, and completion waits for eventually-consistent readback.
        """
        params = _restore_params(restore)
        identity = params.get("_backupsheep_restore") or {}
        target_name = str(restore.resource_id or identity.get("target_name") or "")
        source_id = str(identity.get("source_id") or "")
        marker = _restore_marker_value(restore)
        if not target_name or not source_id or not marker:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")

        table_arn, account_id = self._aws_dynamodb_restore_table_identity(
            auth, table, target_name
        )
        if not isinstance(job, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if (
            str(job.get("RestoreJobId") or "") != str(restore.provider_job_id)
            or str(job.get("RecoveryPointArn") or "") != source_id
            or str(job.get("CreatedResourceArn") or "") != table_arn
            or str(job.get("AccountId") or "") != account_id
            or str(job.get("ResourceType") or "").casefold() != "dynamodb"
        ):
            raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        expected = {
            "BackupSheepRestore": marker,
            "BackupSheepSource": source_id,
        }
        tags = self._aws_dynamodb_restore_tags(client, table_arn)
        for key, value in expected.items():
            if key in tags and tags[key] != value:
                raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        if all(tags.get(key) == value for key, value in expected.items()):
            tagging = dict(params.get("_bs_dynamodb_tagging") or {})
            tagging.update(
                {
                    "schema": 1,
                    "state": "verified",
                    "table_arn": table_arn,
                    "expected_tags": expected,
                    "verified_at": timezone.now().isoformat(),
                }
            )
            params["_bs_dynamodb_tagging"] = tagging
            params["_bs_marker_verified"] = True
            params["_bs_create_outcome_unknown"] = False
            restore.params = params
            restore.operation_phase = _restore_phase("POLLING")
            restore.error = ""
            restore.save(
                update_fields=[
                    "params",
                    "operation_phase",
                    "error",
                    "modified",
                ]
            )
            return True

        tagging = dict(params.get("_bs_dynamodb_tagging") or {})
        now = timezone.now()
        last_attempt_at = None
        try:
            last_attempt_at = datetime.datetime.fromisoformat(
                str(tagging.get("last_attempt_at") or "")
            )
            if timezone.is_naive(last_attempt_at):
                last_attempt_at = timezone.make_aware(last_attempt_at)
        except (TypeError, ValueError):
            last_attempt_at = None
        retry_seconds = min(
            3600,
            max(
                5,
                int(
                    getattr(
                        settings,
                        "DYNAMODB_RESTORE_TAG_RETRY_SECONDS",
                        30,
                    )
                ),
            ),
        )
        should_submit = (
            last_attempt_at is None
            or (now - last_attempt_at).total_seconds() >= retry_seconds
        )
        if not should_submit:
            return False

        tagging.update(
            {
                "schema": 1,
                "state": "intent",
                "table_arn": table_arn,
                "expected_tags": expected,
                "attempt_count": int(tagging.get("attempt_count") or 0) + 1,
                "last_attempt_at": now.isoformat(),
            }
        )
        params["_bs_dynamodb_tagging"] = tagging
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        _restore_begin_mutation(restore)
        client.tag_resource(
            ResourceArn=table_arn,
            Tags=[
                {"Key": key, "Value": value}
                for key, value in expected.items()
                if tags.get(key) != value
            ],
        )
        params = _restore_params(restore)
        tagging = dict(params.get("_bs_dynamodb_tagging") or {})
        tagging["state"] = "submitted"
        params["_bs_dynamodb_tagging"] = tagging
        restore.params = params
        restore.operation_phase = _restore_phase("POLLING")
        restore.save(update_fields=["params", "operation_phase", "modified"])
        return False

    def _aws_s3_restore_source_buckets(self, backup):
        """Return source bucket identifiers without retaining provider details."""
        source_buckets = {str(self.unique_id or "").strip()}
        metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
        aws_backup = metadata.get("_aws_backup") or {}
        resource_arn = str(aws_backup.get("resource_arn") or "").strip()
        if ":s3:::" in resource_arn:
            source_buckets.add(resource_arn.split(":s3:::", 1)[1].split("/", 1)[0])
        return {value.casefold() for value in source_buckets if value}

    @staticmethod
    def _aws_s3_restore_empty_page(response, collections):
        if not isinstance(response, dict) or response.get("IsTruncated") is not False:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        result = {}
        for collection in collections:
            values = response[collection] if collection in response else []
            if not isinstance(values, list) or any(
                not isinstance(item, dict) for item in values
            ):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            result[collection] = values
        return result

    def _record_aws_s3_restore_preflight(self, restore, *, result, reason=None,
                                         versioning_status=None):
        """Persist only safe facts about the S3 destination preflight."""
        witness = {
            "schema": 1,
            "result": str(result),
            "checked_at": timezone.now().isoformat(),
        }
        if reason:
            witness["reason"] = str(reason)
        if versioning_status is not None:
            witness["versioning_status"] = str(versioning_status)
        if result == "passed":
            witness.update({
                "destination_exists": True,
                "versioning": "Enabled",
                "empty": True,
                "current_object_count": 0,
                "noncurrent_version_count": 0,
                "delete_marker_count": 0,
                "multipart_upload_count": 0,
                "scan_complete": True,
            })
        params = _restore_params(restore)
        params["_bs_s3_restore_preflight"] = witness
        restore.params = params
        restore.save(update_fields=["params", "modified"])

    def _aws_s3_restore_destination_preflight(self, client, backup, restore,
                                              destination):
        """Prove a versioned, empty, non-source S3 restore destination."""
        if destination.casefold() in self._aws_s3_restore_source_buckets(backup):
            self._record_aws_s3_restore_preflight(
                restore, result="rejected", reason="source_bucket"
            )
            raise _RestoreProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        try:
            head_response = client.head_bucket(Bucket=destination)
            if not isinstance(head_response, dict):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            versioning_response = client.get_bucket_versioning(Bucket=destination)
        except _RestoreProviderError:
            self._record_aws_s3_restore_preflight(
                restore, result="rejected", reason="malformed_response"
            )
            raise
        except Exception as error:
            classified = _restore_exception(error, mutation=False)
            self._record_aws_s3_restore_preflight(
                restore, result="provider_error", reason=classified.code
            )
            raise classified from None

        if not isinstance(versioning_response, dict):
            self._record_aws_s3_restore_preflight(
                restore, result="rejected", reason="malformed_response"
            )
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        versioning_status = versioning_response.get("Status")
        if not isinstance(versioning_status, (str, type(None))) or versioning_status not in {
            None,
            "Enabled",
            "Suspended",
        }:
            self._record_aws_s3_restore_preflight(
                restore, result="rejected", reason="malformed_response"
            )
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if versioning_status != "Enabled":
            reason = (
                "versioning_suspended"
                if versioning_status == "Suspended"
                else "versioning_unenabled"
            )
            self._record_aws_s3_restore_preflight(
                restore,
                result="rejected",
                reason=reason,
                versioning_status=versioning_status or "Unversioned",
            )
            raise _RestoreProviderError("PROVIDER_FAILED")

        checks = (
            ("list_objects_v2", {"Bucket": destination, "MaxKeys": 1}, ("Contents",)),
            (
                "list_object_versions",
                {"Bucket": destination, "MaxKeys": 1},
                ("Versions", "DeleteMarkers"),
            ),
            (
                "list_multipart_uploads",
                {"Bucket": destination, "MaxUploads": 1},
                ("Uploads",),
            ),
        )
        for method_name, request, collections in checks:
            try:
                response = getattr(client, method_name)(**request)
                page = self._aws_s3_restore_empty_page(response, collections)
            except _RestoreProviderError:
                self._record_aws_s3_restore_preflight(
                    restore, result="rejected", reason="malformed_response"
                )
                raise
            except Exception as error:
                classified = _restore_exception(error, mutation=False)
                self._record_aws_s3_restore_preflight(
                    restore, result="provider_error", reason=classified.code
                )
                raise classified from None

            if method_name == "list_objects_v2" and page["Contents"]:
                self._record_aws_s3_restore_preflight(
                    restore, result="rejected", reason="current_objects"
                )
                raise _RestoreProviderError("PROVIDER_FAILED")
            if method_name == "list_object_versions":
                versions = page["Versions"]
                if versions:
                    if any(
                        not isinstance(version.get("IsLatest"), bool)
                        for version in versions
                    ):
                        self._record_aws_s3_restore_preflight(
                            restore, result="rejected", reason="malformed_response"
                        )
                        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                    reason = (
                        "current_objects"
                        if any(version["IsLatest"] for version in versions)
                        else "noncurrent_versions"
                    )
                    self._record_aws_s3_restore_preflight(
                        restore, result="rejected", reason=reason
                    )
                    raise _RestoreProviderError("PROVIDER_FAILED")
                if page["DeleteMarkers"]:
                    self._record_aws_s3_restore_preflight(
                        restore, result="rejected", reason="delete_markers"
                    )
                    raise _RestoreProviderError("PROVIDER_FAILED")
            if method_name == "list_multipart_uploads" and page["Uploads"]:
                self._record_aws_s3_restore_preflight(
                    restore, result="rejected", reason="multipart_uploads"
                )
                raise _RestoreProviderError("PROVIDER_FAILED")

        self._record_aws_s3_restore_preflight(restore, result="passed")

    def restore_snapshot(self, backup, restore):
        return self._restore_snapshot_aws(backup, restore)
        auth = self.node.connection.auth_aws
        params = restore.params or {}

        if self.resource_type in {self.ResourceType.S3, self.ResourceType.DYNAMODB}:
            from apps._tasks.integration.aws_backup import (
                idempotency_token,
                start_restore_job,
            )

            backup_metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
            aws_backup = backup_metadata.get("_aws_backup") or {}
            recovery_point_arn = aws_backup.get("recovery_point_arn")
            if not recovery_point_arn:
                raise ValueError(
                    "AWS Backup has not published a recovery point for this backup yet."
                )

            if self.resource_type == self.ResourceType.S3:
                destination = str(params.get("destination_bucket_name") or "").strip()
                if not destination:
                    raise ValueError(
                        "destination_bucket_name is required for an S3 restore."
                    )
                s3 = auth.get_client("s3")
                s3.head_bucket(Bucket=destination)
                if (
                    s3.get_bucket_versioning(Bucket=destination).get("Status")
                    != "Enabled"
                ):
                    raise ValueError(
                        "The S3 restore destination must have versioning enabled."
                    )
                restore_metadata = {"DestinationBucketName": destination}
                for key in (
                    "EncryptionType",
                    "KMSKey",
                    "ItemsToRestore",
                    "RestoreLatestVersionsUpTo",
                    "RestoreTime",
                ):
                    if key in params and params[key] is not None:
                        value = params[key]
                        restore_metadata[key] = (
                            json.dumps(value)
                            if isinstance(value, (list, dict))
                            else str(value)
                        )
                requested_restore_acls = params.get("RestoreACLs")
                if str(requested_restore_acls).lower() in {"true", "1"}:
                    try:
                        ownership = s3.get_bucket_ownership_controls(
                            Bucket=destination
                        ).get("OwnershipControls") or {}
                        ownership_enforced = any(
                            rule.get("ObjectOwnership") == "BucketOwnerEnforced"
                            for rule in ownership.get("Rules") or []
                        )
                    except ClientError as error:
                        # A bucket without an OwnershipControls configuration
                        # supports ACLs. If the caller cannot read this optional
                        # setting, let AWS Backup make the final authorization
                        # decision rather than requiring an extra permission.
                        if error.response.get("Error", {}).get("Code") in {
                            "OwnershipControlsNotFoundError",
                            "NoSuchOwnershipControls",
                            "AccessDenied",
                            "AccessDeniedException",
                        }:
                            ownership_enforced = False
                        else:
                            raise
                    if ownership_enforced:
                        raise ValueError(
                            "RestoreACLs=true requires an S3 destination with ACLs enabled."
                        )
                    restore_metadata["RestoreACLs"] = "true"
                else:
                    # AWS Backup otherwise attempts to restore ACLs by default,
                    # which is rejected by common BucketOwnerEnforced buckets.
                    # Preserve ACLs only when the caller explicitly opts in.
                    restore_metadata["RestoreACLs"] = "false"
                resource_id = destination
            else:
                import re

                resource_id = str(
                    params.get("target_table_name") or restore.name or ""
                ).strip()
                resource_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", resource_id)
                if not 3 <= len(resource_id) <= 255:
                    raise ValueError(
                        "target_table_name must be between 3 and 255 characters."
                    )
                dynamodb = auth.get_client("dynamodb")
                try:
                    dynamodb.describe_table(TableName=resource_id)
                except ClientError as error:
                    if error.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                        raise
                else:
                    raise ValueError(
                        f"DynamoDB restore target '{resource_id}' already exists. "
                        "Choose a new table name."
                    )
                restore_metadata = {"TargetTableName": resource_id}
                for key in ("EncryptionType", "KmsMasterKeyArn"):
                    if key in params and params[key] is not None:
                        restore_metadata[key] = str(params[key])

            response = start_restore_job(
                auth,
                self.resource_type,
                recovery_point_arn,
                restore_metadata,
                idempotency_token("restore", restore.id),
            )
            restore.provider_job_id = response.get("RestoreJobId")
            if not restore.provider_job_id:
                raise ValueError("AWS Backup did not return a RestoreJobId.")
            restore.resource_id = resource_id
            restore.params = dict(params, _aws_backup_restore_metadata=restore_metadata)
            restore.save(
                update_fields=[
                    "provider_job_id",
                    "resource_id",
                    "params",
                    "modified",
                ]
            )
            return

        client = auth.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            instance_type = params.get("instance_type")
            if not instance_type:
                response = client.describe_instances(
                    InstanceIds=[self.unique_id],
                )
                if response.get("Reservations"):
                    instance = response.get("Reservations")[0]["Instances"][0]
                    instance_type = instance.get("InstanceType")
            if not instance_type:
                raise Exception(
                    "Unable to determine instance type. Please provide instance_type in params."
                )
            instance_data = {
                "ImageId": backup.unique_id,
                "MinCount": 1,
                "MaxCount": 1,
                "InstanceType": instance_type,
                "TagSpecifications": [
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": restore.name}],
                    }
                ],
            }
            if params.get("key_name"):
                instance_data["KeyName"] = params.get("key_name")
            if params.get("subnet_id"):
                instance_data["SubnetId"] = params.get("subnet_id")
            if params.get("security_group_ids"):
                instance_data["SecurityGroupIds"] = params.get("security_group_ids")
            response = client.run_instances(**instance_data)
            if not response.get("Instances"):
                raise Exception("InstanceId not present in run_instances response.")
            restore.resource_id = response.get("Instances")[0]["InstanceId"]
            restore.save()

        elif self.node.type == CoreNode.Type.VOLUME:
            availability_zone = params.get("availability_zone")
            if not availability_zone:
                response = client.describe_volumes(
                    VolumeIds=[self.unique_id],
                )
                if response.get("Volumes"):
                    availability_zone = response.get("Volumes")[0].get("AvailabilityZone")
            if not availability_zone:
                raise Exception(
                    "Unable to determine availability zone. Please provide availability_zone in params."
                )
            response = client.create_volume(
                AvailabilityZone=availability_zone,
                SnapshotId=backup.unique_id,
            )
            if not response.get("VolumeId"):
                raise Exception("VolumeId not present in create_volume response.")
            restore.resource_id = response.get("VolumeId")
            restore.save()

    def check_restore(self, restore):
        return self._check_restore_aws(restore)
        from apps.console.backup.models import CoreCloudRestore

        auth = self.node.connection.auth_aws

        if self.resource_type in {self.ResourceType.S3, self.ResourceType.DYNAMODB}:
            from apps._tasks.integration.aws_backup import describe_restore_job

            if not restore.provider_job_id:
                return CoreCloudRestore.Status.IN_PROGRESS
            result = describe_restore_job(auth, restore.provider_job_id)
            state = str(result.get("Status") or "").upper()
            if state == "COMPLETED":
                if self.resource_type == self.ResourceType.S3:
                    auth.get_client("s3").head_bucket(Bucket=restore.resource_id)
                else:
                    table = auth.get_client("dynamodb").describe_table(
                        TableName=restore.resource_id
                    ).get("Table") or {}
                    if table.get("TableStatus") != "ACTIVE":
                        return CoreCloudRestore.Status.IN_PROGRESS
                return CoreCloudRestore.Status.COMPLETE
            if state in {"FAILED", "ABORTED", "EXPIRED"}:
                restore.error = result.get("StatusMessage") or (
                    f"AWS Backup restore job ended in {state}."
                )
                restore.save(update_fields=["error", "modified"])
                return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS

        client = auth.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            response = client.describe_instances(
                InstanceIds=[restore.resource_id],
            )
            if response.get("Reservations"):
                instance = response.get("Reservations")[0]["Instances"][0]
                state = instance.get("State", {}).get("Name")
                if state == "running":
                    return CoreCloudRestore.Status.COMPLETE
                elif state == "terminated" or state == "shutting-down":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS

        elif self.node.type == CoreNode.Type.VOLUME:
            response = client.describe_volumes(
                VolumeIds=[restore.resource_id],
            )
            if response.get("Volumes"):
                state = response.get("Volumes")[0].get("State")
                if state == "available":
                    return CoreCloudRestore.Status.COMPLETE
                elif state == "error":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


class CoreLightsail(UtilCloud):
    class ResourceType(models.TextChoices):
        # Existing Lightsail rows represented instances (or disks, which are
        # still distinguished by CoreNode.Type). Keep that value as the model
        # default so adding managed relational databases is backward compatible.
        INSTANCE = "instance", "Instance"
        DATABASE = "database", "Relational Database"

    node = models.OneToOneField(
        "CoreNode", related_name="lightsail", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    resource_type = models.CharField(
        max_length=32,
        choices=ResourceType.choices,
        default=ResourceType.INSTANCE,
    )
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_lightsail"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_lightsail.get_client()

            if self.resource_type == self.ResourceType.DATABASE:
                response = client.get_relational_database(
                    relationalDatabaseName=self.unique_id
                )
                database = response.get("relationalDatabase") or {}
                node_ok = database.get("state") in {"available", "stopped"}
            elif self.node.type == CoreNode.Type.CLOUD:
                response = client.get_instance(
                    instanceName=self.unique_id
                )
                if response.get("instance"):
                    instance = response.get("instance")
                    if instance.get("state", {}).get("name") == "running" or instance.get("state", {}).get(
                            "name") == "stopped":
                        node_ok = True
            elif self.node.type == CoreNode.Type.VOLUME:
                response = client.get_disk(
                    diskName=self.unique_id
                )
                disk = response.get("disk") or {}
                if disk.get("state") == "available" or disk.get("state") == "in-use":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_lightsail.get_client()

            if self.resource_type == self.ResourceType.DATABASE:
                existing = self._find_relational_database_snapshot(
                    client, backup.uuid_str
                )
                if existing:
                    backup.unique_id = existing.get("name", backup.uuid_str)
                    backup.size_gigabytes = existing.get("sizeInGb")
                    backup.metadata = existing
                    backup.save()
                    return

                response = client.create_relational_database_snapshot(
                    relationalDatabaseName=self.unique_id,
                    relationalDatabaseSnapshotName=backup.uuid_str,
                )
                operations = response.get("operations") or []
                if self._lightsail_operation_failed(operations):
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        "Lightsail did not accept the relational database snapshot request.",
                    )
                backup.unique_id = backup.uuid_str
                backup.save()
            elif self.node.type == CoreNode.Type.CLOUD:
                try:
                    existing = client.get_instance_snapshot(
                        instanceSnapshotName=backup.uuid_str
                    ).get("instanceSnapshot")
                except ClientError as error:
                    code = error.response.get("Error", {}).get("Code")
                    if code not in {"NotFoundException", "ResourceNotFoundException"}:
                        raise
                    existing = None
                if existing:
                    backup.unique_id = backup.uuid_str
                    backup.size_gigabytes = existing.get("sizeInGb")
                    backup.metadata = existing
                    backup.save()
                    return
                response = client.create_instance_snapshot(
                    instanceSnapshotName=backup.uuid_str, instanceName=self.unique_id
                )
                operations = response.get("operations") or []
                if not operations or operations[0].get("status") == "Failed":
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Lightsail did not accept the instance snapshot request.",
                    )
                backup.unique_id = backup.uuid_str
                backup.save()
            elif self.node.type == CoreNode.Type.VOLUME:
                try:
                    existing = client.get_disk_snapshot(
                        diskSnapshotName=backup.uuid_str
                    ).get("diskSnapshot")
                except ClientError as error:
                    code = error.response.get("Error", {}).get("Code")
                    if code not in {"NotFoundException", "ResourceNotFoundException"}:
                        raise
                    existing = None
                if existing:
                    backup.unique_id = backup.uuid_str
                    backup.size_gigabytes = existing.get("sizeInGb")
                    backup.metadata = existing
                    backup.save()
                    return
                response = client.create_disk_snapshot(
                    diskName=self.unique_id,
                    diskSnapshotName=backup.uuid_str,
                )
                operations = response.get("operations") or []
                if not operations or operations[0].get("status") == "Failed":
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Lightsail did not accept the disk snapshot request.",
                    )
                backup.unique_id = backup.uuid_str
                backup.save()
        except NodeBackupFailedError:
            raise
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )

    @staticmethod
    def _concrete_availability_zone(value):
        """Return a usable AZ, ignoring Lightsail's regional ``all`` marker."""
        if not isinstance(value, str):
            return None
        value = value.strip()
        if not value or value.lower() in {"all", "global"}:
            return None
        return value

    @staticmethod
    def _lightsail_operation_failed(operations):
        """True when Lightsail did not accept an asynchronous request."""
        if not operations or not isinstance(operations[0], dict):
            return True
        return str(operations[0].get("status") or "").lower() == "failed"

    @staticmethod
    def _find_relational_database_snapshot(client, snapshot_name):
        """Find one relational-database snapshot by exact name across all pages.

        Lightsail does not expose a single-snapshot read API for relational
        databases. An exact, paginated lookup is therefore required before a
        retry sends another create request and before a restore derives its
        source settings.
        """
        page_token = None
        while True:
            request = {"pageToken": page_token} if page_token else {}
            response = client.get_relational_database_snapshots(**request)
            response = response if isinstance(response, dict) else {}
            snapshots = response.get("relationalDatabaseSnapshots") or []
            for snapshot in snapshots:
                if isinstance(snapshot, dict) and snapshot.get("name") == snapshot_name:
                    return snapshot

            next_page_token = response.get("nextPageToken")
            # Do not spin forever on a malformed/repeated pagination token.
            if not next_page_token or next_page_token == page_token:
                return None
            page_token = next_page_token

    def _find_lightsail_restore_target(self, client, restore):
        try:
            if self.resource_type == self.ResourceType.DATABASE:
                response = client.get_relational_database(relationalDatabaseName=restore.name)
                target = response.get("relationalDatabase") if isinstance(response, dict) else None
            elif self.node.type == CoreNode.Type.CLOUD:
                response = client.get_instance(instanceName=restore.name)
                target = response.get("instance") if isinstance(response, dict) else None
            else:
                response = client.get_disk(diskName=restore.name)
                target = response.get("disk") if isinstance(response, dict) else None
        except ClientError as error:
            classified = _restore_exception(error)
            if classified.code == "PROVIDER_NOT_FOUND":
                return None
            raise classified
        if target is None:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        return target

    def _restore_snapshot_lightsail(self, backup, restore):
        client = self.node.connection.auth_lightsail.get_client()
        target_kind = "database" if self.resource_type == self.ResourceType.DATABASE else (
            "instance" if self.node.type == CoreNode.Type.CLOUD else "disk"
        )
        marker, params = _prepare_cloud_restore(
            restore,
            provider="lightsail",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return
        try:
            # Names are Lightsail's only stable create-time identity. On a lost
            # response the exact GET is therefore the provider reconciliation
            # operation; source snapshot fields are checked whenever returned.
            if _restore_unknown(restore):
                existing = self._find_lightsail_restore_target(client, restore)
                if not existing:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                if not _restore_verify_target(
                    restore,
                    existing,
                    source_id=backup.unique_id,
                    marker=marker,
                    source_keys=(
                        "snapshotName", "instanceSnapshotName", "diskSnapshotName",
                        "relationalDatabaseSnapshotName", "sourceSnapshotName",
                    ),
                ):
                    return _restore_status("FAILED")
                return _restore_adopt(restore, existing.get("name") or restore.name, provider_status=existing.get("state"))

            if self.resource_type == self.ResourceType.DATABASE:
                snapshot = self._find_relational_database_snapshot(client, backup.unique_id)
                if not snapshot:
                    return _restore_safe_failure(restore, "PROVIDER_NOT_FOUND")
                availability_zone = self._concrete_availability_zone(
                    params.get("availability_zone") or params.get("availabilityZone")
                ) or self._concrete_availability_zone((snapshot.get("location") or {}).get("availabilityZone"))
                bundle_id = params.get("bundle_id") or params.get("relationalDatabaseBundleId") or snapshot.get("fromRelationalDatabaseBundleId")
                if not availability_zone or not bundle_id:
                    response = client.get_relational_database(relationalDatabaseName=self.unique_id)
                    source_database = response.get("relationalDatabase") if isinstance(response, dict) else None
                    if not isinstance(source_database, dict):
                        raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                    availability_zone = availability_zone or self._concrete_availability_zone((source_database.get("location") or {}).get("availabilityZone"))
                    bundle_id = bundle_id or source_database.get("relationalDatabaseBundleId")
                if not availability_zone or not bundle_id:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                request = {
                    "relationalDatabaseName": restore.name,
                    "relationalDatabaseSnapshotName": backup.unique_id,
                    "availabilityZone": availability_zone,
                    "relationalDatabaseBundleId": bundle_id,
                }
                publicly_accessible = params.get("publicly_accessible")
                if publicly_accessible is None:
                    publicly_accessible = params.get("publiclyAccessible")
                if publicly_accessible is not None:
                    request["publiclyAccessible"] = publicly_accessible
                _restore_begin_mutation(restore)
                response = client.create_relational_database_from_snapshot(**request)
                operations = response.get("operations") if isinstance(response, dict) else None
                if self._lightsail_operation_failed(operations):
                    _restore_clear_unknown(restore)
                    return _restore_safe_failure(restore, "PROVIDER_FAILED")
                return _restore_adopt(restore, restore.name, provider_status=(operations[0].get("status") if operations else "started"), params_update={"availability_zone": availability_zone, "bundle_id": bundle_id})

            if self.node.type == CoreNode.Type.CLOUD:
                availability_zone = self._concrete_availability_zone(params.get("availability_zone"))
                if not availability_zone:
                    response = client.get_instance_snapshot(instanceSnapshotName=backup.unique_id)
                    availability_zone = self._concrete_availability_zone((response.get("instanceSnapshot") or {}).get("location", {}).get("availabilityZone"))
                if not availability_zone:
                    response = client.get_instance(instanceName=self.unique_id)
                    availability_zone = self._concrete_availability_zone((response.get("instance") or {}).get("location", {}).get("availabilityZone"))
                if not availability_zone:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                bundle_id = params.get("bundle_id")
                if not bundle_id:
                    response = client.get_instance(instanceName=self.unique_id)
                    bundle_id = (response.get("instance") or {}).get("bundleId")
                if not bundle_id:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                _restore_begin_mutation(restore)
                client.create_instances_from_snapshot(
                    instanceNames=[restore.name],
                    instanceSnapshotName=backup.unique_id,
                    availabilityZone=availability_zone,
                    bundleId=bundle_id,
                )
                return _restore_adopt(restore, restore.name, params_update={"availability_zone": availability_zone, "bundle_id": bundle_id})

            availability_zone = self._concrete_availability_zone(params.get("availability_zone"))
            if not availability_zone:
                response = client.get_disk_snapshot(diskSnapshotName=backup.unique_id)
                availability_zone = self._concrete_availability_zone((response.get("diskSnapshot") or {}).get("location", {}).get("availabilityZone"))
            if not availability_zone:
                response = client.get_disk(diskName=self.unique_id)
                availability_zone = self._concrete_availability_zone((response.get("disk") or {}).get("location", {}).get("availabilityZone"))
            if not availability_zone:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            _restore_begin_mutation(restore)
            client.create_disk_from_snapshot(
                diskName=restore.name,
                diskSnapshotName=backup.unique_id,
                availabilityZone=availability_zone,
                sizeInGb=int(backup.size_gigabytes),
            )
            return _restore_adopt(restore, restore.name, params_update={"availability_zone": availability_zone})
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_lightsail(self, restore):
        client = self.node.connection.auth_lightsail.get_client()
        if not restore.resource_id:
            if not _restore_unknown(restore):
                return _restore_status("IN_PROGRESS")
            try:
                target = self._find_lightsail_restore_target(client, restore)
                if not target:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                if not _restore_verify_target(
                    restore,
                    target,
                    source_id=(_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                    marker=_restore_marker_value(restore),
                    source_keys=("snapshotName", "instanceSnapshotName", "diskSnapshotName", "relationalDatabaseSnapshotName", "sourceSnapshotName"),
                ):
                    return _restore_status("FAILED")
                _restore_adopt(restore, target.get("name") or restore.name, provider_status=target.get("state"))
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)
        try:
            if self.resource_type == self.ResourceType.DATABASE:
                response = client.get_relational_database(relationalDatabaseName=restore.resource_id)
                target = response.get("relationalDatabase") if isinstance(response, dict) else None
                state = target.get("state") if isinstance(target, dict) else None
                terminal = {"failed", "error", "restore-error", "incompatible-network", "incompatible-parameters", "storage-full"}
            elif self.node.type == CoreNode.Type.CLOUD:
                response = client.get_instance(instanceName=restore.resource_id)
                target = response.get("instance") if isinstance(response, dict) else None
                state = ((target or {}).get("state") or {}).get("name") if isinstance(target, dict) else None
                terminal = {"error", "failed", "terminated"}
            else:
                response = client.get_disk(diskName=restore.resource_id)
                target = response.get("disk") if isinstance(response, dict) else None
                state = target.get("state") if isinstance(target, dict) else None
                terminal = {"error", "failed", "terminated"}
            if not _restore_verify_target(
                restore,
                target,
                source_id=(_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                marker=_restore_marker_value(restore),
                source_keys=("snapshotName", "instanceSnapshotName", "diskSnapshotName", "relationalDatabaseSnapshotName", "sourceSnapshotName"),
            ):
                return _restore_status("FAILED")
            if state in ({"available"} if self.resource_type == self.ResourceType.DATABASE else {"running"} if self.node.type == CoreNode.Type.CLOUD else {"available"}):
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if state in terminal:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if not state:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            # Old restore rows predate the marker contract. Preserve their
            # historical short propagation window for a just-created Lightsail
            # resource, while new rows classify 404 as a terminal provider error.
            classified = _restore_exception(error, mutation=False)
            if classified.code == "PROVIDER_NOT_FOUND" and not (_restore_params(restore).get("_bs_marker_required")):
                return _restore_status("IN_PROGRESS")
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

    def restore_snapshot(self, backup, restore):
        return self._restore_snapshot_lightsail(backup, restore)
        try:
            client = self.node.connection.auth_lightsail.get_client()
            params = restore.params or {}

            if self.resource_type == self.ResourceType.DATABASE:
                snapshot = self._find_relational_database_snapshot(
                    client, backup.unique_id
                )
                if not snapshot:
                    raise Exception(
                        f"Unable to find Lightsail relational database snapshot "
                        f"{backup.unique_id}."
                    )

                availability_zone = self._concrete_availability_zone(
                    params.get("availability_zone") or params.get("availabilityZone")
                ) or self._concrete_availability_zone(
                    (snapshot.get("location") or {}).get("availabilityZone")
                )
                bundle_id = (
                    params.get("bundle_id")
                    or params.get("relationalDatabaseBundleId")
                    or snapshot.get(
                        "fromRelationalDatabaseBundleId"
                    )
                )

                # Snapshot locations can be regional and older snapshots can omit
                # their source bundle. The source database provides the concrete
                # values required by create_relational_database_from_snapshot.
                if not availability_zone or not bundle_id:
                    response = client.get_relational_database(
                        relationalDatabaseName=self.unique_id
                    )
                    source_database = response.get("relationalDatabase") or {}
                    availability_zone = availability_zone or self._concrete_availability_zone(
                        (source_database.get("location") or {}).get("availabilityZone")
                    )
                    bundle_id = bundle_id or source_database.get(
                        "relationalDatabaseBundleId"
                    )

                if not availability_zone:
                    raise Exception(
                        "Unable to determine a concrete Lightsail availability zone."
                    )
                if not bundle_id:
                    raise Exception(
                        "Unable to determine a Lightsail relational database bundle."
                    )

                request = {
                    "relationalDatabaseName": restore.name,
                    "relationalDatabaseSnapshotName": backup.unique_id,
                    "availabilityZone": availability_zone,
                    "relationalDatabaseBundleId": bundle_id,
                }
                publicly_accessible = params.get("publicly_accessible")
                if publicly_accessible is None:
                    publicly_accessible = params.get("publiclyAccessible")
                if publicly_accessible is not None:
                    request["publiclyAccessible"] = publicly_accessible

                response = client.create_relational_database_from_snapshot(**request)
                if self._lightsail_operation_failed(response.get("operations") or []):
                    raise Exception(
                        "Lightsail did not accept the relational database restore request."
                    )
                restore.resource_id = restore.name
                restore.save()
            elif self.node.type == CoreNode.Type.CLOUD:
                availability_zone = self._concrete_availability_zone(
                    params.get("availability_zone")
                )
                if not availability_zone:
                    response = client.get_instance_snapshot(
                        instanceSnapshotName=backup.unique_id
                    )
                    availability_zone = self._concrete_availability_zone(
                        response.get("instanceSnapshot", {})
                        .get("location", {})
                        .get("availabilityZone")
                    )

                # Regional Lightsail snapshots report availabilityZone=all. The
                # restore API needs the concrete AZ of the source instance.
                if not availability_zone:
                    response = client.get_instance(instanceName=self.unique_id)
                    availability_zone = self._concrete_availability_zone(
                        response.get("instance", {})
                        .get("location", {})
                        .get("availabilityZone")
                    )
                if not availability_zone:
                    raise Exception(
                        "Unable to determine a concrete Lightsail availability zone."
                    )

                bundle_id = params.get("bundle_id")
                if not bundle_id:
                    response = client.get_instance(
                        instanceName=self.unique_id
                    )
                    bundle_id = response.get("instance", {}).get("bundleId")

                client.create_instances_from_snapshot(
                    instanceNames=[restore.name],
                    instanceSnapshotName=backup.unique_id,
                    availabilityZone=availability_zone,
                    bundleId=bundle_id,
                )
                restore.resource_id = restore.name
                restore.save()
            elif self.node.type == CoreNode.Type.VOLUME:
                availability_zone = self._concrete_availability_zone(
                    params.get("availability_zone")
                )
                if not availability_zone:
                    response = client.get_disk_snapshot(
                        diskSnapshotName=backup.unique_id
                    )
                    availability_zone = self._concrete_availability_zone(
                        response.get("diskSnapshot", {})
                        .get("location", {})
                        .get("availabilityZone")
                    )
                if not availability_zone:
                    response = client.get_disk(diskName=self.unique_id)
                    availability_zone = self._concrete_availability_zone(
                        response.get("disk", {})
                        .get("location", {})
                        .get("availabilityZone")
                    )
                if not availability_zone:
                    raise Exception(
                        "Unable to determine a concrete Lightsail availability zone."
                    )

                client.create_disk_from_snapshot(
                    diskName=restore.name,
                    diskSnapshotName=backup.unique_id,
                    availabilityZone=availability_zone,
                    sizeInGb=int(backup.size_gigabytes),
                )
                restore.resource_id = restore.name
                restore.save()
        except Exception as e:
            raise Exception(get_error(e))

    def check_restore(self, restore):
        return self._check_restore_lightsail(restore)
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_lightsail.get_client()

        if self.resource_type == self.ResourceType.DATABASE:
            try:
                response = client.get_relational_database(
                    relationalDatabaseName=restore.resource_id
                )
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code")
                if code in {"NotFoundException", "ResourceNotFoundException"}:
                    # A just-accepted create can take a short time to appear.
                    return CoreCloudRestore.Status.IN_PROGRESS
                raise

            database = response.get("relationalDatabase") or {}
            state = str(database.get("state") or "").lower()
            if state == "available":
                return CoreCloudRestore.Status.COMPLETE
            if state in {
                "failed",
                "error",
                "restore-error",
                "incompatible-network",
                "incompatible-parameters",
                "storage-full",
            }:
                return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS
        elif self.node.type == CoreNode.Type.CLOUD:
            response = client.get_instance(
                instanceName=restore.resource_id
            )
            instance = response.get("instance", {})
            state = instance.get("state", {}).get("name")
            if state == "running":
                return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS
        elif self.node.type == CoreNode.Type.VOLUME:
            response = client.get_disk(
                diskName=restore.resource_id
            )
            disk = response.get("disk", {})
            state = disk.get("state")
            if state == "available":
                return CoreCloudRestore.Status.COMPLETE
            elif state == "error":
                return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


class CoreAWSRDS(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="aws_rds", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_rds"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_aws_rds.get_client()

            response = client.describe_db_instances(
                DBInstanceIdentifier=self.unique_id
            )
            if response.get("DBInstances"):
                db_instance = response.get("DBInstances")[0]
                if db_instance.get("DBInstanceStatus") == "available" or db_instance.get("DBInstanceStatus") == "stopped":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        client = self.node.connection.auth_aws_rds.get_client()
        try:
            existing_response = client.describe_db_snapshots(
                DBSnapshotIdentifier=backup.uuid_str,
            )
            existing_snapshots = (
                existing_response.get("DBSnapshots", [])
                if isinstance(existing_response, dict)
                else []
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code not in {"DBSnapshotNotFoundFault", "DBSnapshotNotFound"}:
                raise
            existing_snapshots = []
        if existing_snapshots:
            # RDS includes datetime values in snapshot responses. Normalize
            # the provider payload before persisting it in JSONField; this
            # path is used when a worker retries after AWS accepted a snapshot
            # request but the first response was not persisted.
            from django.core.serializers.json import DjangoJSONEncoder
            import json

            existing = json.loads(
                json.dumps(existing_snapshots[0], cls=DjangoJSONEncoder)
            )
            backup.unique_id = existing.get("DBSnapshotIdentifier", backup.uuid_str)
            backup.size_gigabytes = existing.get("AllocatedStorage")
            backup.metadata = existing
            backup.save()
            return
        snapshot = client.create_db_snapshot(
            DBSnapshotIdentifier=backup.uuid_str, DBInstanceIdentifier=self.unique_id
        )
        backup.unique_id = snapshot["DBSnapshot"]["DBSnapshotIdentifier"]
        backup.size_gigabytes = snapshot["DBSnapshot"]["AllocatedStorage"]
        backup.save()

    @staticmethod
    def _restore_identifier(restore):
        identifier = re.sub(r"[^a-zA-Z0-9-]", "-", str(restore.name))
        identifier = re.sub(r"-+", "-", identifier)
        identifier = re.sub(r"^[^a-zA-Z]+", "", identifier)
        return identifier[:63].rstrip("-")

    @staticmethod
    def _restore_instance_with_tags(client, instance):
        """Read the current RDS ownership tags for one exact restore target."""

        if not isinstance(instance, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        arn = str(instance.get("DBInstanceArn") or "")
        if not arn:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        response = client.list_tags_for_resource(ResourceName=arn)
        if not isinstance(response, dict) or not isinstance(
            response.get("TagList"), list
        ):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        enriched = dict(instance)
        enriched["TagList"] = list(response["TagList"])
        return enriched

    @staticmethod
    def _restore_tags_pending(instance, marker):
        tags = _restore_tags(instance.get("TagList") or [])
        values = set(tags) | set(tags.values())
        return not tags and str(marker) not in values

    @staticmethod
    def _restore_rds_tags_owned(instance, marker, source_id):
        tags = _restore_tags(instance.get("TagList") or [])
        return (
            tags.get("BackupSheepRestore") == str(marker)
            and tags.get("BackupSheepSource") == str(source_id)
        )

    def _restore_snapshot_rds(self, backup, restore):
        client = self.node.connection.auth_aws_rds.get_client()
        identifier = self._restore_identifier(restore)
        if not identifier:
            _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE")
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        params = _restore_params(restore)
        marker, params = _prepare_cloud_restore(
            restore,
            provider="aws_rds",
            source_id=backup.unique_id,
            target_kind="db_instance",
            target_name=identifier,
        )
        if restore.resource_id:
            return
        try:
            existing = None
            try:
                response = client.describe_db_instances(DBInstanceIdentifier=identifier)
                instances = response.get("DBInstances") if isinstance(response, dict) else None
                if not isinstance(instances, list):
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                if len(instances) > 1:
                    raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
                existing = instances[0] if instances else None
            except ClientError as error:
                classified = _restore_exception(error)
                if classified.code != "PROVIDER_NOT_FOUND":
                    raise classified
            if existing:
                existing = self._restore_instance_with_tags(client, existing)
                if self._restore_tags_pending(existing, marker) and _restore_unknown(
                    restore
                ):
                    return _restore_handle_error(
                        restore,
                        _RestoreProviderError(
                            "PROVIDER_TRANSIENT_OUTAGE",
                            retryable=True,
                            unknown_outcome=True,
                        ),
                        mutation=False,
                    )
                if not self._restore_rds_tags_owned(
                    existing, marker, backup.unique_id
                ):
                    return _restore_safe_failure(restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
                if _restore_unknown(restore):
                    _restore_adopt(restore, identifier, provider_status=existing.get("DBInstanceStatus"))
                    return
                return _restore_safe_failure(restore, "PROVIDER_FAILED", manual_review=True)
            if _restore_unknown(restore):
                return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)

            request = {
                "DBInstanceIdentifier": identifier,
                "DBSnapshotIdentifier": backup.unique_id,
                "Tags": [
                    {"Key": "BackupSheepRestore", "Value": marker},
                    {"Key": "BackupSheepSource", "Value": str(backup.unique_id)},
                ],
            }
            for key, provider_key in (
                ("db_instance_class", "DBInstanceClass"),
                ("db_subnet_group_name", "DBSubnetGroupName"),
                ("multi_az", "MultiAZ"),
                ("publicly_accessible", "PubliclyAccessible"),
                ("vpc_security_group_ids", "VpcSecurityGroupIds"),
                ("storage_type", "StorageType"),
            ):
                if params.get(key) is not None:
                    request[provider_key] = params[key]
            _restore_begin_mutation(restore)
            response = client.restore_db_instance_from_db_snapshot(**request)
            created = response.get("DBInstance") if isinstance(response, dict) else None
            if not isinstance(created, dict):
                _restore_unknown_outcome(
                    restore, code="PROVIDER_MALFORMED_RESPONSE"
                )
                return _restore_status("IN_PROGRESS")
            if (
                str(created.get("DBInstanceIdentifier") or "") != identifier
            ):
                return _restore_safe_failure(
                    restore,
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    manual_review=True,
                )
            # RDS commonly omits DBSnapshotIdentifier and returns an empty
            # TagList in the immediate create response even when it accepted the
            # requested tags. Persist the exact resource id, then require both
            # ownership tags on every reconciliation/poll before completion.
            if created.get("TagList") and not self._restore_rds_tags_owned(
                created, marker, backup.unique_id
            ):
                return _restore_safe_failure(
                    restore,
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    manual_review=True,
                )
            _restore_adopt(restore, identifier, provider_status="creating")
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_rds(self, restore):
        client = self.node.connection.auth_aws_rds.get_client()
        if not restore.resource_id:
            return _restore_status("IN_PROGRESS")
        try:
            response = client.describe_db_instances(DBInstanceIdentifier=restore.resource_id)
            instances = response.get("DBInstances") if isinstance(response, dict) else None
            if not isinstance(instances, list) or len(instances) != 1:
                return _restore_safe_failure(restore, "PROVIDER_NOT_FOUND")
            instance = self._restore_instance_with_tags(client, instances[0])
            marker = _restore_marker_value(restore)
            if self._restore_tags_pending(instance, marker):
                return _restore_handle_error(
                    restore,
                    _RestoreProviderError(
                        "PROVIDER_TRANSIENT_OUTAGE", retryable=True
                    ),
                    mutation=False,
                    raise_terminal=False,
                )
            source_id = (
                _restore_params(restore).get("_backupsheep_restore") or {}
            ).get("source_id")
            if not self._restore_rds_tags_owned(instance, marker, source_id):
                return _restore_safe_failure(
                    restore,
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    manual_review=True,
                )
            if str(instance.get("DBInstanceIdentifier") or "") != str(
                restore.resource_id
            ):
                return _restore_status("FAILED")
            status = instance.get("DBInstanceStatus")
            if status == "available":
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if status in {"failed", "incompatible-restore", "incompatible-network", "incompatible-parameters", "deleted"}:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if status not in {"creating", "backing-up", "modifying", "rebooting", "starting", "stopped", "available"}:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            classified = _restore_exception(error, mutation=False)
            if classified.code == "PROVIDER_NOT_FOUND" and not (_restore_params(restore).get("_bs_marker_required")):
                return _restore_status("IN_PROGRESS")
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

    def restore_snapshot(self, backup, restore):
        return self._restore_snapshot_rds(backup, restore)
        import re

        client = self.node.connection.auth_aws_rds.get_client()

        # RDS identifiers must be 1-63 chars, start with a letter, contain
        # only letters/digits/hyphens with no consecutive or trailing hyphens
        identifier = re.sub(r"[^a-zA-Z0-9-]", "-", restore.name)
        identifier = re.sub(r"-+", "-", identifier)
        identifier = re.sub(r"^[^a-zA-Z]+", "", identifier)
        identifier = identifier[:63].rstrip("-")
        if not identifier:
            raise Exception(
                f"Unable to build a valid RDS instance identifier from '{restore.name}'. "
                "The name must contain at least one letter."
            )

        request = {
            "DBInstanceIdentifier": identifier,
            "DBSnapshotIdentifier": backup.unique_id,
        }
        params = restore.params or {}
        if params.get("db_instance_class"):
            request["DBInstanceClass"] = params["db_instance_class"]
        if params.get("db_subnet_group_name"):
            request["DBSubnetGroupName"] = params["db_subnet_group_name"]
        if params.get("multi_az") is not None:
            request["MultiAZ"] = params["multi_az"]
        if params.get("publicly_accessible") is not None:
            request["PubliclyAccessible"] = params["publicly_accessible"]
        if params.get("vpc_security_group_ids"):
            request["VpcSecurityGroupIds"] = params["vpc_security_group_ids"]
        if params.get("storage_type"):
            request["StorageType"] = params["storage_type"]

        try:
            client.restore_db_instance_from_db_snapshot(**request)
        except ClientError as e:
            raise Exception(
                f"Unable to restore RDS snapshot {backup.unique_id}: {get_error(e)}"
            )

        restore.resource_id = identifier
        restore.save()

    def check_restore(self, restore):
        return self._check_restore_rds(restore)
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_aws_rds.get_client()
        try:
            response = client.describe_db_instances(
                DBInstanceIdentifier=restore.resource_id
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
                # the new instance can take a moment to appear after restore starts
                return CoreCloudRestore.Status.IN_PROGRESS
            raise

        db_instance = response.get("DBInstances")[0]
        status = db_instance.get("DBInstanceStatus")

        if status == "available":
            return CoreCloudRestore.Status.COMPLETE
        elif status in ("failed", "incompatible-restore", "incompatible-network", "incompatible-parameters"):
            return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


class CoreVultrDatabase(UtilCloud):
    """Vultr Managed Database cluster source.

    This is intentionally separate from ``CoreVultr``: compute/block snapshots
    and managed-database provider backups have different ownership and restore
    semantics.
    """

    node = models.OneToOneField(
        "CoreNode", related_name="vultr_database", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    engine = models.CharField(max_length=64, default="")
    region = models.CharField(max_length=255, default="")
    plan = models.CharField(max_length=255, default="")
    provider_status = models.CharField(max_length=64, default="")
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr_database"

    @property
    def client(self):
        from apps.console.vultr_database import VultrManagedDatabaseClient

        return VultrManagedDatabaseClient(self.node.connection.auth_vultr)

    def capabilities(self):
        from apps.console.vultr_database import VultrDatabaseCapabilities

        return VultrDatabaseCapabilities(self.engine, self.plan)

    def validate(self):
        from apps.console.vultr_database import safe_vultr_database_record

        try:
            database = self.client.get_database(self.unique_id)
            self.provider_status = str(database.get("status") or "")
            self.metadata = safe_vultr_database_record(database)
            self.save(update_fields=["provider_status", "metadata", "modified"])
            return bool(database) and self.provider_status.lower() not in {
                "failed", "error", "deleted"
            }
        except Exception as error:
            capture_exception(error)
            return False

    def refresh_metadata(self):
        from apps.console.vultr_database import safe_vultr_database_record

        database = self.client.get_database(self.unique_id)
        usage = self.client.get_usage(self.unique_id)
        self.provider_status = str(database.get("status") or "")
        self.metadata = {
            "database": safe_vultr_database_record(database),
            "usage": safe_vultr_database_record(usage),
        }
        self.save(update_fields=["provider_status", "metadata", "modified"])
        return self.metadata

    def create_snapshot(self, backup):
        """Adopt the current provider-managed backup; never change its schedule."""
        from apps.console.backup.models import CoreVultrDatabaseBackup
        from apps.console.vultr_database import (
            VultrDatabaseDuplicateError,
            VultrDatabaseError,
            provider_backup_id,
            provider_backup_state,
            safe_vultr_database_message,
            safe_vultr_database_record,
        )

        self.capabilities().require_backup_support()
        records = self.client.list_backup_records(self.unique_id)
        if not records:
            raise VultrDatabaseError(
                None,
                category="not_found",
            )
        record = records[0]
        provider_id = provider_backup_id(record)
        if not provider_id:
            raise VultrDatabaseError(None, category="malformed_response")
        marker = f"vultr-db:{self.unique_id}:{provider_id}"
        existing = CoreVultrDatabaseBackup.objects.filter(
            vultr_database=self, provider_marker=marker
        ).exclude(pk=backup.pk)
        if existing.count() > 1:
            raise VultrDatabaseDuplicateError(
                f"Multiple BackupSheep records adopt Vultr backup marker {marker}."
            )
        if existing.exists():
            backup.provider_backup_id = existing.first().provider_backup_id

        backup.provider_backup_id = provider_id or None
        backup.provider_marker = marker
        backup.unique_id = provider_id or marker
        backup.provider_state = provider_backup_state(record)
        backup.metadata = {
            "source_database_id": self.unique_id,
            "engine": self.engine,
            "region": self.region,
            "plan": self.plan,
            "provider_backup": safe_vultr_database_record(record),
        }
        backup.save()

    def restore_snapshot(self, backup, restore):
        """Fork to a new cluster with durable, single-create reconciliation.

        The provider has no idempotency key for this operation.  A unique label
        is persisted before the fork request, and ``create_unknown`` is persisted
        before the request itself.  Once the outcome is unknown, later workers
        may adopt a matching provider cluster but are never allowed to issue a
        second fork request automatically.
        """
        from apps.console.vultr_database import (
            VultrDatabaseDuplicateError,
            VultrDatabaseError,
            provider_database_id,
            safe_vultr_database_message,
            safe_vultr_database_record,
        )
        from apps.console.backup.models import CoreVultrDatabaseRestore

        params = dict(restore.params or {})
        mode = str(params.get("type") or "basebackup").lower()
        self.capabilities().require_fork_support(mode)
        client = self.client
        should_fork = False
        body = None
        duplicate_error = None

        def matches(database, label, region, plan):
            if database.get("label") != label or not database.get("id"):
                return False
            # The label is the durable idempotency marker.  Check the requested
            # placement and plan whenever Vultr includes those fields, while
            # remaining compatible with older list responses that omit them.
            if not _vultr_same_region(database.get("region"), region):
                return False
            if database.get("plan") not in (None, "") and str(database["plan"]) != str(plan):
                return False
            for source_key in ("source_database_id", "database_id", "parent_id", "source_id"):
                source_value = database.get(source_key)
                if source_value not in (None, "") and str(source_value) != str(self.unique_id):
                    return False
            return True

        # Commit the marker and the pre-create state before any provider fork
        # request.  The row lock also serializes two Celery deliveries for the
        # same restore while their provider-side reconciliation is in flight.
        with transaction.atomic():
            locked = CoreVultrDatabaseRestore.objects.select_for_update().get(pk=restore.pk)
            if locked.resource_id:
                return

            params = dict(locked.params or {})
            mode = str(params.get("type") or "basebackup").lower()
            self.capabilities().require_fork_support(mode)
            label = locked.provider_marker or f"bs-restore-{locked.uuid.hex[:20]}"
            region = params.get("region") or self.region
            plan = params.get("plan") or self.plan
            params.update({"region": region, "plan": plan, "type": mode})
            locked.provider_marker = label
            locked.params = params
            locked.status = locked.Status.IN_PROGRESS

            candidates = [
                database for database in client.list_databases()
                if database.get("label") == label
            ]
            if len(candidates) > 1:
                duplicate_error = VultrDatabaseDuplicateError(
                    f"Multiple Vultr managed databases match restore marker {label}."
                )
                locked.provider_status = duplicate_error.category
                locked.status = locked.Status.FAILED
                locked.error = safe_vultr_database_message(duplicate_error.category)
                locked.save(
                    update_fields=[
                        "provider_marker", "params", "provider_status", "status", "error", "modified"
                    ]
                )
            elif candidates and not matches(candidates[0], label, region, plan):
                duplicate_error = VultrDatabaseDuplicateError(
                    f"Vultr managed database matched restore marker {label} but failed ownership checks."
                )
                locked.provider_status = duplicate_error.category
                locked.status = locked.Status.FAILED
                locked.error = safe_vultr_database_message(duplicate_error.category)
                locked.save(
                    update_fields=[
                        "provider_marker", "params", "provider_status", "status", "error", "modified"
                    ]
                )
            elif candidates:
                locked.resource_id = str(candidates[0]["id"])
                locked.provider_status = "adopted"
                locked.metadata = {
                    "adopted_database": safe_vultr_database_record(candidates[0])
                }
                locked.save(
                    update_fields=[
                        "provider_marker", "params", "resource_id", "provider_status", "metadata",
                        "status", "modified",
                    ]
                )
            elif locked.provider_status in {"create_unknown", "in_progress"} or locked.provider_job_id:
                # A prior fork may have been accepted but is not list-visible
                # yet.  Reconcile again later; never issue another fork request.
                locked.provider_status = "create_unknown"
                locked.save(
                    update_fields=["provider_marker", "params", "provider_status", "status", "modified"]
                )
            else:
                locked.provider_status = "create_unknown"
                locked.save(
                    update_fields=["provider_marker", "params", "provider_status", "status", "modified"]
                )
                body = {
                    "label": label,
                    "region": region,
                    "plan": plan,
                    "type": mode,
                }
                if mode == "pitr":
                    if params.get("date"):
                        body["date"] = params["date"]
                    if params.get("time"):
                        body["time"] = params["time"]
                should_fork = True

        if duplicate_error:
            raise duplicate_error
        if not should_fork:
            return

        try:
            payload = client.fork_database(self.unique_id, body)
            resource_id = provider_database_id(payload)
            provider_job_id = payload.get("job_id") or payload.get("operation_id")
            if not resource_id and not provider_job_id:
                raise VultrDatabaseError(
                    "Vultr fork response did not include a database or job identifier.",
                    category="transient_outage",
                )
        except VultrDatabaseError as error:
            with transaction.atomic():
                locked = CoreVultrDatabaseRestore.objects.select_for_update().get(pk=restore.pk)
                unknown_outcome = bool(getattr(error, "unknown_outcome", False)) or error.category in {
                    "timeout", "transient_outage"
                }
                locked.provider_status = "create_unknown" if unknown_outcome else error.category
                locked.provider_http_status = error.status_code
                locked.error = safe_vultr_database_message(
                    error.category, error.status_code
                )
                locked.status = (
                    locked.Status.IN_PROGRESS
                    if error.category in {"rate_limited", "timeout", "transient_outage"}
                    else locked.Status.FAILED
                )
                locked.save(
                    update_fields=[
                        "provider_status", "provider_http_status", "error", "status", "modified"
                    ]
                )
            raise

        with transaction.atomic():
            locked = CoreVultrDatabaseRestore.objects.select_for_update().get(pk=restore.pk)
            if not locked.resource_id:
                locked.resource_id = resource_id
                locked.provider_job_id = provider_job_id
                locked.provider_status = "in_progress"
                locked.metadata = safe_vultr_database_record(payload)
                locked.status = locked.Status.IN_PROGRESS
                locked.save(
                    update_fields=[
                        "resource_id", "provider_job_id", "provider_status", "metadata", "status", "modified"
                    ]
                )

    def check_restore(self, restore):
        from apps.console.vultr_database import (
            VultrDatabaseError,
            safe_vultr_database_record,
        )

        try:
            if not restore.resource_id:
                return restore.Status.IN_PROGRESS
            database = self.client.get_database(restore.resource_id)
            if not isinstance(database, dict) or not database.get("id"):
                raise VultrDatabaseError(None, category="malformed_response")
            state = str(database.get("status") or "").lower()
            if not state:
                raise VultrDatabaseError(None, category="malformed_response")
            params = restore.params or {}
            if restore.provider_marker and database.get("label") != restore.provider_marker:
                restore.provider_status = "ownership_mismatch"
                restore.error = "Vultr managed database restore target failed ownership verification."
                restore.status = restore.Status.FAILED
                restore.save(update_fields=["provider_status", "error", "status", "modified"])
                return restore.status
            for field in ("region", "plan"):
                expected = params.get(field)
                actual = database.get(field)
                if (
                    expected
                    and actual not in (None, "")
                    and (
                        str(actual).casefold() != str(expected).casefold()
                        if field == "region"
                        else str(actual) != str(expected)
                    )
                ):
                    restore.provider_status = "ownership_mismatch"
                    restore.error = "Vultr managed database restore target failed ownership verification."
                    restore.status = restore.Status.FAILED
                    restore.save(update_fields=["provider_status", "error", "status", "modified"])
                    return restore.status
            restore.metadata = safe_vultr_database_record(database)
            restore.provider_status = state
            if state in {"running", "active", "available"}:
                restore.status = restore.Status.COMPLETE
            elif state in {"failed", "error", "deleted", "destroyed"}:
                restore.status = restore.Status.FAILED
            else:
                restore.status = restore.Status.IN_PROGRESS
            restore.save()
            return restore.status
        except VultrDatabaseError as error:
            restore.provider_status = error.category
            restore.provider_http_status = error.status_code
            restore.metadata = {"error": error.category, "status_code": error.status_code}
            if error.category in {"rate_limited", "timeout", "transient_outage"}:
                restore.status = restore.Status.IN_PROGRESS
            else:
                restore.status = restore.Status.FAILED
            restore.error = _vultr_safe_message(
                {
                    "auth_failed": "PROVIDER_AUTH_FAILED",
                    "not_found": "PROVIDER_NOT_FOUND",
                    "rate_limited": "PROVIDER_RATE_LIMIT",
                    "timeout": "PROVIDER_TIMEOUT",
                    "transient_outage": "PROVIDER_TRANSIENT_OUTAGE",
                    "malformed_response": "PROVIDER_MALFORMED_RESPONSE",
                }.get(error.category, "PROVIDER_REQUEST_FAILED")
            )
            restore.save(update_fields=["provider_status", "provider_http_status", "metadata", "error", "status", "modified"])
            return restore.status


class CoreVultr(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="vultr", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_vultr.get_client()
            if self.node.type == CoreNode.Type.CLOUD:
                result = requests.get(
                    f"{settings.VULTR_API}/v2/instances/{self.unique_id}",
                    headers=client,
                    verify=True,
                    timeout=vultr_request_timeout(),
                )
                try:
                    if result.status_code == 200:
                        payload = result.json()
                        instance = payload.get("instance") if isinstance(payload, dict) else None
                        node_ok = isinstance(instance, dict) and instance.get("status") == "active"
                finally:
                    result.close()
            elif self.node.type == CoreNode.Type.VOLUME:
                result = requests.get(
                    f"{settings.VULTR_API}/v2/blocks/{self.unique_id}",
                    headers=client,
                    verify=True,
                    timeout=vultr_request_timeout(),
                )
                try:
                    if result.status_code == 200:
                        payload = result.json()
                        block = payload.get("block") if isinstance(payload, dict) else None
                        node_ok = isinstance(block, dict) and block.get("status") == "active"
                finally:
                    result.close()
        except Exception as error:
            capture_exception(error)
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_vultr.get_client()
        except Exception as error:
            capture_exception(error)
            _raise_vultr_backup_failure(
                self.node, backup, "PROVIDER_AUTH_FAILED", cause=error
            )
        source_key = "instance_id" if self.node.type == CoreNode.Type.CLOUD else "block_id"
        backup.metadata = record_snapshot_ownership(
            backup.metadata,
            source_id=self.unique_id,
            source_key=source_key,
        )
        # Commit the source identity before the provider mutation.  If the
        # worker dies after Vultr accepts the request, the next delivery can
        # safely adopt a completed snapshot whose response omits instance_id.
        backup.save(update_fields=["metadata", "modified"])

        def existing_snapshot(path, source_key):
            try:
                snapshots = list(iter_vultr_collection(
                    requests.get,
                    f"{settings.VULTR_API}{path}",
                    headers=client,
                    item_key="snapshots",
                    verify=True,
                ))
            except NodeBackupFailedError:
                raise
            except Exception as error:
                capture_exception(error)
                _raise_vultr_backup_failure(
                    self.node, backup, "PROVIDER_TRANSIENT_OUTAGE", cause=error
                )

            described = [
                snapshot for snapshot in snapshots
                if snapshot.get("description") == backup.uuid_str
            ]
            ownership = (backup.metadata or {}).get("vultr_ownership")
            if any(
                not snapshot_matches_with_recorded_source(
                    snapshot,
                    provider_id=snapshot.get("id"),
                    source_id=self.unique_id,
                    description=backup.uuid_str,
                    source_key=source_key,
                    ownership=ownership,
                )
                for snapshot in described
            ):
                _raise_vultr_backup_failure(
                    self.node, backup, "PROVIDER_OWNERSHIP_MISMATCH"
                )
            if len(described) > 1:
                _raise_vultr_backup_failure(
                    self.node, backup, "PROVIDER_DUPLICATE_MATCH"
                )
            return described[0] if described else None

        def create_snapshot_request(path, request_body, response_key, source_key):
            try:
                existing = existing_snapshot(path, source_key)
                if existing:
                    if not snapshot_matches_with_recorded_source(
                        existing,
                        provider_id=existing.get("id"),
                        source_id=self.unique_id,
                        description=backup.uuid_str,
                        source_key=source_key,
                        ownership=(backup.metadata or {}).get("vultr_ownership"),
                    ):
                        _raise_vultr_backup_failure(
                            self.node, backup, "PROVIDER_OWNERSHIP_MISMATCH"
                        )
                    backup.unique_id = existing.get("id")
                    backup.metadata = record_snapshot_ownership(
                        _safe_vultr_record(existing),
                        source_id=self.unique_id,
                        source_key=source_key,
                    )
                    if source_key == "block_id":
                        backup.size_gigabytes = round(
                            int(existing.get("size", 0)) / (1000 ** 3), 2
                        )
                    backup.save()
                    return

                # A timeout, transport failure, 5xx, or malformed success
                # response may mean Vultr accepted the mutation. Reconcile the
                # deterministic description first; never issue a second POST
                # while this fence is set.
                if (backup.metadata or {}).get("vultr_create_outcome_unknown"):
                    _raise_vultr_backup_failure(
                        self.node, backup, "PROVIDER_RECONCILIATION_REQUIRED"
                    )

                try:
                    result = requests.post(
                        f"{settings.VULTR_API}{path}",
                        headers=client,
                        json=request_body,
                        verify=True,
                        timeout=vultr_request_timeout(),
                    )
                except requests.Timeout as error:
                    capture_exception(error)
                    backup.metadata = {
                        **(backup.metadata or {}),
                        "vultr_create_outcome_unknown": True,
                    }
                    backup.save(update_fields=["metadata", "modified"])
                    _raise_vultr_backup_failure(
                        self.node, backup, "PROVIDER_TIMEOUT", cause=error
                    )
                except requests.RequestException as error:
                    capture_exception(error)
                    backup.metadata = {
                        **(backup.metadata or {}),
                        "vultr_create_outcome_unknown": True,
                    }
                    backup.save(update_fields=["metadata", "modified"])
                    _raise_vultr_backup_failure(
                        self.node, backup, "PROVIDER_TRANSIENT_OUTAGE", cause=error
                    )

                try:
                    status_code = int(result.status_code)
                    if status_code == 201:
                        try:
                            payload = result.json()
                            snapshot = payload.get(response_key) if response_key else payload
                            if not isinstance(snapshot, dict) or not snapshot.get("id"):
                                raise ValueError("missing snapshot id")
                        except (TypeError, ValueError, KeyError) as error:
                            capture_exception(error)
                            backup.metadata = {
                                **(backup.metadata or {}),
                                "vultr_create_outcome_unknown": True,
                            }
                            backup.save(update_fields=["metadata", "modified"])
                            _raise_vultr_backup_failure(
                                self.node, backup, "PROVIDER_MALFORMED_RESPONSE", cause=error
                            )
                        backup.unique_id = str(snapshot["id"])
                        backup.metadata = record_snapshot_ownership(
                            _safe_vultr_record(snapshot),
                            source_id=self.unique_id,
                            source_key=source_key,
                        )
                        backup.save()
                        return

                    if status_code in (401, 403):
                        code = "PROVIDER_AUTH_FAILED"
                    elif status_code == 404:
                        code = "PROVIDER_NOT_FOUND"
                    elif status_code == 429:
                        code = "PROVIDER_RATE_LIMIT"
                    elif status_code in (408, 425) or status_code >= 500:
                        code = "PROVIDER_TRANSIENT_OUTAGE"
                    else:
                        code = "PROVIDER_REQUEST_FAILED"
                    if code == "PROVIDER_TRANSIENT_OUTAGE":
                        backup.metadata = {
                            **(backup.metadata or {}),
                            "vultr_create_outcome_unknown": True,
                        }
                        backup.save(update_fields=["metadata", "modified"])
                    _raise_vultr_backup_failure(self.node, backup, code)
                finally:
                    close = getattr(result, "close", None)
                    if close:
                        close()
            except NodeBackupFailedError:
                raise
            except Exception as error:
                capture_exception(error)
                _raise_vultr_backup_failure(
                    self.node, backup, "PROVIDER_REQUEST_FAILED", cause=error
                )

        try:
            if self.node.type == CoreNode.Type.CLOUD:
                return create_snapshot_request(
                    "/v2/snapshots",
                    {"instance_id": self.unique_id, "description": backup.uuid_str},
                    "snapshot",
                    "instance_id",
                )
            if self.node.type == CoreNode.Type.VOLUME:
                return create_snapshot_request(
                    "/v2/blocks/snapshots",
                    {"block_id": self.unique_id, "description": backup.uuid_str},
                    None,
                    "block_id",
                )
        except NodeBackupFailedError:
            raise

    def restore_snapshot(self, backup, restore):
        """Adopt or create a new Vultr restore target exactly once.

        Vultr does not expose an idempotency key for these create endpoints.
        The restore marker is therefore committed before the POST and the
        restore row is locked while the provider-side reconciliation/create
        decision is made.  If the worker dies after Vultr accepts the POST,
        the next delivery finds the marker and adopts the one matching target.
        """
        import hashlib

        from apps.console.backup.models import CoreCloudRestore

        try:
            client = self.node.connection.auth_vultr.get_client()
        except Exception as error:
            capture_exception(error)
            _restore_safe_failure(restore, "PROVIDER_AUTH_FAILED")
            raise _RestoreProviderError("PROVIDER_AUTH_FAILED") from error
        timeout = vultr_request_timeout()
        params = restore.params or {}
        source_snapshot_id = str(backup.unique_id)

        def _copy_restore_state(source):
            restore.resource_id = source.resource_id
            restore.restore_marker = source.restore_marker
            restore.request_fingerprint = source.request_fingerprint
            restore.operation_phase = source.operation_phase
            restore.status = source.status
            restore.error = source.error

        def _save_failure(message, phase=CoreCloudRestore.OperationPhase.FAILED):
            restore.status = CoreCloudRestore.Status.FAILED
            restore.operation_phase = phase
            restore.error = message
            restore.save(update_fields=["status", "operation_phase", "error", "modified"])

        def _provider_error(status_code, operation, *, mutation=False):
            classified = _restore_http_class(
                SimpleNamespace(status_code=status_code), mutation=mutation
            )
            if classified is None:
                return None, None, None, False
            return (
                _restore_message(classified.code),
                "transient" if classified.retryable else "terminal",
                classified.code,
                classified.unknown_outcome,
            )

        def _json_payload(response, operation):
            try:
                payload = response.json()
            except (TypeError, ValueError) as error:
                capture_exception(error)
                return None, _restore_message("PROVIDER_MALFORMED_RESPONSE")
            if not isinstance(payload, dict):
                return None, _restore_message("PROVIDER_MALFORMED_RESPONSE")
            return payload, None

        def _source_details():
            if self.node.type == CoreNode.Type.CLOUD:
                region = params.get("region")
                plan = params.get("plan")
                path = f"/v2/instances/{self.unique_id}"
                resource_key = "instance"
            else:
                region = params.get("region")
                plan = params.get("size_gb")
                path = f"/v2/blocks/{self.unique_id}"
                resource_key = "block"

            if region and plan:
                return region, plan, None

            try:
                response = requests.get(
                    f"{settings.VULTR_API}{path}",
                    headers=client,
                    verify=True,
                    timeout=timeout,
                )
            except requests.Timeout as error:
                capture_exception(error)
                return None, None, (
                    _restore_message("PROVIDER_TIMEOUT"), "transient", "PROVIDER_TIMEOUT"
                )
            except requests.RequestException as error:
                capture_exception(error)
                return None, None, (
                    _restore_message("PROVIDER_TRANSIENT_OUTAGE"),
                    "transient",
                    "PROVIDER_TRANSIENT_OUTAGE",
                )

            try:
                if response.status_code != 200:
                    message, kind, code, _unknown = _provider_error(
                        response.status_code, "reading the source resource"
                    )
                    return None, None, (message, kind, code)
                payload, malformed = _json_payload(response, "reading the source resource")
                source = payload.get(resource_key) if payload else None
                if malformed or not isinstance(source, dict):
                    return None, None, (
                        malformed or _restore_message("PROVIDER_MALFORMED_RESPONSE"),
                        "terminal",
                        "PROVIDER_MALFORMED_RESPONSE",
                    )
                region = region or source.get("region")
                plan = plan or source.get("plan") or source.get("size_gb")
                if not region or not plan:
                    return None, None, (
                        _restore_message("PROVIDER_MALFORMED_RESPONSE"),
                        "terminal",
                        "PROVIDER_MALFORMED_RESPONSE",
                    )
                return region, plan, None
            finally:
                close = getattr(response, "close", None)
                if close:
                    close()

        region, target_size, source_error = _source_details()
        if source_error:
            message, kind, code = source_error
            if kind == "transient":
                _record_restore_retryable_error(restore, code)
                restore.operation_phase = CoreCloudRestore.OperationPhase.RECONCILING
                restore.save(update_fields=["operation_phase", "modified"])
                return CoreCloudRestore.Status.IN_PROGRESS
            _restore_safe_failure(restore, code or "PROVIDER_REQUEST_FAILED")
            raise _RestoreProviderError(code or "PROVIDER_REQUEST_FAILED")

        fingerprint_data = {
            "provider": "vultr",
            "node_type": self.node.type,
            "source_snapshot_id": source_snapshot_id,
            "region": str(region),
            "target": str(target_size),
        }
        request_fingerprint = hashlib.sha256(
            json.dumps(fingerprint_data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        marker = f"backupsheep-restore-{restore.id}-{request_fingerprint[:16]}"

        # Commit the marker independently of the provider request.  This is the
        # durable evidence used after a worker crash or lost HTTP response.
        with transaction.atomic():
            locked = CoreCloudRestore.objects.select_for_update().get(pk=restore.pk)
            if locked.resource_id:
                _copy_restore_state(locked)
                return None
            if locked.request_fingerprint and locked.request_fingerprint != request_fingerprint:
                message = "Restore request parameters changed after the operation was planned; manual review required."
                locked.status = CoreCloudRestore.Status.FAILED
                locked.operation_phase = CoreCloudRestore.OperationPhase.MANUAL_REVIEW
                locked.error = message
                locked.save(update_fields=["status", "operation_phase", "error", "modified"])
                raise Exception(message)
            locked.restore_marker = locked.restore_marker or marker
            locked.request_fingerprint = locked.request_fingerprint or request_fingerprint
            resolved_params = dict(locked.params or {})
            resolved_params["region"] = region
            if self.node.type == CoreNode.Type.CLOUD:
                resolved_params["plan"] = target_size
            else:
                resolved_params["size_gb"] = target_size
            locked.params = resolved_params
            if locked.operation_phase != CoreCloudRestore.OperationPhase.CREATE_UNKNOWN:
                locked.operation_phase = CoreCloudRestore.OperationPhase.RECONCILING
            locked.status = CoreCloudRestore.Status.IN_PROGRESS
            locked.save(
                update_fields=[
                    "restore_marker",
                    "request_fingerprint",
                    "params",
                    "operation_phase",
                    "status",
                    "modified",
                ]
            )
            _copy_restore_state(locked)

        marker = restore.restore_marker or marker

        def _list_candidates(path, key):
            url = f"{settings.VULTR_API}{path}"
            request_params = {"per_page": 500}
            cursor = None
            items = []
            seen_cursors = set()
            while True:
                try:
                    response = requests.get(
                        url,
                        headers=client,
                        params=request_params,
                        verify=True,
                        timeout=timeout,
                    )
                except requests.Timeout as error:
                    capture_exception(error)
                    return None, _restore_message("PROVIDER_TIMEOUT"), "transient", "PROVIDER_TIMEOUT"
                except requests.RequestException as error:
                    capture_exception(error)
                    return None, _restore_message("PROVIDER_TRANSIENT_OUTAGE"), "transient", "PROVIDER_TRANSIENT_OUTAGE"
                try:
                    if response.status_code != 200:
                        message, kind, code, _unknown = _provider_error(
                            response.status_code, "reconciling the restore"
                        )
                        return None, message, kind, code
                    payload, malformed = _json_payload(response, "reconciling the restore")
                    if malformed:
                        return None, malformed, "terminal", "PROVIDER_MALFORMED_RESPONSE"
                    page_items = payload.get(key)
                    if not isinstance(page_items, list) or any(
                        not isinstance(item, dict) for item in page_items
                    ):
                        return None, _restore_message("PROVIDER_MALFORMED_RESPONSE"), "terminal", "PROVIDER_MALFORMED_RESPONSE"
                    items.extend(page_items)
                    links = (payload.get("meta") or {}).get("links") or {}
                    if not isinstance(links, dict):
                        return None, _restore_message("PROVIDER_MALFORMED_RESPONSE"), "terminal", "PROVIDER_MALFORMED_RESPONSE"
                    next_cursor = links.get("next")
                    if next_cursor in (None, ""):
                        return items, None, None, None
                    if not isinstance(next_cursor, str) or not next_cursor.strip():
                        return None, _restore_message("PROVIDER_MALFORMED_RESPONSE"), "terminal", "PROVIDER_MALFORMED_RESPONSE"
                    if next_cursor in seen_cursors:
                        return None, _restore_message("PROVIDER_MALFORMED_RESPONSE"), "terminal", "PROVIDER_MALFORMED_RESPONSE"
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
                    request_params = {"per_page": 500, "cursor": cursor}
                finally:
                    close = getattr(response, "close", None)
                    if close:
                        close()

        def _matches(resource):
            if self.node.type == CoreNode.Type.CLOUD:
                tags = resource.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                return (
                    marker in tags
                    and str(resource.get("snapshot_id")) == source_snapshot_id
                    and _vultr_same_region(resource.get("region"), region)
                    and resource.get("plan") == target_size
                )
            return (
                resource.get("label") == marker
                and str(resource.get("snapshot_id")) == source_snapshot_id
                and _vultr_same_region(resource.get("region"), region)
                and str(resource.get("size_gb")) == str(target_size)
            )

        def _has_marker(resource):
            if self.node.type == CoreNode.Type.CLOUD:
                tags = resource.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                return marker in tags
            return resource.get("label") == marker

        failure = None
        failure_code = None
        transient = None
        transient_code = None
        create_request = None

        # Reconcile while holding the restore-row lock.  If no target exists,
        # commit CREATE_UNKNOWN before the external create request so a second
        # worker can reconcile but cannot issue a duplicate POST while the first
        # request is still in flight or its response is being persisted.
        with transaction.atomic():
            locked = CoreCloudRestore.objects.select_for_update().get(pk=restore.pk)
            if locked.resource_id:
                _copy_restore_state(locked)
                return None
            marker = locked.restore_marker
            if self.node.type == CoreNode.Type.CLOUD:
                candidates, message, kind, code = _list_candidates("/v2/instances", "instances")
            else:
                candidates, message, kind, code = _list_candidates("/v2/blocks", "blocks")
            if message:
                if kind == "transient":
                    transient = message
                    transient_code = code or "PROVIDER_TRANSIENT_OUTAGE"
                else:
                    failure = message
                    failure_code = code or "PROVIDER_REQUEST_FAILED"
            else:
                marked_candidates = [resource for resource in candidates if _has_marker(resource)]
                matches = [resource for resource in candidates if _matches(resource)]
                if marked_candidates and len(marked_candidates) != 1:
                    failure = _restore_message("PROVIDER_DUPLICATE_MATCH")
                    failure_code = "PROVIDER_DUPLICATE_MATCH"
                    locked.operation_phase = CoreCloudRestore.OperationPhase.MANUAL_REVIEW
                elif marked_candidates and not matches:
                    failure = _restore_message("PROVIDER_OWNERSHIP_MISMATCH")
                    failure_code = "PROVIDER_OWNERSHIP_MISMATCH"
                    locked.operation_phase = CoreCloudRestore.OperationPhase.MANUAL_REVIEW
                elif len(matches) > 1:
                    failure = _restore_message("PROVIDER_DUPLICATE_MATCH")
                    failure_code = "PROVIDER_DUPLICATE_MATCH"
                    locked.operation_phase = CoreCloudRestore.OperationPhase.MANUAL_REVIEW
                elif len(matches) == 1:
                    adopted = matches[0]
                    resource_id = adopted.get("id")
                    if not resource_id:
                        failure = _restore_message("PROVIDER_MALFORMED_RESPONSE")
                        failure_code = "PROVIDER_MALFORMED_RESPONSE"
                    else:
                        locked.resource_id = str(resource_id)
                        locked.status = CoreCloudRestore.Status.IN_PROGRESS
                        locked.operation_phase = CoreCloudRestore.OperationPhase.POLLING
                        locked.error = ""
                        locked.save(
                            update_fields=[
                                "resource_id", "status", "operation_phase", "error", "modified"
                            ]
                        )
                        _copy_restore_state(locked)
                elif locked.operation_phase == CoreCloudRestore.OperationPhase.CREATE_UNKNOWN:
                    code = "PROVIDER_RECONCILIATION_REQUIRED"
                    transient = _restore_message(code)
                    locked.status = CoreCloudRestore.Status.IN_PROGRESS
                    locked.error = transient
                    params_state = _restore_params(locked)
                    params_state["_bs_last_error_code"] = code
                    params_state["_bs_last_error_category"] = "unknown_outcome"
                    locked.params = params_state
                    locked.save(update_fields=["params", "status", "error", "modified"])
                else:
                    if self.node.type == CoreNode.Type.CLOUD:
                        create_payload = {
                            "region": region,
                            "plan": target_size,
                            "snapshot_id": backup.unique_id,
                            "label": restore.name,
                            "hostname": restore.name,
                            "tags": [marker],
                        }
                        endpoint = f"{settings.VULTR_API}/v2/instances"
                    else:
                        create_payload = {
                            "region": region,
                            "size_gb": target_size,
                            "snapshot_id": backup.unique_id,
                            "label": marker,
                        }
                        endpoint = f"{settings.VULTR_API}/v2/blocks"
                    locked.status = CoreCloudRestore.Status.IN_PROGRESS
                    locked.operation_phase = CoreCloudRestore.OperationPhase.CREATE_UNKNOWN
                    locked.error = _restore_message("PROVIDER_UNKNOWN_OUTCOME")
                    locked.save(update_fields=["status", "operation_phase", "error", "modified"])
                    create_request = (endpoint, create_payload)

            if failure:
                locked.status = CoreCloudRestore.Status.FAILED
                if locked.operation_phase != CoreCloudRestore.OperationPhase.MANUAL_REVIEW:
                    locked.operation_phase = CoreCloudRestore.OperationPhase.FAILED
                locked.error = failure
                locked.save(update_fields=["status", "operation_phase", "error", "modified"])
                _copy_restore_state(locked)
            elif transient:
                locked.status = CoreCloudRestore.Status.IN_PROGRESS
                if locked.operation_phase == CoreCloudRestore.OperationPhase.PENDING:
                    locked.operation_phase = CoreCloudRestore.OperationPhase.RECONCILING
                locked.error = transient
                params_state = _restore_params(locked)
                params_state["_bs_last_error_code"] = transient_code or "PROVIDER_TRANSIENT_OUTAGE"
                params_state["_bs_last_error_category"] = "retryable"
                locked.params = params_state
                locked.save(update_fields=["params", "status", "operation_phase", "error", "modified"])
                _copy_restore_state(locked)

        if failure:
            _restore_safe_failure(
                restore,
                failure_code or "PROVIDER_REQUEST_FAILED",
                manual_review=failure_code
                in {"PROVIDER_DUPLICATE_MATCH", "PROVIDER_OWNERSHIP_MISMATCH"},
            )
            raise _RestoreProviderError(failure_code or "PROVIDER_REQUEST_FAILED")
        if transient:
            return CoreCloudRestore.Status.IN_PROGRESS
        if not create_request:
            return None

        endpoint, create_payload = create_request
        try:
            response = requests.post(
                endpoint,
                headers=client,
                json=create_payload,
                verify=True,
                timeout=timeout,
            )
        except requests.Timeout as error:
            capture_exception(error)
            _restore_unknown_outcome(restore, code="PROVIDER_TIMEOUT")
            return CoreCloudRestore.Status.IN_PROGRESS
        except requests.RequestException as error:
            capture_exception(error)
            _restore_unknown_outcome(restore, code="PROVIDER_TRANSIENT_OUTAGE")
            return CoreCloudRestore.Status.IN_PROGRESS
        except Exception as error:
            capture_exception(error)
            _restore_unknown_outcome(restore, code="PROVIDER_TRANSIENT_OUTAGE")
            return CoreCloudRestore.Status.IN_PROGRESS

        try:
            if response.status_code in (201, 202):
                key = "instance" if self.node.type == CoreNode.Type.CLOUD else "block"
                response_payload, malformed = _json_payload(response, "creating the restore")
                created = response_payload.get(key) if response_payload else None
                if malformed or not isinstance(created, dict) or not created.get("id"):
                    _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                    return CoreCloudRestore.Status.IN_PROGRESS
                else:
                    with transaction.atomic():
                        locked = CoreCloudRestore.objects.select_for_update().get(pk=restore.pk)
                        if not locked.resource_id:
                            locked.resource_id = str(created["id"])
                            locked.status = CoreCloudRestore.Status.IN_PROGRESS
                            locked.operation_phase = CoreCloudRestore.OperationPhase.POLLING
                            locked.error = ""
                            params_state = _restore_params(locked)
                            params_state["_bs_create_outcome_unknown"] = False
                            params_state["_bs_last_error_code"] = ""
                            params_state["_bs_last_error_category"] = ""
                            locked.params = params_state
                            locked.save(
                                update_fields=[
                                    "resource_id", "params", "status", "operation_phase", "error", "modified"
                                ]
                            )
                    return None
            else:
                provider_message, provider_kind, provider_code, unknown_outcome = _provider_error(
                    response.status_code, "creating the restore", mutation=True
                )
                if provider_kind == "transient":
                    if unknown_outcome:
                        _restore_unknown_outcome(restore, code=provider_code)
                    else:
                        _record_restore_retryable_error(restore, provider_code)
                    return CoreCloudRestore.Status.IN_PROGRESS
                else:
                    _restore_safe_failure(restore, provider_code or "PROVIDER_REQUEST_FAILED")
                    raise _RestoreProviderError(provider_code or "PROVIDER_REQUEST_FAILED")
        finally:
            close = getattr(response, "close", None)
            if close:
                close()

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        try:
            client = self.node.connection.auth_vultr.get_client()
        except Exception as error:
            capture_exception(error)
            _restore_safe_failure(restore, "PROVIDER_AUTH_FAILED")
            return CoreCloudRestore.Status.FAILED
        timeout = vultr_request_timeout()

        def record(code, phase=None):
            if phase is not None:
                restore.operation_phase = phase
                if phase in {
                    CoreCloudRestore.OperationPhase.FAILED,
                    CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
                }:
                    restore.status = CoreCloudRestore.Status.FAILED
                else:
                    restore.status = CoreCloudRestore.Status.IN_PROGRESS
            params = _restore_params(restore)
            params["_bs_last_error_code"] = str(code)
            params["_bs_last_error_category"] = (
                "retryable"
                if str(code) in {"PROVIDER_RATE_LIMIT", "PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_OUTAGE"}
                else "terminal"
            )
            restore.params = params
            restore.error = _restore_message(code)
            fields = ["params", "status", "operation_phase", "error", "modified"]
            if hasattr(restore, "last_error_code"):
                restore.last_error_code = str(code)
                fields.append("last_error_code")
            restore.save(update_fields=list(dict.fromkeys(fields)))

        if not restore.resource_id:
            record("PROVIDER_RECONCILIATION_REQUIRED", CoreCloudRestore.OperationPhase.RECONCILING)
            return CoreCloudRestore.Status.IN_PROGRESS

        if self.node.type == CoreNode.Type.CLOUD:
            endpoint = f"{settings.VULTR_API}/v2/instances/{restore.resource_id}"
            key = "instance"
        else:
            endpoint = f"{settings.VULTR_API}/v2/blocks/{restore.resource_id}"
            key = "block"

        try:
            result = requests.get(
                endpoint,
                headers=client,
                verify=True,
                timeout=timeout,
            )
        except requests.Timeout as error:
            capture_exception(error)
            record("PROVIDER_TIMEOUT", CoreCloudRestore.OperationPhase.POLLING)
            return CoreCloudRestore.Status.IN_PROGRESS
        except requests.RequestException as error:
            capture_exception(error)
            record("PROVIDER_TRANSIENT_OUTAGE", CoreCloudRestore.OperationPhase.POLLING)
            return CoreCloudRestore.Status.IN_PROGRESS

        try:
            if result.status_code == 429:
                record("PROVIDER_RATE_LIMIT", CoreCloudRestore.OperationPhase.POLLING)
                return CoreCloudRestore.Status.IN_PROGRESS
            if result.status_code in (408, 425) or result.status_code >= 500:
                record("PROVIDER_TRANSIENT_OUTAGE", CoreCloudRestore.OperationPhase.POLLING)
                return CoreCloudRestore.Status.IN_PROGRESS
            if result.status_code in (401, 403):
                record("PROVIDER_AUTH_FAILED", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED
            if result.status_code == 404:
                record("PROVIDER_NOT_FOUND", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED
            if result.status_code != 200:
                record("PROVIDER_REQUEST_FAILED", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED

            try:
                payload = result.json()
                resource = payload.get(key)
            except (TypeError, ValueError, AttributeError) as error:
                capture_exception(error)
                record("PROVIDER_MALFORMED_RESPONSE", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED
            if not isinstance(resource, dict) or not resource.get("status"):
                record("PROVIDER_MALFORMED_RESPONSE", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED

            # New restores must prove ownership on every status read. Legacy
            # rows without a marker remain pollable so existing restores are
            # not stranded.
            if restore.restore_marker:
                if self.node.type == CoreNode.Type.CLOUD:
                    tags = resource.get("tags") or []
                    if isinstance(tags, str):
                        tags = [tags]
                    owned = (
                        restore.restore_marker in tags
                        and str(resource.get("snapshot_id")) == str(restore.backup.unique_id)
                        and _vultr_same_region(
                            resource.get("region"),
                            (restore.params or {}).get("region", resource.get("region")),
                        )
                        and resource.get("plan") == (restore.params or {}).get("plan", resource.get("plan"))
                    )
                else:
                    params = restore.params or {}
                    owned = (
                        resource.get("label") == restore.restore_marker
                        and str(resource.get("snapshot_id")) == str(restore.backup.unique_id)
                        and _vultr_same_region(
                            resource.get("region"), params.get("region", resource.get("region"))
                        )
                        and str(resource.get("size_gb")) == str(params.get("size_gb", resource.get("size_gb")))
                    )
                if not owned:
                    record("PROVIDER_OWNERSHIP_MISMATCH", CoreCloudRestore.OperationPhase.MANUAL_REVIEW)
                    return CoreCloudRestore.Status.FAILED

            status = str(resource["status"]).lower()
            if status == "active":
                restore.status = CoreCloudRestore.Status.COMPLETE
                restore.operation_phase = CoreCloudRestore.OperationPhase.COMPLETE
                restore.error = ""
                restore.save(update_fields=["status", "operation_phase", "error", "modified"])
                return CoreCloudRestore.Status.COMPLETE
            if status in {"suspended", "failed", "error", "destroyed", "terminated"}:
                record("PROVIDER_FAILED", CoreCloudRestore.OperationPhase.FAILED)
                return CoreCloudRestore.Status.FAILED
            restore.operation_phase = CoreCloudRestore.OperationPhase.POLLING
            restore.status = CoreCloudRestore.Status.IN_PROGRESS
            restore.save(update_fields=["status", "operation_phase", "modified"])
            return CoreCloudRestore.Status.IN_PROGRESS
        finally:
            close = getattr(result, "close", None)
            if close:
                close()


class CoreOracle(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="oracle", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_oracle"

    def validate(self):
        import oci
        from oci.core.models import BootVolume, Volume

        node_ok = False

        if self.node.type == CoreNode.Type.VOLUME:
            config = self.node.connection.auth_oracle.get_client()
            block_storage_client = oci.core.BlockstorageClient(config)

            if (self.metadata or {}).get("_bs_vol_type") == "boot":
                request = block_storage_client.get_boot_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_AVAILABLE
                    ):
                        node_ok = True
            elif (self.metadata or {}).get("_bs_vol_type") == "block":
                request = block_storage_client.get_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == Volume.LIFECYCLE_STATE_AVAILABLE
                    ):
                        node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        import oci
        from oci.core.models import CreateBootVolumeBackupDetails, CreateVolumeBackupDetails

        if self.node.type == CoreNode.Type.VOLUME:
            try:
                config = self.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)

                def existing_backup(volume_type):
                    if volume_type == "boot":
                        source_volume = block_storage_client.get_boot_volume(self.unique_id).data
                        response = oci.pagination.list_call_get_all_results(
                            block_storage_client.list_boot_volume_backups,
                            compartment_id=source_volume.compartment_id,
                            boot_volume_id=self.unique_id,
                            display_name=backup.uuid_str,
                        )
                    else:
                        source_volume = block_storage_client.get_volume(self.unique_id).data
                        response = oci.pagination.list_call_get_all_results(
                            block_storage_client.list_volume_backups,
                            compartment_id=source_volume.compartment_id,
                            volume_id=self.unique_id,
                            display_name=backup.uuid_str,
                        )
                    return next(iter(response.data or []), None)

                def record_existing(existing):
                    backup.unique_id = existing.id
                    backup.size_gigabytes = getattr(
                        existing,
                        "size_in_gbs",
                        getattr(existing, "size_in_gigabytes", None),
                    )
                    backup.metadata = {
                        "display_name": existing.display_name,
                        "lifecycle_state": existing.lifecycle_state,
                        "id": existing.id,
                    }
                    backup.save()

                if (self.metadata or {}).get("_bs_vol_type") == "boot":
                    existing = existing_backup("boot")
                    if existing:
                        record_existing(existing)
                        return
                    boot_volume_backup_details = CreateBootVolumeBackupDetails(
                        boot_volume_id=self.unique_id,
                        display_name=backup.uuid_str,
                        freeform_tags={"BACKUPSHEEP__UUID": backup.uuid_str},
                        type=CreateBootVolumeBackupDetails.TYPE_FULL,
                    )

                    request = block_storage_client.create_boot_volume_backup(
                        create_boot_volume_backup_details=boot_volume_backup_details, opc_retry_token=backup.uuid_str
                    )
                    if request.status in (200, 202):
                        backup.unique_id = request.data.id
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"API call returned with status {request.status}",
                        )
                elif (self.metadata or {}).get("_bs_vol_type") == "block":
                    existing = existing_backup("block")
                    if existing:
                        record_existing(existing)
                        return
                    volume_backup_details = CreateVolumeBackupDetails(
                        volume_id=self.unique_id,
                        display_name=backup.uuid_str,
                        freeform_tags={"BACKUPSHEEP__UUID": backup.uuid_str},
                        type=CreateVolumeBackupDetails.TYPE_FULL,
                    )

                    request = block_storage_client.create_volume_backup(
                        create_volume_backup_details=volume_backup_details, opc_retry_token=backup.uuid_str
                    )

                    if request.status in (200, 202):
                        backup.unique_id = request.data.id
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"API call returned with status {request.status}",
                        )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )

    @staticmethod
    def _oracle_resource_dict(resource):
        if isinstance(resource, dict):
            return resource
        return {
            "id": getattr(resource, "id", None),
            "display_name": getattr(resource, "display_name", None),
            "lifecycle_state": getattr(resource, "lifecycle_state", None),
            "freeform_tags": getattr(resource, "freeform_tags", None),
            "source_backup_id": getattr(resource, "source_backup_id", None),
        }

    def _find_oracle_restore_resource(self, client, restore, *, volume_type, compartment_id, availability_domain=None):
        method_name = "list_boot_volumes" if volume_type == "boot" else "list_volumes"
        method = getattr(client, method_name)
        resources = []
        page = None
        seen = set()
        while True:
            request = {"compartment_id": compartment_id, "display_name": restore.name}
            if availability_domain:
                request["availability_domain"] = availability_domain
            if page:
                request["page"] = page
            response = method(**request)
            data = getattr(response, "data", None)
            if data is None and isinstance(response, dict):
                data = response.get("data")
            if not isinstance(data, list):
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            resources.extend(self._oracle_resource_dict(item) for item in data)
            next_page = getattr(response, "opc_next_page", None)
            if next_page is None and isinstance(response, dict):
                next_page = response.get("opc-next-page")
            if not next_page:
                break
            if next_page in seen:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            seen.add(next_page)
            page = next_page
        matches = [item for item in resources if item.get("display_name") == restore.name]
        if len(matches) > 1:
            raise _RestoreProviderError("PROVIDER_DUPLICATE_MATCH")
        return matches

    def _restore_snapshot_oracle(self, backup, restore):
        import oci
        from oci.core.models import (
            BootVolumeSourceFromBootVolumeBackupDetails,
            CreateBootVolumeDetails,
            CreateVolumeDetails,
        )

        if self.node.type != CoreNode.Type.VOLUME:
            _restore_safe_failure(restore, "PROVIDER_FAILED")
            raise _RestoreProviderError("PROVIDER_FAILED")
        config = self.node.connection.auth_oracle.get_client()
        client = oci.core.BlockstorageClient(config)
        params = _restore_params(restore)
        volume_type = (self.metadata or {}).get("_bs_vol_type")
        target_kind = "boot_volume" if volume_type == "boot" else "volume"
        marker, params = _prepare_cloud_restore(
            restore,
            provider="oracle",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return
        try:
            compartment_id = params.get("compartment_id")
            availability_domain = params.get("availability_domain")
            if not compartment_id or not availability_domain:
                source = (
                    client.get_boot_volume(self.unique_id).data
                    if volume_type == "boot"
                    else client.get_volume(self.unique_id).data
                )
                compartment_id = compartment_id or getattr(source, "compartment_id", None)
                availability_domain = availability_domain or getattr(source, "availability_domain", None)
            if not compartment_id:
                raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
            if _restore_unknown(restore):
                matches = self._find_oracle_restore_resource(
                    client,
                    restore,
                    volume_type=volume_type,
                    compartment_id=compartment_id,
                    availability_domain=availability_domain,
                )
                if not matches:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                candidate = _restore_candidates(
                    restore,
                    matches,
                    source_id=backup.unique_id,
                    marker=marker,
                    marker_match=lambda item, value: _restore_marker_matches(item, value),
                    source_match=lambda item, source: _restore_source_matches(item, source, "source_backup_id"),
                )
                if candidate:
                    return

            tags = {"BACKUPSHEEP_RESTORE": marker, "BACKUPSHEEP_SOURCE": str(backup.unique_id)}
            if volume_type == "boot":
                details = CreateBootVolumeDetails(
                    compartment_id=compartment_id,
                    availability_domain=availability_domain,
                    display_name=restore.name,
                    freeform_tags=tags,
                    source_details=BootVolumeSourceFromBootVolumeBackupDetails(id=backup.unique_id),
                )
                _restore_begin_mutation(restore)
                response = client.create_boot_volume(create_boot_volume_details=details)
            elif volume_type == "block":
                details = CreateVolumeDetails(
                    compartment_id=compartment_id,
                    availability_domain=availability_domain,
                    display_name=restore.name,
                    freeform_tags=tags,
                    volume_backup_id=backup.unique_id,
                )
                _restore_begin_mutation(restore)
                response = client.create_volume(create_volume_details=details)
            else:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            problem = _restore_sdk_status(response, mutation=True)
            if problem:
                if problem.code == "PROVIDER_RATE_LIMIT":
                    _restore_clear_unknown(restore)
                    return _restore_handle_error(restore, problem, mutation=False)
                return _restore_handle_error(restore, problem, mutation=True)
            resource_id = getattr(getattr(response, "data", None), "id", None)
            if resource_id is None and isinstance(response, dict):
                resource_id = (response.get("data") or {}).get("id")
            if not resource_id:
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            _restore_adopt(restore, resource_id, provider_status=getattr(getattr(response, "data", None), "lifecycle_state", None), params_update={"compartment_id": compartment_id, "availability_domain": availability_domain})
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_DUPLICATE_MATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_oracle(self, restore):
        import oci
        from oci.core.models import BootVolume, Volume

        client = oci.core.BlockstorageClient(self.node.connection.auth_oracle.get_client())
        volume_type = (self.metadata or {}).get("_bs_vol_type")
        try:
            response = client.get_boot_volume(restore.resource_id) if volume_type == "boot" else client.get_volume(restore.resource_id)
            problem = _restore_sdk_status(response)
            if problem:
                return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
            data = self._oracle_resource_dict(getattr(response, "data", None))
            if not _restore_verify_target(
                restore,
                data,
                source_id=(_restore_params(restore).get("_backupsheep_restore") or {}).get("source_id"),
                marker=_restore_marker_value(restore),
                source_keys=("source_backup_id",),
            ):
                return _restore_status("FAILED")
            state = data.get("lifecycle_state")
            available = BootVolume.LIFECYCLE_STATE_AVAILABLE if volume_type == "boot" else Volume.LIFECYCLE_STATE_AVAILABLE
            faulty = BootVolume.LIFECYCLE_STATE_FAULTY if volume_type == "boot" else Volume.LIFECYCLE_STATE_FAULTY
            if state == available:
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if state == faulty:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if not state:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

    def restore_snapshot(self, backup, restore):
        return self._restore_snapshot_oracle(backup, restore)
        import oci
        from oci.core.models import (
            BootVolumeSourceFromBootVolumeBackupDetails,
            CreateBootVolumeDetails,
            CreateVolumeDetails,
        )

        if self.node.type == CoreNode.Type.VOLUME:
            try:
                config = self.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)
                params = restore.params or {}

                if (self.metadata or {}).get("_bs_vol_type") == "boot":
                    compartment_id = params.get("compartment_id")
                    availability_domain = params.get("availability_domain")
                    if not compartment_id or not availability_domain:
                        source_volume = block_storage_client.get_boot_volume(self.unique_id).data
                        compartment_id = compartment_id or source_volume.compartment_id
                        availability_domain = availability_domain or source_volume.availability_domain

                    request = block_storage_client.create_boot_volume(
                        create_boot_volume_details=CreateBootVolumeDetails(
                            compartment_id=compartment_id,
                            availability_domain=availability_domain,
                            display_name=restore.name,
                            source_details=BootVolumeSourceFromBootVolumeBackupDetails(
                                id=backup.unique_id
                            ),
                        )
                    )
                    if request.status == 200:
                        restore.resource_id = request.data.id
                        restore.save()
                    else:
                        raise Exception(f"API call returned with status {request.status}")
                elif (self.metadata or {}).get("_bs_vol_type") == "block":
                    compartment_id = params.get("compartment_id")
                    availability_domain = params.get("availability_domain")
                    if not compartment_id or not availability_domain:
                        source_volume = block_storage_client.get_volume(self.unique_id).data
                        compartment_id = compartment_id or source_volume.compartment_id
                        availability_domain = availability_domain or source_volume.availability_domain

                    request = block_storage_client.create_volume(
                        create_volume_details=CreateVolumeDetails(
                            compartment_id=compartment_id,
                            availability_domain=availability_domain,
                            volume_backup_id=backup.unique_id,
                            display_name=restore.name,
                        )
                    )
                    if request.status == 200:
                        restore.resource_id = request.data.id
                        restore.save()
                    else:
                        raise Exception(f"API call returned with status {request.status}")
            except Exception as e:
                raise Exception(f"Unable to restore snapshot: {get_error(e)}")

    def check_restore(self, restore):
        return self._check_restore_oracle(restore)
        from apps.console.backup.models import CoreCloudRestore
        import oci
        from oci.core.models import BootVolume, Volume

        config = self.node.connection.auth_oracle.get_client()
        block_storage_client = oci.core.BlockstorageClient(config)

        if (self.metadata or {}).get("_bs_vol_type") == "boot":
            request = block_storage_client.get_boot_volume(restore.resource_id)
            if request.status == 200:
                if request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_AVAILABLE:
                    return CoreCloudRestore.Status.COMPLETE
                elif request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_FAULTY:
                    return CoreCloudRestore.Status.FAILED
        elif (self.metadata or {}).get("_bs_vol_type") == "block":
            request = block_storage_client.get_volume(restore.resource_id)
            if request.status == 200:
                if request.data.lifecycle_state == Volume.LIFECYCLE_STATE_AVAILABLE:
                    return CoreCloudRestore.Status.COMPLETE
                elif request.data.lifecycle_state == Volume.LIFECYCLE_STATE_FAULTY:
                    return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


class CoreGoogleCloud(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="google_cloud", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    zone = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_google_cloud"

    def validate(self):
        node_ok = False

        if self.node.type == CoreNode.Type.CLOUD:
            client = self.node.connection.auth_google_cloud.get_client()

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/instances/{self.node.google_cloud.unique_id}"
            )
            if result.status_code == 200:
                instance = result.json()

                if (
                    instance.get("status") == "RUNNING"
                    or instance.get("status") == "TERMINATED"
                    or instance.get("status") == "SUSPENDED"
                ):
                    node_ok = True

        elif self.node.type == CoreNode.Type.VOLUME:
            client = self.node.connection.auth_google_cloud.get_client()

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/disks/{self.node.google_cloud.unique_id}"
            )
            if result.status_code == 200:
                instance = result.json()

                if instance.get("status") == "READY":
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                client = self.node.connection.auth_google_cloud.get_client()

                existing_result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/global/machineImages/{backup.uuid_str}"
                )
                if existing_result.status_code == 200:
                    image = existing_result.json()
                elif existing_result.status_code == 404:
                    image = None
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        "Unable to verify the existing Google Cloud machine image before creating a new one.",
                    )
                if image and image.get("name") == backup.uuid_str:
                    backup.unique_id = image.get("id") or backup.uuid_str
                    backup.size_gigabytes = int(
                        image.get("totalStorageBytes", 0)
                    ) / (1000 ** 3)
                    backup.metadata = image
                    backup.save()
                    return

                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/instances/{self.node.google_cloud.unique_id}"
                )
                if result.status_code == 200:
                    instance = result.json()

                    result = client.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/global/machineImages",
                        params={
                            "requestId": str(
                                uuid.uuid5(uuid.NAMESPACE_URL, f"backupsheep:{backup.uuid_str}")
                            )
                        },
                        json={
                            "name": backup.uuid_str,
                            "sourceInstance": f"projects/{self.node.google_cloud.project_id}"
                                              f"/zones/{self.node.google_cloud.zone}"
                                              f"/instances/{instance['name']}"
                        },
                    )
                    if result.status_code == 200:
                        image = result.json()
                        backup.unique_id = image.get("id") or image.get("name") or backup.uuid_str
                        backup.size_gigabytes = int(image.get("totalStorageBytes", 0))/(1000**3)
                        backup.metadata = image
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"Unable to create instance image. API call returned with status {result.status_code}",
                        )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        f"Unable to get instance details. API call returned with status {result.status_code}",
                    )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                client = self.node.connection.auth_google_cloud.get_client()
                existing_result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/global/snapshots/{backup.uuid_str}"
                )
                if existing_result.status_code == 200:
                    snapshot = existing_result.json()
                elif existing_result.status_code == 404:
                    snapshot = None
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        "Unable to verify the existing Google Cloud snapshot before creating a new one.",
                    )
                if snapshot and snapshot.get("name") == backup.uuid_str:
                    backup.unique_id = snapshot.get("id") or backup.uuid_str
                    backup.size_gigabytes = int(
                        snapshot.get("storageBytes", 0)
                    ) / (1000 ** 3)
                    backup.metadata = snapshot
                    backup.save()
                    return
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/disks/{self.node.google_cloud.unique_id}"
                )
                if result.status_code == 200:
                    disk = result.json()
                    # The global snapshots.insert endpoint is the current Compute
                    # Engine API and supports the full snapshot resource model.
                    result = client.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/global/snapshots",
                        params={
                            "requestId": str(
                                uuid.uuid5(uuid.NAMESPACE_URL, f"backupsheep:{backup.uuid_str}")
                            )
                        },
                        json={
                            "name": backup.uuid_str,
                            "sourceDisk": f"projects/{self.node.google_cloud.project_id}"
                                           f"/zones/{self.node.google_cloud.zone}"
                                           f"/disks/{disk['name']}",
                        },
                    )
                    if result.status_code in (200, 202):
                        snapshot = result.json()
                        backup.unique_id = snapshot.get("id") or snapshot.get("name") or backup.uuid_str
                        backup.size_gigabytes = int(snapshot.get("storageBytes", 0)) / (1000 ** 3)
                        backup.metadata = snapshot
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"Unable to create disk snapshot. API call returned with status {result.status_code}",
                        )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        f"Unable to get disk details. API call returned with status {result.status_code}",
                    )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )

    def _google_restore_path(self, *, resource_type, name, zone):
        return (
            f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{self.project_id}"
            f"/zones/{zone}/{resource_type}/{name}"
        )

    def _find_google_restore_resource(self, client, restore, *, resource_type, zone):
        response = client.get(self._google_restore_path(resource_type=resource_type, name=restore.name, zone=zone))
        problem = _restore_http_class(response)
        if problem:
            if problem.code == "PROVIDER_NOT_FOUND":
                return None
            raise problem
        try:
            resource = response.json()
        except Exception:
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        if not isinstance(resource, dict):
            raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
        return resource

    def _restore_snapshot_google(self, backup, restore):
        client = self.node.connection.auth_google_cloud.get_client()
        target_kind = "instance" if self.node.type == CoreNode.Type.CLOUD else "disk"
        marker, params = _prepare_cloud_restore(
            restore,
            provider="google_cloud",
            source_id=backup.unique_id,
            target_kind=target_kind,
            target_name=restore.name,
        )
        if restore.resource_id:
            return
        try:
            zone = params.get("zone") or self.zone
            if _restore_unknown(restore):
                existing = self._find_google_restore_resource(
                    client, restore, resource_type=target_kind + "s", zone=zone
                )
                if not existing:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                if not _restore_verify_target(
                    restore,
                    existing,
                    source_id=backup.unique_id,
                    marker=marker,
                    source_keys=("sourceSnapshot", "sourceMachineImage", "sourceDisk"),
                ):
                    return _restore_status("FAILED")
                _restore_adopt(restore, existing.get("name") or restore.name, provider_status=existing.get("status"), params_update={"zone": zone})
                return

            if self.node.type == CoreNode.Type.CLOUD:
                source = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{self.project_id}/zones/{self.zone}/instances/{self.unique_id}"
                )
                problem = _restore_http_class(source)
                if problem and problem.code != "PROVIDER_NOT_FOUND":
                    return _restore_handle_error(restore, problem, mutation=False)
                if not problem:
                    payload = source.json()
                    zone = zone or str(payload.get("zone") or "").split("/")[-1]
                if not zone:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                body = {
                    "name": restore.name,
                    "labels": {"backupsheep_restore": marker[:63]},
                    "sourceMachineImage": f"global/machineImages/{backup.uuid_str}",
                }
                path = f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{self.project_id}/zones/{zone}/instances"
            else:
                size_gb = params.get("sizeGb")
                source = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{self.project_id}/zones/{self.zone}/disks/{self.unique_id}"
                )
                problem = _restore_http_class(source)
                if problem and problem.code != "PROVIDER_NOT_FOUND":
                    return _restore_handle_error(restore, problem, mutation=False)
                if not problem:
                    payload = source.json()
                    zone = zone or str(payload.get("zone") or "").split("/")[-1]
                    size_gb = size_gb or payload.get("sizeGb")
                if not zone:
                    zone = self.zone
                if not size_gb and backup.size_gigabytes:
                    size_gb = int(backup.size_gigabytes + 0.999999)
                if not size_gb:
                    raise _RestoreProviderError("PROVIDER_MALFORMED_RESPONSE")
                body = {
                    "name": restore.name,
                    "labels": {"backupsheep_restore": marker[:63]},
                    "sourceSnapshot": f"global/snapshots/{backup.uuid_str}",
                    "sizeGb": str(size_gb),
                    "type": f"zones/{zone}/diskTypes/pd-balanced",
                }
                path = f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{self.project_id}/zones/{zone}/disks"
            params["zone"] = zone
            params["request_id"] = hashlib.sha256(marker.encode("utf-8")).hexdigest()[:32]
            _restore_begin_mutation(restore)
            response = client.post(path, params={"requestId": params["request_id"]}, json=body)
            problem = _restore_http_class(response, mutation=True)
            if problem:
                if problem.code == "PROVIDER_RATE_LIMIT":
                    _restore_clear_unknown(restore)
                    return _restore_handle_error(restore, problem, mutation=False)
                return _restore_handle_error(restore, problem, mutation=True)
            operation = response.json()
            if not isinstance(operation, dict) or not operation.get("name"):
                _restore_unknown_outcome(restore, code="PROVIDER_MALFORMED_RESPONSE")
                return _restore_status("IN_PROGRESS")
            _restore_adopt(restore, restore.name, provider_status="PENDING", params_update={"zone": zone, "operation_id": operation["name"], "request_id": params["request_id"]})
        except Exception as error:
            if isinstance(error, _RestoreProviderError):
                if error.retryable:
                    return _restore_handle_error(restore, error, mutation=error.unknown_outcome)
                _restore_safe_failure(restore, error.code, manual_review=error.code in {
                    "PROVIDER_MALFORMED_RESPONSE", "PROVIDER_OWNERSHIP_MISMATCH", "PROVIDER_RECONCILIATION_REQUIRED"
                })
                raise
            return _restore_handle_error(restore, error, mutation=True)

    def _check_restore_google(self, restore):
        client = self.node.connection.auth_google_cloud.get_client()
        params = _restore_params(restore)
        zone = params.get("zone") or self.zone
        target_kind = "instance" if self.node.type == CoreNode.Type.CLOUD else "disk"
        if not restore.resource_id:
            if not _restore_unknown(restore):
                return _restore_status("IN_PROGRESS")
            try:
                existing = self._find_google_restore_resource(client, restore, resource_type=target_kind + "s", zone=zone)
                if not existing:
                    return _restore_safe_failure(restore, "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True)
                if not _restore_verify_target(
                    restore,
                    existing,
                    source_id=(params.get("_backupsheep_restore") or {}).get("source_id"),
                    marker=_restore_marker_value(restore),
                    source_keys=("sourceSnapshot", "sourceMachineImage", "sourceDisk"),
                ):
                    return _restore_status("FAILED")
                _restore_adopt(restore, existing.get("name") or restore.name, provider_status=existing.get("status"), params_update={"zone": zone})
            except Exception as error:
                return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)
        try:
            response = client.get(self._google_restore_path(resource_type=target_kind + "s", name=restore.resource_id, zone=zone))
            problem = _restore_http_class(response)
            if problem:
                # Legacy rows without the marker contract retain the short
                # eventual-consistency window; new rows fail closed on 404.
                if problem.code == "PROVIDER_NOT_FOUND" and not params.get("_bs_marker_required"):
                    return _restore_status("IN_PROGRESS")
                return _restore_handle_error(restore, problem, mutation=False, raise_terminal=False)
            resource = response.json()
            if not _restore_verify_target(
                restore,
                resource,
                source_id=(params.get("_backupsheep_restore") or {}).get("source_id"),
                marker=_restore_marker_value(restore),
                source_keys=("sourceSnapshot", "sourceMachineImage", "sourceDisk"),
            ):
                return _restore_status("FAILED")
            status = resource.get("status") if isinstance(resource, dict) else None
            complete = "RUNNING" if self.node.type == CoreNode.Type.CLOUD else "READY"
            if status == complete:
                restore.operation_phase = _restore_phase("COMPLETE")
                restore.save(update_fields=["operation_phase", "modified"])
                return _restore_status("COMPLETE")
            if status in {"FAILED", "TERMINATED", "STOPPING"}:
                return _restore_safe_failure(restore, "PROVIDER_FAILED")
            if status not in {"PROVISIONING", "STAGING", "STOPPED", "RUNNING", "READY"}:
                return _restore_safe_failure(restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True)
            return _restore_status("IN_PROGRESS")
        except Exception as error:
            return _restore_handle_error(restore, error, mutation=False, raise_terminal=False)

    def restore_snapshot(self, backup, restore):
        return self._restore_snapshot_google(backup, restore)
        """Initiate a restore of a snapshot to a NEW instance/disk (never in-place).
        Sets restore.resource_id on success and saves; raises with a clear message on failure."""
        params = restore.params or {}
        client = self.node.connection.auth_google_cloud.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            zone = params.get("zone")
            if not zone:
                # Default to the source instance's zone (last segment of its zone URL);
                # fall back to the node's configured zone if the instance no longer exists.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/instances/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.post(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/instances",
                json={
                    "name": restore.name,
                    # Machine images are addressed by name (= backup.uuid_str);
                    # backup.unique_id holds the id of the insert Operation.
                    "sourceMachineImage": f"global/machineImages/{backup.uuid_str}",
                },
            )
            if result.status_code == 200:
                operation = result.json()
                restore.resource_id = restore.name
                params["zone"] = zone
                params["operation_id"] = operation.get("name")
                restore.params = params
                restore.save()
            else:
                raise Exception(
                    f"Unable to restore instance from machine image. API call returned with status {result.status_code}"
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            import math

            zone = params.get("zone")
            size_gb = params.get("sizeGb")
            if not zone or not size_gb:
                # Default to the source disk's zone and size.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/disks/{self.unique_id}"
                )
                if result.status_code == 200:
                    disk = result.json()
                    if not zone:
                        zone = disk["zone"].split("/")[-1]
                    if not size_gb:
                        size_gb = disk.get("sizeGb")
            if not zone:
                zone = self.zone
            if not size_gb and backup.size_gigabytes:
                size_gb = math.ceil(backup.size_gigabytes)
            if not size_gb:
                raise Exception(
                    "Unable to determine the restored disk size. Provide sizeGb in the restore params."
                )

            result = client.post(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/disks",
                json={
                    "name": restore.name,
                    # Snapshots are addressed by name (= backup.uuid_str);
                    # backup.unique_id holds the id of the insert Operation.
                    "sourceSnapshot": f"global/snapshots/{backup.uuid_str}",
                    "sizeGb": str(size_gb),
                    "type": f"zones/{zone}/diskTypes/pd-balanced",
                },
            )
            if result.status_code == 200:
                operation = result.json()
                restore.resource_id = restore.name
                params["zone"] = zone
                params["operation_id"] = operation.get("name")
                restore.params = params
                restore.save()
            else:
                raise Exception(
                    f"Unable to restore disk from snapshot. API call returned with status {result.status_code}"
                )

    def check_restore(self, restore):
        return self._check_restore_google(restore)
        """Single non-blocking restore status check: COMPLETE / FAILED / IN_PROGRESS."""
        from apps.console.backup.models import CoreCloudRestore

        params = restore.params or {}
        zone = params.get("zone")
        client = self.node.connection.auth_google_cloud.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            if not zone:
                # Fall back to the source instance's zone, then the node's configured zone.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/instances/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/instances/{restore.resource_id or restore.name}"
            )
            if result.status_code == 200:
                instance = result.json()
                if instance.get("status") == "RUNNING":
                    return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS
        elif self.node.type == CoreNode.Type.VOLUME:
            if not zone:
                # Fall back to the source disk's zone, then the node's configured zone.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/disks/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/disks/{restore.resource_id or restore.name}"
            )
            if result.status_code == 200:
                disk = result.json()
                if disk.get("status") == "READY":
                    return CoreCloudRestore.Status.COMPLETE
                elif disk.get("status") == "FAILED":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


@contextmanager
def _local_backup_phase_lock(backup):
    """Serialize the dump/chord publication phase for one backup row.

    A database status is not enough to distinguish a live long-running dump from a
    worker that died mid-dump. A host-level flock gives us that distinction without a
    short lease: a duplicate waits while the original is alive, and the lock is
    released by the OS immediately when the worker process dies. This prevents two
    workers from writing the same archive concurrently while still allowing restart
    recovery without waiting for a fixed timeout.
    """
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
    os.makedirs(storage_dir, exist_ok=True)
    lock_path = os.path.join(storage_dir, f"{backup.uuid_str}.phase.lock")
    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _clear_local_backup_artifacts(backup):
    """Remove only incomplete dump artifacts before restarting a dump phase."""
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
    for name, is_dir in ((backup.uuid_str, True), (f"{backup.uuid_str}.zip", False)):
        target = os.path.realpath(os.path.join(storage_dir, name))
        if target == storage_dir or os.path.commonpath([storage_dir, target]) != storage_dir:
            continue
        if is_dir:
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.remove(target)
            except FileNotFoundError:
                pass


def _resume_local_backup(backup, node, snapshot_callback, storage_relation, point_status):
    """Acquire a cross-worker lease before entering the local backup pipeline."""
    from apps._tasks.execution import durable_execution_lease

    with durable_execution_lease(
        backup,
        phase="source_dispatch",
        task_id=backup.celery_task_id,
    ) as execution:
        if not execution.acquired:
            # Another healthy delivery owns this phase. Late acknowledgements plus
            # the periodic recovery sweep will resume it if that worker disappears.
            return backup
        return _resume_local_backup_owned(
            backup,
            node,
            snapshot_callback,
            storage_relation,
            point_status,
            execution,
        )


def _resume_local_backup_owned(
    backup,
    node,
    snapshot_callback,
    storage_relation,
    point_status,
    execution,
):
    """Resume a local dump/upload pipeline from its persisted phase.

    A worker can die after the dump has been created but before the chord is
    published. Re-running the dump is wasteful and can produce a second upload;
    the parent status and each storage-point status are the durable phase markers.
    """
    terminal = (
        UtilBackup.Status.COMPLETE,
        UtilBackup.Status.PARTIAL,
        UtilBackup.Status.FAILED,
        UtilBackup.Status.UPLOAD_FAILED,
        UtilBackup.Status.TIMEOUT,
        UtilBackup.Status.CANCELLED,
        UtilBackup.Status.STORAGE_VALIDATION_FAILED,
    )
    upload_phase = (
        UtilBackup.Status.DOWNLOAD_COMPLETE,
        UtilBackup.Status.UPLOAD_READY,
        UtilBackup.Status.UPLOAD_IN_PROGRESS,
        UtilBackup.Status.UPLOAD_VALIDATION,
        UtilBackup.Status.UPLOAD_COMPLETE,
    )
    from apps._tasks.execution import verify_and_commit_source_artifact

    with _local_backup_phase_lock(backup):
        # The caller can have waited behind a live worker or arrived after a worker
        # crash. Always re-read the phase marker after acquiring the lock. Refresh
        # in place so callers that retain the model instance observe the same
        # durable phase without silently changing object identity.
        backup.refresh_from_db()
        if backup.status in terminal:
            return backup

        if backup.status not in upload_phase:
            # IN_PROGRESS/RETRYING/DOWNLOAD_IN_PROGRESS means the archive is not a
            # durable upload input yet. Remove partial files before rebuilding it;
            # otherwise an SSH-streamed dump could be appended to a truncated file.
            _clear_local_backup_artifacts(backup)
            backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
            backup.save(update_fields=["status", "modified"])
            snapshot_callback(backup)
            execution.ensure_owned()
            artifact = verify_and_commit_source_artifact(backup)
            execution.progress(
                artifact.byte_count,
                artifact.byte_count,
                unit="bytes",
            )
            backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
            backup.save(update_fields=["status", "modified"])

        stored_backups = getattr(backup, storage_relation)
        pending_statuses = (
            point_status.UPLOAD_READY,
            point_status.UPLOAD_RETRY,
            point_status.UPLOAD_IN_PROGRESS,
            point_status.UPLOAD_VALIDATION,
        )
        from apps._tasks.integration.storage.tasks import storage_upload, finalize_backup

        pending_stored_backups = stored_backups.filter(status__in=pending_statuses)
        if pending_stored_backups.exists():
            # Recovery is allowed to reuse a source archive only after its CRC,
            # checksum, byte count, and local commit marker all still match.
            execution.ensure_owned()
            verify_and_commit_source_artifact(backup)

        storage_upload_task_list = [
            storage_upload.s(node.id, backup.id, stored_backup.id).set()
            for stored_backup in pending_stored_backups
        ]

        if storage_upload_task_list:
            backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
            backup.save(update_fields=["status", "modified"])
            chord(
                storage_upload_task_list,
                finalize_backup.si(node.id, backup.id),
            ).apply_async()
        else:
            # All points are already complete, or there are no accepted destinations.
            # The finalizer makes the correct COMPLETE/PARTIAL/UPLOAD_FAILED decision.
            finalize_backup.apply_async(args=[node.id, backup.id])
        return backup


class CoreWebsite(TimeStampedModel):
    class BackupType(models.IntegerChoices):
        FULL = 1, "Full"
        FULL_V2 = 4, "Full (Server-Side Tar)"

    node = models.OneToOneField(
        "CoreNode", related_name="website", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    paths = models.JSONField(null=True)
    excludes = models.JSONField(null=True)
    includes_regex = models.JSONField(null=True)
    includes_glob = models.JSONField(null=True)
    excludes_regex = models.JSONField(null=True)
    excludes_glob = models.JSONField(null=True)
    parallel = models.IntegerField(null=True, default=3)
    verbose = models.BooleanField(default=False, null=True)
    all_paths = models.BooleanField(null=True)
    notes = models.TextField(null=True, blank=True)
    backup_type = models.IntegerField(choices=BackupType.choices, default=BackupType.FULL)
    incremental = models.BooleanField(default=False)
    tar_temp_backup_dir = models.TextField(null=True, blank=True)
    tar_exclude_vcs_ignores = models.BooleanField(default=False, null=True)
    tar_exclude_vcs = models.BooleanField(default=False, null=True)
    tar_exclude_backups = models.BooleanField(default=False, null=True)
    tar_exclude_caches = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_website"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.website import snapshot_website
        from ..backup.models import CoreWebsiteBackupStoragePoints
        return _resume_local_backup(
            backup,
            self.node,
            snapshot_website,
            "stored_website_backups",
            CoreWebsiteBackupStoragePoints.Status,
        )


class CoreDatabase(TimeStampedModel):
    node = models.OneToOneField(
        "CoreNode", related_name="database", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    tables = models.JSONField(null=True)
    all_tables = models.BooleanField(null=True)
    databases = models.JSONField(null=True)
    all_databases = models.BooleanField(null=True)
    option_single_transaction = models.BooleanField(null=True, default=True)
    option_skip_opt = models.BooleanField(null=True, default=False)
    option_compress = models.BooleanField(null=True, default=True)
    # todo: remove this field.
    option_gtid_purged_off = models.BooleanField(null=True, default=True)
    #todo: remove this field.
    option_postgres_format_custom = models.BooleanField(null=True, default=False)
    notes = models.TextField(null=True, blank=True)
    option_postgres = models.TextField(null=True, blank=True)
    option_mysql = models.TextField(null=True, blank=True)
    option_mariadb = models.TextField(null=True, blank=True)
    option_mongodb = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_database"

    def validate(self):
        """A database node is valid when its connection can still reach the server."""
        try:
            self.node.connection.auth_database.check_connection(check_errors=True)
            return True
        except Exception:
            return False

    def create_snapshot(self, backup):
        from ..connection.models import CoreAuthDatabase
        from apps._tasks.integration.backup.mariadb import snapshot_mariadb
        from apps._tasks.integration.backup.mysql import snapshot_mysql
        from apps._tasks.integration.backup.postgresql import snapshot_postgresql

        def snapshot_database(current_backup):
            if self.node.connection.auth_database.type == CoreAuthDatabase.DatabaseType.MYSQL:
                snapshot_mysql(current_backup)
            elif self.node.connection.auth_database.type == CoreAuthDatabase.DatabaseType.MARIADB:
                snapshot_mariadb(current_backup)
            elif self.node.connection.auth_database.type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
                snapshot_postgresql(current_backup)
            else:
                raise NodeBackupFailedError(
                    self.node,
                    current_backup.uuid_str,
                    current_backup.attempt_no,
                    current_backup.type,
                    message=f"Unsupported database engine type: "
                            f"{self.node.connection.auth_database.type}",
                )

        return _resume_local_backup(
            backup,
            self.node,
            snapshot_database,
            "stored_database_backups",
            CoreDatabaseBackupStoragePoints.Status,
        )


class CoreWordPress(TimeStampedModel):
    class Include(models.IntegerChoices):
        FULL = 1, "Full (Database + Files)"
        DATABASE = 2, "Only Database"
        FILES = 3, "Only Files"

    include = models.IntegerField(choices=Include.choices, default=Include.FULL)
    node = models.OneToOneField(
        "CoreNode", related_name="wordpress", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_wordpress"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.wordpress import snapshot_wordpress
        from ..backup.models import CoreWordPressBackupStoragePoints
        return _resume_local_backup(
            backup,
            self.node,
            snapshot_wordpress,
            "stored_wordpress_backups",
            CoreWordPressBackupStoragePoints.Status,
        )


class CoreBasecamp(TimeStampedModel):
    node = models.OneToOneField(
        "CoreNode", related_name="basecamp", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    projects = models.JSONField(null=True)
    all_projects = models.BooleanField(default=False)

    class Meta:
        db_table = "core_basecamp"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.basecamp import snapshot_basecamp
        from ..backup.models import CoreBasecampBackupStoragePoints
        return _resume_local_backup(
            backup,
            self.node,
            snapshot_basecamp,
            "stored_basecamp_backups",
            CoreBasecampBackupStoragePoints.Status,
        )


class CoreSchedule(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        PAUSED = 2, "Paused"
        DELETE_REQUESTED = 3, "Delete Requested"

    class Type(models.TextChoices):
        CRON = "cron", "Cron"
        RATE = "rate", "Rate"
        ONETIME = "at", "One-time"

    class RateUnit(models.TextChoices):
        MINUTES = "minutes", "Minutes"
        HOURS = "hours", "Hours"
        DAYS = "days", "Days"

    node = models.ForeignKey(
        "CoreNode", related_name="schedules", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreServerScheduleStatus, related_name="schedules", on_delete=models.PROTECT
    # )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.CharField(choices=Type.choices, default="cron", max_length=64)
    rate_unit = models.CharField(choices=RateUnit.choices, null=True, max_length=64)
    rate_value = models.IntegerField(null=True)
    at_datetime = models.DateTimeField(null=True)
    celery_periodic_task = models.ForeignKey(
        PeriodicTask,
        related_name="schedules",
        null=True,
        on_delete=models.SET_NULL,
        editable=False,
    )
    storage_points = models.ManyToManyField(CoreStorage, related_name="schedules")
    name = models.CharField(max_length=255)
    keep_last = models.PositiveIntegerField(null=True)
    require_air_gapped_copy = models.BooleanField(default=False)
    type_legacy = models.CharField(max_length=32, default="crontab")
    hour = models.CharField(max_length=255, null=True, blank=True)
    minute = models.CharField(max_length=255, null=True, blank=True)
    day_of_week = models.CharField(max_length=255, null=True, blank=True)
    day_of_month = models.CharField(max_length=255, null=True, blank=True)
    month_of_year = models.CharField(max_length=255, null=True, blank=True)
    year = models.CharField(max_length=255, default="*", null=True, blank=True)
    delete_remote_backups = models.BooleanField(default=False)
    compressed_backups_only = models.BooleanField(default=False, null=True)
    delete_remote_backups_time = models.IntegerField(null=True)
    encrypt_backup = models.BooleanField(default=False, null=True)
    timezone = models.CharField(max_length=64)
    notes = models.TextField(null=True, blank=True)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_schedules",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_schedule"

    @property
    def uuid_str(self):
        return slugify(f"bs-s{self.id}-n{self.node.id}-a{self.node.connection.account.id}")

    @property
    def task_name(self):
        name = (
            f"scheduled_backup"
            f"__{self.node.connection.location.queue}"
        )
        return name

    @property
    def queue_name(self):
        name = (
            f"scheduled_backup"
            f"__{self.node.get_type_display().lower()}"
            f"__{self.node.get_integration_alt_code()}"
            f"__{self.node.connection.location.queue}"
        )
        return name

    @property
    def storage_ids(self):
        return list(self.storage_points.filter().values_list("id", flat=True))

    def crontab_display(self):
        return f"{self.minute} {self.hour} {self.day_of_month} {self.month_of_year} {self.day_of_week}"

    def delete_requested(self):
        self.status = CoreSchedule.Status.DELETE_REQUESTED
        # if self.celery_periodic_task:
        #     self.celery_periodic_task.enabled = False
        #     self.celery_periodic_task.save()
        self.save()

    def _periodic_schedule(self):
        """Return (PeriodicTask field name, schedule object) for this schedule's type."""
        from django_celery_beat.models import (
            CrontabSchedule,
            IntervalSchedule,
            ClockedSchedule,
        )

        if self.type == CoreSchedule.Type.CRON:
            crontab, _ = CrontabSchedule.objects.get_or_create(
                minute=self.minute or "*",
                hour=self.hour or "*",
                day_of_week=self.day_of_week or "*",
                day_of_month=self.day_of_month or "*",
                month_of_year=self.month_of_year or "*",
                timezone=self.timezone or "UTC",
            )
            return "crontab", crontab
        elif self.type == CoreSchedule.Type.RATE:
            interval, _ = IntervalSchedule.objects.get_or_create(
                every=self.rate_value,
                period=self.rate_unit,
            )
            return "interval", interval
        elif self.type == CoreSchedule.Type.ONETIME:
            clocked, _ = ClockedSchedule.objects.get_or_create(clocked_time=self.at_datetime)
            return "clocked", clocked
        return None, None

    def schedule_create(self):
        """Create the local django-celery-beat PeriodicTask that drives this schedule."""
        field, schedule_obj = self._periodic_schedule()
        if not field:
            return
        periodic_task = PeriodicTask.objects.create(
            name=self.uuid_str,
            task="run_scheduled_backup",
            args=json.dumps([self.id]),
            enabled=(self.status == CoreSchedule.Status.ACTIVE),
            one_off=(self.type == CoreSchedule.Type.ONETIME),
            **{field: schedule_obj},
        )
        self.celery_periodic_task = periodic_task
        self.save(update_fields=["celery_periodic_task"])

    def schedule_update(self):
        """Update (or create) the PeriodicTask to match this schedule."""
        if not self.celery_periodic_task:
            return self.schedule_create()
        field, schedule_obj = self._periodic_schedule()
        if not field:
            return
        periodic_task = self.celery_periodic_task
        periodic_task.crontab = None
        periodic_task.interval = None
        periodic_task.clocked = None
        setattr(periodic_task, field, schedule_obj)
        periodic_task.one_off = self.type == CoreSchedule.Type.ONETIME
        periodic_task.enabled = self.status == CoreSchedule.Status.ACTIVE
        periodic_task.args = json.dumps([self.id])
        periodic_task.save()

    def schedule_delete(self):
        """Remove the local PeriodicTask for this schedule."""
        if self.celery_periodic_task:
            self.celery_periodic_task.delete()
            self.celery_periodic_task = None


class CoreScheduleRun(TimeStampedModel):
    schedule = models.ForeignKey(CoreSchedule, related_name="runs", on_delete=models.CASCADE)
    request_id = models.CharField(max_length=1024)

    class Meta:
        db_table = "core_schedule_run"
        constraints = [
            UniqueConstraint(
                fields=["schedule", "request_id"], name="unique_schedule_trigger_request"
            ),
        ]


class CoreNode(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        BACKUP_READY = 2, "Ready for Backup"
        BACKUP_IN_PROGRESS = 3, "Backup In-Progress"
        BACKUP_RETRYING = 4, "Retrying Backup"
        SUSPENDED = 5, "Suspended"
        PAUSED = 6, "Paused"
        PAUSED_MAX_RETRIES = 8, "Paused (Max Retries)"
        DELETE_REQUESTED = 7, "Delete Requested"
        DELETE_COMPLETED = 9, "Delete Completed"

    class Type(models.IntegerChoices):
        CLOUD = 1, "Cloud"
        VOLUME = 2, "Volume"
        WEBSITE = 3, "Website"
        DATABASE = 4, "Database"
        SAAS = 5, "SaaS"

    connection = models.ForeignKey(
        CoreConnection, related_name="nodes", on_delete=models.CASCADE
    )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.IntegerField(choices=Type.choices)
    name = models.CharField(max_length=255)
    flag_next_run_wait = models.IntegerField(null=True)
    flag_delete_node = models.BooleanField(default=False)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    email_data = models.JSONField(null=True)
    timezone = models.CharField(max_length=64, default="UTC")
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_nodes",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_node"
        permissions = (
            ("create_ondemand_backup", "can create on-demand backup"),
            ("create_schedule", "can create schedule for backup"),
        )

    def _integration_object(self):
        """Return the provider-specific object attached to this node.

        Most integrations use the integration code as their reverse relation
        name (for example ``node.vultr``).  Vultr managed databases are a
        separate model, however, so their reverse relation is
        ``node.vultr_database`` even though the connection integration code is
        still ``vultr``.  Keeping this lookup in one place prevents generic
        scheduling, recovery, and UI helpers from accidentally treating a
        managed database as a compute node.
        """
        integration_code = self.connection.integration.code
        if integration_code == "vultr" and hasattr(self, "vultr_database"):
            return self.vultr_database
        return getattr(self, integration_code, None)

    def validate(self):
        node_integration_object = self._integration_object()
        if node_integration_object:
            return node_integration_object.validate()

    """
    Disabled this on Oct-2021. Don't think this is used anymore because node status is checked in backup_ready_to_initiate()
    """

    # def save(self, *args, **kwargs):
    #     if self.id:
    #         if self.status == self.Status.ACTIVE:
    #             # re-enable schedules, otherwise they will keep running
    #             for schedule in self.schedules.filter(
    #                     status=CoreSchedule.Status.PAUSED
    #             ):
    #                 schedule.status = CoreSchedule.Status.ACTIVE
    #                 schedule.save()
    #         elif (
    #                 self.status == self.Status.PAUSED
    #                 or self.status == self.Status.SUSPENDED
    #         ):
    #             # disable schedules, otherwise they will keep running
    #             for schedule in self.schedules.filter(
    #                     status=CoreSchedule.Status.ACTIVE
    #             ):
    #                 schedule.status = CoreSchedule.Status.PAUSED
    #                 schedule.save()
    #     return super(CoreNode, self).save(*args, **kwargs)

    def backup_task_name(self):
        if self.connection.integration.code == "vultr" and hasattr(self, "vultr_database"):
            return "backup_vultr_database"
        return f"backup_{self.connection.integration.code}"

    def get_integration_alt_code(self):
        if self.connection.integration.code == "database":
            return self.connection.auth_database.get_type_display().lower()
        elif self.connection.integration.code == "website":
            return self.connection.auth_website.get_protocol_display().lower()
        else:
            return self.connection.integration.code.lower()

    def get_integration_alt_name(self):
        if self.connection.integration.code == "database":
            return self.connection.auth_database.get_type_display()
        elif self.connection.integration.code == "website":
            return self.connection.auth_website.get_protocol_display()
        else:
            return self.connection.integration.name

    def get_backup_from_celery_task_id(self, celery_task_id):
        node_type_object = self._integration_object()
        if not node_type_object:
            return None
        if node_type_object.backups.filter(celery_task_id=celery_task_id).exists() and celery_task_id:
            return node_type_object.backups.get(celery_task_id=celery_task_id)

    def get_cloud_backup(self, backup_id):
        """Return this node's provider-specific backup by id (used by the async
        poll_cloud_backup task to re-load a snapshot it is waiting on)."""
        node_type_object = self._integration_object()
        if not node_type_object:
            return None
        return node_type_object.backups.filter(id=backup_id).first()

    @property
    def get_node_url(self):
        node_type_object = self._integration_object()
        if not node_type_object:
            return None
        return f"/console/{self.get_type_display().lower()}s/{self.connection.integration.code}/{node_type_object.id}"

    @property
    def name_slug(self):
        trimmed = (self.name[:24]) if len(self.name) > 24 else self.name
        return slugify(f"{trimmed}-n{self.id}")

    @property
    def uuid_str(self):
        return slugify(f"bs-n{self.id}")

    @property
    def incremental_backup_available(self):
        if self.connection.integration.code == "website":
            return self.connection.auth_website.use_public_key or self.connection.auth_website.use_private_key

    def backup_ready_to_initiate(self, celery_task_id=None):
        if self.get_backup_from_celery_task_id(celery_task_id):
            return True
        elif self.status == self.Status.ACTIVE:
            return True
        elif self.status == self.Status.BACKUP_RETRYING or\
                self.status == self.Status.BACKUP_READY or\
                self.status == self.Status.PAUSED_MAX_RETRIES or\
                self.status == self.Status.BACKUP_IN_PROGRESS:
            node_type_object = self._integration_object()
            if not node_type_object:
                return True

            if node_type_object.backups.filter().count() > 0:
                last_backup = node_type_object.backups.filter().order_by("-created").first()
                if last_backup.status in UtilBackup.SUCCESS_STATUSES:
                    return True
                else:
                    t_difference = datetime.datetime.now(tz=pytz.UTC) - last_backup.created
                    hours_since_last_backup = int(t_difference.total_seconds() / 3600)
                    if hours_since_last_backup >= 1:
                        return True
            else:
                return True


    def last_backup_date(self):
        node_type_object = self._integration_object()
        if not node_type_object:
            return None
        if node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).count() > 0:
            backup = node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).order_by('-created').first()
            timezone = str(get_current_timezone())
            timezone = pytz.timezone(timezone)
            date_time = backup.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
            return date_time
        else:
            return None

    def list_backups(self, list_all_backups=None):
        from django.db.models import Q
        node_type_object = self._integration_object()
        if list_all_backups is True:
            return node_type_object.backups.filter()
        else:
            query = (
                    ~Q(status=UtilBackup.Status.DELETE_FAILED)
                    & ~Q(status=UtilBackup.Status.DELETE_REQUESTED)
                    & ~Q(status=UtilBackup.Status.DELETE_COMPLETED)
                    & ~Q(status=UtilBackup.Status.DELETE_FAILED_NOT_FOUND)
                    & ~Q(status=UtilBackup.Status.DELETE_MAX_RETRY_FAILED)
            )
        return node_type_object.backups.filter(query)

    def total_backups(self):
        node_type_object = self._integration_object()
        if not node_type_object:
            return 0
        return node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).count()

    def total_storage(self):
        from django.db.models import Sum

        node_type_object = self._integration_object()
        if not node_type_object:
            return humanfriendly.format_size(0)

        if self.connection.integration.code == "website" or self.connection.integration.code == "database":
            node_stats = node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).aggregate(Sum("size"))
            return humanfriendly.format_size(node_stats["size__sum"] or 0)
        elif self.connection.integration.type == "saas":
            node_stats = node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).aggregate(Sum("size"))
            return humanfriendly.format_size(node_stats["size__sum"] or 0)
        else:
            node_stats = node_type_object.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).aggregate(
                Sum("size_gigabytes"))
            return humanfriendly.format_size(1000 ** 3 * (node_stats["size_gigabytes__sum"] or 0))

    def total_schedules(self):
        return self.schedules.filter(status=CoreSchedule.Status.ACTIVE).count()

    @staticmethod
    def _canonical_backup_storage_ids(storage_ids):
        """Return a stable, duplicate-free storage selection and invalid count.

        The selection becomes part of a backup's durable request identity.  Be
        deliberately conservative when recovering malformed legacy metadata: only
        positive integer primary keys are accepted and everything else is counted as
        an unavailable requested destination instead of crashing the recovery task.
        """
        if storage_ids is None:
            values = []
        elif isinstance(storage_ids, (list, tuple, set)):
            values = storage_ids
        else:
            values = [storage_ids]

        normalized = []
        seen = set()
        invalid_count = 0
        for value in values:
            if isinstance(value, bool):
                invalid_count += 1
                continue
            if isinstance(value, int):
                storage_id = value
            elif isinstance(value, str) and value.strip().isdigit():
                storage_id = int(value.strip())
            else:
                invalid_count += 1
                continue
            if storage_id <= 0:
                invalid_count += 1
                continue
            if storage_id not in seen:
                seen.add(storage_id)
                normalized.append(storage_id)
        return normalized, invalid_count

    @staticmethod
    def _write_destination_setup_state(
        backup,
        *,
        state,
        requested_count,
        accepted_count,
        validation_failed_ids,
        unavailable_count,
        error_code="",
        status=None,
    ):
        """Merge a safe destination checkpoint under the concrete backup row lock."""
        with transaction.atomic():
            locked = backup.__class__.objects.select_for_update().get(pk=backup.pk)
            metadata = dict(locked.metadata or {})
            metadata["_backup_destination_setup"] = {
                "state": str(state),
                "requested_count": max(0, int(requested_count)),
                "accepted_count": max(0, int(accepted_count)),
                "validation_failed_count": len(validation_failed_ids),
                # These IDs belong to the requesting account and are needed to make
                # a retry deterministic. Never persist provider exception text here.
                "validation_failed_storage_ids": sorted(validation_failed_ids),
                "unavailable_count": max(0, int(unavailable_count)),
                "error_code": str(error_code or "")[:64],
                "updated_at": timezone.now().isoformat(),
            }
            locked.metadata = metadata
            update_fields = ["metadata", "modified"]
            if status is not None:
                locked.status = status
                update_fields.insert(0, "status")
            locked.save(update_fields=update_fields)
        backup.metadata = metadata
        if status is not None:
            backup.status = status

    def _reconcile_local_backup_destinations(self, backup, schedule_id):
        """Crash-safely reconcile every requested local-backup destination.

        A storage validation can take a network round trip.  The renewable execution
        lease elects one setup worker, while the M2M rows and metadata checkpoints let
        a replacement worker continue after a process/server crash without forgetting
        destinations that had not yet been visited.
        """
        from apps._tasks.execution import durable_execution_lease

        with durable_execution_lease(
            backup,
            phase="destination_setup",
            task_id=backup.celery_task_id,
        ) as execution:
            if not execution.acquired:
                return False

            backup.refresh_from_db(fields=["metadata", "status"])
            metadata = dict(backup.metadata or {})
            requested_ids, malformed_count = self._canonical_backup_storage_ids(
                metadata.get("_backup_storage_ids")
            )
            try:
                persisted_invalid_count = max(
                    0, int(metadata.get("_backup_storage_invalid_id_count") or 0)
                )
            except (TypeError, ValueError):
                persisted_invalid_count = 0
            invalid_count = max(persisted_invalid_count, malformed_count)
            requested_count = len(requested_ids) + invalid_count

            prior_setup = metadata.get("_backup_destination_setup")
            prior_setup = prior_setup if isinstance(prior_setup, dict) else {}
            failed_ids, _ignored_invalid = self._canonical_backup_storage_ids(
                prior_setup.get("validation_failed_storage_ids")
            )
            failed_ids = set(failed_ids).intersection(requested_ids)

            # An attached row is the durable acceptance marker. This intentionally
            # includes a destination that was paused after setup: silently replacing
            # the immutable request would be worse than allowing its upload task to
            # report the precise terminal condition.
            accepted_ids = set(
                backup.storage_points.filter(id__in=requested_ids).values_list(
                    "id", flat=True
                )
            )
            unresolved_ids = [
                storage_id
                for storage_id in requested_ids
                if storage_id not in accepted_ids and storage_id not in failed_ids
            ]
            available = {
                storage.id: storage
                for storage in CoreStorage.objects.filter(
                    id__in=unresolved_ids,
                    account=self.connection.account,
                    status=CoreStorage.Status.ACTIVE,
                ).select_related("type")
            }

            def checkpoint(state="in_progress", error_code="", status=None):
                unavailable_count = invalid_count + sum(
                    storage_id not in available
                    for storage_id in requested_ids
                    if storage_id not in accepted_ids and storage_id not in failed_ids
                )
                self._write_destination_setup_state(
                    backup,
                    state=state,
                    requested_count=requested_count,
                    accepted_count=len(accepted_ids),
                    validation_failed_ids=failed_ids,
                    unavailable_count=unavailable_count,
                    error_code=error_code,
                    status=status,
                )
                return unavailable_count

            checkpoint()
            for storage_id in unresolved_ids:
                storage_point = available.get(storage_id)
                if storage_point is None:
                    continue
                execution.ensure_owned()
                accepted = bool(storage_point.validate())
                execution.ensure_owned()
                if accepted:
                    # Django's M2M manager checks the target identity, so replaying
                    # this step after a crash cannot create a second logical upload.
                    backup.storage_points.add(storage_point)
                    accepted_ids.add(storage_id)
                else:
                    failed_ids.add(storage_id)
                checkpoint()

                if not accepted:
                    message = (
                        f"Storage validation failed for {storage_point.name} "
                        f"({storage_point.type.name}) during backup "
                        f"({backup.uuid_str}) of your node ({self.name})."
                    )
                    try:
                        self.connection.account.create_backup_log(
                            message=message,
                            node=self,
                            backup=backup,
                        )
                    except Exception as error:
                        capture_exception(error)
                    try:
                        self.notify_storage_validation_fail(storage_point, backup)
                    except Exception as error:
                        capture_exception(error)

            execution.ensure_owned()
            accepted_air_gap = backup.storage_points.filter(
                id__in=accepted_ids,
                is_air_gapped=True,
            ).exists()
            schedule = (
                CoreSchedule.objects.filter(id=schedule_id).first()
                if schedule_id
                else None
            )
            air_gap_required = bool(schedule and schedule.require_air_gapped_copy)

            if not accepted_ids:
                error_code = "NO_VALID_STORAGE_DESTINATION"
            elif air_gap_required and not accepted_air_gap:
                error_code = "AIR_GAPPED_DESTINATION_REQUIRED"
            else:
                checkpoint(state="complete")
                return True

            checkpoint(
                state="failed",
                error_code=error_code,
                status=UtilBackup.Status.STORAGE_VALIDATION_FAILED,
            )
            backup.record_execution_error(
                code=error_code,
                retryable=False,
                lease_owner=execution.owner,
                lease_token=execution.token,
            )
            if error_code == "AIR_GAPPED_DESTINATION_REQUIRED":
                message = (
                    f"Required air-gapped copy was not accepted for backup "
                    f"({backup.uuid_str}) of your node ({self.name})."
                )
            else:
                message = (
                    f"No requested storage destination was accepted for backup "
                    f"({backup.uuid_str}) of your node ({self.name})."
                )
            try:
                self.connection.account.create_backup_log(
                    message=message,
                    node=self,
                    backup=backup,
                )
            except Exception as error:
                capture_exception(error)
            return False

    # def validate(self):
    #     validate_ok = (
    #             self.connection.status == CoreConnection.Status.ACTIVE
    #             and self.connection.validate()
    #     )
    #     return validate_ok

    def backup_initiate(
            self, celery_task_id, backup_type, attempt_no, schedule_id, storage_ids, notes
    ):
        """
        Duplicate-backup guard: lock this node's row so concurrent backup tasks for
        the same node serialize here, then refuse to start a second backup while one
        is still in flight. An active backup (see UtilBackup.ACTIVE_STATUSES) created
        by a DIFFERENT celery task means its snapshot may already exist at the
        provider, so the new task must exit without creating a backup record or
        calling the provider API -- in that case this returns None and the caller
        (the celery task) returns immediately. A retry of the SAME task reuses its
        own backup (same celery_task_id) and is never blocked by it.
        """
        with transaction.atomic():
            # Keep the durable delivery ledger in sync with the concrete backup
            # while the node lock is held.  This import stays local to avoid
            # widening the node/backup model import cycle.
            from apps.console.backup.models import CoreBackupRequest

            CoreNode.objects.select_for_update().get(id=self.id)
            node_type_object = self._integration_object()
            active_backup = node_type_object.backups.filter(
                status__in=UtilBackup.ACTIVE_STATUSES
            ).exclude(celery_task_id=celery_task_id).first()
            if active_backup:
                print(
                    f"Skipping duplicate backup of node {self.id}: backup "
                    f"{active_backup.id} is already in flight (status "
                    f"{active_backup.get_status_display()}, task "
                    f"{active_backup.celery_task_id}); task {celery_task_id} exiting."
                )
                CoreBackupRequest.link_backup(
                    task_id=celery_task_id,
                    node=self,
                    backup=active_backup,
                    duplicate=True,
                )
                return None
            backup, created = node_type_object.backups.get_or_create(celery_task_id=celery_task_id)
            # A redelivered/recovered task must continue the persisted phase. In
            # particular, DOWNLOAD_COMPLETE and UPLOAD_IN_PROGRESS mean that the
            # local dump already exists and only storage work remains; resetting the
            # row to IN_PROGRESS would cause a worker restart to create the dump again.
            if created or backup.status in (
                UtilBackup.Status.PENDING,
                UtilBackup.Status.STARTED,
                UtilBackup.Status.RETRYING,
            ):
                backup.status = UtilBackup.Status.IN_PROGRESS
            backup.type = backup_type
            backup.attempt_no = attempt_no
            backup.schedule_id = schedule_id
            backup.notes = notes

            # Celery is not the source of truth after a worker crash. Freeze the
            # caller's destination selection once so DB-only recovery can reconstruct
            # the request and a redelivery cannot silently substitute another bucket.
            is_local_backup = self.type in (
                self.Type.DATABASE,
                self.Type.WEBSITE,
                self.Type.SAAS,
            )
            if is_local_backup:
                metadata = (
                    dict(backup.metadata)
                    if isinstance(backup.metadata, dict)
                    else {}
                )
                if "_backup_storage_ids" not in metadata:
                    selection = storage_ids
                    if selection is None and not created:
                        # Backward-compatible recovery for a pre-ledger backup.
                        selection = list(
                            backup.storage_points.values_list("id", flat=True)
                        )
                    normalized_ids, invalid_count = (
                        self._canonical_backup_storage_ids(selection)
                    )
                    metadata["_backup_storage_ids"] = normalized_ids
                    metadata["_backup_storage_invalid_id_count"] = invalid_count
                else:
                    normalized_ids, malformed_count = (
                        self._canonical_backup_storage_ids(
                            metadata.get("_backup_storage_ids")
                        )
                    )
                    metadata["_backup_storage_ids"] = normalized_ids
                    try:
                        persisted_invalid_count = max(
                            0,
                            int(
                                metadata.get("_backup_storage_invalid_id_count")
                                or 0
                            ),
                        )
                    except (TypeError, ValueError):
                        persisted_invalid_count = 0
                    metadata["_backup_storage_invalid_id_count"] = max(
                        persisted_invalid_count,
                        malformed_count,
                    )
                backup.metadata = metadata

            # Only setup UUID if it's new backup. No need to generate same UUID on retry
            if created:
                if schedule_id:
                    schedule = CoreSchedule.objects.get(id=schedule_id)
                    schedule_slug = f"{backup.get_type_display()}-{schedule.name}"
                else:
                    schedule_slug = f"{backup.get_type_display()}"
                n_and_s = f"{self.name} - {schedule_slug}"
                n_and_s_trimmed = (n_and_s[:24]) if len(n_and_s) > 24 else n_and_s
                backup.uuid = slugify(f"bs-{n_and_s_trimmed}-n{self.id}-b{backup.id}").replace("_", "-")
            # A recovery message has reached the provider/local task. Clear only
            # the enqueue lease; the poller will establish its own lease later.
            recovery_lease = None
            if isinstance(backup.metadata, dict):
                metadata = dict(backup.metadata)
                control = metadata.get("_backup_control")
                if isinstance(control, dict) and (
                    "recovery_task_id" in control or "recovery_lease_until" in control
                ):
                    control = dict(control)
                    recovery_lease = (
                        control.get("recovery_task_id"),
                        control.get("recovery_lease_token"),
                    )
                    control.pop("recovery_task_id", None)
                    control.pop("recovery_lease_until", None)
                    control.pop("recovery_lease_token", None)
                    metadata["_backup_control"] = control
                    backup.metadata = metadata
            backup.save()
            CoreBackupRequest.link_backup(
                task_id=celery_task_id,
                node=self,
                backup=backup,
                duplicate=False,
            )
            if recovery_lease and all(recovery_lease):
                backup.release_execution(
                    lease_owner=recovery_lease[0],
                    lease_token=recovery_lease[1],
                    phase="recovery",
                )
            # Persist broker delivery and retry metadata independently from Celery's
            # result backend. This lazily creates the durable execution ledger for old
            # backup rows while leaving the established backup status contract intact.
            backup.initialize_execution(
                celery_task_id=celery_task_id,
                attempt_no=attempt_no,
                task_name=self.backup_task_name(),
            )

        # Cloud servers and volumes don't have storage points for now. Local source
        # generation may start only after the complete immutable destination request
        # has been reconciled under a renewable lease.
        if is_local_backup and not self._reconcile_local_backup_destinations(
            backup,
            schedule_id,
        ):
            return None

        self.save()
        return backup

    def backup_complete_reset(self, celery_task_id=None):
        self.status = CoreNode.Status.ACTIVE
        self.save()

        if celery_task_id:
            backup = self.get_backup_from_celery_task_id(celery_task_id)
            if backup:
                backup.status = UtilBackup.Status.COMPLETE
                backup.save()

    def backup_timeout_reset(self, celery_task_id=None):
        self.status = CoreNode.Status.ACTIVE
        self.save()

        if celery_task_id:
            backup = self.get_backup_from_celery_task_id(celery_task_id)
            if backup:
                # A soft time limit during a provider create is ambiguous: the
                # remote API may have accepted the request even though this worker
                # stopped waiting. Keep the row recoverable and retain the create
                # lease so the recovery sweep performs a deterministic lookup after
                # the lease expires. Local dump/upload tasks have no create lease and
                # retain the terminal TIMEOUT behavior.
                metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
                control = metadata.get("_backup_control")
                if isinstance(control, dict) and control.get("create_lease_until"):
                    backup.status = UtilBackup.Status.RETRYING
                else:
                    backup.status = UtilBackup.Status.TIMEOUT
                backup.save()

    def backup_retrying_reset(self, celery_task_id):
        backup = self.get_backup_from_celery_task_id(celery_task_id)
        if backup:
            backup.status = UtilBackup.Status.RETRYING
            # Do not clear a provider-create lease here. An exception may represent
            # an accepted remote request whose response was lost; releasing the
            # lease would let the immediate retry overlap that unknown request.
            # Successful provider calls release the lease in run_provider_create,
            # while the recovery sweep takes over after the conservative lease
            # expires and performs the provider-specific deterministic lookup.
            metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
            control = metadata.get("_backup_control")
            if isinstance(control, dict):
                metadata = dict(metadata)
                control = dict(control)
                metadata["_backup_control"] = control
                backup.metadata = metadata
            backup.save(update_fields=["status", "metadata", "modified"])

    def backup_max_retries_reached(self, celery_task_id):
        # 2022-June - don't do max paused retry. This creates more problem.
        # self.status = self.Status.PAUSED_MAX_RETRIES
        # self.save()

        # pause schedules, otherwise they will keep running
        # 2022-May - don't need to disable all schedules. Just pause the node.
        # for schedule in self.schedules.filter(status=CoreSchedule.Status.ACTIVE):
        #     schedule.status = CoreSchedule.Status.PAUSED
        #     schedule.save()

        backup = self.get_backup_from_celery_task_id(celery_task_id)
        if backup:
            backup.status = UtilBackup.Status.MAX_RETRY_FAILED
            backup.save()

    def restart_reset(self):
        # node_type_object = getattr(self, self.connection.integration.code)
        # node_type_object.backups.filter()
        self.status = self.Status.ACTIVE
        self.save()

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def notify_storage_validation_fail(self, storage, backup):
        """Email 'fail' recipients when a storage point fails validation at backup start.

        Called from backup_initiate, so everything is wrapped: a notification
        problem must never break the backup itself. The email's action_url is
        built inside the storage_validation_failed template from the injected
        site_app_url + node_id passed here.
        """
        from apps._tasks.helper.tasks import send_postmark_email

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                account = self.connection.account
                data = {
                    "message": f"Storage validation failed for {storage.name} ({storage.type.name}) "
                               f"during backup ({backup.uuid_str}) of your node ({self.name}).",
                    "node_id": self.id,
                    "node_name": self.name,
                    "node_type": self.get_type_display().lower(),
                    "storage_type": storage.type.name,
                    "storage_name": storage.name,
                    "backup_name": backup.uuid_str,
                    "connection_name": self.connection.name,
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }
                for _member, to_email in account.get_notification_recipients("fail"):
                    send_postmark_email.delay(
                        to_email,
                        "storage_validation_failed",
                        data,
                    )
        except Exception as e:
            capture_exception(e)

    def _backup_notification_contract(self, error):
        """Return a public-safe notification contract for a backup failure.

        Provider/client exceptions are inspected only by the existing safe
        classifier.  Their text, response bodies, and exception class names are
        never returned from this method or placed in an account log/email.
        """
        class_name = error.__class__.__name__
        template = "error_during_backup"
        code = None

        if class_name == "ConnectionNotReadyForBackupError":
            code = "CONNECTION_NOT_READY"
            template = "unable_to_start_backup"
        elif class_name == "NodeNotReadyForBackupError":
            code = "NODE_NOT_READY"
            template = "unable_to_start_backup"
        elif class_name in {
            "ConnectionValidationFailedError",
            "IntegrationValidationError",
        }:
            template = "unable_to_start_backup"
            try:
                from apps._tasks.integration.backup.errors import safe_backup_failure

                failure = safe_backup_failure(error, stage="connection")
                classified_code = getattr(failure, "code", "")
            except Exception as classification_error:
                capture_exception(classification_error)
                classified_code = ""
            if classified_code in _BACKUP_NOTIFICATION_SAFE_CODES:
                code = classified_code
            if code in {"SOURCE_EXPORT_FAILED", "BACKUP_FAILED"} or not code:
                code = "CONNECTION_VALIDATION_FAILED"
        elif class_name in {
            "SoftTimeLimitExceeded",
            "NodeBackupTimeoutError",
        }:
            code = "BACKUP_TIMEOUT"
        elif class_name == "NodeBackupStatusCheckTimeOutError":
            code = "BACKUP_STATUS_TIMEOUT"
        elif class_name == "NodeBackupFailedError":
            # Provider adapters may attach a stable code.  Accept it only from
            # the explicit allowlist; never accept arbitrary exception text.
            for attribute in ("error_code", "code"):
                try:
                    candidate = getattr(error, attribute, None)
                except Exception:
                    candidate = None
                if isinstance(candidate, str):
                    candidate = candidate.strip().upper()
                    if candidate in _BACKUP_NOTIFICATION_SAFE_CODES:
                        code = candidate
                        break
            if not code:
                try:
                    from apps._tasks.integration.backup.errors import safe_backup_failure

                    failure = safe_backup_failure(error, stage="backup")
                    classified_code = getattr(failure, "code", "")
                except Exception as classification_error:
                    capture_exception(classification_error)
                    classified_code = ""
                if classified_code in _BACKUP_NOTIFICATION_SAFE_CODES:
                    code = classified_code
                if code in {"SOURCE_EXPORT_FAILED", "CONNECTION_VALIDATION_FAILED"}:
                    code = "BACKUP_FAILED"

        if code not in _BACKUP_NOTIFICATION_SAFE_CODES:
            return None

        retryable = code in {
            "CONNECTION_REFUSED",
            "DNS_FAILURE",
            "TCP_TIMEOUT",
            "WORKER_DISK_FULL",
            "ARCHIVE_VALIDATION_FAILED",
            "SOURCE_EXPORT_FAILED",
            "PROVIDER_RATE_LIMIT",
            "PROVIDER_TIMEOUT",
            "PROVIDER_TRANSIENT_OUTAGE",
            "STORAGE_RATE_LIMITED",
            "STORAGE_TIMEOUT",
            "STORAGE_TRANSIENT_FAILURE",
            "WORKER_LEASE_LOST",
            "BACKUP_TIMEOUT",
            "BACKUP_STATUS_TIMEOUT",
        }
        return {
            "code": code,
            "message": _BACKUP_NOTIFICATION_MESSAGES[code],
            "remediation": _BACKUP_NOTIFICATION_REMEDIATIONS[code],
            "retryable": retryable,
            "template": template,
        }

    def _backup_notification_action_url(self, *, validation=False):
        """Build an allowlisted URL without embedding connection metadata."""
        if validation:
            try:
                integration_code = slugify(
                    str(self.get_integration_alt_code()).lower()
                )[:64]
            except Exception as url_error:
                capture_exception(url_error)
                integration_code = ""
            integration_code = integration_code or "integration"
            return (
                "https://backupsheep.com/console/integration/"
                f"{integration_code}/"
            )

        try:
            node_id = int(self.pk)
        except (TypeError, ValueError):
            node_id = 0
        if self.type in {
            self.Type.CLOUD,
            self.Type.VOLUME,
            self.Type.DATABASE,
            self.Type.WEBSITE,
        }:
            try:
                integration_code = slugify(
                    str(self.get_integration_alt_code()).lower()
                )[:64]
            except Exception as url_error:
                capture_exception(url_error)
                integration_code = ""
            if integration_code:
                return (
                    "https://backupsheep.com/console/setup/"
                    f"{integration_code}/"
                )
        return f"https://backupsheep.com/console/nodes/{node_id}/"

    def _backup_notification_correlation(self, error, code, backup_type):
        """Return a durable execution correlation ID or a deterministic fallback."""
        backup_key = None
        for attribute in ("backup_uuid", "backup_name"):
            try:
                backup_key = getattr(error, attribute, None)
            except Exception:
                backup_key = None
            if backup_key is not None:
                break

        if backup_key is not None:
            try:
                node_type_object = self._integration_object()
                backup = (
                    node_type_object.backups.filter(uuid=str(backup_key))
                    .order_by("-id")
                    .first()
                    if node_type_object
                    else None
                )
                if backup:
                    state = backup.record_execution_error(
                        code=code,
                        message=_BACKUP_NOTIFICATION_MESSAGES[code],
                    )
                    if state and getattr(state, "correlation_id", None):
                        return str(state.correlation_id)
            except Exception as execution_error:
                # The notification still has a safe deterministic ID if a legacy
                # backup row cannot yet materialize its execution ledger.
                capture_exception(execution_error)

        try:
            supplied_correlation = getattr(error, "correlation_id", None)
            return str(uuid.UUID(str(supplied_correlation)))
        except (AttributeError, TypeError, ValueError):
            pass

        try:
            node_id = int(self.pk)
        except (TypeError, ValueError):
            node_id = 0
        # uuid5 makes the fallback stable across Celery redelivery without storing
        # the backup UUID, endpoint, or any exception-derived text.
        seed = f"backup-notification:{node_id}:{code}:{backup_type}"
        return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

    def _notify_backup_fail_safe(self, error, backup_type):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime

        class_name = error.__class__.__name__
        if class_name in {
            "ConnectionNotReadyForBackupError",
            "NodeNotReadyForBackupError",
            "NodeBackupFailedError",
        } and getattr(error, "attempt_no", None) != 1:
            return

        contract = self._backup_notification_contract(error)
        if not contract:
            return

        backup_type_value = str(backup_type)
        if backup_type_value == "1":
            backup_type_label = "On-Demand"
        elif backup_type_value == "2":
            backup_type_label = "Scheduled"
        else:
            backup_type_label = "Other"

        try:
            correlation_id = self._backup_notification_correlation(
                error,
                contract["code"],
                backup_type_label,
            )
            account = self.connection.account
            if not self.notify_on_fail or not account.notify_on_fail:
                return

            recipients = account.get_notification_recipients("fail")
            member = recipients[0][0] if recipients else None
            try:
                notification_timezone = pytz.timezone(
                    (getattr(member, "timezone", None) or "UTC")
                )
            except Exception:
                notification_timezone = pytz.UTC

            date_time = datetime.now(tz=notification_timezone).strftime(
                "%b %d %Y - %I:%M%p %Z"
            )
            is_validation = contract["template"] == "unable_to_start_backup"
            # Deliberately omit node/connection names and all location fields:
            # those fields can contain endpoints, usernames, or paths supplied
            # during integration setup.
            data = {
                "node_id": self.pk,
                "node_type": self.get_type_display().lower(),
                "node_status": self.get_status_display(),
                "backup_time": date_time,
                "action_url": self._backup_notification_action_url(
                    validation=is_validation
                ),
                "backup_type": backup_type_label,
                "error": contract["code"],
                "error_code": contract["code"],
                "message": contract["message"],
                "error_details": contract["message"],
                "remediation": contract["remediation"],
                "retryable": contract["retryable"],
                "correlation_id": correlation_id,
                "help_url": "https://support.backupsheep.com",
                "sender_name": "BackupSheep - Notification Bot",
            }

            account.create_log(data=data)
            for _member, to_email in recipients:
                send_postmark_email.delay(
                    to_email,
                    contract["template"],
                    data,
                )
        except Exception as notification_error:
            capture_exception(notification_error)

    def notify_backup_fail(self, error, backup_type):
        """Persist and send only the stable public backup-failure contract."""
        return self._notify_backup_fail_safe(error, backup_type)

    def notify_upload_fail(self, error, backup, storage):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime

        # Keep full diagnostics in Sentry only. The account log and email are
        # a stable public contract and must never contain provider bodies,
        # command lines, credentials, hostnames, or exception text.
        capture_exception(error)
        safe_code = getattr(error, "error_code", None)
        if not isinstance(safe_code, str) or safe_code not in _BACKUP_NOTIFICATION_SAFE_CODES:
            safe_code = "STORAGE_UPLOAD_FAILED"
        safe_message = _BACKUP_NOTIFICATION_MESSAGES[safe_code]

        if backup.type == 1:
            backup_type = "On-Demand"
        elif backup.type == 2:
            backup_type = "Scheduled"
        else:
            backup_type = "n/a"

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                account = self.connection.account
                # Email every eligible member (notify_on_fail honored; the primary
                # membership is always included) instead of only the primary member.
                recipients = account.get_notification_recipients("fail")

                member = recipients[0][0] if recipients else None

                timezone = pytz.timezone((member.timezone if member else None) or "UTC")
                now = datetime.now()

                date_time = now.astimezone(timezone).strftime("%b %d %Y - %I:%M%p %Z")

                action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                data = {
                    "node_type": self.get_type_display().lower(),
                    "node_status": self.get_status_display(),
                    "node_name": self.name,
                    "backup_time": date_time,
                    "storage_type": storage.type.name,
                    "storage_name": storage.name,
                    "connection_name": self.connection.name,
                    "connection_status": self.connection.get_status_display(),
                    "action_url": action_url,
                    "backup_type": backup_type,
                    "endpoint_name": self.connection.location.name,
                    "endpoint_location": self.connection.location.location,
                    "endpoint_ip": self.connection.location.ip_address,
                    "endpoint_ipv6": self.connection.location.ip_address_v6,
                    "error": safe_code,
                    "error_code": safe_code,
                    "error_details": safe_message,
                    "message_detail": safe_message,
                    "message": "upload_fail",
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }

                self.connection.account.create_log(data=data)

                for _member, to_email in recipients:
                    send_postmark_email.delay(
                        to_email,
                        "unable_to_upload_backup",
                        data,
                    )
        except Exception as e:
            capture_exception(e)

    def notify_backup_success(self, backup):
        from apps._tasks.helper.tasks import send_postmark_email

        try:
            if self.notify_on_success and self.connection.account.notify_on_success:
                account = self.connection.account
                # Email every eligible member (notify_on_success honored; the primary
                # membership is always included) instead of only the primary member.
                recipients = account.get_notification_recipients("success")

                member = recipients[0][0] if recipients else None

                timezone = pytz.timezone((member.timezone if member else None) or "UTC")
                date_time = backup.modified.astimezone(timezone).strftime(
                    "%b %d %Y - %I:%M%p %Z"
                )

                time_delta = backup.created - backup.modified

                if backup.type == 1:
                    backup_type = "On-Demand"
                elif backup.type == 2:
                    backup_type = "Scheduled"
                else:
                    backup_type = "n/a"

                node_type_object = self._integration_object()

                action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                # if self.type == self.Type.CLOUD:
                #     action_url = f"https://backupsheep.com/console/clouds/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.VOLUME:
                #     action_url = f"https://backupsheep.com/console/volumes/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.DATABASE:
                #     action_url = f"https://backupsheep.com/console/databases/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.WEBSITE:
                #     action_url = f"https://backupsheep.com/console/websites/files_n_folders/{node_type_object.id}/"
                # else:
                #     action_url = f"https://backupsheep.com/console/"

                data = {
                    "message": f"Backup successful for node {self.name}."
                               f" Backup Name: {backup.uuid_str}."
                               f" Node url: {action_url}",
                    "node_type": self.get_type_display().lower(),
                    "node_status": self.get_status_display(),
                    "node_name": self.name,
                    "backup_time": date_time,
                    "backup_size": backup.size_display(),
                    "connection_name": self.connection.name,
                    "connection_status": self.connection.get_status_display(),
                    "action_url": action_url,
                    "backup_name": backup.uuid_str,
                    "backup_type": backup_type,
                    "backup_duration": humanize.precisedelta(time_delta),
                    "endpoint_name": self.connection.location.name,
                    "endpoint_ip": self.connection.location.ip_address,
                    "endpoint_ipv6": self.connection.location.ip_address_v6,
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }

                self.connection.account.create_log(data=data)

                for _member, to_email in recipients:
                    send_postmark_email.delay(
                        to_email,
                        "backup_is_complete",
                        data,
                    )
        except Exception as e:
            capture_exception(e)

# class CoreStorageUsage(TimeStampedModel):
#     account = models.ForeignKey(CoreAccount, related_name='storage_usage', on_delete=models.PROTECT)
#
#     size = models.BigIntegerField(null=True)
#
#     created = models.BigIntegerField()
#
#     class Meta:
#         db_table = 'core_storage_usage'
#
#     def save(self, *args, **kwargs):
#         """ On save, update timestamps """
#         if not self.id:
#             self.created = int(time.time())
#         self.modified = int(time.time())
#
#         return super(CoreStorageUsage, self).save(*args, **kwargs)
