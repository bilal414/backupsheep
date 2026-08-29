import json
import hashlib
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone as datetime_timezone
from email.utils import parsedate_to_datetime

import dropbox
import humanfriendly
import paramiko
from apps.api.v1.utils.http import request_timeout, requests
from botocore.exceptions import ClientError
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.json import DjangoJSONEncoder
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models, IntegrityError, transaction
from django.db.models import UniqueConstraint
from django.urls import reverse
from django.utils import timezone
from google.cloud.exceptions import NotFound
from model_utils import Choices
from model_utils.fields import StatusField
from model_utils.models import TimeStampedModel
from ovh import ResourceNotFoundError
from paramiko.ssh_exception import SSHException
from sentry_sdk import capture_exception, capture_message

from apps.console.storage.models import CoreStorage
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeBackupStatusCheckTimeOutError,
    NodeBackupStatusCheckCallError,
    NodeSnapshotDeleteFailed,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.api.v1.utils.boto import (
    bounded_boto3_client,
    bounded_ibm_boto3_client,
)
from ..utils.models import BackupExecutionLeaseLostError, UtilBackup
from apps._tasks.helper.tasks import delete_from_disk
from backupsheep.celery import app
from botocore.config import Config
from ..vultr import (
    is_terminal_snapshot_failure,
    provider_classification,
    record_provider_result,
    snapshot_matches_with_recorded_source,
    snapshot_state,
    vultr_request_timeout,
)


def _presigned_url_expiry():
    """Return the five-minute signed-URL default with a one-hour hard ceiling."""
    try:
        configured = int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 5 * 60))
    except (TypeError, ValueError):
        configured = 5 * 60
    return min(max(configured, 1), 60 * 60)


def _stop_legacy_backup_container(container_name):
    """Best-effort cleanup for the retired per-backup Docker execution path.

    Stock containers deliberately receive neither a Docker client nor the daemon
    socket. Process-managed legacy deployments may still provide the client, but a
    database value must never become a shell command or an arbitrary container name.
    """
    candidate = str(container_name or "").lower()
    suffix = "-storage" if candidate.endswith("-storage") else ""
    identifier = candidate[: -len(suffix)] if suffix else candidate
    try:
        canonical_identifier = str(uuid.UUID(identifier))
    except (ValueError, AttributeError, TypeError):
        return
    if identifier != canonical_identifier:
        return

    docker_cli = shutil.which("docker")
    if not docker_cli:
        return
    try:
        subprocess.run(
            [docker_cli, "stop", f"{canonical_identifier}{suffix}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def _cancel_storage_point_uploads(storage_points):
    """Cancel deliveries without overwriting durable provider-boundary evidence."""

    for storage_point in storage_points:
        with transaction.atomic():
            current = storage_point.__class__.objects.select_for_update().get(
                pk=storage_point.pk
            )
            task_id = current.celery_task_id
            current.status = current.Status.CANCELLED
            current.save(update_fields=["status", "modified"])
        app.control.revoke(task_id, terminate=True)


class StoragePointLeaseLostError(RuntimeError):
    """A stale storage worker attempted to persist after losing its fence."""


class RestoreExecutionLeaseLostError(RuntimeError):
    """A stale restore worker attempted to persist after losing its fence."""


class AWSDeleteLeaseLost(RuntimeError):
    """A stale AWS deletion worker was fenced by a replacement."""


class AWSDeleteOwnershipError(RuntimeError):
    """AWS did not provide exact ownership proof for a deletion target."""


class AWSDeleteUnprovenNotFound(RuntimeError):
    """AWS reported an absent target before ownership had been proven."""


class AWSDeleteAmbiguous(RuntimeError):
    """AWS deletion was accepted or rejected ambiguously and needs reconciliation."""


class AWSNativeLeaseLost(RuntimeError):
    """A stale native AWS worker attempted to persist after losing its fence."""


class AWSNativeOwnershipError(RuntimeError):
    """Native EC2/EBS identity or ownership proof failed closed."""


class AWSNativeDuplicateMatch(RuntimeError):
    """More than one exact native EC2/EBS resource matched a witness."""


class AWSNativeMalformedResponse(RuntimeError):
    """AWS returned a native EC2/EBS response that cannot be reconciled safely."""


class AWSNativeResourceNotFound(RuntimeError):
    """An exact native AWS resource pointer is not currently provider-visible."""


class AWSNativeReconciliationPending(RuntimeError):
    """An ambiguous native create is still inside its no-write reconciliation window."""

    code = "PROVIDER_CREATE_OUTCOME_UNKNOWN"
    error_code = code
    retryable = True
    unknown_outcome = True


class HetznerDeleteLeaseLost(RuntimeError):
    """A stale Hetzner deletion worker lost its fenced checkpoint lease."""


class HetznerDeleteOwnershipError(RuntimeError):
    """The Hetzner snapshot did not match the durable backup witness."""


class HetznerDeleteUnprovenNotFound(RuntimeError):
    """Hetzner reported absence before ownership and delete intent were durable."""


class HetznerDeleteAmbiguous(RuntimeError):
    """A Hetzner delete response was lost and must be reconciled read-only."""


class UpCloudDeleteLeaseLost(RuntimeError):
    """A stale UpCloud deletion worker lost its durable checkpoint lease."""


class UpCloudDeleteOwnershipError(RuntimeError):
    """An UpCloud backup storage did not match its immutable witness."""


class UpCloudDeleteUnprovenNotFound(RuntimeError):
    """UpCloud reported absence before an owned delete intent was durable."""


class UpCloudDeleteRetryable(RuntimeError):
    """An UpCloud delete check or mutation needs bounded reconciliation."""

    def __init__(self, code, *, ambiguous=False):
        super().__init__(str(code or "PROVIDER_TRANSIENT_OUTAGE"))
        self.code = str(code or "PROVIDER_TRANSIENT_OUTAGE")[:64]
        self.ambiguous = bool(ambiguous)


class RDSLeaseLost(RuntimeError):
    """A stale RDS worker attempted to persist after losing its fence."""


class RDSOwnershipError(RuntimeError):
    """An RDS snapshot did not provide exact ownership proof."""


class RDSDuplicateMatch(RuntimeError):
    """More than one exact RDS snapshot matched a deterministic identity."""


class RDSUnprovenNotFound(RuntimeError):
    """RDS reported a missing snapshot before deletion ownership was proven."""


class RDSMalformedResponse(RuntimeError):
    """RDS returned a response that cannot be safely reconciled."""


class RDSOwnershipTagPending(RuntimeError):
    """A just-created RDS snapshot is visible before its ownership tag."""


_PROVIDER_AUTH_HTTP_CODES = {401, 403}
_PROVIDER_TRANSIENT_HTTP_CODES = {408, 425, 500, 502, 503, 504}
_PROVIDER_NOT_FOUND_ERROR_CODES = {
    "dbinstancenotfound",
    "dbinstancenotfoundfault",
    "dbsnapshotnotfound",
    "dbsnapshotnotfoundfault",
    "invalidamiid.notfound",
    "invalidsnapshot.notfound",
    "notfound",
    "resourcenotfoundexception",
}
_PROVIDER_AUTH_ERROR_CODES = {
    "accessdenied",
    "accessdeniedexception",
    "authfailure",
    "expiredtoken",
    "expiredtokenexception",
    "invalidclienttokenid",
    "signaturedoesnotmatch",
    "unauthorizedoperation",
    "unrecognizedclientexception",
}
_PROVIDER_RATE_LIMIT_ERROR_CODES = {
    "limitexceededexception",
    "requestlimitexceeded",
    "throttledexception",
    "throttling",
    "throttlingexception",
    "toomanyrequestsexception",
}
_PROVIDER_TRANSIENT_ERROR_CODES = {
    "internalerror",
    "internalfailure",
    "priorrequestnotcomplete",
    "requestexpired",
    "requesttimeout",
    "requesttimeoutexception",
    "serviceunavailable",
    "serviceunavailableexception",
}


def _provider_retry_at(headers=None, *, default_seconds=60):
    """Return a bounded retry deadline without persisting provider response data."""
    headers = headers or {}
    value = headers.get("Retry-After") or headers.get("retry-after")
    seconds = default_seconds
    if value not in (None, ""):
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            try:
                retry_date = parsedate_to_datetime(str(value))
                if timezone.is_naive(retry_date):
                    retry_date = timezone.make_aware(retry_date)
                seconds = int((retry_date - timezone.now()).total_seconds())
            except (TypeError, ValueError, OverflowError):
                seconds = default_seconds
    return timezone.now() + timedelta(seconds=max(1, min(int(seconds), 86400)))


def _record_provider_outcome(
    backup,
    *,
    provider,
    category,
    operation="poll",
    provider_status=None,
    error_code=None,
    retry_at=None,
    http_status=None,
    resource_id=None,
    operation_id=None,
):
    """Persist only bounded, non-sensitive provider outcome evidence."""
    fence = {}
    lease_owner = getattr(backup, "_required_backup_lease_owner", "")
    lease_token = getattr(backup, "_required_backup_lease_token", "")
    if lease_owner and lease_token:
        fence = {
            "lease_owner": lease_owner,
            "lease_token": lease_token,
            "require_live": True,
        }
    safe_metadata = {"provider": provider, "operation": operation}
    if http_status is not None:
        safe_metadata["http_status"] = int(http_status)
    saved = backup.record_provider_reference(
        operation_id=operation_id,
        resource_id=resource_id,
        provider_status=provider_status or category,
        metadata=safe_metadata,
        **fence,
    )
    if fence and saved is None:
        raise BackupExecutionLeaseLostError(
            "The backup worker lost its execution lease while recording provider outcome."
        )
    if error_code:
        reconciliation_reason = None
        reconciliation_metadata = None
        if error_code == "PROVIDER_RECONCILIATION_REQUIRED":
            # A categorized provider poll can run after a previous successful
            # adoption marked the execution resolved. Preserve a bounded,
            # provider-independent reconciliation witness for the durable state
            # machine; never pass provider response or exception text here.
            reconciliation_reason = "provider_reconciliation_required"
            reconciliation_metadata = {
                "source": "provider_outcome",
                "error_code": error_code,
            }
        saved = backup.record_execution_error(
            code=error_code,
            message=backup.EXECUTION_ERROR_MESSAGES.get(
                error_code, "The provider operation failed."
            ),
            retry_at=retry_at,
            reconciliation_reason=reconciliation_reason,
            reconciliation_metadata=reconciliation_metadata,
            **fence,
        )
        if fence and saved is None:
            raise BackupExecutionLeaseLostError(
                "The backup worker lost its execution lease while recording provider error."
            )


def _provider_http_outcome(backup, response, *, provider, operation="poll"):
    """Classify an unsuccessful HTTP response into terminal or retryable state."""
    status_code = int(getattr(response, "status_code", 0) or 0)
    headers = getattr(response, "headers", None) or {}
    if status_code == 404:
        category, error_code, result = (
            "not_found",
            "PROVIDER_NOT_FOUND",
            UtilBackup.Status.FAILED,
        )
        retry_at = None
    elif status_code in _PROVIDER_AUTH_HTTP_CODES:
        category, error_code, result = (
            "auth_failed",
            "PROVIDER_AUTH_FAILED",
            UtilBackup.Status.FAILED,
        )
        retry_at = None
    elif status_code == 429:
        category, error_code, result = (
            "rate_limited",
            "PROVIDER_RATE_LIMIT",
            UtilBackup.Status.IN_PROGRESS,
        )
        retry_at = _provider_retry_at(headers)
    elif status_code in _PROVIDER_TRANSIENT_HTTP_CODES or status_code >= 500:
        category, error_code, result = (
            "transient_outage",
            "PROVIDER_TRANSIENT_OUTAGE",
            UtilBackup.Status.IN_PROGRESS,
        )
        retry_at = _provider_retry_at(headers)
    else:
        category, error_code, result = (
            "request_failed",
            "PROVIDER_REQUEST_FAILED",
            UtilBackup.Status.FAILED,
        )
        retry_at = None
    _record_provider_outcome(
        backup,
        provider=provider,
        category=category,
        operation=operation,
        error_code=error_code,
        retry_at=retry_at,
        http_status=status_code,
        resource_id=getattr(backup, "unique_id", None),
        operation_id=getattr(backup, "action_id", None),
    )
    return result


def _provider_exception_details(error):
    """Extract status/code/headers without exposing an exception or response body."""
    status_code = None
    error_code = ""
    headers = {}
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata") or {}
        status_code = metadata.get("HTTPStatusCode")
        headers = metadata.get("HTTPHeaders") or {}
        error_code = str((response.get("Error") or {}).get("Code") or "")
    elif response is not None:
        status_code = getattr(response, "status_code", None)
        headers = getattr(response, "headers", None) or {}
    status_code = status_code or getattr(error, "status", None) or getattr(
        error, "status_code", None
    )
    return status_code, error_code.lower(), headers


def _provider_exception_outcome(backup, error, *, provider, operation="poll"):
    status_code, provider_code, headers = _provider_exception_details(error)
    classified = None
    if provider_code in _PROVIDER_NOT_FOUND_ERROR_CODES:
        classified = (
            "not_found",
            "PROVIDER_NOT_FOUND",
            UtilBackup.Status.FAILED,
            None,
        )
    elif provider_code in _PROVIDER_AUTH_ERROR_CODES:
        classified = (
            "auth_failed",
            "PROVIDER_AUTH_FAILED",
            UtilBackup.Status.FAILED,
            None,
        )
    elif provider_code in _PROVIDER_RATE_LIMIT_ERROR_CODES:
        classified = (
            "rate_limited",
            "PROVIDER_RATE_LIMIT",
            UtilBackup.Status.IN_PROGRESS,
            _provider_retry_at(headers),
        )
    elif provider_code in _PROVIDER_TRANSIENT_ERROR_CODES:
        classified = (
            "transient_outage",
            "PROVIDER_TRANSIENT_OUTAGE",
            UtilBackup.Status.IN_PROGRESS,
            _provider_retry_at(headers),
        )
    elif status_code:
        response = type(
            "SafeProviderResponse",
            (),
            {"status_code": status_code, "headers": headers},
        )()
        return _provider_http_outcome(
            backup, response, provider=provider, operation=operation
        )

    if classified is not None:
        category, error_code, result, retry_at = classified
        _record_provider_outcome(
            backup,
            provider=provider,
            category=category,
            operation=operation,
            error_code=error_code,
            retry_at=retry_at,
            http_status=status_code,
            resource_id=getattr(backup, "unique_id", None),
            operation_id=getattr(backup, "action_id", None),
        )
        return result

    exception_name = error.__class__.__name__.lower()
    if isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
        category, error_code, result = (
            "timeout",
            "PROVIDER_TIMEOUT",
            UtilBackup.Status.IN_PROGRESS,
        )
        retry_at = _provider_retry_at()
    elif isinstance(error, requests.exceptions.ConnectionError):
        category, error_code, result = (
            "transient_outage",
            "PROVIDER_TRANSIENT_OUTAGE",
            UtilBackup.Status.IN_PROGRESS,
        )
        retry_at = _provider_retry_at()
    elif any(
        token in exception_name
        for token in ("credential", "auth", "permission", "accessdenied", "relatedobject")
    ):
        category, error_code, result, retry_at = (
            "auth_failed",
            "PROVIDER_AUTH_FAILED",
            UtilBackup.Status.FAILED,
            None,
        )
    else:
        category, error_code, result, retry_at = (
            "client_error",
            "PROVIDER_CLIENT_ERROR",
            UtilBackup.Status.FAILED,
            None,
        )
    _record_provider_outcome(
        backup,
        provider=provider,
        category=category,
        operation=operation,
        error_code=error_code,
        retry_at=retry_at,
        resource_id=getattr(backup, "unique_id", None),
        operation_id=getattr(backup, "action_id", None),
    )
    return result


def _provider_in_progress(backup, *, provider, state, resource_id=None, operation_id=None):
    _record_provider_outcome(
        backup,
        provider=provider,
        category="in_progress",
        provider_status=str(state or "in_progress").lower(),
        resource_id=resource_id,
        operation_id=operation_id,
    )
    return UtilBackup.Status.IN_PROGRESS


def _provider_failed(backup, *, provider, state, code="PROVIDER_FAILED"):
    _record_provider_outcome(
        backup,
        provider=provider,
        category="terminal_failure",
        provider_status=str(state or "failed").lower(),
        error_code=code,
        resource_id=getattr(backup, "unique_id", None),
        operation_id=getattr(backup, "action_id", None),
    )
    return UtilBackup.Status.FAILED


def _rds_error_code(error):
    """Return a normalized AWS error code without retaining provider details."""
    _status_code, provider_code, _headers = _provider_exception_details(error)
    return provider_code


def _rds_not_found(error):
    return _rds_error_code(error) in {
        "dbinstancenotfound",
        "dbinstancenotfoundfault",
        "dbsnapshotnotfound",
        "dbsnapshotnotfoundfault",
        "resourcenotfoundexception",
        "notfound",
    }


def _rds_snapshot_arn_identity(snapshot):
    """Extract account, region, and resource id from an RDS snapshot ARN.

    RDS does not echo account and region as independent fields on every response;
    the ARN is the authoritative provider identity returned by the API. Requiring
    this exact shape keeps adoption/deletion fail-closed when a mock, proxy, or
    differently scoped endpoint omits ownership data.
    """
    if not isinstance(snapshot, dict):
        return None
    arn = str(snapshot.get("DBSnapshotArn") or "")
    match = re.fullmatch(
        r"arn:(?P<partition>[^:]+):rds:(?P<region>[^:]+):(?P<account>[0-9]{12}):snapshot:(?P<identifier>[^:]+)",
        arn,
    )
    if not match:
        return None
    return {
        "partition": match.group("partition"),
        "region": match.group("region"),
        "account_id": match.group("account"),
        "snapshot_identifier": match.group("identifier"),
    }


def _rds_json(value):
    """Normalize datetime values before storing an AWS response in JSONField."""
    try:
        return json.loads(json.dumps(value, cls=DjangoJSONEncoder))
    except (TypeError, ValueError) as error:
        raise RDSMalformedResponse("The RDS response was not JSON serializable.") from error


def _provider_owned(resource, *, resource_id=None, marker=None, source_fields=None):
    """Require every requested provider identity field to be present and exact.

    Missing identity is not ownership proof. Provider responses often omit fields
    because credentials are scoped differently or an endpoint returned another
    resource shape; accepting that absence would make polling/deletion fail open.
    """
    if not isinstance(resource, dict):
        return False
    actual_resource_id = (
        resource.get("id")
        or resource.get("uuid")
        or resource.get("ImageId")
        or resource.get("SnapshotId")
        or resource.get("DBSnapshotIdentifier")
    )
    if resource_id is not None and str(actual_resource_id) != str(resource_id):
        return False
    if marker is not None and str(
        resource.get("name")
        or resource.get("Name")
        or resource.get("DBSnapshotIdentifier")
        or resource.get("description")
        or resource.get("Description")
        or resource.get("title")
        or resource.get("displayName")
        or ""
    ) != str(marker):
        return False
    for field, expected in source_fields or ():
        if expected is None:
            continue
        actual = resource.get(field)
        if isinstance(actual, dict):
            actual = actual.get("id")
        if actual in (None, "") or str(actual) != str(expected):
            return False
    return True


def _poll_ovh_snapshot(backup, snapshots, *, provider, ready_state, source_id):
    candidates = [
        item
        for item in (snapshots or [])
        if str(item.get("id") or "")
        in {str(backup.unique_id or ""), str(backup.uuid_str or "")}
        or str(item.get("name") or "")
        in {str(backup.unique_id or ""), str(backup.uuid_str or "")}
    ]
    if len(candidates) > 1:
        return _provider_failed(
            backup,
            provider=provider,
            state="duplicate_matches",
            code="PROVIDER_OWNERSHIP_MISMATCH",
        )
    if not candidates:
        return _provider_in_progress(
            backup,
            provider=provider,
            state="snapshot_not_visible",
            resource_id=backup.unique_id,
        )
    snapshot = candidates[0]
    source_value = (
        snapshot.get("instanceId")
        or snapshot.get("volumeId")
        or snapshot.get("sourceId")
    )
    name = snapshot.get("name")
    if str(name or "") != str(backup.uuid_str) or str(
        source_value or ""
    ) != str(source_id):
        return _provider_failed(
            backup,
            provider=provider,
            state="ownership_mismatch",
            code="PROVIDER_OWNERSHIP_MISMATCH",
        )
    state = str(snapshot.get("status") or "").lower()
    if state == ready_state:
        backup.unique_id = snapshot.get("id") or backup.unique_id
        backup.size_gigabytes = snapshot.get("size")
        backup.set_provider_metadata(snapshot)
        backup.status = UtilBackup.Status.COMPLETE
        backup.save()
        _record_provider_outcome(
            backup,
            provider=provider,
            category="complete",
            provider_status=state,
            resource_id=backup.unique_id,
        )
        return UtilBackup.Status.COMPLETE
    if state in {"error", "failed", "deleted", "deleting"}:
        return _provider_failed(backup, provider=provider, state=state)
    return _provider_in_progress(
        backup,
        provider=provider,
        state=state,
        resource_id=backup.unique_id,
    )


def _ovh_snapshot_owned_for_delete(backup, snapshots, *, source_id):
    matches = [
        item
        for item in (snapshots or [])
        if str(item.get("id") or "") == str(backup.unique_id or "")
    ]
    if len(matches) != 1:
        return False
    snapshot = matches[0]
    name = snapshot.get("name")
    source_value = (
        snapshot.get("instanceId")
        or snapshot.get("volumeId")
        or snapshot.get("sourceId")
    )
    return str(name or "") == str(backup.uuid_str) and str(
        source_value or ""
    ) == str(source_id)


class CoreBackupExecution(TimeStampedModel):
    """Provider-independent durable orchestration state for any backup row.

    Existing backup statuses remain the public lifecycle contract. This companion
    record owns worker fencing, retry/reconciliation evidence, and progress so a
    process crash cannot turn Celery delivery state into the source of truth.
    """

    class ReconciliationState(models.TextChoices):
        NONE = "none", "None"
        REQUIRED = "required", "Required"
        IN_PROGRESS = "in_progress", "In Progress"
        RESOLVED = "resolved", "Resolved"
        MANUAL_REVIEW = "manual_review", "Manual Review"

    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    backup_content_type = models.ForeignKey(
        ContentType,
        related_name="backupsheep_backup_executions",
        on_delete=models.CASCADE,
    )
    backup_object_id = models.PositiveBigIntegerField()
    backup = GenericForeignKey(
        "backup_content_type", "backup_object_id", for_concrete_model=False
    )

    celery_task_id = models.CharField(max_length=255, blank=True, default="")
    task_name = models.CharField(max_length=255, blank=True, default="")
    worker_name = models.CharField(max_length=255, blank=True, default="")
    attempt_count = models.PositiveIntegerField(default=0)
    delivery_count = models.PositiveIntegerField(default=0)
    claim_count = models.PositiveIntegerField(default=0)
    phase = models.CharField(max_length=64, blank=True, default="")

    lease_owner = models.CharField(max_length=255, blank=True, default="")
    lease_token = models.UUIDField(null=True, blank=True, editable=False)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    reconciliation_state = models.CharField(
        max_length=24,
        choices=ReconciliationState.choices,
        default=ReconciliationState.NONE,
    )
    reconciliation_reason = models.CharField(max_length=255, blank=True, default="")
    reconciliation_metadata = models.JSONField(default=dict, blank=True)

    last_error_code = models.CharField(max_length=64, blank=True, default="")
    last_error_message = models.TextField(blank=True, default="")
    last_error_at = models.DateTimeField(null=True, blank=True)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    progress_completed = models.PositiveBigIntegerField(default=0)
    progress_total = models.PositiveBigIntegerField(null=True, blank=True)
    progress_unit = models.CharField(max_length=32, blank=True, default="")

    provider_operation_id = models.CharField(max_length=255, blank=True, default="")
    provider_resource_id = models.CharField(max_length=255, blank=True, default="")
    provider_idempotency_key = models.CharField(
        max_length=255, blank=True, default=""
    )
    provider_status = models.CharField(max_length=64, blank=True, default="")
    provider_metadata = models.JSONField(default=dict, blank=True)

    # Integrity of the provider/local source artifact before it fans out to one or
    # more storage destinations. Per-destination evidence lives in CoreBackupArtifact.
    artifact_bytes = models.PositiveBigIntegerField(default=0)
    artifact_checksum_algorithm = models.CharField(
        max_length=32, blank=True, default=""
    )
    artifact_checksum = models.CharField(max_length=255, blank=True, default="")
    artifact_verified_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "core_backup_execution"
        constraints = [
            models.UniqueConstraint(
                fields=("backup_content_type", "backup_object_id"),
                name="unique_backup_execution",
            )
        ]
        indexes = [
            models.Index(
                fields=("lease_expires_at",), name="backup_exec_lease_idx"
            ),
            models.Index(
                fields=("reconciliation_state", "next_retry_at"),
                name="backup_exec_reconcile_idx",
            ),
        ]

    def __str__(self):
        return f"{self.backup_content_type_id}:{self.backup_object_id}:{self.correlation_id}"

    def lease_matches(
        self,
        owner,
        token,
        *,
        phase=None,
        now=None,
        require_live=True,
    ):
        if not self.lease_token or str(self.lease_token) != str(token or ""):
            return False
        if self.lease_owner != str(owner or ""):
            return False
        if phase is not None and self.phase != str(phase):
            return False
        if require_live:
            now = now or timezone.now()
            if not self.lease_expires_at or self.lease_expires_at <= now:
                return False
        return True

    def lease_is_active(self, now=None):
        now = now or timezone.now()
        return bool(
            self.lease_token
            and self.lease_expires_at
            and self.lease_expires_at > now
        )

    def lease_is_stale(self, now=None):
        now = now or timezone.now()
        return bool(
            (self.lease_owner or self.lease_token or self.lease_expires_at)
            and (not self.lease_expires_at or self.lease_expires_at <= now)
        )


class CoreBackupEncryptionEnvelope(TimeStampedModel):
    """Durable identity and authenticated-header witness for one backup.

    Wrapped data keys are separate generation records so a root-key rotation never
    requires rewriting a potentially multi-terabyte backup object.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        MANUAL_REVIEW = "manual_review", "Manual review"
        RETIRED = "retired", "Retired"

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    execution = models.OneToOneField(
        CoreBackupExecution,
        related_name="encryption_envelope",
        on_delete=models.CASCADE,
    )
    format_version = models.PositiveSmallIntegerField(default=1)
    algorithm = models.CharField(max_length=32, default="AES-256-GCM-SIV")
    chunk_size = models.PositiveIntegerField(default=4 * 1024 * 1024)
    context_canonical_json = models.CharField(max_length=2048)
    context_sha256 = models.CharField(max_length=64)
    header_sha256 = models.CharField(max_length=64)
    plaintext_byte_count = models.PositiveBigIntegerField(default=0)
    plaintext_sha256 = models.CharField(max_length=64)
    ciphertext_byte_count = models.PositiveBigIntegerField(default=0)
    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.PENDING
    )
    sealed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "core_backup_encryption_envelope"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    format_version=1, algorithm="AES-256-GCM-SIV"
                ),
                name="backup_envelope_bse1_algorithm",
            ),
            models.CheckConstraint(
                condition=models.Q(chunk_size__gte=64 * 1024)
                & models.Q(chunk_size__lte=64 * 1024 * 1024),
                name="backup_envelope_chunk_bounds",
            ),
            models.CheckConstraint(
                condition=~models.Q(status="active")
                | models.Q(sealed_at__isnull=False),
                name="active_backup_envelope_is_sealed",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=("pending", "active", "manual_review", "retired")
                ),
                name="backup_envelope_status_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(context_canonical_json__gt=""),
                name="backup_envelope_context_present",
            ),
            models.CheckConstraint(
                condition=~models.Q(status="active")
                | models.Q(ciphertext_byte_count__gt=0),
                name="active_backup_envelope_has_ciphertext",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(context_sha256__regex=r"^[0-9a-f]{64}$")
                    & models.Q(header_sha256__regex=r"^[0-9a-f]{64}$")
                    & models.Q(plaintext_sha256__regex=r"^[0-9a-f]{64}$")
                ),
                name="backup_envelope_digests_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=("status", "sealed_at"), name="backup_envelope_status_idx"
            )
        ]

    @staticmethod
    def _valid_sha256(value):
        if not isinstance(value, str) or len(value) != 64:
            return False
        try:
            return bytes.fromhex(value).hex() == value
        except ValueError:
            return False

    def clean(self):
        super().clean()
        errors = {}
        for field in ("context_sha256", "header_sha256", "plaintext_sha256"):
            if not self._valid_sha256(getattr(self, field)):
                errors[field] = "Must be a lowercase SHA-256 hexadecimal digest."
        try:
            context = self.get_artifact_context()
        except ValidationError as error:
            errors["context_canonical_json"] = error.messages
        else:
            if context.sha256 != self.context_sha256:
                errors["context_sha256"] = (
                    "The artifact context digest does not match its canonical context."
                )
        if self.status == self.Status.ACTIVE and self.sealed_at is None:
            errors["sealed_at"] = "An active encryption envelope must be sealed."
        if self.status == self.Status.ACTIVE and self.ciphertext_byte_count <= 0:
            errors["ciphertext_byte_count"] = (
                "An active encryption envelope must have ciphertext bytes."
            )
        if errors:
            raise ValidationError(errors)

    def set_artifact_context(self, context):
        from backupsheep.artifact_crypto.context import ArtifactContext

        if not isinstance(context, ArtifactContext):
            raise ValidationError("An ArtifactContext instance is required.")
        canonical = context.canonical_bytes().decode("ascii")
        if len(canonical) > 2048:
            raise ValidationError("The canonical artifact context is too large.")
        self.context_canonical_json = canonical
        self.context_sha256 = context.sha256

    def get_artifact_context(self):
        from backupsheep.artifact_crypto.context import ArtifactContext

        try:
            values = json.loads(self.context_canonical_json)
            context = ArtifactContext.from_mapping(values)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValidationError("The canonical artifact context is invalid.") from error
        if context.canonical_bytes().decode("ascii") != self.context_canonical_json:
            raise ValidationError("The artifact context is not canonical JSON.")
        return context

    def get_active_key_wrap(self):
        """Fail closed unless exactly one active key-wrap generation exists."""

        if self.status != self.Status.ACTIVE or self.sealed_at is None:
            raise ValidationError("The encryption envelope is not active and sealed.")
        return self.key_wraps.get(status=CoreBackupKeyWrap.Status.ACTIVE)

    def validate_restore_state(self):
        """Return immutable restore inputs only for a complete active envelope."""

        self.full_clean()
        context = self.get_artifact_context()
        try:
            key_wrap = self.get_active_key_wrap()
        except (CoreBackupKeyWrap.DoesNotExist, CoreBackupKeyWrap.MultipleObjectsReturned):
            raise ValidationError(
                "The encryption envelope does not have exactly one active key wrap."
            ) from None
        key_wrap.full_clean()
        return context, key_wrap

    def activate_with_key_wrap(self, key_wrap, *, artifacts=(), activated_at=None):
        """Atomically activate custody and publish one or more encrypted artifacts."""

        if self.pk is None or key_wrap.pk is None:
            raise ValidationError("The envelope and key wrap must be durable records.")
        artifact_ids = [artifact.pk for artifact in artifacts]
        if any(value is None for value in artifact_ids):
            raise ValidationError("Published artifacts must be durable records.")
        now = activated_at or timezone.now()
        with transaction.atomic():
            envelope = type(self).objects.select_for_update().get(pk=self.pk)
            wrap = CoreBackupKeyWrap.objects.select_for_update().get(pk=key_wrap.pk)
            if wrap.envelope_id != envelope.pk:
                raise ValidationError("The key wrap belongs to a different envelope.")
            if envelope.status not in {
                self.Status.PENDING,
                self.Status.MANUAL_REVIEW,
            }:
                raise ValidationError("Only a pending envelope can be activated.")
            if wrap.status not in {
                CoreBackupKeyWrap.Status.PENDING,
                CoreBackupKeyWrap.Status.MANUAL_REVIEW,
            }:
                raise ValidationError("Only a pending key wrap can be activated.")
            if envelope.sealed_at is None:
                envelope.sealed_at = now
            envelope.status = self.Status.ACTIVE
            wrap.status = CoreBackupKeyWrap.Status.ACTIVE
            wrap.activated_at = now
            envelope.full_clean()
            wrap.full_clean()
            wrap.save(update_fields=["status", "activated_at", "modified"])
            envelope.save(update_fields=["status", "sealed_at", "modified"])
            for artifact_id in artifact_ids:
                artifact = CoreBackupArtifact.objects.select_for_update().get(
                    pk=artifact_id
                )
                artifact.artifact_format = CoreBackupArtifact.Format.BSE1
                artifact.encryption_envelope = envelope
                artifact.full_clean()
                artifact.save(
                    update_fields=[
                        "artifact_format",
                        "encryption_envelope",
                        "modified",
                    ]
                )
            envelope.validate_restore_state()
        self.refresh_from_db()
        key_wrap.refresh_from_db()
        return self


class CoreBackupKeyWrap(TimeStampedModel):
    """One authenticated wrapping generation of a backup's random data key."""

    class Provider(models.TextChoices):
        LOCAL_FILE = "local-file", "Local file"
        LOCAL_DEVELOPMENT = "local-development", "Local development"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        MANUAL_REVIEW = "manual_review", "Manual review"
        RETIRED = "retired", "Retired"

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    envelope = models.ForeignKey(
        CoreBackupEncryptionEnvelope,
        related_name="key_wraps",
        on_delete=models.CASCADE,
    )
    generation = models.PositiveIntegerField(default=1)
    provider = models.CharField(max_length=32, choices=Provider.choices)
    wrapping_key_id = models.CharField(max_length=2048)
    wrapped_data_key = models.BinaryField(editable=False, max_length=8192)
    wrapped_key_sha256 = models.CharField(max_length=64)
    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.PENDING
    )
    activated_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "core_backup_key_wrap"
        constraints = [
            models.UniqueConstraint(
                fields=("envelope", "generation"),
                name="unique_backup_key_wrap_generation",
            ),
            models.UniqueConstraint(
                fields=("envelope",),
                condition=models.Q(status="active"),
                name="unique_active_backup_key_wrap",
            ),
            models.CheckConstraint(
                condition=models.Q(generation__gte=1),
                name="backup_key_wrap_generation_positive",
            ),
            models.CheckConstraint(
                condition=~models.Q(status="active")
                | models.Q(activated_at__isnull=False),
                name="active_backup_key_wrap_is_activated",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=("pending", "active", "manual_review", "retired")
                ),
                name="backup_key_wrap_status_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(provider__in=("local-file", "local-development")),
                name="backup_key_wrap_provider_valid",
            ),
            models.CheckConstraint(
                condition=~models.Q(status="retired")
                | models.Q(retired_at__isnull=False),
                name="retired_backup_key_wrap_has_witness",
            ),
            models.CheckConstraint(
                condition=models.Q(wrapping_key_id__gt=""),
                name="backup_key_wrap_key_id_present",
            ),
            models.CheckConstraint(
                condition=models.Q(wrapped_key_sha256__regex=r"^[0-9a-f]{64}$"),
                name="backup_key_wrap_digest_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=("provider", "status"), name="backup_key_wrap_state_idx"
            )
        ]

    def clean(self):
        super().clean()
        errors = {}
        wrapped = self.wrapped_data_key
        if isinstance(wrapped, memoryview):
            wrapped = wrapped.tobytes()
        if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
            errors["wrapped_data_key"] = "A wrapped data key is required."
        elif len(wrapped) > 8192:
            errors["wrapped_data_key"] = "The wrapped data key is too large."
        else:
            expected = hashlib.sha256(bytes(wrapped)).hexdigest()
            if self.wrapped_key_sha256 != expected:
                errors["wrapped_key_sha256"] = (
                    "The wrapped data key digest does not match."
                )
        if self.status == self.Status.ACTIVE and self.activated_at is None:
            errors["activated_at"] = "An active key wrap must be activated."
        if self.status == self.Status.RETIRED and self.retired_at is None:
            errors["retired_at"] = "A retired key wrap must have a retirement time."
        if errors:
            raise ValidationError(errors)


class CoreBackupArtifact(TimeStampedModel):
    """Integrity and resume metadata for one backup artifact/destination."""

    class Role(models.TextChoices):
        SOURCE = "source", "Source"
        ARCHIVE = "archive", "Archive"
        DESTINATION = "destination", "Destination"
        MANIFEST = "manifest", "Manifest"

    class Format(models.TextChoices):
        LEGACY_ZIP = "legacy_zip", "Legacy ZIP"
        BSE1 = "bse1", "BSE1 encrypted envelope"

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    backup_content_type = models.ForeignKey(
        ContentType,
        related_name="backupsheep_backup_artifacts",
        on_delete=models.CASCADE,
    )
    backup_object_id = models.PositiveBigIntegerField()
    backup = GenericForeignKey(
        "backup_content_type", "backup_object_id", for_concrete_model=False
    )
    storage = models.ForeignKey(
        CoreStorage,
        related_name="backup_artifacts",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    role = models.CharField(
        max_length=32, choices=Role.choices, default=Role.ARCHIVE
    )
    artifact_format = models.CharField(
        max_length=16, choices=Format.choices, default=Format.LEGACY_ZIP
    )
    encryption_envelope = models.ForeignKey(
        CoreBackupEncryptionEnvelope,
        related_name="artifacts",
        null=True,
        blank=True,
        on_delete=models.RESTRICT,
    )
    idempotency_key = models.CharField(max_length=255)
    object_key = models.TextField(blank=True, default="")
    byte_count = models.PositiveBigIntegerField(default=0)
    checksum_algorithm = models.CharField(max_length=32, blank=True, default="")
    checksum_value = models.CharField(max_length=255, blank=True, default="")
    etag = models.CharField(max_length=512, blank=True, default="")
    version_id = models.CharField(max_length=255, blank=True, default="")
    multipart_upload_id = models.CharField(max_length=512, blank=True, default="")
    verified_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "core_backup_artifact"
        constraints = [
            models.UniqueConstraint(
                fields=(
                    "backup_content_type",
                    "backup_object_id",
                    "idempotency_key",
                ),
                name="unique_backup_artifact_key",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        artifact_format="legacy_zip",
                        encryption_envelope__isnull=True,
                    )
                    | models.Q(
                        artifact_format="bse1",
                        encryption_envelope__isnull=False,
                    )
                ),
                name="backup_artifact_format_envelope",
            ),
        ]
        indexes = [
            models.Index(
                fields=("backup_content_type", "backup_object_id"),
                name="backup_artifact_owner_idx",
            ),
            models.Index(
                fields=("storage", "verified_at"),
                name="backup_artifact_verify_idx",
            ),
        ]

    def clean(self):
        super().clean()
        if self.encryption_envelope_id:
            execution = self.encryption_envelope.execution
            if (
                execution.backup_content_type_id != self.backup_content_type_id
                or execution.backup_object_id != self.backup_object_id
            ):
                raise ValidationError(
                    {
                        "encryption_envelope": (
                            "The encryption envelope belongs to a different backup."
                        )
                    }
                )

    def validate_encrypted_restore_state(self):
        if (
            self.artifact_format != self.Format.BSE1
            or self.encryption_envelope_id is None
        ):
            raise ValidationError("The artifact is not a BSE1 encrypted artifact.")
        self.full_clean()
        return self.encryption_envelope.validate_restore_state()

    def bind_encrypted_envelope(self, envelope):
        """Attach an additional artifact only to a complete matching envelope."""

        if self.pk is None or envelope.pk is None:
            raise ValidationError("The artifact and envelope must be durable records.")
        with transaction.atomic():
            artifact = type(self).objects.select_for_update().get(pk=self.pk)
            durable_envelope = CoreBackupEncryptionEnvelope.objects.select_for_update().get(
                pk=envelope.pk
            )
            durable_envelope.validate_restore_state()
            artifact.artifact_format = self.Format.BSE1
            artifact.encryption_envelope = durable_envelope
            artifact.full_clean()
            artifact.save(
                update_fields=["artifact_format", "encryption_envelope", "modified"]
            )
        self.refresh_from_db()
        return self


class CoreBackupRequest(TimeStampedModel):
    """Durable outbox row for a backup request before Celery receives it.

    A broker acknowledgement is not a durable product-level job record.  The API
    commits this row first, then publishes the stable ``task_id``.  A periodic
    dispatcher republishes unclaimed rows with that same id after broker/server
    failure; ``CoreNode.backup_initiate`` atomically links the first delivery to
    the concrete backup and all later deliveries become harmless duplicates.
    """

    class Trigger(models.TextChoices):
        ON_DEMAND = "on_demand", "On demand"
        SCHEDULE = "schedule", "Schedule"
        RETRY = "retry", "Retry"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending dispatch"
        DISPATCHED = "dispatched", "Dispatched"
        CLAIMED = "claimed", "Backup created"
        DUPLICATE = "duplicate", "Duplicate suppressed"
        CANCELLED = "cancelled", "Cancelled"
        MANUAL_REVIEW = "manual_review", "Manual review"

    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    request_key = models.CharField(max_length=255, unique=True)
    task_id = models.CharField(max_length=255, unique=True)
    task_name = models.CharField(max_length=255)
    node = models.ForeignKey(
        "CoreNode", related_name="backup_requests", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="backup_requests",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    requested_by = models.ForeignKey(
        "CoreMember",
        related_name="backup_requests",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    trigger = models.CharField(
        max_length=24, choices=Trigger.choices, default=Trigger.ON_DEMAND
    )
    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.PENDING
    )
    payload = models.JSONField(default=dict, blank=True)

    backup_content_type = models.ForeignKey(
        ContentType,
        related_name="backupsheep_backup_requests",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    backup_object_id = models.PositiveBigIntegerField(null=True, blank=True)
    backup = GenericForeignKey(
        "backup_content_type", "backup_object_id", for_concrete_model=False
    )

    dispatch_attempt_count = models.PositiveIntegerField(default=0)
    dispatch_lease_owner = models.CharField(max_length=255, blank=True, default="")
    dispatch_lease_token = models.UUIDField(null=True, blank=True, editable=False)
    dispatch_lease_expires_at = models.DateTimeField(null=True, blank=True)
    next_dispatch_at = models.DateTimeField(null=True, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.CharField(max_length=64, blank=True, default="")
    last_error_message = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_backup_request"
        indexes = [
            models.Index(
                fields=("status", "next_dispatch_at"),
                name="backup_request_dispatch_idx",
            ),
            models.Index(
                fields=("node", "status"), name="backup_request_node_idx"
            ),
            models.Index(
                fields=("dispatch_lease_expires_at",),
                name="backup_request_lease_idx",
            ),
        ]

    @classmethod
    def link_backup(cls, *, task_id, node, backup, duplicate=False):
        """Atomically finish dispatch ownership and link the accepted backup."""
        if not task_id or backup is None or getattr(backup, "pk", None) is None:
            return None
        content_type = ContentType.objects.get_for_model(
            backup, for_concrete_model=False
        )
        now = timezone.now()
        status = cls.Status.DUPLICATE if duplicate else cls.Status.CLAIMED
        return cls.objects.filter(task_id=str(task_id), node=node).update(
            status=status,
            backup_content_type=content_type,
            backup_object_id=backup.pk,
            claimed_at=now,
            dispatch_lease_owner="",
            dispatch_lease_token=None,
            dispatch_lease_expires_at=None,
            next_dispatch_at=None,
            last_error_code="",
            last_error_message="",
            modified=now,
        )


class CoreBackupType(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_backup_type"


class CoreDOBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_do_backup_status"


class CoreOVHCABackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_ovh_ca_backup_status"


class CoreOVHEUBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_ovh_eu_backup_status"


class CoreVultrBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_vultr_backup_status"


class CoreWebsiteBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_website_backup_status"


class CoreDatabaseBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_database_backup_status"


class CoreAWSBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_aws_backup_status"


class CoreLightsailBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_lightsail_backup_status"


class CoreAWSRDSBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_aws_rds_backup_status"


class CoreDigitalOceanBackup(UtilBackup):
    DELETE_STATE_KEY = "_digitalocean_delete"
    DELETE_LEASE_SECONDS = 300
    DELETE_MAX_ATTEMPTS = 3
    DELETE_RETRY_GRACE_SECONDS = 60
    RECONCILIATION_MAX_OBSERVATIONS = 12

    class DeleteLeaseLost(RuntimeError):
        pass

    class DeleteOwnershipError(RuntimeError):
        pass

    class DeleteUnprovenNotFound(RuntimeError):
        pass

    class DeleteAmbiguous(RuntimeError):
        pass

    digitalocean = models.ForeignKey(
        "CoreDigitalOcean", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="digitalocean_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    action_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_digitalocean_backup"

    @staticmethod
    def _bounded_setting(name, default, *, minimum=0, maximum=10_000):
        try:
            value = int(getattr(settings, name, default))
        except (TypeError, ValueError):
            value = default
        return min(max(value, minimum), maximum)

    def _digitalocean_witness(self):
        from ..node.models import CoreNode

        resource_type = (
            "droplet"
            if self.digitalocean.node.type == CoreNode.Type.CLOUD
            else "volume"
            if self.digitalocean.node.type == CoreNode.Type.VOLUME
            else ""
        )
        if not resource_type:
            raise self.DeleteOwnershipError()
        expected = {
            "provider": "digitalocean",
            "marker": str(self.uuid_str),
            "source_id": str(self.digitalocean.unique_id),
            "resource_type": resource_type,
            "scope": {
                "account_id": str(self.digitalocean.node.connection.account_id),
                "connection_id": str(self.digitalocean.node.connection_id),
            },
        }
        execution = self.get_execution_state(create=True)
        provider_metadata = dict(execution.provider_metadata or {})
        stored = provider_metadata.get("witness")
        stored = dict(stored) if isinstance(stored, dict) else {}
        for key in ("provider", "marker", "source_id", "resource_type"):
            value = stored.get(key, provider_metadata.get(key))
            if value not in (None, "") and str(value) != expected[key]:
                raise self.DeleteOwnershipError()
        stored_scope = stored.get("scope")
        if stored_scope is not None and (
            not isinstance(stored_scope, dict)
            or any(
                str(stored_scope.get(key) or "") != value
                for key, value in expected["scope"].items()
            )
        ):
            raise self.DeleteOwnershipError()
        request = (self.metadata or {}).get("_digitalocean_request")
        if request is not None:
            if not isinstance(request, dict):
                raise self.DeleteOwnershipError()
            request_expected = {
                "marker": expected["marker"],
                "source_id": expected["source_id"],
                "resource_type": expected["resource_type"],
                "account_id": expected["scope"]["account_id"],
                "connection_id": expected["scope"]["connection_id"],
            }
            if any(
                str(request.get(key) or "") != value
                for key, value in request_expected.items()
            ):
                raise self.DeleteOwnershipError()
        return execution, expected

    @staticmethod
    def _snapshot_owned(snapshot, witness, *, resource_id=None):
        if not isinstance(snapshot, dict):
            return False
        if resource_id is not None and str(snapshot.get("id") or "") != str(
            resource_id
        ):
            return False
        return (
            str(snapshot.get("name") or "") == witness["marker"]
            and str(snapshot.get("resource_id") or "") == witness["source_id"]
            and str(snapshot.get("resource_type") or "")
            == witness["resource_type"]
        )

    @staticmethod
    def _action_owned(action, witness, action_id):
        return (
            isinstance(action, dict)
            and str(action.get("id") or "") == str(action_id)
            and str(action.get("type") or "") == "snapshot"
            and str(action.get("resource_id") or "") == witness["source_id"]
            and str(action.get("resource_type") or "") == "droplet"
        )

    def _adopt_snapshot(self, snapshot, witness):
        if not self._snapshot_owned(snapshot, witness):
            raise self.DeleteOwnershipError()
        safe_snapshot = {
            key: snapshot.get(key)
            for key in (
                "id",
                "name",
                "resource_id",
                "resource_type",
                "min_disk_size",
                "size_gigabytes",
                "status",
                "state",
                "created_at",
            )
            if isinstance(snapshot.get(key), (str, int, float, bool))
            or snapshot.get(key) is None
        }
        resource_id = str(snapshot["id"])
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            if locked.unique_id not in (None, "") and str(locked.unique_id) != resource_id:
                raise self.DeleteOwnershipError()
            metadata = dict(locked.metadata or {})
            metadata.update(
                {
                    "_provider_ownership_verified": True,
                    "_provider_source_id": witness["source_id"],
                    "_provider_resource_type": witness["resource_type"],
                    "_provider_marker": witness["marker"],
                    "_digitalocean_snapshot": safe_snapshot,
                }
            )
            locked.unique_id = resource_id
            locked.size_gigabytes = snapshot.get(
                "min_disk_size", snapshot.get("size_gigabytes")
            )
            locked.metadata = metadata
            locked.save(
                update_fields=[
                    "unique_id",
                    "size_gigabytes",
                    "metadata",
                    "modified",
                ]
            )
        self.unique_id = resource_id
        self.size_gigabytes = locked.size_gigabytes
        self.metadata = metadata
        self.record_provider_reference(
            resource_id=resource_id,
            operation_id=self.action_id,
            idempotency_key=witness["marker"],
            provider_status=str(
                snapshot.get("state") or snapshot.get("status") or "visible"
            ),
            metadata={
                "witness": witness,
                "resource": safe_snapshot,
                "create_attempted": True,
                "outcome_unknown": False,
                "adopted": True,
            },
        )

    def _digitalocean_api_error_outcome(self, error, *, operation="poll"):
        code = str(getattr(error, "code", "PROVIDER_REQUEST_FAILED"))
        mapping = {
            "PROVIDER_NOT_FOUND": ("not_found", UtilBackup.Status.FAILED, None),
            "PROVIDER_AUTH_FAILED": ("auth_failed", UtilBackup.Status.FAILED, None),
            "PROVIDER_RATE_LIMIT": (
                "rate_limited",
                UtilBackup.Status.IN_PROGRESS,
                _provider_retry_at(),
            ),
            "PROVIDER_TIMEOUT": (
                "timeout",
                UtilBackup.Status.IN_PROGRESS,
                _provider_retry_at(),
            ),
            "PROVIDER_TRANSIENT_OUTAGE": (
                "transient_outage",
                UtilBackup.Status.IN_PROGRESS,
                _provider_retry_at(),
            ),
            "PROVIDER_DUPLICATE_MATCH": (
                "duplicate_matches",
                UtilBackup.Status.FAILED,
                None,
            ),
            "PROVIDER_OWNERSHIP_MISMATCH": (
                "ownership_mismatch",
                UtilBackup.Status.FAILED,
                None,
            ),
            "PROVIDER_MALFORMED_RESPONSE": (
                "malformed_provider_response",
                UtilBackup.Status.FAILED,
                None,
            ),
        }
        category, result, retry_at = mapping.get(
            code, ("request_failed", UtilBackup.Status.FAILED, None)
        )
        _record_provider_outcome(
            self,
            provider="digitalocean",
            category=category,
            operation=operation,
            error_code=code,
            retry_at=retry_at,
            http_status=getattr(error, "status_code", None),
            resource_id=self.unique_id,
            operation_id=self.action_id,
        )
        return result

    def _observe_missing_snapshot(self, execution):
        metadata = dict(execution.provider_metadata or {})
        reconciliation = metadata.get("digitalocean_reconciliation")
        reconciliation = (
            dict(reconciliation) if isinstance(reconciliation, dict) else {}
        )
        observations = int(reconciliation.get("missing_observations") or 0) + 1
        maximum = self._bounded_setting(
            "DIGITALOCEAN_RECONCILIATION_MAX_OBSERVATIONS",
            self.RECONCILIATION_MAX_OBSERVATIONS,
            minimum=1,
            maximum=100,
        )
        reconciliation.update(
            {
                "missing_observations": observations,
                "maximum_observations": maximum,
                "last_observed_at": timezone.now().isoformat(),
            }
        )
        if observations >= maximum:
            self.record_provider_reference(
                provider_status="reconciliation_required",
                metadata={"digitalocean_reconciliation": reconciliation},
            )
            self.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
                reason="PROVIDER_RECONCILIATION_REQUIRED",
                metadata=reconciliation,
            )
            return _provider_failed(
                self,
                provider="digitalocean",
                state="reconciliation_required",
                code="PROVIDER_RECONCILIATION_REQUIRED",
            )
        self.record_provider_reference(
            provider_status="snapshot_not_visible",
            metadata={"digitalocean_reconciliation": reconciliation},
        )
        self.record_execution_error(
            code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
            retryable=True,
            retry_at=_provider_retry_at(),
            reconciliation_reason="digitalocean_snapshot_visibility",
            reconciliation_metadata=reconciliation,
        )
        return UtilBackup.Status.IN_PROGRESS

    def poll_status(self):
        """Perform one bounded, categorized, ownership-checked status check."""
        from ..node.models import CoreNode
        from apps.api.v1.connection.digitalocean.client import (
            DigitalOceanAPIError,
            find_exact_snapshot,
        )

        try:
            execution, witness = self._digitalocean_witness()
            client = self.digitalocean.node.connection.auth_digitalocean.get_verified_client()
            persisted_resource_ids = {
                str(value)
                for value in (self.unique_id, execution.provider_resource_id)
                if value not in (None, "")
            }
            persisted_action_ids = {
                str(value)
                for value in (self.action_id, execution.provider_operation_id)
                if value not in (None, "")
            }
            if len(persisted_resource_ids) > 1 or len(persisted_action_ids) > 1:
                raise self.DeleteOwnershipError()
            resource_id = str(
                self.unique_id or execution.provider_resource_id or ""
            )
            action_id = str(
                self.action_id or execution.provider_operation_id or ""
            )

            def record_snapshot(snapshot):
                if not self._snapshot_owned(
                    snapshot, witness, resource_id=resource_id or None
                ):
                    return _provider_failed(
                        self,
                        provider="digitalocean",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                self._adopt_snapshot(snapshot, witness)
                state = str(
                    snapshot.get("state") or snapshot.get("status") or ""
                ).lower()
                if state in {
                    "error",
                    "errored",
                    "failed",
                    "canceled",
                    "cancelled",
                    "deleted",
                }:
                    return _provider_failed(
                        self, provider="digitalocean", state=state
                    )
                if state in {"new", "pending", "creating", "in-progress", "processing"}:
                    return _provider_in_progress(
                        self,
                        provider="digitalocean",
                        state=state,
                        resource_id=self.unique_id,
                        operation_id=action_id or None,
                    )
                # Snapshot objects do not always expose a status. Exact visibility
                # from the snapshots endpoint is itself DigitalOcean's completion
                # witness; any non-empty unrecognized state fails closed.
                if state not in {"", "available", "completed", "complete"}:
                    return _provider_failed(
                        self,
                        provider="digitalocean",
                        state="malformed_provider_state",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                self.status = UtilBackup.Status.COMPLETE
                self.save(update_fields=["status", "modified"])
                _record_provider_outcome(
                    self,
                    provider="digitalocean",
                    category="complete",
                    provider_status=state or "visible",
                    resource_id=self.unique_id,
                    operation_id=action_id or None,
                )
                return UtilBackup.Status.COMPLETE

            # A persisted snapshot id is the strongest recovery pointer. This also
            # handles a worker dying after the provider returned the id but before
            # action_id/metadata was written locally.
            if resource_id:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/snapshots/{resource_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                try:
                    if result.status_code != 200:
                        return _provider_http_outcome(
                            self, result, provider="digitalocean"
                        )
                    try:
                        payload = result.json()
                    except Exception:
                        return _provider_failed(
                            self,
                            provider="digitalocean",
                            state="malformed_provider_response",
                            code="PROVIDER_MALFORMED_RESPONSE",
                        )
                    snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
                    return record_snapshot(snapshot)
                finally:
                    result.close()

            action_completed = False
            action_missing = False
            if CoreNode.Type.CLOUD == self.digitalocean.node.type and action_id:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/actions/{action_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                try:
                    if result.status_code == 404:
                        action_missing = True
                    elif result.status_code != 200:
                        return _provider_http_outcome(
                            self, result, provider="digitalocean"
                        )
                    else:
                        try:
                            payload = result.json()
                        except Exception:
                            return _provider_failed(
                                self,
                                provider="digitalocean",
                                state="malformed_provider_response",
                                code="PROVIDER_MALFORMED_RESPONSE",
                            )
                        action = payload.get("action") if isinstance(payload, dict) else None
                        if not self._action_owned(action, witness, action_id):
                            return _provider_failed(
                                self,
                                provider="digitalocean",
                                state="ownership_mismatch",
                                code="PROVIDER_OWNERSHIP_MISMATCH",
                            )
                        action_status = str(action.get("status") or "").lower()
                        if action_status == "errored":
                            return _provider_failed(
                                self, provider="digitalocean", state=action_status
                            )
                        if action_status == "in-progress":
                            return _provider_in_progress(
                                self,
                                provider="digitalocean",
                                state=action_status,
                                operation_id=action_id,
                            )
                        if action_status != "completed":
                            return _provider_failed(
                                self,
                                provider="digitalocean",
                                state="malformed_provider_state",
                                code="PROVIDER_MALFORMED_RESPONSE",
                            )
                        action_completed = True
                finally:
                    result.close()

            snapshot = find_exact_snapshot(
                headers=client,
                marker=witness["marker"],
                source_id=witness["source_id"],
                resource_type=witness["resource_type"],
            )
            if snapshot:
                return record_snapshot(snapshot)
            provider_metadata = dict(execution.provider_metadata or {})
            create_uncertain = bool(
                provider_metadata.get("create_attempted")
                or provider_metadata.get("outcome_unknown")
                or action_id
            )
            if create_uncertain and not action_missing:
                return self._observe_missing_snapshot(execution)
            if action_completed:
                return self._observe_missing_snapshot(execution)
            return _provider_failed(
                self,
                provider="digitalocean",
                state="not_found",
                code="PROVIDER_NOT_FOUND",
            )
        except DigitalOceanAPIError as error:
            return self._digitalocean_api_error_outcome(error)
        except self.DeleteOwnershipError:
            return _provider_failed(
                self,
                provider="digitalocean",
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="digitalocean"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.digitalocean.node

    def _claim_digitalocean_delete(self, witness):
        now = timezone.now()
        lease_seconds = self._bounded_setting(
            "DIGITALOCEAN_DELETE_LEASE_SECONDS",
            self.DELETE_LEASE_SECONDS,
            minimum=30,
            maximum=3600,
        )
        resource_id = str(self.unique_id or "")
        if not resource_id:
            raise self.DeleteOwnershipError()
        expected = {
            "resource_id": resource_id,
            "source_id": witness["source_id"],
            "marker": witness["marker"],
            "resource_type": witness["resource_type"],
            "account_id": witness["scope"]["account_id"],
            "connection_id": witness["scope"]["connection_id"],
        }
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            raw = metadata.get(self.DELETE_STATE_KEY)
            if raw is not None and not isinstance(raw, dict):
                raise self.DeleteOwnershipError()
            state = dict(raw or {})
            for key, value in expected.items():
                if state.get(key) not in (None, "") and str(state[key]) != str(value):
                    raise self.DeleteOwnershipError()
            try:
                lease_expires_at = float(state.get("lease_expires_at") or 0)
            except (TypeError, ValueError):
                raise self.DeleteOwnershipError() from None
            if state.get("lease_token") and lease_expires_at > now.timestamp():
                return None, None
            token = str(uuid.uuid4())
            state.update(expected)
            state.update(
                {
                    "schema": 1,
                    "lease_token": token,
                    "lease_expires_at": now.timestamp() + lease_seconds,
                    "legacy_ownership_verified": bool(
                        metadata.get("_provider_ownership_verified")
                        and str(metadata.get("_provider_source_id") or "")
                        == witness["source_id"]
                    ),
                    "updated_at": now.isoformat(),
                }
            )
            metadata[self.DELETE_STATE_KEY] = state
            locked.metadata = metadata
            locked.status = UtilBackup.Status.DELETE_IN_PROGRESS
            locked.save(update_fields=["metadata", "status", "modified"])
        self.metadata = metadata
        self.status = UtilBackup.Status.DELETE_IN_PROGRESS
        return state, token

    def _checkpoint_digitalocean_delete(self, state, token, *, release=False):
        lease_seconds = self._bounded_setting(
            "DIGITALOCEAN_DELETE_LEASE_SECONDS",
            self.DELETE_LEASE_SECONDS,
            minimum=30,
            maximum=3600,
        )
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            raw = metadata.get(self.DELETE_STATE_KEY)
            if not isinstance(raw, dict):
                raise self.DeleteLeaseLost()
            current = dict(raw)
            if str(current.get("lease_token") or "") != str(token or ""):
                raise self.DeleteLeaseLost()
            immutable = (
                "resource_id",
                "source_id",
                "marker",
                "resource_type",
                "account_id",
                "connection_id",
            )
            if any(
                str(current.get(key) or "") != str(state.get(key) or "")
                for key in immutable
            ):
                raise self.DeleteOwnershipError()
            checkpoint = dict(state)
            checkpoint["updated_at"] = timezone.now().isoformat()
            if release:
                checkpoint.pop("lease_token", None)
                checkpoint.pop("lease_expires_at", None)
            else:
                checkpoint["lease_token"] = token
                checkpoint["lease_expires_at"] = (
                    timezone.now().timestamp() + lease_seconds
                )
            metadata[self.DELETE_STATE_KEY] = checkpoint
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return checkpoint

    def soft_delete(self):
        from ..node.models import CoreDigitalOcean

        msg = (
            f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
            f"is being deleted using connection {self.digitalocean.node.connection.name}"
        )
        state = token = None
        try:
            _execution, witness = self._digitalocean_witness()
            state, token = self._claim_digitalocean_delete(witness)
            if state is None:
                return False
            client = self.digitalocean.node.connection.auth_digitalocean.get_verified_client()
            resource_id = state["resource_id"]
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/snapshots/{resource_id}",
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            try:
                if result.status_code == 404:
                    if not (
                        state.get("ownership_verified")
                        and state.get("delete_started")
                    ) and not state.get("legacy_ownership_verified"):
                        raise self.DeleteUnprovenNotFound()
                    state.update(
                        {
                            "delete_completed": True,
                            "delete_outcome_unknown": False,
                            "phase": "complete",
                        }
                    )
                    state = self._checkpoint_digitalocean_delete(state, token)
                    _record_provider_outcome(
                        self,
                        provider="digitalocean",
                        category="already_absent",
                        operation="delete",
                        provider_status="not_found_after_ownership_proof",
                        resource_id=resource_id,
                    )
                elif result.status_code != 200:
                    outcome = _provider_http_outcome(
                        self, result, provider="digitalocean", operation="delete"
                    )
                    state.update(
                        {
                            "phase": "preflight_retry"
                            if outcome == UtilBackup.Status.IN_PROGRESS
                            else "preflight_failed",
                            "last_http_status": int(result.status_code),
                        }
                    )
                    self._checkpoint_digitalocean_delete(state, token)
                    self.status = UtilBackup.Status.DELETE_FAILED
                    self.save(update_fields=["status", "modified"])
                    return False
                else:
                    try:
                        payload = result.json()
                    except Exception:
                        raise self.DeleteOwnershipError() from None
                    snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
                    if not self._snapshot_owned(
                        snapshot, witness, resource_id=resource_id
                    ):
                        raise self.DeleteOwnershipError()
                    state.update(
                        {
                            "ownership_verified": True,
                            "phase": "ownership_verified",
                        }
                    )
                    state = self._checkpoint_digitalocean_delete(state, token)
            finally:
                result.close()

            if not state.get("delete_completed"):
                now = timezone.now()
                attempts = int(state.get("delete_attempts") or 0)
                maximum_attempts = self._bounded_setting(
                    "DIGITALOCEAN_DELETE_MAX_ATTEMPTS",
                    self.DELETE_MAX_ATTEMPTS,
                    minimum=1,
                    maximum=10,
                )
                retry_grace = self._bounded_setting(
                    "DIGITALOCEAN_DELETE_RETRY_GRACE_SECONDS",
                    self.DELETE_RETRY_GRACE_SECONDS,
                    minimum=0,
                    maximum=3600,
                )
                if state.get("delete_started") and not state.get("delete_completed"):
                    if attempts >= maximum_attempts:
                        state["phase"] = "manual_review"
                        self._checkpoint_digitalocean_delete(state, token)
                        raise self.DeleteAmbiguous()
                    try:
                        last_attempt_epoch = float(
                            state.get("last_attempt_epoch") or 0
                        )
                    except (TypeError, ValueError):
                        raise self.DeleteOwnershipError() from None
                    if now.timestamp() - last_attempt_epoch < retry_grace:
                        state["phase"] = "reconciliation_wait"
                        self._checkpoint_digitalocean_delete(state, token)
                        self.status = UtilBackup.Status.DELETE_FAILED
                        self.save(update_fields=["status", "modified"])
                        return False

                state.update(
                    {
                        "delete_started": True,
                        "delete_outcome_unknown": True,
                        "delete_attempts": attempts + 1,
                        "last_attempt_epoch": now.timestamp(),
                        "phase": "delete_requested",
                    }
                )
                state = self._checkpoint_digitalocean_delete(state, token)
                try:
                    delete_result = requests.delete(
                        f"{settings.DIGITALOCEAN_API}/v2/snapshots/{resource_id}",
                        headers=client,
                        verify=True,
                        timeout=request_timeout(),
                    )
                    try:
                        if delete_result.status_code in {200, 202, 204}:
                            CoreDigitalOcean._fault_after_provider_accept(
                                operation="delete-snapshot",
                                marker=witness["marker"],
                            )
                        if delete_result.status_code in {200, 204, 404}:
                            state.update(
                                {
                                    "delete_completed": True,
                                    "delete_outcome_unknown": False,
                                    "phase": "complete",
                                }
                            )
                            state = self._checkpoint_digitalocean_delete(
                                state, token
                            )
                        elif delete_result.status_code == 202:
                            state["phase"] = "delete_accepted"
                            self._checkpoint_digitalocean_delete(state, token)
                            raise self.DeleteAmbiguous()
                        elif (
                            delete_result.status_code in {408, 425}
                            or delete_result.status_code >= 500
                        ):
                            state["phase"] = "delete_outcome_unknown"
                            self._checkpoint_digitalocean_delete(state, token)
                            raise self.DeleteAmbiguous()
                        else:
                            _provider_http_outcome(
                                self,
                                delete_result,
                                provider="digitalocean",
                                operation="delete",
                            )
                            state.update(
                                {
                                    "delete_started": False,
                                    "delete_outcome_unknown": False,
                                    "phase": "delete_rejected",
                                    "last_http_status": int(
                                        delete_result.status_code
                                    ),
                                }
                            )
                            self._checkpoint_digitalocean_delete(state, token)
                            self.status = UtilBackup.Status.DELETE_FAILED
                            self.save(update_fields=["status", "modified"])
                            return False
                    finally:
                        delete_result.close()
                except (
                    requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                ) as error:
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_digitalocean_delete(state, token)
                    raise self.DeleteAmbiguous() from error

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save(update_fields=["status", "modified"])
            _record_provider_outcome(
                self,
                provider="digitalocean",
                category="delete_completed",
                operation="delete",
                resource_id=state["resource_id"],
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"deleted successfully using connection {self.digitalocean.node.connection.name}"
            )
            return True
        except self.DeleteLeaseLost:
            return False
        except self.DeleteAmbiguous as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="digitalocean",
                category="reconciliation_required",
                operation="delete",
                error_code="PROVIDER_RECONCILIATION_REQUIRED",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = "DigitalOcean snapshot deletion requires read-only reconciliation."
            return False
        except self.DeleteUnprovenNotFound as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="digitalocean",
                category="not_found",
                operation="delete",
                error_code="PROVIDER_NOT_FOUND",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save(update_fields=["status", "modified"])
            msg = "DigitalOcean snapshot was absent before ownership could be proven."
            return False
        except self.DeleteOwnershipError as error:
            capture_exception(error)
            _provider_failed(
                self,
                provider="digitalocean",
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = "DigitalOcean snapshot ownership could not be verified."
            return False
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="digitalocean", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"could not be deleted using connection {self.digitalocean.node.connection.name}."
            )
            return False
        finally:
            if state is not None and token is not None:
                try:
                    self._checkpoint_digitalocean_delete(
                        state, token, release=True
                    )
                except (self.DeleteLeaseLost, self.DeleteOwnershipError):
                    pass
            try:
                self.digitalocean.node.connection.account.create_backup_log(
                    msg, self.digitalocean.node, self
                )
            except Exception as error:
                capture_exception(error)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.digitalocean.node.backup_complete_reset()


class CoreHetznerBackup(UtilBackup):
    hetzner = models.ForeignKey(
        "CoreHetzner", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="hetzner_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    action_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_hetzner_backup"

    def _hetzner_witness(self):
        from ..node.models import CoreHetzner

        execution = self.get_execution_state(create=False)
        provider_metadata = (
            dict(execution.provider_metadata or {}) if execution is not None else {}
        )
        stored = provider_metadata.get("witness")
        expected = {
            "provider": "hetzner",
            "marker": self.uuid_str,
            "source_id": str(self.hetzner.unique_id),
            "resource_type": "instance",
            "scope": {
                "account_id": str(self.hetzner.node.connection.account_id),
                "connection_id": str(self.hetzner.node.connection_id),
            },
        }
        witness = dict(stored) if isinstance(stored, dict) else dict(expected)
        for key in ("provider", "marker", "source_id", "resource_type"):
            if str(witness.get(key) or "") != str(expected[key]):
                raise HetznerDeleteOwnershipError(
                    "The durable Hetzner backup identity changed."
                )
        scope = witness.get("scope")
        if not isinstance(scope, dict) or any(
            str(scope.get(key) or "") != value
            for key, value in expected["scope"].items()
        ):
            raise HetznerDeleteOwnershipError(
                "The durable Hetzner project scope changed."
            )
        # Materialize the expected labels here so callers do not need to trust
        # mutable backup metadata.
        witness["labels"] = CoreHetzner._backup_labels(witness)
        return execution, witness

    @staticmethod
    def _hetzner_action_owned(action, action_id, source_id):
        if not isinstance(action, dict) or str(action.get("id") or "") != str(action_id):
            return False
        if str(action.get("command") or "") != "create_image":
            return False
        resources = action.get("resources")
        if not isinstance(resources, list):
            return False
        return any(
            isinstance(resource, dict)
            and str(resource.get("type") or "") == "server"
            and str(resource.get("id") or "") == str(source_id)
            for resource in resources
        )

    @staticmethod
    def _hetzner_safe_image(image):
        return {
            key: image.get(key)
            for key in (
                "id", "type", "status", "description", "disk_size", "created"
            )
            if isinstance(image.get(key), (str, int, float, bool))
            or image.get(key) is None
        }

    def _hetzner_adopt_image(self, image, witness, *, action_id=None):
        from ..node.models import CoreHetzner

        resource_id = image.get("id") if isinstance(image, dict) else None
        if not resource_id or not CoreHetzner._snapshot_owned(
            image, witness, resource_id=resource_id
        ):
            raise HetznerDeleteOwnershipError(
                "Hetzner snapshot ownership did not match."
            )
        safe_image = self._hetzner_safe_image(image)
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            fresh.unique_id = str(resource_id)
            if action_id:
                fresh.action_id = str(action_id)
            fresh.size_gigabytes = image.get("disk_size")
            metadata = dict(fresh.metadata or {})
            metadata["_hetzner_image"] = safe_image
            metadata["_provider_ownership_verified"] = True
            fresh.metadata = metadata
            fresh.save(
                update_fields=[
                    "unique_id", "action_id", "size_gigabytes", "metadata", "modified"
                ]
            )
        self.unique_id = str(resource_id)
        if action_id:
            self.action_id = str(action_id)
        self.size_gigabytes = image.get("disk_size")
        self.metadata = metadata
        self.record_provider_reference(
            operation_id=self.action_id,
            resource_id=self.unique_id,
            idempotency_key=witness["marker"],
            provider_status=str(image.get("status") or "accepted"),
            metadata={
                "witness": {key: value for key, value in witness.items() if key != "labels"},
                "resource": safe_image,
                "adopted": True,
                "outcome_unknown": False,
            },
        )

    def poll_status(self):
        """Perform one bounded, categorized, ownership-checked Hetzner poll."""
        from ..node.models import CoreHetzner, CoreNode

        if CoreNode.Type.CLOUD != self.hetzner.node.type:
            return _provider_failed(
                self, provider="hetzner", state="unsupported_resource"
            )
        try:
            execution, witness = self._hetzner_witness()
            client = self.hetzner.node.connection.auth_hetzner.get_client()
            action_id = str(
                self.action_id
                or (execution.provider_operation_id if execution is not None else "")
                or ""
            )
            resource_id = str(
                self.unique_id
                or (execution.provider_resource_id if execution is not None else "")
                or ""
            )
            if action_id:
                response = requests.get(
                    f"{settings.HETZNER_API}/v1/actions/{action_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                if response.status_code != 200:
                    return _provider_http_outcome(
                        self, response, provider="hetzner"
                    )
                try:
                    payload = response.json()
                except Exception:
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="malformed_provider_response",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                action = payload.get("action") if isinstance(payload, dict) else None
                if not self._hetzner_action_owned(
                    action, action_id, witness["source_id"]
                ):
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                action_state = str(action.get("status") or "").lower()
                if action_state == "error":
                    return _provider_failed(
                        self, provider="hetzner", state=action_state
                    )
                if action_state == "running":
                    return _provider_in_progress(
                        self,
                        provider="hetzner",
                        state=action_state,
                        resource_id=resource_id,
                        operation_id=action_id,
                    )
                if action_state != "success":
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="malformed_provider_state",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )

            image = None
            if resource_id:
                response = requests.get(
                    f"{settings.HETZNER_API}/v1/images/{resource_id}",
                    headers=client,
                    verify=True,
                    timeout=request_timeout(),
                )
                if response.status_code != 200:
                    return _provider_http_outcome(
                        self, response, provider="hetzner"
                    )
                try:
                    payload = response.json()
                except Exception:
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="malformed_provider_response",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                image = payload.get("image") if isinstance(payload, dict) else None
            else:
                matches, _pages, _items = self.hetzner._backup_candidates(
                    client, witness
                )
                if len(matches) > 1:
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="duplicate_matches",
                        code="PROVIDER_DUPLICATE_MATCH",
                    )
                image = matches[0] if matches else None
                if image is None:
                    provider_metadata = (
                        dict(execution.provider_metadata or {}) if execution else {}
                    )
                    if provider_metadata.get("create_attempted") or provider_metadata.get(
                        "outcome_unknown"
                    ):
                        _record_provider_outcome(
                            self,
                            provider="hetzner",
                            category="not_found_during_reconciliation",
                            provider_status="not_found_during_reconciliation",
                            error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                        )
                        return UtilBackup.Status.IN_PROGRESS
                    return _provider_failed(
                        self,
                        provider="hetzner",
                        state="not_found",
                        code="PROVIDER_NOT_FOUND",
                    )

            if not CoreHetzner._snapshot_owned(
                image, witness, resource_id=image.get("id") if isinstance(image, dict) else None
            ):
                return _provider_failed(
                    self,
                    provider="hetzner",
                    state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
            self._hetzner_adopt_image(image, witness, action_id=action_id or None)
            image_state = str(image.get("status") or "").lower()
            if image_state == "available":
                self.status = UtilBackup.Status.COMPLETE
                self.save(update_fields=["status", "modified"])
                _record_provider_outcome(
                    self,
                    provider="hetzner",
                    category="complete",
                    provider_status=image_state,
                    resource_id=self.unique_id,
                    operation_id=self.action_id,
                )
                return UtilBackup.Status.COMPLETE
            if image_state in {"creating"}:
                return _provider_in_progress(
                    self,
                    provider="hetzner",
                    state=image_state,
                    resource_id=self.unique_id,
                    operation_id=self.action_id,
                )
            if image_state in {"error", "deleted"}:
                return _provider_failed(
                    self, provider="hetzner", state=image_state
                )
            return _provider_failed(
                self,
                provider="hetzner",
                state="malformed_provider_state",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        except HetznerDeleteOwnershipError:
            return _provider_failed(
                self,
                provider="hetzner",
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="hetzner"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.hetzner.node

    def _claim_hetzner_delete(self):
        now = timezone.now()
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            state = metadata.get("_hetzner_delete")
            state = dict(state) if isinstance(state, dict) else {}
            try:
                expires_at = float(state.get("lease_expires_at") or 0)
            except (TypeError, ValueError):
                expires_at = 0
            if state.get("lease_token") and expires_at > now.timestamp():
                return None, None
            token = str(uuid.uuid4())
            state.update(
                {
                    "schema": 1,
                    "lease_token": token,
                    "lease_expires_at": now.timestamp() + 300,
                }
            )
            metadata["_hetzner_delete"] = state
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return state, token

    def _checkpoint_hetzner_delete(self, state, token, *, release=False):
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            current = metadata.get("_hetzner_delete")
            current = dict(current) if isinstance(current, dict) else {}
            if str(current.get("lease_token") or "") != str(token or ""):
                raise HetznerDeleteLeaseLost()
            checkpoint = dict(current if release else state)
            if release:
                checkpoint.pop("lease_token", None)
                checkpoint.pop("lease_expires_at", None)
            else:
                checkpoint["lease_token"] = token
                checkpoint["lease_expires_at"] = timezone.now().timestamp() + 300
            checkpoint["updated_at"] = timezone.now().isoformat()
            metadata["_hetzner_delete"] = checkpoint
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return checkpoint

    def soft_delete(self):
        from ..node.models import CoreHetzner, CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
            f"is being deleted using connection {self.hetzner.node.connection.name}"
        )
        state, token = self._claim_hetzner_delete()
        if state is None:
            return False
        try:
            if CoreNode.Type.CLOUD != self.hetzner.node.type:
                raise HetznerDeleteOwnershipError()
            _execution, witness = self._hetzner_witness()
            resource_id = str(self.unique_id or "")
            if not resource_id:
                raise HetznerDeleteOwnershipError()
            expected = {
                "resource_id": resource_id,
                "source_id": witness["source_id"],
                "marker": witness["marker"],
                "account_id": witness["scope"]["account_id"],
                "connection_id": witness["scope"]["connection_id"],
            }
            for key, value in expected.items():
                if state.get(key) not in (None, "") and str(state[key]) != str(value):
                    raise HetznerDeleteOwnershipError()
            state.update(expected)
            state = self._checkpoint_hetzner_delete(state, token)
            client = self.hetzner.node.connection.auth_hetzner.get_client()
            response = requests.get(
                f"{settings.HETZNER_API}/v1/images/{resource_id}",
                headers=client,
                verify=True,
                timeout=request_timeout(),
            )
            if response.status_code == 404:
                if state.get("ownership_verified") and state.get("delete_started"):
                    state.update({"delete_completed": True, "phase": "complete"})
                    self._checkpoint_hetzner_delete(state, token)
                else:
                    raise HetznerDeleteUnprovenNotFound()
            elif response.status_code != 200:
                _provider_http_outcome(
                    self, response, provider="hetzner", operation="delete"
                )
                raise RuntimeError("Hetzner delete preflight failed safely.")
            else:
                try:
                    payload = response.json()
                except Exception:
                    raise HetznerDeleteOwnershipError() from None
                image = payload.get("image") if isinstance(payload, dict) else None
                if not CoreHetzner._snapshot_owned(
                    image, witness, resource_id=resource_id
                ):
                    raise HetznerDeleteOwnershipError()
                if state.get("delete_started") and not state.get("delete_completed"):
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_hetzner_delete(state, token)
                    raise HetznerDeleteAmbiguous()
                state.update({"ownership_verified": True, "phase": "ownership_verified"})
                state = self._checkpoint_hetzner_delete(state, token)
                state.update({"delete_started": True, "phase": "delete_requested"})
                state = self._checkpoint_hetzner_delete(state, token)
                try:
                    delete_response = requests.delete(
                        f"{settings.HETZNER_API}/v1/images/{resource_id}",
                        headers=client,
                        verify=True,
                        timeout=request_timeout(),
                    )
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_hetzner_delete(state, token)
                    raise HetznerDeleteAmbiguous() from error
                if delete_response.status_code in {200, 204, 404}:
                    state.update({"delete_completed": True, "phase": "complete"})
                    self._checkpoint_hetzner_delete(state, token)
                elif delete_response.status_code in {408, 425, 500, 502, 503, 504} or delete_response.status_code >= 500:
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_hetzner_delete(state, token)
                    raise HetznerDeleteAmbiguous()
                else:
                    state.update({"delete_started": False, "phase": "delete_rejected"})
                    self._checkpoint_hetzner_delete(state, token)
                    _provider_http_outcome(
                        self,
                        delete_response,
                        provider="hetzner",
                        operation="delete",
                    )
                    raise RuntimeError("Hetzner rejected the delete request safely.")

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save(update_fields=["status", "modified"])
            _record_provider_outcome(
                self,
                provider="hetzner",
                category="delete_completed",
                operation="delete",
                resource_id=resource_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
                f"deleted successfully using connection {self.hetzner.node.connection.name}"
            )
            return True
        except HetznerDeleteLeaseLost:
            return False
        except HetznerDeleteAmbiguous as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="hetzner",
                category="reconciliation_required",
                operation="delete",
                error_code="PROVIDER_RECONCILIATION_REQUIRED",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_IN_PROGRESS
            self.save(update_fields=["status", "modified"])
            msg = "Hetzner deletion requires read-only reconciliation."
            return False
        except HetznerDeleteUnprovenNotFound as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="hetzner",
                category="not_found",
                operation="delete",
                error_code="PROVIDER_NOT_FOUND",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save(update_fields=["status", "modified"])
            msg = "Hetzner snapshot was absent before ownership could be proven."
            return False
        except HetznerDeleteOwnershipError as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="hetzner",
                category="ownership_mismatch",
                operation="delete",
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = "Hetzner snapshot ownership could not be verified."
            return False
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="hetzner", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
                f"could not be deleted using connection {self.hetzner.node.connection.name}."
            )
            return False
        finally:
            try:
                self._checkpoint_hetzner_delete(state, token, release=True)
            except HetznerDeleteLeaseLost:
                pass
            try:
                self.hetzner.node.connection.account.create_backup_log(
                    msg, self.hetzner.node, self
                )
            except Exception as error:
                capture_exception(error)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.hetzner.node.backup_complete_reset()


class CoreUpCloudBackup(UtilBackup):
    upcloud = models.ForeignKey(
        "CoreUpCloud", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="upcloud_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_upcloud_backup"

    _UPCLOUD_TRANSITIONAL_STATES = frozenset(
        {"backuping", "cloning", "maintenance", "offline", "syncing"}
    )
    _UPCLOUD_KNOWN_STATES = _UPCLOUD_TRANSITIONAL_STATES | {
        "online",
        "error",
    }
    _UPCLOUD_DELETE_MAX_ATTEMPTS = 3

    def _upcloud_witness(self):
        """Return one immutable source/scope identity for poll and delete."""
        from ..node.models import CoreNode, _backup_scope_fingerprint

        execution = self.get_execution_state(create=False)
        execution_metadata = (
            dict(execution.provider_metadata or {}) if execution is not None else {}
        )
        stored = execution_metadata.get("witness")
        if isinstance(stored, dict):
            witness = dict(stored)
        else:
            metadata = dict(self.metadata or {})
            scope = metadata.get("_bs_scope")
            if not (
                metadata.get("_bs_ownership_verified")
                and metadata.get("_bs_provider") == "upcloud"
                and isinstance(scope, dict)
            ):
                raise UpCloudDeleteOwnershipError()
            resource_type = (
                "server_boot_storage"
                if self.upcloud.node.type == CoreNode.Type.CLOUD
                else "storage"
            )
            witness = {
                "provider": "upcloud",
                "marker": metadata.get("_bs_marker"),
                "source_id": metadata.get("_bs_source_id"),
                "resource_type": resource_type,
                "scope": dict(scope),
                "scope_fingerprint": metadata.get("_bs_scope_fingerprint"),
            }

        resource_type = (
            "server_boot_storage"
            if self.upcloud.node.type == CoreNode.Type.CLOUD
            else "storage"
        )
        expected = {
            "provider": "upcloud",
            "marker": self.uuid_str,
            "resource_type": resource_type,
        }
        if any(
            str(witness.get(key) or "") != str(value)
            for key, value in expected.items()
        ):
            raise UpCloudDeleteOwnershipError()
        source_id = str(witness.get("source_id") or "")
        scope = witness.get("scope")
        if not source_id or not isinstance(scope, dict):
            raise UpCloudDeleteOwnershipError()
        scope = {str(key): str(value) for key, value in scope.items()}
        if (
            str(scope.get("account_id") or "")
            != str(self.upcloud.node.connection.account_id)
            or str(scope.get("connection_id") or "")
            != str(self.upcloud.node.connection_id)
            or not re.fullmatch(
                r"[a-z0-9][a-z0-9-]{0,63}", str(scope.get("zone") or "")
            )
        ):
            raise UpCloudDeleteOwnershipError()
        if self.upcloud.node.type == CoreNode.Type.VOLUME:
            if source_id != str(self.upcloud.unique_id):
                raise UpCloudDeleteOwnershipError()
        elif self.upcloud.node.type == CoreNode.Type.CLOUD:
            if (
                source_id == str(self.upcloud.unique_id)
                or str(scope.get("server_id") or "")
                != str(self.upcloud.unique_id)
            ):
                raise UpCloudDeleteOwnershipError()
        else:
            raise UpCloudDeleteOwnershipError()

        expected_fingerprint = _backup_scope_fingerprint(
            "upcloud", source_id, resource_type, scope
        )
        if str(witness.get("scope_fingerprint") or "") != expected_fingerprint:
            raise UpCloudDeleteOwnershipError()
        witness["source_id"] = source_id
        witness["scope"] = scope
        witness["scope_fingerprint"] = expected_fingerprint

        if execution is not None:
            if execution.provider_idempotency_key and str(
                execution.provider_idempotency_key
            ) != self.uuid_str:
                raise UpCloudDeleteOwnershipError()
            if (
                execution.provider_resource_id
                and self.unique_id
                and str(execution.provider_resource_id) != str(self.unique_id)
            ):
                raise UpCloudDeleteOwnershipError()
        return execution, witness

    def _upcloud_storage_owned(self, storage, witness, *, resource_id):
        if not isinstance(storage, dict):
            return False
        state = str(storage.get("state") or "").casefold()
        return all(
            (
                str(storage.get("uuid") or "") == str(resource_id),
                str(storage.get("title") or "") == str(witness["marker"]),
                str(storage.get("origin") or "") == str(witness["source_id"]),
                str(storage.get("zone") or "")
                == str(witness["scope"]["zone"]),
                str(storage.get("type") or "") == "backup",
                state in self._UPCLOUD_KNOWN_STATES,
            )
        )

    @staticmethod
    def _upcloud_safe_storage(storage):
        return {
            key: storage.get(key)
            for key in (
                "uuid",
                "title",
                "origin",
                "zone",
                "type",
                "state",
                "size",
                "tier",
                "encrypted",
            )
            if isinstance(storage.get(key), (str, int, float, bool))
            or storage.get(key) is None
        }

    def _upcloud_adopt_backup(self, storage, witness):
        from ..node.models import _backup_adopt_provider_resource

        if not self._upcloud_storage_owned(
            storage, witness, resource_id=storage.get("uuid")
        ):
            raise UpCloudDeleteOwnershipError()
        _backup_adopt_provider_resource(
            self,
            storage,
            witness=witness,
            provider="upcloud",
            id_keys=("uuid",),
        )

    def _upcloud_reconcile_backup(self, client, witness):
        from apps._tasks.integration.upcloud import (
            _owned_upcloud_candidate,
            list_upcloud_storages,
        )

        resources = list_upcloud_storages(client, storage_type="backup")
        return _owned_upcloud_candidate(
            resources,
            marker=witness["marker"],
            source_id=witness["source_id"],
            zone=witness["scope"]["zone"],
            storage_type="backup",
        )

    def poll_status(self):
        """Perform one typed, exact-ownership UpCloud backup observation."""
        from apps._tasks.integration.upcloud import classify_upcloud_response
        from ..node.models import CoreNode, _BackupProviderError

        if self.upcloud.node.type not in {
            CoreNode.Type.CLOUD,
            CoreNode.Type.VOLUME,
        }:
            return _provider_failed(
                self, provider="upcloud", state="unsupported_resource"
            )
        try:
            execution, witness = self._upcloud_witness()
            client = self.upcloud.node.connection.auth_upcloud.get_verified_client()
            resource_id = str(
                self.unique_id
                or (
                    execution.provider_resource_id
                    if execution is not None
                    else ""
                )
                or ""
            )
            if not resource_id:
                provider_metadata = (
                    dict(execution.provider_metadata or {})
                    if execution is not None
                    else {}
                )
                if not (
                    provider_metadata.get("create_attempted")
                    or provider_metadata.get("outcome_unknown")
                ):
                    return _provider_failed(
                        self,
                        provider="upcloud",
                        state="missing_provider_identifier",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                candidate = self._upcloud_reconcile_backup(client, witness)
                if candidate is None:
                    _record_provider_outcome(
                        self,
                        provider="upcloud",
                        category="reconciling_not_visible",
                        provider_status="not_visible",
                        error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                    )
                    return UtilBackup.Status.IN_PROGRESS
                self._upcloud_adopt_backup(candidate, witness)
                resource_id = str(self.unique_id or "")

            result = requests.get(
                f"{settings.UPCLOUD_API}/storage/{resource_id}",
                auth=client,
                verify=True,
                timeout=request_timeout(),
                headers={"accept": "application/json"},
            )
            problem = classify_upcloud_response(result)
            if problem is not None:
                if problem.retryable:
                    _record_provider_outcome(
                        self,
                        provider="upcloud",
                        category=(
                            "rate_limited"
                            if problem.code == "PROVIDER_RATE_LIMIT"
                            else "transient_outage"
                        ),
                        error_code=problem.code,
                        http_status=result.status_code,
                        resource_id=resource_id,
                    )
                    return UtilBackup.Status.IN_PROGRESS
                return _provider_failed(
                    self,
                    provider="upcloud",
                    state=problem.code.casefold(),
                    code=problem.code,
                )
            try:
                payload = result.json()
            except Exception:
                return _provider_failed(
                    self,
                    provider="upcloud",
                    state="malformed_provider_response",
                    code="PROVIDER_MALFORMED_RESPONSE",
                )
            storage = payload.get("storage") if isinstance(payload, dict) else None
            if not self._upcloud_storage_owned(
                storage, witness, resource_id=resource_id
            ):
                return _provider_failed(
                    self,
                    provider="upcloud",
                    state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
            self._upcloud_adopt_backup(storage, witness)
            state = str(storage.get("state") or "").casefold()
            if state == "online":
                self.status = UtilBackup.Status.COMPLETE
                self.save(update_fields=["status", "modified"])
                _record_provider_outcome(
                    self,
                    provider="upcloud",
                    category="complete",
                    provider_status=state,
                    resource_id=resource_id,
                )
                return UtilBackup.Status.COMPLETE
            if state == "error":
                return _provider_failed(self, provider="upcloud", state=state)
            if state in self._UPCLOUD_TRANSITIONAL_STATES:
                return _provider_in_progress(
                    self,
                    provider="upcloud",
                    state=state,
                    resource_id=resource_id,
                )
            return _provider_failed(
                self,
                provider="upcloud",
                state="malformed_provider_state",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        except UpCloudDeleteOwnershipError:
            return _provider_failed(
                self,
                provider="upcloud",
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
        except _BackupProviderError as error:
            if error.retryable:
                _record_provider_outcome(
                    self,
                    provider="upcloud",
                    category="reconciliation_retry",
                    error_code=error.code,
                    resource_id=self.unique_id,
                )
                return UtilBackup.Status.IN_PROGRESS
            return _provider_failed(
                self,
                provider="upcloud",
                state=error.code.casefold(),
                code=error.code,
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="upcloud"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.upcloud.node

    def _claim_upcloud_delete(self):
        now = timezone.now()
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            state = metadata.get("_upcloud_delete")
            state = dict(state) if isinstance(state, dict) else {}
            try:
                expires_at = float(state.get("lease_expires_at") or 0)
            except (TypeError, ValueError):
                expires_at = 0
            if state.get("lease_token") and expires_at > now.timestamp():
                return None, None
            token = str(uuid.uuid4())
            state.update(
                {
                    "schema": 1,
                    "lease_token": token,
                    "lease_expires_at": now.timestamp() + 300,
                }
            )
            metadata["_upcloud_delete"] = state
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return state, token

    def _checkpoint_upcloud_delete(self, state, token, *, release=False):
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            current = metadata.get("_upcloud_delete")
            current = dict(current) if isinstance(current, dict) else {}
            if str(current.get("lease_token") or "") != str(token or ""):
                raise UpCloudDeleteLeaseLost()
            checkpoint = dict(current if release else state)
            if release:
                checkpoint.pop("lease_token", None)
                checkpoint.pop("lease_expires_at", None)
            else:
                checkpoint["lease_token"] = token
                checkpoint["lease_expires_at"] = (
                    timezone.now().timestamp() + 300
                )
            checkpoint["updated_at"] = timezone.now().isoformat()
            metadata["_upcloud_delete"] = checkpoint
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return checkpoint

    def soft_delete(self):
        from apps._tasks.integration.upcloud import classify_upcloud_response
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
            f"is being deleted using connection {self.upcloud.node.connection.name}"
        )
        state, token = self._claim_upcloud_delete()
        if state is None:
            return False
        try:
            if self.upcloud.node.type not in {
                CoreNode.Type.CLOUD,
                CoreNode.Type.VOLUME,
            }:
                raise UpCloudDeleteOwnershipError()
            _execution, witness = self._upcloud_witness()
            resource_id = str(self.unique_id or "")
            if not resource_id:
                raise UpCloudDeleteOwnershipError()
            expected = {
                "resource_id": resource_id,
                "source_id": witness["source_id"],
                "marker": witness["marker"],
                "zone": witness["scope"]["zone"],
                "scope_fingerprint": witness["scope_fingerprint"],
                "account_id": str(self.upcloud.node.connection.account_id),
                "connection_id": str(self.upcloud.node.connection_id),
            }
            for key, value in expected.items():
                if state.get(key) not in (None, "") and str(
                    state[key]
                ) != str(value):
                    raise UpCloudDeleteOwnershipError()
            state.update(expected)
            state = self._checkpoint_upcloud_delete(state, token)
            client = self.upcloud.node.connection.auth_upcloud.get_verified_client()
            try:
                verification = requests.get(
                    f"{settings.UPCLOUD_API}/storage/{resource_id}",
                    auth=client,
                    verify=True,
                    timeout=request_timeout(),
                    headers={"accept": "application/json"},
                )
            except requests.exceptions.Timeout as error:
                raise UpCloudDeleteRetryable("PROVIDER_TIMEOUT") from error
            except requests.exceptions.ConnectionError as error:
                raise UpCloudDeleteRetryable(
                    "PROVIDER_TRANSIENT_OUTAGE"
                ) from error

            if verification.status_code == 404:
                if state.get("ownership_verified") and state.get(
                    "delete_started"
                ):
                    state.update(
                        {
                            "delete_completed": True,
                            "phase": "complete",
                        }
                    )
                    self._checkpoint_upcloud_delete(state, token)
                else:
                    raise UpCloudDeleteUnprovenNotFound()
            else:
                problem = classify_upcloud_response(verification)
                if problem is not None:
                    if problem.retryable:
                        raise UpCloudDeleteRetryable(problem.code)
                    _provider_http_outcome(
                        self,
                        verification,
                        provider="upcloud",
                        operation="delete",
                    )
                    raise RuntimeError("UpCloud delete preflight failed safely.")
                try:
                    payload = verification.json()
                except Exception:
                    raise UpCloudDeleteOwnershipError() from None
                storage = (
                    payload.get("storage") if isinstance(payload, dict) else None
                )
                if not self._upcloud_storage_owned(
                    storage, witness, resource_id=resource_id
                ):
                    raise UpCloudDeleteOwnershipError()
                state.update(
                    {
                        "ownership_verified": True,
                        "phase": "ownership_verified",
                    }
                )
                state = self._checkpoint_upcloud_delete(state, token)
                try:
                    attempts = int(state.get("delete_attempts") or 0)
                except (TypeError, ValueError):
                    raise UpCloudDeleteOwnershipError() from None
                if attempts >= self._UPCLOUD_DELETE_MAX_ATTEMPTS:
                    raise UpCloudDeleteRetryable(
                        "PROVIDER_RECONCILIATION_REQUIRED"
                    )
                state.update(
                    {
                        "delete_started": True,
                        "delete_attempts": attempts + 1,
                        "phase": "delete_requested",
                    }
                )
                state = self._checkpoint_upcloud_delete(state, token)
                try:
                    result = requests.delete(
                        f"{settings.UPCLOUD_API}/storage/{resource_id}",
                        auth=client,
                        verify=True,
                        timeout=request_timeout(),
                        headers={"accept": "application/json"},
                    )
                except requests.exceptions.Timeout as error:
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_upcloud_delete(state, token)
                    raise UpCloudDeleteRetryable(
                        "PROVIDER_TIMEOUT", ambiguous=True
                    ) from error
                except requests.exceptions.ConnectionError as error:
                    state["phase"] = "delete_outcome_unknown"
                    self._checkpoint_upcloud_delete(state, token)
                    raise UpCloudDeleteRetryable(
                        "PROVIDER_TRANSIENT_OUTAGE", ambiguous=True
                    ) from error

                problem = classify_upcloud_response(result, mutation=True)
                if problem is None or result.status_code == 404:
                    state.update(
                        {
                            "delete_completed": True,
                            "phase": "complete",
                        }
                    )
                    self._checkpoint_upcloud_delete(state, token)
                elif problem.retryable:
                    if problem.unknown_outcome:
                        state["phase"] = "delete_outcome_unknown"
                    else:
                        state.update(
                            {
                                "delete_started": False,
                                "phase": "delete_rejected_retryable",
                            }
                        )
                    self._checkpoint_upcloud_delete(state, token)
                    raise UpCloudDeleteRetryable(
                        problem.code,
                        ambiguous=problem.unknown_outcome,
                    )
                else:
                    state.update(
                        {
                            "delete_started": False,
                            "phase": "delete_rejected",
                        }
                    )
                    self._checkpoint_upcloud_delete(state, token)
                    _provider_http_outcome(
                        self,
                        result,
                        provider="upcloud",
                        operation="delete",
                    )
                    raise RuntimeError("UpCloud rejected the delete request safely.")

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save(update_fields=["status", "modified"])
            _record_provider_outcome(
                self,
                provider="upcloud",
                category="delete_completed",
                operation="delete",
                resource_id=resource_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"deleted successfully using connection {self.upcloud.node.connection.name}"
            )
            return True
        except UpCloudDeleteLeaseLost:
            return False
        except UpCloudDeleteRetryable as error:
            _record_provider_outcome(
                self,
                provider="upcloud",
                category=(
                    "reconciliation_required"
                    if error.ambiguous
                    or error.code == "PROVIDER_RECONCILIATION_REQUIRED"
                    else "retryable_delete_failure"
                ),
                operation="delete",
                error_code=error.code,
                resource_id=self.unique_id,
            )
            self.status = (
                UtilBackup.Status.DELETE_FAILED
                if error.code == "PROVIDER_RECONCILIATION_REQUIRED"
                else UtilBackup.Status.DELETE_IN_PROGRESS
            )
            self.save(update_fields=["status", "modified"])
            msg = "UpCloud deletion is waiting for exact reconciliation."
            return False
        except UpCloudDeleteUnprovenNotFound:
            _record_provider_outcome(
                self,
                provider="upcloud",
                category="not_found",
                operation="delete",
                error_code="PROVIDER_NOT_FOUND",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save(update_fields=["status", "modified"])
            msg = "UpCloud backup was absent before ownership could be proven."
            return False
        except UpCloudDeleteOwnershipError:
            _record_provider_outcome(
                self,
                provider="upcloud",
                category="ownership_mismatch",
                operation="delete",
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = "UpCloud backup ownership could not be verified."
            return False
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="upcloud", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"could not be deleted using connection {self.upcloud.node.connection.name}."
            )
            return False
        finally:
            try:
                self._checkpoint_upcloud_delete(state, token, release=True)
            except UpCloudDeleteLeaseLost:
                pass
            try:
                self.upcloud.node.connection.account.create_backup_log(
                    msg, self.upcloud.node, self
                )
            except Exception as error:
                capture_exception(error)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.upcloud.node.backup_complete_reset()


class CoreOracleBackup(UtilBackup):
    oracle = models.ForeignKey("CoreOracle", related_name="backups", on_delete=models.CASCADE)
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="oracle_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_oracle_backup"

    def poll_status(self):
        """Perform one exact, categorized Oracle backup observation."""
        from apps._tasks.integration.oracle import (
            OracleProviderError,
            oracle_backup_adapter,
        )

        try:
            return oracle_backup_adapter(self.oracle).poll_backup(self)
        except OracleProviderError as error:
            if error.retryable or error.unknown_outcome:
                return _provider_in_progress(
                    self,
                    provider="oracle",
                    state=error.code,
                    resource_id=self.unique_id,
                )
            return _provider_failed(
                self,
                provider="oracle",
                state=error.code,
                code=error.code,
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="oracle", operation="poll"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.oracle.node

    def _enqueue_delete_reconciliation(self):
        """Queue one immediate read-only follow-up; beat remains the fallback."""
        try:
            from apps._tasks.helper.tasks import reconcile_oracle_backup_deletion

            reconcile_oracle_backup_deletion.apply_async(
                args=[self.pk],
                countdown=0,
            )
        except Exception as error:
            # The durable DELETE_IN_PROGRESS row is intentionally left intact.
            # The 60-second beat sweep will republish it if the broker is down.
            capture_exception(error)

    def soft_delete(
        self,
        *,
        enqueue_reconciliation=True,
        execution_owner=None,
        execution_token=None,
    ):
        owns_api_lease = False
        lease_owner = execution_owner
        lease_token = execution_token
        release_oracle_lease = None
        enqueue_after_release = False
        msg = (
            f"Backup {self.uuid_str} of node {self.oracle.node.name} "
            f"is being deleted using integration {self.oracle.node.connection.name}"
        )

        try:
            from apps._tasks.integration.oracle import (
                OracleProviderError,
                claim_oracle_delete_reconciliation,
                oracle_backup_adapter,
                release_oracle_delete_reconciliation,
            )
            release_oracle_lease = release_oracle_delete_reconciliation

            if execution_owner and execution_token:
                self.bind_execution_fence(execution_owner, execution_token)
                self.ensure_execution_fence()
            else:
                lease_owner = (
                    f"oracle-api-delete-{self.pk}-{uuid.uuid4().hex}"
                )
                claimed = claim_oracle_delete_reconciliation(
                    self,
                    lease_owner,
                    getattr(settings, "BACKUP_DELETE_LEASE_SECONDS", 300),
                    allow_initial=True,
                )
                if claimed is None:
                    current_status = (
                        self.__class__.objects.filter(pk=self.pk)
                        .values_list("status", flat=True)
                        .first()
                    )
                    if (
                        current_status == UtilBackup.Status.DELETE_IN_PROGRESS
                        and enqueue_reconciliation
                    ):
                        self._enqueue_delete_reconciliation()
                    msg = (
                        f"Backup {self.uuid_str} of node {self.oracle.node.name} "
                        "is already owned by another Oracle delete worker."
                    )
                    return False
                self, lease_token = claimed
                owns_api_lease = True
                self.bind_execution_fence(lease_owner, lease_token)
                self.ensure_execution_fence()

            result = oracle_backup_adapter(self.oracle).delete_backup(self)
            # OCI's 202/204 response only accepts an asynchronous delete.  The
            # adapter may not report completion until a later read proves that
            # the exact owned resource is absent.
            if result == "already_absent":
                self.status = UtilBackup.Status.DELETE_COMPLETED
                _record_provider_outcome(
                    self,
                    provider="oracle",
                    category="delete_completed",
                    operation="delete",
                    resource_id=self.unique_id,
                )
                msg = (
                    f"Backup {self.uuid_str} of node {self.oracle.node.name} "
                    f"deleted successfully using integration {self.oracle.node.connection.name}"
                )
                self.save(update_fields=["status", "modified"])
                return True
            if result in {UtilBackup.Status.IN_PROGRESS, "delete_accepted"}:
                self.status = UtilBackup.Status.DELETE_IN_PROGRESS
                self.save(update_fields=["status", "modified"])
                msg = (
                    f"Backup {self.uuid_str} of node {self.oracle.node.name} "
                    "is still being reconciled by Oracle Cloud."
                )
                if owns_api_lease:
                    enqueue_after_release = enqueue_reconciliation
                elif enqueue_reconciliation:
                    self._enqueue_delete_reconciliation()
                return False
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Invalid response from Oracle API. The backup {self.uuid_str} "
                f"is marked {self.get_status_display()}. "
                "Please check your Oracle Cloud account."
            )
            if (
                self.status == UtilBackup.Status.DELETE_IN_PROGRESS
                and owns_api_lease
            ):
                enqueue_after_release = enqueue_reconciliation
            elif self.status == UtilBackup.Status.DELETE_IN_PROGRESS and enqueue_reconciliation:
                self._enqueue_delete_reconciliation()
            return False
        except OracleProviderError as error:
            if error.retryable or error.unknown_outcome:
                self.status = UtilBackup.Status.DELETE_IN_PROGRESS
            elif error.code == "PROVIDER_NOT_FOUND":
                self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            else:
                self.status = UtilBackup.Status.DELETE_FAILED
            if error.retryable or error.unknown_outcome:
                _provider_in_progress(
                    self,
                    provider="oracle",
                    state=error.code,
                    resource_id=self.unique_id,
                )
            else:
                _provider_failed(
                    self,
                    provider="oracle",
                    state=error.code,
                    code=error.code,
                )
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Invalid response from Oracle API. The backup {self.uuid_str} "
                f"is marked {self.get_status_display()}. "
                "Please check your Oracle Cloud account."
            )
            if (
                self.status == UtilBackup.Status.DELETE_IN_PROGRESS
                and owns_api_lease
            ):
                enqueue_after_release = enqueue_reconciliation
            elif self.status == UtilBackup.Status.DELETE_IN_PROGRESS and enqueue_reconciliation:
                self._enqueue_delete_reconciliation()
            return False
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="oracle", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Invalid response from Oracle API. The backup {self.uuid_str} "
                f"is marked {self.get_status_display()}. "
                "Please check your Oracle Cloud account."
            )
            return False
        finally:
            if owns_api_lease:
                try:
                    release_oracle_lease(
                        self,
                        lease_owner,
                        lease_token,
                        retry_seconds=(
                            0
                            if enqueue_after_release
                            else max(
                                60,
                                int(
                                    getattr(
                                        settings, "BACKUP_POLL_INTERVAL", 120
                                    )
                                ),
                            )
                        ),
                    )
                except Exception as error:
                    # The lease expiry and beat sweep remain the durable fallback
                    # if the API process dies while releasing its handoff.
                    capture_exception(error)
                finally:
                    self.unbind_execution_fence()
                if enqueue_after_release:
                    self._enqueue_delete_reconciliation()
            self.oracle.node.connection.account.create_backup_log(msg, self.oracle.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.oracle.node.backup_complete_reset()


class CoreOVHCABackup(UtilBackup):
    ovh_ca = models.ForeignKey(
        "CoreOVHCA", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreOVHCABackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="ovh_ca_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_ca_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_ca_backup"

    def poll_status(self):
        """Perform one categorized OVH Canada snapshot status check."""
        from ..node.models import CoreNode

        try:
            client = self.ovh_ca.node.connection.auth_ovh_ca.get_client()
            if CoreNode.Type.CLOUD == self.ovh_ca.node.type:
                snapshots = client.get(
                    self.ovh_ca._ovh_snapshot_path(client, "instance")
                )
                return _poll_ovh_snapshot(
                    self,
                    snapshots,
                    provider="ovh_ca",
                    ready_state="active",
                    source_id=self.ovh_ca.unique_id,
                )
            if CoreNode.Type.VOLUME == self.ovh_ca.node.type:
                snapshots = client.get(
                    self.ovh_ca._ovh_snapshot_path(client, "volume")
                )
                return _poll_ovh_snapshot(
                    self,
                    snapshots,
                    provider="ovh_ca",
                    ready_state="available",
                    source_id=self.ovh_ca.unique_id,
                )
            return _provider_failed(
                self, provider="ovh_ca", state="unsupported_resource"
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="ovh_ca"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_ca.node

    def soft_delete(self):
        from ..node.models import CoreNode
        from ..log.models import CoreLog

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
            f"is being deleted using connection {self.ovh_ca.node.connection.name}"
        )

        try:
            client = self.ovh_ca.node.connection.auth_ovh_ca.get_client()
            kind = "instance" if CoreNode.Type.CLOUD == self.ovh_ca.node.type else "volume"
            snapshots = client.get(self.ovh_ca._ovh_snapshot_path(client, kind))
            if not _ovh_snapshot_owned_for_delete(
                self, snapshots, source_id=self.ovh_ca.unique_id
            ):
                _provider_failed(
                    self, provider="ovh_ca", state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            client.delete(
                self.ovh_ca._ovh_snapshot_path(client, kind, self.unique_id)
            )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider="ovh_ca", category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"deleted successfully using connection {self.ovh_ca.node.connection.name}"
            )
        except ResourceNotFoundError:
            _record_provider_outcome(
                self, provider="ovh_ca", category="not_found",
                operation="delete", provider_status="not_found",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"was not found on hosting using {self.ovh_ca.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="ovh_ca", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"could not be deleted using connection {self.ovh_ca.node.connection.name}."
            )
        finally:
            self.ovh_ca.node.connection.account.create_backup_log(msg, self.ovh_ca.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_ca.node.backup_complete_reset()


class CoreOVHEUBackup(UtilBackup):
    ovh_eu = models.ForeignKey(
        "CoreOVHEU", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreOVHEUBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="ovh_eu_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_eu_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_eu_backup"

    def poll_status(self):
        """Perform one categorized OVH Europe snapshot status check."""
        from ..node.models import CoreNode

        try:
            client = self.ovh_eu.node.connection.auth_ovh_eu.get_client()
            if CoreNode.Type.CLOUD == self.ovh_eu.node.type:
                snapshots = client.get(
                    self.ovh_eu._ovh_snapshot_path(client, "instance")
                )
                return _poll_ovh_snapshot(
                    self, snapshots, provider="ovh_eu", ready_state="active",
                    source_id=self.ovh_eu.unique_id,
                )
            if CoreNode.Type.VOLUME == self.ovh_eu.node.type:
                snapshots = client.get(
                    self.ovh_eu._ovh_snapshot_path(client, "volume")
                )
                return _poll_ovh_snapshot(
                    self, snapshots, provider="ovh_eu", ready_state="available",
                    source_id=self.ovh_eu.unique_id,
                )
            return _provider_failed(
                self, provider="ovh_eu", state="unsupported_resource"
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="ovh_eu"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_eu.node

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
            f"is being deleted using connection {self.ovh_eu.node.connection.name}"
        )
        try:
            client = self.ovh_eu.node.connection.auth_ovh_eu.get_client()
            kind = "instance" if CoreNode.Type.CLOUD == self.ovh_eu.node.type else "volume"
            snapshots = client.get(self.ovh_eu._ovh_snapshot_path(client, kind))
            if not _ovh_snapshot_owned_for_delete(
                self, snapshots, source_id=self.ovh_eu.unique_id
            ):
                _provider_failed(
                    self, provider="ovh_eu", state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            client.delete(
                self.ovh_eu._ovh_snapshot_path(client, kind, self.unique_id)
            )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider="ovh_eu", category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"deleted successfully using connection {self.ovh_eu.node.connection.name}"
            )
        except ResourceNotFoundError:
            _record_provider_outcome(
                self, provider="ovh_eu", category="not_found",
                operation="delete", provider_status="not_found",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"was not found on hosting using {self.ovh_eu.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="ovh_eu", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"could not be deleted using connection {self.ovh_eu.node.connection.name}."
            )
        finally:
            self.ovh_eu.node.connection.account.create_backup_log(msg, self.ovh_eu.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_eu.node.backup_complete_reset()


class CoreOVHUSBackup(UtilBackup):
    ovh_us = models.ForeignKey(
        "CoreOVHUS", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_us_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_us_backup"

    def poll_status(self):
        """Perform one categorized OVH US snapshot status check."""
        from ..node.models import CoreNode

        try:
            client = self.ovh_us.node.connection.auth_ovh_us.get_client()
            if CoreNode.Type.CLOUD == self.ovh_us.node.type:
                snapshots = client.get(
                    self.ovh_us._ovh_snapshot_path(client, "instance")
                )
                return _poll_ovh_snapshot(
                    self, snapshots, provider="ovh_us", ready_state="active",
                    source_id=self.ovh_us.unique_id,
                )
            if CoreNode.Type.VOLUME == self.ovh_us.node.type:
                snapshots = client.get(
                    self.ovh_us._ovh_snapshot_path(client, "volume")
                )
                return _poll_ovh_snapshot(
                    self, snapshots, provider="ovh_us", ready_state="available",
                    source_id=self.ovh_us.unique_id,
                )
            return _provider_failed(
                self, provider="ovh_us", state="unsupported_resource"
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="ovh_us"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_us.node

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
            f"is being deleted using connection {self.ovh_us.node.connection.name}"
        )
        try:
            client = self.ovh_us.node.connection.auth_ovh_us.get_client()
            kind = "instance" if CoreNode.Type.CLOUD == self.ovh_us.node.type else "volume"
            snapshots = client.get(self.ovh_us._ovh_snapshot_path(client, kind))
            if not _ovh_snapshot_owned_for_delete(
                self, snapshots, source_id=self.ovh_us.unique_id
            ):
                _provider_failed(
                    self, provider="ovh_us", state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            client.delete(
                self.ovh_us._ovh_snapshot_path(client, kind, self.unique_id)
            )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider="ovh_us", category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"deleted successfully using connection {self.ovh_us.node.connection.name}"
            )
        except ResourceNotFoundError:
            _record_provider_outcome(
                self, provider="ovh_us", category="not_found",
                operation="delete", provider_status="not_found",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"was not found on hosting using {self.ovh_us.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="ovh_us", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"could not be deleted using connection {self.ovh_us.node.connection.name}."
            )
        finally:
            self.ovh_us.node.connection.account.create_backup_log(msg, self.ovh_us.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_us.node.backup_complete_reset()


class CoreVultrBackup(UtilBackup):
    vultr = models.ForeignKey(
        "CoreVultr", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreVultrBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="vultr_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="vultr_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr_backup"

    def poll_status(self):
        """Perform one ownership-checked, resumable snapshot status check."""
        from ..node.models import CoreNode

        source_key = "block_id" if CoreNode.Type.VOLUME == self.vultr.node.type else "instance_id"
        path = (
            f"/v2/blocks/snapshots/{self.unique_id}"
            if CoreNode.Type.VOLUME == self.vultr.node.type
            else f"/v2/snapshots/{self.unique_id}"
        )

        def record(classification, status_code=None, error=None):
            self.metadata = record_provider_result(
                self.metadata,
                classification=classification,
                status_code=status_code,
                error=error,
            )
            self.save()

        try:
            client = self.vultr.node.connection.auth_vultr.get_client()
            r = requests.get(
                f"{settings.VULTR_API}{path}",
                headers=client,
                verify=True,
                timeout=vultr_request_timeout(),
            )
            try:
                if r.status_code == 404:
                    record("missing", 404, "Vultr snapshot was not found.")
                    _provider_http_outcome(self, r, provider="vultr")
                    self.status = UtilBackup.Status.FAILED
                    self.save()
                    return self.status
                if r.status_code != 200:
                    classification = provider_classification(r.status_code)
                    record(classification, r.status_code, "Vultr snapshot status request failed.")
                    self.status = _provider_http_outcome(
                        self, r, provider="vultr"
                    )
                    self.save()
                    return self.status

                payload = r.json()
                snapshot = payload if CoreNode.Type.VOLUME == self.vultr.node.type else payload.get("snapshot")
                if not snapshot_matches_with_recorded_source(
                    snapshot,
                    provider_id=self.unique_id,
                    source_id=self.vultr.unique_id,
                    description=self.uuid_str,
                    source_key=source_key,
                    ownership=(self.metadata or {}).get("vultr_ownership"),
                ):
                    record("ownership_mismatch", 200, "Vultr snapshot ownership verification failed.")
                    _provider_failed(
                        self,
                        provider="vultr",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                    self.status = UtilBackup.Status.FAILED
                    self.save()
                    return self.status

                metadata = dict(self.metadata or {})
                metadata["vultr_ownership_verified"] = True
                metadata = record_provider_result(metadata, classification="in_progress")
                self.metadata = metadata
                state = snapshot_state(snapshot)
                if is_terminal_snapshot_failure(snapshot):
                    self.status = UtilBackup.Status.FAILED
                    self.metadata = record_provider_result(
                        metadata,
                        classification="provider_terminal_failure",
                        error="Vultr reported a terminal snapshot failure.",
                    )
                    self.save()
                    _provider_failed(
                        self,
                        provider="vultr",
                        state=state or "failed",
                    )
                    return self.status
                if state in {"complete", "completed"}:
                    self.size_gigabytes = round(int(snapshot.get("size", 0)) / (1000 ** 3), 2)
                    self.status = UtilBackup.Status.COMPLETE
                    self.metadata = record_provider_result(metadata, classification="complete")
                    self.save()
                    _record_provider_outcome(
                        self,
                        provider="vultr",
                        category="complete",
                        provider_status=state,
                        resource_id=self.unique_id,
                    )
                    return self.status
                if state in {
                    "pending", "pending_create", "creating", "in_progress",
                    "processing", "running",
                }:
                    self.status = UtilBackup.Status.IN_PROGRESS
                    self.save()
                    _provider_in_progress(
                        self,
                        provider="vultr",
                        state=state,
                        resource_id=self.unique_id,
                    )
                    return self.status

                self.status = UtilBackup.Status.FAILED
                self.metadata = record_provider_result(
                    metadata, classification="malformed_provider_state",
                    error="Vultr returned an unrecognized snapshot state.",
                )
                self.save()
                _provider_failed(
                    self,
                    provider="vultr",
                    state="malformed_provider_state",
                    code="PROVIDER_MALFORMED_RESPONSE",
                )
                return self.status
            finally:
                r.close()
        except requests.RequestException as error:
            record("transient_client_error", error="Vultr snapshot status request timed out or failed.")
            self.status = _provider_exception_outcome(
                self, error, provider="vultr"
            )
            self.save()
            return self.status
        except (TypeError, ValueError, KeyError):
            record("malformed_provider_response", error="Vultr returned malformed snapshot status data.")
            self.status = UtilBackup.Status.FAILED
            self.save()
            _provider_failed(
                self,
                provider="vultr",
                state="malformed_provider_response",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
            return UtilBackup.Status.FAILED
        except Exception as error:
            record("transient_client_error", error="Vultr snapshot status client failed.")
            self.status = _provider_exception_outcome(
                self, error, provider="vultr"
            )
            self.save()
            return self.status

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.vultr.node

    def soft_delete(self):
        from ..log.models import CoreLog
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.vultr.node.name} "
            f"is being deleted using connection {self.vultr.node.connection.name}"
        )
        failure_classification = "delete_failed"
        try:
            client = self.vultr.node.connection.auth_vultr.get_client()
            source_key = "block_id" if CoreNode.Type.VOLUME == self.vultr.node.type else "instance_id"
            path = (
                f"/v2/blocks/snapshots/{self.unique_id}"
                if CoreNode.Type.VOLUME == self.vultr.node.type
                else f"/v2/snapshots/{self.unique_id}"
            )
            get_result = requests.get(
                f"{settings.VULTR_API}{path}",
                headers=client,
                verify=True,
                timeout=vultr_request_timeout(),
            )
            try:
                if get_result.status_code == 404:
                    if not (self.metadata or {}).get("vultr_ownership_verified"):
                        _provider_http_outcome(
                            self,
                            get_result,
                            provider="vultr",
                            operation="delete",
                        )
                        self.status = UtilBackup.Status.DELETE_FAILED
                        self.metadata = record_provider_result(
                            self.metadata,
                            classification="missing_without_ownership_proof",
                            status_code=404,
                            error="Unable to prove ownership of the missing Vultr snapshot.",
                        )
                        self.save()
                        return
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                    self.metadata = record_provider_result(
                        self.metadata, classification="missing_after_ownership_proof",
                        status_code=404, error="Vultr snapshot was already absent.",
                    )
                    self.save()
                    _record_provider_outcome(
                        self,
                        provider="vultr",
                        category="already_absent",
                        operation="delete",
                        provider_status="not_found_after_ownership_proof",
                        resource_id=self.unique_id,
                    )
                    return
                if get_result.status_code != 200:
                    failure_classification = provider_classification(get_result.status_code)
                    _provider_http_outcome(
                        self,
                        get_result,
                        provider="vultr",
                        operation="delete",
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED
                    self.metadata = record_provider_result(
                        self.metadata,
                        classification=failure_classification,
                        status_code=get_result.status_code,
                        error="Unable to verify Vultr snapshot ownership before deletion.",
                    )
                    self.save()
                    return
                payload = get_result.json()
                snapshot = payload if CoreNode.Type.VOLUME == self.vultr.node.type else payload.get("snapshot")
                if not snapshot_matches_with_recorded_source(
                    snapshot,
                    provider_id=self.unique_id,
                    source_id=self.vultr.unique_id,
                    description=self.uuid_str,
                    source_key=source_key,
                    ownership=(self.metadata or {}).get("vultr_ownership"),
                ):
                    _provider_failed(
                        self,
                        provider="vultr",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED
                    self.metadata = record_provider_result(
                        self.metadata,
                        classification="ownership_mismatch",
                        error="Vultr snapshot ownership verification failed; refusing deletion.",
                    )
                    self.save()
                    return
                self.metadata = record_provider_result(
                    {**(self.metadata or {}), "vultr_ownership_verified": True},
                    classification="ownership_verified",
                )
                self.save()
                _record_provider_outcome(
                    self,
                    provider="vultr",
                    category="ownership_verified",
                    operation="delete",
                    resource_id=self.unique_id,
                )
            finally:
                get_result.close()

            r = requests.delete(
                f"{settings.VULTR_API}{path}",
                headers=client,
                verify=True,
                timeout=vultr_request_timeout(),
            )
            try:
                if r.status_code == 404:
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                    self.metadata = record_provider_result(
                        self.metadata, classification="missing_after_ownership_proof",
                        status_code=404, error="Vultr snapshot was already absent.",
                    )
                    self.save()
                    _record_provider_outcome(
                        self,
                        provider="vultr",
                        category="already_absent",
                        operation="delete",
                        provider_status="not_found_after_ownership_proof",
                        resource_id=self.unique_id,
                    )
                    return
                if r.status_code == 204:
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                    self.metadata = record_provider_result(
                        self.metadata, classification="delete_completed"
                    )
                    self.save()
                    _record_provider_outcome(
                        self,
                        provider="vultr",
                        category="delete_completed",
                        operation="delete",
                        resource_id=self.unique_id,
                    )
                    msg = (
                        f"Backup {self.uuid_str} of node {self.vultr.node.name} "
                        f"deleted successfully using connection {self.vultr.node.connection.name}"
                    )
                    return
                failure_classification = provider_classification(r.status_code)
                _provider_http_outcome(
                    self, r, provider="vultr", operation="delete"
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.metadata = record_provider_result(
                    self.metadata,
                    classification=failure_classification,
                    status_code=r.status_code,
                    error="Unable to delete the verified Vultr snapshot.",
                )
                self.save()
                return
            finally:
                r.close()
        except requests.exceptions.Timeout as error:
            failure_classification = "transient_client_error"
            _provider_exception_outcome(
                self, error, provider="vultr", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.metadata = record_provider_result(
                self.metadata,
                classification=failure_classification,
                error="Vultr snapshot deletion request timed out.",
            )
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.vultr.node.name} "
                f"could not be deleted using connection {self.vultr.node.connection.name}."
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="vultr", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.metadata = record_provider_result(
                self.metadata,
                classification=failure_classification,
                error="Vultr snapshot deletion failed.",
            )
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.vultr.node.name} "
                f"could not be deleted using connection {self.vultr.node.connection.name}."
            )
        finally:
            self.vultr.node.connection.account.create_backup_log(msg, self.vultr.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.vultr.node.backup_complete_reset()


class CoreGoogleCloudBackup(UtilBackup):
    google_cloud = models.ForeignKey(
        "CoreGoogleCloud", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="google_cloud_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_google_cloud_backup"

    def poll_status(self):
        """Perform one categorized, ownership-checked Google Cloud status check."""
        from ..node.models import CoreNode

        try:
            if self.google_cloud.node.type == CoreNode.Type.CLOUD:
                client = self.google_cloud.node.connection.auth_google_cloud.get_client()
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.google_cloud.project_id}"
                    f"/global/machineImages/{self.uuid_str}"
                )
                if result.status_code == 200:
                    image = result.json()
                    source = str(image.get("sourceInstance") or "")
                    if (
                        not _provider_owned(
                            image,
                            resource_id=self.unique_id,
                            marker=self.uuid_str,
                        )
                        or (not source or not source.endswith(
                            f"/instances/{self.google_cloud.unique_id}"
                        ))
                    ):
                        return _provider_failed(
                            self,
                            provider="google_cloud",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    state = str(image.get("status") or "").upper()
                    if state == "READY":
                        self.size_gigabytes = int(image.get("totalStorageBytes", 0))/(1000**3)
                        self.set_provider_metadata(image)
                        self.status = UtilBackup.Status.COMPLETE
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="google_cloud",
                            category="complete",
                            provider_status=state,
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    if state in ("INVALID", "DELETING", "FAILED"):
                        return _provider_failed(
                            self, provider="google_cloud", state=state
                        )
                    if state in {"CREATING", "UPLOADING", "PENDING"}:
                        return _provider_in_progress(
                            self,
                            provider="google_cloud",
                            state=state,
                            resource_id=self.unique_id,
                        )
                    return _provider_failed(
                        self,
                        provider="google_cloud",
                        state="malformed_provider_state",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                return _provider_http_outcome(
                    self, result, provider="google_cloud"
                )
            elif self.google_cloud.node.type == CoreNode.Type.VOLUME:
                client = self.google_cloud.node.connection.auth_google_cloud.get_client()
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.google_cloud.project_id}"
                    f"/global/snapshots/{self.uuid_str}"
                )
                if result.status_code == 200:
                    disk = result.json()
                    source = str(disk.get("sourceDisk") or "")
                    if (
                        not _provider_owned(
                            disk,
                            resource_id=self.unique_id,
                            marker=self.uuid_str,
                        )
                        or (not source or not source.endswith(
                            f"/disks/{self.google_cloud.unique_id}"
                        ))
                    ):
                        return _provider_failed(
                            self,
                            provider="google_cloud",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    state = str(disk.get("status") or "").upper()
                    if state == "READY":
                        self.size_gigabytes = int(disk.get("storageBytes", 0))/(1000**3)
                        self.set_provider_metadata(disk)
                        self.status = UtilBackup.Status.COMPLETE
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="google_cloud",
                            category="complete",
                            provider_status=state,
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    if state in ("FAILED", "DELETING"):
                        return _provider_failed(
                            self, provider="google_cloud", state=state
                        )
                    if state in {"CREATING", "UPLOADING", "PENDING"}:
                        return _provider_in_progress(
                            self,
                            provider="google_cloud",
                            state=state,
                            resource_id=self.unique_id,
                        )
                    return _provider_failed(
                        self,
                        provider="google_cloud",
                        state="malformed_provider_state",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )
                return _provider_http_outcome(
                    self, result, provider="google_cloud"
                )
            return _provider_failed(
                self, provider="google_cloud", state="unsupported_resource"
            )
        except Exception as error:
            return _provider_exception_outcome(
                self, error, provider="google_cloud"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.google_cloud.node

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
            f"is being deleted using connection {self.google_cloud.node.connection.name}"
        )
        try:
            client = self.google_cloud.node.connection.auth_google_cloud.get_client()
            if self.google_cloud.node.type == CoreNode.Type.CLOUD:
                path = (
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.google_cloud.project_id}"
                    f"/global/machineImages/{self.uuid_str}"
                )
                verification = client.get(path)
                if verification.status_code != 200:
                    _provider_http_outcome(
                        self, verification, provider="google_cloud", operation="delete"
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND if verification.status_code == 404 else UtilBackup.Status.DELETE_FAILED
                    self.save()
                    return
                resource = verification.json()
                source = str(resource.get("sourceInstance") or "")
                owned = _provider_owned(
                    resource, resource_id=self.unique_id, marker=self.uuid_str
                ) and (
                    bool(source) and source.endswith(
                        f"/instances/{self.google_cloud.unique_id}"
                    )
                )
            elif self.google_cloud.node.type == CoreNode.Type.VOLUME:
                path = (
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.google_cloud.project_id}"
                    f"/global/snapshots/{self.uuid_str}"
                )
                verification = client.get(path)
                if verification.status_code != 200:
                    _provider_http_outcome(
                        self, verification, provider="google_cloud", operation="delete"
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND if verification.status_code == 404 else UtilBackup.Status.DELETE_FAILED
                    self.save()
                    return
                resource = verification.json()
                source = str(resource.get("sourceDisk") or "")
                owned = _provider_owned(
                    resource, resource_id=self.unique_id, marker=self.uuid_str
                ) and (
                    bool(source) and source.endswith(
                        f"/disks/{self.google_cloud.unique_id}"
                    )
                )
            else:
                owned = False
                path = ""
            if not owned:
                _provider_failed(
                    self, provider="google_cloud", state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            result = client.delete(path)
            if result.status_code not in {200, 204}:
                _provider_http_outcome(
                    self, result, provider="google_cloud", operation="delete"
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider="google_cloud", category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
                f"deleted successfully using connection {self.google_cloud.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="google_cloud", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
                f"could not be deleted using connection {self.google_cloud.node.connection.name}."
            )
        finally:
            self.google_cloud.node.connection.account.create_backup_log(msg, self.google_cloud.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.google_cloud.node.backup_complete_reset()


def _soft_delete_storage_backed_backup(backup, relation_name):
    """Route every legacy caller through the committed deletion-lease path."""

    model_key = {
        "stored_website_backups": "website",
        "stored_database_backups": "database",
        "stored_basecamp_backups": "basecamp",
    }[relation_name]
    with transaction.atomic():
        locked = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        if locked.status == locked.Status.DELETE_COMPLETED:
            backup.status = locked.status
            return True
        if locked.status not in (
            locked.Status.DELETE_REQUESTED,
            locked.Status.DELETE_IN_PROGRESS,
        ):
            metadata = dict(locked.metadata or {})
            metadata["_deletion_request"] = {
                "requested_at": timezone.now().isoformat(),
                "previous_status": int(locked.status),
                "state": "pending",
            }
            locked.metadata = metadata
            locked.status = locked.Status.DELETE_REQUESTED
            locked.save(update_fields=["metadata", "status", "modified"])

    # Import locally to avoid the backup-model/task module cycle. The helper
    # commits a short parent claim, mutates at most one point outside a database
    # transaction, then commits the reconciled result.
    from apps._tasks.integration.storage.tasks import _delete_backup_requested_id

    outcome = _delete_backup_requested_id(model_key, backup.pk)
    backup.refresh_from_db(fields=["status", "metadata"])
    return outcome.get("result") == "deleted"


class CoreWebsiteBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    website = models.ForeignKey(
        "CoreWebsite", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="website_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    zip_size = models.BigIntegerField(null=True)
    raw_size = models.BigIntegerField(null=True)
    total_files = models.BigIntegerField(null=True)
    total_folders = models.BigIntegerField(null=True)
    total_files_n_folders_calculated = models.BooleanField(null=True)
    excludes = models.JSONField(null=True)
    paths = models.JSONField(null=True)
    file_list_json = models.JSONField(null=True)
    file_list_path = models.JSONField(null=True)
    all_paths = models.BooleanField(null=True)
    unzip_request = StatusField(choices_name="UNZIP_REQUEST", default=None, null=True)
    unzip_sftp_time = models.BigIntegerField(null=True)
    unzip_sftp_docker = models.CharField(null=True, max_length=2048)
    unzip_sftp_user = models.CharField(null=True, max_length=2048)
    unzip_sftp_pass = models.CharField(null=True, max_length=2048)
    unzip_sftp_host = models.CharField(null=True, max_length=2048)
    unzip_sftp_port = models.IntegerField(null=True)
    unique_id = models.CharField(max_length=255, null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="website_backups",
        through="CoreWebsiteBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_website_backup"

    def soft_delete(self):
        return _soft_delete_storage_backed_backup(
            self, "stored_website_backups"
        )

    def all_storage_points_uploaded(self):
        return self.stored_website_backups.all().count() == self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    @property
    def node(self):
        return self.website.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        _cancel_storage_point_uploads(self.stored_website_backups.all())
        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save(update_fields=["status", "modified"])

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
        )

        """
        Reset the node status
        """
        self.website.node.backup_complete_reset()

        """
        Stop docker container if any
        """
        _stop_legacy_backup_container(self.uuid_str)


class CoreWebsiteBackupFiles(TimeStampedModel):
    md5_hash = models.TextField()
    path = models.TextField()
    backup = models.ForeignKey(CoreWebsiteBackup, related_name="files", on_delete=models.CASCADE)

    class Meta:
        db_table = "core_website_backup_file"


class BaseBackupStoragePoints(TimeStampedModel):
    upload_lease_owner = models.CharField(max_length=255, blank=True, default="")
    upload_lease_token = models.UUIDField(null=True, blank=True, editable=False)
    upload_lease_expires_at = models.DateTimeField(null=True, blank=True)
    upload_heartbeat_at = models.DateTimeField(null=True, blank=True)
    upload_attempt_count = models.PositiveIntegerField(default=0)
    last_error_code = models.CharField(max_length=64, blank=True, default="")
    last_error_message = models.TextField(blank=True, default="")

    class Meta:
        abstract = True

    def bind_upload_fence(self, owner, token):
        """Require all subsequent instance saves to own this live lease token."""
        self._required_upload_lease_owner = str(owner or "")
        self._required_upload_lease_token = str(token or "")
        return self

    def ensure_upload_fence(self):
        """Fail before a new provider mutation when this worker lost its lease."""
        required_owner = getattr(self, "_required_upload_lease_owner", "")
        required_token = getattr(self, "_required_upload_lease_token", "")
        if not self.pk or not required_owner or not required_token:
            return
        now = timezone.now()
        if not self.__class__.objects.filter(
            pk=self.pk,
            upload_lease_owner=required_owner,
            upload_lease_token=required_token,
            upload_lease_expires_at__gt=now,
        ).exists():
            raise StoragePointLeaseLostError(
                "Storage upload lease ownership was lost."
            )

    def save(self, *args, **kwargs):
        required_owner = getattr(self, "_required_upload_lease_owner", "")
        required_token = getattr(self, "_required_upload_lease_token", "")
        if self.pk and required_owner and required_token:
            with transaction.atomic():
                current = self.__class__.objects.select_for_update().only(
                    "upload_lease_owner",
                    "upload_lease_token",
                    "upload_lease_expires_at",
                    "upload_heartbeat_at",
                ).get(pk=self.pk)
                if (
                    current.upload_lease_owner != required_owner
                    or str(current.upload_lease_token or "") != required_token
                    or not current.upload_lease_expires_at
                    or current.upload_lease_expires_at <= timezone.now()
                ):
                    raise StoragePointLeaseLostError(
                        "Storage upload lease ownership was lost."
                    )
                # Heartbeats update these fields directly in the database while
                # provider adapters retain the claimed model instance. Never let a
                # later full-model save write the instance's older lease deadline
                # back over a successful renewal.
                self.upload_lease_owner = current.upload_lease_owner
                self.upload_lease_token = current.upload_lease_token
                self.upload_lease_expires_at = current.upload_lease_expires_at
                self.upload_heartbeat_at = current.upload_heartbeat_at
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)

    def committed_version_id(self):
        """Return the exact committed object version, failing closed on conflict."""
        object_keys = self.committed_object_keys()
        version_ids = set(
            self.backup.artifact_records.filter(
                storage_id=self.storage_id,
                role__in=("archive", "destination"),
                object_key__in=object_keys,
                verified_at__isnull=False,
            )
            .exclude(version_id__in=("", "null"))
            .values_list("version_id", flat=True)
        )
        for state in (self.metadata or {}).values():
            if not isinstance(state, dict):
                continue
            version_id = str(state.get("version_id") or "")
            if version_id not in ("", "null"):
                version_ids.add(version_id)
        if len(version_ids) > 1:
            raise RuntimeError(
                "Committed storage object version records disagree."
            )
        return next(iter(version_ids), "")

    def committed_version_kwargs(self):
        version_id = self.committed_version_id()
        return {"VersionId": version_id} if version_id else {}

    def committed_integrity_identity(self):
        """Return the one destination identity committed for this storage point."""
        object_keys = self.committed_object_keys()
        identities = set()
        for artifact in self.backup.artifact_records.filter(
            storage_id=self.storage_id,
            role__in=("archive", "destination"),
            object_key__in=object_keys,
            verified_at__isnull=False,
            checksum_algorithm__iexact="sha256",
        ):
            identities.add((int(artifact.byte_count), artifact.checksum_value.lower()))
        for state in (self.metadata or {}).values():
            if not isinstance(state, dict):
                continue
            checksum = str(state.get("sha256") or "").lower()
            byte_count = state.get("size_bytes")
            if len(checksum) != 64 or byte_count is None:
                continue
            try:
                identities.add((int(byte_count), checksum))
            except (TypeError, ValueError):
                raise RuntimeError("Committed storage integrity metadata is invalid.")
        if len(identities) > 1:
            raise RuntimeError("Committed storage integrity records disagree.")
        if not identities:
            return None
        byte_count, checksum = identities.pop()
        return {"size_bytes": byte_count, "sha256": checksum}

    def committed_object_keys(self):
        """Return all provider identifiers durably tied to this storage row."""
        keys = set()
        if self.storage_file_id:
            keys.add(str(self.storage_file_id))
        for state in (self.metadata or {}).values():
            if not isinstance(state, dict):
                continue
            for field in (
                "object_key",
                "path",
                "provider_id",
                "file_id",
                "fileid",
            ):
                value = state.get(field)
                if value not in (None, ""):
                    keys.add(str(value))
        return keys

    def verify_s3_head_ownership(self, head):
        """Fail closed unless HEAD proves this exact object belongs to this row."""
        metadata = {
            str(key).lower(): str(value)
            for key, value in (head.get("Metadata") or {}).items()
        }
        backup_marker = metadata.get("backupsheep-backup-id") or metadata.get(
            "backup"
        )
        if backup_marker != str(self.backup_id):
            raise RuntimeError(
                "Storage object ownership marker does not match this backup."
            )
        expected = self.committed_integrity_identity()
        if expected is None:
            # Legacy objects can still be deleted only when their provider metadata
            # carries the exact BackupSheep backup id.  New objects additionally
            # require the committed byte/checksum ledger below.
            return True
        remote_checksum = metadata.get("backupsheep-sha256")
        remote_bytes = metadata.get("backupsheep-bytes")
        if (
            int(head.get("ContentLength", -1)) != expected["size_bytes"]
            or remote_checksum != expected["sha256"]
            or remote_bytes != str(expected["size_bytes"])
        ):
            raise RuntimeError(
                "Storage object integrity does not match this backup."
            )
        committed_version = self.committed_version_id()
        provider_version = str(head.get("VersionId") or "")
        if (
            committed_version
            and provider_version
            and committed_version != provider_version
        ):
            raise RuntimeError(
                "Storage object version does not match this backup."
            )
        return True

    def delete_owned_s3_object(self, client, **kwargs):
        """HEAD, verify ownership/integrity, then delete the exact object version."""
        if str(kwargs.get("Key") or "") != str(self.storage_file_id or ""):
            raise RuntimeError("Storage delete key does not match this backup.")
        head_args = dict(kwargs)
        head_args.update(self.committed_version_kwargs())
        try:
            head = client.head_object(**head_args)
        except Exception as error:
            response = getattr(error, "response", {}) or {}
            code = str((response.get("Error") or {}).get("Code") or "")
            if code in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise
        self.verify_s3_head_ownership(head)
        delete_args = dict(kwargs)
        version_id = self.committed_version_id() or str(head.get("VersionId") or "")
        if version_id and version_id != "null":
            delete_args["VersionId"] = version_id
        client.delete_object(**delete_args)
        return True

    def direct_download_permitted(self):
        """Return false when a browser URL would expose ciphertext as a ZIP."""

        encrypted = self.backup.artifact_records.filter(
            storage_id=self.storage_id,
            role__in=("archive", "destination"),
        ).filter(
            models.Q(artifact_format=CoreBackupArtifact.Format.BSE1)
            | models.Q(encryption_envelope__isnull=False)
        ).exists()
        allow_legacy = getattr(
            settings, "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE", False
        )
        enterprise = getattr(
            settings, "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE", False
        )
        return bool(
            not encrypted
            and type(allow_legacy) is bool
            and allow_legacy
            and type(enterprise) is bool
            and not enterprise
        )

    def generate_download_url(self, *, for_restore=False):
        if not for_restore and not self.direct_download_permitted():
            raise RuntimeError(
                "Direct download is disabled for encrypted backup artifacts."
            )
        encryption_key = self.storage.account.get_encryption_key()

        if self.storage.type.code == "aws_s3":
            aws_s3 = self.storage.storage_aws_s3
            s3_client = bounded_boto3_client(
                "s3",
                aws_s3.region.code,
                aws_access_key_id=bs_decrypt(aws_s3.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    aws_s3.secret_key, encryption_key
                ),
            )
            owner_kwargs = aws_s3.expected_bucket_owner_kwargs(
                aws_s3.expected_bucket_owner
            )
            version_kwargs = self.committed_version_kwargs()
            s3_object = s3_client.head_object(
                Bucket=aws_s3.bucket_name,
                Key=f"{self.storage_file_id}",
                **version_kwargs,
                **owner_kwargs,
            )
            if s3_object.get("StorageClass") and (
                    s3_object.get("StorageClass") == "GLACIER"
                    or s3_object.get("StorageClass") == "DEEP_ARCHIVE"
            ):
                if not s3_object.get("Restore"):
                    s3_client.restore_object(
                        Bucket=aws_s3.bucket_name,
                        Key=f"{self.storage_file_id}",
                        RestoreRequest={
                            "Days": 2,
                            "GlacierJobParameters": {
                                "Tier": "Expedited",
                            },
                        },
                        **version_kwargs,
                        **owner_kwargs,
                    )
                    return "restore_requested"
                elif 'ongoing-request="true"' in s3_object.get("Restore"):
                    return "restore_in_progress"
                elif 'ongoing-request="false"' in s3_object.get("Restore"):
                    response = s3_client.generate_presigned_url(
                        "get_object",
                        Params={
                            "Bucket": aws_s3.bucket_name,
                            "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                            **owner_kwargs,
                        },
                        ExpiresIn=_presigned_url_expiry(),
                    )
                    return response
            else:
                response = s3_client.generate_presigned_url(
                    "get_object",
                    Params={
                        "Bucket": aws_s3.bucket_name,
                        "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                        **owner_kwargs,
                    },
                    ExpiresIn=_presigned_url_expiry(),
                )
                return response
        elif self.storage.type.code == "do_spaces":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_do_spaces.region.endpoint}",
                aws_access_key_id=bs_decrypt(
                    self.storage.storage_do_spaces.access_key, encryption_key
                ),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_do_spaces.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_do_spaces.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "filebase":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://s3.filebase.com",
                aws_access_key_id=bs_decrypt(self.storage.storage_filebase.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_filebase.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_filebase.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "exoscale":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_exoscale.region.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_exoscale.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_exoscale.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_exoscale.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "oracle":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_oracle.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_oracle.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_oracle.secret_key, encryption_key
                ),
                region_name=self.storage.storage_oracle.region.code
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_oracle.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "scaleway":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_scaleway.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_scaleway.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_scaleway.secret_key, encryption_key
                ),
                region_name=self.storage.storage_scaleway.region.code
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_scaleway.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "backblaze_b2":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_backblaze_b2.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_backblaze_b2.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_backblaze_b2.secret_key, encryption_key
                ),
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_backblaze_b2.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "linode":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_linode.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_linode.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_linode.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_linode.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "vultr":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_vultr.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_vultr.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_vultr.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_vultr.bucket_name,
                    "Key": f"{self.storage_file_id}",
                    **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "upcloud":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_upcloud.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_upcloud.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_upcloud.secret_key, encryption_key
                ),
                region_name=self.storage.storage_upcloud.endpoint.split('.')[1],
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_upcloud.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "cloudflare":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_cloudflare.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_cloudflare.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_cloudflare.secret_key, encryption_key
                ),
                region_name="auto",
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_cloudflare.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "wasabi":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_wasabi.region.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_wasabi.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_wasabi.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_wasabi.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "dropbox":
            dbx = dropbox.Dropbox(
                bs_decrypt(self.storage.storage_dropbox.access_token, encryption_key)
            )
            url = dbx.files_get_temporary_link(self.storage_file_id).link
            return url
        elif self.storage.type.code == "google_drive":
            client = self.storage.storage_google_drive.get_client()

            search_params = {
                "fields": "webViewLink",
            }

            result = client.get(
                f"https://www.googleapis.com/drive/v3/files/{self.storage_file_id}",
                params=search_params,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )

            if result.status_code == 200:
                response = result.json()["webViewLink"]
                return response
            else:
                return None
        elif self.storage.type.code == "pcloud":
            url = f"https://my.pcloud.com/#page=filemanager" \
                  f"&q=name:{self.backup.uuid_str}" \
                  f"&folderid={self.metadata.get('parentfolderid')}" \
                  f"&filter=all"
            return url
        elif self.storage.type.code == "onedrive":
            onedrive_path = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.storage.storage_onedrive.drive_id}/root:/{self.storage_file_id}"

            r = requests.get(
                onedrive_path + "", headers=self.storage.storage_onedrive.get_client()
            )

            url = r.json().get("@microsoft.graph.downloadUrl")

            return url
        elif self.storage.type.code == "google_cloud":
            from google.cloud import storage as gc_storage
            from datetime import timedelta

            storage_client = gc_storage.Client(credentials=self.storage.storage_google_cloud.get_credentials())
            bucket = storage_client.bucket(self.storage.storage_google_cloud.bucket_name)

            if bucket.exists():
                blob = bucket.blob(self.storage_file_id)
                if blob.exists():
                    url = blob.generate_signed_url(
                        version="v4",
                        expiration=timedelta(seconds=_presigned_url_expiry()),
                        method="GET",
                    )
                    return url
                else:
                    return None
            else:
                return None

        elif self.storage.type.code == "azure":
            import datetime
            from azure.storage.blob import BlobSasPermissions, generate_blob_sas
            from datetime import timedelta

            bucket_name = self.storage.storage_azure.bucket_name

            blob_service_client = self.storage.storage_azure.get_client()

            sas_expiry = datetime.datetime.now(
                datetime.timezone.utc
            ) + timedelta(seconds=_presigned_url_expiry())
            sas_permissions = BlobSasPermissions(read=True, write=False, delete=False)
            sas_token = generate_blob_sas(
                account_name=blob_service_client.account_name,
                container_name=bucket_name,
                blob_name=self.storage_file_id,
                account_key=blob_service_client.credential.account_key,
                permission=sas_permissions,
                expiry=sas_expiry,
            )

            return f"https://{blob_service_client.account_name}.blob.core.windows.net/{bucket_name}/{self.storage_file_id}?{sas_token}"

        elif self.storage.type.code == "alibaba":
            import oss2

            auth = oss2.AuthV4(
                bs_decrypt(self.storage.storage_alibaba.access_key, encryption_key),
                bs_decrypt(self.storage.storage_alibaba.secret_key, encryption_key),
            )
            # Signature V4 requires the region ID, e.g. "us-east-1" from endpoint "oss-us-east-1.aliyuncs.com".
            region_id = self.storage.storage_alibaba.endpoint.split(".")[0].removeprefix("oss-").removesuffix("-internal")
            bucket = oss2.Bucket(auth, f"https://{self.storage.storage_alibaba.endpoint}", self.storage.storage_alibaba.bucket_name, region=region_id)
            return bucket.sign_url(
                "GET",
                self.storage_file_id,
                _presigned_url_expiry(),
                headers={"content-disposition": "attachment"},
                slash_safe=True,
            )

        elif self.storage.type.code == "tencent":
            from qcloud_cos import CosConfig
            from qcloud_cos import CosS3Client

            config = CosConfig(
                Region=self.storage.storage_tencent.region.code,
                SecretId=bs_decrypt(self.storage.storage_tencent.access_key, encryption_key),
                SecretKey=bs_decrypt(self.storage.storage_tencent.secret_key, encryption_key),
                Scheme="https",
            )
            client = CosS3Client(config)
            return client.get_presigned_url(
                Method='GET',
                Bucket=self.storage.storage_tencent.bucket_name,
                Key=self.storage_file_id,
                Expired=_presigned_url_expiry(),
            )
        elif self.storage.type.code == "leviia":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_leviia.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_leviia.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_leviia.secret_key, encryption_key
                ),
                region_name="auto",
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_leviia.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "idrive":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=self.storage.storage_idrive.endpoint_url,
                aws_access_key_id=bs_decrypt(self.storage.storage_idrive.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_idrive.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_idrive.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "ionos":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_ionos.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_ionos.access_key, encryption_key),
                region_name=self.storage.storage_ionos.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_ionos.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_ionos.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "rackcorp":
            s3_client = bounded_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_rackcorp.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_rackcorp.access_key, encryption_key),
                region_name=self.storage.storage_rackcorp.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_rackcorp.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_rackcorp.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "ibm":
            s3_client = bounded_ibm_boto3_client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_ibm.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_ibm.access_key, encryption_key),
                region_name=self.storage.storage_ibm.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_ibm.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_ibm.bucket_name,
                    "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                },
                ExpiresIn=_presigned_url_expiry(),
            )
            return response
        elif self.storage.type.code == "local":
            # Local Storage files never leave this server; the download view streams
            # them through the app (session-authenticated, account-scoped).
            return f"/api/v1/storage/local/file/{self.id}/"


    def delete_requested(self):

        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def defer_protected_delete(self, reason, retain_until=None):
        """Keep a protected storage point restorable and record why cleanup paused."""
        metadata = dict(self.metadata or {})
        metadata["deletion_protection"] = {
            "reason": reason,
            "deferred_at": timezone.now().isoformat(),
            "retain_until": retain_until.isoformat() if retain_until else None,
        }
        self.metadata = metadata
        self.save(update_fields=["metadata", "modified"])
        self.storage.account.create_storage_log(
            f"Backup {self.backup.uuid_str} remains in {self.storage.name} - "
            f"{self.storage.type.name}: deletion is protected ({reason}).",
            self.backup.node,
            self.backup,
            self.storage,
        )
        return False

    def soft_delete(self):
        import subprocess
        from django.utils.dateparse import parse_datetime

        encryption_key = self.storage.account.get_encryption_key()

        data = {
            "account_id": self.storage.account.id,
            "backup_uuid": self.backup.uuid_str,
            "storage_id": self.storage.id,
            "storage_type_id": self.storage.type.id,
            "storage_type_name": self.storage.type.name,
            "storage_name": self.storage.name,
        }

        try:
            if self.storage_file_id:
                try:
                    provider_config = getattr(
                        self.storage, f"storage_{self.storage.type.code}"
                    )
                except (AttributeError, ObjectDoesNotExist):
                    provider_config = None
                if self.storage.is_air_gapped or bool(
                    getattr(provider_config, "no_delete", False)
                ):
                    return self.defer_protected_delete(
                        "destination deletion protection is enabled"
                    )
                if self.storage.type.code == "aws_s3":
                    aws_s3 = self.storage.storage_aws_s3
                    s3_client = bounded_boto3_client(
                        "s3",
                        region_name=aws_s3.region.code if aws_s3.region else None,
                        aws_access_key_id=bs_decrypt(aws_s3.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(aws_s3.secret_key, encryption_key),
                    )
                    owner_kwargs = aws_s3.expected_bucket_owner_kwargs(
                        aws_s3.expected_bucket_owner
                    )
                    head_args = {
                        "Bucket": aws_s3.bucket_name,
                        "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                        **owner_kwargs,
                    }
                    try:
                        s3_object = s3_client.head_object(**head_args)
                    except ClientError as exc:
                        # A missing object has already been deleted outside
                        # BackupSheep; close the local record without issuing a
                        # bare delete that could create a versioned delete marker.
                        error_code = (exc.response.get("Error") or {}).get("Code")
                        if error_code not in {"404", "NoSuchKey", "NotFound"}:
                            raise
                        self.status = self.Status.DELETE_COMPLETED
                        self.save()
                        message = (
                            f"Backup {self.backup.uuid_str} was already absent from "
                            f"storage point {self.storage.name} - {self.storage.type.name}."
                        )
                        self.storage.account.create_storage_log(
                            message, self.backup.node, self.backup, self.storage
                        )
                        return True

                    lock_metadata = (self.metadata or {}).get("s3_object_lock") or {}
                    retain_until = s3_object.get("ObjectLockRetainUntilDate")
                    if retain_until is None and lock_metadata.get("retain_until"):
                        retain_until = parse_datetime(lock_metadata["retain_until"])
                    if retain_until and timezone.is_naive(retain_until):
                        retain_until = timezone.make_aware(retain_until)
                    legal_hold = (
                        s3_object.get("ObjectLockLegalHoldStatus")
                        or lock_metadata.get("legal_hold")
                    )
                    if legal_hold == "ON":
                        return self.defer_protected_delete("S3 Object Lock legal hold is active")
                    if retain_until and retain_until > timezone.now():
                        return self.defer_protected_delete(
                            "S3 Object Lock retention is active", retain_until
                        )

                    version_id = s3_object.get("VersionId") or lock_metadata.get("version_id")
                    if aws_s3.object_lock_is_configured() and not version_id:
                        return self.defer_protected_delete(
                            "Object Lock version ID is unavailable; deletion is deferred safely"
                        )
                    delete_args = {
                        "Bucket": aws_s3.bucket_name,
                        "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                        **owner_kwargs,
                    }
                    if version_id:
                        delete_args["VersionId"] = version_id
                    self.delete_owned_s3_object(s3_client, **delete_args)
                elif self.storage.type.code == "do_spaces":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_do_spaces.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_do_spaces.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_do_spaces.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_do_spaces.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "filebase":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://s3.filebase.com",
                        aws_access_key_id=bs_decrypt(self.storage.storage_filebase.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_filebase.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_filebase.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "exoscale":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_exoscale.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_exoscale.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_exoscale.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_exoscale.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "oracle":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_oracle.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_oracle.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_oracle.secret_key, encryption_key),
                        region_name=self.storage.storage_oracle.region.code,
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_oracle.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "scaleway":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_scaleway.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_scaleway.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_scaleway.secret_key, encryption_key),
                        region_name=self.storage.storage_scaleway.region.code,
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_scaleway.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "backblaze_b2":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_backblaze_b2.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_backblaze_b2.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_backblaze_b2.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_backblaze_b2.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "linode":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_linode.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_linode.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_linode.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_linode.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "vultr":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_vultr.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_vultr.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_vultr.secret_key, encryption_key),
                    )
                    object_metadata = (self.metadata or {}).get("vultr_s3_object") or {}
                    version_id = object_metadata.get("version_id")
                    delete_args = {
                        "Bucket": self.storage.storage_vultr.bucket_name,
                        "Key": f"{self.storage_file_id}",
                        **self.committed_version_kwargs(),
                    }
                    if version_id and version_id != "null":
                        delete_args["VersionId"] = version_id
                    self.delete_owned_s3_object(s3_client, **delete_args)
                elif self.storage.type.code == "upcloud":
                    # Reuse the exact normalized endpoint and SigV4 settings
                    # used by uploads.  In particular, an UpCloud endpoint is
                    # not an AWS region and must never be parsed with split().
                    from apps._tasks.integration.storage.upcloud import _s3_client

                    s3_client = _s3_client(
                        self.storage.storage_upcloud, encryption_key
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_upcloud.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "cloudflare":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_cloudflare.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_cloudflare.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_cloudflare.secret_key, encryption_key),
                        region_name="auto",
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_cloudflare.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "wasabi":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_wasabi.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_wasabi.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_wasabi.secret_key, encryption_key),
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_wasabi.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "dropbox":
                    from apps._tasks.integration.storage.dropbox import (
                        DROPBOX_METADATA_KEY,
                        _dropbox_timeout,
                        _is_not_found,
                        _normalize_dropbox_metadata,
                    )

                    state = dict(
                        (self.metadata or {}).get(DROPBOX_METADATA_KEY) or {}
                    )
                    expected = self.committed_integrity_identity()
                    if (
                        state.get("ownership_marker")
                        != f"backupsheep:{self.backup.uuid_str}"
                        or str(state.get("provider_id") or "")
                        != str(self.storage_file_id)
                        or expected is None
                        or not state.get("revision")
                        or not state.get("content_hash")
                    ):
                        raise RuntimeError(
                            "Dropbox ownership evidence is incomplete; deletion was stopped."
                        )
                    dropbox_config = self.storage.storage_dropbox
                    dbx = dropbox.Dropbox(
                        oauth2_access_token=bs_decrypt(
                            dropbox_config.access_token, encryption_key
                        ),
                        oauth2_refresh_token=bs_decrypt(
                            dropbox_config.refresh_token, encryption_key
                        ),
                        app_key=settings.DROPBOX_APP_KEY,
                        app_secret=settings.DROPBOX_APP_SECRET,
                        timeout=_dropbox_timeout(),
                    )
                    try:
                        remote = _normalize_dropbox_metadata(
                            dbx.files_get_metadata(self.storage_file_id)
                        )
                    except Exception as error:
                        if not _is_not_found(error):
                            raise
                        remote = None
                    if remote is not None:
                        if (
                            remote["provider_id"] != str(self.storage_file_id)
                            or remote["path_lower"]
                            != str(state.get("path") or "").lower()
                            or int(remote.get("size_bytes") or -1)
                            != expected["size_bytes"]
                            or remote.get("revision") != state["revision"]
                            or remote.get("content_hash")
                            != state["content_hash"]
                        ):
                            raise RuntimeError(
                                "Dropbox object ownership or integrity changed; deletion was stopped."
                            )
                        dbx.files_delete_v2(
                            remote["path"], parent_rev=state["revision"]
                        )
                elif self.storage.type.code == "google_drive":
                    from apps._tasks.integration.storage.google_drive import (
                        GoogleDriveDeleteReconciliationRequired,
                        delete_google_drive_storage_point,
                    )

                    try:
                        delete_google_drive_storage_point(self)
                    except GoogleDriveDeleteReconciliationRequired as error:
                        # An ambiguous DELETE must remain visibly pending.  A
                        # later worker may reconcile the exact persisted object,
                        # but must never flatten this into an ordinary failure or
                        # issue another blind provider mutation.
                        capture_exception(error)
                        self.refresh_from_db()
                        self.status = self.Status.DELETE_REQUESTED
                        self.save(update_fields=["status", "modified"])
                        self.storage.account.create_storage_log(
                            f"Backup {self.backup.uuid_str} deletion from "
                            f"{self.storage.name} - {self.storage.type.name} "
                            "is awaiting provider reconciliation.",
                            self.backup.node,
                            self.backup,
                            self.storage,
                        )
                        return False
                elif self.storage.type.code == "pcloud":
                    from apps._tasks.integration.storage.pcloud import (
                        PCLOUD_METADATA_KEY,
                        PCloudStorageAdapterError,
                        _request_json,
                        _verify_candidate,
                    )

                    state = dict(
                        (self.metadata or {}).get(PCLOUD_METADATA_KEY) or {}
                    )
                    expected = self.committed_integrity_identity()
                    file_id = str(
                        state.get("fileid")
                        or state.get("file_id")
                        or state.get("provider_id")
                        or ""
                    )
                    if (
                        state.get("ownership_marker")
                        != f"backupsheep:{self.backup.uuid_str}"
                        or not file_id
                        or expected is None
                    ):
                        raise RuntimeError(
                            "pCloud ownership evidence is incomplete; deletion was stopped."
                        )
                    pcloud_config = self.storage.storage_pcloud
                    token = pcloud_config.get_access_token()
                    try:
                        stat_payload = _request_json(
                            pcloud_config,
                            token,
                            "GET",
                            "stat",
                            data={"fileid": file_id},
                        )
                    except PCloudStorageAdapterError as error:
                        if error.code != "NOT_FOUND":
                            raise
                        stat_payload = None
                    if stat_payload is not None:
                        candidate = stat_payload.get("metadata")
                        if not isinstance(candidate, dict):
                            raise RuntimeError(
                                "pCloud returned malformed ownership evidence."
                            )
                        verified = _verify_candidate(
                            pcloud_config,
                            token,
                            candidate,
                            str(state.get("folder") or ""),
                            f"{self.backup.uuid_str}.zip",
                            expected,
                        )
                        if (
                            str(verified.get("fileid") or "") != file_id
                            or (
                                state.get("provider_hash") not in (None, "")
                                and str(verified.get("hash") or "")
                                != str(state["provider_hash"])
                            )
                        ):
                            raise RuntimeError(
                                "pCloud object ownership or integrity changed; deletion was stopped."
                            )
                        _request_json(
                            pcloud_config,
                            token,
                            "POST",
                            "deletefile",
                            data={"fileid": file_id},
                        )
                elif self.storage.type.code == "onedrive":
                    from apps._tasks.integration.storage.onedrive import (
                        STATE_KEY,
                        _client_headers,
                        _get_item_by_id,
                        _graph_item_id,
                        _marker,
                        _raise_response,
                        _request,
                    )

                    state = dict((self.metadata or {}).get(STATE_KEY) or {})
                    expected = self.committed_integrity_identity()
                    target_path = str(state.get("provider_path") or "")
                    provider_id = str(state.get("provider_id") or "")
                    etag = str(state.get("etag") or "")
                    session_fingerprint = str(
                        state.get("session_fingerprint") or ""
                    )
                    marker = _marker(self.backup.uuid_str, expected or {})
                    if (
                        state.get("phase") != "committed"
                        or target_path != str(self.storage_file_id or "")
                        or not provider_id
                        or expected is None
                        or not etag
                        or len(session_fingerprint) != 64
                    ):
                        raise RuntimeError(
                            "OneDrive ownership evidence is incomplete; deletion was stopped."
                        )
                    remote = _get_item_by_id(
                        self.storage,
                        provider_id,
                        target_path,
                        marker,
                        allow_missing_marker=True,
                    )
                    if remote is not None:
                        if (
                            str(remote.get("id") or "") != provider_id
                            or int(remote.get("size") or -1)
                            != expected["size_bytes"]
                            or str(remote.get("eTag") or "") != etag
                            or (
                                state.get("revision")
                                and str(remote.get("cTag") or "")
                                != str(state["revision"])
                            )
                        ):
                            raise RuntimeError(
                                "OneDrive object version or integrity changed; deletion was stopped."
                            )
                        result = _request(
                            "delete",
                            _graph_item_id(self.storage, provider_id),
                            headers={
                                **_client_headers(self.storage),
                                "If-Match": etag,
                            },
                        )
                        _raise_response(
                            result, "delete OneDrive item", allowed=(204,)
                        )

                elif self.storage.type.code == "google_cloud":
                    from apps._tasks.integration.storage.google_cloud import (
                        delete_owned_google_cloud_object,
                    )

                    delete_owned_google_cloud_object(self)

                elif self.storage.type.code == "azure":
                    from apps._tasks.integration.storage.azure import (
                        delete_owned_azure_blob,
                    )

                    delete_owned_azure_blob(self)

                elif self.storage.type.code == "alibaba":
                    from apps._tasks.integration.storage.alibaba import _s3_client

                    alibaba = self.storage.storage_alibaba
                    self.delete_owned_s3_object(
                        _s3_client(alibaba, encryption_key),
                        Bucket=alibaba.bucket_name,
                        Key=self.storage_file_id,
                    )

                elif self.storage.type.code == "tencent":
                    from apps._tasks.integration.storage.tencent import _s3_client

                    tencent = self.storage.storage_tencent
                    self.delete_owned_s3_object(
                        _s3_client(tencent, encryption_key),
                        Bucket=tencent.bucket_name,
                        Key=self.storage_file_id,
                    )

                elif self.storage.type.code == "leviia":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_leviia.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_leviia.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_leviia.secret_key, encryption_key),
                        region_name="auto",
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_leviia.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "idrive":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=self.storage.storage_idrive.endpoint_url,
                        aws_access_key_id=bs_decrypt(self.storage.storage_idrive.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_idrive.secret_key, encryption_key),
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_idrive.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "ionos":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_ionos.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_ionos.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_ionos.secret_key, encryption_key),
                        region_name=self.storage.storage_ionos.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_ionos.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "rackcorp":
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_rackcorp.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_rackcorp.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_rackcorp.secret_key, encryption_key),
                        region_name=self.storage.storage_rackcorp.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_rackcorp.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "ibm":
                    s3_client = bounded_ibm_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_ibm.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_ibm.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_ibm.secret_key, encryption_key),
                        region_name=self.storage.storage_ibm.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    self.delete_owned_s3_object(s3_client,
                        Bucket=self.storage.storage_ibm.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "local":
                    if not self.storage.storage_local.no_delete:
                        from apps._tasks.integration.storage.local import (
                            delete_local_object,
                        )

                        # The storage task receives only this point's database id.
                        # Deletion derives an exact root-relative object key from
                        # persisted ownership evidence and uses no-follow dir fds.
                        delete_local_object(self)

                self.status = self.Status.DELETE_COMPLETED
                self.save()

            message = (
                f"Backup {self.backup.uuid_str} was deleted "
                f"from storage point {self.storage.name} - {self.storage.type.name}."
            )

            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
            return True
        except SSHException as e:
            capture_exception(e)
            self.status = self.Status.DELETE_FAILED
            self.save()
            message = (
                f"Backup {self.backup.uuid_str} "
                f"unable to delete from storage point {self.storage.name} - {self.storage.type.name}. "
                "The provider authentication or transport check failed; deletion was stopped safely."
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
            return False
        except NotFound as e:
            capture_exception(e)
            self.status = self.Status.DELETE_COMPLETED
            self.save()
            message = (
                f"Backup {self.backup.uuid_str} was already absent from "
                f"storage point {self.storage.name} - {self.storage.type.name}."
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
            return True
        except Exception as e:
            capture_exception(e)
            self.status = self.Status.DELETE_FAILED
            self.save()

            message = (
                f"Backup {self.backup.uuid_str} "
                f"unable to delete from storage point {self.storage.name} - {self.storage.type.name}. "
                "Provider ownership or integrity could not be verified; deletion was stopped safely."
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
            return False


class CoreWebsiteBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 13, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 12, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 5, "Delete REQUESTED"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        CANCELLED = 6, "Cancelled"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreWebsiteBackup,
        on_delete=models.CASCADE,
        related_name="stored_website_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_website_backups"
    )

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_website_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage"],
                name="unique_stored_website_backups",
            ),
        ]


class CoreBasecampBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    basecamp = models.ForeignKey("CoreBasecamp", related_name="backups", on_delete=models.CASCADE)
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="basecamp_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    zip_size = models.BigIntegerField(null=True)
    raw_size = models.BigIntegerField(null=True)
    total_files = models.BigIntegerField(null=True)
    total_folders = models.BigIntegerField(null=True)
    total_files_n_folders_calculated = models.BooleanField(null=True)
    projects = models.JSONField(null=True)
    file_list_json = models.JSONField(null=True)
    file_list_path = models.JSONField(null=True)
    all_paths = models.BooleanField(null=True)
    unique_id = models.CharField(max_length=255, null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="basecamp_backups",
        through="CoreBasecampBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_basecamp_backup"

    def soft_delete(self):
        return _soft_delete_storage_backed_backup(
            self, "stored_basecamp_backups"
        )

    def all_storage_points_uploaded(self):
        return (
            self.stored_basecamp_backups.all().count()
            == self.stored_basecamp_backups.filter(
                status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE
            ).count()
        )

    def partial_storage_points_uploaded(self):
        return (
            self.stored_basecamp_backups.filter(status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE).count()
            > 0
        )

    def storage_points_uploaded(self):
        return self.stored_basecamp_backups.filter(
            status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE
        ).count()


    @property
    def node(self):
        return self.basecamp.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        _cancel_storage_point_uploads(self.stored_basecamp_backups.all())

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save(update_fields=["status", "modified"])

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
        )

        """
        Reset the node status
        """
        self.basecamp.node.backup_complete_reset()

        """
        Stop main docker container if any
        """
        _stop_legacy_backup_container(self.uuid_str)

        """
        Stop upload docker container if any
        """
        _stop_legacy_backup_container(f"{self.uuid_str}-storage")


class CoreBasecampBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 13, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 12, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 5, "Delete REQUESTED"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        CANCELLED = 6, "Cancelled"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreBasecampBackup,
        on_delete=models.CASCADE,
        related_name="stored_basecamp_backups",
    )
    storage = models.ForeignKey(CoreStorage, on_delete=models.CASCADE, related_name="stored_basecamp_backups")

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_basecamp_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage"],
                name="unique_stored_basecamp_backups",
            ),
        ]


class CoreDatabaseBackupLegacy(models.Model):
    storage_id = models.IntegerField(null=True)

    class Meta:
        db_table = "core_database_backup"
        managed = False


class CoreHostingBackupLegacy(models.Model):
    storage_id = models.IntegerField(null=True)

    class Meta:
        db_table = "core_hosting_backup"
        managed = False


class CoreDatabaseBackup(UtilBackup):
    database = models.ForeignKey(
        "CoreDatabase", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="database_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    tables = models.JSONField(null=True)
    all_tables = models.BooleanField(null=True)
    all_databases = models.BooleanField(null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="database_backups",
        through="CoreDatabaseBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)
    option_postgres = models.TextField(null=True, blank=True)
    option_mysql = models.TextField(null=True, blank=True)
    option_mariadb = models.TextField(null=True, blank=True)
    option_mongodb = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_database_backup"

    def all_storage_points_uploaded(self):
        return self.stored_database_backups.all().count() == self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    def soft_delete(self):
        return _soft_delete_storage_backed_backup(
            self, "stored_database_backups"
        )

    @property
    def node(self):
        return self.database.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        _cancel_storage_point_uploads(self.stored_database_backups.all())

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save(update_fields=["status", "modified"])

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
        )

        """
        Reset the node status
        """
        self.database.node.backup_complete_reset()


class CoreDatabaseBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 15, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 14, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 12, "Delete REQUESTED"
        CANCELLED = 13, "Cancelled"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreDatabaseBackup,
        on_delete=models.CASCADE,
        related_name="stored_database_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_database_backups"
    )
    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_database_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage"],
                name="unique_stored_database_backups",
            ),
        ]


class CoreAWSBackup(UtilBackup):
    aws = models.ForeignKey("CoreAWS", related_name="backups", on_delete=models.CASCADE)
    # old_status = models.ForeignKey(
    #     CoreAWSBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="aws_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule", related_name="aws_backups", null=True, on_delete=models.SET_NULL
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_backup"

    # Native EC2/EBS backups use the execution ledger as the durable request
    # witness.  AWS Backup (S3/DynamoDB) has a separate job protocol below and is
    # intentionally left on its existing path.
    _AWS_NATIVE_REQUEST_KEY = "aws_native_request"

    def _aws_native_kind(self):
        from ..node.models import CoreNode

        if (
            self.aws.resource_type == "instance"
            and self.aws.node.type == CoreNode.Type.CLOUD
        ):
            return "instance"
        if (
            self.aws.resource_type == "volume"
            and self.aws.node.type == CoreNode.Type.VOLUME
        ):
            return "volume"
        raise AWSNativeOwnershipError(
            "AWS native backup source type does not match the node type."
        )

    @staticmethod
    def _aws_native_region(auth):
        region = str(getattr(getattr(auth, "region", None), "code", "") or "")
        if not region:
            raise AWSNativeOwnershipError("AWS region ownership could not be verified.")
        return region

    @staticmethod
    def _aws_native_account_id(auth):
        sts = auth.get_client("sts")
        response = sts.get_caller_identity()
        account_id = str((response or {}).get("Account") or "")
        if not re.fullmatch(r"[0-9]{12}", account_id):
            raise AWSNativeOwnershipError(
                "AWS account ownership could not be verified."
            )
        return account_id

    def _aws_native_request(self):
        state = self.get_execution_state(create=False)
        metadata = dict(state.provider_metadata or {}) if state is not None else {}
        request = metadata.get(self._AWS_NATIVE_REQUEST_KEY)
        return state, dict(request or {}) if isinstance(request, dict) else {}

    @staticmethod
    def _aws_native_marker(backup):
        marker = str(backup.uuid_str or "").strip()
        if not marker:
            raise AWSNativeMalformedResponse(
                "AWS native backup has no deterministic request marker."
            )
        return marker[:128]

    @classmethod
    def _aws_native_witness(
        cls,
        *,
        marker,
        provider,
        source_id,
        source_type,
        account_id,
        region,
        strict_identity=True,
    ):
        values = {
            "schema": 1,
            "provider": str(provider),
            "marker": str(marker),
            "source_id": str(source_id or ""),
            "source_type": str(source_type),
            "account_id": str(account_id or ""),
            "region": str(region or ""),
            "strict_identity": bool(strict_identity),
        }
        if not values["source_id"] or not values["account_id"] or not values["region"]:
            raise AWSNativeOwnershipError("AWS native request identity is incomplete.")
        fingerprint_payload = {
            key: values[key]
            for key in (
                "provider",
                "marker",
                "source_id",
                "source_type",
                "account_id",
                "region",
            )
        }
        values["request_fingerprint"] = hashlib.sha256(
            json.dumps(
                fingerprint_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return values

    def _aws_native_persist_witness(
        self,
        witness,
        *,
        owner=None,
        token=None,
        provider_status="reconciling",
        metadata=None,
    ):
        fence = {}
        if owner is not None and token is not None:
            fence = {"lease_owner": owner, "lease_token": token}
        provider_metadata = {
            self._AWS_NATIVE_REQUEST_KEY: dict(witness),
            "witness": dict(witness),
            "marker": witness["marker"],
            "source_id": witness["source_id"],
            "resource_type": witness["source_type"],
            "scope": {
                "account_id": witness["account_id"],
                "region": witness["region"],
            },
            "scope_fingerprint": witness["request_fingerprint"],
        }
        provider_metadata.update(dict(metadata or {}))
        saved = self.record_provider_reference(
            idempotency_key=witness["marker"],
            provider_status=provider_status,
            metadata=provider_metadata,
            **fence,
        )
        if fence and saved is None:
            raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")
        return saved

    def _aws_native_current_witness(self, auth, *, owner=None, token=None, persist=True):
        kind = self._aws_native_kind()
        region = self._aws_native_region(auth)
        account_id = self._aws_native_account_id(auth)
        source_id = str(self.aws.unique_id or "")
        marker = self._aws_native_marker(self)
        _state, stored = self._aws_native_request()
        if stored:
            expected = {
                "provider": "aws_ec2" if kind == "instance" else "aws_ebs",
                "marker": marker,
                "source_id": source_id,
                "source_type": kind,
                "region": region,
                "account_id": account_id,
            }
            for key, value in expected.items():
                stored_value = stored.get(key)
                if stored_value not in (None, "", "pending") and str(stored_value) != str(value):
                    raise AWSNativeOwnershipError(
                        "The durable AWS native request identity changed."
                    )
        witness = self._aws_native_witness(
            marker=marker,
            provider="aws_ec2" if kind == "instance" else "aws_ebs",
            source_id=source_id,
            source_type=kind,
            account_id=account_id,
            region=region,
            strict_identity=True,
        )
        if persist and stored != witness:
            self._aws_native_persist_witness(
                witness,
                owner=owner,
                token=token,
                provider_status="reconciling",
            )
        return witness

    def _aws_native_create_lease(self, task_id=None):
        state = self.get_execution_state(create=False)
        if (
            state is not None
            and state.lease_is_active()
            and state.phase in {"create", "provider_create"}
        ):
            if task_id and state.lease_owner != str(task_id):
                return None
            return state.lease_owner, str(state.lease_token), False
        owner = str(task_id or "aws-native-create-" + uuid.uuid4().hex)
        state = self.claim_execution(
            lease_owner=owner,
            phase="create",
            lease_seconds=max(
                60,
                min(
                    int(getattr(settings, "BACKUP_CREATE_LEASE_SECONDS", 3600)),
                    86400,
                ),
            ),
            respect_retry_at=False,
        )
        if state is None:
            return None
        return owner, str(state.lease_token), True

    def _aws_native_release_create(self, owner, token):
        self.release_execution(
            lease_owner=owner,
            lease_token=token,
            phase="create",
            finished=False,
        )

    @staticmethod
    def _aws_native_page_collection(client, method_name, collection_key, params):
        items = []
        token = None
        seen = set()
        page_count = 0
        while True:
            request = dict(params)
            if token:
                request["NextToken"] = token
            response = getattr(client, method_name)(**request)
            if not isinstance(response, dict) or collection_key not in response:
                raise AWSNativeMalformedResponse(
                    "AWS returned a malformed native resource page."
                )
            page = response.get(collection_key)
            if not isinstance(page, list):
                raise AWSNativeMalformedResponse(
                    "AWS returned an invalid native resource collection."
                )
            items.extend(page)
            page_count += 1
            if page_count > 1000:
                raise AWSNativeMalformedResponse(
                    "AWS pagination exceeded the bounded reconciliation limit."
                )
            next_token = response.get("NextToken")
            if next_token in (None, ""):
                return items, page_count
            if not isinstance(next_token, str) or next_token in seen or next_token == token:
                raise AWSNativeMalformedResponse(
                    "AWS returned a repeated pagination token."
                )
            seen.add(next_token)
            token = next_token

    @staticmethod
    def _aws_native_tags(resource):
        raw = resource.get("Tags") if isinstance(resource, dict) else None
        if raw is None and isinstance(resource, dict):
            raw = resource.get("tags")
        if isinstance(raw, dict):
            return {str(key): str(value) for key, value in raw.items()}
        tags = {}
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and item.get("Key") is not None:
                    tags[str(item["Key"])] = str(item.get("Value", ""))
        return tags

    @staticmethod
    def _aws_native_region_matches(resource, region):
        if not isinstance(resource, dict):
            return False
        explicit = resource.get("Region") or resource.get("region")
        if explicit not in (None, "") and str(explicit) != str(region):
            return False
        availability_zone = resource.get("AvailabilityZone")
        if availability_zone not in (None, "") and not str(availability_zone).startswith(
            str(region)
        ):
            return False
        return True

    @classmethod
    def _aws_native_backup_owned(cls, resource, witness, resource_id=None):
        if not isinstance(resource, dict):
            return False
        kind = witness["source_type"]
        actual_id = resource.get("ImageId") if kind == "instance" else resource.get("SnapshotId")
        if resource_id is not None and str(actual_id or "") != str(resource_id):
            return False
        if str(resource.get("OwnerId") or "") != str(witness["account_id"]):
            return False
        if not cls._aws_native_region_matches(resource, witness["region"]):
            return False
        marker = str(witness["marker"])
        if kind == "instance":
            if str(resource.get("Name") or "") != marker:
                return False
            if str(resource.get("Description") or "") != marker:
                return False
        else:
            if str(resource.get("Description") or "") != marker:
                return False
            if str(resource.get("VolumeId") or "") != str(witness["source_id"]):
                return False

        tags = cls._aws_native_tags(resource)
        if tags:
            expected = {
                "BackupSheepBackup": marker,
                "BackupSheepSourceId": str(witness["source_id"]),
                "BackupSheepSourceType": kind,
                "BackupSheepAccountId": str(witness["account_id"]),
                "BackupSheepRegion": str(witness["region"]),
            }
            for key, value in expected.items():
                if key in tags and tags[key] != value:
                    return False
            if witness.get("strict_identity"):
                if any(tags.get(key) != value for key, value in expected.items()):
                    return False
        elif witness.get("strict_identity"):
            # New AMI and EBS requests carry this complete tag witness.  A
            # name/description collision is not sufficient ownership proof,
            # even when AWS also echoes the source volume on an EBS snapshot.
            return False
        return True

    @staticmethod
    def _aws_native_safe_resource(resource):
        if not isinstance(resource, dict):
            raise AWSNativeMalformedResponse("AWS returned a non-object resource.")
        allowed = {
            "ImageId", "SnapshotId", "Name", "Description", "OwnerId", "State",
            "VolumeId", "VolumeSize", "BlockDeviceMappings", "AvailabilityZone",
            "Region", "Tags", "InstanceId", "InstanceType", "ImageId",
        }
        safe = {}
        for key in allowed:
            if key not in resource:
                continue
            value = resource[key]
            if key == "Tags":
                safe[key] = [
                    {"Key": str(item.get("Key")), "Value": str(item.get("Value", ""))[:256]}
                    for item in value[:64]
                    if isinstance(item, dict) and item.get("Key") is not None
                ] if isinstance(value, list) else value
            elif isinstance(value, (str, int, float, bool)) or value is None:
                safe[key] = str(value)[:512] if isinstance(value, str) else value
            elif key == "BlockDeviceMappings" and isinstance(value, list):
                safe[key] = [
                    {
                        "SnapshotId": str((item.get("Ebs") or {}).get("SnapshotId"))[:128],
                        "VolumeSize": (item.get("Ebs") or {}).get("VolumeSize"),
                    }
                    for item in value[:128]
                    if isinstance(item, dict) and isinstance(item.get("Ebs"), dict)
                ]
        return safe

    def _aws_native_source(self, client, witness):
        source_id = str(witness["source_id"])
        if witness["source_type"] == "instance":
            response = client.describe_instances(InstanceIds=[source_id])
            if not isinstance(response, dict) or not isinstance(response.get("Reservations"), list):
                raise AWSNativeMalformedResponse("AWS returned a malformed source instance response.")
            resources = []
            for reservation in response["Reservations"]:
                if not isinstance(reservation, dict) or not isinstance(reservation.get("Instances"), list):
                    raise AWSNativeMalformedResponse("AWS returned a malformed source instance page.")
                resources.extend(reservation["Instances"])
            matches = [
                item for item in resources
                if isinstance(item, dict) and str(item.get("InstanceId") or "") == source_id
            ]
            if len(matches) != 1 or len(resources) != 1:
                raise AWSNativeOwnershipError("AWS source instance ownership did not match.")
            source = matches[0]
            state = str((source.get("State") or {}).get("Name") or "")
            if state and state not in {"running", "stopped"}:
                raise AWSNativeOwnershipError("AWS source instance is not backup eligible.")
        else:
            response = client.describe_volumes(VolumeIds=[source_id])
            if not isinstance(response, dict) or not isinstance(response.get("Volumes"), list):
                raise AWSNativeMalformedResponse("AWS returned a malformed source volume response.")
            resources = response["Volumes"]
            matches = [
                item for item in resources
                if isinstance(item, dict) and str(item.get("VolumeId") or "") == source_id
            ]
            if len(matches) != 1 or len(resources) != 1:
                raise AWSNativeOwnershipError("AWS source volume ownership did not match.")
            source = matches[0]
            state = str(source.get("State") or "")
            if state and state not in {"available", "in-use"}:
                raise AWSNativeOwnershipError("AWS source volume is not backup eligible.")
        if not self._aws_native_region_matches(source, witness["region"]):
            raise AWSNativeOwnershipError("AWS source resource region did not match.")
        owner_id = source.get("OwnerId")
        if owner_id not in (None, "") and str(owner_id) != str(witness["account_id"]):
            raise AWSNativeOwnershipError("AWS source resource account did not match.")
        return source

    @staticmethod
    def _aws_native_validate_source_configuration(configuration, witness):
        if not isinstance(configuration, dict):
            raise AWSNativeMalformedResponse(
                "AWS returned malformed source restore configuration."
            )
        source_type = str(witness.get("source_type") or "")
        if str(configuration.get("source_type") or "") != source_type:
            raise AWSNativeOwnershipError(
                "AWS source restore configuration type did not match."
            )
        if str(configuration.get("source_id") or "") != str(
            witness.get("source_id") or ""
        ):
            raise AWSNativeOwnershipError(
                "AWS source restore configuration identity did not match."
            )
        normalized = {
            "schema": 1,
            "source_type": source_type,
            "source_id": str(witness.get("source_id") or ""),
        }
        if source_type == "instance":
            instance_type = str(configuration.get("instance_type") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}", instance_type):
                raise AWSNativeMalformedResponse(
                    "AWS source instance type is missing or malformed."
                )
            security_group_ids = []
            groups = configuration.get("security_group_ids")
            if groups is None:
                groups = []
            if (
                not isinstance(groups, list)
                or len(groups) > 32
            ):
                raise AWSNativeMalformedResponse(
                    "AWS source security-group configuration is malformed."
                )
            for group_id in groups:
                group_id = str(group_id or "").strip()
                if not re.fullmatch(r"sg-[0-9A-Fa-f]{8,32}", group_id):
                    raise AWSNativeMalformedResponse(
                        "AWS source security-group identity is malformed."
                    )
                if group_id not in security_group_ids:
                    security_group_ids.append(group_id)
            subnet_id = str(configuration.get("subnet_id") or "").strip()
            if subnet_id and not re.fullmatch(
                r"subnet-[0-9A-Fa-f]{8,32}", subnet_id
            ):
                raise AWSNativeMalformedResponse(
                    "AWS source subnet identity is malformed."
                )
            key_name = str(configuration.get("key_name") or "").strip()
            if len(key_name) > 255 or any(ord(value) < 32 for value in key_name):
                raise AWSNativeMalformedResponse(
                    "AWS source key-name configuration is malformed."
                )
            normalized.update(
                {
                    "instance_type": instance_type,
                    "subnet_id": subnet_id,
                    "security_group_ids": security_group_ids,
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
            raise AWSNativeMalformedResponse(
                "AWS source volume availability zone is missing or malformed."
            )
        normalized["availability_zone"] = availability_zone
        return normalized

    @classmethod
    def _aws_native_source_configuration(cls, source, witness):
        """Persist the minimum non-secret source settings needed for a restore.

        A backup must remain restorable after its source is deleted. AMIs do not
        retain the source instance type, subnet, security groups, or EC2 key-name,
        and EBS snapshots do not provide a future placement zone. Capture those
        immutable restore inputs before the snapshot mutation and keep them in the
        fenced provider ledger; never retain addresses, user data, IAM credentials,
        or provider response bodies.
        """
        if not isinstance(source, dict):
            raise AWSNativeMalformedResponse(
                "AWS returned malformed source restore configuration."
            )
        source_type = str(witness.get("source_type") or "")
        if source_type == "instance":
            groups = source.get("SecurityGroups") or []
            if (
                not isinstance(groups, list)
                or len(groups) > 32
                or any(not isinstance(group, dict) for group in groups)
            ):
                raise AWSNativeMalformedResponse(
                    "AWS source security-group configuration is malformed."
                )
            configuration = {
                "source_type": source_type,
                "source_id": str(witness.get("source_id") or ""),
                "instance_type": source.get("InstanceType"),
                "subnet_id": source.get("SubnetId") or "",
                "security_group_ids": [
                    group.get("GroupId")
                    for group in groups
                ],
                "key_name": source.get("KeyName") or "",
            }
        else:
            configuration = {
                "source_type": source_type,
                "source_id": str(witness.get("source_id") or ""),
                "availability_zone": source.get("AvailabilityZone"),
            }
        return cls._aws_native_validate_source_configuration(
            configuration,
            witness,
        )

    @classmethod
    def _aws_native_find_owned(cls, resources, witness):
        if any(not isinstance(item, dict) for item in resources):
            raise AWSNativeMalformedResponse("AWS returned a malformed native resource.")
        marker = str(witness["marker"])
        marked = []
        for item in resources:
            label = str(item.get("Name") or item.get("Description") or "")
            if label == marker:
                marked.append(item)
        matches = [
            item
            for item in marked
            if cls._aws_native_backup_owned(item, witness)
        ]
        if len(matches) > 1:
            raise AWSNativeDuplicateMatch("Multiple exact AWS native resources matched.")
        if marked and len(matches) != len(marked):
            raise AWSNativeOwnershipError("AWS native resource ownership did not match.")
        return matches[0] if matches else None

    @classmethod
    def _aws_native_find_by_id(cls, resources, witness, resource_id):
        if any(not isinstance(item, dict) for item in resources):
            raise AWSNativeMalformedResponse("AWS returned a malformed native resource.")
        matches = [
            item
            for item in resources
            if str(
                (
                    item.get("ImageId")
                    if witness["source_type"] == "instance"
                    else item.get("SnapshotId")
                )
                or ""
            ) == str(resource_id)
        ]
        if not matches:
            raise AWSNativeResourceNotFound(
                "AWS native resource is not currently visible."
            )
        if len(matches) > 1:
            raise AWSNativeDuplicateMatch("AWS returned duplicate native resource IDs.")
        if not cls._aws_native_backup_owned(matches[0], witness, resource_id):
            raise AWSNativeOwnershipError("AWS native resource ownership did not match.")
        return matches[0]

    def _aws_native_lists(self, client, witness, *, resource_id=None):
        if witness["source_type"] == "instance":
            params = {"Owners": [witness["account_id"]]}
            if resource_id:
                params["ImageIds"] = [str(resource_id)]
            else:
                params["Filters"] = [
                    {"Name": "name", "Values": [witness["marker"]]},
                ]
            return self._aws_native_page_collection(
                client, "describe_images", "Images", params
            )
        params = {
            "OwnerIds": [witness["account_id"]],
        }
        if resource_id:
            params["SnapshotIds"] = [str(resource_id)]
        else:
            params["Filters"] = [
                {"Name": "description", "Values": [witness["marker"]]},
            ]
        return self._aws_native_page_collection(
            client, "describe_snapshots", "Snapshots", params
        )

    def _aws_native_adopt(
        self,
        resource,
        witness,
        *,
        owner=None,
        token=None,
        provider_status=None,
    ):
        resource_id = (
            resource.get("ImageId")
            if witness["source_type"] == "instance"
            else resource.get("SnapshotId")
        )
        if not resource_id:
            raise AWSNativeMalformedResponse("AWS native resource ID was missing.")
        if not self._aws_native_backup_owned(resource, witness, resource_id):
            raise AWSNativeOwnershipError("AWS native resource ownership did not match.")
        safe_resource = self._aws_native_safe_resource(resource)
        size = None
        if witness["source_type"] == "volume":
            size = resource.get("VolumeSize")
        else:
            size = sum(
                int((mapping.get("Ebs") or {}).get("VolumeSize") or 0)
                for mapping in resource.get("BlockDeviceMappings") or []
                if isinstance(mapping, dict) and isinstance(mapping.get("Ebs"), dict)
            )
        fence = {}
        if owner is not None and token is not None:
            fence = {"lease_owner": owner, "lease_token": token}
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh)
            if fence and not state.lease_matches(
                owner, token, now=timezone.now(), require_live=True
            ):
                raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")
            metadata = dict(fresh.metadata or {}) if isinstance(fresh.metadata, dict) else {}
            metadata["_aws_native"] = safe_resource
            fresh.unique_id = str(resource_id)
            fresh.region = witness["region"]
            if size is not None:
                fresh.size_gigabytes = float(size)
            fresh.metadata = metadata
            fields = ["unique_id", "region", "metadata", "modified"]
            if size is not None:
                fields.insert(2, "size_gigabytes")
            fresh.save(update_fields=fields)
            provider_metadata = dict(state.provider_metadata or {})
            provider_metadata.update(
                {
                    self._AWS_NATIVE_REQUEST_KEY: dict(witness),
                    "resource": safe_resource,
                    "create_attempted": True,
                    "outcome_unknown": False,
                    "adopted": True,
                }
            )
            state.provider_operation_id = ""
            state.provider_resource_id = str(resource_id)[:255]
            state.provider_idempotency_key = witness["marker"]
            state.provider_status = str(
                provider_status or resource.get("State") or "accepted"
            )[:64]
            state.provider_metadata = provider_metadata
            state.reconciliation_state = state.ReconciliationState.RESOLVED
            state.reconciliation_reason = "aws_native_resource_adopted"
            state.last_error_code = ""
            state.next_retry_at = None
            state.save()
        self.unique_id = str(resource_id)
        self.region = witness["region"]
        self.metadata = metadata
        if size is not None:
            self.size_gigabytes = float(size)
        return self

    def _aws_native_reconcile_zero_match(
        self,
        witness,
        *,
        owner,
        token,
        page_count,
        provider_id="",
    ):
        """Record an eventually-consistent empty scan without issuing a write.

        Once a create request has an ambiguous outcome, an empty AWS inventory is
        not proof that the provider rejected it.  We perform a bounded number of
        read-only scans across a bounded window and then stop for manual review;
        this method never authorizes a second create request.
        """
        state, _request = self._aws_native_request()
        metadata = dict(state.provider_metadata or {}) if state is not None else {}
        attempted = bool(
            metadata.get("create_attempted")
            or metadata.get("outcome_unknown")
            or provider_id
        )
        if not attempted:
            return False

        now = timezone.now()
        try:
            window_seconds = int(
                getattr(settings, "AWS_NATIVE_RECONCILIATION_WINDOW_SECONDS", 900)
            )
        except (TypeError, ValueError):
            window_seconds = 900
        window_seconds = max(60, min(window_seconds, 86400))
        try:
            required_observations = int(
                getattr(settings, "AWS_NATIVE_RECONCILIATION_MIN_OBSERVATIONS", 3)
            )
        except (TypeError, ValueError):
            required_observations = 3
        required_observations = max(2, min(required_observations, 20))

        started_at = None
        raw_started_at = metadata.get("create_started_at")
        if raw_started_at:
            try:
                started_at = datetime.fromisoformat(
                    str(raw_started_at).replace("Z", "+00:00")
                )
                if timezone.is_naive(started_at):
                    started_at = timezone.make_aware(started_at)
            except (TypeError, ValueError, OverflowError):
                started_at = None
        if started_at is None:
            started_at = getattr(state, "created", None) or now
        deadline = started_at + timedelta(seconds=window_seconds)
        observations = int(metadata.get("zero_match_observations") or 0) + 1
        scan_metadata = {
            "create_attempted": True,
            "outcome_unknown": True,
            "zero_match_observations": observations,
            "last_zero_match_at": now.isoformat(),
            "reconciliation_deadline": deadline.isoformat(),
            "scan_page_count": int(page_count or 0),
            "scan_match_count": 0,
            "scan_complete": True,
        }
        if provider_id:
            scan_metadata["provider_resource_id"] = str(provider_id)[:255]
        self._aws_native_record_outcome(
            owner=owner,
            token=token,
            category="not_found_during_reconciliation",
            error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
            retry_at=now + timedelta(seconds=60),
            provider_status="not_found_during_reconciliation",
            operation="create_reconcile",
            metadata=scan_metadata,
        )
        from apps.console.backup.models import CoreBackupExecution

        saved = self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
            reason="aws_native_create_outcome_unknown",
            metadata=scan_metadata,
            lease_owner=owner,
            lease_token=token,
        )
        if saved is None:
            raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")
        self._aws_native_set_status(
            UtilBackup.Status.IN_PROGRESS,
            owner=owner,
            token=token,
        )
        if now < deadline or observations < required_observations:
            return True
        self._aws_native_create_failure(
            "PROVIDER_RECONCILIATION_REQUIRED",
            owner=owner,
            token=token,
            manual_review=True,
            reason="aws_native_zero_match_after_ambiguous_create",
        )
        return None

    def _aws_native_record_outcome(
        self,
        *,
        owner=None,
        token=None,
        category,
        error_code=None,
        retry_at=None,
        provider_status=None,
        operation="poll",
        metadata=None,
    ):
        fence = {}
        if owner is not None and token is not None:
            fence = {"lease_owner": owner, "lease_token": token}
        saved = self.record_provider_reference(
            provider_status=provider_status or category,
            metadata={
                "provider": (
                    "aws_ec2"
                    if self.aws.resource_type == "instance"
                    else "aws_ebs"
                ),
                "operation": operation,
                **dict(metadata or {}),
            },
            **fence,
        )
        if fence and saved is None:
            raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")
        if error_code:
            saved = self.record_execution_error(
                code=error_code,
                retry_at=retry_at,
                retryable=retry_at is not None,
                **fence,
            )
            if fence and saved is None:
                raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")

    def _aws_native_set_status(self, status, *, owner=None, token=None):
        fence = {}
        if owner is not None and token is not None:
            fence = {"lease_owner": owner, "lease_token": token}
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh)
            if fence and not state.lease_matches(
                owner, token, now=timezone.now(), require_live=True
            ):
                raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")
            fresh.status = status
            fresh.save(update_fields=["status", "modified"])
        self.status = status

    @staticmethod
    def _aws_native_exception_outcome(error, *, mutation=False):
        status_code, provider_code, headers = _provider_exception_details(error)
        try:
            status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        if provider_code in _PROVIDER_AUTH_ERROR_CODES or status_code in _PROVIDER_AUTH_HTTP_CODES:
            return "auth_failed", "PROVIDER_AUTH_FAILED", None, False, False
        if provider_code in _PROVIDER_NOT_FOUND_ERROR_CODES or status_code == 404:
            return "not_found", "PROVIDER_NOT_FOUND", None, False, False
        if provider_code in _PROVIDER_RATE_LIMIT_ERROR_CODES or status_code == 429:
            return "rate_limited", "PROVIDER_RATE_LIMIT", _provider_retry_at(headers), True, mutation
        if (
            provider_code in _PROVIDER_TRANSIENT_ERROR_CODES
            or status_code in _PROVIDER_TRANSIENT_HTTP_CODES
            or (status_code is not None and status_code >= 500)
        ):
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", _provider_retry_at(headers), True, mutation
        if isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
            return "timeout", "PROVIDER_TIMEOUT", _provider_retry_at(), True, mutation
        if isinstance(error, requests.exceptions.ConnectionError):
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", _provider_retry_at(), True, mutation
        if isinstance(error, (ValueError, KeyError, TypeError, json.JSONDecodeError)):
            return "malformed_provider_response", "PROVIDER_MALFORMED_RESPONSE", None, False, mutation
        return "provider_failed", "PROVIDER_FAILED", None, False, mutation

    def _aws_native_create_failure(
        self,
        code,
        *,
        owner,
        token,
        manual_review=False,
        reason="aws_native_create_failed",
    ):
        self._aws_native_record_outcome(
            owner=owner,
            token=token,
            category="terminal_failure",
            error_code=code,
            provider_status=reason,
            operation="create",
        )
        from apps.console.backup.models import CoreBackupExecution

        self.set_reconciliation_state(
            reconciliation_state=(
                CoreBackupExecution.ReconciliationState.MANUAL_REVIEW
                if manual_review
                else CoreBackupExecution.ReconciliationState.RESOLVED
            ),
            reason=reason,
            metadata={"provider": "aws_native", "error_code": code},
            lease_owner=owner,
            lease_token=token,
        )
        self._aws_native_set_status(
            UtilBackup.Status.FAILED,
            owner=owner,
            token=token,
        )

    def _aws_native_mark_create_started(self, witness, *, owner, token):
        from apps.console.backup.models import CoreBackupExecution

        self._aws_native_persist_witness(
            witness,
            owner=owner,
            token=token,
            provider_status="create_requested",
            metadata={
                "create_attempted": True,
                "outcome_unknown": True,
                "create_started_at": timezone.now().isoformat(),
            },
        )
        saved = self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
            reason="aws_native_create_outcome_unknown",
            metadata={"provider": "aws_native", "create_attempted": True},
            lease_owner=owner,
            lease_token=token,
        )
        if saved is None:
            raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")

    def _aws_native_persist_provider_id(self, resource_id, witness, *, owner, token):
        saved = self.record_provider_reference(
            resource_id=str(resource_id),
            idempotency_key=witness["marker"],
            provider_status="accepted",
            metadata={
                self._AWS_NATIVE_REQUEST_KEY: dict(witness),
                "create_attempted": True,
                "outcome_unknown": True,
                "provider_resource_id": str(resource_id),
            },
            lease_owner=owner,
            lease_token=token,
        )
        if saved is None:
            raise AWSNativeLeaseLost("The AWS native worker lost its execution lease.")

    def create_snapshot(self, task_id=None):
        """Create or adopt one native EC2 AMI/EBS snapshot crash-safely."""
        lease = self._aws_native_create_lease(task_id)
        if lease is None:
            return None
        owner, token, release_on_success = lease
        completed = False
        mutation_started = False
        try:
            auth = self.aws.node.connection.auth_aws
            kind = self._aws_native_kind()
            region = self._aws_native_region(auth)
            source_id = str(self.aws.unique_id or "")
            marker = self._aws_native_marker(self)
            provisional = self._aws_native_witness(
                marker=marker,
                provider="aws_ec2" if kind == "instance" else "aws_ebs",
                source_id=source_id,
                source_type=kind,
                account_id="pending",
                region=region,
                strict_identity=True,
            )
            # The immutable marker/source/region is committed before the STS or
            # EC2 mutation path. ``pending`` is replaced only after the caller
            # identity is verified.
            provisional["account_id"] = "pending"
            self._aws_native_persist_witness(
                provisional,
                owner=owner,
                token=token,
                provider_status="reconciling",
            )
            account_id = self._aws_native_account_id(auth)
            witness = self._aws_native_witness(
                marker=marker,
                provider="aws_ec2" if kind == "instance" else "aws_ebs",
                source_id=source_id,
                source_type=kind,
                account_id=account_id,
                region=region,
                strict_identity=True,
            )
            self._aws_native_persist_witness(
                witness,
                owner=owner,
                token=token,
                provider_status="reconciling",
            )
            client = auth.get_client("ec2")
            state = self.get_execution_state(create=False)
            provider_metadata = (
                dict(state.provider_metadata or {}) if state is not None else {}
            )
            stored_source_configuration = provider_metadata.get(
                "source_configuration"
            )
            if stored_source_configuration is not None:
                source_configuration = (
                    self._aws_native_validate_source_configuration(
                        stored_source_configuration,
                        witness,
                    )
                )
            else:
                source = self._aws_native_source(client, witness)
                source_configuration = self._aws_native_source_configuration(
                    source, witness
                )
                self._aws_native_persist_witness(
                    witness,
                    owner=owner,
                    token=token,
                    provider_status="reconciling",
                    metadata={"source_configuration": source_configuration},
                )

            state, request = self._aws_native_request()
            provider_id = str(
                self.unique_id
                or (state.provider_resource_id if state is not None else "")
                or ""
            )
            if provider_id:
                resources, pages = self._aws_native_lists(
                    client, witness, resource_id=provider_id
                )
                try:
                    resource = self._aws_native_find_by_id(
                        resources,
                        witness,
                        provider_id,
                    )
                except AWSNativeResourceNotFound:
                    pending = self._aws_native_reconcile_zero_match(
                        witness,
                        owner=owner,
                        token=token,
                        page_count=pages,
                        provider_id=provider_id,
                    )
                    if pending:
                        raise AWSNativeReconciliationPending()
                    if pending is None:
                        completed = True
                        return self
                    raise
                self._aws_native_adopt(
                    resource,
                    witness,
                    owner=owner,
                    token=token,
                    provider_status=resource.get("State"),
                )
                completed = True
                return self

            resources, pages = self._aws_native_lists(client, witness)
            existing = self._aws_native_find_owned(resources, witness)
            if existing is not None:
                self._aws_native_adopt(
                    existing,
                    witness,
                    owner=owner,
                    token=token,
                    provider_status=existing.get("State"),
                )
                completed = True
                return self

            pending = self._aws_native_reconcile_zero_match(
                witness,
                owner=owner,
                token=token,
                page_count=pages,
            )
            if pending:
                raise AWSNativeReconciliationPending()
            if pending is None:
                completed = True
                return self

            self._aws_native_mark_create_started(witness, owner=owner, token=token)
            mutation_started = True
            tags = [
                {"Key": "BackupSheepBackup", "Value": marker},
                {"Key": "BackupSheepSourceId", "Value": source_id},
                {"Key": "BackupSheepSourceType", "Value": kind},
                {"Key": "BackupSheepAccountId", "Value": account_id},
                {"Key": "BackupSheepRegion", "Value": region},
            ]
            if kind == "instance":
                response = client.create_image(
                    Description=marker,
                    InstanceId=source_id,
                    Name=marker,
                    NoReboot=self.aws.no_reboot,
                    TagSpecifications=[
                        {"ResourceType": "image", "Tags": tags},
                        {"ResourceType": "snapshot", "Tags": tags},
                    ],
                )
                resource_id = (response or {}).get("ImageId") if isinstance(response, dict) else None
            else:
                response = client.create_snapshot(
                    Description=marker,
                    VolumeId=source_id,
                    TagSpecifications=[{"ResourceType": "snapshot", "Tags": tags}],
                )
                resource_id = (response or {}).get("SnapshotId") if isinstance(response, dict) else None
            if not resource_id:
                raise AWSNativeMalformedResponse("AWS did not return a native resource ID.")
            # Persist the provider ID before a follow-up describe. A crash here is
            # recoverable from this pointer or the complete marker inventory.
            self._aws_native_persist_provider_id(
                resource_id, witness, owner=owner, token=token
            )
            resources, pages = self._aws_native_lists(
                client, witness, resource_id=str(resource_id)
            )
            try:
                resource = self._aws_native_find_by_id(
                    resources,
                    witness,
                    str(resource_id),
                )
            except AWSNativeResourceNotFound:
                pending = self._aws_native_reconcile_zero_match(
                    witness,
                    owner=owner,
                    token=token,
                    page_count=pages,
                    provider_id=str(resource_id),
                )
                if pending:
                    raise AWSNativeReconciliationPending()
                if pending is None:
                    completed = True
                    return self
                raise
            self._aws_native_adopt(
                resource,
                witness,
                owner=owner,
                token=token,
                provider_status=resource.get("State"),
            )
            completed = True
            return self
        except AWSNativeLeaseLost:
            return False
        except AWSNativeReconciliationPending:
            raise
        except (AWSNativeDuplicateMatch, AWSNativeOwnershipError, AWSNativeMalformedResponse) as error:
            code = (
                "PROVIDER_DUPLICATE_MATCH"
                if isinstance(error, AWSNativeDuplicateMatch)
                else "PROVIDER_MALFORMED_RESPONSE"
                if isinstance(error, AWSNativeMalformedResponse)
                else "PROVIDER_OWNERSHIP_MISMATCH"
            )
            self._aws_native_create_failure(
                code,
                owner=owner,
                token=token,
                manual_review=True,
                reason=code.lower(),
            )
            completed = True
            return self
        except Exception as error:
            category, code, retry_at, retryable, unknown = self._aws_native_exception_outcome(
                error, mutation=mutation_started
            )
            if mutation_started or unknown:
                self._aws_native_record_outcome(
                    owner=owner,
                    token=token,
                    category=category,
                    error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                    retry_at=retry_at,
                    provider_status=category,
                    operation="create",
                    metadata={"outcome_unknown": True, "provider_error": code},
                )
                from apps.console.backup.models import CoreBackupExecution

                self.set_reconciliation_state(
                    reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                    reason="aws_native_create_outcome_unknown",
                    metadata={"provider_error": code},
                    lease_owner=owner,
                    lease_token=token,
                )
                raise
            if retryable:
                self._aws_native_record_outcome(
                    owner=owner,
                    token=token,
                    category=category,
                    error_code=code,
                    retry_at=retry_at,
                    provider_status=category,
                    operation="create",
                )
                self._aws_native_set_status(
                    UtilBackup.Status.IN_PROGRESS,
                    owner=owner,
                    token=token,
                )
                raise
            self._aws_native_create_failure(
                code,
                owner=owner,
                token=token,
                manual_review=code in {
                    "PROVIDER_MALFORMED_RESPONSE",
                    "PROVIDER_OWNERSHIP_MISMATCH",
                },
                reason=category,
            )
            completed = True
            return self
        finally:
            if release_on_success and completed:
                self._aws_native_release_create(owner, token)

    def poll_status(self):
        """Perform one categorized, ownership-checked AWS status check."""
        from ..node.models import CoreNode

        if self.aws.resource_type in {"s3", "dynamodb"}:
            try:
                from apps._tasks.integration.aws_backup import describe_backup_job

                metadata = self.metadata if isinstance(self.metadata, dict) else {}
                aws_backup = dict(metadata.get("_aws_backup") or {})
                job_id = self.unique_id or aws_backup.get("job_id")
                if not job_id:
                    return _provider_failed(
                        self,
                        provider="aws_backup",
                        state="missing_provider_id",
                        code="PROVIDER_MALFORMED_RESPONSE",
                    )

                result = describe_backup_job(
                    self.aws.node.connection.auth_aws,
                    job_id,
                )
                expected_resource_arn = aws_backup.get("resource_arn")
                if str(result.get("BackupJobId") or "") != str(job_id) or (
                    expected_resource_arn
                    and str(result.get("ResourceArn") or "")
                    != str(expected_resource_arn)
                ):
                    return _provider_failed(
                        self,
                        provider="aws_backup",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                aws_backup.update(
                    {
                        "job_id": job_id,
                        # boto3 returns datetime values in the provider
                        # response; normalize before persisting to JSONField.
                        "backup_job": json.loads(
                            json.dumps(result, cls=DjangoJSONEncoder)
                        ),
                    }
                )
                recovery_point_arn = result.get("RecoveryPointArn")
                if recovery_point_arn:
                    aws_backup["recovery_point_arn"] = recovery_point_arn
                backup_size = result.get("BackupSizeInBytes")
                if backup_size is not None:
                    self.size_gigabytes = float(backup_size) / 1000**3
                metadata["_aws_backup"] = aws_backup
                self.metadata = metadata

                state = str(result.get("State") or "").upper()
                if state in {"COMPLETED", "COMPLETE"}:
                    self.status = UtilBackup.Status.COMPLETE
                    self.save()
                    _record_provider_outcome(
                        self,
                        provider="aws_backup",
                        category="complete",
                        provider_status=state,
                        resource_id=recovery_point_arn,
                        operation_id=job_id,
                    )
                    return UtilBackup.Status.COMPLETE
                # PARTIAL is a terminal provider result, not an in-progress
                # state. AWS Backup may complete a job with a warning for some
                # resource types, but a partial recovery point is not a fully
                # verified BackupSheep backup.
                if state in {"FAILED", "ABORTED", "EXPIRED", "PARTIAL"}:
                    self.save(update_fields=["metadata", "size_gigabytes", "modified"])
                    return _provider_failed(
                        self, provider="aws_backup", state=state
                    )
                self.save(update_fields=["metadata", "size_gigabytes", "modified"])
                if state in {"CREATED", "PENDING", "RUNNING", "ABORTING"}:
                    return _provider_in_progress(
                        self,
                        provider="aws_backup",
                        state=state,
                        resource_id=recovery_point_arn,
                        operation_id=job_id,
                    )
                return _provider_failed(
                    self,
                    provider="aws_backup",
                    state="malformed_provider_state",
                    code="PROVIDER_MALFORMED_RESPONSE",
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="aws_backup"
                )

        try:
            kind = self._aws_native_kind()
            provider = "aws_ec2" if kind == "instance" else "aws_ebs"
            from apps.console.backup.models import CoreBackupExecution

            execution, _request = self._aws_native_request()
            if (
                execution is not None
                and execution.lease_is_active()
                and execution.phase in {"create", "provider_create"}
            ):
                return _provider_in_progress(
                    self,
                    provider=provider,
                    state="create_reconciliation",
                    resource_id=self.unique_id or execution.provider_resource_id,
                )
            auth = self.aws.node.connection.auth_aws
            witness = self._aws_native_current_witness(auth)
            client = auth.get_client("ec2")
            owner = execution.lease_owner if execution and execution.phase == "poll" else None
            token = str(execution.lease_token) if execution and execution.phase == "poll" else None
            provider_id = str(
                self.unique_id
                or (execution.provider_resource_id if execution is not None else "")
                or ""
            )
            if provider_id:
                resources, pages = self._aws_native_lists(
                    client, witness, resource_id=provider_id
                )
                try:
                    resource = self._aws_native_find_by_id(
                        resources,
                        witness,
                        provider_id,
                    )
                except AWSNativeResourceNotFound:
                    pending = self._aws_native_reconcile_zero_match(
                        witness,
                        owner=owner,
                        token=token,
                        page_count=pages,
                        provider_id=provider_id,
                    )
                    if pending:
                        return UtilBackup.Status.IN_PROGRESS
                    if pending is None:
                        return UtilBackup.Status.FAILED
                    raise
            else:
                resources, pages = self._aws_native_lists(client, witness)
                resource = self._aws_native_find_owned(resources, witness)
                if resource is None:
                    metadata = dict(execution.provider_metadata or {}) if execution else {}
                    attempted = bool(
                        metadata.get("create_attempted") or metadata.get("outcome_unknown")
                    )
                    if attempted:
                        pending = self._aws_native_reconcile_zero_match(
                            witness,
                            owner=owner,
                            token=token,
                            page_count=pages,
                        )
                        if pending:
                            return UtilBackup.Status.IN_PROGRESS
                        if pending is None:
                            return UtilBackup.Status.FAILED
                    code = "PROVIDER_NOT_FOUND"
                    self._aws_native_record_outcome(
                        owner=owner,
                        token=token,
                        category="not_found",
                        error_code=code,
                        operation="poll",
                    )
                    self._aws_native_set_status(
                        UtilBackup.Status.FAILED,
                        owner=owner,
                        token=token,
                    )
                    return UtilBackup.Status.FAILED
            self._aws_native_adopt(
                resource,
                witness,
                owner=owner,
                token=token,
                provider_status=resource.get("State"),
            )
            state = str(resource.get("State") or "").lower()
            if (kind == "instance" and state == "available") or (
                kind == "volume" and state == "completed"
            ):
                self._aws_native_set_status(
                    UtilBackup.Status.COMPLETE,
                    owner=owner,
                    token=token,
                )
                self._aws_native_record_outcome(
                    owner=owner,
                    token=token,
                    category="complete",
                    provider_status=state,
                    operation="poll",
                )
                return UtilBackup.Status.COMPLETE
            if (kind == "instance" and state in {"pending", "transient"}) or (
                kind == "volume" and state == "pending"
            ):
                self._aws_native_record_outcome(
                    owner=owner,
                    token=token,
                    category="in_progress",
                    provider_status=state,
                    operation="poll",
                )
                return UtilBackup.Status.IN_PROGRESS
            if state in {"failed", "error", "invalid", "deregistered"}:
                self._aws_native_record_outcome(
                    owner=owner,
                    token=token,
                    category="terminal_failure",
                    error_code="PROVIDER_FAILED",
                    provider_status=state,
                    operation="poll",
                )
                self._aws_native_set_status(
                    UtilBackup.Status.FAILED,
                    owner=owner,
                    token=token,
                )
                return UtilBackup.Status.FAILED
            self._aws_native_record_outcome(
                owner=owner,
                token=token,
                category="malformed_provider_response",
                error_code="PROVIDER_MALFORMED_RESPONSE",
                provider_status="malformed_provider_state",
                operation="poll",
            )
            self._aws_native_set_status(
                UtilBackup.Status.FAILED,
                owner=owner,
                token=token,
            )
            return UtilBackup.Status.FAILED
        except AWSNativeDuplicateMatch:
            self._aws_native_record_outcome(
                category="duplicate_matches",
                error_code="PROVIDER_DUPLICATE_MATCH",
                operation="poll",
            )
            self._aws_native_set_status(UtilBackup.Status.FAILED)
            return UtilBackup.Status.FAILED
        except AWSNativeOwnershipError:
            self._aws_native_record_outcome(
                category="ownership_mismatch",
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                operation="poll",
            )
            self._aws_native_set_status(UtilBackup.Status.FAILED)
            return UtilBackup.Status.FAILED
        except AWSNativeMalformedResponse:
            self._aws_native_record_outcome(
                category="malformed_provider_response",
                error_code="PROVIDER_MALFORMED_RESPONSE",
                operation="poll",
            )
            self._aws_native_set_status(UtilBackup.Status.FAILED)
            return UtilBackup.Status.FAILED
        except AWSNativeResourceNotFound:
            self._aws_native_record_outcome(
                category="not_found",
                error_code="PROVIDER_NOT_FOUND",
                operation="poll",
            )
            self._aws_native_set_status(UtilBackup.Status.FAILED)
            return UtilBackup.Status.FAILED
        except AWSNativeLeaseLost:
            return UtilBackup.Status.IN_PROGRESS
        except Exception as error:
            category, code, retry_at, retryable, _unknown = self._aws_native_exception_outcome(
                error, mutation=False
            )
            self._aws_native_record_outcome(
                category=category,
                error_code=code,
                retry_at=retry_at,
                operation="poll",
            )
            if retryable:
                return UtilBackup.Status.IN_PROGRESS
            self._aws_native_set_status(UtilBackup.Status.FAILED)
            return UtilBackup.Status.FAILED

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.aws.node

    @staticmethod
    def _aws_delete_not_found(error):
        _status, code, _headers = _provider_exception_details(error)
        return code in _PROVIDER_NOT_FOUND_ERROR_CODES

    def _claim_aws_delete_lease(self):
        """Elect one exact-resource AWS deletion worker with a fenced JSON lease."""
        now = timezone.now()
        try:
            lease_seconds = int(
                getattr(settings, "BACKUP_DELETE_LEASE_SECONDS", 300)
            )
        except (TypeError, ValueError):
            lease_seconds = 300
        lease_seconds = max(60, min(lease_seconds, 3600))
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            state = metadata.get("_aws_delete")
            state = dict(state) if isinstance(state, dict) else {}
            try:
                active_until = float(state.get("lease_expires_at") or 0)
            except (TypeError, ValueError):
                active_until = 0
            if state.get("lease_token") and active_until > now.timestamp():
                return None, None
            token = str(uuid.uuid4())
            state.update(
                {
                    "schema": 1,
                    "lease_token": token,
                    "lease_expires_at": now.timestamp() + lease_seconds,
                    "lease_seconds": lease_seconds,
                }
            )
            metadata["_aws_delete"] = state
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return state, token

    def _checkpoint_aws_delete(self, state, token, *, release=False):
        """Persist one deletion phase only while the caller owns the fence."""
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            metadata = dict(locked.metadata or {})
            current = metadata.get("_aws_delete")
            current = dict(current) if isinstance(current, dict) else {}
            if str(current.get("lease_token") or "") != str(token or ""):
                raise AWSDeleteLeaseLost(
                    "AWS deletion ownership changed while work was in progress."
                )
            if release:
                # A provider call may have raised after this worker committed newer
                # child progress. Release the current database checkpoint rather than
                # overwriting it with the caller's stale pre-call copy.
                checkpoint = dict(current)
                checkpoint.pop("lease_token", None)
                checkpoint.pop("lease_expires_at", None)
                checkpoint.pop("lease_seconds", None)
            else:
                checkpoint = dict(state)
                lease_seconds = max(
                    60,
                    min(int(checkpoint.get("lease_seconds") or 300), 3600),
                )
                checkpoint["lease_token"] = token
                checkpoint["lease_seconds"] = lease_seconds
                checkpoint["lease_expires_at"] = (
                    timezone.now().timestamp() + lease_seconds
                )
            checkpoint["updated_at"] = timezone.now().isoformat()
            metadata["_aws_delete"] = checkpoint
            locked.metadata = metadata
            locked.save(update_fields=["metadata", "modified"])
        self.metadata = metadata
        return checkpoint

    @staticmethod
    def _aws_account_id(auth):
        identity = auth.get_client("sts").get_caller_identity()
        account_id = str((identity or {}).get("Account") or "")
        if not re.fullmatch(r"[0-9]{12}", account_id):
            raise AWSDeleteOwnershipError(
                "AWS account ownership could not be verified."
            )
        return account_id

    @staticmethod
    def _aws_resource_absent_or_raise(callback, *, proven):
        try:
            return callback()
        except Exception as error:
            if CoreAWSBackup._aws_delete_not_found(error):
                if proven:
                    return None
                raise AWSDeleteUnprovenNotFound(
                    "AWS resource was absent before ownership was proven."
                ) from error
            raise

    def _aws_native_delete_witness(self, auth, state):
        """Return and freeze the exact native deletion identity before reads/mutation."""
        kind = self._aws_native_kind()
        region = self._aws_native_region(auth)
        verified_account = self._aws_account_id(auth)
        account_id = str(state.get("account_id") or verified_account)
        if account_id != verified_account:
            raise AWSDeleteOwnershipError("AWS deletion account scope changed.")
        source_id = str(self.aws.unique_id or "")
        resource_id = str(self.unique_id or "")
        if not source_id or not resource_id:
            raise AWSDeleteOwnershipError(
                "AWS native deletion requires exact resource and source IDs."
            )
        _execution, stored = self._aws_native_request()
        if stored:
            witness = dict(stored)
            for key, value in {
                "provider": "aws_ec2" if kind == "instance" else "aws_ebs",
                "source_id": source_id,
                "source_type": kind,
                "account_id": account_id,
                "region": region,
                "marker": self._aws_native_marker(self),
            }.items():
                if str(witness.get(key) or "") not in {str(value), "pending"}:
                    raise AWSDeleteOwnershipError(
                        "The durable AWS native deletion identity changed."
                    )
        else:
            witness = self._aws_native_witness(
                marker=self._aws_native_marker(self),
                provider="aws_ec2" if kind == "instance" else "aws_ebs",
                source_id=source_id,
                source_type=kind,
                account_id=account_id,
                region=region,
                strict_identity=False,
            )
        expected = {
            "kind": kind,
            "resource_id": resource_id,
            "source_id": source_id,
            "source_type": kind,
            "account_id": account_id,
            "region": region,
            "marker": witness["marker"],
        }
        for key, value in expected.items():
            existing = state.get(key)
            if existing not in (None, "") and str(existing) != str(value):
                raise AWSDeleteOwnershipError(
                    "AWS deletion checkpoint identity no longer matches this backup."
                )
        state.update(expected)
        state["witness"] = dict(witness)
        return witness

    def _delete_aws_backup_recovery_point(self, auth, state, token):
        from apps._tasks.integration.aws_backup import resource_arn as aws_resource_arn

        metadata = self.metadata if isinstance(self.metadata, dict) else {}
        aws_backup = metadata.get("_aws_backup") or {}
        recovery_point_arn = str(aws_backup.get("recovery_point_arn") or "")
        resource_arn = str(aws_backup.get("resource_arn") or "")
        expected_resource_arn = aws_resource_arn(
            auth,
            self.aws.resource_type,
            self.aws.unique_id,
        )
        if (
            not recovery_point_arn
            or not resource_arn
            or resource_arn != expected_resource_arn
        ):
            raise AWSDeleteOwnershipError(
                "AWS Backup deletion requires an exact recovery point and source ARN."
            )
        vault_name = (
            aws_backup.get("vault_name")
            or auth.backup_vault_name
            or "Default"
        )
        expected_identity = {
            "kind": self.aws.resource_type,
            "resource_id": recovery_point_arn,
            "source_id": resource_arn,
        }
        persisted_identity = {
            key: state.get(key) for key in expected_identity
        }
        if any(persisted_identity.values()) and persisted_identity != expected_identity:
            raise AWSDeleteOwnershipError(
                "AWS deletion checkpoint identity no longer matches this backup."
            )
        state.update(expected_identity)
        client = auth.get_client("backup")
        recovery_point = self._aws_resource_absent_or_raise(
            lambda: client.describe_recovery_point(
                BackupVaultName=vault_name,
                RecoveryPointArn=recovery_point_arn,
            ),
            proven=bool(
                state.get("ownership_verified")
                and state.get("delete_started")
            ),
        )
        if recovery_point is None:
            state["phase"] = "complete"
            return self._checkpoint_aws_delete(state, token)
        if str(recovery_point.get("RecoveryPointArn") or "") != recovery_point_arn or str(
            recovery_point.get("ResourceArn") or ""
        ) != resource_arn:
            raise AWSDeleteOwnershipError(
                "AWS Backup recovery point ownership did not match."
            )
        if state.get("delete_started") and not state.get("delete_completed"):
            state["phase"] = "delete_outcome_unknown"
            state = self._checkpoint_aws_delete(state, token)
            raise AWSDeleteAmbiguous(
                "AWS Backup deletion outcome is ambiguous while the exact recovery point remains visible."
            )
        state["ownership_verified"] = True
        state["phase"] = "ownership_verified"
        state = self._checkpoint_aws_delete(state, token)
        state["delete_started"] = True
        state["phase"] = "delete_requested"
        state = self._checkpoint_aws_delete(state, token)
        try:
            client.delete_recovery_point(
                BackupVaultName=vault_name,
                RecoveryPointArn=recovery_point_arn,
            )
        except Exception as error:
            if self._aws_delete_not_found(error):
                state.update({"delete_completed": True, "phase": "complete"})
                return self._checkpoint_aws_delete(state, token)
            category, code, _retry_at, _retryable, unknown = (
                self._aws_native_exception_outcome(error, mutation=True)
            )
            if unknown:
                state.update(
                    {
                        "phase": "delete_outcome_unknown",
                        "last_error_code": code,
                        "last_error_category": category,
                    }
                )
                self._checkpoint_aws_delete(state, token)
                raise AWSDeleteAmbiguous(
                    "AWS Backup deletion returned an ambiguous outcome."
                ) from error
            # A definitive rejection (for example AccessDenied) proves the
            # provider did not accept this request, so a later authorized worker
            # may retry after re-verifying ownership.
            state.update(
                {
                    "delete_started": False,
                    "phase": "delete_rejected",
                    "last_error_code": code,
                    "last_error_category": category,
                }
            )
            self._checkpoint_aws_delete(state, token)
            raise
        state["phase"] = "complete"
        state["delete_completed"] = True
        return self._checkpoint_aws_delete(state, token)

    def _delete_aws_ebs_snapshot(self, auth, state, token):
        witness = self._aws_native_delete_witness(auth, state)
        snapshot_id = str(self.unique_id or "")
        account_id = str(state["account_id"])
        client = auth.get_client("ec2")
        if state.get("delete_completed") or state.get("phase") == "complete":
            state["phase"] = "complete"
            return self._checkpoint_aws_delete(state, token)
        # Freeze the immutable deletion identity before the first reconciliation
        # read. A worker crash cannot leave the next worker guessing its scope.
        state = self._checkpoint_aws_delete(state, token)
        response = self._aws_resource_absent_or_raise(
            lambda: self._aws_native_page_collection(
                client,
                "describe_snapshots",
                "Snapshots",
                {"SnapshotIds": [snapshot_id], "OwnerIds": [account_id]},
            )[0],
            proven=bool(state.get("ownership_verified") and state.get("delete_started")),
        )
        snapshots = response or []
        if not snapshots:
            if state.get("ownership_verified") and state.get("delete_started"):
                state.update({"delete_completed": True, "phase": "complete"})
                return self._checkpoint_aws_delete(state, token)
            raise AWSDeleteUnprovenNotFound(
                "AWS EBS snapshot was absent before ownership was proven."
            )
        if len(snapshots) != 1 or not self._aws_native_backup_owned(
            snapshots[0], witness, snapshot_id
        ):
            raise AWSDeleteOwnershipError(
                "AWS EBS snapshot ownership did not match."
            )
        if state.get("delete_started") and not state.get("delete_completed"):
            state["phase"] = "delete_outcome_unknown"
            state = self._checkpoint_aws_delete(state, token)
            raise AWSDeleteAmbiguous(
                "AWS EBS deletion outcome is ambiguous while the exact snapshot remains visible."
            )
        state["ownership_verified"] = True
        state["phase"] = "ownership_verified"
        state = self._checkpoint_aws_delete(state, token)
        state["delete_started"] = True
        state["phase"] = "delete_requested"
        state = self._checkpoint_aws_delete(state, token)
        try:
            client.delete_snapshot(SnapshotId=snapshot_id)
        except Exception as error:
            if self._aws_delete_not_found(error):
                state.update({"delete_completed": True, "phase": "complete"})
                return self._checkpoint_aws_delete(state, token)
            category, code, _retry_at, _retryable, unknown = (
                self._aws_native_exception_outcome(error, mutation=True)
            )
            if unknown:
                state.update(
                    {
                        "phase": "delete_outcome_unknown",
                        "last_error_code": code,
                        "last_error_category": category,
                    }
                )
                self._checkpoint_aws_delete(state, token)
                raise AWSDeleteAmbiguous(
                    "AWS EBS deletion returned an ambiguous outcome."
                ) from error
            state.update(
                {
                    "delete_started": False,
                    "phase": "delete_rejected",
                    "last_error_code": code,
                    "last_error_category": category,
                }
            )
            self._checkpoint_aws_delete(state, token)
            raise
        state.update({"delete_completed": True, "phase": "complete"})
        return self._checkpoint_aws_delete(state, token)

    def _delete_aws_ami(self, auth, state, token):
        witness = self._aws_native_delete_witness(auth, state)
        image_id = str(self.unique_id or "")
        account_id = str(state["account_id"])
        client = auth.get_client("ec2")
        if state.get("phase") == "complete" and state.get("image_deregistered"):
            return self._checkpoint_aws_delete(state, token)
        state = self._checkpoint_aws_delete(state, token)

        if not state.get("ownership_verified"):
            response = self._aws_resource_absent_or_raise(
                lambda: self._aws_native_page_collection(
                    client,
                    "describe_images",
                    "Images",
                    {"ImageIds": [image_id], "Owners": [account_id]},
                )[0],
                proven=False,
            )
            images = response or []
            if not images:
                raise AWSDeleteUnprovenNotFound(
                    "AWS AMI was absent before ownership was proven."
                )
            if len(images) != 1 or not self._aws_native_backup_owned(
                images[0], witness, image_id
            ):
                raise AWSDeleteOwnershipError("AWS AMI ownership did not match.")
            mappings = images[0].get("BlockDeviceMappings")
            if not isinstance(mappings, list):
                raise AWSNativeMalformedResponse(
                    "AWS AMI omitted its block-device mapping."
                )
            child_ids = sorted(
                {
                    str((mapping.get("Ebs") or {}).get("SnapshotId"))
                    for mapping in mappings
                    if isinstance(mapping, dict)
                    and (mapping.get("Ebs") or {}).get("SnapshotId")
                }
            )
            previous_children = dict(state.get("children") or {})
            if previous_children and set(previous_children) != set(child_ids):
                raise AWSDeleteOwnershipError(
                    "AWS AMI child snapshot identity changed."
                )
            state["children"] = previous_children or {
                child_id: {"status": "pending", "delete_started": False}
                for child_id in child_ids
            }
            state["ownership_verified"] = True
            state["phase"] = "ownership_verified"
            state = self._checkpoint_aws_delete(state, token)

        if not state.get("image_deregistered"):
            if state.get("image_delete_started"):
                # A lost deregister response is not permission to issue a second
                # deregister call while the exact owned image remains visible.
                response = self._aws_resource_absent_or_raise(
                    lambda: self._aws_native_page_collection(
                        client,
                        "describe_images",
                        "Images",
                        {"ImageIds": [image_id], "Owners": [account_id]},
                    )[0],
                    proven=True,
                )
                if response:
                    if len(response) != 1 or not self._aws_native_backup_owned(
                        response[0], witness, image_id
                    ):
                        raise AWSDeleteOwnershipError(
                            "AWS AMI ownership changed during deletion."
                        )
                    state["phase"] = "delete_outcome_unknown"
                    state = self._checkpoint_aws_delete(state, token)
                    raise AWSDeleteAmbiguous(
                        "AWS AMI deregistration outcome is ambiguous while the image remains visible."
                    )
                state["image_deregistered"] = True
            else:
                state["image_delete_started"] = True
                state["phase"] = "image_deregister_requested"
                state = self._checkpoint_aws_delete(state, token)
                try:
                    client.deregister_image(ImageId=image_id)
                except Exception as error:
                    if not self._aws_delete_not_found(error):
                        category, code, _retry_at, _retryable, unknown = (
                            self._aws_native_exception_outcome(
                                error, mutation=True
                            )
                        )
                        if unknown:
                            state.update(
                                {
                                    "phase": "delete_outcome_unknown",
                                    "last_error_code": code,
                                    "last_error_category": category,
                                }
                            )
                            self._checkpoint_aws_delete(state, token)
                            raise AWSDeleteAmbiguous(
                                "AWS AMI deregistration returned an ambiguous outcome."
                            ) from error
                        state.update(
                            {
                                "image_delete_started": False,
                                "phase": "delete_rejected",
                                "last_error_code": code,
                                "last_error_category": category,
                            }
                        )
                        self._checkpoint_aws_delete(state, token)
                        raise
                state["image_deregistered"] = True
            state["phase"] = "deleting_child_snapshots"
            state = self._checkpoint_aws_delete(state, token)

        children = dict(state.get("children") or {})
        for snapshot_id in sorted(children):
            child = dict(children[snapshot_id] or {})
            if child.get("status") == "deleted" or child.get("delete_completed"):
                continue
            response = self._aws_resource_absent_or_raise(
                lambda snapshot_id=snapshot_id: self._aws_native_page_collection(
                    client,
                    "describe_snapshots",
                    "Snapshots",
                    {"SnapshotIds": [snapshot_id], "OwnerIds": [account_id]},
                )[0],
                proven=True,
            )
            snapshots = response or []
            if not snapshots:
                child.update(
                    {
                        "status": "deleted",
                        "delete_completed": True,
                        "absent_after_ownership_proof": True,
                    }
                )
                children[snapshot_id] = child
                state["children"] = children
                state = self._checkpoint_aws_delete(state, token)
                continue
            if len(snapshots) != 1:
                raise AWSDeleteOwnershipError(
                    "AWS AMI child snapshot returned duplicate identities."
                )
            child_snapshot = snapshots[0]
            if str(child_snapshot.get("SnapshotId") or "") != snapshot_id or str(
                child_snapshot.get("OwnerId") or ""
            ) != account_id:
                raise AWSDeleteOwnershipError(
                    "AWS AMI child snapshot ownership did not match."
                )
            if child.get("delete_started") and not child.get("delete_completed"):
                child["status"] = "delete_outcome_unknown"
                children[snapshot_id] = child
                state["children"] = children
                state["phase"] = "delete_outcome_unknown"
                state = self._checkpoint_aws_delete(state, token)
                raise AWSDeleteAmbiguous(
                    "AWS AMI child snapshot deletion outcome is ambiguous while it remains visible."
                )
            child["delete_started"] = True
            child["status"] = "delete_requested"
            children[snapshot_id] = child
            state["children"] = children
            state = self._checkpoint_aws_delete(state, token)
            try:
                client.delete_snapshot(SnapshotId=snapshot_id)
            except Exception as error:
                if not self._aws_delete_not_found(error):
                    category, code, _retry_at, _retryable, unknown = (
                        self._aws_native_exception_outcome(error, mutation=True)
                    )
                    if unknown:
                        child.update(
                            {
                                "status": "delete_outcome_unknown",
                                "last_error_code": code,
                                "last_error_category": category,
                            }
                        )
                        children[snapshot_id] = child
                        state["children"] = children
                        state["phase"] = "delete_outcome_unknown"
                        self._checkpoint_aws_delete(state, token)
                        raise AWSDeleteAmbiguous(
                            "AWS AMI child snapshot deletion returned an ambiguous outcome."
                        ) from error
                    child.update(
                        {
                            "status": "delete_rejected",
                            "delete_started": False,
                            "last_error_code": code,
                            "last_error_category": category,
                        }
                    )
                    children[snapshot_id] = child
                    state["children"] = children
                    state["phase"] = "delete_rejected"
                    self._checkpoint_aws_delete(state, token)
                    raise
            child.update({"status": "deleted", "delete_completed": True})
            children[snapshot_id] = child
            state["children"] = children
            state = self._checkpoint_aws_delete(state, token)

        state["phase"] = "complete"
        return self._checkpoint_aws_delete(state, token)

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.aws.node.name} "
            f"is being deleted using connection {self.aws.node.connection.name}"
        )

        state, lease_token = self._claim_aws_delete_lease()
        if state is None:
            return False

        completed = False
        try:
            if state.get("phase") == "complete":
                completed = True
            else:
                auth = self.aws.node.connection.auth_aws
                if self.aws.resource_type in {"s3", "dynamodb"}:
                    state = self._delete_aws_backup_recovery_point(
                        auth, state, lease_token
                    )
                elif CoreNode.Type.CLOUD == self.aws.node.type:
                    state = self._delete_aws_ami(auth, state, lease_token)
                elif CoreNode.Type.VOLUME == self.aws.node.type:
                    state = self._delete_aws_ebs_snapshot(
                        auth, state, lease_token
                    )
                else:
                    raise AWSDeleteOwnershipError(
                        "AWS deletion does not support this resource type."
                    )
                completed = state.get("phase") == "complete"

            if not completed:
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save(update_fields=["status", "modified"])
                return False
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save(update_fields=["status", "modified"])
            _record_provider_outcome(
                self,
                provider="aws",
                category="delete_completed",
                operation="delete",
                resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"deleted successfully using connection "
                f"{self.aws.node.connection.name}"
            )
            return True
        except AWSDeleteLeaseLost:
            return False
        except AWSDeleteAmbiguous as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="aws",
                category="reconciliation_required",
                operation="delete",
                error_code="PROVIDER_RECONCILIATION_REQUIRED",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_IN_PROGRESS
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"could not be deleted because the provider deletion outcome "
                f"requires reconciliation."
            )
            return False
        except AWSDeleteOwnershipError as error:
            capture_exception(error)
            _provider_failed(
                self,
                provider="aws",
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"could not be deleted because provider ownership was not verified."
            )
            return False
        except AWSDeleteUnprovenNotFound as error:
            capture_exception(error)
            _record_provider_outcome(
                self,
                provider="aws",
                category="not_found",
                operation="delete",
                error_code="PROVIDER_NOT_FOUND",
                resource_id=self.unique_id,
            )
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"was absent before provider ownership could be verified."
            )
            return False
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="aws", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save(update_fields=["status", "modified"])
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"could not be deleted using connection "
                f"{self.aws.node.connection.name}."
            )
            return False
        finally:
            try:
                self._checkpoint_aws_delete(state, lease_token, release=True)
            except AWSDeleteLeaseLost:
                pass
            try:
                self.aws.node.connection.account.create_backup_log(
                    msg, self.aws.node, self
                )
            except Exception as error:
                capture_exception(error)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.aws.node.backup_complete_reset()


class CoreLightsailBackup(UtilBackup):
    lightsail = models.ForeignKey(
        "CoreLightsail", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreLightsailBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="lightsail_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="lightsail_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_lightsail_backup"

    def poll_status(self):
        """Perform one categorized, ownership-checked Lightsail status check."""
        from ..node.models import CoreLightsail, CoreNode

        if self.lightsail.resource_type == CoreLightsail.ResourceType.DATABASE:
            try:
                client = self.lightsail.node.connection.auth_lightsail.get_client()
                snapshot = self.lightsail._find_relational_database_snapshot(
                    client, self.unique_id or self.uuid_str
                )
                if snapshot:
                    if not _provider_owned(
                        snapshot,
                        marker=self.unique_id or self.uuid_str,
                        source_fields=((
                            "fromRelationalDatabaseName",
                            self.lightsail.unique_id,
                        ),),
                    ):
                        return _provider_failed(
                            self,
                            provider="lightsail_database",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    self.size_gigabytes = snapshot.get("sizeInGb")
                    self.set_provider_metadata(snapshot)
                    state = str(snapshot.get("state") or "").lower()
                    if state == "available":
                        self.status = UtilBackup.Status.COMPLETE
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="lightsail_database",
                            category="complete",
                            provider_status=state,
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    self.save(update_fields=["size_gigabytes", "metadata", "modified"])
                    if state in {"failed", "error"}:
                        return _provider_failed(
                            self, provider="lightsail_database", state=state
                        )
                    return _provider_in_progress(
                        self,
                        provider="lightsail_database",
                        state=state,
                        resource_id=self.unique_id,
                    )
                return _provider_failed(
                    self,
                    provider="lightsail_database",
                    state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="lightsail_database"
                )
        elif CoreNode.Type.CLOUD == self.lightsail.node.type:
            try:
                client = self.lightsail.node.connection.auth_lightsail.get_client()
                response = client.get_instance_snapshot(
                    instanceSnapshotName=self.unique_id
                )
                if response.get("instanceSnapshot"):
                    snapshot = response["instanceSnapshot"]
                    if not _provider_owned(
                        snapshot,
                        marker=self.unique_id,
                        source_fields=(("fromInstanceName", self.lightsail.unique_id),),
                    ):
                        return _provider_failed(
                            self,
                            provider="lightsail_instance",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    state = str(snapshot.get("state") or "").lower()
                    if state == "available":
                        self.size_gigabytes = snapshot["sizeInGb"]
                        self.set_provider_metadata(snapshot)
                        self.status = UtilBackup.Status.COMPLETE
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="lightsail_instance",
                            category="complete",
                            provider_status=state,
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    if state in {"error", "failed"}:
                        return _provider_failed(
                            self, provider="lightsail_instance", state=state
                        )
                    return _provider_in_progress(
                        self,
                        provider="lightsail_instance",
                        state=state,
                        resource_id=self.unique_id,
                    )
                return _provider_failed(
                    self, provider="lightsail_instance", state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="lightsail_instance"
                )
        elif CoreNode.Type.VOLUME == self.lightsail.node.type:
            try:
                client = self.lightsail.node.connection.auth_lightsail.get_client()
                response = client.get_disk_snapshot(diskSnapshotName=self.unique_id)
                if response.get("diskSnapshot"):
                    snapshot = response["diskSnapshot"]
                    if not _provider_owned(
                        snapshot,
                        marker=self.unique_id,
                        source_fields=(("fromDiskName", self.lightsail.unique_id),),
                    ):
                        return _provider_failed(
                            self,
                            provider="lightsail_disk",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    state = str(snapshot.get("state") or "").lower()
                    if state == "completed":
                        self.size_gigabytes = snapshot["sizeInGb"]
                        self.set_provider_metadata(snapshot)
                        self.status = UtilBackup.Status.COMPLETE
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="lightsail_disk",
                            category="complete",
                            provider_status=state,
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    if state in {"error", "failed"}:
                        return _provider_failed(
                            self, provider="lightsail_disk", state=state
                        )
                    return _provider_in_progress(
                        self,
                        provider="lightsail_disk",
                        state=state,
                        resource_id=self.unique_id,
                    )
                return _provider_failed(
                    self, provider="lightsail_disk", state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="lightsail_disk"
                )
        return _provider_failed(
            self, provider="lightsail", state="unsupported_resource"
        )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.lightsail.node

    def soft_delete(self):
        from ..node.models import CoreLightsail, CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
            f"is being deleted using connection {self.lightsail.node.connection.name}"
        )

        try:
            client = self.lightsail.node.connection.auth_lightsail.get_client()
            if self.lightsail.resource_type == CoreLightsail.ResourceType.DATABASE:
                snapshot = self.lightsail._find_relational_database_snapshot(
                    client, self.unique_id
                )
                owned = snapshot and _provider_owned(
                    snapshot,
                    marker=self.unique_id,
                    source_fields=((
                        "fromRelationalDatabaseName",
                        self.lightsail.unique_id,
                    ),),
                )
                provider = "lightsail_database"
            elif CoreNode.Type.CLOUD == self.lightsail.node.type:
                snapshot = client.get_instance_snapshot(
                    instanceSnapshotName=self.unique_id
                ).get("instanceSnapshot")
                owned = snapshot and _provider_owned(
                    snapshot,
                    marker=self.unique_id,
                    source_fields=(("fromInstanceName", self.lightsail.unique_id),),
                )
                provider = "lightsail_instance"
            elif CoreNode.Type.VOLUME == self.lightsail.node.type:
                snapshot = client.get_disk_snapshot(
                    diskSnapshotName=self.unique_id
                ).get("diskSnapshot")
                owned = snapshot and _provider_owned(
                    snapshot,
                    marker=self.unique_id,
                    source_fields=(("fromDiskName", self.lightsail.unique_id),),
                )
                provider = "lightsail_disk"
            else:
                owned = False
                provider = "lightsail"
            if not owned:
                _provider_failed(
                    self, provider=provider, state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return

            if self.lightsail.resource_type == CoreLightsail.ResourceType.DATABASE:
                client.delete_relational_database_snapshot(
                    relationalDatabaseSnapshotName=self.unique_id
                )
            elif CoreNode.Type.CLOUD == self.lightsail.node.type:
                client.delete_instance_snapshot(instanceSnapshotName=self.unique_id)
            elif CoreNode.Type.VOLUME == self.lightsail.node.type:
                client.delete_disk_snapshot(diskSnapshotName=self.unique_id)

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider=provider, category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
                f"deleted successfully using connection {self.lightsail.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="lightsail", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
                f"could not be deleted using connection {self.lightsail.node.connection.name}."
            )
        finally:
            self.lightsail.node.connection.account.create_backup_log(msg, self.lightsail.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.lightsail.node.backup_complete_reset()


class CoreAWSRDSBackup(UtilBackup):
    aws_rds = models.ForeignKey(
        "CoreAWSRDS", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreAWSRDSBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="aws_rds_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="aws_rds_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_rds_backup"

    _RDS_PROVIDER = "aws_rds"
    _RDS_SNAPSHOT_TYPE = "manual"
    # Version 2 relied on name/ARN/source identity.  RDS ARNs are name based,
    # so that protocol cannot distinguish a deleted snapshot from a later
    # snapshot with the same identifier.  Version 3 adds a request-bound tag,
    # the provider incarnation time, and an explicit provisional/committed
    # state.  Keep v2 readable only through the explicit legacy compatibility
    # path below; never upgrade it from present-day provider data.
    _RDS_WITNESS_VERSION = 3
    _RDS_LEGACY_WITNESS_VERSION = 2
    _RDS_PROVISIONAL_WITNESS_STATE = "provisional"
    _RDS_COMMITTED_WITNESS_STATE = "committed"
    _RDS_STABLE_SNAPSHOT_STATES = frozenset({"available"})
    _RDS_SNAPSHOT_OWNERSHIP_TAG_KEY = "BackupSheepOwnership"
    _RDS_CREATE_LEASE_DEFAULT_SECONDS = 300
    _RDS_CREATE_LEASE_MAX_SECONDS = 900
    _RDS_CREATE_VISIBILITY_DEFAULT_SECONDS = 15 * 60
    _RDS_CREATE_VISIBILITY_MAX_SECONDS = 60 * 60
    _RDS_CREATE_VISIBILITY_MIN_OBSERVATIONS = 3
    _RDS_CREATE_VISIBILITY_MAX_OBSERVATIONS = 20
    _RDS_DELETE_REDISPATCH_GRACE_DEFAULT_SECONDS = 60
    _RDS_DELETE_REDISPATCH_GRACE_MAX_SECONDS = 10 * 60
    _RDS_DELETE_MAX_ATTEMPTS_DEFAULT = 2
    _RDS_DELETE_MAX_ATTEMPTS_LIMIT = 5
    _RDS_LIST_MAX_PAGES_DEFAULT = 100
    _RDS_LIST_MAX_PAGES_LIMIT = 1000
    _RDS_LIST_MAX_ITEMS_DEFAULT = 10000
    _RDS_LIST_MAX_ITEMS_LIMIT = 100000
    _RDS_RESTORE_CONFIGURATION_KEYS = (
        "db_instance_class",
        "db_subnet_group_name",
        "multi_az",
        "publicly_accessible",
        "vpc_security_group_ids",
        "storage_type",
        "iops",
        "storage_throughput",
    )
    _RDS_STORAGE_TYPES = frozenset({"standard", "gp2", "gp3", "io1", "io2"})
    _RDS_WITNESS_KEYS = frozenset(
        {
            "snapshot_identifier",
            "source_db_instance_identifier",
            "account_id",
            "region",
            "snapshot_type",
            "snapshot_arn",
            "source_node_id",
            "source_resource_id",
            "source_dbi_resource_id",
            "source_db_instance_arn",
            "witness_version",
            "witness_state",
            "ownership_marker",
            "snapshot_create_time",
            "original_snapshot_create_time",
            "source_restore_configuration",
            "source_restore_configuration_sha256",
        }
    )

    @staticmethod
    def _rds_identifier(value, *, maximum_length):
        value = str(value or "")
        if (
            len(value) > maximum_length
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", value)
            or value.endswith("-")
            or "--" in value
        ):
            raise RDSOwnershipError("The RDS identifier is invalid.")
        return value

    @staticmethod
    def _rds_partition(region):
        region = str(region or "")
        if region.startswith("cn-"):
            return "aws-cn"
        if region.startswith("us-gov-"):
            return "aws-us-gov"
        if region.startswith("us-iso-b-"):
            return "aws-iso-b"
        if region.startswith("us-iso-"):
            return "aws-iso"
        if region.startswith("us-isof-"):
            return "aws-iso-f"
        return "aws"

    @classmethod
    def _rds_snapshot_arn(cls, identifier, *, account_id, region):
        return (
            f"arn:{cls._rds_partition(region)}:rds:{region}:"
            f"{account_id}:snapshot:{identifier}"
        )

    @staticmethod
    def _rds_instance_arn_identity(arn):
        match = re.fullmatch(
            r"arn:(?P<partition>[^:]+):rds:(?P<region>[^:]+):"
            r"(?P<account>[0-9]{12}):db:(?P<identifier>[^:]+)",
            str(arn or ""),
        )
        if not match:
            return None
        return {
            "partition": match.group("partition"),
            "region": match.group("region"),
            "account_id": match.group("account"),
            "source_db_instance_identifier": match.group("identifier"),
        }

    @staticmethod
    def _rds_provider_identifier(value, *, field):
        value = str(value or "").strip()
        if (
            not value
            or len(value) > 255
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", value)
        ):
            raise RDSMalformedResponse(f"The RDS {field} is invalid.")
        return value

    @classmethod
    def _rds_validate_restore_configuration(cls, configuration):
        """Return one canonical, provider-safe RDS restore configuration."""

        if not isinstance(configuration, dict) or set(configuration) != set(
            cls._RDS_RESTORE_CONFIGURATION_KEYS
        ):
            raise RDSMalformedResponse(
                "The RDS source restore configuration is incomplete."
            )

        db_class = configuration.get("db_instance_class")
        if (
            not isinstance(db_class, str)
            or len(db_class) > 64
            or not re.fullmatch(r"db\.[a-z0-9-]+\.[a-z0-9-]+", db_class)
        ):
            raise RDSMalformedResponse("The RDS instance class is invalid.")

        subnet_group = configuration.get("db_subnet_group_name")
        if (
            not isinstance(subnet_group, str)
            or len(subnet_group) > 255
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9.-]*", subnet_group)
            or subnet_group.endswith(("-", "."))
            or ".." in subnet_group
        ):
            raise RDSMalformedResponse("The RDS subnet group is invalid.")

        security_groups = configuration.get("vpc_security_group_ids")
        if not isinstance(security_groups, (list, tuple)) or not security_groups:
            raise RDSMalformedResponse("The RDS security-group list is invalid.")
        normalized_security_groups = []
        for group_id in security_groups:
            if not isinstance(group_id, str) or not re.fullmatch(
                r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})", group_id
            ):
                raise RDSMalformedResponse("An RDS security-group id is invalid.")
            normalized_security_groups.append(group_id)
        if len(normalized_security_groups) != len(set(normalized_security_groups)):
            raise RDSMalformedResponse("The RDS security-group list is ambiguous.")

        multi_az = configuration.get("multi_az")
        publicly_accessible = configuration.get("publicly_accessible")
        if type(multi_az) is not bool or type(publicly_accessible) is not bool:
            raise RDSMalformedResponse("The RDS network flags are invalid.")

        storage_type = configuration.get("storage_type")
        if (
            not isinstance(storage_type, str)
            or storage_type not in cls._RDS_STORAGE_TYPES
        ):
            raise RDSMalformedResponse("The RDS storage type is invalid.")

        iops = configuration.get("iops")
        if type(iops) is int and iops == 0:
            iops = None
        if iops is not None and (type(iops) is not int or iops < 1000):
            raise RDSMalformedResponse("The RDS provisioned IOPS value is invalid.")
        storage_throughput = configuration.get("storage_throughput")
        if type(storage_throughput) is int and storage_throughput == 0:
            storage_throughput = None
        if storage_throughput is not None and (
            type(storage_throughput) is not int
            or not 125 <= storage_throughput <= 1000
        ):
            raise RDSMalformedResponse("The RDS storage throughput is invalid.")
        if storage_type in {"io1", "io2"} and iops is None:
            raise RDSMalformedResponse(
                "The RDS storage type requires a provisioned IOPS witness."
            )
        if storage_type != "gp3" and storage_throughput is not None:
            raise RDSMalformedResponse(
                "The RDS storage throughput does not match the storage type."
            )

        return {
            "db_instance_class": db_class,
            "db_subnet_group_name": subnet_group,
            "multi_az": multi_az,
            "publicly_accessible": publicly_accessible,
            "vpc_security_group_ids": sorted(normalized_security_groups),
            "storage_type": storage_type,
            "iops": iops,
            "storage_throughput": storage_throughput,
        }

    @classmethod
    def _rds_source_restore_configuration(cls, instance, *, source_id):
        """Extract only immutable restore inputs from one exact source instance."""

        if not isinstance(instance, dict):
            raise RDSMalformedResponse("RDS returned an invalid source instance.")
        provider_source_id = instance.get("DBInstanceIdentifier")
        if not isinstance(provider_source_id, str):
            raise RDSMalformedResponse("RDS omitted the source instance identity.")
        if provider_source_id != source_id:
            raise RDSOwnershipError("RDS returned a different source instance.")

        subnet_group = instance.get("DBSubnetGroup")
        if not isinstance(subnet_group, dict):
            raise RDSMalformedResponse("RDS omitted the source subnet group.")
        security_groups = instance.get("VpcSecurityGroups")
        if not isinstance(security_groups, list):
            raise RDSMalformedResponse("RDS omitted the source security groups.")
        security_group_ids = []
        for group in security_groups:
            if not isinstance(group, dict) or "VpcSecurityGroupId" not in group:
                raise RDSMalformedResponse(
                    "RDS returned an invalid source security group."
                )
            security_group_ids.append(group["VpcSecurityGroupId"])

        return cls._rds_validate_restore_configuration(
            {
                "db_instance_class": instance.get("DBInstanceClass"),
                "db_subnet_group_name": subnet_group.get("DBSubnetGroupName"),
                "multi_az": instance.get("MultiAZ"),
                "publicly_accessible": instance.get("PubliclyAccessible"),
                "vpc_security_group_ids": security_group_ids,
                "storage_type": instance.get("StorageType"),
                "iops": instance.get("Iops"),
                "storage_throughput": instance.get("StorageThroughput"),
            }
        )

    @classmethod
    def _rds_source_provider_evidence(
        cls, instance, *, source_id, account_id, region
    ):
        """Extract immutable provider identity needed after source deletion."""
        if not isinstance(instance, dict):
            raise RDSMalformedResponse("RDS returned an invalid source instance.")
        provider_source_id = instance.get("DBInstanceIdentifier")
        if provider_source_id != source_id:
            raise RDSOwnershipError("RDS returned a different source instance.")

        # DbiResourceId is the provider identity that survives a database
        # identifier being deleted and later reused. New v2 witnesses require it.
        source_dbi_resource_id = cls._rds_provider_identifier(
            instance.get("DbiResourceId"), field="source DbiResourceId"
        )
        evidence = {"source_dbi_resource_id": source_dbi_resource_id}

        source_arn = instance.get("DBInstanceArn")
        if source_arn not in (None, ""):
            identity = cls._rds_instance_arn_identity(source_arn)
            if identity is None:
                raise RDSMalformedResponse("RDS returned an invalid source ARN.")
            if (
                identity["source_db_instance_identifier"] != source_id
                or identity["account_id"] != str(account_id)
                or identity["region"] != str(region)
                or identity["partition"] != cls._rds_partition(region)
            ):
                raise RDSOwnershipError("RDS source ARN ownership did not match.")
            evidence["source_db_instance_arn"] = str(source_arn)
        return evidence

    @classmethod
    def _rds_describe_source_restore_configuration(
        cls, client, *, source_id, account_id, region
    ):
        response = client.describe_db_instances(DBInstanceIdentifier=source_id)
        if not isinstance(response, dict):
            raise RDSMalformedResponse("RDS returned an invalid source response.")
        instances = response.get("DBInstances")
        if not isinstance(instances, list):
            raise RDSMalformedResponse("RDS omitted the source instance collection.")
        if len(instances) > 1:
            raise RDSDuplicateMatch("RDS returned multiple exact source instances.")
        if not instances:
            raise RDSMalformedResponse("RDS did not return the exact source instance.")
        instance = instances[0]
        return (
            cls._rds_source_restore_configuration(instance, source_id=source_id),
            cls._rds_source_provider_evidence(
                instance,
                source_id=source_id,
                account_id=account_id,
                region=region,
            ),
        )

    @staticmethod
    def _rds_canonical_snapshot_time(value, *, field="SnapshotCreateTime"):
        """Normalize one AWS snapshot incarnation timestamp.

        ``SnapshotCreateTime`` is returned by RDS as a timezone-aware datetime,
        but JSON round trips and mocks commonly turn it into an ISO string.  A
        single UTC representation lets reconciliation compare the provider's
        incarnation exactly instead of comparing display-formatted values.
        """
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value.strip():
            raw = value.strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(raw)
            except (TypeError, ValueError) as error:
                raise RDSMalformedResponse(
                    f"RDS returned an invalid {field}."
                ) from error
        else:
            raise RDSMalformedResponse(f"RDS omitted {field}.")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime_timezone.utc)
        else:
            parsed = parsed.astimezone(datetime_timezone.utc)
        return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")

    @classmethod
    def _rds_ownership_marker(
        cls,
        *,
        identifier,
        source_id,
        region,
        source_node_id=None,
        source_resource_id=None,
    ):
        """Build a stable tag value from request identity, never user text."""
        payload = json.dumps(
            {
                "provider": cls._RDS_PROVIDER,
                "operation": "manual_snapshot",
                "snapshot_identifier": str(identifier or ""),
                "source_db_instance_identifier": str(source_id or ""),
                "region": str(region or ""),
                "source_node_id": str(source_node_id or ""),
                "source_resource_id": str(source_resource_id or ""),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return "bs-rds-" + hashlib.sha256(payload).hexdigest()

    @classmethod
    def _rds_validate_ownership_marker(cls, marker):
        marker = str(marker or "")
        if not re.fullmatch(r"bs-rds-[0-9a-f]{64}", marker):
            raise RDSMalformedResponse("The RDS ownership marker is invalid.")
        return marker

    @staticmethod
    def _rds_witness_digest(witness):
        payload = {
            key: value
            for key, value in witness.items()
            if key != "source_restore_configuration_sha256"
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _rds_canonical_witness(cls, witness):
        if not isinstance(witness, dict) or not witness:
            raise RDSMalformedResponse("The durable RDS witness is invalid.")
        if set(witness) - cls._RDS_WITNESS_KEYS:
            raise RDSMalformedResponse(
                "The durable RDS witness contains unsupported fields."
            )
        required = {
            "snapshot_identifier",
            "source_db_instance_identifier",
            "account_id",
            "region",
            "snapshot_type",
        }
        if not required.issubset(witness):
            raise RDSMalformedResponse("The durable RDS witness is incomplete.")
        if witness.get("snapshot_type") != cls._RDS_SNAPSHOT_TYPE:
            raise RDSOwnershipError("The durable RDS snapshot type changed.")

        version = witness.get("witness_version")
        if version in (None, cls._RDS_LEGACY_WITNESS_VERSION):
            # This is the intentionally narrow legacy path.  It preserves the
            # old record exactly and carries no present-day marker/time data.
            if set(witness) - {
                "snapshot_identifier",
                "source_db_instance_identifier",
                "account_id",
                "region",
                "snapshot_type",
                "snapshot_arn",
                "source_node_id",
                "source_resource_id",
                "source_dbi_resource_id",
                "source_db_instance_arn",
                "witness_version",
                "source_restore_configuration",
                "source_restore_configuration_sha256",
            }:
                raise RDSMalformedResponse(
                    "The legacy RDS witness contains current-version fields."
                )
            try:
                canonical = cls._rds_witness(
                    identifier=witness.get("snapshot_identifier"),
                    source_id=witness.get("source_db_instance_identifier"),
                    account_id=witness.get("account_id"),
                    region=witness.get("region"),
                    source_node_id=witness.get("source_node_id"),
                    source_resource_id=witness.get("source_resource_id"),
                    snapshot_arn=witness.get("snapshot_arn"),
                    source_dbi_resource_id=witness.get("source_dbi_resource_id"),
                    source_db_instance_arn=witness.get("source_db_instance_arn"),
                    source_restore_configuration=witness.get(
                        "source_restore_configuration"
                    ),
                    witness_version=cls._RDS_LEGACY_WITNESS_VERSION,
                )
            except (RDSMalformedResponse, RDSOwnershipError):
                raise
            if canonical != witness:
                raise RDSMalformedResponse("The legacy RDS witness is invalid.")
            return canonical

        if version != cls._RDS_WITNESS_VERSION:
            raise RDSMalformedResponse("The RDS witness version is unsupported.")

        witness_state = witness.get("witness_state")
        if witness_state not in {
            cls._RDS_PROVISIONAL_WITNESS_STATE,
            cls._RDS_COMMITTED_WITNESS_STATE,
        }:
            raise RDSMalformedResponse("The RDS witness state is invalid.")
        ownership_marker = cls._rds_validate_ownership_marker(
            witness.get("ownership_marker")
        )
        snapshot_create_time = witness.get("snapshot_create_time")
        original_snapshot_create_time = witness.get(
            "original_snapshot_create_time"
        )
        if witness_state == cls._RDS_COMMITTED_WITNESS_STATE:
            if snapshot_create_time in (None, ""):
                raise RDSMalformedResponse(
                    "The committed RDS witness is missing SnapshotCreateTime."
                )
        elif snapshot_create_time not in (None, ""):
            # A timestamp is the commit boundary.  It must never be stored in a
            # witness still labelled provisional.
            raise RDSMalformedResponse(
                "The provisional RDS witness contains SnapshotCreateTime."
            )
        if snapshot_create_time not in (None, ""):
            snapshot_create_time = cls._rds_canonical_snapshot_time(
                snapshot_create_time
            )
        if original_snapshot_create_time not in (None, ""):
            original_snapshot_create_time = cls._rds_canonical_snapshot_time(
                original_snapshot_create_time,
                field="OriginalSnapshotCreateTime",
            )

        configuration = witness.get("source_restore_configuration")
        if configuration is not None:
            # A version-2 witness must be independently usable after the source
            # DB identifier has been deleted or reused.  The snapshot ARN and
            # source DbiResourceId are therefore mandatory, not optional JSON
            # decorations that can be silently reconstructed on read.
            if (
                not witness.get("snapshot_arn")
                or not witness.get("source_dbi_resource_id")
            ):
                raise RDSMalformedResponse(
                    "The version-2 RDS witness is missing provider identity evidence."
                )
        canonical = cls._rds_witness(
            identifier=witness.get("snapshot_identifier"),
            source_id=witness.get("source_db_instance_identifier"),
            account_id=witness.get("account_id"),
            region=witness.get("region"),
            source_node_id=witness.get("source_node_id"),
            source_resource_id=witness.get("source_resource_id"),
            snapshot_arn=witness.get("snapshot_arn"),
            source_dbi_resource_id=witness.get("source_dbi_resource_id"),
            source_db_instance_arn=witness.get("source_db_instance_arn"),
            source_restore_configuration=configuration,
            ownership_marker=ownership_marker,
            snapshot_create_time=snapshot_create_time,
            original_snapshot_create_time=original_snapshot_create_time,
            witness_state=witness_state,
            witness_version=cls._RDS_WITNESS_VERSION,
        )
        if canonical != witness:
            raise RDSMalformedResponse("The durable RDS witness digest is invalid.")
        return canonical

    @classmethod
    def _rds_merge_witness(cls, existing, incoming):
        incoming = cls._rds_canonical_witness(incoming)
        if existing is None:
            return incoming
        existing = cls._rds_canonical_witness(existing)

        existing_version = existing.get("witness_version")
        incoming_version = incoming.get("witness_version")
        if existing_version != incoming_version:
            # A v2 row may not be upgraded by reading mutable provider data.  A
            # repair/migration must explicitly replace it with a new request.
            raise RDSOwnershipError("The legacy RDS witness cannot be upgraded.")
        if existing_version == cls._RDS_LEGACY_WITNESS_VERSION:
            if existing != incoming:
                raise RDSOwnershipError("The legacy RDS request identity changed.")
            return existing

        for key in (
            "snapshot_identifier",
            "source_db_instance_identifier",
            "region",
            "snapshot_type",
            "snapshot_arn",
            "source_dbi_resource_id",
            "source_db_instance_arn",
            "ownership_marker",
        ):
            if (
                key in existing
                and key in incoming
                and existing[key] != incoming[key]
            ):
                raise RDSOwnershipError("The durable RDS request identity changed.")
        for key in ("source_node_id", "source_resource_id"):
            if key in existing and key in incoming and existing[key] != incoming[key]:
                raise RDSOwnershipError("The durable RDS node identity changed.")

        existing_account = existing["account_id"]
        incoming_account = incoming["account_id"]
        if (
            existing_account != "pending"
            and incoming_account != "pending"
            and existing_account != incoming_account
        ):
            raise RDSOwnershipError("The durable RDS account identity changed.")

        existing_configuration = existing.get("source_restore_configuration")
        incoming_configuration = incoming.get("source_restore_configuration")
        if (
            existing_configuration is not None
            and incoming_configuration is not None
            and incoming_configuration != existing_configuration
        ):
            raise RDSOwnershipError("The durable RDS source configuration changed.")

        existing_time = existing.get("snapshot_create_time")
        incoming_time = incoming.get("snapshot_create_time")
        if existing_time and incoming_time and existing_time != incoming_time:
            raise RDSOwnershipError("The RDS snapshot incarnation changed.")
        existing_original_time = existing.get("original_snapshot_create_time")
        incoming_original_time = incoming.get("original_snapshot_create_time")
        if (
            existing_original_time
            and incoming_original_time
            and existing_original_time != incoming_original_time
        ):
            raise RDSOwnershipError("The RDS original snapshot incarnation changed.")

        account_id = (
            existing_account if existing_account != "pending" else incoming_account
        )
        snapshot_time = existing_time or incoming_time
        witness_state = (
            cls._RDS_COMMITTED_WITNESS_STATE
            if snapshot_time
            else cls._RDS_PROVISIONAL_WITNESS_STATE
        )
        return cls._rds_witness(
            identifier=existing["snapshot_identifier"],
            source_id=existing["source_db_instance_identifier"],
            account_id=account_id,
            region=existing["region"],
            source_node_id=existing.get("source_node_id")
            or incoming.get("source_node_id"),
            source_resource_id=existing.get("source_resource_id")
            or incoming.get("source_resource_id"),
            snapshot_arn=existing.get("snapshot_arn")
            or incoming.get("snapshot_arn"),
            source_dbi_resource_id=existing.get("source_dbi_resource_id")
            or incoming.get("source_dbi_resource_id"),
            source_db_instance_arn=existing.get("source_db_instance_arn")
            or incoming.get("source_db_instance_arn"),
            source_restore_configuration=existing_configuration
            or incoming_configuration,
            ownership_marker=existing["ownership_marker"],
            snapshot_create_time=snapshot_time,
            original_snapshot_create_time=(
                existing_original_time or incoming_original_time
            ),
            witness_state=witness_state,
            witness_version=cls._RDS_WITNESS_VERSION,
        )

    @staticmethod
    def _rds_region(auth):
        region = str(getattr(getattr(auth, "region", None), "code", "") or "")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]", region):
            raise RDSOwnershipError("The RDS connection has no region identity.")
        return region

    @staticmethod
    def _rds_account_id(auth):
        """Resolve the account without retaining credentials or response data."""
        sts_client = None
        try:
            # A few test/future auth implementations expose service selection here.
            sts_client = auth.get_client("sts")
        except TypeError:
            # CoreAuthAWSRDS historically exposes only an RDS client. Build the
            # bounded STS client with the same encrypted credentials in memory.
            encryption_key = auth.connection.account.get_encryption_key()
            sts_client = bounded_boto3_client(
                "sts",
                region_name=CoreAWSRDSBackup._rds_region(auth),
                aws_access_key_id=bs_decrypt(auth.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(auth.secret_key, encryption_key),
            )
        response = sts_client.get_caller_identity()
        account_id = str((response or {}).get("Account") or "")
        if not re.fullmatch(r"[0-9]{12}", account_id):
            raise RDSOwnershipError("The RDS account identity could not be verified.")
        return account_id

    @classmethod
    def _rds_witness(
        cls,
        *,
        identifier,
        source_id,
        account_id,
        region,
        source_node_id=None,
        source_resource_id=None,
        snapshot_arn=None,
        source_dbi_resource_id=None,
        source_db_instance_arn=None,
        source_restore_configuration=None,
        ownership_marker=None,
        snapshot_create_time=None,
        original_snapshot_create_time=None,
        witness_state=None,
        witness_version=None,
    ):
        if witness_version is None:
            witness_version = cls._RDS_WITNESS_VERSION
        try:
            witness_version = int(witness_version)
        except (TypeError, ValueError) as error:
            raise RDSMalformedResponse("The RDS witness version is invalid.") from error
        values = {
            "snapshot_identifier": cls._rds_identifier(
                identifier, maximum_length=255
            ),
            "source_db_instance_identifier": cls._rds_identifier(
                source_id, maximum_length=63
            ),
            "account_id": str(account_id or ""),
            "region": str(region or ""),
            "snapshot_type": cls._RDS_SNAPSHOT_TYPE,
        }
        if values["account_id"] != "pending" and not re.fullmatch(
            r"[0-9]{12}", values["account_id"]
        ):
            raise RDSOwnershipError("The RDS account identity is invalid.")
        if not re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]", values["region"]
        ):
            raise RDSOwnershipError("The RDS region identity is invalid.")

        if snapshot_arn is not None:
            snapshot_arn = str(snapshot_arn)
            expected_snapshot_arn = cls._rds_snapshot_arn(
                values["snapshot_identifier"],
                account_id=values["account_id"],
                region=values["region"],
            )
            snapshot_identity = _rds_snapshot_arn_identity(
                {"DBSnapshotArn": snapshot_arn}
            )
            if (
                snapshot_arn != expected_snapshot_arn
                or not snapshot_identity
                or snapshot_identity["partition"]
                != cls._rds_partition(values["region"])
            ):
                raise RDSOwnershipError("The RDS snapshot ARN identity is invalid.")
            values["snapshot_arn"] = snapshot_arn

        if source_dbi_resource_id is not None:
            values["source_dbi_resource_id"] = cls._rds_provider_identifier(
                source_dbi_resource_id, field="source DbiResourceId"
            )

        if source_db_instance_arn is not None:
            source_db_instance_arn = str(source_db_instance_arn)
            source_identity = cls._rds_instance_arn_identity(source_db_instance_arn)
            if (
                not source_identity
                or source_identity["source_db_instance_identifier"]
                != values["source_db_instance_identifier"]
                or source_identity["account_id"] != values["account_id"]
                or source_identity["region"] != values["region"]
                or source_identity["partition"]
                != cls._rds_partition(values["region"])
            ):
                raise RDSOwnershipError(
                    "The RDS source instance ARN identity is invalid."
                )
            values["source_db_instance_arn"] = source_db_instance_arn

        if source_node_id is not None or source_resource_id is not None:
            try:
                source_node_id = int(source_node_id)
                source_resource_id = int(source_resource_id)
            except (TypeError, ValueError) as error:
                raise RDSOwnershipError(
                    "The RDS node identity is invalid."
                ) from error
            if source_node_id <= 0 or source_resource_id <= 0:
                raise RDSOwnershipError("The RDS node identity is invalid.")
            values["source_node_id"] = source_node_id
            values["source_resource_id"] = source_resource_id

        if witness_version == cls._RDS_LEGACY_WITNESS_VERSION:
            if any(
                value not in (None, "")
                for value in (
                    ownership_marker,
                    snapshot_create_time,
                    original_snapshot_create_time,
                    witness_state,
                )
            ):
                raise RDSMalformedResponse(
                    "Legacy RDS witnesses cannot contain v3 incarnation data."
                )
            values["witness_version"] = cls._RDS_LEGACY_WITNESS_VERSION
            if source_restore_configuration is not None:
                if (
                    values["account_id"] == "pending"
                    or "source_node_id" not in values
                    or "source_resource_id" not in values
                ):
                    raise RDSOwnershipError(
                        "The legacy RDS restore witness identity is incomplete."
                    )
                values["source_restore_configuration"] = (
                    cls._rds_validate_restore_configuration(
                        source_restore_configuration
                    )
                )
                values["source_restore_configuration_sha256"] = (
                    cls._rds_witness_digest(values)
                )
            return values

        if witness_version != cls._RDS_WITNESS_VERSION:
            raise RDSMalformedResponse("The RDS witness version is unsupported.")
        if ownership_marker in (None, ""):
            ownership_marker = cls._rds_ownership_marker(
                identifier=values["snapshot_identifier"],
                source_id=values["source_db_instance_identifier"],
                region=values["region"],
                source_node_id=values.get("source_node_id"),
                source_resource_id=values.get("source_resource_id"),
            )
        values["ownership_marker"] = cls._rds_validate_ownership_marker(
            ownership_marker
        )
        if witness_state is None:
            witness_state = (
                cls._RDS_COMMITTED_WITNESS_STATE
                if snapshot_create_time not in (None, "")
                else cls._RDS_PROVISIONAL_WITNESS_STATE
            )
        if witness_state not in {
            cls._RDS_PROVISIONAL_WITNESS_STATE,
            cls._RDS_COMMITTED_WITNESS_STATE,
        }:
            raise RDSMalformedResponse("The RDS witness state is invalid.")
        if snapshot_create_time not in (None, ""):
            snapshot_create_time = cls._rds_canonical_snapshot_time(
                snapshot_create_time
            )
        if original_snapshot_create_time not in (None, ""):
            original_snapshot_create_time = cls._rds_canonical_snapshot_time(
                original_snapshot_create_time,
                field="OriginalSnapshotCreateTime",
            )
        if witness_state == cls._RDS_COMMITTED_WITNESS_STATE and not snapshot_create_time:
            raise RDSMalformedResponse(
                "A committed RDS witness requires SnapshotCreateTime."
            )
        if witness_state == cls._RDS_PROVISIONAL_WITNESS_STATE and snapshot_create_time:
            raise RDSMalformedResponse(
                "A provisional RDS witness cannot contain SnapshotCreateTime."
            )
        values["witness_version"] = cls._RDS_WITNESS_VERSION
        values["witness_state"] = witness_state
        if snapshot_create_time:
            values["snapshot_create_time"] = snapshot_create_time
        if original_snapshot_create_time:
            values["original_snapshot_create_time"] = original_snapshot_create_time

        if source_restore_configuration is not None:
            if (
                values["account_id"] == "pending"
                or "source_node_id" not in values
                or "source_resource_id" not in values
                or "source_dbi_resource_id" not in values
            ):
                raise RDSOwnershipError(
                    "The RDS restore witness identity is incomplete."
                )
            values.setdefault(
                "snapshot_arn",
                cls._rds_snapshot_arn(
                    values["snapshot_identifier"],
                    account_id=values["account_id"],
                    region=values["region"],
                ),
            )
            values["witness_version"] = cls._RDS_WITNESS_VERSION
            values["source_restore_configuration"] = (
                cls._rds_validate_restore_configuration(
                    source_restore_configuration
                )
            )
            values["source_restore_configuration_sha256"] = (
                cls._rds_witness_digest(values)
            )
        return values

    def _rds_execution_metadata(self):
        state = self.get_execution_state(create=False)
        raw_metadata = state.provider_metadata if state is not None else {}
        if raw_metadata in (None, {}):
            metadata = {}
        elif isinstance(raw_metadata, dict):
            metadata = dict(raw_metadata)
        else:
            raise RDSMalformedResponse(
                "The durable RDS provider metadata is invalid."
            )
        request = metadata.get("rds_request")
        if request is None:
            return state, {}
        if not isinstance(request, dict):
            raise RDSMalformedResponse("The durable RDS request witness is invalid.")
        return state, dict(request)

    def _rds_persist_witness(self, witness, *, lease_owner=None, lease_token=None):
        incoming = self._rds_canonical_witness(dict(witness))
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh)
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, require_live=False
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            raw_provider_metadata = state.provider_metadata
            if raw_provider_metadata in (None, {}):
                provider_metadata = {}
            elif isinstance(raw_provider_metadata, dict):
                provider_metadata = dict(raw_provider_metadata)
            else:
                raise RDSMalformedResponse(
                    "The durable RDS provider metadata is invalid."
                )
            existing = provider_metadata.get("rds_request")
            if existing is not None and not isinstance(existing, dict):
                raise RDSMalformedResponse(
                    "The durable RDS request witness is invalid."
                )
            persisted = self._rds_merge_witness(existing, incoming)
            state.provider_idempotency_key = persisted["snapshot_identifier"]
            state.provider_status = "reconciliation_required"
            provider_metadata["rds_request"] = persisted
            state.provider_metadata = provider_metadata
            state.save(
                update_fields=[
                    "provider_idempotency_key",
                    "provider_status",
                    "provider_metadata",
                    "modified",
                ]
            )
            return state

    @staticmethod
    def _rds_bounded_setting(name, default, *, minimum, maximum):
        try:
            value = int(getattr(settings, name, default))
        except (TypeError, ValueError):
            value = int(default)
        return min(int(maximum), max(int(minimum), value))

    @classmethod
    def _rds_create_visibility_seconds(cls):
        return cls._rds_bounded_setting(
            "RDS_CREATE_VISIBILITY_WINDOW_SECONDS",
            cls._RDS_CREATE_VISIBILITY_DEFAULT_SECONDS,
            minimum=60,
            maximum=cls._RDS_CREATE_VISIBILITY_MAX_SECONDS,
        )

    @classmethod
    def _rds_create_visibility_min_observations(cls):
        return cls._rds_bounded_setting(
            "RDS_CREATE_VISIBILITY_MIN_OBSERVATIONS",
            cls._RDS_CREATE_VISIBILITY_MIN_OBSERVATIONS,
            minimum=cls._RDS_CREATE_VISIBILITY_MIN_OBSERVATIONS,
            maximum=cls._RDS_CREATE_VISIBILITY_MAX_OBSERVATIONS,
        )

    @classmethod
    def _rds_parse_durable_timestamp(cls, value, *, field):
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value.strip():
            raw = value.strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(raw)
            except (TypeError, ValueError) as error:
                raise RDSMalformedResponse(
                    f"The durable RDS {field} is invalid."
                ) from error
        else:
            raise RDSMalformedResponse(f"The durable RDS {field} is missing.")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime_timezone.utc)
        return parsed.astimezone(datetime_timezone.utc)

    def _rds_create_reconciliation_state(self):
        state = self.get_execution_state(create=False)
        metadata = dict(state.provider_metadata or {}) if state is not None else {}
        value = metadata.get("rds_create_reconciliation")
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise RDSMalformedResponse(
                "The durable RDS create reconciliation state is invalid."
            )
        return dict(value)

    def _rds_create_reconciliation_pending(self):
        state = self._rds_create_reconciliation_state()
        return bool(state.get("mutation_started_at") and not state.get("resolved_at"))

    def _rds_checkpoint_create_mutation(self, owner, token):
        """Commit the no-second-create boundary immediately before AWS."""

        now = timezone.now()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner,
                token,
                phase="create",
                now=now,
                require_live=True,
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            metadata = dict(state.provider_metadata or {})
            reconciliation = metadata.get("rds_create_reconciliation") or {}
            if not isinstance(reconciliation, dict):
                raise RDSMalformedResponse(
                    "The durable RDS create reconciliation state is invalid."
                )
            reconciliation = dict(reconciliation)
            if not reconciliation.get("mutation_started_at"):
                reconciliation.update(
                    {
                        "mutation_started_at": now.isoformat(),
                        "visibility_deadline_at": (
                            now
                            + timedelta(seconds=self._rds_create_visibility_seconds())
                        ).isoformat(),
                        "minimum_observations": (
                            self._rds_create_visibility_min_observations()
                        ),
                        "visibility_observations": 0,
                        "zero_match_observations": 0,
                        "missing_tag_observations": 0,
                    }
                )
            reconciliation.update(
                {
                    "mutation_intent_committed": True,
                    "outcome_unknown": True,
                    "resolved_at": None,
                }
            )
            metadata["rds_create_reconciliation"] = reconciliation
            state.provider_metadata = metadata
            state.provider_status = "create_requested"
            state.reconciliation_state = state.ReconciliationState.REQUIRED
            state.reconciliation_reason = "rds_create_mutation_started"
            state.save(
                update_fields=[
                    "provider_metadata",
                    "provider_status",
                    "reconciliation_state",
                    "reconciliation_reason",
                    "modified",
                ]
            )
            return dict(reconciliation)

    def _rds_checkpoint_create_outcome(
        self, owner, token, *, category, error_code
    ):
        now = timezone.now()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner,
                token,
                phase="create",
                now=now,
                require_live=True,
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            metadata = dict(state.provider_metadata or {})
            reconciliation = metadata.get("rds_create_reconciliation")
            if not isinstance(reconciliation, dict) or not reconciliation.get(
                "mutation_started_at"
            ):
                raise RDSMalformedResponse(
                    "The durable RDS create mutation checkpoint is missing."
                )
            reconciliation = dict(reconciliation)
            reconciliation.update(
                {
                    "outcome_unknown": True,
                    "last_provider_category": str(category)[:64],
                    "last_error_code": str(error_code)[:64],
                    "last_error_at": now.isoformat(),
                }
            )
            metadata["rds_create_reconciliation"] = reconciliation
            state.provider_metadata = metadata
            state.save(update_fields=["provider_metadata", "modified"])
            return dict(reconciliation)

    def _rds_resolve_create_reconciliation(
        self, *, lease_owner=None, lease_token=None
    ):
        now = timezone.now()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None:
                return
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, now=now, require_live=True
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            metadata = dict(state.provider_metadata or {})
            reconciliation = metadata.get("rds_create_reconciliation")
            if not isinstance(reconciliation, dict):
                return
            reconciliation = dict(reconciliation)
            reconciliation["outcome_unknown"] = False
            reconciliation["resolved_at"] = now.isoformat()
            metadata["rds_create_reconciliation"] = reconciliation
            state.provider_metadata = metadata
            state.save(update_fields=["provider_metadata", "modified"])

    def _rds_record_create_visibility_observation(
        self,
        *,
        kind,
        error_code,
        provider_status,
        lease_owner=None,
        lease_token=None,
    ):
        """Record one bounded read-only reconciliation observation.

        The deadline is anchored to the durable pre-mutation checkpoint and is
        never extended by polling. Both the deadline and the minimum observation
        count must be exhausted before the backup fails closed for review.
        """

        if kind not in {"zero_match", "missing_tag"}:
            raise ValueError("Unsupported RDS visibility observation.")
        now = timezone.now()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None:
                return None
            if lease_token is not None and not state.lease_matches(
                lease_owner,
                lease_token,
                phase="create",
                now=now,
                require_live=True,
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            metadata = dict(state.provider_metadata or {})
            reconciliation = metadata.get("rds_create_reconciliation")
            if reconciliation is None:
                return None
            if not isinstance(reconciliation, dict):
                raise RDSMalformedResponse(
                    "The durable RDS create reconciliation state is invalid."
                )
            reconciliation = dict(reconciliation)
            if reconciliation.get("resolved_at"):
                return None
            started_at = self._rds_parse_durable_timestamp(
                reconciliation.get("mutation_started_at"),
                field="create mutation timestamp",
            )
            deadline_at = self._rds_parse_durable_timestamp(
                reconciliation.get("visibility_deadline_at"),
                field="create visibility deadline",
            )
            if (
                deadline_at < started_at
                or deadline_at - started_at
                > timedelta(seconds=self._RDS_CREATE_VISIBILITY_MAX_SECONDS)
            ):
                raise RDSMalformedResponse(
                    "The durable RDS create visibility window is invalid."
                )
            try:
                minimum_observations = int(
                    reconciliation.get("minimum_observations")
                )
                observations = int(
                    reconciliation.get("visibility_observations", 0)
                )
                zero_matches = int(
                    reconciliation.get("zero_match_observations", 0)
                )
                missing_tags = int(
                    reconciliation.get("missing_tag_observations", 0)
                )
            except (TypeError, ValueError) as error:
                raise RDSMalformedResponse(
                    "The durable RDS create observation counters are invalid."
                ) from error
            if (
                not self._RDS_CREATE_VISIBILITY_MIN_OBSERVATIONS
                <= minimum_observations
                <= self._RDS_CREATE_VISIBILITY_MAX_OBSERVATIONS
                or min(observations, zero_matches, missing_tags) < 0
            ):
                raise RDSMalformedResponse(
                    "The durable RDS create observation counters are invalid."
                )
            observations += 1
            if kind == "zero_match":
                zero_matches += 1
            else:
                missing_tags += 1
            exhausted = now >= deadline_at and observations >= minimum_observations
            reconciliation.update(
                {
                    "outcome_unknown": True,
                    "visibility_observations": observations,
                    "zero_match_observations": zero_matches,
                    "missing_tag_observations": missing_tags,
                    "last_observation": kind,
                    "last_observed_at": now.isoformat(),
                    "last_error_code": str(error_code)[:64],
                    "last_provider_category": str(provider_status)[:64],
                }
            )
            if kind == "zero_match" and not reconciliation.get(
                "first_zero_match_at"
            ):
                reconciliation["first_zero_match_at"] = now.isoformat()
            if kind == "zero_match":
                reconciliation["last_zero_match_at"] = now.isoformat()
            if kind == "missing_tag" and not reconciliation.get(
                "first_missing_tag_at"
            ):
                reconciliation["first_missing_tag_at"] = now.isoformat()
            if kind == "missing_tag":
                reconciliation["last_missing_tag_at"] = now.isoformat()
            metadata["rds_create_reconciliation"] = reconciliation
            state.provider_metadata = metadata
            state.provider_status = str(provider_status)[:64]
            state.last_error_code = str(error_code)[:64]
            state.last_error_message = self.EXECUTION_ERROR_MESSAGES.get(
                state.last_error_code,
                "The provider operation requires reconciliation.",
            )
            state.last_error_at = now
            state.reconciliation_state = (
                state.ReconciliationState.MANUAL_REVIEW
                if exhausted
                else state.ReconciliationState.REQUIRED
            )
            state.reconciliation_reason = (
                "rds_create_visibility_exhausted"
                if exhausted
                else "rds_create_visibility_wait"
            )
            state.next_retry_at = None if exhausted else now + timedelta(seconds=60)
            reconciliation_metadata = dict(state.reconciliation_metadata or {})
            reconciliation_metadata["rds_create_visibility"] = {
                "deadline_at": deadline_at.isoformat(),
                "minimum_observations": minimum_observations,
                "observation_count": observations,
                "last_observation": kind,
            }
            state.reconciliation_metadata = reconciliation_metadata
            fresh.status = (
                UtilBackup.Status.FAILED
                if exhausted
                # A provider error/absence is not the same public state as a
                # provider snapshot that is actively creating.  RETRYING is
                # still an active backup status (and is picked up by the
                # durable recovery sweep), while keeping ``IN_PROGRESS`` for
                # an actually visible provider operation.
                else UtilBackup.Status.RETRYING
            )
            state.save(
                update_fields=[
                    "provider_metadata",
                    "provider_status",
                    "last_error_code",
                    "last_error_message",
                    "last_error_at",
                    "reconciliation_state",
                    "reconciliation_reason",
                    "reconciliation_metadata",
                    "next_retry_at",
                    "modified",
                ]
            )
            fresh.save(update_fields=["status", "modified"])
        self.status = fresh.status
        return fresh.status

    def _rds_reconcile_create_request(
        self,
        client,
        witness,
        *,
        lease_owner,
        lease_token,
    ):
        """Reconcile a request whose CreateDBSnapshot result was lost.

        Once ``_rds_checkpoint_create_mutation`` commits, this method is the
        only path a later worker may take until AWS exposes one exact owned
        snapshot or the bounded visibility window is exhausted.  In
        particular, a zero-result/404 response is an observation, never a
        license to issue a second create request.
        """
        if not self._rds_create_reconciliation_pending():
            return "not_pending"
        try:
            snapshots = self._rds_list_snapshots(
                client, witness["snapshot_identifier"]
            )
        except ClientError as error:
            if not _rds_not_found(error):
                raise
            result = self._rds_record_create_visibility_observation(
                kind="zero_match",
                error_code="PROVIDER_NOT_FOUND",
                provider_status="not_found",
                lease_owner=lease_owner,
                lease_token=lease_token,
            )
            return "exhausted" if result == UtilBackup.Status.FAILED else "pending"

        try:
            snapshot = self._rds_find_owned_snapshot(
                snapshots,
                witness,
                client=client,
                allow_missing_provisional_tag=True,
            )
        except RDSOwnershipTagPending:
            result = self._rds_record_create_visibility_observation(
                kind="missing_tag",
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                provider_status="ownership_tag_pending",
                lease_owner=lease_owner,
                lease_token=lease_token,
            )
            return "exhausted" if result == UtilBackup.Status.FAILED else "pending"

        if snapshot is None:
            result = self._rds_record_create_visibility_observation(
                kind="zero_match",
                error_code="PROVIDER_NOT_FOUND",
                provider_status="not_found",
                lease_owner=lease_owner,
                lease_token=lease_token,
            )
            return "exhausted" if result == UtilBackup.Status.FAILED else "pending"

        # _rds_find_owned_snapshot has already fetched and validated the tag
        # list.  Passing tags_verified avoids a second read, while the adopt
        # method still validates name/source/ARN/time before persisting it.
        self._rds_adopt_snapshot(
            snapshot,
            witness,
            client=client,
            tags_verified=True,
            lease_owner=lease_owner,
            lease_token=lease_token,
        )
        return "adopted"

    @classmethod
    def _rds_list_snapshots(cls, client, identifier):
        """Iterate exact RDS cursor pages with finite page/item bounds."""
        try:
            max_pages = int(
                getattr(
                    settings,
                    "RDS_SNAPSHOT_LIST_MAX_PAGES",
                    cls._RDS_LIST_MAX_PAGES_DEFAULT,
                )
            )
        except (TypeError, ValueError):
            max_pages = cls._RDS_LIST_MAX_PAGES_DEFAULT
        max_pages = min(cls._RDS_LIST_MAX_PAGES_LIMIT, max(1, max_pages))
        try:
            max_items = int(
                getattr(
                    settings,
                    "RDS_SNAPSHOT_LIST_MAX_ITEMS",
                    cls._RDS_LIST_MAX_ITEMS_DEFAULT,
                )
            )
        except (TypeError, ValueError):
            max_items = cls._RDS_LIST_MAX_ITEMS_DEFAULT
        max_items = min(cls._RDS_LIST_MAX_ITEMS_LIMIT, max(1, max_items))
        marker = None
        seen_markers = set()
        snapshots = []
        page_count = 0
        while True:
            page_count += 1
            if page_count > max_pages:
                raise RDSMalformedResponse(
                    "RDS snapshot pagination exceeded the page bound."
                )
            params = {"DBSnapshotIdentifier": identifier}
            if marker:
                params["Marker"] = marker
            response = client.describe_db_snapshots(**params)
            if not isinstance(response, dict):
                raise RDSMalformedResponse("RDS returned a non-object snapshot page.")
            if "DBSnapshots" not in response:
                raise RDSMalformedResponse("RDS omitted the snapshot collection.")
            page = response["DBSnapshots"]
            if not isinstance(page, list):
                raise RDSMalformedResponse("RDS returned an invalid snapshot page.")
            snapshots.extend(page)
            if len(snapshots) > max_items:
                raise RDSMalformedResponse(
                    "RDS snapshot pagination exceeded the item bound."
                )
            next_marker = str(response.get("Marker") or "")
            if not next_marker:
                return snapshots
            if next_marker in seen_markers or next_marker == marker:
                raise RDSMalformedResponse("RDS returned a repeated pagination marker.")
            seen_markers.add(next_marker)
            marker = next_marker

    @classmethod
    def _rds_snapshot_owned(cls, snapshot, witness):
        if not isinstance(snapshot, dict):
            return False
        identifier = str(snapshot.get("DBSnapshotIdentifier") or "")
        if identifier != witness["snapshot_identifier"]:
            return False
        source_id = str(snapshot.get("DBInstanceIdentifier") or "")
        if source_id != witness["source_db_instance_identifier"]:
            return False
        snapshot_type = str(snapshot.get("SnapshotType") or "").lower()
        if snapshot_type != witness["snapshot_type"]:
            return False
        arn_identity = _rds_snapshot_arn_identity(snapshot)
        if not arn_identity:
            return False
        if (
            arn_identity["partition"] != cls._rds_partition(witness["region"])
            or arn_identity["snapshot_identifier"]
            != witness["snapshot_identifier"]
            or arn_identity["account_id"] != witness["account_id"]
            or arn_identity["region"] != witness["region"]
        ):
            return False
        if "snapshot_arn" in witness and str(snapshot.get("DBSnapshotArn") or "") != str(
            witness["snapshot_arn"]
        ):
            return False
        if "source_dbi_resource_id" in witness and str(
            snapshot.get("DbiResourceId") or ""
        ) != str(witness["source_dbi_resource_id"]):
            return False
        if witness.get("witness_version") == cls._RDS_WITNESS_VERSION:
            actual_create_time = None
            if snapshot.get("SnapshotCreateTime") not in (None, ""):
                try:
                    actual_create_time = cls._rds_canonical_snapshot_time(
                        snapshot.get("SnapshotCreateTime")
                    )
                except RDSMalformedResponse:
                    return False
            expected_create_time = witness.get("snapshot_create_time")
            if expected_create_time and actual_create_time != expected_create_time:
                return False
            if witness.get("witness_state") == cls._RDS_COMMITTED_WITNESS_STATE and (
                not expected_create_time or not actual_create_time
            ):
                return False
            expected_original_time = witness.get("original_snapshot_create_time")
            if expected_original_time:
                try:
                    actual_original_time = cls._rds_canonical_snapshot_time(
                        snapshot.get("OriginalSnapshotCreateTime"),
                        field="OriginalSnapshotCreateTime",
                    )
                except RDSMalformedResponse:
                    return False
                if actual_original_time != expected_original_time:
                    return False
        return (
            arn_identity["snapshot_identifier"] == witness["snapshot_identifier"]
            and arn_identity["account_id"] == witness["account_id"]
            and arn_identity["region"] == witness["region"]
        )

    @classmethod
    def _rds_snapshot_tags(cls, client, snapshot):
        """Fetch and validate RDS tags; describe output alone is not ownership."""
        if not isinstance(snapshot, dict):
            raise RDSMalformedResponse("RDS returned an invalid snapshot object.")
        resource_name = str(snapshot.get("DBSnapshotArn") or "")
        if not resource_name:
            raise RDSMalformedResponse("RDS omitted the snapshot ARN for tag lookup.")
        response = client.list_tags_for_resource(ResourceName=resource_name)
        if not isinstance(response, dict) or not isinstance(
            response.get("TagList"), list
        ):
            raise RDSMalformedResponse("RDS returned an invalid snapshot tag list.")
        tags = {}
        for item in response["TagList"]:
            if not isinstance(item, dict) or item.get("Key") in (None, ""):
                raise RDSMalformedResponse("RDS returned an invalid snapshot tag.")
            key = str(item["Key"])
            value = str(item.get("Value") or "")
            if key in tags and tags[key] != value:
                raise RDSMalformedResponse("RDS returned duplicate snapshot tags.")
            tags[key] = value
        return list(response["TagList"]), tags

    @classmethod
    def _rds_find_owned_snapshot(
        cls,
        snapshots,
        witness,
        *,
        client=None,
        allow_missing_provisional_tag=False,
    ):
        exact = [
            snapshot
            for snapshot in snapshots
            if isinstance(snapshot, dict)
            and str(snapshot.get("DBSnapshotIdentifier") or "")
            == witness["snapshot_identifier"]
        ]
        if not exact:
            if snapshots:
                raise RDSOwnershipError(
                    "RDS returned a snapshot outside the requested identity."
                )
            return None
        if witness.get("witness_version") == cls._RDS_WITNESS_VERSION:
            if client is None:
                raise RDSMalformedResponse(
                    "RDS snapshot ownership requires a tag lookup client."
                )
            tagged = []
            for snapshot in exact:
                tag_list, tags = cls._rds_snapshot_tags(client, snapshot)
                actual_marker = tags.get(cls._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY)
                expected_marker = witness.get("ownership_marker")
                if actual_marker in (None, ""):
                    if (
                        allow_missing_provisional_tag
                        and witness.get("witness_state")
                        == cls._RDS_PROVISIONAL_WITNESS_STATE
                    ):
                        raise RDSOwnershipTagPending(
                            "The RDS ownership tag is not visible yet."
                        )
                    raise RDSOwnershipError(
                        "RDS snapshot ownership tag verification failed."
                    )
                if actual_marker != expected_marker:
                    raise RDSOwnershipError(
                        "RDS snapshot ownership tag verification failed."
                    )
                enriched = dict(snapshot)
                enriched["TagList"] = tag_list
                tagged.append(enriched)
            exact = tagged
        if any(not cls._rds_snapshot_owned(snapshot, witness) for snapshot in exact):
            raise RDSOwnershipError("RDS snapshot ownership verification failed.")
        if len(exact) > 1:
            raise RDSDuplicateMatch("Multiple exact RDS snapshots matched the request.")
        snapshot = exact[0]
        return snapshot

    def _rds_current_witness(self, auth, *, identifier=None, lease_owner=None, lease_token=None):
        state, stored = self._rds_execution_metadata()
        expected_identifier = str(identifier or self.unique_id or self.uuid_str)
        region = self._rds_region(auth)
        source_id = str(self.aws_rds.unique_id or "")
        account_id = self._rds_account_id(auth)
        if not stored:
            raise RDSMalformedResponse(
                "The RDS backup has no current-version provider witness."
            )
        stored = self._rds_canonical_witness(stored)
        if stored.get("witness_version") != self._RDS_WITNESS_VERSION:
            raise RDSMalformedResponse(
                "Legacy RDS backups require explicit compatibility handling."
            )
        if stored["snapshot_identifier"] != expected_identifier:
            raise RDSOwnershipError("The durable RDS request identity changed.")
        if stored["source_db_instance_identifier"] != source_id:
            raise RDSOwnershipError("The durable RDS source identity changed.")
        if stored["region"] != region:
            raise RDSOwnershipError("The durable RDS region identity changed.")
        if stored["account_id"] not in {"pending", account_id}:
            raise RDSOwnershipError("The durable RDS account identity changed.")
        if "source_node_id" in stored and stored["source_node_id"] != self.aws_rds.node_id:
            raise RDSOwnershipError("The durable RDS node identity changed.")
        if (
            "source_resource_id" in stored
            and stored["source_resource_id"] != self.aws_rds_id
        ):
            raise RDSOwnershipError("The durable RDS resource identity changed.")
        return dict(stored)

    def validated_rds_restore_witness(
        self,
        auth,
        *,
        node_id,
        source_resource_id,
        source_id,
        snapshot_id,
    ):
        """Return the immutable backup-time witness after identity proof.

        A missing witness identifies a legacy backup and returns ``None`` so the
        restore adapter can use its exact-source compatibility lookup. A present
        but incomplete, modified, or differently scoped witness always fails
        closed.
        """

        _state, stored = self._rds_execution_metadata()
        if not stored:
            return None
        stored = self._rds_canonical_witness(stored)
        if stored.get("witness_version") != self._RDS_WITNESS_VERSION:
            # Legacy rows remain an explicit compatibility path.  They do not
            # contain enough historical evidence to distinguish a same-name
            # snapshot incarnation, so they are never upgraded for restore.
            return None
        if stored.get("witness_state") != self._RDS_COMMITTED_WITNESS_STATE:
            raise RDSMalformedResponse(
                "The RDS restore witness is provisional and cannot be restored."
            )
        expected = {
            "snapshot_identifier": str(snapshot_id or ""),
            "source_db_instance_identifier": str(source_id or ""),
            "region": self._rds_region(auth),
            "account_id": self._rds_account_id(auth),
        }
        for key, value in expected.items():
            if stored.get(key) != value:
                raise RDSOwnershipError(
                    "The durable RDS restore witness identity changed."
                )
        try:
            expected_resource_id = int(source_resource_id)
            expected_node_id = int(node_id)
        except (TypeError, ValueError) as error:
            raise RDSMalformedResponse(
                "The RDS restore node identity is invalid."
            ) from error
        if self.aws_rds_id != expected_resource_id or self.aws_rds.node_id != expected_node_id:
            raise RDSOwnershipError("The RDS backup node identity changed.")

        configuration = stored.get("source_restore_configuration")
        if configuration is not None and (
            stored.get("source_node_id") != expected_node_id
            or stored.get("source_resource_id") != expected_resource_id
        ):
            raise RDSOwnershipError("The durable RDS restore node identity changed.")
        return dict(stored)

    def validated_rds_restore_configuration(
        self,
        auth,
        *,
        node_id,
        source_resource_id,
        source_id,
        snapshot_id,
    ):
        """Return the immutable backup-time configuration after identity proof."""

        stored = self.validated_rds_restore_witness(
            auth,
            node_id=node_id,
            source_resource_id=source_resource_id,
            source_id=source_id,
            snapshot_id=snapshot_id,
        )
        if stored is None:
            return None
        configuration = stored.get("source_restore_configuration")
        if configuration is None:
            if stored.get("account_id") == "pending":
                raise RDSMalformedResponse(
                    "The durable RDS restore witness is incomplete."
                )
            return None
        return dict(configuration)

    def validate_rds_snapshot_for_restore(
        self,
        auth,
        client,
        *,
        node_id,
        source_resource_id,
        source_id,
        snapshot_id,
        witness=None,
    ):
        """Re-describe a v2 snapshot and prove its immutable source identity."""

        witness = witness or self.validated_rds_restore_witness(
            auth,
            node_id=node_id,
            source_resource_id=source_resource_id,
            source_id=source_id,
            snapshot_id=snapshot_id,
        )
        if witness is None or witness.get("source_restore_configuration") is None:
            return None
        if witness.get("witness_version") != self._RDS_WITNESS_VERSION:
            return None
        if witness.get("witness_state") != self._RDS_COMMITTED_WITNESS_STATE:
            raise RDSMalformedResponse(
                "The provisional RDS witness cannot be used for restore."
            )
        snapshots = self._rds_list_snapshots(
            client, witness["snapshot_identifier"]
        )
        return (
            self._rds_find_owned_snapshot(snapshots, witness, client=client)
            is not None
        )

    def validate_legacy_rds_snapshot_for_restore(
        self,
        auth,
        client,
        *,
        node_id,
        source_resource_id,
        source_id,
        snapshot_id,
    ):
        """Handle a pre-v3 backup without inventing a witness.

        Legacy backups have no immutable backup-time marker or incarnation time.
        They therefore cannot be safely adopted, restored, or deleted after a
        same-name provider recreation. Keep the method as an explicit
        compatibility boundary and fail closed instead of retrofitting mutable
        present-day values as historical evidence.
        """
        raise RDSMalformedResponse(
            "Legacy RDS snapshots require an explicit re-registration before restore."
        )

    def _rds_snapshot_witness(self, witness, snapshot):
        """Pin incarnation data only after an exact stable snapshot observation.

        RDS may include ``SnapshotCreateTime`` in the response to
        ``CreateDBSnapshot`` while the snapshot is still ``creating``. That
        value is not a safe incarnation witness: a later exact ``Describe``
        can expose the stable timestamp for the same owned snapshot with a
        different value. Keep the request-bound marker/ARN/source witness
        provisional until the provider reports ``available``. Once committed,
        retain strict timestamp matching for every later observation.
        """
        if witness.get("witness_version") != self._RDS_WITNESS_VERSION:
            raise RDSMalformedResponse(
                "Only current-version RDS snapshots can be adopted."
            )
        status = str(snapshot.get("Status") or "").lower()
        committed = (
            witness.get("witness_state") == self._RDS_COMMITTED_WITNESS_STATE
        )
        stable_observation = status in self._RDS_STABLE_SNAPSHOT_STATES
        create_time = None
        if committed or stable_observation:
            if snapshot.get("SnapshotCreateTime") not in (None, ""):
                create_time = self._rds_canonical_snapshot_time(
                    snapshot.get("SnapshotCreateTime")
                )
        expected_time = witness.get("snapshot_create_time")
        if expected_time and create_time != expected_time:
            raise RDSOwnershipError("The RDS snapshot incarnation changed.")
        if stable_observation and not create_time:
            raise RDSMalformedResponse(
                "RDS marked the snapshot available without SnapshotCreateTime."
            )
        original_time = None
        if (committed or stable_observation) and snapshot.get(
            "OriginalSnapshotCreateTime"
        ) not in (None, ""):
            original_time = self._rds_canonical_snapshot_time(
                snapshot.get("OriginalSnapshotCreateTime"),
                field="OriginalSnapshotCreateTime",
            )
        if witness.get("original_snapshot_create_time") and (
            original_time != witness["original_snapshot_create_time"]
        ):
            raise RDSOwnershipError("The RDS original snapshot incarnation changed.")
        return self._rds_witness(
            identifier=witness["snapshot_identifier"],
            source_id=witness["source_db_instance_identifier"],
            account_id=witness["account_id"],
            region=witness["region"],
            source_node_id=witness.get("source_node_id"),
            source_resource_id=witness.get("source_resource_id"),
            snapshot_arn=witness.get("snapshot_arn")
            or snapshot.get("DBSnapshotArn"),
            source_dbi_resource_id=witness.get("source_dbi_resource_id"),
            source_db_instance_arn=witness.get("source_db_instance_arn"),
            source_restore_configuration=witness.get(
                "source_restore_configuration"
            ),
            ownership_marker=witness["ownership_marker"],
            snapshot_create_time=create_time,
            original_snapshot_create_time=(
                witness.get("original_snapshot_create_time") or original_time
            ),
            witness_state=(
                self._RDS_COMMITTED_WITNESS_STATE
                if create_time
                else self._RDS_PROVISIONAL_WITNESS_STATE
            ),
            witness_version=self._RDS_WITNESS_VERSION,
        )

    def _rds_adopt_snapshot(
        self,
        snapshot,
        witness,
        *,
        client=None,
        lease_owner=None,
        lease_token=None,
        tags_verified=False,
        allow_missing_provisional_tag=False,
    ):
        if witness.get("witness_version") == self._RDS_WITNESS_VERSION:
            if client is None:
                raise RDSMalformedResponse(
                    "RDS snapshot adoption requires a tag lookup client."
                )
            if not tags_verified:
                tag_list, tags = self._rds_snapshot_tags(client, snapshot)
                actual_marker = tags.get(self._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY)
                expected_marker = witness.get("ownership_marker")
                if actual_marker in (None, ""):
                    if (
                        allow_missing_provisional_tag
                        and witness.get("witness_state")
                        == self._RDS_PROVISIONAL_WITNESS_STATE
                    ):
                        raise RDSOwnershipTagPending(
                            "The RDS ownership tag is not visible yet."
                        )
                    raise RDSOwnershipError(
                        "RDS snapshot ownership tag verification failed."
                    )
                if actual_marker != expected_marker:
                    raise RDSOwnershipError(
                        "RDS snapshot ownership tag verification failed."
                    )
                snapshot = dict(snapshot)
                snapshot["TagList"] = tag_list
        if not self._rds_snapshot_owned(snapshot, witness):
            raise RDSOwnershipError("RDS snapshot ownership verification failed.")
        adopted_witness = self._rds_snapshot_witness(witness, snapshot)
        self._rds_persist_witness(
            adopted_witness, lease_owner=lease_owner, lease_token=lease_token
        )
        normalized = _rds_json(snapshot)
        # Django's JSON encoder intentionally emits milliseconds for datetimes;
        # do not let that presentation round trip truncate the exact provider
        # incarnation pinned in the durable witness.
        if (
            adopted_witness.get("witness_state")
            == self._RDS_PROVISIONAL_WITNESS_STATE
        ):
            # RDS can expose a mutable create timestamp while the snapshot is
            # still creating. Keep the backup row request-bound and provisional
            # until an exact-owned available observation supplies the stable
            # incarnation values.
            normalized.pop("SnapshotCreateTime", None)
            normalized.pop("OriginalSnapshotCreateTime", None)
        elif adopted_witness.get("snapshot_create_time"):
            normalized["SnapshotCreateTime"] = adopted_witness[
                "snapshot_create_time"
            ]
        if adopted_witness.get("original_snapshot_create_time"):
            normalized["OriginalSnapshotCreateTime"] = adopted_witness[
                "original_snapshot_create_time"
            ]
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh)
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, now=timezone.now(), require_live=True
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            fresh.unique_id = adopted_witness["snapshot_identifier"]
            fresh.region = adopted_witness["region"]
            fresh.size_gigabytes = normalized.get("AllocatedStorage")
            fresh.set_provider_metadata(normalized)
            fresh.save(
                update_fields=[
                    "unique_id",
                    "region",
                    "size_gigabytes",
                    "metadata",
                    "modified",
                ]
            )
        self.unique_id = witness["snapshot_identifier"]
        self.region = adopted_witness["region"]
        self.size_gigabytes = normalized.get("AllocatedStorage")
        self.set_provider_metadata(normalized)
        state = self.record_provider_reference(
            idempotency_key=adopted_witness["ownership_marker"],
            resource_id=adopted_witness["snapshot_identifier"],
            provider_status=str(normalized.get("Status") or "creating"),
            metadata={
                "rds_snapshot": {
                    "snapshot_identifier": adopted_witness[
                        "snapshot_identifier"
                    ],
                    "status": str(normalized.get("Status") or "creating"),
                    "snapshot_create_time": adopted_witness.get(
                        "snapshot_create_time"
                    ),
                    "ownership_marker": adopted_witness["ownership_marker"],
                },
            },
            lease_owner=lease_owner,
            lease_token=lease_token,
        )
        if state is None:
            raise RDSLeaseLost("The RDS worker lost its execution lease.")
        if adopted_witness.get("witness_state") == self._RDS_COMMITTED_WITNESS_STATE:
            self.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
                reason="rds_snapshot_adopted",
                metadata={
                    "snapshot_identifier": adopted_witness["snapshot_identifier"],
                    "snapshot_create_time": adopted_witness.get(
                        "snapshot_create_time"
                    ),
                },
                lease_owner=lease_owner,
                lease_token=lease_token,
            )
            self._rds_resolve_create_reconciliation(
                lease_owner=lease_owner, lease_token=lease_token
            )
        else:
            # RDS can return a creating snapshot before it exposes
            # SnapshotCreateTime.  Persist the provisional provider pointer,
            # but do not claim that the create witness is committed until a
            # later poll pins the provider incarnation timestamp.
            self.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                reason="rds_snapshot_provisional",
                metadata={
                    "snapshot_identifier": adopted_witness["snapshot_identifier"],
                    "snapshot_create_time": None,
                },
                lease_owner=lease_owner,
                lease_token=lease_token,
            )
        return self

    def _rds_create_lease(self, task_id=None):
        state = self.get_execution_state(create=False)
        if state is not None and state.lease_is_active() and state.phase in {
            "create",
            "provider_create",
        }:
            # A live lease is exclusive even when the delivery carries the
            # same Celery id (or no id at all).  Reusing its token would allow
            # two concurrent callers to cross the provider mutation boundary.
            return None
        owner = str(task_id or "rds-create-" + uuid.uuid4().hex)
        state = self.claim_execution(
            lease_owner=owner,
            phase="create",
            lease_seconds=self._rds_create_lease_seconds(),
            respect_retry_at=False,
        )
        if state is None:
            return None
        return owner, str(state.lease_token), True

    @classmethod
    def _rds_create_lease_seconds(cls):
        """Keep abrupt-worker recovery bounded to a short RDS-specific lease."""
        try:
            configured = int(
                getattr(
                    settings,
                    "RDS_CREATE_LEASE_SECONDS",
                    cls._RDS_CREATE_LEASE_DEFAULT_SECONDS,
                )
            )
        except (TypeError, ValueError):
            configured = cls._RDS_CREATE_LEASE_DEFAULT_SECONDS
        return min(
            cls._RDS_CREATE_LEASE_MAX_SECONDS,
            max(1, configured),
        )

    def _rds_assert_live_create_lease(self, owner, token):
        """Renew and fence the create lease at the AWS mutation boundary."""

        now = timezone.now()
        lease_seconds = self._rds_create_lease_seconds()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner,
                token,
                phase="create",
                now=now,
                require_live=True,
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            state.heartbeat_at = now
            state.lease_expires_at = now + timedelta(seconds=lease_seconds)
            state.save(
                update_fields=["heartbeat_at", "lease_expires_at", "modified"]
            )
            return state

    def _rds_release_create(self, owner, token):
        self.release_execution(
            lease_owner=owner,
            lease_token=token,
            phase="create",
            finished=False,
        )

    @staticmethod
    def _rds_exception_outcome(error):
        status_code, provider_code, headers = _provider_exception_details(error)
        try:
            status_code = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        if provider_code in {"dbsnapshotalreadyexists", "dbsnapshotalreadyexist"}:
            return "already_exists", "PROVIDER_CREATE_OUTCOME_UNKNOWN", UtilBackup.Status.RETRYING, _provider_retry_at(headers)
        if provider_code in _PROVIDER_AUTH_ERROR_CODES or status_code in _PROVIDER_AUTH_HTTP_CODES:
            return "auth_failed", "PROVIDER_AUTH_FAILED", UtilBackup.Status.FAILED, None
        if provider_code in _PROVIDER_RATE_LIMIT_ERROR_CODES or status_code == 429:
            return "rate_limited", "PROVIDER_RATE_LIMIT", UtilBackup.Status.RETRYING, _provider_retry_at(headers)
        if provider_code in _PROVIDER_TRANSIENT_ERROR_CODES or status_code in _PROVIDER_TRANSIENT_HTTP_CODES or status_code and status_code >= 500:
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", UtilBackup.Status.RETRYING, _provider_retry_at(headers)
        if isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
            return "timeout", "PROVIDER_TIMEOUT", UtilBackup.Status.RETRYING, _provider_retry_at()
        if isinstance(error, requests.exceptions.ConnectionError):
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", UtilBackup.Status.RETRYING, _provider_retry_at()
        if provider_code in _PROVIDER_NOT_FOUND_ERROR_CODES or status_code == 404:
            return "not_found", "PROVIDER_NOT_FOUND", UtilBackup.Status.FAILED, None
        return "provider_failed", "PROVIDER_FAILED", UtilBackup.Status.FAILED, None

    def _rds_record_fenced_outcome(
        self,
        *,
        owner,
        token,
        category,
        error_code=None,
        retry_at=None,
        provider_status=None,
        operation="create",
    ):
        state = self.record_provider_reference(
            provider_status=provider_status or category,
            metadata={"operation": operation, "provider": self._RDS_PROVIDER},
            lease_owner=owner,
            lease_token=token,
        )
        if state is None:
            raise RDSLeaseLost("The RDS worker lost its execution lease.")
        if error_code:
            state = self.record_execution_error(
                code=error_code,
                retry_at=retry_at,
                lease_owner=owner,
                lease_token=token,
            )
            if state is None:
                raise RDSLeaseLost("The RDS worker lost its execution lease.")

    def _rds_terminal_create_failure(self, code, *, owner, token, reason):
        self._rds_record_fenced_outcome(
            owner=owner,
            token=token,
            category="terminal_failure",
            error_code=code,
            provider_status=reason,
            operation="create",
        )
        self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
            reason=reason,
            metadata={"provider": self._RDS_PROVIDER},
            lease_owner=owner,
            lease_token=token,
        )
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner, token, phase="create", now=timezone.now(), require_live=True
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            fresh.status = UtilBackup.Status.FAILED
            fresh.save(update_fields=["status", "modified"])

    def create_snapshot(self, task_id=None):
        """Create/adopt one native RDS snapshot using a durable request witness.

        The normal Celery task currently invokes the cloud-node adapter. This
        method is the backup-row-owned implementation used by recovery and direct
        callers; it intentionally keeps the deterministic RDS protocol in the
        durable backup model so the provider mutation can never be retried blindly.
        """
        lease = self._rds_create_lease(task_id)
        if lease is None:
            return None
        owner, token, release_on_success = lease
        completed = False
        client = None
        mutation_started = False

        def mark_unknown(category, error_code, retry_at):
            """Persist the provider category before exposing an unknown result."""
            self._rds_checkpoint_create_outcome(
                owner,
                token,
                category=category,
                error_code=error_code,
            )
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category=category,
                error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                retry_at=retry_at,
                operation="create",
            )
            self.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                reason="rds_create_outcome_unknown",
                metadata={
                    "provider": self._RDS_PROVIDER,
                    "provider_error_category": str(category)[:64],
                    "provider_error_code": str(error_code)[:64],
                },
                lease_owner=owner,
                lease_token=token,
            )

        try:
            auth = self.aws_rds.node.connection.auth_aws_rds
            client = auth.get_client()
            region = self._rds_region(auth)
            identifier = str(self.unique_id or self.uuid_str)
            # Persist the deterministic identity before even the account lookup;
            # the create call must never be the first durable evidence.
            provisional = self._rds_witness(
                identifier=identifier,
                source_id=self.aws_rds.unique_id,
                account_id="pending",
                region=region,
                source_node_id=self.aws_rds.node_id,
                source_resource_id=self.aws_rds_id,
                witness_state=self._RDS_PROVISIONAL_WITNESS_STATE,
            )
            self._rds_persist_witness(provisional, lease_owner=owner, lease_token=token)
            _state, stored = self._rds_execution_metadata()
            stored = self._rds_canonical_witness(stored)
            account_id = stored["account_id"]
            if account_id == "pending":
                account_id = self._rds_account_id(auth)
            if stored["account_id"] not in {"pending", account_id}:
                raise RDSOwnershipError(
                    "The durable RDS account identity changed."
                )
            source_restore_configuration = stored.get(
                "source_restore_configuration"
            )
            source_provider_evidence = {
                key: stored[key]
                for key in (
                    "source_dbi_resource_id",
                    "source_db_instance_arn",
                )
                if key in stored
            }
            if source_restore_configuration is None:
                source_restore_configuration, source_provider_evidence = (
                    self._rds_describe_source_restore_configuration(
                        client,
                        source_id=str(self.aws_rds.unique_id),
                        account_id=account_id,
                        region=region,
                    )
                )
            witness = self._rds_witness(
                identifier=identifier,
                source_id=self.aws_rds.unique_id,
                account_id=account_id,
                region=region,
                source_node_id=self.aws_rds.node_id,
                source_resource_id=self.aws_rds_id,
                source_dbi_resource_id=source_provider_evidence.get(
                    "source_dbi_resource_id"
                ),
                source_db_instance_arn=source_provider_evidence.get(
                    "source_db_instance_arn"
                ),
                source_restore_configuration=source_restore_configuration,
                ownership_marker=provisional["ownership_marker"],
                witness_state=self._RDS_PROVISIONAL_WITNESS_STATE,
            )
            state = self._rds_persist_witness(
                witness, lease_owner=owner, lease_token=token
            )
            witness = dict(state.provider_metadata["rds_request"])

            # A worker may have died after AWS accepted the request.  Reconcile
            # the durable mutation intent before doing any new create lookup or
            # request.  This path is read-only and bounded by the original
            # checkpoint deadline.
            reconciliation_result = self._rds_reconcile_create_request(
                client,
                witness,
                lease_owner=owner,
                lease_token=token,
            )
            if reconciliation_result != "not_pending":
                completed = True
                return self

            try:
                existing = self._rds_find_owned_snapshot(
                    self._rds_list_snapshots(client, identifier),
                    witness,
                    client=client,
                )
            except Exception as error:
                if not _rds_not_found(error):
                    raise
                existing = None
            if existing is not None:
                self._rds_adopt_snapshot(
                    existing,
                    witness,
                    client=client,
                    tags_verified=True,
                    lease_owner=owner,
                    lease_token=token,
                )
                completed = True
                return self
            # This is deliberately the final durable check before the only
            # non-idempotent RDS create request.  A worker paused during source
            # discovery must not call AWS after another worker takes over.
            self._rds_assert_live_create_lease(owner, token)
            self._rds_checkpoint_create_mutation(owner, token)
            mutation_started = True
            response = client.create_db_snapshot(
                DBSnapshotIdentifier=identifier,
                DBInstanceIdentifier=self.aws_rds.unique_id,
                Tags=[
                    {
                        "Key": self._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                        "Value": witness["ownership_marker"],
                    }
                ],
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("DBSnapshot"), dict
            ):
                raise RDSMalformedResponse("RDS did not return a snapshot object.")
            snapshot = response["DBSnapshot"]
            if not self._rds_snapshot_owned(snapshot, witness):
                raise RDSOwnershipError("RDS create response ownership failed.")
            self._rds_adopt_snapshot(
                snapshot,
                witness,
                client=client,
                allow_missing_provisional_tag=True,
                lease_owner=owner,
                lease_token=token,
            )
            completed = True
            return self
        except RDSOwnershipTagPending:
            if not mutation_started:
                self._rds_terminal_create_failure(
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    owner=owner,
                    token=token,
                    reason="rds_ownership_tag_missing",
                )
                completed = True
                return self
            result = self._rds_record_create_visibility_observation(
                kind="missing_tag",
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                provider_status="ownership_tag_pending",
                lease_owner=owner,
                lease_token=token,
            )
            completed = True
            return self
        except (RDSDuplicateMatch, RDSOwnershipError, RDSMalformedResponse) as error:
            # A malformed response after the provider mutation boundary is an
            # unknown outcome, not proof that the create failed. Ownership and
            # duplicate evidence remain terminal/manual because they identify a
            # conflicting provider object.
            if mutation_started and isinstance(error, RDSMalformedResponse):
                mark_unknown(
                    "malformed_response",
                    "PROVIDER_MALFORMED_RESPONSE",
                    None,
                )
                self._rds_release_create(owner, token)
                raise
            code = (
                "PROVIDER_DUPLICATE_MATCH"
                if isinstance(error, RDSDuplicateMatch)
                else "PROVIDER_MALFORMED_RESPONSE"
                if isinstance(error, RDSMalformedResponse)
                else "PROVIDER_OWNERSHIP_MISMATCH"
            )
            self._rds_terminal_create_failure(
                code, owner=owner, token=token, reason=code.lower()
            )
            completed = True
            return self
        except RDSLeaseLost:
            return False
        except Exception as error:
            category, code, result, retry_at = self._rds_exception_outcome(error)
            if mutation_started:
                # Any exception after the provider call can conceal an accepted
                # RDS request, including a provider 404/rate-limit response.
                # Preserve that provider category separately from the durable
                # reconciliation intent and never issue a blind second create.
                mark_unknown(category, code, retry_at)
                self._rds_release_create(owner, token)
                raise
            if result == UtilBackup.Status.FAILED:
                self._rds_record_fenced_outcome(
                    owner=owner,
                    token=token,
                    category=category,
                    error_code=code,
                    retry_at=retry_at,
                    operation="create",
                )
                with transaction.atomic():
                    fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
                    state = self._locked_execution_state(fresh, create=False)
                    if state is None or not state.lease_matches(
                        owner, token, phase="create", now=timezone.now(), require_live=True
                    ):
                        raise RDSLeaseLost("The RDS worker lost its execution lease.")
                    fresh.status = result
                    fresh.save(update_fields=["status", "modified"])
                completed = True
                return self
            # A provider retryable failure before the mutation boundary is not an
            # unknown create. Keep its category and use RETRYING so the recovery
            # sweep can retry without presenting a provider error as IN_PROGRESS.
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category=category,
                error_code=code,
                retry_at=retry_at,
                operation="create",
            )
            with transaction.atomic():
                fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
                state = self._locked_execution_state(fresh, create=False)
                if state is None or not state.lease_matches(
                    owner, token, phase="create", now=timezone.now(), require_live=True
                ):
                    raise RDSLeaseLost("The RDS worker lost its execution lease.")
                fresh.status = result
                fresh.save(update_fields=["status", "modified"])
            completed = True
            return self
        finally:
            if release_on_success and completed:
                self._rds_release_create(owner, token)

    def poll_status(self):
        """Perform one categorized, ownership-checked RDS status check."""
        try:
            execution = self.get_execution_state(create=False)
            if execution is not None and execution.lease_is_active() and execution.phase == "create":
                return _provider_in_progress(
                    self,
                    provider=self._RDS_PROVIDER,
                    state="create_reconciliation",
                    resource_id=self.unique_id or self.uuid_str,
                )
            auth = self.aws_rds.node.connection.auth_aws_rds
            client = auth.get_client()
            witness = self._rds_current_witness(auth)
            reconciliation_pending = self._rds_create_reconciliation_pending()
            try:
                snapshots = self._rds_list_snapshots(
                    client, witness["snapshot_identifier"]
                )
            except ClientError as error:
                if _rds_not_found(error):
                    if reconciliation_pending:
                        return self._rds_record_create_visibility_observation(
                            kind="zero_match",
                            error_code="PROVIDER_NOT_FOUND",
                            provider_status="not_found",
                        )
                    return _provider_failed(
                        self,
                        provider=self._RDS_PROVIDER,
                        state="not_found",
                        code="PROVIDER_NOT_FOUND",
                    )
                raise
            try:
                snapshot = self._rds_find_owned_snapshot(
                    snapshots,
                    witness,
                    client=client,
                    allow_missing_provisional_tag=reconciliation_pending,
                )
            except RDSOwnershipTagPending:
                if not reconciliation_pending:
                    raise RDSOwnershipError(
                        "RDS snapshot ownership tag verification failed."
                    )
                return self._rds_record_create_visibility_observation(
                    kind="missing_tag",
                    error_code="PROVIDER_OWNERSHIP_MISMATCH",
                    provider_status="ownership_tag_pending",
                )
            if snapshot is None:
                if reconciliation_pending:
                    return self._rds_record_create_visibility_observation(
                        kind="zero_match",
                        error_code="PROVIDER_NOT_FOUND",
                        provider_status="not_found",
                    )
                return _provider_failed(
                    self,
                    provider=self._RDS_PROVIDER,
                    state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
            self._rds_adopt_snapshot(
                snapshot, witness, client=client, tags_verified=True
            )
            state = str(snapshot.get("Status") or "").lower()
            if state == "available":
                self.status = UtilBackup.Status.COMPLETE
                self.save(update_fields=["status", "modified"])
                _record_provider_outcome(
                    self,
                    provider=self._RDS_PROVIDER,
                    category="complete",
                    provider_status=state,
                    resource_id=self.unique_id,
                )
                return UtilBackup.Status.COMPLETE
            if state in {"failed", "incompatible-restore", "incompatible-network"}:
                return _provider_failed(self, provider=self._RDS_PROVIDER, state=state)
            if state in {"creating", "copying", "deleting", "backing-up"}:
                return _provider_in_progress(
                    self,
                    provider=self._RDS_PROVIDER,
                    state=state,
                    resource_id=self.unique_id,
                )
            return _provider_failed(
                self,
                provider=self._RDS_PROVIDER,
                state="malformed_provider_state",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        except (RDSDuplicateMatch, RDSOwnershipError) as error:
            return _provider_failed(
                self,
                provider=self._RDS_PROVIDER,
                state="duplicate_matches" if isinstance(error, RDSDuplicateMatch) else "ownership_mismatch",
                code="PROVIDER_DUPLICATE_MATCH" if isinstance(error, RDSDuplicateMatch) else "PROVIDER_OWNERSHIP_MISMATCH",
            )
        except RDSMalformedResponse:
            return _provider_failed(
                self,
                provider=self._RDS_PROVIDER,
                state="malformed_provider_response",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        except Exception as error:
            category, code, result, retry_at = self._rds_exception_outcome(error)
            _record_provider_outcome(
                self,
                provider=self._RDS_PROVIDER,
                category=category,
                operation="poll",
                provider_status=category,
                error_code=code,
                retry_at=retry_at,
                resource_id=self.unique_id,
            )
            self.status = result
            self.save(update_fields=["status", "modified"])
            if result == UtilBackup.Status.FAILED:
                return result
            # RETRYING is deliberately distinct from a provider snapshot that
            # is actually in an IN_PROGRESS lifecycle state.
            return result

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.aws_rds.node

    @classmethod
    def _rds_delete_redispatch_grace_seconds(cls):
        return cls._rds_bounded_setting(
            "RDS_DELETE_REDISPATCH_GRACE_SECONDS",
            cls._RDS_DELETE_REDISPATCH_GRACE_DEFAULT_SECONDS,
            minimum=1,
            maximum=cls._RDS_DELETE_REDISPATCH_GRACE_MAX_SECONDS,
        )

    @classmethod
    def _rds_delete_max_attempts(cls):
        return cls._rds_bounded_setting(
            "RDS_DELETE_MAX_ATTEMPTS",
            cls._RDS_DELETE_MAX_ATTEMPTS_DEFAULT,
            minimum=1,
            maximum=cls._RDS_DELETE_MAX_ATTEMPTS_LIMIT,
        )

    def _rds_confirm_delete_absence(self, client, witness):
        """Return True only after a post-delete provider read proves absence."""
        try:
            snapshots = self._rds_list_snapshots(
                client, witness["snapshot_identifier"]
            )
        except ClientError as error:
            if _rds_not_found(error):
                return True
            raise
        if not snapshots:
            return True
        # A visible object must still pass the complete ownership check.  A
        # foreign replacement is a terminal safety failure, never "absence".
        snapshot = self._rds_find_owned_snapshot(
            snapshots, witness, client=client
        )
        return snapshot is None

    def _rds_mark_delete_pending(self, owner, token, *, provider_status):
        self._rds_checkpoint_delete(
            owner,
            token,
            {
                "provider_status": str(provider_status or "pending")[:64],
                "phase": "delete_wait",
            },
        )
        self._rds_set_delete_status(
            owner, token, UtilBackup.Status.DELETE_IN_PROGRESS
        )
        self._rds_record_fenced_outcome(
            owner=owner,
            token=token,
            category="reconciliation_required",
            error_code="PROVIDER_RECONCILIATION_REQUIRED",
            operation="delete",
            provider_status=provider_status,
        )
        self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
            reason="rds_delete_visibility_pending",
            metadata={"provider": self._RDS_PROVIDER},
            lease_owner=owner,
            lease_token=token,
        )
        return False

    def _rds_mark_delete_manual_review(self, owner, token, *, reason):
        self._rds_record_fenced_outcome(
            owner=owner,
            token=token,
            category="manual_review",
            error_code="PROVIDER_RECONCILIATION_REQUIRED",
            operation="delete",
            provider_status=reason,
        )
        self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
            reason=reason,
            metadata={"provider": self._RDS_PROVIDER},
            lease_owner=owner,
            lease_token=token,
        )
        self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_FAILED)
        return False

    def soft_delete(self):
        msg = (
            f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
            f"is being deleted using connection {self.aws_rds.node.connection.name}"
        )
        lease = self._rds_claim_delete_lease()
        if lease is None:
            return False
        owner, token = lease
        completed = False
        try:
            auth = self.aws_rds.node.connection.auth_aws_rds
            client = auth.get_client()
            witness = self._rds_current_witness(
                auth, identifier=str(self.unique_id or self.uuid_str),
                lease_owner=owner, lease_token=token,
            )
            delete_state = self._rds_delete_state()
            identity = dict(delete_state.get("identity") or {})
            if identity and identity != witness:
                raise RDSOwnershipError("The durable RDS deletion identity changed.")
            if delete_state.get("delete_completed"):
                # A worker can die after the durable completion checkpoint but
                # before the local status commit. Reconfirm absence instead of
                # trusting a flag that could have been persisted too early by an
                # older worker.
                if self._rds_confirm_delete_absence(client, witness):
                    self._rds_set_delete_status(
                        owner, token, UtilBackup.Status.DELETE_COMPLETED
                    )
                    completed = True
                    return True
                self._rds_checkpoint_delete(
                    owner, token, {"delete_completed": False, "phase": "delete_requested"}
                )
                delete_state = self._rds_delete_state()
            delete_started = bool(delete_state.get("delete_started"))
            try:
                snapshots = self._rds_list_snapshots(client, witness["snapshot_identifier"])
            except ClientError as error:
                if not _rds_not_found(error):
                    raise
                snapshots = []
            if not snapshots:
                if not delete_started:
                    raise RDSUnprovenNotFound(
                        "RDS snapshot was absent before ownership was proven."
                    )
                self._rds_checkpoint_delete(
                    owner,
                    token,
                    {
                        "identity": witness,
                        "ownership_verified": True,
                        "delete_completed": True,
                        "phase": "complete",
                    },
                )
                self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_COMPLETED)
                self._rds_record_fenced_outcome(
                    owner=owner,
                    token=token,
                    category="delete_completed",
                    operation="delete",
                    provider_status="delete_completed",
                )
                completed = True
                return True
            snapshot = self._rds_find_owned_snapshot(
                snapshots, witness, client=client
            )
            if snapshot is None:
                raise RDSOwnershipError("RDS deletion target was not found in the full listing.")
            request_sent_at = delete_state.get("delete_request_sent_at")
            request_recent = False
            if request_sent_at:
                try:
                    request_recent = (
                        timezone.now()
                        - self._rds_parse_durable_timestamp(
                            request_sent_at, field="delete request timestamp"
                        )
                        < timedelta(seconds=self._rds_delete_redispatch_grace_seconds())
                    )
                except RDSMalformedResponse:
                    raise
            if delete_started and request_recent:
                # A recent request may have been accepted while the target is
                # still visible. Wait for the provider's asynchronous delete
                # instead of issuing a duplicate immediately.
                return self._rds_mark_delete_pending(
                    owner,
                    token,
                    provider_status=str(snapshot.get("Status") or "present"),
                )
            response_received = bool(delete_state.get("delete_response_received_at"))
            provider_status = str(snapshot.get("Status") or "").lower()
            if delete_started and (response_received or provider_status == "deleting"):
                # A confirmed SDK response or the provider's own deleting
                # lifecycle is proof that the delete request is already in
                # flight. Never redispatch against that visible snapshot.
                return self._rds_mark_delete_pending(
                    owner,
                    token,
                    provider_status=provider_status or "delete_requested",
                )
            if delete_started and provider_status != "available":
                # Only an exact available snapshot can be safely considered a
                # crash-before-request candidate. Other states require polling.
                return self._rds_mark_delete_pending(
                    owner,
                    token,
                    provider_status=provider_status or "unknown",
                )
            attempts = int(delete_state.get("delete_attempts", 0) or 0) + 1
            if attempts > self._rds_delete_max_attempts():
                return self._rds_mark_delete_manual_review(
                    owner,
                    token,
                    reason="rds_delete_max_attempts_exhausted",
                )
            now = timezone.now()
            self._rds_checkpoint_delete(
                owner,
                token,
                {
                    "identity": witness,
                    "ownership_verified": True,
                    "proof": {
                        "snapshot_identifier": witness["snapshot_identifier"],
                        "source_db_instance_identifier": witness["source_db_instance_identifier"],
                        "account_id": witness["account_id"],
                        "region": witness["region"],
                        "snapshot_type": witness["snapshot_type"],
                    },
                    "delete_started": True,
                    "delete_attempts": attempts,
                    # This is the no-second-delete boundary.  It is durable
                    # before the SDK call so a crash between checkpoint and
                    # request can be redispatched after the bounded grace.
                    "delete_intent_at": delete_state.get(
                        "delete_intent_at"
                    )
                    or now.isoformat(),
                    "delete_request_sent_at": now.isoformat(),
                    "delete_completed": False,
                    "phase": "delete_requested",
                },
            )
            delete_call_not_found = False
            try:
                client.delete_db_snapshot(
                    DBSnapshotIdentifier=witness["snapshot_identifier"]
                )
            except Exception as error:
                if not _rds_not_found(error):
                    raise
                delete_call_not_found = True
                self._rds_checkpoint_delete(
                    owner,
                    token,
                    {
                        "delete_response_received_at": timezone.now().isoformat(),
                        "delete_response_category": "not_found",
                    },
                )
            else:
                self._rds_checkpoint_delete(
                    owner,
                    token,
                    {
                        "delete_response_received_at": timezone.now().isoformat(),
                        "delete_response_category": "accepted",
                    },
                )
            # A successful/404 delete response is not itself completion. The
            # post-request inventory read is the completion witness.
            if not self._rds_confirm_delete_absence(client, witness):
                return self._rds_mark_delete_pending(
                    owner,
                    token,
                    provider_status=(
                        "not_found_response_pending"
                        if delete_call_not_found
                        else "delete_requested"
                    ),
                )
            self._rds_checkpoint_delete(
                owner,
                token,
                {"delete_completed": True, "phase": "complete"},
            )
            self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_COMPLETED)
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category="delete_completed",
                operation="delete",
                provider_status="delete_completed",
            )
            completed = True
            return True
        except RDSUnprovenNotFound:
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category="not_found",
                error_code="PROVIDER_NOT_FOUND",
                operation="delete",
            )
            self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_FAILED_NOT_FOUND)
            return False
        except (RDSDuplicateMatch, RDSOwnershipError, RDSMalformedResponse) as error:
            code = (
                "PROVIDER_DUPLICATE_MATCH"
                if isinstance(error, RDSDuplicateMatch)
                else "PROVIDER_MALFORMED_RESPONSE"
                if isinstance(error, RDSMalformedResponse)
                else "PROVIDER_OWNERSHIP_MISMATCH"
            )
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category="terminal_failure",
                error_code=code,
                operation="delete",
            )
            self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_FAILED)
            return False
        except RDSLeaseLost:
            return False
        except Exception as error:
            category, code, result, retry_at = self._rds_exception_outcome(error)
            self._rds_record_fenced_outcome(
                owner=owner,
                token=token,
                category=category,
                error_code=code,
                retry_at=retry_at,
                operation="delete",
            )
            delete_started = bool(self._rds_delete_state().get("delete_started"))
            if delete_started and result == UtilBackup.Status.RETRYING:
                self.set_reconciliation_state(
                    reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                    reason="rds_delete_provider_retry",
                    metadata={"provider": self._RDS_PROVIDER},
                    lease_owner=owner,
                    lease_token=token,
                )
            self._rds_set_delete_status(
                owner,
                token,
                UtilBackup.Status.DELETE_IN_PROGRESS
                if delete_started and result == UtilBackup.Status.RETRYING
                else UtilBackup.Status.DELETE_FAILED,
            )
            return False
        finally:
            try:
                self._rds_release_delete_lease(owner, token, finished=completed)
            except RDSLeaseLost:
                pass
            try:
                if completed:
                    msg = (
                        f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
                        f"deleted successfully using connection {self.aws_rds.node.connection.name}"
                    )
                else:
                    msg = (
                        f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
                        f"could not be deleted using connection {self.aws_rds.node.connection.name}."
                    )
                self.aws_rds.node.connection.account.create_backup_log(
                    msg, self.aws_rds.node, self
                )
            except Exception:
                pass

    def _rds_delete_state(self):
        state = self.get_execution_state(create=False)
        metadata = dict(state.provider_metadata or {}) if state is not None else {}
        value = metadata.get("rds_delete")
        return dict(value or {}) if isinstance(value, dict) else {}

    def _rds_claim_delete_lease(self):
        owner = "rds-delete-" + uuid.uuid4().hex
        now = timezone.now()
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            if fresh.status == UtilBackup.Status.DELETE_COMPLETED:
                return None
            state = self._locked_execution_state(fresh)
            if state.lease_token and state.lease_expires_at and state.lease_expires_at > now:
                return None
            state.lease_owner = owner
            state.lease_token = uuid.uuid4()
            state.lease_expires_at = now + timedelta(
                seconds=max(1, int(getattr(settings, "BACKUP_DELETE_LEASE_SECONDS", 300)))
            )
            state.heartbeat_at = now
            state.phase = "delete"
            state.claim_count += 1
            state.finished_at = None
            state.save()
            if fresh.status == UtilBackup.Status.DELETE_REQUESTED:
                fresh.status = UtilBackup.Status.DELETE_IN_PROGRESS
                fresh.save(update_fields=["status", "modified"])
            return owner, str(state.lease_token)

    def _rds_checkpoint_delete(self, owner, token, patch):
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner, token, phase="delete", now=timezone.now(), require_live=True
            ):
                raise RDSLeaseLost("The RDS deletion lease was lost.")
            metadata = dict(state.provider_metadata or {})
            delete_state = dict(metadata.get("rds_delete") or {})
            delete_state.update(dict(patch or {}))
            metadata["rds_delete"] = delete_state
            state.provider_metadata = metadata
            state.provider_resource_id = str(self.unique_id or self.uuid_str)[:255]
            state.provider_idempotency_key = str(self.unique_id or self.uuid_str)[:255]
            state.save(update_fields=["provider_metadata", "provider_resource_id", "provider_idempotency_key", "modified"])
            return delete_state

    def _rds_set_delete_status(self, owner, token, status):
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh, create=False)
            if state is None or not state.lease_matches(
                owner, token, phase="delete", now=timezone.now(), require_live=True
            ):
                raise RDSLeaseLost("The RDS deletion lease was lost.")
            fresh.status = status
            fresh.save(update_fields=["status", "modified"])
        self.status = status

    def _rds_release_delete_lease(self, owner, token, *, finished=False):
        self.release_execution(
            lease_owner=owner,
            lease_token=token,
            phase="delete",
            finished=finished,
        )

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.aws_rds.node.backup_complete_reset()


class CoreVultrDatabaseBackup(UtilBackup):
    """A local record for a Vultr provider-managed database backup."""

    vultr_database = models.ForeignKey(
        "CoreVultrDatabase", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="vultr_database_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=255, null=True)
    provider_backup_id = models.CharField(max_length=255, null=True)
    provider_marker = models.CharField(max_length=512, null=True)
    provider_state = models.CharField(max_length=64, default="")
    provider_error_class = models.CharField(max_length=64, default="")
    provider_http_status = models.PositiveIntegerField(null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr_database_backup"
        constraints = [
            models.UniqueConstraint(
                fields=("vultr_database", "provider_marker"),
                condition=models.Q(provider_marker__isnull=False),
                name="unique_vultr_database_provider_marker",
            )
        ]

    def poll_status(self):
        from apps.console.vultr_database import (
            VultrDatabaseError,
            provider_backup_id,
            provider_backup_state,
        )

        try:
            records = self.vultr_database.client.list_backup_records(
                self.vultr_database.unique_id
            )
            record = next(
                (
                    item for item in records
                    if self.provider_backup_id
                    and provider_backup_id(item) == self.provider_backup_id
                ),
                None,
            )
            if record is None and self.provider_marker:
                record = next(
                    (
                        item for item in records
                        if f"vultr-db:{self.vultr_database.unique_id}:{provider_backup_id(item)}"
                        == self.provider_marker
                    ),
                    None,
                )
            if record is None:
                self.provider_error_class = "not_found"
                self.provider_status = "not_found"
                self.status = self.Status.FAILED
                self.save()
                _provider_failed(
                    self,
                    provider="vultr_database",
                    state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
                return self.Status.FAILED

            state = provider_backup_state(record)
            self.provider_state = state
            self.provider_error_class = ""
            self.provider_http_status = None
            self.provider_backup_id = provider_backup_id(record) or self.provider_backup_id
            self.set_provider_metadata({
                "source_database_id": self.vultr_database.unique_id,
                "provider_backup": record,
            })
            if state in {"complete", "completed", "available", "succeeded", "success"}:
                self.provider_status = "complete"
                self.status = self.Status.COMPLETE
                outcome = "complete"
            elif state in {"failed", "failure", "error", "errored", "cancelled", "canceled"}:
                self.provider_status = "terminal_failure"
                self.provider_error_class = "terminal_failure"
                self.status = self.Status.FAILED
                outcome = "failed"
            else:
                self.provider_status = "in_progress"
                self.status = self.Status.IN_PROGRESS
                outcome = "in_progress"
            self.save()
            if outcome == "complete":
                _record_provider_outcome(
                    self,
                    provider="vultr_database",
                    category="complete",
                    provider_status=state,
                    resource_id=self.provider_backup_id,
                )
            elif outcome == "failed":
                _provider_failed(
                    self, provider="vultr_database", state=state
                )
            else:
                _provider_in_progress(
                    self,
                    provider="vultr_database",
                    state=state,
                    resource_id=self.provider_backup_id,
                )
            return self.status
        except VultrDatabaseError as error:
            self.provider_status = error.category
            self.provider_error_class = error.category
            self.provider_http_status = error.status_code
            self.set_provider_metadata({
                "source_database_id": self.vultr_database.unique_id,
                "error": error.category,
                "status_code": error.status_code,
            })
            self.status = (
                self.Status.IN_PROGRESS
                if error.category in {"rate_limited", "transient_outage"}
                else self.Status.FAILED
            )
            self.save()
            safe_code = {
                "not_found": "PROVIDER_NOT_FOUND",
                "rate_limited": "PROVIDER_RATE_LIMIT",
                "transient_outage": "PROVIDER_TRANSIENT_OUTAGE",
            }.get(error.category, "PROVIDER_REQUEST_FAILED")
            retry_at = (
                _provider_retry_at()
                if self.status == self.Status.IN_PROGRESS
                else None
            )
            _record_provider_outcome(
                self,
                provider="vultr_database",
                category=error.category,
                provider_status=error.category,
                error_code=safe_code,
                retry_at=retry_at,
                http_status=error.status_code,
                resource_id=self.provider_backup_id,
            )
            return self.status

    @property
    def node(self):
        return self.vultr_database.node

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save(update_fields=["status", "modified"])

    def soft_delete(self):
        # Vultr-managed database backup metadata is provider-owned. Cleanup only
        # removes the BackupSheep record; it never deletes or alters the provider
        # backup retention policy.
        self.status = self.Status.DELETE_COMPLETED
        self.save(update_fields=["status", "modified"])
        return True

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)
        self.status = self.Status.CANCELLED
        self.save(update_fields=["status", "modified"])


class BaseRestoreExecution(TimeStampedModel):
    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    execution_phase = models.CharField(max_length=64, blank=True, default="pending")
    execution_metadata = models.JSONField(default=dict, blank=True)
    lease_owner = models.CharField(max_length=255, blank=True, default="")
    lease_token = models.UUIDField(null=True, blank=True, editable=False)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    attempt_count = models.PositiveIntegerField(default=0)
    progress_completed = models.PositiveBigIntegerField(default=0)
    progress_total = models.PositiveBigIntegerField(null=True, blank=True)
    progress_unit = models.CharField(max_length=32, blank=True, default="")
    last_error_code = models.CharField(max_length=64, blank=True, default="")
    next_retry_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    def bind_execution_fence(self, owner, token):
        self._required_restore_lease_owner = str(owner or "")
        self._required_restore_lease_token = str(token or "")
        return self

    def assert_live_execution_fence(self):
        """Re-read and verify the renewable restore lease at a mutation boundary."""
        required_owner = getattr(self, "_required_restore_lease_owner", "")
        required_token = getattr(self, "_required_restore_lease_token", "")
        if self.pk is None or not required_owner or not required_token:
            raise RestoreExecutionLeaseLostError(
                "Restore execution lease ownership was not bound."
            )
        with transaction.atomic():
            current = self.__class__.objects.select_for_update().only(
                "lease_owner", "lease_token", "lease_expires_at"
            ).get(pk=self.pk)
            if (
                current.lease_owner != required_owner
                or str(current.lease_token or "") != required_token
                or not current.lease_expires_at
                or current.lease_expires_at <= timezone.now()
            ):
                raise RestoreExecutionLeaseLostError(
                    "Restore execution lease ownership was lost."
                )
            return current

    def save(self, *args, **kwargs):
        required_owner = getattr(self, "_required_restore_lease_owner", "")
        required_token = getattr(self, "_required_restore_lease_token", "")
        if self.pk and required_owner and required_token:
            with transaction.atomic():
                current = self.__class__.objects.select_for_update().only(
                    "lease_owner", "lease_token", "lease_expires_at"
                ).get(pk=self.pk)
                if (
                    current.lease_owner != required_owner
                    or str(current.lease_token or "") != required_token
                    or not current.lease_expires_at
                    or current.lease_expires_at <= timezone.now()
                ):
                    raise RestoreExecutionLeaseLostError(
                        "Restore execution lease ownership was lost."
                    )
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)


class CoreVultrDatabaseRestore(BaseRestoreExecution):
    """Durable, database-specific fork/restore state.

    ``resource_id`` is always a newly forked database. The source cluster is
    never passed to an in-place restore endpoint.
    """

    class Status(models.IntegerChoices):
        PENDING = 1, "Pending"
        IN_PROGRESS = 2, "In-Progress"
        COMPLETE = 3, "Complete"
        FAILED = 4, "Failed"
        CANCELLED = 5, "Cancelled"

    backup = models.ForeignKey(
        "CoreVultrDatabaseBackup", related_name="restores", on_delete=models.CASCADE
    )
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=255)
    params = models.JSONField(null=True, blank=True)
    resource_id = models.CharField(max_length=255, null=True, blank=True)
    provider_job_id = models.CharField(max_length=255, null=True, blank=True)
    provider_marker = models.CharField(max_length=255, null=True, blank=True)
    provider_status = models.CharField(max_length=64, default="")
    provider_http_status = models.PositiveIntegerField(null=True, blank=True)
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING)
    metadata = models.JSONField(null=True, blank=True)
    error = models.TextField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "core_vultr_database_restore"
        indexes = [
            models.Index(
                fields=("status", "next_retry_at", "modified"),
                name="vultr_db_restore_retry_idx",
            ),
            models.Index(
                fields=("status", "lease_expires_at"),
                name="vultr_db_restore_lease_idx",
            ),
        ]

    @property
    def node(self):
        return self.backup.vultr_database.node


class CoreCloudRestore(BaseRestoreExecution):
    """Tracks a restore of a cloud / volume snapshot to a NEW provider resource.

    Each provider keeps its own backup table, so the source backup row is resolved
    through node.get_cloud_backup(backup_id) and only the integer id is stored here.
    Provider-specific target options (size/plan/zone/instance type, ...) go in
    `params`; the provider's restore_snapshot() implementation fills `resource_id`
    once the new resource exists.
    """

    class Status(models.IntegerChoices):
        PENDING = 1, "Pending"
        IN_PROGRESS = 2, "In-Progress"
        COMPLETE = 3, "Complete"
        FAILED = 4, "Failed"

    class OperationPhase(models.TextChoices):
        PENDING = "pending", "Pending"
        RECONCILING = "reconciling", "Reconciling"
        CREATE_UNKNOWN = "create_unknown", "Create outcome unknown"
        POLLING = "polling", "Polling"
        COMPLETE = "complete", "Complete"
        FAILED = "failed", "Failed"
        MANUAL_REVIEW = "manual_review", "Manual review"

    node = models.ForeignKey(
        "CoreNode", related_name="restores", on_delete=models.CASCADE
    )
    backup_id = models.BigIntegerField()
    name = models.CharField(max_length=255)
    params = models.JSONField(null=True, blank=True)
    resource_id = models.CharField(max_length=255, null=True, blank=True)
    # AWS Backup restores are asynchronous.  Keep the provider job id separate
    # from resource_id so a worker restart can resume polling without starting a
    # second restore request.
    provider_job_id = models.CharField(max_length=255, null=True, blank=True)
    # Native cloud restores have no provider idempotency key.  These fields are
    # committed before a provider create request so a redelivered task can
    # reconcile an accepted request whose response was lost.
    restore_marker = models.CharField(max_length=128, blank=True, default="")
    request_fingerprint = models.CharField(max_length=64, blank=True, default="")
    operation_phase = models.CharField(
        max_length=32,
        choices=OperationPhase.choices,
        default=OperationPhase.PENDING,
    )
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING)
    error = models.TextField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "core_cloud_restore"
        indexes = [
            models.Index(
                fields=("status", "next_retry_at", "modified"),
                name="cloud_restore_retry_idx",
            ),
            models.Index(
                fields=("status", "lease_expires_at"),
                name="cloud_restore_lease_idx",
            ),
        ]

    @property
    def backup(self):
        return self.node.get_cloud_backup(self.backup_id)

    @property
    def node_type_object(self):
        return self.node._integration_object()

    def _upcloud_server_verification_resume_safe(
        self,
        *,
        params,
        identity,
        generic,
        backup,
        source_id,
        source_server_id,
        digest,
    ):
        """Validate a pointerless UpCloud server state-machine resume."""
        execution = backup.get_execution_state(create=False)
        provider_metadata = (
            dict(execution.provider_metadata or {}) if execution else {}
        )
        witness = provider_metadata.get("witness")
        resource = provider_metadata.get("resource")
        scope = witness.get("scope") if isinstance(witness, dict) else None
        source_storage_id = (
            str(witness.get("source_id") or "")
            if isinstance(witness, dict)
            else ""
        )
        server_marker = f"backupsheep-upcloud-server-{self.pk}-{digest}"[:128]
        storage_marker = f"backupsheep-upcloud-storage-{self.pk}-{digest}"[:128]
        hostname = f"bs-upcloud-{self.pk}-{digest[:16]}"[:63]
        expected_identity = {
            "source_id": source_id,
            "source_origin_id": source_storage_id,
            "source_server_id": source_server_id,
            "target_type": "server",
            "marker": server_marker,
            "server_marker": server_marker,
            "storage_marker": storage_marker,
            "hostname": hostname,
            "marker_digest": digest,
            "marker_source_bound": True,
            "account_id": str(self.node.connection.account_id),
            "connection_id": str(self.node.connection_id),
        }
        if any(
            identity.get(key) != value
            for key, value in expected_identity.items()
        ):
            return False
        expected_generic = {
            "provider": "upcloud",
            "source_id": source_id,
            "target_kind": "server",
            "target_name": server_marker,
            "marker": server_marker,
        }
        if any(
            str(generic.get(key) or "") != value
            for key, value in expected_generic.items()
        ):
            return False
        if any(
            (
                str(params.get("_bs_provider_name") or "") != server_marker,
                str(self.restore_marker or "") != server_marker,
                not re.fullmatch(
                    r"[0-9a-f]{64}", str(self.request_fingerprint or "")
                ),
            )
        ):
            return False

        if not all(
            (
                execution,
                isinstance(witness, dict),
                isinstance(scope, dict),
                isinstance(resource, dict),
                str(witness.get("provider") or "") == "upcloud",
                str(witness.get("resource_type") or "")
                == "server_boot_storage",
                str(witness.get("marker") or "") == str(backup.uuid_str),
                str(resource.get("uuid") or "") == source_id,
                str(resource.get("type") or "") == "backup",
                str(resource.get("title") or "") == str(backup.uuid_str),
                str(resource.get("origin") or "")
                == str(witness.get("source_id") or ""),
                resource.get("_bs_ownership_verified") is True,
                str(resource.get("_bs_provider") or "") == "upcloud",
                str(resource.get("_bs_marker") or "")
                == str(backup.uuid_str),
                str(resource.get("_bs_source_id") or "")
                == str(witness.get("source_id") or ""),
                str(execution.provider_resource_id or "") == source_id,
                str(scope.get("server_id") or "") == source_server_id,
                str(scope.get("account_id") or "")
                == str(self.node.connection.account_id),
                str(scope.get("connection_id") or "")
                == str(self.node.connection_id),
            )
        ):
            return False
        try:
            backup_size = int(resource.get("size"))
            stored_size = identity.get("boot_storage_size")
            if stored_size not in (None, "") and int(stored_size) != backup_size:
                return False
        except (TypeError, ValueError):
            return False
        if backup_size <= 0:
            return False

        zone = str(identity.get("target_zone") or "")
        tier = str(identity.get("boot_storage_tier") or "").casefold()
        encrypted = str(identity.get("boot_storage_encrypted") or "").casefold()
        config = identity.get("server_config")
        firewall = identity.get("server_firewall")
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", zone)
            or zone != str(scope.get("zone") or "")
            or tier not in {"standard", "maxiops"}
            or tier != str(scope.get("tier") or "").casefold()
            or encrypted not in {"yes", "no"}
            or encrypted != str(scope.get("encrypted") or "").casefold()
            or not isinstance(config, dict)
            or not isinstance(firewall, dict)
        ):
            return False
        config_fingerprint = hashlib.sha256(
            json.dumps(
                config,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        firewall_rules = firewall.get("rules")
        if not isinstance(firewall_rules, list) or not firewall_rules:
            return False
        firewall_fingerprint = hashlib.sha256(
            json.dumps(
                firewall_rules,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if any(
            (
                str(identity.get("server_config_fingerprint") or "")
                != config_fingerprint,
                str(scope.get("server_config_fingerprint") or "")
                != config_fingerprint,
                witness.get("upcloud_server_config") != config,
                str(witness.get("upcloud_server_config_fingerprint") or "")
                != config_fingerprint,
                witness.get("upcloud_firewall") != firewall,
                str(identity.get("firewall_fingerprint") or "")
                != firewall_fingerprint,
                str(firewall.get("fingerprint") or "")
                != firewall_fingerprint,
                str(params.get("_bs_upcloud_firewall_fingerprint") or "")
                != firewall_fingerprint,
                str(scope.get("firewall_fingerprint") or "")
                != firewall_fingerprint,
            )
        ):
            return False

        uuid_pattern = (
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}"
        )
        target_storage_id = str(identity.get("target_storage_id") or "")
        candidate_server_id = str(identity.get("candidate_server_id") or "")
        if (
            target_storage_id
            and not re.fullmatch(uuid_pattern, target_storage_id)
        ) or (
            candidate_server_id
            and not re.fullmatch(uuid_pattern, candidate_server_id)
        ):
            return False

        def witness_server_id_is_safe(witness):
            """Return the exact provider target bound by a mutation witness.

            A marker-adopted server may not have ``candidate_server_id``: the
            worker can crash after the provider accepted create but before
            that pointer was stored.  The witness UUID is still safe when it
            is syntactically valid because the resumed worker must rediscover
            and fully verify the unique marker-owned server before mutation.
            When a candidate pointer does exist, require an exact match.
            """
            witness_server_id = str(witness.get("server_id") or "")
            if not re.fullmatch(uuid_pattern, witness_server_id):
                return ""
            if candidate_server_id and witness_server_id != candidate_server_id:
                return ""
            return witness_server_id

        def power_witness_is_safe(witness, *, expected_payload):
            """Validate the exact durable witness for one power request.

            These fields are written before the provider POST.  Manual resume
            must therefore prove both the target identity and the exact
            request that may already have been accepted; a merely plausible
            server id or arbitrary hash is not sufficient.
            """
            required_keys = {
                "server_id",
                "request_fingerprint",
                "requested_at",
                "deadline_at",
            }
            if (
                not isinstance(witness, dict)
                or set(witness) != required_keys
                or not witness_server_id_is_safe(witness)
            ):
                return False
            expected_fingerprint = hashlib.sha256(
                json.dumps(
                    expected_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if witness.get("request_fingerprint") != expected_fingerprint:
                return False

            parsed = {}
            for key in ("requested_at", "deadline_at"):
                value = witness.get(key)
                if not isinstance(value, str) or not value.strip():
                    return False
                raw = value.strip()
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                try:
                    timestamp = datetime.fromisoformat(raw)
                except (TypeError, ValueError):
                    return False
                # The worker writes aware ISO-8601 values.  Reject naive
                # values instead of assigning a timezone during resume.
                if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                    return False
                parsed[key] = timestamp.astimezone(datetime_timezone.utc)
            duration = parsed["deadline_at"] - parsed["requested_at"]
            return timedelta(0) < duration <= timedelta(hours=1)

        def public_ip_witness_is_safe(witness):
            """Validate one exact durable public-IP assignment request."""
            required_keys = {
                "server_id",
                "ordinal",
                "family",
                "request_fingerprint",
            }
            if not isinstance(witness, dict) or set(witness) != required_keys:
                return False
            server_id = witness_server_id_is_safe(witness)
            ordinal = witness.get("ordinal")
            family = str(witness.get("family") or "")
            public_ip_families = (
                config.get("public_ip_families")
                if isinstance(config, dict)
                else None
            )
            if (
                not server_id
                or type(ordinal) is not int
                or not isinstance(public_ip_families, list)
                or ordinal < 0
                or ordinal >= len(public_ip_families)
                or family != public_ip_families[ordinal]
                or active != f"public_ip:{ordinal}:{family}"
            ):
                return False
            expected_payload = {
                "ip_address": {"family": family, "server": server_id}
            }
            expected_fingerprint = hashlib.sha256(
                json.dumps(
                    expected_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            return witness.get("request_fingerprint") == expected_fingerprint

        stage = str(identity.get("stage") or "")
        active = str(identity.get("active_mutation") or "")
        stage_contracts = {
            "storage_create_requested": {"storage"},
            "storage_adopted": {""},
            "server_create_requested": {"server"},
            "server_candidate_received": {"server"},
            "firewall_replace_requested": {"firewall"},
            "firewall_verified": {""},
            "firewall_stabilizing": {""},
            "public_ip_assign_requested": {
                value
                for value in (active,)
                if re.fullmatch(r"public_ip:[0-9]+:IPv[46]", value)
            },
            "server_stop_requested": {"server_stop"},
            "server_start_requested": {"server_start"},
        }
        if stage not in stage_contracts or active not in stage_contracts[stage]:
            return False

        power_contracts = {
            "server_stop_requested": (
                "server_stop_request",
                {"stop_server": {"stop_type": "soft"}},
            ),
            "server_start_requested": (
                "server_start_request",
                {"server": {"start_type": "async"}},
            ),
        }
        if stage == "public_ip_assign_requested":
            witness_key = "public_ip_assignment"
            if not public_ip_witness_is_safe(identity.get(witness_key)):
                return False
        else:
            power_contract = power_contracts.get(stage)
            if power_contract is None:
                return True
            witness_key, expected_payload = power_contract
            if not power_witness_is_safe(
                identity.get(witness_key), expected_payload=expected_payload
            ):
                return False
        if any(
            identity.get(other_key) is not None
            for other_key in (
                "server_stop_request",
                "public_ip_assignment",
                "server_start_request",
            )
            if other_key != witness_key
        ):
            return False
        return True

    def _upcloud_server_definite_retry_safe(self, *, params, identity):
        """Prove that one rejected server create may retry the same row.

        A definite provider rejection means no server was accepted.  Retrying
        is nevertheless allowed only after a complete marker inventory found
        zero matches and the durable state machine still points at the exact
        owned boot-storage clone.  The worker repeats all live ownership reads
        and the complete marker scan before crossing the create boundary.
        """
        if any(
            (
                params.get("_bs_create_outcome_unknown") is not False,
                params.get("_bs_marker_required") is not True,
                str(self.last_error_code or "") != "PROVIDER_REQUEST_FAILED",
                str(params.get("_bs_last_error_code") or "")
                != "PROVIDER_REQUEST_FAILED",
                str(params.get("_bs_last_error_category") or "") != "terminal",
                str(identity.get("stage") or "") != "server_create_requested",
                str(identity.get("active_mutation") or "") != "server",
                bool(str(identity.get("candidate_server_id") or "").strip()),
            )
        ):
            return False
        uuid_pattern = (
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}"
        )
        if not re.fullmatch(
            uuid_pattern, str(identity.get("target_storage_id") or "")
        ):
            return False
        scan = params.get("_bs_upcloud_server_scan")
        if not isinstance(scan, dict) or scan.get("scan_complete") is not True:
            return False
        try:
            page_count = int(scan.get("page_count"))
            item_count = int(scan.get("item_count"))
            match_count = int(scan.get("match_count"))
        except (TypeError, ValueError, OverflowError):
            return False
        return page_count >= 1 and item_count >= 0 and match_count == 0

    @property
    def verification_resume_mode(self):
        """Return the safe operator-resume mode, or an empty string.

        Most manual resumes require a committed provider pointer and can only
        poll that exact target. UpCloud volume/server state machines also
        reconcile an accepted request whose UUID was not persisted. A third,
        narrower mode retries the same server row after a *definite* provider
        rejection and a complete zero-match scan. Every mode requires an
        internally consistent source-bound durable identity.
        """
        if self.status != self.Status.FAILED:
            return ""
        manual_review = self.operation_phase == self.OperationPhase.MANUAL_REVIEW
        definite_failure = self.operation_phase == self.OperationPhase.FAILED
        if not (manual_review or definite_failure):
            return ""
        if str(self.resource_id or self.provider_job_id or "").strip():
            return "provider_pointer" if manual_review else ""

        try:
            node = self.node
            if node.connection.integration.code != "upcloud":
                return ""
            params = self.params if isinstance(self.params, dict) else {}
            identity = params.get("_bs_upcloud_restore")
            generic = params.get("_backupsheep_restore")
            if not isinstance(identity, dict) or not isinstance(generic, dict):
                return ""
            if params.get("_bs_marker_required") is not True:
                return ""

            backup = self.backup
            source_id = str(getattr(backup, "unique_id", "") or "").strip()
            source_origin_id = str(
                getattr(self.node_type_object, "unique_id", "") or ""
            ).strip()
            if not source_id or not source_origin_id:
                return ""

            digest = hashlib.sha256(
                f"upcloud:v1:{self.pk}:{self.correlation_id}:{source_id}".encode(
                    "utf-8"
                )
            ).hexdigest()[:24]
            if node.type == node.Type.CLOUD:
                safe_identity = self._upcloud_server_verification_resume_safe(
                    params=params,
                    identity=identity,
                    generic=generic,
                    backup=backup,
                    source_id=source_id,
                    source_server_id=source_origin_id,
                    digest=digest,
                )
                if not safe_identity:
                    return ""
                if manual_review and params.get("_bs_create_outcome_unknown") is True:
                    return "provider_reconciliation"
                if definite_failure and self._upcloud_server_definite_retry_safe(
                    params=params,
                    identity=identity,
                ):
                    return "provider_retry"
                return ""
            if node.type != node.Type.VOLUME:
                return ""
            if not manual_review or params.get("_bs_create_outcome_unknown") is not True:
                return ""
            marker = f"backupsheep-upcloud-{self.pk}-{digest}"[:128]
            expected_identity = {
                "source_id": source_id,
                "source_origin_id": source_origin_id,
                "target_type": "normal",
                "marker": marker,
                "marker_digest": digest,
                "marker_source_bound": True,
            }
            if any(identity.get(key) != value for key, value in expected_identity.items()):
                return ""
            expected_generic = {
                "provider": "upcloud",
                "source_id": source_id,
                "target_kind": "storage",
                "target_name": marker,
                "marker": marker,
            }
            if any(
                str(generic.get(key) or "") != value
                for key, value in expected_generic.items()
            ):
                return ""
            if str(params.get("_bs_provider_name") or "") != marker:
                return ""
            if str(self.restore_marker or "") != marker:
                return ""
            if not re.fullmatch(r"[0-9a-f]{64}", str(self.request_fingerprint or "")):
                return ""

            source_zone = str(identity.get("source_zone") or "")
            target_zone = str(identity.get("target_zone") or "")
            source_tier = str(identity.get("source_tier") or "").casefold()
            target_tier = str(identity.get("target_tier") or "").casefold()
            source_encrypted = str(identity.get("source_encrypted") or "").casefold()
            target_encrypted = str(identity.get("target_encrypted") or "").casefold()
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", source_zone):
                return ""
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", target_zone):
                return ""
            if source_tier not in {"standard", "maxiops"} or target_tier != source_tier:
                return ""
            if source_encrypted not in {"yes", "no"} or target_encrypted != source_encrypted:
                return ""
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            return ""
        return "provider_reconciliation"

    @property
    def can_resume_verification(self):
        return bool(self.verification_resume_mode)

    def poll_status(self):
        """Single restore status check, used by the poll_cloud_restore task.

        Provider adapters must return a real lifecycle state. Transport/provider
        errors are intentionally allowed to reach the task so it can distinguish
        authentication, 404, rate-limit, timeout, and transient outage outcomes
        instead of falsely reporting every failure as IN_PROGRESS.
        """
        return self.node_type_object.check_restore(self)


class CoreWebsiteRestore(BaseRestoreExecution):
    """Tracks a restore of a website/files backup zip back onto its source server.

    `storage_point` is the concrete stored-backup row (one uploaded copy of the
    backup zip on a storage backend) the restore is fetched from; nullable so
    deleting that copy later does not cascade-delete the restore history.
    Restore options go in `params` (e.g. {"delete": true} -- remove remote files
    that are not present in the backup).
    """

    class Status(models.IntegerChoices):
        PENDING = 1, "Pending"
        IN_PROGRESS = 2, "In-Progress"
        COMPLETE = 3, "Complete"
        FAILED = 4, "Failed"

    backup = models.ForeignKey(
        "CoreWebsiteBackup", related_name="restores", on_delete=models.CASCADE
    )
    storage_point = models.ForeignKey(
        "CoreWebsiteBackupStoragePoints",
        related_name="restores",
        null=True,
        on_delete=models.SET_NULL,
    )
    name = models.CharField(max_length=255)
    params = models.JSONField(null=True)
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING)
    error = models.TextField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "core_website_restore"
        indexes = [
            models.Index(
                fields=("status", "next_retry_at", "modified"),
                name="website_restore_retry_idx",
            ),
            models.Index(
                fields=("status", "lease_expires_at"),
                name="website_restore_lease_idx",
            ),
        ]


class CoreDatabaseRestore(BaseRestoreExecution):
    """Tracks a restore of a database backup zip back into its source server.

    `storage_point` is the concrete stored-backup row (one uploaded copy of the
    backup zip on a storage backend) the restore is fetched from; nullable so
    deleting that copy later does not cascade-delete the restore history.
    """

    class Status(models.IntegerChoices):
        PENDING = 1, "Pending"
        IN_PROGRESS = 2, "In-Progress"
        COMPLETE = 3, "Complete"
        FAILED = 4, "Failed"

    backup = models.ForeignKey(
        "CoreDatabaseBackup", related_name="restores", on_delete=models.CASCADE
    )
    storage_point = models.ForeignKey(
        "CoreDatabaseBackupStoragePoints",
        related_name="restores",
        null=True,
        on_delete=models.SET_NULL,
    )
    name = models.CharField(max_length=255)
    params = models.JSONField(null=True)
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING)
    error = models.TextField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "core_database_restore"
        indexes = [
            models.Index(
                fields=("status", "next_retry_at", "modified"),
                name="database_restore_retry_idx",
            ),
            models.Index(
                fields=("status", "lease_expires_at"),
                name="database_restore_lease_idx",
            ),
        ]
