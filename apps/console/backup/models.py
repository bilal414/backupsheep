import json
import hashlib
import re
import subprocess
import time
import uuid
from datetime import datetime, timedelta
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
from django.core.exceptions import ObjectDoesNotExist
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
from ..utils.models import UtilBackup
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
    """Seconds before a generated backup download URL expires (configurable via
    S3_DOWNLOAD_URL_EXPIRES; default 24h)."""
    return int(getattr(settings, "S3_DOWNLOAD_URL_EXPIRES", 24 * 3600))


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


_PROVIDER_AUTH_HTTP_CODES = {401, 403}
_PROVIDER_TRANSIENT_HTTP_CODES = {408, 425, 500, 502, 503, 504}
_PROVIDER_NOT_FOUND_ERROR_CODES = {
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
    safe_metadata = {"provider": provider, "operation": operation}
    if http_status is not None:
        safe_metadata["http_status"] = int(http_status)
    backup.record_provider_reference(
        operation_id=operation_id,
        resource_id=resource_id,
        provider_status=provider_status or category,
        metadata=safe_metadata,
    )
    if error_code:
        backup.record_execution_error(
            code=error_code,
            message=backup.EXECUTION_ERROR_MESSAGES.get(
                error_code, "The provider operation failed."
            ),
            retry_at=retry_at,
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
        backup.metadata = snapshot
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


class CoreBackupArtifact(TimeStampedModel):
    """Integrity and resume metadata for one backup artifact/destination."""

    class Role(models.TextChoices):
        SOURCE = "source", "Source"
        ARCHIVE = "archive", "Archive"
        DESTINATION = "destination", "Destination"
        MANIFEST = "manifest", "Manifest"

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
            )
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

    def poll_status(self):
        """Perform one categorized, ownership-checked DigitalOcean status check."""
        from ..node.models import CoreNode

        try:
            client = self.digitalocean.node.connection.auth_digitalocean.get_client()
            resource_type = (
                "droplet"
                if CoreNode.Type.CLOUD == self.digitalocean.node.type
                else "volume"
            )
            source_id = self.digitalocean.unique_id

            def record_snapshot(snapshot):
                state = str(snapshot.get("state") or snapshot.get("status") or "").lower()
                if not _provider_owned(
                    snapshot,
                    resource_id=self.unique_id if self.unique_id else None,
                    marker=self.uuid_str,
                    source_fields=(("resource_id", source_id),),
                ) or (
                    snapshot.get("resource_type")
                    and snapshot.get("resource_type") != resource_type
                ):
                    return _provider_failed(
                        self,
                        provider="digitalocean",
                        state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                if snapshot.get("id"):
                    self.unique_id = str(snapshot["id"])
                if snapshot.get("size_gigabytes") is not None:
                    self.size_gigabytes = snapshot["size_gigabytes"]
                metadata = dict(self.metadata or {})
                metadata["_provider_ownership_verified"] = True
                metadata["_provider_source_id"] = str(source_id)
                self.metadata = metadata
                if state in {"error", "errored", "failed", "canceled", "cancelled"}:
                    self.save(
                        update_fields=[
                            "unique_id",
                            "size_gigabytes",
                            "metadata",
                            "modified",
                        ]
                    )
                    return _provider_failed(
                        self, provider="digitalocean", state=state
                    )
                if state and state not in {"available", "completed", "complete"}:
                    self.save(
                        update_fields=[
                            "unique_id",
                            "size_gigabytes",
                            "metadata",
                            "modified",
                        ]
                    )
                    return _provider_in_progress(
                        self,
                        provider="digitalocean",
                        state=state,
                        resource_id=self.unique_id,
                        operation_id=self.action_id,
                    )
                self.status = UtilBackup.Status.COMPLETE
                self.save()
                _record_provider_outcome(
                    self,
                    provider="digitalocean",
                    category="complete",
                    provider_status=state or "complete",
                    resource_id=self.unique_id,
                    operation_id=self.action_id,
                )
                return UtilBackup.Status.COMPLETE

            # A persisted snapshot id is the strongest recovery pointer. This also
            # handles a worker dying after the provider returned the id but before
            # action_id/metadata was written locally.
            if self.unique_id:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/snapshots/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    payload = result.json()
                    return record_snapshot(payload.get("snapshot", payload))
                return _provider_http_outcome(
                    self, result, provider="digitalocean"
                )

            if CoreNode.Type.CLOUD == self.digitalocean.node.type and self.action_id:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/actions/{self.action_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    action = result.json().get("action", {})
                    if not _provider_owned(
                        action,
                        resource_id=self.action_id,
                        source_fields=(("resource_id", source_id),),
                    ):
                        return _provider_failed(
                            self,
                            provider="digitalocean",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                    action_status = str(action.get("status") or "").lower()
                    if action_status in {"errored", "canceled"}:
                        return _provider_failed(
                            self, provider="digitalocean", state=action_status
                        )
                    if action_status != "completed":
                        return _provider_in_progress(
                            self,
                            provider="digitalocean",
                            state=action_status,
                            operation_id=self.action_id,
                        )
                else:
                    return _provider_http_outcome(
                        self, result, provider="digitalocean"
                    )

            # The action may have completed while the worker was down and before its
            # id was saved. Search by the deterministic name before declaring success.
            params = {"resource_type": resource_type, "per_page": 200, "page": 1}
            snapshots = []
            while True:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/snapshots",
                    headers=client,
                    params=params,
                    verify=True,
                )
                if result.status_code != 200:
                    return _provider_http_outcome(
                        self, result, provider="digitalocean"
                    )
                payload = result.json()
                # An empty DigitalOcean catalog may be encoded as null rather
                # than an empty array. It is still a successful empty page.
                snapshots.extend(payload.get("snapshots") or [])
                total = (payload.get("meta") or {}).get("total", len(snapshots))
                if len(snapshots) >= total:
                    break
                params["page"] += 1
            matches = [
                item for item in snapshots if item.get("name") == self.uuid_str
            ]
            if len(matches) > 1 or (
                matches
                and not _provider_owned(
                    matches[0],
                    marker=self.uuid_str,
                    source_fields=(("resource_id", source_id),),
                )
            ):
                return _provider_failed(
                    self,
                    provider="digitalocean",
                    state="duplicate_matches",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
            if matches:
                return record_snapshot(matches[0])
            return _provider_in_progress(
                self,
                provider="digitalocean",
                state="snapshot_not_visible",
                operation_id=self.action_id,
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

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
            f"is being deleted using connection {self.digitalocean.node.connection.name}"
        )

        try:
            client = self.digitalocean.node.connection.auth_digitalocean.get_client()
            resource_type = (
                "droplet"
                if CoreNode.Type.CLOUD == self.digitalocean.node.type
                else "volume"
            )
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/snapshots/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 404:
                if (self.metadata or {}).get("_provider_ownership_verified"):
                    _record_provider_outcome(
                        self,
                        provider="digitalocean",
                        category="already_absent",
                        operation="delete",
                        provider_status="not_found_after_ownership_proof",
                        resource_id=self.unique_id,
                    )
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                else:
                    _provider_http_outcome(
                        self, result, provider="digitalocean", operation="delete"
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
                self.save()
                return
            if result.status_code != 200:
                _provider_http_outcome(
                    self, result, provider="digitalocean", operation="delete"
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return

            payload = result.json()
            snapshot = payload.get("snapshot", payload)
            if not _provider_owned(
                snapshot,
                resource_id=self.unique_id,
                marker=self.uuid_str,
                source_fields=(("resource_id", self.digitalocean.unique_id),),
            ) or (
                snapshot.get("resource_type")
                and snapshot.get("resource_type") != resource_type
            ):
                _provider_failed(
                    self,
                    provider="digitalocean",
                    state="ownership_mismatch",
                    code="PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return

            metadata = dict(self.metadata or {})
            metadata["_provider_ownership_verified"] = True
            self.metadata = metadata
            self.save(update_fields=["metadata", "modified"])
            result = requests.delete(
                f"{settings.DIGITALOCEAN_API}/v2/snapshots/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code not in {200, 204, 404}:
                _provider_http_outcome(
                    self, result, provider="digitalocean", operation="delete"
                )
                self.status = UtilBackup.Status.DELETE_FAILED
                self.save()
                return
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self,
                provider="digitalocean",
                category="delete_completed",
                operation="delete",
                resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"deleted successfully using connection {self.digitalocean.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="digitalocean", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"could not be deleted using connection {self.digitalocean.node.connection.name}."
            )
        finally:
            self.digitalocean.node.connection.account.create_backup_log(msg, self.digitalocean.node, self)

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

    def poll_status(self):
        """Perform one categorized, ownership-checked UpCloud status check."""
        from ..node.models import CoreNode

        if CoreNode.Type.VOLUME == self.upcloud.node.type:
            try:
                client = self.upcloud.node.connection.auth_upcloud.get_client()
                result = requests.get(
                    f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"},
                )
                if result.status_code == 200:
                    storage = result.json()["storage"]

                    if not _provider_owned(
                        storage,
                        resource_id=self.unique_id,
                        marker=self.uuid_str,
                        source_fields=(("origin", self.upcloud.unique_id),),
                    ):
                        return _provider_failed(
                            self,
                            provider="upcloud",
                            state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )

                    if storage["state"] == "online":
                        self.size_gigabytes = storage["size"]
                        self.status = UtilBackup.Status.COMPLETE
                        self.metadata = storage
                        self.save()
                        _record_provider_outcome(
                            self,
                            provider="upcloud",
                            category="complete",
                            provider_status="online",
                            resource_id=self.unique_id,
                        )
                        return UtilBackup.Status.COMPLETE
                    elif storage["state"] == "error":
                        return _provider_failed(
                            self, provider="upcloud", state="error"
                        )
                    return _provider_in_progress(
                        self,
                        provider="upcloud",
                        state=storage.get("state"),
                        resource_id=self.unique_id,
                    )
                return _provider_http_outcome(
                    self, result, provider="upcloud"
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="upcloud"
                )
        return _provider_failed(
            self, provider="upcloud", state="unsupported_resource"
        )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.upcloud.node

    def soft_delete(self):
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
            f"is being deleted using connection {self.upcloud.node.connection.name}"
        )

        try:
            client = self.upcloud.node.connection.auth_upcloud.get_client()
            if CoreNode.Type.VOLUME == self.upcloud.node.type:
                verification = requests.get(
                    f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"},
                )
                if verification.status_code != 200:
                    _provider_http_outcome(
                        self, verification, provider="upcloud", operation="delete"
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND if verification.status_code == 404 else UtilBackup.Status.DELETE_FAILED
                    self.save()
                    return
                storage = verification.json().get("storage") or {}
                if not _provider_owned(
                    storage,
                    resource_id=self.unique_id,
                    marker=self.uuid_str,
                    source_fields=(("origin", self.upcloud.unique_id),),
                ):
                    _provider_failed(
                        self, provider="upcloud", state="ownership_mismatch",
                        code="PROVIDER_OWNERSHIP_MISMATCH",
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED
                    self.save()
                    return
                result = requests.delete(
                    f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"},
                )
                if result.status_code != 204:
                    _provider_http_outcome(
                        self, result, provider="upcloud", operation="delete"
                    )
                    self.status = UtilBackup.Status.DELETE_FAILED
                    self.save()
                    return
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            _record_provider_outcome(
                self, provider="upcloud", category="delete_completed",
                operation="delete", resource_id=self.unique_id,
            )
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"deleted successfully using connection {self.upcloud.node.connection.name}"
            )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="upcloud", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"could not be deleted using connection {self.upcloud.node.connection.name}."
            )
        finally:
            self.upcloud.node.connection.account.create_backup_log(msg, self.upcloud.node, self)

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
        """Perform one categorized Oracle volume-backup status check."""
        import oci
        from oci.core.models import BootVolumeBackup, VolumeBackup
        from ..node.models import CoreNode

        if CoreNode.Type.VOLUME == self.oracle.node.type:
            try:
                config = self.oracle.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)

                if (self.oracle.metadata or {}).get("_bs_vol_type") == "boot":
                    request = block_storage_client.get_boot_volume_backup(boot_volume_backup_id=self.unique_id)
                    if request.status == 200:
                        if str(getattr(request.data, "id", self.unique_id)) != str(
                            self.unique_id
                        ) or (
                            getattr(request.data, "boot_volume_id", None)
                            and str(request.data.boot_volume_id)
                            != str(self.oracle.unique_id)
                        ):
                            return _provider_failed(
                                self,
                                provider="oracle",
                                state="ownership_mismatch",
                                code="PROVIDER_OWNERSHIP_MISMATCH",
                            )
                        if request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_AVAILABLE:
                            self.size_gigabytes = request.data.size_in_gbs
                            self.status = UtilBackup.Status.COMPLETE
                            self.metadata = {
                                "_bs_name": request.data.display_name,
                                "_bs_size": request.data.size_in_gbs,
                                "_bs_vol_type": "boot",
                            }
                            self.save()
                            _record_provider_outcome(
                                self,
                                provider="oracle",
                                category="complete",
                                provider_status=request.data.lifecycle_state,
                                resource_id=self.unique_id,
                            )
                            return UtilBackup.Status.COMPLETE
                        elif request.data.lifecycle_state in (
                            BootVolumeBackup.LIFECYCLE_STATE_FAULTY,
                            BootVolumeBackup.LIFECYCLE_STATE_TERMINATED,
                            BootVolumeBackup.LIFECYCLE_STATE_TERMINATING,
                        ):
                            return _provider_failed(
                                self,
                                provider="oracle",
                                state=request.data.lifecycle_state,
                            )
                        return _provider_in_progress(
                            self,
                            provider="oracle",
                            state=request.data.lifecycle_state,
                            resource_id=self.unique_id,
                        )
                    return _provider_http_outcome(
                        self, request, provider="oracle"
                    )
                elif (self.oracle.metadata or {}).get("_bs_vol_type") == "block":
                    request = block_storage_client.get_volume_backup(volume_backup_id=self.unique_id)
                    if request.status == 200:
                        if str(getattr(request.data, "id", self.unique_id)) != str(
                            self.unique_id
                        ) or (
                            getattr(request.data, "volume_id", None)
                            and str(request.data.volume_id)
                            != str(self.oracle.unique_id)
                        ):
                            return _provider_failed(
                                self,
                                provider="oracle",
                                state="ownership_mismatch",
                                code="PROVIDER_OWNERSHIP_MISMATCH",
                            )
                        if request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_AVAILABLE:
                            self.size_gigabytes = request.data.size_in_gbs
                            self.status = UtilBackup.Status.COMPLETE
                            self.metadata = {
                                "_bs_name": request.data.display_name,
                                "_bs_size": request.data.size_in_gbs,
                                "_bs_vol_type": "block",
                            }
                            self.save()
                            _record_provider_outcome(
                                self,
                                provider="oracle",
                                category="complete",
                                provider_status=request.data.lifecycle_state,
                                resource_id=self.unique_id,
                            )
                            return UtilBackup.Status.COMPLETE
                        elif request.data.lifecycle_state in (
                            VolumeBackup.LIFECYCLE_STATE_FAULTY,
                            VolumeBackup.LIFECYCLE_STATE_TERMINATED,
                            VolumeBackup.LIFECYCLE_STATE_TERMINATING,
                        ):
                            return _provider_failed(
                                self,
                                provider="oracle",
                                state=request.data.lifecycle_state,
                            )
                        return _provider_in_progress(
                            self,
                            provider="oracle",
                            state=request.data.lifecycle_state,
                            resource_id=self.unique_id,
                        )
                    return _provider_http_outcome(
                        self, request, provider="oracle"
                    )
                return _provider_failed(
                    self,
                    provider="oracle",
                    state="missing_volume_type",
                    code="PROVIDER_MALFORMED_RESPONSE",
                )
            except Exception as error:
                return _provider_exception_outcome(
                    self, error, provider="oracle"
                )
        return _provider_failed(
            self, provider="oracle", state="unsupported_resource"
        )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.oracle.node

    def soft_delete(self):
        import oci
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.oracle.node.name} "
            f"is being deleted using integration {self.oracle.node.connection.name}"
        )

        try:
            if CoreNode.Type.VOLUME == self.oracle.node.type:
                config = self.oracle.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)

                if (self.oracle.metadata or {}).get("_bs_vol_type") == "boot":
                    owned = block_storage_client.get_boot_volume_backup(
                        boot_volume_backup_id=self.unique_id
                    )
                    if (
                        str(getattr(owned.data, "id", "")) != str(self.unique_id)
                        or (
                            getattr(owned.data, "boot_volume_id", None)
                            and str(owned.data.boot_volume_id)
                            != str(self.oracle.unique_id)
                        )
                    ):
                        _provider_failed(
                            self, provider="oracle", state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                        self.status = UtilBackup.Status.DELETE_FAILED
                        self.save()
                        return
                    response = block_storage_client.delete_boot_volume_backup(boot_volume_backup_id=self.unique_id)
                    if response.status == 204:
                        self.status = UtilBackup.Status.DELETE_COMPLETED
                    else:
                        self.status = UtilBackup.Status.DELETE_FAILED
                elif (self.oracle.metadata or {}).get("_bs_vol_type") == "block":
                    owned = block_storage_client.get_volume_backup(
                        volume_backup_id=self.unique_id
                    )
                    if (
                        str(getattr(owned.data, "id", "")) != str(self.unique_id)
                        or (
                            getattr(owned.data, "volume_id", None)
                            and str(owned.data.volume_id)
                            != str(self.oracle.unique_id)
                        )
                    ):
                        _provider_failed(
                            self, provider="oracle", state="ownership_mismatch",
                            code="PROVIDER_OWNERSHIP_MISMATCH",
                        )
                        self.status = UtilBackup.Status.DELETE_FAILED
                        self.save()
                        return
                    response = block_storage_client.delete_volume_backup(volume_backup_id=self.unique_id)
                    if response.status == 204:
                        self.status = UtilBackup.Status.DELETE_COMPLETED
                    else:
                        self.status = UtilBackup.Status.DELETE_FAILED
                self.save()

                if self.status == UtilBackup.Status.DELETE_COMPLETED:
                    _record_provider_outcome(
                        self, provider="oracle", category="delete_completed",
                        operation="delete", resource_id=self.unique_id,
                    )
                else:
                    _provider_http_outcome(
                        self, response, provider="oracle", operation="delete"
                    )

                if self.status == UtilBackup.Status.DELETE_COMPLETED:
                    msg = (
                        f"Backup {self.uuid_str} of node {self.oracle.node.name} "
                        f"deleted successfully using integration {self.oracle.node.connection.name}"
                    )
                else:
                    msg = (
                        f"Invalid response from Oracle API. The backup {self.uuid_str} "
                        f"is marked {self.get_status_display()}. "
                        f"Please check your Oracle Cloud account."
                    )
        except Exception as error:
            _provider_exception_outcome(
                self, error, provider="oracle", operation="delete"
            )
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Invalid response from Oracle API. The backup {self.uuid_str} "
                f"is marked {self.get_status_display()}. "
                "Please check your Oracle Cloud account."
            )
        finally:
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
                        self.metadata = image
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
                        self.metadata = disk
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
        deleted = all(
            stored_website_backup.soft_delete() is not False
            for stored_website_backup in self.stored_website_backups.all()
        )
        if deleted:
            self.status = self.Status.DELETE_COMPLETED
            self.save()
        return deleted

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
        for stored_website_backup in self.stored_website_backups.all():
            try:
                stored_website_backup.status = (
                    CoreWebsiteBackupStoragePoints.Status.CANCELLED
                )
                stored_website_backup.save()
                app.control.revoke(stored_website_backup.celery_task_id, terminate=True)
            except IntegrityError:
                stored_website_backup.delete()
        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

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
        self.save()

        """
        Stop docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )


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

    def save(self, *args, **kwargs):
        required_owner = getattr(self, "_required_upload_lease_owner", "")
        required_token = getattr(self, "_required_upload_lease_token", "")
        if self.pk and required_owner and required_token:
            with transaction.atomic():
                current = self.__class__.objects.select_for_update().only(
                    "upload_lease_owner",
                    "upload_lease_token",
                    "upload_lease_expires_at",
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

    def generate_download_url(self):
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
                        expiration=timedelta(hours=24),
                        method="GET",
                    )
                    return url
                else:
                    return None
            else:
                return None

        elif self.storage.type.code == "azure":
            import time
            import datetime
            from azure.storage.blob import BlobSasPermissions, generate_blob_sas
            from datetime import timedelta

            bucket_name = self.storage.storage_azure.bucket_name

            blob_service_client = self.storage.storage_azure.get_client()

            # Create a SAS token that expires in 1 hour
            sas_expiry = datetime.datetime.utcnow() + timedelta(hours=48)
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
                "GET", self.storage_file_id, 3600 * 24, headers={"content-disposition": "attachment"}, slash_safe=True
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
                Expired=24 * 3600
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
                    s3_client = bounded_boto3_client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_upcloud.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_upcloud.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_upcloud.secret_key, encryption_key),
                        region_name=self.storage.storage_upcloud.endpoint.split(".")[1],
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
                    import hashlib
                    import os
                    if not self.storage.storage_local.no_delete:
                        # storage_file_id is the absolute path written by the local
                        # upload backend; only ever unlink inside the storage root.
                        local_root = os.path.realpath(settings.LOCAL_STORAGE_ROOT)
                        target = os.path.realpath(self.storage_file_id)
                        if target != local_root and not target.startswith(local_root + os.sep):
                            raise ValueError("Local storage delete is outside its configured root.")
                        if os.path.basename(target) != f"{self.backup.uuid_str}.zip":
                            raise ValueError("Local storage object is not owned by this backup.")
                        if os.path.exists(target):
                            expected = self.committed_integrity_identity()
                            if expected is None:
                                raise ValueError(
                                    "Local storage integrity evidence is unavailable; deletion was stopped."
                                )
                            digest = hashlib.sha256()
                            byte_count = 0
                            with open(target, "rb") as local_object:
                                while True:
                                    chunk = local_object.read(1024 * 1024)
                                    if not chunk:
                                        break
                                    digest.update(chunk)
                                    byte_count += len(chunk)
                            if (
                                digest.hexdigest() != expected["sha256"]
                                or byte_count != expected["size_bytes"]
                            ):
                                raise ValueError(
                                    "Local storage object integrity does not match this backup."
                                )
                            os.remove(target)

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


class CoreWordPressBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    wordpress = models.ForeignKey(
        "CoreWordPress", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="wordpress_backups",
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
        related_name="wordpress_backups",
        through="CoreWordPressBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_wordpress_backup"

    def soft_delete(self):
        deleted = all(
            stored_wordpress_backup.soft_delete() is not False
            for stored_wordpress_backup in self.stored_wordpress_backups.all()
        )
        if deleted:
            self.status = self.Status.DELETE_COMPLETED
            self.save()
        return deleted

    def all_storage_points_uploaded(self):
        return self.stored_wordpress_backups.all().count() == self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    @property
    def node(self):
        return self.wordpress.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_wordpress_backup in self.stored_wordpress_backups.all():
            stored_wordpress_backup.status = (
                CoreWordPressBackupStoragePoints.Status.CANCELLED
            )
            stored_wordpress_backup.save()
            app.control.revoke(stored_wordpress_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
        )

        """
        Reset the node status
        """
        self.wordpress.node.backup_complete_reset()
        self.save()

        """
        Stop main docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Stop upload docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Delete files from wordpress
        """
        client = self.wordpress.node.connection.auth_wordpress.get_client()
        auth = self.wordpress.node.connection.auth_wordpress.get_auth()
        try:
            result = requests.get(
                f"{self.wordpress.node.connection.auth_wordpress.url}"
                f"/?rest_route=/backupsheep/updraftplus/files&backup_uuid={self.uuid_str}"
                f"&key={self.wordpress.node.connection.auth_wordpress.key}"
                f"&t={time.time()}",
                auth=auth,
                headers=client,
                verify=True,
                timeout=180,
            )
            if result.status_code == 200:
                try:
                    backup_files = result.json().get("files", [])
                    for backup_file in backup_files:
                        # delete the downloaded file from WordPress
                        r_delete = requests.get(
                            f"{self.wordpress.node.connection.auth_wordpress.url}"
                            f"/?rest_route=/backupsheep/updraftplus/delete&backup_file={backup_file}"
                            f"&backup_uuid={self.uuid_str}"
                            f"&key={self.wordpress.node.connection.auth_wordpress.key}"
                            f"&t={time.time()}",
                            allow_redirects=True,
                            auth=auth,
                            headers=client,
                            verify=True
                        )
                        if r_delete.status_code == 200:
                            if r_delete.json().get("deleted"):
                                msg = f"Cancelled backup - Deleted file from WordPress: {backup_file}"
                                self.wordpress.node.connection.account.create_backup_log(msg, self.wordpress.node, self)
                except Exception as e:
                    pass
        except Exception as e:
            pass


class CoreWordPressBackupStoragePoints(BaseBackupStoragePoints):
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
        CoreWordPressBackup,
        on_delete=models.CASCADE,
        related_name="stored_wordpress_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_wordpress_backups"
    )

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_wordpress_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage"],
                name="unique_stored_wordpress_backups",
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
        deleted = all(
            stored_basecamp_backup.soft_delete() is not False
            for stored_basecamp_backup in self.stored_basecamp_backups.all()
        )
        if deleted:
            self.status = self.Status.DELETE_COMPLETED
            self.save()
        return deleted

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
        for stored_basecamp_backup in self.stored_basecamp_backups.all():
            stored_basecamp_backup.status = CoreBasecampBackupStoragePoints.Status.CANCELLED
            stored_basecamp_backup.save()
            app.control.revoke(stored_basecamp_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

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
        self.save()

        """
        Stop main docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Stop upload docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )


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
        deleted = all(
            stored_database_backup.soft_delete() is not False
            for stored_database_backup in self.stored_database_backups.all()
        )
        if deleted:
            self.status = self.Status.DELETE_COMPLETED
            self.save()
        return deleted

    @property
    def node(self):
        return self.database.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_database_backup in self.stored_database_backups.all():
            stored_database_backup.status = (
                CoreDatabaseBackupStoragePoints.Status.CANCELLED
            )
            stored_database_backup.save()
            app.control.revoke(stored_database_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

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
        self.save()


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
            self._aws_native_source(client, witness)

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
                    self.metadata = snapshot
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
                        self.metadata = snapshot
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
                        self.metadata = snapshot
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

    @staticmethod
    def _rds_region(auth):
        region = str(getattr(getattr(auth, "region", None), "code", "") or "")
        if not region:
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
    def _rds_witness(cls, *, identifier, source_id, account_id, region):
        values = {
            "snapshot_identifier": str(identifier or ""),
            "source_db_instance_identifier": str(source_id or ""),
            "account_id": str(account_id or ""),
            "region": str(region or ""),
            "snapshot_type": cls._RDS_SNAPSHOT_TYPE,
        }
        if not values["snapshot_identifier"] or not values["source_db_instance_identifier"]:
            raise RDSOwnershipError("The RDS request identity is incomplete.")
        return values

    def _rds_execution_metadata(self):
        state = self.get_execution_state(create=False)
        metadata = dict(state.provider_metadata or {}) if state is not None else {}
        request = metadata.get("rds_request")
        return state, dict(request or {}) if isinstance(request, dict) else {}

    def _rds_persist_witness(self, witness, *, lease_owner=None, lease_token=None):
        state = self.record_provider_reference(
            idempotency_key=witness["snapshot_identifier"],
            provider_status="reconciliation_required",
            metadata={"rds_request": dict(witness)},
            lease_owner=lease_owner,
            lease_token=lease_token,
        )
        if state is None:
            raise RDSLeaseLost("The RDS worker lost its execution lease.")
        return state

    @staticmethod
    def _rds_list_snapshots(client, identifier):
        """Iterate every RDS response page, guarding repeated markers."""
        marker = None
        seen_markers = set()
        snapshots = []
        while True:
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
        return (
            arn_identity["snapshot_identifier"] == witness["snapshot_identifier"]
            and arn_identity["account_id"] == witness["account_id"]
            and arn_identity["region"] == witness["region"]
        )

    @classmethod
    def _rds_find_owned_snapshot(cls, snapshots, witness):
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
        if any(not cls._rds_snapshot_owned(snapshot, witness) for snapshot in exact):
            raise RDSOwnershipError("RDS snapshot ownership verification failed.")
        if len(exact) > 1:
            raise RDSDuplicateMatch("Multiple exact RDS snapshots matched the request.")
        return exact[0]

    def _rds_current_witness(self, auth, *, identifier=None, lease_owner=None, lease_token=None):
        state, stored = self._rds_execution_metadata()
        expected_identifier = str(identifier or self.unique_id or self.uuid_str)
        region = self._rds_region(auth)
        source_id = str(self.aws_rds.unique_id or "")
        if stored:
            if stored.get("snapshot_identifier") not in (None, expected_identifier):
                raise RDSOwnershipError("The durable RDS request identity changed.")
            if stored.get("source_db_instance_identifier") not in (None, source_id):
                raise RDSOwnershipError("The durable RDS source identity changed.")
            stored_region = str(stored.get("region") or "")
            if stored_region and stored_region != region:
                raise RDSOwnershipError("The durable RDS region identity changed.")
        account_id = str(stored.get("account_id") or "")
        if account_id == "pending":
            account_id = ""
        if not account_id:
            account_id = self._rds_account_id(auth)
        witness = self._rds_witness(
            identifier=expected_identifier,
            source_id=source_id,
            account_id=account_id,
            region=region,
        )
        if (
            not stored
            or any(str(stored.get(key) or "") != str(value) for key, value in witness.items())
        ):
            self._rds_persist_witness(
                witness, lease_owner=lease_owner, lease_token=lease_token
            )
        return witness

    def _rds_adopt_snapshot(
        self, snapshot, witness, *, lease_owner=None, lease_token=None
    ):
        if not self._rds_snapshot_owned(snapshot, witness):
            raise RDSOwnershipError("RDS snapshot ownership verification failed.")
        normalized = _rds_json(snapshot)
        with transaction.atomic():
            fresh = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(fresh)
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, now=timezone.now(), require_live=True
            ):
                raise RDSLeaseLost("The RDS worker lost its execution lease.")
            fresh.unique_id = witness["snapshot_identifier"]
            fresh.region = witness["region"]
            fresh.size_gigabytes = normalized.get("AllocatedStorage")
            fresh.metadata = normalized
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
        self.region = witness["region"]
        self.size_gigabytes = normalized.get("AllocatedStorage")
        self.metadata = normalized
        state = self.record_provider_reference(
            idempotency_key=witness["snapshot_identifier"],
            resource_id=witness["snapshot_identifier"],
            provider_status=str(normalized.get("Status") or "creating"),
            metadata={
                "rds_request": dict(witness),
                "rds_snapshot": {
                    "snapshot_identifier": witness["snapshot_identifier"],
                    "status": str(normalized.get("Status") or "creating"),
                },
            },
            lease_owner=lease_owner,
            lease_token=lease_token,
        )
        if state is None:
            raise RDSLeaseLost("The RDS worker lost its execution lease.")
        self.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
            reason="rds_snapshot_adopted",
            metadata={"snapshot_identifier": witness["snapshot_identifier"]},
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
            if task_id and state.lease_owner != str(task_id):
                return None
            return state.lease_owner, str(state.lease_token), False
        owner = str(task_id or "rds-create-" + uuid.uuid4().hex)
        state = self.claim_execution(
            lease_owner=owner,
            phase="create",
            lease_seconds=max(1, int(getattr(settings, "BACKUP_CREATE_LEASE_SECONDS", 3600))),
            respect_retry_at=False,
        )
        if state is None:
            return None
        return owner, str(state.lease_token), True

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
            return "already_exists", "PROVIDER_CREATE_OUTCOME_UNKNOWN", UtilBackup.Status.IN_PROGRESS, _provider_retry_at(headers)
        if provider_code in _PROVIDER_AUTH_ERROR_CODES or status_code in _PROVIDER_AUTH_HTTP_CODES:
            return "auth_failed", "PROVIDER_AUTH_FAILED", UtilBackup.Status.FAILED, None
        if provider_code in _PROVIDER_RATE_LIMIT_ERROR_CODES or status_code == 429:
            return "rate_limited", "PROVIDER_RATE_LIMIT", UtilBackup.Status.IN_PROGRESS, _provider_retry_at(headers)
        if provider_code in _PROVIDER_TRANSIENT_ERROR_CODES or status_code in _PROVIDER_TRANSIENT_HTTP_CODES or status_code and status_code >= 500:
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", UtilBackup.Status.IN_PROGRESS, _provider_retry_at(headers)
        if isinstance(error, (requests.exceptions.Timeout, TimeoutError)):
            return "timeout", "PROVIDER_TIMEOUT", UtilBackup.Status.IN_PROGRESS, _provider_retry_at()
        if isinstance(error, requests.exceptions.ConnectionError):
            return "transient_outage", "PROVIDER_TRANSIENT_OUTAGE", UtilBackup.Status.IN_PROGRESS, _provider_retry_at()
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
            )
            self._rds_persist_witness(provisional, lease_owner=owner, lease_token=token)
            account_id = self._rds_account_id(auth)
            witness = self._rds_witness(
                identifier=identifier,
                source_id=self.aws_rds.unique_id,
                account_id=account_id,
                region=region,
            )
            self._rds_persist_witness(witness, lease_owner=owner, lease_token=token)
            try:
                existing = self._rds_find_owned_snapshot(
                    self._rds_list_snapshots(client, identifier), witness
                )
            except Exception as error:
                if not _rds_not_found(error):
                    raise
                existing = None
            if existing is not None:
                self._rds_adopt_snapshot(
                    existing, witness, lease_owner=owner, lease_token=token
                )
                completed = True
                return self
            response = client.create_db_snapshot(
                DBSnapshotIdentifier=identifier,
                DBInstanceIdentifier=self.aws_rds.unique_id,
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("DBSnapshot"), dict
            ):
                raise RDSMalformedResponse("RDS did not return a snapshot object.")
            snapshot = response["DBSnapshot"]
            if not self._rds_snapshot_owned(snapshot, witness):
                raise RDSOwnershipError("RDS create response ownership failed.")
            self._rds_adopt_snapshot(
                snapshot, witness, lease_owner=owner, lease_token=token
            )
            completed = True
            return self
        except (RDSDuplicateMatch, RDSOwnershipError, RDSMalformedResponse) as error:
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
                    fresh.status = UtilBackup.Status.FAILED
                    fresh.save(update_fields=["status", "modified"])
                completed = True
                return self
            # A timeout, throttle, or outage after the provider request may mean
            # AWS accepted it. Keep the witness and lease, and force reconciliation
            # before any future create attempt.
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
                metadata={"provider": self._RDS_PROVIDER},
                lease_owner=owner,
                lease_token=token,
            )
            raise
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
            try:
                snapshots = self._rds_list_snapshots(
                    client, witness["snapshot_identifier"]
                )
            except ClientError as error:
                if _rds_not_found(error):
                    return _provider_failed(
                        self,
                        provider=self._RDS_PROVIDER,
                        state="not_found",
                        code="PROVIDER_NOT_FOUND",
                    )
                raise
            snapshot = self._rds_find_owned_snapshot(snapshots, witness)
            if snapshot is None:
                return _provider_failed(
                    self,
                    provider=self._RDS_PROVIDER,
                    state="not_found",
                    code="PROVIDER_NOT_FOUND",
                )
            normalized = _rds_json(snapshot)
            self._rds_adopt_snapshot(normalized, witness)
            state = str(normalized.get("Status") or "").lower()
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
            return _provider_exception_outcome(
                self, error, provider="aws_rds"
            )

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.aws_rds.node

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
                self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_COMPLETED)
                completed = True
                return True
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
            snapshot = self._rds_find_owned_snapshot(snapshots, witness)
            if snapshot is None:
                raise RDSOwnershipError("RDS deletion target was not found in the full listing.")
            if delete_started:
                # The request may already have been accepted. Never issue a second
                # delete while the exact owned object remains visible.
                self._rds_set_delete_status(owner, token, UtilBackup.Status.DELETE_IN_PROGRESS)
                self._rds_record_fenced_outcome(
                    owner=owner,
                    token=token,
                    category="reconciliation_required",
                    error_code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                    operation="delete",
                    provider_status=str(snapshot.get("Status") or "present"),
                )
                self.set_reconciliation_state(
                    reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                    reason="rds_delete_outcome_unknown",
                    metadata={"provider": self._RDS_PROVIDER},
                    lease_owner=owner,
                    lease_token=token,
                )
                return False
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
                    "phase": "delete_requested",
                },
            )
            try:
                client.delete_db_snapshot(
                    DBSnapshotIdentifier=witness["snapshot_identifier"]
                )
            except Exception as error:
                if not _rds_not_found(error):
                    raise
                # A 404 after the exact proof and delete_started checkpoint is a
                # successful lost-response adoption, not a new deletion attempt.
                self._rds_checkpoint_delete(
                    owner,
                    token,
                    {"delete_completed": True, "phase": "complete"},
                )
            else:
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
            if result == UtilBackup.Status.IN_PROGRESS:
                self.set_reconciliation_state(
                    reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
                    reason="rds_delete_outcome_unknown",
                    metadata={"provider": self._RDS_PROVIDER},
                    lease_owner=owner,
                    lease_token=token,
                )
            self._rds_set_delete_status(
                owner,
                token,
                UtilBackup.Status.DELETE_IN_PROGRESS
                if result == UtilBackup.Status.IN_PROGRESS
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
            self.metadata = {
                "source_database_id": self.vultr_database.unique_id,
                "provider_backup": record,
            }
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
            self.metadata = {
                "source_database_id": self.vultr_database.unique_id,
                "error": error.category,
                "status_code": error.status_code,
            }
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
