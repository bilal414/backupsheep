import subprocess
import time
from datetime import timedelta
from billiard.exceptions import SoftTimeLimitExceeded
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import ClientError
from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from sentry_sdk import capture_exception, capture_message

from apps._tasks.diagnostics import capture_backup_diagnostic

from apps._tasks.exceptions import (
    TaskParamsNotProvided,
    NodeGoogleDriveNotEnoughStorageError,
    NodeDropboxNotEnoughStorageError,
    NodeDropboxFileIDMissingError,
    NodeAWSS3UploadFailedError,
    NodeDropboxUploadFailedError,
    NodeBackupSheepUploadFailedError,
    NodeDigitalOceanSpacesBucketDeletedError,
    NodeDropboxTokenExpiredError,
    NodeDigitalOceanSpacesNoSuchBucketError,
    StorageFilebaseQuotaExceededError,
)
from apps._tasks.integration.storage.alibaba import storage_alibaba
from apps._tasks.integration.storage.aws_s3 import (
    storage_aws_s3,
)
from apps._tasks.integration.storage.azure import storage_azure
from apps._tasks.integration.storage.backblaze_b2 import (
    storage_backblaze_b2,
)
from apps._tasks.integration.storage.cloudflare import storage_cloudflare
from apps._tasks.integration.storage.do_spaces import (
    storage_do_spaces,
    storage_do_spaces_delete,
)
from apps._tasks.integration.storage.dropbox import (
    storage_dropbox,
)
from apps._tasks.integration.storage.exoscale import storage_exoscale
from apps._tasks.integration.storage.google_cloud import storage_google_cloud
from apps._tasks.integration.storage.ibm import storage_ibm
from apps._tasks.integration.storage.idrive import storage_idrive
from apps._tasks.integration.storage.ionos import storage_ionos
from apps._tasks.integration.storage.leviia import storage_leviia
from apps._tasks.integration.storage.onedrive import storage_onedrive
from apps._tasks.integration.storage.oracle import storage_oracle
from apps._tasks.integration.storage.filebase import storage_filebase
from apps._tasks.integration.storage.google_drive import (
    storage_google_drive,
    storage_google_drive_delete,
)
from apps._tasks.integration.storage.linode import storage_linode
from apps._tasks.integration.storage.local import storage_local
from apps._tasks.integration.storage.pcloud import storage_pcloud
from apps._tasks.integration.storage.rackcorp import storage_rackcorp
from apps._tasks.integration.storage.scaleway import storage_scaleway
from apps._tasks.integration.storage.tencent import storage_tencent
from apps._tasks.integration.storage.upcloud import storage_upcloud
from apps._tasks.integration.storage.vultr import storage_vultr
from apps._tasks.integration.storage.wasabi import (
    storage_wasabi,
    storage_wasabi_delete,
)
from apps._tasks.execution import verify_and_commit_source_artifact
from apps._tasks.integration.storage.lease import (
    DurableStorageUploadLease,
    StorageCleanupNotEligible,
    StorageUploadAlreadyComplete,
    StorageUploadLeaseBusy,
    StorageUploadLeaseLost,
)
from apps._tasks.integration.storage.s3_verified import (
    S3MultipartCleanupNotEligible,
    S3MultipartCleanupPending,
    S3ObjectIntegrityError,
    S3UploadInventoryFailure,
    S3UploadOutcomePending,
    S3UploadReconciliationRequired,
    S3UploadStalled,
    cleanup_owned_multipart_upload,
)
from apps._tasks.integration.storage.s3_cleanup import (
    UnsupportedMultipartCleanupBackend,
    has_owned_multipart_cleanup_candidate,
    multipart_cleanup_context,
    multipart_cleanup_metadata_keys,
)
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
    CoreWordPressBackup, CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints,
    CoreWordPressBackupStoragePoints, CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    StoragePointLeaseLostError,
)
from apps.console.node.models import CoreNode
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup


class UnsupportedStorageBackend(RuntimeError):
    pass


class SourceArtifactInvalid(RuntimeError):
    pass


def _mark_storage_upload_started(backup):
    """Move a source-ready parent into upload only after a point is claimed.

    The conditional update preserves terminal decisions and makes parallel point
    claims idempotent.  It deliberately does not touch the execution lease: the
    source worker may still be releasing its fenced ``source_dispatch`` lease while
    a fast storage worker starts.
    """
    updated = backup.__class__.objects.filter(
        pk=backup.pk,
        status__in=(
            UtilBackup.Status.DOWNLOAD_COMPLETE,
            UtilBackup.Status.UPLOAD_READY,
        ),
    ).update(
        status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
        modified=timezone.now(),
    )
    if updated:
        backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
    return bool(updated)


_STORAGE_AUTH_CODES = {
    "AccessDenied",
    "ExpiredToken",
    "InvalidAccessKeyId",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "Unauthorized",
}
_STORAGE_RATE_LIMIT_CODES = {
    "RequestLimitExceeded",
    "SlowDown",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
}
_STORAGE_NOT_FOUND_CODES = {"404", "NoSuchBucket", "NoSuchKey", "NotFound"}

_STORAGE_POINT_MODELS = {
    "website": CoreWebsiteBackupStoragePoints,
    "database": CoreDatabaseBackupStoragePoints,
    "wordpress": CoreWordPressBackupStoragePoints,
    "basecamp": CoreBasecampBackupStoragePoints,
}
_STORAGE_POINT_MODEL_KEYS = {
    model: key for key, model in _STORAGE_POINT_MODELS.items()
}


def _terminal_cleanup_statuses(model):
    names = (
        "UPLOAD_FAILED",
        "UPLOAD_FAILED_STORAGE_LIMIT",
        "UPLOAD_FAILED_FILE_NOT_FOUND",
        "UPLOAD_TIME_LIMIT_REACHED",
        "STORAGE_VALIDATION_FAILED",
        "CANCELLED",
    )
    return [
        value
        for value in (getattr(model.Status, name, None) for name in names)
        if value is not None
    ]


def _multipart_cleanup_candidate_query():
    query = Q(pk__in=[])
    for metadata_key in multipart_cleanup_metadata_keys():
        proof_path = (
            f"metadata__{metadata_key}__multipart__creation_proof__version"
        )
        cleanup_phase_path = (
            f"metadata__{metadata_key}__multipart_cleanup__phase"
        )
        query |= Q(**{proof_path: 1}) & (
            Q(**{f"{cleanup_phase_path}__isnull": True})
            | ~Q(**{f"{cleanup_phase_path}__in": ["complete", "abort_rejected"]})
        )
    return query


def _schedule_owned_multipart_cleanup(stored_backup):
    model_key = _STORAGE_POINT_MODEL_KEYS.get(stored_backup.__class__)
    if not model_key or not has_owned_multipart_cleanup_candidate(stored_backup):
        return False
    storage_cleanup_owned_multipart.apply_async(
        args=[model_key, stored_backup.pk]
    )
    return True


def _client_error_code(error):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ClientError):
            return str((current.response.get("Error") or {}).get("Code") or "")
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return ""


def _caused_by(error, exception_types):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, exception_types):
            return True
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return False


def _declared_retry_after(error):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "retry_after", None)
        try:
            if value is not None:
                return max(1, min(int(value), 86400))
        except (TypeError, ValueError):
            pass
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return None


def _declared_error_code(error):
    current = error
    seen = set()
    fallback = ""
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "error_code", None) or getattr(
            current, "code", None
        )
        if isinstance(value, str) and value:
            if isinstance(current, S3UploadInventoryFailure):
                return value.upper()
            if not fallback:
                fallback = value.upper()
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return fallback


def _chain_has_class_name(error, class_name):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if type(current).__name__ == class_name:
            return True
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return False


def _storage_error_outcome(error, point):
    """Map an exception to a safe, stable status without persisting its text."""
    quota_errors = (
        NodeGoogleDriveNotEnoughStorageError,
        NodeDropboxNotEnoughStorageError,
        StorageFilebaseQuotaExceededError,
    )
    missing_errors = (
        NodeDigitalOceanSpacesBucketDeletedError,
        NodeDigitalOceanSpacesNoSuchBucketError,
        NodeDropboxFileIDMissingError,
    )
    if isinstance(error, quota_errors):
        return (
            "STORAGE_QUOTA_EXCEEDED",
            "The destination does not have enough available storage capacity.",
            point.Status.UPLOAD_FAILED_STORAGE_LIMIT,
            False,
        )
    if isinstance(error, NodeDropboxTokenExpiredError):
        return (
            "STORAGE_AUTH_FAILED",
            "The storage destination rejected its configured credentials.",
            point.Status.UPLOAD_FAILED,
            False,
        )
    if _caused_by(error, (FileNotFoundError,)):
        return (
            "SOURCE_ARTIFACT_MISSING",
            "The committed local backup artifact is no longer available.",
            point.Status.UPLOAD_FAILED_FILE_NOT_FOUND,
            False,
        )
    if isinstance(error, missing_errors):
        return (
            "STORAGE_DESTINATION_NOT_FOUND",
            "The configured storage destination or object was not found.",
            point.Status.UPLOAD_FAILED,
            False,
        )
    if _caused_by(error, (S3ObjectIntegrityError, SourceArtifactInvalid)) or (
        _chain_has_class_name(error, "_LocalStorageIntegrityError")
    ):
        return (
            "STORAGE_INTEGRITY_FAILED",
            "The uploaded object failed integrity verification.",
            point.Status.STORAGE_VALIDATION_FAILED,
            False,
        )
    if _caused_by(error, (S3UploadStalled,)):
        return (
            "STORAGE_STALLED",
            "The storage upload made no provider-visible progress and will resume "
            "automatically from its durable checkpoint.",
            point.Status.UPLOAD_RETRY,
            True,
        )
    if _caused_by(error, (S3UploadOutcomePending,)):
        return (
            "STORAGE_RECONCILIATION_PENDING",
            "The provider upload outcome is pending visibility; verification will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        )
    if _caused_by(error, (S3UploadReconciliationRequired,)):
        return (
            "STORAGE_RECONCILIATION_REQUIRED",
            "The provider returned ambiguous upload state; automatic writes were stopped safely.",
            point.Status.STORAGE_VALIDATION_FAILED,
            False,
        )
    if isinstance(error, UnsupportedStorageBackend):
        return (
            "STORAGE_BACKEND_UNSUPPORTED",
            "This storage backend is not supported by the current worker.",
            point.Status.UPLOAD_FAILED,
            False,
        )
    if isinstance(error, SoftTimeLimitExceeded):
        return (
            "STORAGE_TIMEOUT",
            "The storage operation timed out and will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        )

    declared_code = _declared_error_code(error)
    declared_outcomes = {
        "STORAGE_AUTH_FAILED": (
            "STORAGE_AUTH_FAILED",
            "The storage destination rejected its configured credentials.",
            point.Status.UPLOAD_FAILED,
            False,
        ),
        "STORAGE_DESTINATION_NOT_FOUND": (
            "STORAGE_DESTINATION_NOT_FOUND",
            "The configured storage destination or object was not found.",
            point.Status.UPLOAD_FAILED,
            False,
        ),
        "STORAGE_RATE_LIMITED": (
            "STORAGE_RATE_LIMITED",
            "The storage provider rate limit was reached; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "PROVIDER_TIMEOUT": (
            "STORAGE_TIMEOUT",
            "The storage operation timed out and will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "STORAGE_TIMEOUT": (
            "STORAGE_TIMEOUT",
            "The storage operation timed out and will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "STORAGE_STALLED": (
            "STORAGE_STALLED",
            "The storage upload made no provider-visible progress and will resume "
            "automatically from its durable checkpoint.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "PROVIDER_TRANSIENT_FAILURE": (
            "STORAGE_TRANSIENT_FAILURE",
            "The storage provider could not complete the operation; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "STORAGE_TRANSIENT_FAILURE": (
            "STORAGE_TRANSIENT_FAILURE",
            "The storage provider could not complete the operation; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "ARTIFACT_PERSISTENCE_FAILED": (
            "STORAGE_TRANSIENT_FAILURE",
            "Verified storage evidence could not be persisted; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "STATE_PERSISTENCE_FAILED": (
            "STORAGE_TRANSIENT_FAILURE",
            "Storage progress could not be persisted; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        ),
        "STREAMING_VERIFICATION_UNAVAILABLE": (
            "STORAGE_BACKEND_UNSUPPORTED",
            "This storage client cannot safely stream the object for integrity verification.",
            point.Status.STORAGE_VALIDATION_FAILED,
            False,
        ),
        "PROVIDER_MALFORMED_RESPONSE": (
            "STORAGE_RECONCILIATION_REQUIRED",
            "The provider returned malformed upload state; automatic writes were stopped safely.",
            point.Status.STORAGE_VALIDATION_FAILED,
            False,
        ),
        "SESSION_STATE_UNAVAILABLE": (
            "STORAGE_RECONCILIATION_REQUIRED",
            "Resumable upload state could not be protected; automatic writes were stopped safely.",
            point.Status.STORAGE_VALIDATION_FAILED,
            False,
        ),
    }
    if declared_code in declared_outcomes:
        return declared_outcomes[declared_code]

    provider_code = _client_error_code(error)
    if provider_code in _STORAGE_AUTH_CODES:
        return (
            "STORAGE_AUTH_FAILED",
            "The storage destination rejected its configured credentials.",
            point.Status.UPLOAD_FAILED,
            False,
        )
    if provider_code in _STORAGE_NOT_FOUND_CODES:
        return (
            "STORAGE_DESTINATION_NOT_FOUND",
            "The configured storage destination or object was not found.",
            point.Status.UPLOAD_FAILED,
            False,
        )
    if provider_code in _STORAGE_RATE_LIMIT_CODES:
        return (
            "STORAGE_RATE_LIMITED",
            "The storage provider rate limit was reached; upload will resume automatically.",
            point.Status.UPLOAD_RETRY,
            True,
        )
    return (
        "STORAGE_TRANSIENT_FAILURE",
        "The storage provider could not complete the operation; upload will resume automatically.",
        point.Status.UPLOAD_RETRY,
        True,
    )


@current_app.task(
    name="storage_upload",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=96,
    time_limit=(48 * 3600),
    soft_time_limit=(48 * 3600),
)
def storage_upload(self, node_id, backup_id, stored_backup_id):
    node = CoreNode.objects.get(id=node_id)
    attempt_no = self.request.retries + 1
    cleanup_after_release = False

    if node.type == CoreNode.Type.WEBSITE:
        backup = CoreWebsiteBackup.objects.get(id=backup_id)
        stored_backup = backup.stored_website_backups.get(id=stored_backup_id)
    elif node.type == CoreNode.Type.DATABASE:
        backup = CoreDatabaseBackup.objects.get(id=backup_id)
        stored_backup = backup.stored_database_backups.get(id=stored_backup_id)
    elif node.type == CoreNode.Type.SAAS:
        if node.connection.integration.code == "wordpress":
            backup = CoreWordPressBackup.objects.get(id=backup_id)
            stored_backup = backup.stored_wordpress_backups.get(id=stored_backup_id)
        elif node.connection.integration.code == "basecamp":
            backup = CoreBasecampBackup.objects.get(id=backup_id)
            stored_backup = backup.stored_basecamp_backups.get(id=stored_backup_id)
        else:
            raise TaskParamsNotProvided()
    else:
        raise TaskParamsNotProvided()

    # Celery delivery is not execution ownership.  Claim a renewable DB lease and
    # bind its random fence to every adapter save before touching a destination.
    lease = DurableStorageUploadLease(
        stored_backup,
        task_id=self.request.id,
        worker_name=getattr(self.request, "hostname", ""),
    )
    try:
        stored_backup = lease.claim()
    except StorageUploadAlreadyComplete:
        return
    except StorageUploadLeaseBusy as error:
        raise self.retry(
            countdown=error.retry_after,
            max_retries=2880,
        )

    _mark_storage_upload_started(backup)

    log_file_path = f"_storage/{backup.uuid_str}.log"
    try:
        log_file = open(log_file_path, "a+")
    except Exception:
        lease.release()
        raise

    storage_type_name = f"Storage ({stored_backup.storage.type.name})"
    log_file.write(f"{storage_type_name}: Starting Upload \n")
    log_file.write(f"{storage_type_name}: Attempt Number: {attempt_no} \n")
    log_file.write(f"{storage_type_name}: {stored_backup.storage.name} \n")

    try:
        # A destination may only upload the immutable source identity committed by
        # the dump worker.  This catches disk corruption and stale-file reuse before
        # a provider receives any bytes.
        try:
            verify_and_commit_source_artifact(backup)
        except FileNotFoundError:
            raise
        except Exception as error:
            raise SourceArtifactInvalid(
                "The committed source artifact failed verification."
            ) from error

        if stored_backup.storage.type.code == "dropbox":
            storage_dropbox(stored_backup)
        elif stored_backup.storage.type.code == "google_drive":
            storage_google_drive(stored_backup)
        elif stored_backup.storage.type.code == "aws_s3":
            storage_aws_s3(stored_backup)
        elif stored_backup.storage.type.code == "wasabi":
            storage_wasabi(stored_backup)
        elif stored_backup.storage.type.code == "do_spaces":
            storage_do_spaces(stored_backup)
        elif stored_backup.storage.type.code == "filebase":
            storage_filebase(stored_backup)
        elif stored_backup.storage.type.code == "backblaze_b2":
            storage_backblaze_b2(stored_backup)
        elif stored_backup.storage.type.code == "linode":
            storage_linode(stored_backup)
        elif stored_backup.storage.type.code == "vultr":
            storage_vultr(stored_backup)
        elif stored_backup.storage.type.code == "upcloud":
            storage_upcloud(stored_backup)
        elif stored_backup.storage.type.code == "exoscale":
            storage_exoscale(stored_backup)
        elif stored_backup.storage.type.code == "oracle":
            storage_oracle(stored_backup)
        elif stored_backup.storage.type.code == "scaleway":
            storage_scaleway(stored_backup)
        elif stored_backup.storage.type.code == "pcloud":
            storage_pcloud(stored_backup)
        elif stored_backup.storage.type.code == "onedrive":
            storage_onedrive(stored_backup)
        elif stored_backup.storage.type.code == "cloudflare":
            storage_cloudflare(stored_backup)
        elif stored_backup.storage.type.code == "google_cloud":
            storage_google_cloud(stored_backup)
        elif stored_backup.storage.type.code == "azure":
            storage_azure(stored_backup)
        elif stored_backup.storage.type.code == "leviia":
            storage_leviia(stored_backup)
        elif stored_backup.storage.type.code == "idrive":
            storage_idrive(stored_backup)
        elif stored_backup.storage.type.code == "ionos":
            storage_ionos(stored_backup)
        elif stored_backup.storage.type.code == "alibaba":
            storage_alibaba(stored_backup)
        elif stored_backup.storage.type.code == "tencent":
            storage_tencent(stored_backup)
        elif stored_backup.storage.type.code == "rackcorp":
            storage_rackcorp(stored_backup)
        elif stored_backup.storage.type.code == "ibm":
            storage_ibm(stored_backup)
        elif stored_backup.storage.type.code == "local":
            storage_local(stored_backup)
        else:
            raise UnsupportedStorageBackend()

        lease.ensure_owned()

        # The backend sets the storage point to UPLOAD_COMPLETE on success (or a
        # failure status / raises). Backup-level completion (status, notification,
        # retention) is handled exactly once by the finalize_backup chord callback
        # after every upload finishes.
        log_file.write(f"{storage_type_name}: {stored_backup.get_status_display()} \n")

    except (StorageUploadLeaseLost, StoragePointLeaseLostError) as error:
        # A replacement worker may already be active.  Never let this stale
        # delivery overwrite its state, even with a failure status.
        capture_exception(error)
        raise self.retry(countdown=30, max_retries=2880)
    except Exception as error:
        code, message, status, retryable = _storage_error_outcome(
            error, stored_backup
        )
        capture_backup_diagnostic(
            error,
            backup,
            stage="storage_uploading",
            code=code,
        )
        stored_backup.last_error_code = code
        stored_backup.last_error_message = message
        stored_backup.status = status
        stored_backup.save(
            update_fields=[
                "last_error_code",
                "last_error_message",
                "status",
                "modified",
            ]
        )
        cleanup_after_release = (
            not retryable
            and has_owned_multipart_cleanup_candidate(stored_backup)
        )
        retry_after = None
        retry_at = None
        if retryable:
            retry_after = _declared_retry_after(error) or 900
            retry_at = timezone.now() + timedelta(seconds=retry_after)
        backup.record_execution_error(
            code=code,
            message=message,
            retryable=retryable,
            retry_at=retry_at,
            stage="storage_uploading",
        )
        if attempt_no <= 3:
            node.notify_upload_fail(
                error,
                backup,
                stored_backup.storage,
                error_code=code,
            )
        node.connection.account.create_storage_log(
            message, node, backup, stored_backup.storage
        )
        log_file.write(f"Error [{code}]: {message}\n")
        if retryable:
            try:
                raise self.retry(countdown=retry_after)
            except MaxRetriesExceededError:
                stored_backup.status = stored_backup.Status.UPLOAD_FAILED
                stored_backup.last_error_code = "STORAGE_RETRIES_EXHAUSTED"
                stored_backup.last_error_message = (
                    "The storage upload exhausted its automatic retry budget."
                )
                stored_backup.save(
                    update_fields=[
                        "status",
                        "last_error_code",
                        "last_error_message",
                        "modified",
                    ]
                )
                cleanup_after_release = has_owned_multipart_cleanup_candidate(
                    stored_backup
                )
                log_file.write(
                    "Error [STORAGE_RETRIES_EXHAUSTED]: automatic retries exhausted.\n"
                )
    finally:
        log_file.close()
        lease.release()
        if cleanup_after_release:
            try:
                _schedule_owned_multipart_cleanup(stored_backup)
            except Exception as cleanup_error:
                # Broker loss cannot make the upload task replay a provider
                # mutation. The bounded periodic sweep will republish this exact
                # terminal point.
                capture_exception(cleanup_error)


@current_app.task(
    name="storage_cleanup_owned_multipart",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=24,
    time_limit=1800,
    soft_time_limit=1500,
)
def storage_cleanup_owned_multipart(self, model_key, stored_backup_id):
    """Reconcile and abort one exact-owned terminal multipart upload."""

    model = _STORAGE_POINT_MODELS.get(str(model_key or ""))
    if model is None:
        raise TaskParamsNotProvided()
    point = model.objects.select_related(
        "storage__type", "storage__account", "backup"
    ).get(pk=stored_backup_id)
    if not has_owned_multipart_cleanup_candidate(point):
        return {"result": "not_eligible"}

    lease = DurableStorageUploadLease(
        point,
        task_id=self.request.id,
        worker_name=getattr(self.request, "hostname", ""),
        purpose="multipart_cleanup",
    )
    try:
        point = lease.claim()
    except (StorageUploadAlreadyComplete, StorageCleanupNotEligible):
        return {"result": "not_eligible"}
    except StorageUploadLeaseBusy as error:
        raise self.retry(countdown=error.retry_after)

    try:
        context = multipart_cleanup_context(point)
        result = cleanup_owned_multipart_upload(point, **context)
        lease.ensure_owned()
        return {
            "result": result.get("result"),
            "phase": result.get("phase"),
        }
    except S3MultipartCleanupPending as error:
        raise self.retry(countdown=error.retry_after)
    except (
        S3MultipartCleanupNotEligible,
        S3UploadReconciliationRequired,
        UnsupportedMultipartCleanupBackend,
    ):
        return {"result": "not_eligible"}
    except (StorageUploadLeaseLost, StoragePointLeaseLostError) as error:
        capture_exception(error)
        raise self.retry(countdown=30)
    except Exception as error:
        capture_exception(error)
        delay = min(300 * (2 ** min(self.request.retries, 4)), 3600)
        raise self.retry(countdown=delay)
    finally:
        lease.release()


@current_app.task(
    name="storage_sweep_owned_multipart_cleanup",
    track_started=True,
    bind=True,
    time_limit=900,
    soft_time_limit=840,
)
def storage_sweep_owned_multipart_cleanup(self):
    """Publish a bounded, keyset-paginated sweep of stale eligible points."""

    stale_seconds = max(
        300,
        min(
            int(
                getattr(
                    settings,
                    "S3_MULTIPART_CLEANUP_STALE_SECONDS",
                    6 * 3600,
                )
            ),
            30 * 24 * 3600,
        ),
    )
    batch_size = max(
        1,
        min(
            int(getattr(settings, "S3_MULTIPART_CLEANUP_BATCH_SIZE", 50)),
            500,
        ),
    )
    scan_limit = max(
        batch_size,
        min(
            int(getattr(settings, "S3_MULTIPART_CLEANUP_SCAN_LIMIT", 1000)),
            10000,
        ),
    )
    page_size = min(100, scan_limit)
    now = timezone.now()
    cutoff = now - timedelta(seconds=stale_seconds)
    enqueued = 0
    scanned = 0

    for model_key, model in _STORAGE_POINT_MODELS.items():
        last_id = 0
        base = (
            model.objects.select_related("storage__type")
            .filter(
                status__in=_terminal_cleanup_statuses(model),
                modified__lte=cutoff,
            )
            .filter(_multipart_cleanup_candidate_query())
            .filter(
                Q(upload_lease_expires_at__isnull=True)
                | Q(upload_lease_expires_at__lte=now)
            )
            .exclude(metadata__isnull=True)
            .order_by("id")
        )
        while scanned < scan_limit and enqueued < batch_size:
            page = list(base.filter(id__gt=last_id)[:page_size])
            if not page:
                break
            for point in page:
                last_id = point.pk
                scanned += 1
                if has_owned_multipart_cleanup_candidate(point):
                    storage_cleanup_owned_multipart.apply_async(
                        args=[model_key, point.pk]
                    )
                    enqueued += 1
                    if enqueued >= batch_size:
                        break
                if scanned >= scan_limit:
                    break
    return {"enqueued": enqueued, "scanned": scanned}


@current_app.task(
    name="finalize_backup",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=8,
)
def finalize_backup(self, node_id, backup_id):
    """Chord callback: runs exactly once after every storage_upload for a backup
    finishes. Decides the backup's final state from the real upload tally, applies
    the schedule retention policy, and cleans up the local working files.

    Marking completion here (instead of inside each parallel storage_upload) removes
    the previous race conditions and the false "complete on first success".
    """
    from apps._tasks.helper.tasks import delete_from_disk

    node = CoreNode.objects.get(id=node_id)

    if node.type == CoreNode.Type.WEBSITE:
        backup = CoreWebsiteBackup.objects.get(id=backup_id)
    elif node.type == CoreNode.Type.DATABASE:
        backup = CoreDatabaseBackup.objects.get(id=backup_id)
    elif node.type == CoreNode.Type.SAAS:
        if node.connection.integration.code == "wordpress":
            backup = CoreWordPressBackup.objects.get(id=backup_id)
        elif node.connection.integration.code == "basecamp":
            backup = CoreBasecampBackup.objects.get(id=backup_id)
        else:
            raise TaskParamsNotProvided()
    else:
        raise TaskParamsNotProvided()

    relation_name = {
        CoreNode.Type.WEBSITE: "stored_website_backups",
        CoreNode.Type.DATABASE: "stored_database_backups",
        CoreNode.Type.SAAS: (
            "stored_wordpress_backups"
            if node.connection.integration.code == "wordpress"
            else "stored_basecamp_backups"
        ),
    }[node.type]

    # The callback is normally invoked by a chord, but it can also be published by
    # recovery or be duplicated by broker redelivery. Lock both the backup row and
    # all of its storage points so a second finalizer cannot tally a moving upload
    # set or send a second completion notification.
    with transaction.atomic():
        backup = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        storage_relation = getattr(backup, relation_name)
        point_model = storage_relation.model
        storage_points = list(storage_relation.select_for_update().all())
        pending_statuses = {
            point_model.Status.UPLOAD_READY,
            point_model.Status.UPLOAD_RETRY,
            point_model.Status.UPLOAD_IN_PROGRESS,
            point_model.Status.UPLOAD_VALIDATION,
        }
        if any(point.status in pending_statuses for point in storage_points):
            # A duplicate/early callback must not turn an in-flight upload into a
            # false PARTIAL or UPLOAD_FAILED result.
            raise self.retry(countdown=60)

        uploaded_count = sum(
            point.status == point.Status.UPLOAD_COMPLETE
            for point in storage_points
        )
        storage_point_count = len(storage_points)
        metadata = dict(backup.metadata or {})
        destination_setup = metadata.get("_backup_destination_setup")
        destination_setup = (
            destination_setup if isinstance(destination_setup, dict) else {}
        )
        try:
            requested_storage_count = max(
                storage_point_count,
                int(destination_setup.get("requested_count") or 0),
            )
        except (TypeError, ValueError):
            requested_storage_count = storage_point_count
        terminal_statuses = set(UtilBackup.SUCCESS_STATUSES) | {
            UtilBackup.Status.FAILED,
            UtilBackup.Status.MAX_RETRY_FAILED,
            UtilBackup.Status.UPLOAD_FAILED,
            UtilBackup.Status.TIMEOUT,
            UtilBackup.Status.CANCELLED,
            UtilBackup.Status.STORAGE_VALIDATION_FAILED,
        }
        if backup.status in terminal_statuses:
            # A late callback must never downgrade or replace a cancellation or a
            # prior terminal decision made by another worker.
            final_status = backup.status
        else:
            all_uploaded = (
                requested_storage_count > 0
                and uploaded_count == requested_storage_count
            )
            if uploaded_count > 0:
                final_status = (
                    UtilBackup.Status.COMPLETE
                    if all_uploaded
                    else UtilBackup.Status.PARTIAL
                )
            else:
                # Nothing was stored anywhere -> failure (do not silently mark complete).
                final_status = UtilBackup.Status.UPLOAD_FAILED

        finalization = metadata.get("_backup_finalization")
        finalization = dict(finalization) if isinstance(finalization, dict) else {}
        status_changed = backup.status != final_status
        if status_changed:
            finalization = {
                "success_notified": False,
                "partial_logged": False,
                "retention_applied": False,
            }
        metadata["_backup_finalization"] = finalization
        if uploaded_count > 0:
            metadata["storage_upload_summary"] = {
                "uploaded": uploaded_count,
                # ``configured`` is retained for API compatibility, but now means
                # the complete immutable request rather than only the subset that
                # happened to attach before a worker crash.
                "configured": requested_storage_count,
                "accepted": storage_point_count,
                "failed": max(requested_storage_count - uploaded_count, 0),
                "partial": final_status == UtilBackup.Status.PARTIAL,
            }
        backup.status = final_status
        backup.metadata = metadata
        backup.save(update_fields=["status", "metadata", "modified"])
        if (
            final_status
            in {UtilBackup.Status.PARTIAL, UtilBackup.Status.UPLOAD_FAILED}
            and any(
                point.last_error_code == "STORAGE_RETRIES_EXHAUSTED"
                for point in storage_points
            )
        ):
            # A retrying destination records a transient parent error while its
            # ETA delivery is still live. Once that destination exhausts its
            # budget, the finalizer must replace the stale retry guidance before
            # exposing a terminal partial/failure row.
            backup.record_execution_error(
                code="STORAGE_RETRIES_EXHAUSTED",
                retryable=False,
                retry_at=None,
            )
        if final_status in UtilBackup.SUCCESS_STATUSES:
            terminal_phase = "complete"
        elif final_status == UtilBackup.Status.CANCELLED:
            terminal_phase = "cancelled"
        else:
            terminal_phase = "failed"
        # Keep the public backup status and the durable execution ledger in the same
        # database transaction.  This also clears any source-dispatch lease so a
        # stale worker cannot resurrect progress after finalization.
        backup.finalize_execution(terminal_phase=terminal_phase)

    should_notify_success = (
        final_status == UtilBackup.Status.COMPLETE
        and not finalization.get("success_notified")
    )
    should_log_partial = (
        final_status == UtilBackup.Status.PARTIAL
        and not finalization.get("partial_logged")
    )
    should_apply_retention = (
        final_status in UtilBackup.SUCCESS_STATUSES
        and not finalization.get("retention_applied")
        and backup.schedule_id
        and (backup.schedule.keep_last or 0) > 0
    )

    try:
        if should_notify_success:
            node.notify_backup_success(backup)
            finalization_flag = "success_notified"
            with transaction.atomic():
                fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
                metadata = dict(fresh.metadata or {})
                state = dict(metadata.get("_backup_finalization") or {})
                state[finalization_flag] = True
                metadata["_backup_finalization"] = state
                fresh.metadata = metadata
                fresh.save(update_fields=["metadata", "modified"])
        elif should_log_partial:
            message = (
                f"Backup {backup.uuid_str} completed partially: "
                f"{uploaded_count}/{requested_storage_count} storage destinations succeeded."
            )
            node.connection.account.create_backup_log(message, node, backup)
            capture_message(message)
            with transaction.atomic():
                fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
                metadata = dict(fresh.metadata or {})
                state = dict(metadata.get("_backup_finalization") or {})
                state["partial_logged"] = True
                metadata["_backup_finalization"] = state
                fresh.metadata = metadata
                fresh.save(update_fields=["metadata", "modified"])

        # Retention includes partial runs: they occupy destination space and must
        # not bypass the schedule's keep_last policy. The metadata flag makes a
        # redelivered finalizer resume an interrupted retention pass rather than
        # starting it from scratch on every delivery.
        if should_apply_retention:
            keep_last = backup.schedule.keep_last
            successful = list(
                backup.__class__.objects.filter(
                    schedule=backup.schedule,
                    status__in=UtilBackup.SUCCESS_STATUSES,
                ).order_by("created")
            )
            for old_backup in successful[:-keep_last]:
                old_backup.soft_delete()
            with transaction.atomic():
                fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
                metadata = dict(fresh.metadata or {})
                state = dict(metadata.get("_backup_finalization") or {})
                state["retention_applied"] = True
                metadata["_backup_finalization"] = state
                fresh.metadata = metadata
                fresh.save(update_fields=["metadata", "modified"])
    except Exception as error:
        # The terminal DB state is already durable. Keep the files cleanup below,
        # but record side-effect failures so a support operator can distinguish a
        # completed backup from a missed notification/retention pass.
        capture_exception(error)
    finally:
        # Local working files are no longer needed once the terminal DB decision is
        # committed. If the DB transaction above failed, control never reaches this
        # block, preserving the files for recovery.
        delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
