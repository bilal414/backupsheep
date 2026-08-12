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
    StorageUploadAlreadyComplete,
    StorageUploadLeaseBusy,
    StorageUploadLeaseLost,
)
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadInventoryFailure,
    S3UploadOutcomePending,
    S3UploadReconciliationRequired,
)
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
    CoreWordPressBackup, CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints,
    CoreWordPressBackupStoragePoints, CoreBasecampBackup,
    StoragePointLeaseLostError,
)
from apps.console.node.models import CoreNode
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup


class UnsupportedStorageBackend(RuntimeError):
    pass


class SourceArtifactInvalid(RuntimeError):
    pass


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
        capture_exception(error)
        code, message, status, retryable = _storage_error_outcome(
            error, stored_backup
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
        )
        if attempt_no <= 3:
            node.notify_upload_fail(message, backup, stored_backup.storage)
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
                log_file.write(
                    "Error [STORAGE_RETRIES_EXHAUSTED]: automatic retries exhausted.\n"
                )
    finally:
        log_file.close()
        lease.release()


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
