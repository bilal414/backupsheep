import subprocess
import time
import uuid
from datetime import timedelta
from billiard.exceptions import SoftTimeLimitExceeded
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import ClientError
from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
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
from apps._tasks.artifact_encryption import (
    ArtifactPipelineError,
    cleanup_terminal_restore_ciphertext_handoff,
    cleanup_terminal_source_ciphertext,
    ensure_destination_ciphertext_ledger,
    materialize_local_restore_ciphertext_handoff,
    storage_upload_artifact,
)
from apps._tasks.artifact_deletion import (
    DELETION_ORIGIN_KEY,
    build_deletion_origin,
    validate_deletion_origin,
)
from apps._tasks.integration.storage.lease import (
    DurableStorageUploadLease,
    StorageCleanupNotEligible,
    StorageUploadAlreadyComplete,
    StorageUploadLeaseBusy,
    StorageUploadLeaseLost,
    StorageUploadTerminalState,
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
    CoreWebsiteBackupStoragePoints,
    CoreDatabaseBackupStoragePoints,
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreDatabaseRestore,
    CoreWebsiteRestore,
    StoragePointLeaseLostError,
)
from apps.console.node.models import CoreNode
from apps.console.storage.models import (
    CoreStorage,
    CoreStorageDeletionLease,
    CoreStorageLocal,
)
from apps.console.utils.models import UtilBackup


class UnsupportedStorageBackend(RuntimeError):
    pass


class SourceArtifactInvalid(RuntimeError):
    pass


_STORAGE_ADAPTER_INVENTORY = {
    "dropbox": (storage_dropbox, "remote-stream-sha256"),
    "google_drive": (storage_google_drive, "remote-stream-sha256"),
    "aws_s3": (storage_aws_s3, "verified-s3-object"),
    "wasabi": (storage_wasabi, "verified-s3-object"),
    "do_spaces": (storage_do_spaces, "verified-s3-object"),
    "filebase": (storage_filebase, "verified-s3-object"),
    "backblaze_b2": (storage_backblaze_b2, "verified-s3-object"),
    "linode": (storage_linode, "verified-s3-object"),
    "vultr": (storage_vultr, "verified-s3-object"),
    "upcloud": (storage_upcloud, "verified-s3-object"),
    "exoscale": (storage_exoscale, "verified-s3-object"),
    "oracle": (storage_oracle, "verified-s3-object"),
    "scaleway": (storage_scaleway, "verified-s3-object"),
    "pcloud": (storage_pcloud, "remote-stream-sha256"),
    "onedrive": (storage_onedrive, "remote-stream-sha256"),
    "cloudflare": (storage_cloudflare, "verified-s3-object"),
    "google_cloud": (storage_google_cloud, "remote-stream-sha256"),
    "azure": (storage_azure, "remote-stream-sha256"),
    "leviia": (storage_leviia, "verified-s3-object"),
    "idrive": (storage_idrive, "verified-s3-object"),
    "ionos": (storage_ionos, "verified-s3-object"),
    "alibaba": (storage_alibaba, "verified-s3-object"),
    "tencent": (storage_tencent, "verified-s3-object"),
    "rackcorp": (storage_rackcorp, "verified-s3-object"),
    "ibm": (storage_ibm, "verified-s3-object"),
    "local": (storage_local, "local-readback-sha256"),
}


def _dispatch_storage_adapter(stored_backup):
    """Run one inventoried adapter; every entry must persist readback evidence."""

    entry = _STORAGE_ADAPTER_INVENTORY.get(stored_backup.storage.type.code)
    if entry is None:
        raise UnsupportedStorageBackend()
    adapter, _verification_mechanism = entry
    adapter(stored_backup)


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
    "basecamp": CoreBasecampBackupStoragePoints,
}
_STORAGE_POINT_MODEL_KEYS = {
    model: key for key, model in _STORAGE_POINT_MODELS.items()
}
_BACKUP_MODELS = {
    "website": CoreWebsiteBackup,
    "database": CoreDatabaseBackup,
    "basecamp": CoreBasecampBackup,
}
_BACKUP_POINT_RELATIONS = {
    "website": "stored_website_backups",
    "database": "stored_database_backups",
    "basecamp": "stored_basecamp_backups",
}
_LOCAL_RESTORE_MODELS = {
    "website": CoreWebsiteRestore,
    "database": CoreDatabaseRestore,
}


def _frozen_local_backup_request(backup):
    """Reconstruct the source message from the durable concrete backup only."""

    metadata = dict(backup.metadata or {})
    storage_ids, _invalid_count = CoreNode._canonical_backup_storage_ids(
        metadata.get("_backup_storage_ids")
    )
    return {
        "node_id": int(backup.node.pk),
        "schedule_id": int(backup.schedule_id) if backup.schedule_id else None,
        "storage_ids": storage_ids,
        "notes": backup.notes,
        "resume": True,
    }


def _publish_prepared_local_backup(model_key, backup):
    """Publish the stable source task only after storage authorization commits."""

    node = backup.node
    if not node.authorized_local_destination_point_ids(backup):
        return False
    task_id = str(backup.celery_task_id or "")
    if not task_id:
        raise RuntimeError("prepared local backup has no stable source task id")
    current_app.send_task(
        node.backup_task_name(),
        task_id=task_id,
        kwargs=_frozen_local_backup_request(backup),
        delivery_mode=2,
        mandatory=True,
        retry=True,
        retry_policy={
            "max_retries": 3,
            "interval_start": 0,
            "interval_step": 1,
            "interval_max": 3,
        },
    )
    return True


def _prepare_local_backup_destinations_id(model_key, backup_id):
    """Validate one durable local request and hand it back to its source lane."""

    model_key = str(model_key or "")
    model = _BACKUP_MODELS.get(model_key)
    canonical_id = _canonical_positive_id(backup_id)
    if model is None or canonical_id is None:
        return {"result": "invalid_request"}
    backup = model.objects.filter(pk=canonical_id).first()
    if backup is None:
        return {"result": "not_found"}
    if backup.status not in UtilBackup.ACTIVE_STATUSES:
        return {"result": "terminal"}

    node = backup.node
    metadata = dict(backup.metadata or {})
    storage_ids, _invalid_count = CoreNode._canonical_backup_storage_ids(
        metadata.get("_backup_storage_ids")
    )
    prepared = node.backup_initiate(
        backup.celery_task_id,
        backup.type or UtilBackup.Type.ON_DEMAND,
        max(1, int(backup.attempt_no or 1)),
        backup.schedule_id,
        storage_ids,
        backup.notes,
        prepare_destinations=True,
    )
    if prepared is None:
        backup.refresh_from_db(fields=["status", "metadata"])
        if backup.status == UtilBackup.Status.STORAGE_VALIDATION_FAILED:
            return {"result": "rejected"}
        return {"result": "busy"}
    if not _publish_prepared_local_backup(model_key, prepared):
        return {"result": "not_authorized"}
    return {"result": "published"}


@current_app.task(
    name="prepare_local_backup_destinations",
    bind=True,
    default_retry_delay=60,
    max_retries=16,
    ignore_result=True,
)
def prepare_local_backup_destinations(self, model_key, backup_id):
    """Run credential-bearing destination validation in the storage lane."""

    try:
        result = _prepare_local_backup_destinations_id(model_key, backup_id)
    except Exception as error:
        capture_exception(error)
        raise self.retry(exc=error)
    if result.get("result") == "busy":
        raise self.retry(countdown=60)
    return result


@current_app.task(
    name="resume_pending_backup_destination_validations",
    ignore_result=True,
)
def resume_pending_backup_destination_validations():
    """Repair source/setup publication gaps from durable local backup rows."""

    try:
        batch_size = max(
            1,
            min(
                int(getattr(settings, "BACKUP_RECOVERY_BATCH_SIZE", 100)),
                1000,
            ),
        )
    except (TypeError, ValueError):
        batch_size = 100
    preparation_published = []
    for model_key, model in _BACKUP_MODELS.items():
        candidates = list(
            model.objects.filter(status__in=UtilBackup.ACTIVE_STATUSES)
            .order_by("modified", "pk")[:batch_size]
        )
        for backup in candidates:
            if backup.node.authorized_local_destination_point_ids(backup):
                # Once authorization commits, the existing lane-specific source
                # recovery sweep owns a lost storage-to-source publish. It already
                # honors the source execution lease and stable task id.
                continue
            prepare_local_backup_destinations.apply_async(
                args=[model_key, backup.pk],
                task_id=CoreNode.local_destination_preparation_task_id(backup),
            )
            preparation_published.append((model_key, backup.pk))
    return preparation_published


def _canonical_positive_id(value):
    """Accept a canonical positive database id, never a path-like payload."""

    try:
        canonical = int(value)
    except (TypeError, ValueError):
        return None
    if canonical <= 0 or str(canonical) != str(value):
        return None
    return canonical


def _validate_local_storage_id(storage_id):
    canonical_id = _canonical_positive_id(storage_id)
    if canonical_id is None:
        return {"result": "invalid_id"}

    with transaction.atomic():
        storage = (
            CoreStorage.objects.select_for_update()
            .select_related("type")
            .filter(pk=canonical_id, type__code="local")
            .first()
        )
        if storage is None:
            return {"result": "not_found"}
        if storage.status != CoreStorage.Status.PENDING:
            return {"result": "not_pending"}
        local_storage = CoreStorageLocal.objects.select_for_update().get(
            storage_id=storage.pk
        )

        try:
            valid = bool(local_storage.probe_filesystem())
        except Exception as error:
            capture_exception(error)
            valid = False
        storage.status = (
            CoreStorage.Status.ACTIVE if valid else CoreStorage.Status.SUSPENDED
        )
        storage.save(update_fields=["status", "modified"])
        return {"result": "valid" if valid else "invalid"}


@current_app.task(name="validate_local_storage", ignore_result=True)
def validate_local_storage(storage_id):
    """Validate one persisted Local Storage row from the RW storage boundary."""

    return _validate_local_storage_id(storage_id)


@current_app.task(name="validate_pending_local_storages", ignore_result=True)
def validate_pending_local_storages():
    """Recover validation publishes lost to a broker outage or worker restart."""

    storage_ids = list(
        CoreStorage.objects.filter(
            type__code="local", status=CoreStorage.Status.PENDING
        ).values_list("pk", flat=True)[:100]
    )
    return [_validate_local_storage_id(storage_id) for storage_id in storage_ids]


def _delete_lease_seconds():
    try:
        configured = int(
            getattr(settings, "STORAGE_POINT_DELETE_LEASE_SECONDS", 3600)
        )
    except (TypeError, ValueError):
        configured = 3600
    return max(300, min(configured, 24 * 3600))


def _delete_coordinator_lease_seconds():
    # The point lease, not the coordinator, excludes external side effects. A
    # short coordinator lease lets the sweep finalize a point already committed
    # before its worker crashed, while the longer point fence still blocks overlap.
    return min(_delete_lease_seconds(), 300)


def _lease_is_live(expires_at, now=None):
    if isinstance(expires_at, str):
        expires_at = parse_datetime(expires_at)
    return bool(expires_at and expires_at > (now or timezone.now()))


def _point_is_deletion_protected(point):
    if point.storage.is_air_gapped:
        return True
    try:
        config = getattr(point.storage, f"storage_{point.storage.type.code}")
    except (AttributeError, ObjectDoesNotExist):
        return False
    return bool(getattr(config, "no_delete", False))


def _restore_previous_backup_status(request_state):
    try:
        previous_status = int(request_state.get("previous_status"))
    except (TypeError, ValueError):
        previous_status = int(UtilBackup.Status.COMPLETE)
    forbidden = {
        int(UtilBackup.Status.DELETE_REQUESTED),
        int(UtilBackup.Status.DELETE_IN_PROGRESS),
        int(UtilBackup.Status.DELETE_COMPLETED),
    }
    valid = {int(value) for value, _label in UtilBackup.Status.choices}
    return (
        previous_status
        if previous_status in valid and previous_status not in forbidden
        else int(UtilBackup.Status.COMPLETE)
    )


def _claim_backup_deletion(model, backup_id, owner):
    token = uuid.uuid4()
    now = timezone.now()
    with transaction.atomic():
        backup = model.objects.select_for_update().filter(pk=backup_id).first()
        if backup is None:
            return None, "not_requested"
        metadata = dict(backup.metadata or {})
        existing = dict(metadata.get("_deletion_claim") or {})
        if backup.status == UtilBackup.Status.DELETE_IN_PROGRESS:
            if _lease_is_live(existing.get("expires_at"), now):
                return None, "busy"
        elif backup.status != UtilBackup.Status.DELETE_REQUESTED:
            return None, "not_requested"

        request_state = dict(metadata.get("_deletion_request") or {})
        request_state.setdefault("previous_status", int(UtilBackup.Status.COMPLETE))
        request_state.update({"state": "in_progress", "last_attempt_at": now.isoformat()})
        metadata["_deletion_request"] = request_state
        metadata["_deletion_claim"] = {
            "owner": owner,
            "token": str(token),
            "expires_at": (
                now + timedelta(seconds=_delete_coordinator_lease_seconds())
            ).isoformat(),
        }
        backup.metadata = metadata
        backup.status = UtilBackup.Status.DELETE_IN_PROGRESS
        backup.save(update_fields=["status", "metadata", "modified"])
    return token, "claimed"


def _claim_storage_point_delete(model_key, point_id, owner):
    model = _STORAGE_POINT_MODELS[model_key]
    now = timezone.now()
    token = uuid.uuid4()
    with transaction.atomic():
        point = model.objects.select_for_update().filter(pk=point_id).first()
        if point is None:
            return None, "missing"
        if point.status == point.Status.DELETE_COMPLETED:
            metadata = dict(point.metadata or {})
            metadata.pop(DELETION_ORIGIN_KEY, None)
            metadata.pop("_deletion_claim", None)
            point.metadata = metadata
            point.upload_lease_owner = ""
            point.upload_lease_token = None
            point.upload_lease_expires_at = None
            point.upload_heartbeat_at = None
            point.save(
                update_fields=[
                    "metadata",
                    "upload_lease_owner",
                    "upload_lease_token",
                    "upload_lease_expires_at",
                    "upload_heartbeat_at",
                    "modified",
                ]
            )
            return None, "deleted"
        if _lease_is_live(point.upload_lease_expires_at, now):
            return None, "busy"

        metadata = dict(point.metadata or {})
        validated_origin = validate_deletion_origin(point)
        if validated_origin is not None:
            _custody, previous_status = validated_origin
        else:
            if DELETION_ORIGIN_KEY in metadata or point.status in {
                point.Status.DELETE_REQUESTED,
                point.Status.DELETE_FAILED,
            }:
                return None, "invalid_origin"
            previous_status = int(point.status)
            metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
                point,
                previous_status,
            )
        metadata["_deletion_claim"] = {
            "owner": owner,
            "token": str(token),
            "previous_status": previous_status,
            "claimed_at": now.isoformat(),
        }
        point.metadata = metadata
        point.status = point.Status.DELETE_REQUESTED
        point.upload_lease_owner = owner
        point.upload_lease_token = token
        point.upload_lease_expires_at = now + timedelta(
            seconds=_delete_lease_seconds()
        )
        point.upload_heartbeat_at = now
        point.save(
            update_fields=[
                "metadata",
                "status",
                "upload_lease_owner",
                "upload_lease_token",
                "upload_lease_expires_at",
                "upload_heartbeat_at",
                "modified",
            ]
        )
    return token, "claimed"


def _delete_one_storage_point(model_key, point_id, owner):
    model = _STORAGE_POINT_MODELS[model_key]
    token, claim_result = _claim_storage_point_delete(model_key, point_id, owner)
    if token is None:
        return claim_result

    point = model.objects.select_related(
        "storage__type", "storage__account", "backup"
    ).get(pk=point_id)
    point.bind_upload_fence(owner, token)
    try:
        point.ensure_upload_fence()
        deleted = point.soft_delete()
    except StoragePointLeaseLostError:
        return "busy"
    except Exception as error:
        capture_exception(error)
        deleted = False

    with transaction.atomic():
        current = model.objects.select_for_update().filter(pk=point_id).first()
        if current is None:
            return "deleted"
        if (
            current.upload_lease_owner != owner
            or str(current.upload_lease_token or "") != str(token)
        ):
            return "busy"
        metadata = dict(current.metadata or {})
        metadata.pop("_deletion_claim", None)
        protected = bool(metadata.get("deletion_protection"))
        if deleted:
            metadata.pop(DELETION_ORIGIN_KEY, None)
            current.status = current.Status.DELETE_COMPLETED
            outcome = "deleted"
        elif protected:
            validated_origin = validate_deletion_origin(current)
            if validated_origin is None:
                current.status = current.Status.DELETE_FAILED
                outcome = "pending"
            else:
                _custody, previous_status = validated_origin
                metadata.pop(DELETION_ORIGIN_KEY, None)
                current.status = previous_status
                outcome = "protected"
        else:
            if current.status == current.Status.DELETE_REQUESTED:
                current.status = current.Status.DELETE_FAILED
            outcome = "pending"
        current.metadata = metadata
        current.upload_lease_owner = ""
        current.upload_lease_token = None
        current.upload_lease_expires_at = None
        current.upload_heartbeat_at = None
        current.save(
            update_fields=[
                "metadata",
                "status",
                "upload_lease_owner",
                "upload_lease_token",
                "upload_lease_expires_at",
                "upload_heartbeat_at",
                "modified",
            ]
        )
    return outcome


def _delete_backup_requested_id(model_key, backup_id, *, owner=None):
    model_key = str(model_key or "")
    model = _BACKUP_MODELS.get(model_key)
    canonical_id = _canonical_positive_id(backup_id)
    if model is None or canonical_id is None:
        return {"result": "invalid_request"}
    owner = str(owner or f"backup-delete-{uuid.uuid4().hex}")[:255]
    token, claim_result = _claim_backup_deletion(model, canonical_id, owner)
    if token is None:
        return {"result": claim_result}

    backup = model.objects.get(pk=canonical_id)
    relation_name = _BACKUP_POINT_RELATIONS[model_key]
    points = getattr(backup, relation_name).select_related(
        "storage__type"
    ).order_by("pk")

    # Refuse the whole request before deleting any unprotected sibling. This keeps
    # a multi-destination backup fully restorable when one destination is an
    # intentional air-gap/no-delete copy.
    protected_point = next(
        (point for point in points if _point_is_deletion_protected(point)), None
    )
    if protected_point is not None:
        protected_point.defer_protected_delete(
            "destination deletion protection is enabled"
        )
        point_result = "protected"
    else:
        point = points.exclude(status=points.model.Status.DELETE_COMPLETED).first()
        point_result = (
            _delete_one_storage_point(model_key, point.pk, owner)
            if point is not None
            else "deleted"
        )

    republish = False
    with transaction.atomic():
        current = model.objects.select_for_update().filter(pk=canonical_id).first()
        if current is None:
            return {"result": "deleted"}
        metadata = dict(current.metadata or {})
        claim = dict(metadata.get("_deletion_claim") or {})
        if claim.get("owner") != owner or claim.get("token") != str(token):
            return {"result": "stale"}
        metadata.pop("_deletion_claim", None)
        request_state = dict(metadata.get("_deletion_request") or {})
        now = timezone.now().isoformat()

        if point_result == "protected":
            current.status = _restore_previous_backup_status(request_state)
            request_state.update(
                {"state": "deferred_protected", "completed_at": now}
            )
            result = "protected"
        elif point_result == "deleted" and not getattr(
            current, relation_name
        ).exclude(status=points.model.Status.DELETE_COMPLETED).exists():
            current.status = UtilBackup.Status.DELETE_COMPLETED
            request_state.update({"state": "complete", "completed_at": now})
            result = "deleted"
        else:
            current.status = UtilBackup.Status.DELETE_REQUESTED
            request_state.update({"state": "pending", "last_attempt_at": now})
            result = "pending" if point_result != "busy" else "busy"
            republish = point_result == "deleted"
        metadata["_deletion_request"] = request_state
        current.metadata = metadata
        current.save(update_fields=["status", "metadata", "modified"])

        if republish:
            transaction.on_commit(
                lambda: delete_backup_requested.apply_async(
                    args=[model_key, canonical_id]
                )
            )
    return {"result": result}


@current_app.task(
    name="delete_backup_requested",
    bind=True,
    default_retry_delay=60,
    max_retries=16,
    ignore_result=True,
)
def delete_backup_requested(self, model_key, backup_id):
    """Delete one already-authorized backup by allowlisted model key and DB id."""

    try:
        owner = str(self.request.id or f"backup-delete-{uuid.uuid4().hex}")
        return _delete_backup_requested_id(model_key, backup_id, owner=owner)
    except Exception as error:
        capture_exception(error)
        raise self.retry(exc=error)


def _claim_storage_deletion(storage_id, owner):
    token = uuid.uuid4()
    now = timezone.now()
    with transaction.atomic():
        storage = CoreStorage.objects.select_for_update().filter(
            pk=storage_id, status=CoreStorage.Status.DELETE_REQUESTED
        ).first()
        if storage is None:
            return None, "not_requested"
        lease, _created = CoreStorageDeletionLease.objects.get_or_create(
            storage=storage
        )
        lease = CoreStorageDeletionLease.objects.select_for_update().get(
            pk=lease.pk
        )
        if _lease_is_live(lease.expires_at, now):
            return None, "busy"
        lease.owner = owner
        lease.token = token
        lease.expires_at = now + timedelta(
            seconds=_delete_coordinator_lease_seconds()
        )
        lease.save(
            update_fields=["owner", "token", "expires_at", "modified"]
        )
    return token, "claimed"


def _delete_storage_requested_id(storage_id, *, owner=None):
    canonical_id = _canonical_positive_id(storage_id)
    if canonical_id is None:
        return {"result": "invalid_id"}
    owner = str(owner or f"storage-delete-{uuid.uuid4().hex}")[:255]
    token, claim_result = _claim_storage_deletion(canonical_id, owner)
    if token is None:
        return {"result": claim_result}

    storage = CoreStorage.objects.get(pk=canonical_id)
    candidates = []
    protected_point = None
    for model_key, model in _STORAGE_POINT_MODELS.items():
        for point in model.objects.filter(storage_id=canonical_id).select_related(
            "storage__type"
        ).order_by("pk"):
            if _point_is_deletion_protected(point):
                protected_point = point
                break
            if point.status != point.Status.DELETE_COMPLETED:
                candidates.append((model_key, point.pk))
        if protected_point is not None:
            break

    if protected_point is not None:
        protected_point.defer_protected_delete(
            "destination deletion protection is enabled"
        )
        point_result = "protected"
    elif candidates:
        model_key, point_id = candidates[0]
        point_result = _delete_one_storage_point(model_key, point_id, owner)
    else:
        point_result = "deleted"

    republish = False
    with transaction.atomic():
        current = CoreStorage.objects.select_for_update().filter(
            pk=canonical_id
        ).first()
        if current is None:
            return {"result": "deleted"}
        lease = CoreStorageDeletionLease.objects.select_for_update().get(
            storage_id=canonical_id
        )
        if (
            lease.owner != owner
            or str(lease.token or "") != str(token)
        ):
            return {"result": "stale"}
        if point_result == "protected":
            current.status = CoreStorage.Status.ACTIVE
            result = "protected"
        elif point_result == "deleted":
            remaining = any(
                model.objects.filter(storage_id=canonical_id)
                .exclude(status=model.Status.DELETE_COMPLETED)
                .exists()
                for model in _STORAGE_POINT_MODELS.values()
            )
            if not remaining:
                current.delete()
                return {"result": "deleted"}
            result = "pending"
            republish = True
        else:
            result = "pending" if point_result != "busy" else "busy"
        current.save(update_fields=["status", "modified"])
        lease.owner = ""
        lease.token = None
        lease.expires_at = None
        lease.save(
            update_fields=["owner", "token", "expires_at", "modified"]
        )
        if republish:
            transaction.on_commit(
                lambda: delete_storage_requested.apply_async(args=[canonical_id])
            )
    return {"result": result}


@current_app.task(
    name="delete_storage_requested",
    bind=True,
    default_retry_delay=60,
    max_retries=16,
    ignore_result=True,
)
def delete_storage_requested(self, storage_id):
    """Delete one requested storage config only after its objects are resolved."""

    try:
        owner = str(self.request.id or f"storage-delete-{uuid.uuid4().hex}")
        return _delete_storage_requested_id(storage_id, owner=owner)
    except Exception as error:
        capture_exception(error)
        raise self.retry(exc=error)


@current_app.task(name="resume_requested_storage_deletions", ignore_result=True)
def resume_requested_storage_deletions():
    """Republish exact durable deletion requests without doing provider I/O here."""

    backup_requests = []
    for model_key, model in _BACKUP_MODELS.items():
        backup_ids = list(
            model.objects.filter(
                status__in=(
                    UtilBackup.Status.DELETE_REQUESTED,
                    UtilBackup.Status.DELETE_IN_PROGRESS,
                )
            )
            .values_list("pk", flat=True)[:100]
        )
        for backup_id in backup_ids:
            delete_backup_requested.apply_async(args=[model_key, backup_id])
            backup_requests.append((model_key, backup_id))
    storage_ids = list(
        CoreStorage.objects.filter(status=CoreStorage.Status.DELETE_REQUESTED)
        .values_list("pk", flat=True)[:100]
    )
    for storage_id in storage_ids:
        delete_storage_requested.apply_async(args=[storage_id])
    return {"backup_requests": backup_requests, "storage_ids": storage_ids}


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
    if _caused_by(
        error,
        (S3ObjectIntegrityError, SourceArtifactInvalid, ArtifactPipelineError),
    ) or (
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


def _publish_backup_finalizer_if_terminal(node, backup, stored_backup):
    """Publish finalization only after this durable destination is terminal."""

    stored_backup.refresh_from_db(fields=["status"])
    pending_statuses = {
        stored_backup.Status.UPLOAD_READY,
        stored_backup.Status.UPLOAD_RETRY,
        stored_backup.Status.UPLOAD_IN_PROGRESS,
        stored_backup.Status.UPLOAD_VALIDATION,
    }
    if stored_backup.status in pending_statuses:
        return False
    # ``finalize_backup`` is resolved when the upload executes, after module task
    # registration has completed. A fresh task id is intentional: duplicate
    # finalizers are harmless, while the signed id remains replay-protected.
    finalize_backup.apply_async(args=[node.pk, backup.pk])
    return True


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
        if node.connection.integration.code == "basecamp":
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
        try:
            _publish_backup_finalizer_if_terminal(node, backup, stored_backup)
        except Exception as finalizer_error:
            # The point is already terminal, so replaying its provider mutation
            # would be unsafe. The durable recovery sweep will republish the
            # idempotent finalizer if the broker is temporarily unavailable.
            capture_exception(finalizer_error)
        return
    except StorageUploadTerminalState:
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
        # In BSE1 mode this context materializes only authenticated-header,
        # ledger-matched ciphertext into storage's private volume.  The .zip
        # suffix is retained solely for compatibility with existing adapters;
        # remote objects contain BSE1 bytes and are never decrypted here.
        with storage_upload_artifact(
            backup,
            legacy_verifier=verify_and_commit_source_artifact,
        ) as source_artifact:
            _dispatch_storage_adapter(stored_backup)
            lease.ensure_owned()
            ensure_destination_ciphertext_ledger(
                backup,
                stored_backup,
                source_artifact,
            )

        # The backend sets the storage point to UPLOAD_COMPLETE on success (or a
        # failure status / raises). Backup-level completion (status, notification,
        # retention) is handled by the idempotent finalizer once every point is
        # terminal.
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
        try:
            _publish_backup_finalizer_if_terminal(node, backup, stored_backup)
        except Exception as finalizer_error:
            # Never replay a completed provider mutation merely because the
            # broker was unavailable for the follow-up. The bounded recovery
            # sweep can derive and republish finalization from durable rows.
            capture_exception(finalizer_error)


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


def _cleanup_source_ciphertext(model_key, backup_id, *, expected_lane):
    if model_key not in _BACKUP_MODELS:
        raise ArtifactPipelineError("The ciphertext cleanup model is invalid.")
    if (
        (expected_lane == "database" and model_key != "database")
        or (expected_lane == "files" and model_key == "database")
    ):
        raise ArtifactPipelineError(
            "The ciphertext cleanup model is routed to the wrong lane."
        )
    canonical_id = _canonical_positive_id(backup_id)
    if canonical_id is None:
        raise ArtifactPipelineError("The ciphertext cleanup backup id is invalid.")
    backup = _BACKUP_MODELS[model_key].objects.get(pk=canonical_id)
    return cleanup_terminal_source_ciphertext(backup, expected_lane=expected_lane)


@current_app.task(
    name="cleanup_database_ciphertext_fence",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=24,
)
def cleanup_database_ciphertext_fence(self, backup_id):
    """Clean a terminal database fence only inside the database source lane."""

    try:
        return _cleanup_source_ciphertext(
            "database", backup_id, expected_lane="database"
        )
    except Exception as error:
        capture_exception(error)
        raise self.retry(
            exc=ArtifactPipelineError(
                "Database ciphertext-fence cleanup did not complete safely."
            )
        ) from None


@current_app.task(
    name="cleanup_files_ciphertext_fence",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=24,
)
def cleanup_files_ciphertext_fence(self, model_key, backup_id):
    """Clean terminal website/SaaS fences only inside the files source lane."""

    try:
        return _cleanup_source_ciphertext(
            model_key, backup_id, expected_lane="files"
        )
    except Exception as error:
        capture_exception(error)
        raise self.retry(
            exc=ArtifactPipelineError(
                "Files ciphertext-fence cleanup did not complete safely."
            )
        ) from None


def _local_restore(model_key, restore_id):
    model = _LOCAL_RESTORE_MODELS.get(str(model_key))
    canonical_id = _canonical_positive_id(restore_id)
    if model is None or canonical_id is None:
        raise ArtifactPipelineError("The local restore handoff identity is invalid.")
    return model.objects.get(pk=canonical_id)


@current_app.task(
    name="stage_local_restore_ciphertext",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=96,
    time_limit=48 * 3600,
    soft_time_limit=47 * 3600,
)
def stage_local_restore_ciphertext(self, model_key, restore_id):
    """Stage an exact local BSE1 object for one database/files restore lane."""

    try:
        restore = _local_restore(model_key, restore_id)
        return materialize_local_restore_ciphertext_handoff(
            restore,
            task_id=self.request.id,
        )
    except Exception as error:
        capture_exception(error)
        raise self.retry(
            exc=ArtifactPipelineError(
                "Local restore ciphertext staging did not complete safely."
            )
        ) from None


@current_app.task(
    name="cleanup_local_restore_ciphertext",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=24,
)
def cleanup_local_restore_ciphertext(self, model_key, restore_id):
    """Clean one reverse local-restore handoff after durable terminal state."""

    try:
        restore = _local_restore(model_key, restore_id)
        return cleanup_terminal_restore_ciphertext_handoff(restore)
    except Exception as error:
        capture_exception(error)
        raise self.retry(
            exc=ArtifactPipelineError(
                "Local restore ciphertext cleanup did not complete safely."
            )
        ) from None


@current_app.task(
    name="finalize_backup",
    track_started=True,
    bind=True,
    default_retry_delay=300,
    max_retries=8,
)
def finalize_backup(self, node_id, backup_id):
    """Idempotently finalize a backup after its storage uploads become terminal.

    Each terminal storage worker can publish this task, and recovery can publish it
    again after broker loss. The locked durable tally below ensures early or
    duplicate delivery cannot commit a false or repeated result. It applies the
    schedule retention policy and cleans up the local working files.

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
        if node.connection.integration.code == "basecamp":
            backup = CoreBasecampBackup.objects.get(id=backup_id)
        else:
            raise TaskParamsNotProvided()
    else:
        raise TaskParamsNotProvided()

    relation_name = {
        CoreNode.Type.WEBSITE: "stored_website_backups",
        CoreNode.Type.DATABASE: "stored_database_backups",
        CoreNode.Type.SAAS: "stored_basecamp_backups",
    }[node.type]

    # Lock both the backup row and all of its storage points so an early or duplicate
    # finalizer cannot tally a moving upload set or send a second completion
    # notification.
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
        try:
            if backup.artifact_records.filter(
                role="source",
                storage__isnull=True,
                artifact_format="bse1",
                encryption_envelope__isnull=False,
            ).exists():
                if node.type == CoreNode.Type.DATABASE:
                    cleanup_database_ciphertext_fence.apply_async(args=[backup.pk])
                else:
                    model_key = (
                        "website"
                        if node.type == CoreNode.Type.WEBSITE
                        else "basecamp"
                    )
                    cleanup_files_ciphertext_fence.apply_async(
                        args=[model_key, backup.pk]
                    )
            delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
        except Exception as error:
            capture_exception(error)
            raise self.retry(
                exc=ArtifactPipelineError(
                    "Terminal artifact cleanup publication did not complete safely."
                ),
                countdown=60,
            ) from None
