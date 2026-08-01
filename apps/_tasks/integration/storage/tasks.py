import subprocess
import time
from billiard.exceptions import SoftTimeLimitExceeded
from boto3.exceptions import S3UploadFailedError
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
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
    CoreWordPressBackup, CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints,
    CoreWordPressBackupStoragePoints, CoreBasecampBackup,
)
from apps.console.node.models import CoreNode
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup


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

    # Chord publication and worker acknowledgement are separate events. A storage
    # task can therefore be delivered twice, or be recovered after a worker loss.
    # Claim the storage-point row before touching the remote backend and skip a
    # healthy in-flight claimant. A stale claimant is safe to resume because each
    # backend uses the deterministic backup UUID/file key.
    with transaction.atomic():
        locked = stored_backup.__class__.objects.select_for_update().get(pk=stored_backup.pk)
        if locked.status == locked.Status.UPLOAD_COMPLETE:
            return
        if locked.status == locked.Status.UPLOAD_IN_PROGRESS:
            stale_after = int(
                getattr(
                    settings,
                    "BACKUP_STORAGE_STALE_SECONDS",
                    getattr(settings, "BACKUP_RECOVERY_STALE_SECONDS", 900),
                )
            )
            if (timezone.now() - locked.modified).total_seconds() < stale_after:
                # This task may be a duplicate header from a redelivered parent
                # chord, including a duplicate with the same Celery id. Keep the
                # header slot pending until the claimant completes; returning here
                # would let the duplicate chord finalize the backup while the real
                # upload is still running.
                raise self.retry(countdown=60)
        locked.status = locked.Status.UPLOAD_IN_PROGRESS
        locked.celery_task_id = self.request.id
        locked.save(update_fields=["status", "celery_task_id", "modified"])
        stored_backup = locked

    log_file_path = f"_storage/{backup.uuid_str}.log"
    log_file = open(log_file_path, "a+")

    storage_type_name = f"Storage ({stored_backup.storage.type.name})"
    log_file.write(f"{storage_type_name}: Starting Upload \n")
    log_file.write(f"{storage_type_name}: Attempt Number: {attempt_no} \n")
    log_file.write(f"{storage_type_name}: {stored_backup.storage.name} \n")

    try:
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
            stored_backup.status = stored_backup.Status.UPLOAD_FAILED
            stored_backup.save()
            log_file.write(
                f"{storage_type_name}: Unsupported storage type "
                f"'{stored_backup.storage.type.code}'\n"
            )

        # The backend sets the storage point to UPLOAD_COMPLETE on success (or a
        # failure status / raises). Backup-level completion (status, notification,
        # retention) is handled exactly once by the finalize_backup chord callback
        # after every upload finishes.
        log_file.write(f"{storage_type_name}: {stored_backup.get_status_display()} \n")

    except NodeGoogleDriveNotEnoughStorageError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except NodeDigitalOceanSpacesBucketDeletedError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except NodeDigitalOceanSpacesNoSuchBucketError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except NodeDropboxNotEnoughStorageError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except StorageFilebaseQuotaExceededError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except NodeDropboxTokenExpiredError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_STORAGE_LIMIT
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except NodeDropboxFileIDMissingError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    #    An error occurred (NoSuchBucket) when calling the
    #    CreateMultipartUpload operation: The specified bucket does not exist
    except S3UploadFailedError as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")

    # #     An error occurred (InvalidAccessKeyId) when calling the
    # PutObject operation: The AWS Access Key Id you provided does not exist in our records.
    # except NodeAWSS3UploadFailedError as e:
    #     node.notify_upload_fail(e, backup, stored_backup.storage)
    #     stored_backup.status = stored_backup.Status.UPLOAD_FAILED
    #     stored_backup.save()
    #     node.connection.account.create_storage_log(e, node, backup, stored_backup.storage)
    except SoftTimeLimitExceeded as e:
        node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)
        stored_backup.status = stored_backup.Status.UPLOAD_TIME_LIMIT_REACHED
        stored_backup.save()
        node.connection.account.create_storage_log(
            e.__str__(), node, backup, stored_backup.storage
        )
        log_file.write(f"Error: {e.__str__()} \n")
    except Exception as e:
        capture_exception(e)

        # A missing local backup file cannot be fixed by retrying; fail immediately.
        if (
            "user-provided path" in e.__str__().lower()
            and "does not exist" in e.__str__().lower()
        ):
            stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
            stored_backup.save()
            node.connection.account.create_storage_log(
                e.__str__(), node, backup, stored_backup.storage
            )
            log_file.write(f"Error (not retryable): {e.__str__()} \n")
        else:
            try:
                if attempt_no <= 3:
                    node.notify_upload_fail(e.__str__(), backup, stored_backup.storage)

                stored_backup.status = stored_backup.Status.UPLOAD_RETRY
                stored_backup.save()

                node.connection.account.create_storage_log(
                    e.__str__(), node, backup, stored_backup.storage
                )
                log_file.write(f"Error: {e.__str__()} \n")
                raise self.retry()
            except MaxRetriesExceededError:
                stored_backup.status = stored_backup.Status.UPLOAD_FAILED
                stored_backup.save()
                log_file.write(f"Error: Giving up after max retries \n")
    finally:
        log_file.close()


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
        all_uploaded = uploaded_count == storage_point_count
        if uploaded_count > 0:
            final_status = (
                UtilBackup.Status.COMPLETE
                if all_uploaded
                else UtilBackup.Status.PARTIAL
            )
        else:
            # Nothing was stored anywhere -> failure (do not silently mark complete).
            final_status = UtilBackup.Status.UPLOAD_FAILED

        metadata = dict(backup.metadata or {})
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
                "configured": storage_point_count,
                "partial": final_status == UtilBackup.Status.PARTIAL,
            }
        backup.status = final_status
        backup.metadata = metadata
        backup.save(update_fields=["status", "metadata", "modified"])

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
                f"{uploaded_count}/{storage_point_count} storage destinations succeeded."
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
