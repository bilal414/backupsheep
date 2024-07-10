import subprocess
import time
from billiard.exceptions import SoftTimeLimitExceeded
from boto3.exceptions import S3UploadFailedError
from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.db.models import Q
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
from apps._tasks.integration.storage.bs import storage_bs

from apps._tasks.integration.storage.bs_ceph import storage_bs_ceph
from apps._tasks.integration.storage.bs_google_cloud import bs_google_cloud
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

    log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid_str}.log"
    log_file = open(log_file_path, "a+")

    storage_type_name = f"Storage ({stored_backup.storage.type.name})"
    log_file.write(f"{storage_type_name}: Starting Upload \n")
    log_file.write(f"{storage_type_name}: Attempt Number: {attempt_no} \n")
    log_file.write(f"{storage_type_name}: {stored_backup.storage.name} \n")

    try:
        """
        Set main backup status to upload upload-in-progress since no storage point is uploaded.
        """
        if backup.storage_points_uploaded() == 0:
            backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
            backup.save()

        stored_backup.status = stored_backup.Status.UPLOAD_IN_PROGRESS
        stored_backup.celery_task_id = self.request.id
        stored_backup.save()

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
        elif stored_backup.storage.type.code == "bs":
            if stored_backup.storage.storage_bs.endpoint == "s3.backupsheep.com":
                storage_bs_ceph(stored_backup)
            elif stored_backup.storage.storage_bs.endpoint == "storage.cloud.google.com":
                bs_google_cloud(stored_backup)
            else:
                storage_bs(stored_backup)

        """
        Set storage point status to complete
        """
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()

        log_file.write(f"{storage_type_name}: {stored_backup.get_status_display()} \n")

        """
        NEED AT LEAST ONE STORAGE POINT UPLOADED
        ----------------------------------------
        Now we have to check if at-least one upload is complete. Then we will send email notification and 
        also delete old backups of it's scheduled backup. 
        """

        if (
            backup.storage_points_uploaded() > 0
            and backup.status != UtilBackup.Status.COMPLETE
        ):
            log_file.write(f"Message: At-least one upload is complete. \n")

            """
            Now we can mark backup complete
            """
            backup.status = UtilBackup.Status.COMPLETE
            backup.save()
            log_file.write(f"Status: {backup.get_status_display()}\n")

            """
            Notify user about successful backup.
            """
            node.notify_backup_success(backup)

            """
            Now mark backups delete requested based on schedule.
            """
            if backup.schedule:
                log_file.write(f"Schedule: {backup.schedule.name}\n")

                """
                DELETE PREVIOUS BACKUPS if KEEP LAST # IS USED
                """
                if (backup.schedule.keep_last or 0) > 0:
                    log_file.write(f"Retention Policy: {backup.schedule.keep_last}\n")

                    if node.type == CoreNode.Type.WEBSITE:
                        while backup.schedule.website_backups.filter(
                            status=UtilBackup.Status.COMPLETE
                        ).count() > (backup.schedule.keep_last or 0):
                            backup_to_delete = (
                                backup.schedule.website_backups.filter(
                                    status=UtilBackup.Status.COMPLETE
                                )
                                .order_by("created")
                                .first()
                            )
                            backup_to_delete.soft_delete()
                    elif node.type == CoreNode.Type.DATABASE:
                        while backup.schedule.database_backups.filter(
                            status=UtilBackup.Status.COMPLETE
                        ).count() > (backup.schedule.keep_last or 0):
                            backup_to_delete = (
                                backup.schedule.database_backups.filter(
                                    status=UtilBackup.Status.COMPLETE
                                )
                                .order_by("created")
                                .first()
                            )
                            backup_to_delete.soft_delete()
                    elif node.type == CoreNode.Type.SAAS:
                        while backup.schedule.wordpress_backups.filter(
                            status=UtilBackup.Status.COMPLETE
                        ).count() > (backup.schedule.keep_last or 0):
                            backup_to_delete = (
                                backup.schedule.wordpress_backups.filter(
                                    status=UtilBackup.Status.COMPLETE
                                )
                                .order_by("created")
                                .first()
                            )
                            backup_to_delete.soft_delete()
            else:
                log_file.write(f"Message: This is on-demand backup\n")

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

        try:
            if (
                "user-provided path" in e.__str__().lower()
                and "does not exist" in e.__str__().lower()
            ):
                stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
                stored_backup.save()

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
        # """
        # Upload failed, so we will upload it to BackupSheep storage by default.
        # """
        # if backup.storage_points_bs() == 0 and attempt_no == 3:
        #     log_file.write(f"Info: Looks like no backups were uploaded. "
        #                    f"Uploading it to BackupSheep storage just to be safe. \n")
        #
        #     storage = CoreStorage.objects.filter(
        #         storage_bs__isnull=False,
        #         account=node.connection.account,
        #         status=CoreStorage.Status.ACTIVE,
        #     ).first()
        #
        #     if node.type == CoreNode.Type.WEBSITE:
        #         if not CoreWebsiteBackupStoragePoints.objects.filter(backup=backup, storage=storage).exists():
        #             stored_backup = CoreWebsiteBackupStoragePoints(backup=backup, storage=storage)
        #             stored_backup.save()
        #             backup.stored_website_backups.add(stored_backup)
        #             storage_upload(node_id, backup_id, stored_backup.id)
        #     elif node.type == CoreNode.Type.DATABASE:
        #         if not CoreDatabaseBackupStoragePoints.objects.filter(backup=backup, storage=storage).exists():
        #             stored_backup = CoreDatabaseBackupStoragePoints(backup=backup, storage=storage)
        #             stored_backup.save()
        #             backup.stored_database_backups.add(stored_backup)
        #             storage_upload(node_id, backup_id, stored_backup.id)
        #     elif node.type == CoreNode.Type.SAAS:
        #         if not CoreWordPressBackupStoragePoints.objects.filter(backup=backup, storage=storage).exists():
        #             stored_backup = CoreWordPressBackupStoragePoints(backup=backup, storage=storage)
        #             stored_backup.save()
        #             backup.stored_wordpress_backups.add(stored_backup)
        #             storage_upload(node_id, backup_id, stored_backup.id)

        log_file.close()
