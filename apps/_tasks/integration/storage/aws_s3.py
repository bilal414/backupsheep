import json

import boto3
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeSnapshotDeleteFailed,
    NodeAWSS3UploadFailedError,
    StorageAWSS3UploadFailedError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
    CoreWordPressBackup,
)
from apps.console.node.models import CoreNode, CoreServerStatus
from apps.console.storage.models import CoreStorage
from django.core.cache import cache


def storage_aws_s3(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup
        encryption_key = storage.account.get_encryption_key()
        prefix = storage.storage_aws_s3.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=bs_decrypt(
                storage.storage_aws_s3.access_key, encryption_key
            ),
            aws_secret_access_key=bs_decrypt(
                storage.storage_aws_s3.secret_key, encryption_key
            ),
        )
        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            aws_key = prefix + file_name
        else:
            aws_key = file_name

        metadata = {
            "account": storage.account.id,
            "backup": backup.id,
            "backup_type": backup.get_type_display().lower(),
            "schedule": backup.schedule.id if backup.schedule else "",
        }

        if hasattr(backup, "database"):
            metadata.update(
                {
                    "node": backup.database.node.id,
                    "type": backup.database.node.get_type_display(),
                    "database": backup.database.id,
                    "connection": backup.database.node.connection.id,
                }
            )
        elif hasattr(backup, "website"):
            metadata.update(
                {
                    "node": backup.website.node.id,
                    "type": backup.website.node.get_type_display(),
                    "website": backup.website.id,
                    "connection": backup.website.node.connection.id,
                }
            )
        elif hasattr(backup, "wordpress"):
            metadata.update(
                {
                    "node": backup.wordpress.node.id,
                    "type": backup.wordpress.node.get_type_display(),
                    "wordpress": backup.wordpress.id,
                    "connection": backup.wordpress.node.connection.id,
                }
            )

        metadata_new = json.loads(json.dumps(metadata), parse_int=str)

        with open(local_zip, "rb") as data:
            s3_client.upload_fileobj(
                data,
                storage.storage_aws_s3.bucket_name,
                aws_key,
                ExtraArgs={
                    "StorageClass": "STANDARD",
                    "Metadata": metadata_new,
                },
            )
        storage_file_id = aws_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageAWSS3UploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
