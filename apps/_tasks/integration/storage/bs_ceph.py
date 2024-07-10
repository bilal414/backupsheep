import json

import boto3
from sentry_sdk import capture_exception

from apps._tasks.exceptions import (
    NodeBackupSheepUploadFailedError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt


def storage_bs_ceph(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup
        encryption_key = storage.account.get_encryption_key()

        access_key = bs_decrypt(storage.storage_bs.access_key, encryption_key)
        secret_key = bs_decrypt(storage.storage_bs.secret_key, encryption_key)
        s3_endpoint = f"https://{storage.storage_bs.endpoint}"

        file_name = f"{stored_backup.backup.uuid}.zip"

        s3_client = boto3.client(
            "s3",
            endpoint_url=s3_endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        if storage.storage_bs.prefix:
            object_key = storage.storage_bs.prefix + file_name
        else:
            object_key = file_name

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
                storage.storage_bs.bucket_name,
                object_key,
                ExtraArgs={
                    "Metadata": metadata_new,
                },
            )
        storage_file_id = object_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        capture_exception(e)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        capture_exception(e)
        raise NodeBackupSheepUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
