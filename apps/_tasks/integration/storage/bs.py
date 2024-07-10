import json

import boto3
from botocore.config import Config
from django.conf import settings
from django.template.defaultfilters import slugify
from sentry_sdk import capture_exception

from apps._tasks.exceptions import (
    NodeBackupSheepUploadFailedError,
)


def storage_bs(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup

        s3_endpoint = f"https://{storage.storage_bs.endpoint}"

        if "fra.idrivee" in s3_endpoint:
            access_key = settings.IDRIVE_FRA_ACCESS_KEY
            secret_key = settings.IDRIVE_FRA_SECRET_ACCESS_KEY
        else:
            access_key = settings.AWS_S3_ACCESS_KEY
            secret_key = settings.AWS_S3_SECRET_ACCESS_KEY

        prefix = storage.storage_bs.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"

        s3_client = boto3.client(
            "s3",
            endpoint_url=s3_endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            object_key = f"{prefix}{backup.node.uuid_str}/{file_name}"
        else:
            object_key = f"{backup.node.uuid_str}/{file_name}"

        metadata = {
            "account": storage.account.id,
            "backup": backup.id,
            "backup_type": backup.get_type_display().lower(),
            "schedule": backup.schedule.id if backup.schedule else "",
            "schedule_name": slugify(backup.schedule.name) if backup.schedule else "",
        }

        if hasattr(backup, "database"):
            metadata.update(
                {
                    "node": backup.database.node.id,
                    "node_name": slugify(backup.database.node.name),
                    "type": backup.database.node.get_type_display(),
                    "database": backup.database.id,
                    "integration": backup.database.node.connection.id,
                    "integration_name": slugify(backup.database.node.connection.name),
                }
            )
        elif hasattr(backup, "website"):
            metadata.update(
                {
                    "node": backup.website.node.id,
                    "node_name": slugify(backup.website.node.name),
                    "type": backup.website.node.get_type_display(),
                    "website": backup.website.id,
                    "integration": backup.website.node.connection.id,
                    "integration_name": slugify(backup.website.node.connection.name),
                }
            )
        elif hasattr(backup, "wordpress"):
            metadata.update(
                {
                    "node": backup.wordpress.node.id,
                    "node_name": slugify(backup.wordpress.node.name),
                    "type": backup.wordpress.node.get_type_display(),
                    "wordpress": backup.wordpress.id,
                    "integration": backup.wordpress.node.connection.id,
                    "integration_name": slugify(backup.wordpress.node.connection.name),
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
