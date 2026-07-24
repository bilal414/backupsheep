import json
from datetime import timedelta

import boto3
from django.utils import timezone
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
        aws_s3 = storage.storage_aws_s3
        prefix = aws_s3.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"
        s3_client = boto3.client(
            "s3",
            region_name=aws_s3.region.code if aws_s3.region else None,
            aws_access_key_id=bs_decrypt(
                aws_s3.access_key, encryption_key
            ),
            aws_secret_access_key=bs_decrypt(
                aws_s3.secret_key, encryption_key
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

        extra_args = {
            "StorageClass": "STANDARD",
            "Metadata": metadata_new,
        }
        if aws_s3.expected_bucket_owner:
            extra_args["ExpectedBucketOwner"] = aws_s3.expected_bucket_owner

        retain_until = None
        if aws_s3.object_lock_is_configured():
            retain_until = timezone.now() + timedelta(days=aws_s3.object_lock_retain_days)
            # An additional checksum is required by S3 for Object Lock writes.
            extra_args.update(
                {
                    "ObjectLockMode": aws_s3.object_lock_mode,
                    "ObjectLockRetainUntilDate": retain_until,
                    "ChecksumAlgorithm": "SHA256",
                }
            )

        with open(local_zip, "rb") as data:
            s3_client.upload_fileobj(
                data,
                aws_s3.bucket_name,
                aws_key,
                ExtraArgs=extra_args,
            )

        if aws_s3.object_lock_is_configured():
            lock_metadata = {
                "mode": aws_s3.object_lock_mode,
                "retain_until": retain_until.isoformat(),
                "air_gapped": storage.is_air_gapped,
                "deletion_protection": bool(aws_s3.no_delete or storage.is_air_gapped),
            }
            head_args = {"Bucket": aws_s3.bucket_name, "Key": aws_key}
            if aws_s3.expected_bucket_owner:
                head_args["ExpectedBucketOwner"] = aws_s3.expected_bucket_owner
            try:
                s3_object = s3_client.head_object(**head_args)
                object_retain_until = s3_object.get("ObjectLockRetainUntilDate")
                lock_metadata.update(
                    {
                        "mode": s3_object.get("ObjectLockMode") or lock_metadata["mode"],
                        "retain_until": (
                            object_retain_until.isoformat()
                            if object_retain_until
                            else lock_metadata["retain_until"]
                        ),
                        "version_id": s3_object.get("VersionId"),
                        "legal_hold": s3_object.get("ObjectLockLegalHoldStatus"),
                    }
                )
            except Exception:
                # The upload is durable at this point. Keep the intended retention
                # metadata and fail closed during deletion if we cannot read a
                # version ID back from S3.
                lock_metadata["version_id"] = None

            stored_backup.metadata = {
                **(stored_backup.metadata or {}),
                "s3_object_lock": lock_metadata,
            }
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
