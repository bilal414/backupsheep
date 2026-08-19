import json
from datetime import timedelta

import boto3
from botocore.config import Config
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
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps.api.v1.utils.boto import bounded_boto3_client


AWS_S3_OBJECT_METADATA_KEY = "aws_s3_object"


def _s3_client(aws_s3, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        region_name=aws_s3.region.code if aws_s3.region else None,
        aws_access_key_id=bs_decrypt(aws_s3.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(aws_s3.secret_key, encryption_key),
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_aws_s3(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup
        encryption_key = storage.account.get_encryption_key()
        aws_s3 = storage.storage_aws_s3
        prefix = aws_s3.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"
        s3_client = _s3_client(aws_s3, encryption_key)
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
            extra_args.update(
                {
                    "ObjectLockMode": aws_s3.object_lock_mode,
                    "ObjectLockRetainUntilDate": retain_until,
                }
            )

        object_state = upload_verified_s3(
            stored_backup,
            client=s3_client,
            bucket=aws_s3.bucket_name,
            key=aws_key,
            local_path=local_zip,
            metadata_key=AWS_S3_OBJECT_METADATA_KEY,
            expected_owner=aws_s3.expected_bucket_owner or None,
            extra_args=extra_args,
            supports_checksum=True,
        )

        if aws_s3.object_lock_is_configured():
            lock_metadata = {
                "mode": aws_s3.object_lock_mode,
                "retain_until": retain_until.isoformat(),
                "air_gapped": storage.is_air_gapped,
                "deletion_protection": bool(aws_s3.no_delete or storage.is_air_gapped),
                "version_id": object_state.get("version_id"),
            }
            stored_backup.metadata = {
                **(stored_backup.metadata or {}),
                "s3_object_lock": lock_metadata,
            }
            stored_backup.save(update_fields=["metadata", "modified"])
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
