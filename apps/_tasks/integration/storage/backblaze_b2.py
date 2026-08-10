from botocore.config import Config

from apps._tasks.exceptions import StorageBackBlazeB2UploadFailedError
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.integration.storage.vultr import _safe_upload_exception
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


BACKBLAZE_B2_OBJECT_METADATA_KEY = "backblaze_b2_s3_object"


def _s3_client(backblaze, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(backblaze.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(backblaze.secret_key, encryption_key),
        endpoint_url=f"https://{backblaze.endpoint}",
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_backblaze_b2(stored_backup):
    try:
        storage = stored_backup.storage
        backblaze = storage.storage_backblaze_b2
        prefix = backblaze.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(backblaze, storage.account.get_encryption_key()),
            bucket=backblaze.bucket_name,
            key=key,
            local_path=f"_storage/{stored_backup.backup.uuid}.zip",
            metadata_key=BACKBLAZE_B2_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageBackBlazeB2UploadFailedError, stored_backup, error
        ) from error
import boto3
