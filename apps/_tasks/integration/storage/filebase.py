from botocore.config import Config

from apps._tasks.exceptions import (
    StorageFilebaseQuotaExceededError,
    StorageFilebaseUploadFailedError,
)
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.integration.storage.vultr import (
    _safe_s3_failure,
    _safe_upload_exception,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


FILEBASE_OBJECT_METADATA_KEY = "filebase_s3_object"


def _s3_client(filebase, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(filebase.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(filebase.secret_key, encryption_key),
        endpoint_url="https://s3.filebase.io",
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_filebase(stored_backup):
    try:
        storage = stored_backup.storage
        filebase = storage.storage_filebase
        prefix = filebase.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(filebase, storage.account.get_encryption_key()),
            bucket=filebase.bucket_name,
            key=key,
            local_path=f"_storage/{stored_backup.backup.uuid}.zip",
            metadata_key=FILEBASE_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        failure = _safe_s3_failure(error)
        exception_type = (
            StorageFilebaseQuotaExceededError
            if failure.code == "STORAGE_QUOTA_EXCEEDED"
            else StorageFilebaseUploadFailedError
        )
        raise _safe_upload_exception(
            exception_type, stored_backup, error, failure=failure
        ) from error
import boto3
