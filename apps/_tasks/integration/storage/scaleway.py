from botocore.config import Config

from apps._tasks.exceptions import StorageScalewayUploadFailedError
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.integration.storage.vultr import _safe_upload_exception
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


SCALEWAY_OBJECT_METADATA_KEY = "scaleway_s3_object"


def _s3_client(scaleway, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(scaleway.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(scaleway.secret_key, encryption_key),
        region_name=scaleway.region.code,
        endpoint_url=f"https://{scaleway.endpoint}",
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_scaleway(stored_backup):
    try:
        storage = stored_backup.storage
        scaleway = storage.storage_scaleway
        prefix = scaleway.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(scaleway, storage.account.get_encryption_key()),
            bucket=scaleway.bucket_name,
            key=key,
            local_path=f"_storage/{stored_backup.backup.uuid}.zip",
            metadata_key=SCALEWAY_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageScalewayUploadFailedError, stored_backup, error
        ) from error
import boto3
