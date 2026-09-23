from botocore.config import Config

from apps._tasks.exceptions import StorageIonosUploadFailedError
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.artifact_encryption import storage_artifact_identity
from apps._tasks.integration.storage.vultr import _safe_upload_exception
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


IONOS_OBJECT_METADATA_KEY = "ionos_s3_object"


def _s3_client(ionos, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(ionos.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(ionos.secret_key, encryption_key),
        region_name=ionos.region.code,
        endpoint_url=f"https://{ionos.endpoint}",
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            # IONOS rejects boto3's optional trailing checksum headers.
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_ionos(stored_backup):
    try:
        storage = stored_backup.storage
        ionos = storage.storage_ionos
        prefix = ionos.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        artifact_identity = storage_artifact_identity(stored_backup.backup)
        key = (
            f"{prefix}{stored_backup.backup.node.name_slug}/{artifact_identity.filename}"
            if artifact_identity.artifact_format == "legacy_zip"
            else f"{prefix}{artifact_identity.filename}"
        )

        upload_verified_s3(
            stored_backup,
            client=_s3_client(ionos, storage.account.get_encryption_key()),
            bucket=ionos.bucket_name,
            key=key,
            local_path=f"_storage/{artifact_identity.filename}",
            metadata_key=IONOS_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageIonosUploadFailedError, stored_backup, error
        ) from error
import boto3
