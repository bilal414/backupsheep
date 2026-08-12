import re

import boto3
from botocore.config import Config

from apps._tasks.exceptions import StorageUpCloudUploadFailedError
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.integration.storage.vultr import _safe_upload_exception
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


UPCLOUD_OBJECT_METADATA_KEY = "upcloud_s3_object"
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_upcloud_endpoint(endpoint):
    """Accept only an UpCloud-managed HTTPS S3 hostname.

    The database stores a hostname rather than a URL.  Enforcing UpCloud's
    documented ``*.upcloudobjects.com`` boundary prevents credentials and
    validation requests from being redirected to an arbitrary host.
    """
    hostname = str(endpoint or "").strip().casefold().rstrip(".")
    if (
        not hostname
        or "://" in hostname
        or any(character in hostname for character in "/?#@:")
        or len(hostname) > 253
    ):
        raise ValueError("Invalid UpCloud Object Storage endpoint.")
    labels = hostname.split(".")
    if (
        len(labels) < 3
        or labels[-2:] != ["upcloudobjects", "com"]
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("Invalid UpCloud Object Storage endpoint.")
    return hostname


def _s3_client(upcloud, encryption_key):
    # Revalidate the persisted endpoint at every credential-use boundary.  UI
    # validation protects newly-created rows, but legacy/imported rows must not
    # be able to redirect object-storage credentials to an arbitrary host.
    endpoint = normalize_upcloud_endpoint(upcloud.endpoint)
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(upcloud.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(upcloud.secret_key, encryption_key),
        endpoint_url=f"https://{endpoint}",
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_upcloud(stored_backup):
    try:
        storage = stored_backup.storage
        upcloud = storage.storage_upcloud
        prefix = upcloud.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(upcloud, storage.account.get_encryption_key()),
            bucket=upcloud.bucket_name,
            key=key,
            local_path=f"_storage/{stored_backup.backup.uuid}.zip",
            metadata_key=UPCLOUD_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageUpCloudUploadFailedError, stored_backup, error
        ) from error
