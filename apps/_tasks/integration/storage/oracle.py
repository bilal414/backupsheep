from botocore.config import Config
import boto3  # Imported for the shared S3 adapter test/patch contract.
import re

from apps._tasks.exceptions import StorageOracleUploadFailedError
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.artifact_encryption import storage_artifact_identity
from apps._tasks.integration.storage.vultr import _safe_upload_exception
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


ORACLE_OBJECT_METADATA_KEY = "oracle_s3_object"
_OCI_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,254}\Z")
_OCI_REGION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_SAFE_ENDPOINT_HOST = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z"
)


def oracle_object_endpoint(namespace, region):
    namespace = str(namespace or "").strip()
    region = str(region or "").strip().lower()
    if not _OCI_NAMESPACE.fullmatch(namespace) or not _OCI_REGION.fullmatch(region):
        raise ValueError("Oracle Object Storage endpoint identity is invalid.")
    return f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com"


def _s3_client(oracle, encryption_key):
    namespace = getattr(oracle, "namespace", None)
    if not namespace:
        legacy_endpoint = str(getattr(oracle, "endpoint", "") or "")
        suffix = f".compat.objectstorage.{oracle.region.code}.oraclecloud.com"
        if legacy_endpoint.endswith(suffix):
            namespace = legacy_endpoint[: -len(suffix)]
    if namespace:
        endpoint = oracle_object_endpoint(namespace, oracle.region.code)
    elif _SAFE_ENDPOINT_HOST.fullmatch(legacy_endpoint):
        # Compatibility for old in-memory integrations. Persisted Oracle rows
        # always have a namespace and therefore use the canonical path endpoint.
        endpoint = f"https://{legacy_endpoint}"
    else:
        raise ValueError("Oracle Object Storage endpoint identity is invalid.")
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(oracle.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(oracle.secret_key, encryption_key),
        region_name=oracle.region.code,
        endpoint_url=endpoint,
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_oracle(stored_backup):
    try:
        storage = stored_backup.storage
        oracle = storage.storage_oracle
        prefix = oracle.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        artifact_identity = storage_artifact_identity(stored_backup.backup)
        key = f"{prefix}{artifact_identity.filename}"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(oracle, storage.account.get_encryption_key()),
            bucket=oracle.bucket_name,
            key=key,
            local_path=f"_storage/{artifact_identity.filename}",
            metadata_key=ORACLE_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageOracleUploadFailedError, stored_backup, error
        ) from error
