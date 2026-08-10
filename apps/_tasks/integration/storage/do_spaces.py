from botocore.config import Config

from apps._tasks.exceptions import (
    NodeDigitalOceanSpacesBucketDeletedError,
    NodeDigitalOceanSpacesNoSuchBucketError,
    NodeSnapshotDeleteFailed,
    StorageDOSpacesUploadFailedError,
)
from apps._tasks.integration.storage.s3_verified import upload_verified_s3
from apps._tasks.integration.storage.vultr import (
    _safe_s3_failure,
    _safe_upload_exception,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreWebsiteBackup,
    CoreWordPressBackup,
)
from apps.console.node.models import CoreNode


DO_SPACES_OBJECT_METADATA_KEY = "do_spaces_s3_object"


def _client_config():
    return Config(
        connect_timeout=10,
        read_timeout=60,
        retries={"max_attempts": 5, "mode": "standard"},
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    )


def _s3_client(spaces, encryption_key):
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(spaces.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(spaces.secret_key, encryption_key),
        endpoint_url=f"https://{spaces.region.endpoint}",
        config=_client_config(),
    )


def storage_do_spaces(stored_backup):
    try:
        storage = stored_backup.storage
        spaces = storage.storage_do_spaces
        prefix = spaces.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(spaces, storage.account.get_encryption_key()),
            bucket=spaces.bucket_name,
            key=key,
            local_path=f"_storage/{stored_backup.backup.uuid}.zip",
            metadata_key=DO_SPACES_OBJECT_METADATA_KEY,
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        failure = _safe_s3_failure(error)
        exception_type = StorageDOSpacesUploadFailedError
        if failure.provider_code == "bucketdeleted":
            exception_type = NodeDigitalOceanSpacesBucketDeletedError
        elif failure.provider_code == "nosuchbucket":
            exception_type = NodeDigitalOceanSpacesNoSuchBucketError
        raise _safe_upload_exception(
            exception_type, stored_backup, error, failure=failure
        ) from error


def storage_do_spaces_delete(node, backup_name):
    try:
        backup = None
        encryption_key = node.connection.account.get_encryption_key()

        if node.type == CoreNode.Type.WEBSITE:
            backup = CoreWebsiteBackup.objects.get(uuid=backup_name)
        elif node.type == CoreNode.Type.DATABASE:
            backup = CoreDatabaseBackup.objects.get(uuid=backup_name)
        elif node.type == CoreNode.Type.SAAS:
            backup = CoreWordPressBackup.objects.get(uuid=backup_name)

        if backup:
            spaces = backup.storage_byo.storage_do_spaces
            s3_client = _s3_client(spaces, encryption_key)
            _delete_owned_legacy_object(
                s3_client,
                backup,
                Bucket=spaces.bucket_name,
                Key=backup.storage_file_id,
            )
    except Exception as error:
        wrapped = NodeSnapshotDeleteFailed(
            node,
            backup_name,
            message="Unable to delete backup; provider ownership could not be verified, so deletion was stopped safely.",
        )
        wrapped.error_code = "STORAGE_OWNERSHIP_UNVERIFIED"
        wrapped.code = "STORAGE_OWNERSHIP_UNVERIFIED"
        wrapped.retryable = False
        wrapped.retry_after = None
        raise wrapped from error


def _delete_owned_legacy_object(client, backup, **kwargs):
    """Keep the legacy entry point fail-closed until HEAD proves ownership."""
    key = kwargs.get("Key")
    if not key or not getattr(backup, "id", None):
        raise RuntimeError("Storage delete ownership proof is unavailable.")
    head = client.head_object(**kwargs)
    metadata = {
        str(name).lower(): value
        for name, value in (head.get("Metadata") or {}).items()
        if isinstance(name, str)
    }
    if metadata.get("backupsheep-backup-id") != str(backup.id):
        raise RuntimeError("Storage object ownership marker does not match this backup.")
    delete_kwargs = dict(kwargs)
    version_id = head.get("VersionId")
    if version_id and version_id != "null":
        delete_kwargs["VersionId"] = version_id
    client.delete_object(**delete_kwargs)
import boto3
