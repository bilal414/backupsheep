import boto3
from botocore.client import Config

from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeSnapshotDeleteFailed, NodeWasabiUploadFailedError, StorageWasabiUploadFailedError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup, CoreWordPressBackup,
)
from apps.console.node.models import CoreNode


def storage_wasabi(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        prefix = storage.storage_wasabi.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"
        session = boto3.Session(
            aws_access_key_id=bs_decrypt(storage.storage_wasabi.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(storage.storage_wasabi.secret_key, encryption_key),
        )
        config = Config(connect_timeout=300, retries={"max_attempts": 12})
        s3 = session.resource(
            "s3",
            endpoint_url=f"https://{storage.storage_wasabi.region.endpoint}",
            config=config,
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            wasabi_key = prefix + file_name
        else:
            wasabi_key = file_name
        s3.meta.client.upload_file(
            local_zip, storage.storage_wasabi.bucket_name, wasabi_key
        )
        storage_file_id = wasabi_key

        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageWasabiUploadFailedError(stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__())


def storage_wasabi_delete(node, backup_name):
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
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{backup.storage_byo.storage_wasabi.region.endpoint}",
                aws_access_key_id=bs_decrypt(
                    backup.storage_byo.storage_wasabi.access_key, encryption_key
                ),
                aws_secret_access_key=bs_decrypt(
                    backup.storage_byo.storage_wasabi.secret_key, encryption_key
                ),
            )
            s3_delete = s3_client.delete_object(
                Bucket=backup.storage_byo.storage_wasabi.bucket_name,
                Key=backup.storage_file_id,
            )
    except Exception as e:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
