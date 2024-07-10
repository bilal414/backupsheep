import boto3
from apps._tasks.exceptions import StorageAliBabaUploadFailedError, StorageTencentUploadFailedError
from apps.api.v1.utils.api_helpers import bs_decrypt
import oss2
from qcloud_cos import CosConfig
from qcloud_cos import CosS3Client


def storage_tencent(stored_backup):
    try:
        backup = stored_backup.backup

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        prefix = storage.storage_tencent.prefix

        file_name = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        config = CosConfig(
            Region=storage.storage_tencent.region.code,
            SecretId=bs_decrypt(storage.storage_tencent.access_key, encryption_key),
            SecretKey=bs_decrypt(storage.storage_tencent.secret_key, encryption_key),
            Scheme="https",
        )
        client = CosS3Client(config)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            file_key = prefix + file_name
        else:
            file_key = file_name

        client.upload_file(
            Bucket=storage.storage_tencent.bucket_name, Key=file_key, LocalFilePath=local_zip, EnableMD5=True
        )

        storage_file_id = file_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageTencentUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
