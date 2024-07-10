import boto3
from apps._tasks.exceptions import StorageAliBabaUploadFailedError
from apps.api.v1.utils.api_helpers import bs_decrypt
import oss2


def storage_alibaba(stored_backup):
    try:
        backup = stored_backup.backup

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        prefix = storage.storage_alibaba.prefix

        file_name = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        auth = oss2.Auth(bs_decrypt(storage.storage_alibaba.access_key, encryption_key), bs_decrypt(storage.storage_alibaba.secret_key, encryption_key))

        bucket = oss2.Bucket(auth, f"https://{storage.storage_alibaba.endpoint}", storage.storage_alibaba.bucket_name)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            file_key = prefix + file_name
        else:
            file_key = file_name

        bucket.put_object_from_file(file_key, local_zip)

        storage_file_id = file_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageAliBabaUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
