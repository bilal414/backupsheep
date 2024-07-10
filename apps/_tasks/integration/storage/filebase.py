import boto3
from apps._tasks.exceptions import NodeDoSpacesUploadFailedError, StorageFilebaseUploadFailedError, \
    StorageFilebaseQuotaExceededError
from apps.api.v1.utils.api_helpers import bs_decrypt


def storage_filebase(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        prefix = storage.storage_filebase.prefix

        file_name = f"{stored_backup.backup.uuid}.zip"
        session = boto3.Session(
            aws_access_key_id=bs_decrypt(storage.storage_filebase.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(storage.storage_filebase.secret_key, encryption_key),
        )
        s3 = session.resource(
            "s3", endpoint_url="https://s3.filebase.com"
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            file_key = prefix + file_name
        else:
            file_key = file_name
        s3.meta.client.upload_file(
            local_zip, storage.storage_filebase.bucket_name, file_key
        )
        storage_file_id = file_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        if "exceeded your storage quota" in e.__str__():
            raise StorageFilebaseQuotaExceededError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
                e.__str__(),
            )
        else:
            raise StorageFilebaseUploadFailedError(stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__())
