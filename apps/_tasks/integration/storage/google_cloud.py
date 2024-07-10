from apps._tasks.exceptions import StorageGoogleCloudUploadFailedError
from google.cloud import storage as gc_storage


def storage_google_cloud(stored_backup):
    try:
        backup = stored_backup.backup

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"

        storage = stored_backup.storage

        prefix = storage.storage_google_cloud.prefix

        file_name = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        storage_client = gc_storage.Client(credentials=storage.storage_google_cloud.get_credentials())

        bucket = storage_client.bucket(storage.storage_google_cloud.bucket_name)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            file_key = prefix + file_name
        else:
            file_key = file_name

        blob = bucket.blob(file_key)

        blob.upload_from_filename(local_zip)

        blob.reload()

        storage_file_id = file_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageGoogleCloudUploadFailedError(
            stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__()
        )
