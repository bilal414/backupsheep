from django.conf import settings
from sentry_sdk import capture_exception
from apps._tasks.exceptions import (
    NodeBackupSheepUploadFailedError,
)
import json
from google.oauth2 import service_account
from google.cloud import storage as gc_storage


def bs_google_cloud(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup
        encryption_key = storage.account.get_encryption_key()

        service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)

        credentials = service_account.Credentials.from_service_account_info(service_key_json)

        storage_client = gc_storage.Client(credentials=credentials)
        bucket = storage_client.bucket(storage.storage_bs.bucket_name)

        file_name = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        if storage.storage_bs.prefix:
            object_key = storage.storage_bs.prefix + file_name
        else:
            object_key = file_name

        blob = bucket.blob(object_key)

        blob.upload_from_filename(local_zip)

        blob.reload()

        storage_file_id = object_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        capture_exception(e)
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        capture_exception(e)
        raise NodeBackupSheepUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
