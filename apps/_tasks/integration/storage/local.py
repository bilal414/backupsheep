import os
import shutil

from apps._tasks.exceptions import (
    StorageLocalUploadFailedError,
)


def storage_local(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup

        target_dir = storage.storage_local.resolve_path()
        os.makedirs(target_dir, exist_ok=True)

        target_file = os.path.join(target_dir, f"{backup.uuid}.zip")
        source_size = os.path.getsize(local_zip)

        with open(local_zip, "rb") as src, open(target_file, "wb") as dst:
            shutil.copyfileobj(src, dst)

        if os.path.getsize(target_file) != source_size:
            raise IOError(
                f"Size mismatch after copy to {target_file}: expected "
                f"{source_size} bytes, got {os.path.getsize(target_file)} bytes."
            )

        storage_file_id = os.path.abspath(target_file)
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageLocalUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
