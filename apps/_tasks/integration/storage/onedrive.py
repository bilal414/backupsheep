import os

import requests
from django.conf import settings
from apps._tasks.exceptions import (
    NodeOneDriveUploadFailedError,
)


def storage_onedrive(stored_backup):
    storage_file_id = None

    try:
        storage = stored_backup.storage
        backup = stored_backup.backup

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"

        target_file_path = f"backupsheep/{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        file_size = os.stat(local_zip).st_size
        file_data = open(local_zip, "rb")
        onedrive_destination = f"{settings.MS_GRAPH_ENDPOINT}/drives/{storage.storage_onedrive.drive_id}/root:/{target_file_path}"

        if file_size < 6553600:
            # Perform is simple upload to the API
            r = requests.put(
                onedrive_destination + ":/content", data=file_data, headers=storage.storage_onedrive.get_client()
            )
            if r.status_code == 201 or r.status_code == 200:
                storage_file_id = target_file_path
            else:
                raise NodeOneDriveUploadFailedError(
                    stored_backup.backup.uuid_str,
                    stored_backup.backup.attempt_no,
                    stored_backup.backup.type,
                )
        else:
            # Creating an upload session
            upload_session = requests.post(
                onedrive_destination + ":/createUploadSession", headers=storage.storage_onedrive.get_client()
            ).json()

            with open(local_zip, "rb") as f:
                total_file_size = os.path.getsize(local_zip)
                chunk_size = 6553600
                chunk_number = total_file_size // chunk_size
                chunk_leftover = total_file_size - chunk_size * chunk_number
                i = 0
                while True:
                    chunk_data = f.read(chunk_size)
                    start_index = i * chunk_size
                    end_index = start_index + chunk_size
                    # If end of file, break
                    if not chunk_data:
                        break
                    if i == chunk_number:
                        end_index = start_index + chunk_leftover
                    # Setting the header with the appropriate chunk data location in the file
                    headers = {
                        "Content-Length": "{}".format(chunk_size),
                        "Content-Range": "bytes {}-{}/{}".format(start_index, end_index - 1, total_file_size),
                    }
                    # Upload one chunk at a time
                    r = requests.put(upload_session["uploadUrl"], data=chunk_data, headers=headers)
                    i = i + 1

                    # Chunk accepted
                    if r.status_code == 202:
                        pass
                    # File created
                    elif r.status_code == 201:
                        storage_file_id = target_file_path
                    else:
                        raise NodeOneDriveUploadFailedError(
                            stored_backup.backup.uuid_str,
                            stored_backup.backup.attempt_no,
                            stored_backup.backup.type,
                        )
        file_data.close()

        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise NodeOneDriveUploadFailedError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            e.__str__(),
        )
