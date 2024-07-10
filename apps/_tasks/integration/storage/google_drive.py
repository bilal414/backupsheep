import os
import httplib2
from apiclient import discovery
from googleapiclient.errors import ResumableUploadError
from oauth2client.client import GoogleCredentials

from apps._tasks.exceptions import (
    NodeSnapshotDeleteFailed,
    NodeGoogleDriveUploadFailedError,
    NodeGoogleDriveNotEnoughStorageError, NodeGoogleDriveTooManyRequestsError,
)
from apps.api.v1.utils.api_helpers import bs_encrypt, bs_decrypt
from apps.api.v1.utils.api_mail import *
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup, CoreWordPressBackup,
)
from apps.console.node.models import CoreNode


def storage_google_drive(stored_backup):
    try:
        # sleep(randint(60, 900))

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup
        node_folder = None
        bs_folder = None

        client = storage.storage_google_drive.get_client()

        """
        Find or create BackupSheep folder
        """
        search_params = {
            "q": "name='BackupSheep' and trashed = False and mimeType='application/vnd.google-apps.folder'",
            "fields": "files(id, name, trashed)",
        }

        result = client.get(
            f"https://www.googleapis.com/drive/v3/files",
            params=search_params,
            headers={"Content-Type": "application/json; charset=UTF-8"},
        )

        if result.status_code == 200:
            files = result.json().get("files")

            bs_folder_list = [d['id'] for d in files if d['name'] == 'BackupSheep' and d['trashed'] is False]

            if len(bs_folder_list) > 0:
                bs_folder = bs_folder_list[0]
            else:
                file_metadata = {
                    "name": "BackupSheep",
                    "mimeType": "application/vnd.google-apps.folder",
                    # 'parents': [folder_id]
                }

                file_withmetadata = {"data": ("metadata", json.dumps(file_metadata), "application/json; charset=UTF-8")}

                result = client.post(
                    f"https://www.googleapis.com/upload/drive/v3/files",
                    files=file_withmetadata,
                )

                bs_folder = result.json()["id"]

        if bs_folder:
            """
            Find or create Node folder
            """
            search_params = {
                "q": f"name = '{backup.node.name_slug}' and '{bs_folder}' in parents and trashed = False and mimeType='application/vnd.google-apps.folder'",
                "fields": "files(id, name, trashed)",
            }

            result = client.get(
                f"https://www.googleapis.com/drive/v3/files",
                params=search_params,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )

            if result.status_code == 200:
                files = result.json().get("files")

                node_folder_list = [d['id'] for d in files if d['name'] == 'BackupSheep' and d['trashed'] is False]

                if len(node_folder_list) > 0:
                    node_folder = node_folder_list[0]
                else:
                    file_metadata = {
                        "name": f"{backup.node.name_slug}",
                        "mimeType": "application/vnd.google-apps.folder",
                        'parents': [bs_folder]
                    }

                    file_withmetadata = {
                        "data": ("metadata", json.dumps(file_metadata), "application/json; charset=UTF-8")}

                    result = client.post(
                        f"https://www.googleapis.com/upload/drive/v3/files",
                        files=file_withmetadata,
                    )

                    node_folder = result.json()["id"]

        if bs_folder and node_folder:
            """
            Now upload file.
            """
            file_metadata = {
                "name": f"{stored_backup.backup.uuid_str}.zip",
                "mimeType": "application\zip",
                "parents": [node_folder],
            }

            result = client.post(
                f"https://www.googleapis.com/upload/drive/v3/files/?uploadType=resumable",
                data=json.dumps(file_metadata),
                headers={"Content-Type": "application/json; charset=UTF-8"}
            )

            gdrive_upload_url = result.headers.get("Location")

            with open(local_zip, "rb") as f:
                total_file_size = os.path.getsize(local_zip)
                chunk_size = 2147000000
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
                        "Content-Length": "{}".format(total_file_size),
                        "Content-Range": "bytes {}-{}/{}".format(start_index, end_index - 1, total_file_size),
                    }
                    # Upload one chunk at a time
                    r = client.put(gdrive_upload_url, data=chunk_data, headers=headers, timeout=24*3600)
                    i = i + 1

                    # Chunk accepted
                    if r.status_code == 201 or r.status_code == 200:
                        storage_file_id = r.json()["id"]
                        storage_file_id = storage_file_id
                        stored_backup.storage_file_id = storage_file_id
                        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
                        stored_backup.save()
                    elif r.status_code == 308:
                        # A 308 Resume Incomplete response indicates that you need to continue to upload the file.
                        pass
                    elif r.status_code == 404:
                        # A 404 Not Found response indicates the upload session has expired and
                        # the upload must be restarted from the beginning.
                        raise NodeGoogleDriveUploadFailedError(
                            message="Upload file is missing in Google Drive. We will retry upload.")
                    else:
                        raise NodeGoogleDriveUploadFailedError(
                            message="Unable to get final upload status from Google Drive API.")
        else:
            raise NodeGoogleDriveUploadFailedError(
                message="Unable to get ID of BackupSheep and Node folder in your Google Drive.")

    except ResumableUploadError as e:
        if "quota has been exceeded" in e.__str__().lower():
            raise NodeGoogleDriveNotEnoughStorageError(message=e.__str__())
        elif "too many requests" in e.__str__().lower():
            raise NodeGoogleDriveTooManyRequestsError(message=e.__str__())
        else:
            raise NodeGoogleDriveUploadFailedError(message=e.__str__())
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise NodeGoogleDriveUploadFailedError(message=e.__str__())


def storage_google_drive_delete(node, backup_name):
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
            credentials = GoogleCredentials(
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                token_uri="https://accounts.google.com/o/oauth2/token",
                token_expiry=None,
                access_token=bs_decrypt(
                    backup.storage_byo.storage_google_drive.access_token, encryption_key
                ),
                refresh_token=bs_decrypt(
                    backup.storage_byo.storage_google_drive.refresh_token, encryption_key
                ),
                user_agent="backupsheep-agent/1.0",
            )

            http = credentials.authorize(httplib2.Http())
            credentials.refresh(http)
            backup.storage_byo.storage_google_drive.access_token = (
                credentials.access_token
            )
            backup.storage_byo.storage_google_drive.refresh_token = (
                credentials.refresh_token
            )
            backup.storage_byo.storage_google_drive.save()
            service = discovery.build("drive", "v3", credentials=credentials)
            gd_response = (
                service.files().delete(fileId=backup.storage_file_id).execute()
            )
    except Exception as e:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
