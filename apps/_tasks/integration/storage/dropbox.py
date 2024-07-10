import dropbox
import os

from django.conf import settings
from dropbox.files import WriteMode

from apps._tasks.exceptions import (
    NodeSnapshotDeleteFailed,
    NodeDropboxUploadFailedError,
    NodeDropboxNotEnoughStorageError,
    NodeDropboxFileIDMissingError,
    NodeDropboxTokenExpiredError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
    CoreWordPressBackup,
)
from apps.console.node.models import CoreNode


def storage_dropbox(stored_backup):
    storage_file_id = None

    try:
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"

        file_size = os.path.getsize(local_zip)
        # Files uploaded through the API must be 350GB or smaller.
        chunk_size = 157286400
        dest_path = f"/{stored_backup.backup.uuid}.zip"
        access_token = bs_decrypt(stored_backup.storage.storage_dropbox.access_token, encryption_key)
        refresh_token = bs_decrypt(stored_backup.storage.storage_dropbox.refresh_token, encryption_key)

        dbx = dropbox.Dropbox(
            oauth2_access_token=access_token,
            oauth2_refresh_token=refresh_token,
            app_key=settings.DROPBOX_APP_KEY,
            app_secret=settings.DROPBOX_APP_SECRET,
            timeout=900 * 2,
        )

        with open(local_zip, "rb") as file_to_upload:
            if file_size <= chunk_size:
                dbx_file = dbx.files_upload(
                    file_to_upload.read(),
                    str(dest_path),
                    dropbox.files.WriteMode.overwrite,
                )
                storage_file_id = dbx_file.id
            else:
                upload_session_start_result = dbx.files_upload_session_start(
                    file_to_upload.read(chunk_size)
                )
                session_id = upload_session_start_result.session_id
                cursor = dropbox.files.UploadSessionCursor(
                    session_id, offset=file_to_upload.tell()
                )
                commit = dropbox.files.CommitInfo(
                    path=dest_path, mode=dropbox.files.WriteMode.overwrite
                )
                while file_to_upload.tell() < file_size:
                    if (file_size - file_to_upload.tell()) <= chunk_size:
                        dbx_file = dbx.files_upload_session_finish(
                            file_to_upload.read(chunk_size), cursor, commit
                        )
                        storage_file_id = dbx_file.id
                    else:
                        dbx.files_upload_session_append_v2(
                            file_to_upload.read(chunk_size), cursor
                        )
                        # This is needed to upload. Ignore read only warning
                        cursor.offset = file_to_upload.tell()
        try:
            dbx.sharing_create_shared_link_with_settings(dest_path)
        except:
            pass

        if not storage_file_id:
            raise NodeDropboxFileIDMissingError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
            )

        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        if "insufficient_space" in e.__str__():
            raise NodeDropboxNotEnoughStorageError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
                e.__str__(),
            )
        elif "expired_access_token" in e.__str__():
            raise NodeDropboxTokenExpiredError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
                e.__str__(),
            )
        else:
            raise NodeDropboxUploadFailedError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
                e.__str__(),
            )


def storage_dropbox_delete(node, backup_name):
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
            dbx = dropbox.Dropbox(
                bs_decrypt(
                    backup.storage_byo.storage_dropbox.access_token, encryption_key
                )
            )

            dbx = dropbox.Dropbox(
                bs_decrypt(
                    backup.storage_byo.storage_dropbox.access_token, encryption_key
                )
            )

            file_path = dbx.files_get_metadata(backup.storage_file_id).path_lower

            dbx.files_delete_v2(file_path)
    except Exception as e:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
