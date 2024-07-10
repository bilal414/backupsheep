import uuid
from azure.storage.blob import BlobBlock
from apps._tasks.exceptions import StorageAzureUploadFailedError


def storage_azure(stored_backup):
    try:
        backup = stored_backup.backup

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"

        storage = stored_backup.storage

        prefix = storage.storage_azure.prefix

        file_name = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        blob_service_client = storage.storage_azure.get_client()

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"
            file_key = prefix + file_name
        else:
            file_key = file_name

        blob_client = blob_service_client.get_blob_client(container=storage.storage_azure.bucket_name, blob=file_key)

        # check this if you get large file upload error
        # https://xhinker.medium.com/how-to-upload-large-files-to-azure-blob-storage-with-python-dacf2b969a90
        block_list = []
        chunk_size = 1024 * 1024 * 4
        with open(local_zip, "rb") as f:
            while True:
                read_data = f.read(chunk_size)
                if not read_data:
                    break  # done
                blk_id = str(uuid.uuid4())
                blob_client.stage_block(block_id=blk_id, data=read_data)
                block_list.append(BlobBlock(block_id=blk_id))
        blob_client.commit_block_list(block_list)

        storage_file_id = file_key
        stored_backup.storage_file_id = storage_file_id
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
    except FileNotFoundError as e:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save()
    except Exception as e:
        raise StorageAzureUploadFailedError(
            stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__()
        )
