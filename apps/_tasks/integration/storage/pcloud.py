import mimetypes
import os

import requests
from pcloud import PyCloud
from requests_toolbelt import MultipartEncoder

from apps._tasks.exceptions import StoragePCloudUploadFailedError


def storage_pcloud(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        backup = stored_backup.backup

        file_name = f"{stored_backup.backup.uuid}.zip"

        # create node folder if it doesn't exist
        requests.post(
            f"https://{storage.storage_pcloud.hostname}/createfolderifnotexists?path=/{backup.node.name_slug}",
            headers=storage.storage_pcloud.get_client(),
            verify=True,
        )

        pc = PyCloud(
            username=storage.storage_pcloud.userid,
            password=storage.storage_pcloud.get_access_token(),
            endpoint=storage.storage_pcloud.hostname.split(".")[0],
            oauth2=True,
        )

        result = pc.uploadfile(files=[local_zip], path=f"/{backup.node.name_slug}")

        if result.get("metadata"):
            metadata = result.get("metadata")[0]
            if metadata.get("fileid"):
                stored_backup.storage_file_id = metadata.get("path")
                stored_backup.metadata = metadata
                stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
                stored_backup.save()
        else:
            raise StoragePCloudUploadFailedError(
                stored_backup.backup.uuid_str,
                stored_backup.backup.attempt_no,
                stored_backup.backup.type,
                result,
            )
    except Exception as e:
        raise StoragePCloudUploadFailedError(
            stored_backup.backup.uuid_str, stored_backup.backup.attempt_no, stored_backup.backup.type, e.__str__()
        )
