import json
import subprocess
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeSnapshotDeleteFailed,
)
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreDatabaseBackup,
)
from apps.console.node.models import CoreNode, CoreServerStatus
from django.core.cache import cache


def storage_bb2(node, backup_name):
    cache_data = cache.get(backup_name, {})
    backup_type = cache_data.get("backup_type")
    attempt_no = cache_data.get("attempt_no")
    storage_id = cache_data.get("storage_id")

    try:
        local_zip = f"_storage/{backup_name}.zip"
        storage = CoreStorageDefault.objects.get(id=storage_id)

        execstr = (
            f"/home/ubuntu/backupsheep/venv/bin/b2 upload-file --noProgress --quiet {storage.bucket_name} {local_zip} {local_zip.replace('_storage/', '', 1)}"
        )
        process = subprocess.Popen(
            execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        stdout, stderr = process.communicate()
        if stderr and stderr != "":
            raise ValueError(stderr)
        stdout_json = json.loads(stdout)
        storage_file_id = stdout_json["fileId"]
        cache_data["storage_file_id"] = storage_file_id
        cache.set(node.current_backup_uuid, cache_data)
    except Exception as e:
        raise NodeBackupFailedError(node, backup_name, attempt_no, backup_type, e.__str__())


def storage_backupsheep_backblaze_b2_delete(node, backup_name):
    try:
        backup = None

        if node.type == CoreNode.Type.WEBSITE:
            backup = CoreWebsiteBackup.objects.get(uuid=backup_name)
        elif node.type == CoreNode.Type.DATABASE:
            backup = CoreDatabaseBackup.objects.get(uuid=backup_name)
        if backup:
            """
            Remove directory from Backblaze B2
            """
            prefix = f"{backup.uuid}/"
            execstr = (
                f"/home/ubuntu/backupsheep/venv/bin/b2 sync --delete"
                f" --allowEmptySource _empty/ b2://{backup.storage_backupsheep.bucket_name}/{prefix}"
            )

            process = subprocess.Popen(
                execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
            process.communicate()

            execstr = (
                f"/home/ubuntu/backupsheep/venv/bin/b2 delete-file-version {backup.storage_file_id}"
            )
            process = subprocess.Popen(
                execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
            process.communicate()

    except Exception as e:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
