import subprocess
import os
from sentry_sdk import capture_exception
from apps._tasks.integration.backup.errors import safe_backup_failure
import hashlib
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.backup._archive import create_zip
from apps.api.v1.utils.api_helpers import check_string_in_file, aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import mkdir_p, safe_basename
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import BackupExecutionLeaseLostError, UtilBackup
import time


_WORDPRESS_SUCCESS_STATUSES = frozenset({
    "backup_complete",
    "backup_completed",
    "complete",
    "completed",
    "success",
    "successful",
    "succeeded",
})
_WORDPRESS_FAILURE_STATUSES = frozenset({
    "backup_error",
    "backup_failed",
    "cancelled",
    "canceled",
    "error",
    "errored",
    "failed",
    "failure",
})

def snapshot_wordpress(backup):
    node = backup.wordpress.node
    auth_wordpress = node.connection.auth_wordpress

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    working_dir = f"."
    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)

    # Backup Log
    log_file_path = f"{working_dir}/_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")
    tree_log_path = f"_storage/{backup.uuid}-dir-tree.log"

    try:
        """
        Checking for connection
        """
        auth_wordpress.validate()

        """
        Trigger Backup in WordPress UpdraftPlus plugin
        """
        try:
            log_file.write("Trigger WordPress backup request.\n")

            # We don't need to wait for this
            auth_wordpress.request(
                "backup",
                params={
                    "backup_uuid": backup.uuid_str,
                    "include": node.wordpress.include,
                    "t": time.time(),
                },
                timeout=3600,
            )
        except Exception as e:
            msg = f"Timeout for /?rest_route=/backupsheep/updraftplus/backup&backup_uuid={backup.uuid_str}" \
                  f"&t={time.time()}" \
                  f"No worries. We can check backup status using log file."
            log_file.write(f"INFO: {msg} \n")

        backup_status = None
        check_counter = 0

        while not backup_status:
            if check_counter <= 1440:
                log_file.write("Check WordPress backup status.\n")
                result = auth_wordpress.request(
                    "status",
                    params={"backup_uuid": backup.uuid_str, "t": time.time()},
                    timeout=180,
                )
                result.raise_for_status()
                # Strip any directory component the remote site may include so it cannot
                # be used to write/read outside the backup's _storage directory.
                status_payload = result.json()
                updraft_log_file = safe_basename(status_payload.get("log_file"))
                status = status_payload.get("status")
                normalized_status = str(status or "").strip().lower()

                msg = f"Check counter no {check_counter}. Backup status: {status} Logfile: {updraft_log_file}."
                log_file.write(f"INFO: {msg} \n")

                if normalized_status in _WORDPRESS_FAILURE_STATUSES:
                    raise NodeBackupFailedError(
                        node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        message=f"WordPress backup failed with status: {status}",
                    )
                if normalized_status in _WORDPRESS_SUCCESS_STATUSES:
                    backup_status = True

                    msg = f"Backup is complete. Validated status flag from API: {status}."
                    log_file.write(f"INFO: {msg} \n")
                elif updraft_log_file:
                    # download the log file
                    log_file.write("Download UpdraftPlus backup log.\n")
                    r = auth_wordpress.request(
                        "download",
                        params={
                            "backup_file": updraft_log_file,
                            "t": time.time(),
                        },
                        stream=True,
                    )
                    r.raise_for_status()
                    # save downloaded log file
                    with open(f"{local_dir}{updraft_log_file}", "wb") as b_file:
                        for chunk in r.iter_content(chunk_size=1024):
                            if chunk:
                                b_file.write(chunk)

                    if check_string_in_file(f"{local_dir}{updraft_log_file}", ") The backup apparently succeeded") \
                            and check_string_in_file(f"{local_dir}{updraft_log_file}", "and is now complete"):
                        backup_status = True

                        msg = f"Backup is complete. Validation using log file: {updraft_log_file}."
                        log_file.write(f"INFO: {msg} \n")
                else:
                    msg = (
                        "WordPress returned a non-terminal backup status without a log. "
                        f"Check counter no {check_counter}. Backup status: {status}."
                    )
                    log_file.write(f"INFO: {msg} \n")
            else:
                msg = f"Giving up on status checking. Backup status is considered a failure. " \
                      f"Check counter no {check_counter}."
                log_file.write(f"INFO: {msg} \n")

                raise NodeBackupFailedError(
                    node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=f"Unable to find log UpdraftPlus file in WordPress to validate status",
                )
            check_counter += 1
            time.sleep(15)

        log_file.write("Get list of WordPress backup files.\n")
        result = auth_wordpress.request(
            "files",
            params={"backup_uuid": backup.uuid_str, "t": time.time()},
            timeout=180,
        )
        result.raise_for_status()
        msg = "We have list of backup files."
        log_file.write(f"INFO: {msg} \n")

        # We have changed the file names to add MD5 so files can be restored.
        md5_code = hashlib.md5(str(int(time.time())).encode()).hexdigest()[0:12]

        backup_files = []
        for remote_file in result.json().get("files", []):
            if not isinstance(remote_file, str):
                continue
            backup_file = safe_basename(remote_file, fallback="")
            if backup_file:
                backup_files.append(backup_file)
        if not backup_files:
            raise NodeBackupFailedError(
                node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                message="WordPress returned no backup files.",
            )

        for backup_file in backup_files:
            log_file.write(f"Downloading WordPress file: {backup_file}.\n")
            r = auth_wordpress.request(
                "download",
                params={"backup_file": backup_file, "t": time.time()},
                stream=True,
            )
            r.raise_for_status()
            # Strip any directory component the remote site may include so the write
            # stays inside the backup's _storage directory.
            backup_file_alt = safe_basename(backup_file.replace(backup.uuid_str, md5_code))

            # Some servers return database .gz files with a .zip suffix.
            if backup_file_alt.endswith("-db.gz.zip"):
                backup_file_alt = backup_file_alt.replace("-db.gz.zip", "-db.gz")

            with open(f"{local_dir}{backup_file_alt}", "wb") as b_file:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        b_file.write(chunk)

            log_file.write(f"INFO: Saved file as: {backup_file_alt} \n")

        # We downloaded all files; now remove the remote copies.
        for backup_file in backup_files:
            log_file.write(f"Delete WordPress file: {backup_file}.\n")
            r_delete = auth_wordpress.request(
                "delete",
                params={
                    "backup_file": backup_file,
                    "backup_uuid": backup.uuid_str,
                    "t": time.time(),
                },
            )
            r_delete.raise_for_status()
            if not r_delete.json().get("deleted"):
                raise NodeBackupFailedError(
                    node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=f"WordPress did not delete backup file: {backup_file}",
                )
            log_file.write(f"INFO: Deleted file from WordPress: {backup_file}.\n")

        # Rebuild backup history on Updraft
        rebuild_result = auth_wordpress.request(
            "rebuild_history",
            params={"t": time.time()},
            timeout=180,
        )
        rebuild_result.raise_for_status()
        log_file.write("Rebuild backup history on UpdraftPlus.\n")

        # ZIP all downloaded files.
        create_zip(
            local_dir,
            local_zip,
            timeout=43200,
            before_publish=backup.ensure_execution_fence,
        )

        # Generate Report
        try:
            subprocess.run(
                [
                    "tree", "-a", "-f", "-h", "-F", "-v", "-i", "-N", "-n",
                    "-o", tree_log_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=900,
                cwd=local_dir,
            )
            log_file.write(f"---Directory Tree--- \n")

            # open both files
            with open(tree_log_path, 'r', errors="ignore") as tree_log_file:
                for line in tree_log_file:
                    log_file.write(f"{line} \n")
            os.remove(tree_log_path)
        except Exception as e:
            capture_exception(e)

        backup.size = os.stat(local_zip).st_size
        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()
        log_file.write(f"Size (compressed): {backup.size_display()} \n")


        """
        Delete directory because no need for it now that we have zip
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
        )
    except BackupExecutionLeaseLostError:
        raise
    except Exception as e:
        capture_exception(e)
        failure = safe_backup_failure(e, stage="wordpress_backup")
        log_file.write(f"Error [{failure.code}]: {failure.detail}\n")
        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
        )
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, failure.detail
        )
    finally:
        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()

        # Upload first part of file here. Second will be pushed when files are uploaded.
        if os.path.exists(log_file_path):
            aws_s3_upload_log_file(log_file_path, f"{backup.uuid}.log")
