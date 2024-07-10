import subprocess
import os
import requests
from sentry_sdk import capture_exception
import hashlib
from apps._tasks.exceptions import NodeBackupFailedError
from apps.api.v1.utils.api_helpers import check_string_in_file, aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import mkdir_p
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import UtilBackup
import time


def snapshot_wordpress(backup):
    node = backup.wordpress.node
    encryption_key = node.connection.account.get_encryption_key()
    account = node.connection.account

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    working_dir = f"/home/ubuntu/backupsheep"
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
    tree_log_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}-dir-tree.log"

    try:
        """
        Checking for connection
        """
        node.connection.auth_wordpress.validate()

        """
        Trigger Backup in WordPress UpdraftPlus plugin
        """
        client = node.connection.auth_wordpress.get_client()
        auth = node.connection.auth_wordpress.get_auth()

        try:
            url = f"{node.connection.auth_wordpress.url}" \
                  f"/?rest_route=/backupsheep/updraftplus" \
                  f"/backup&backup_uuid={backup.uuid_str}" \
                  f"&key={node.connection.auth_wordpress.key}" \
                  f"&include={node.wordpress.include}" \
                  f"&t={time.time()}"

            log_file.write(f"Tigger Backup: {url} \n")

            # We don't need to wait for this
            requests.get(
                url,
                auth=auth,
                headers=client,
                verify=False,
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
                url = f"{node.connection.auth_wordpress.url}" \
                      f"/?rest_route=/backupsheep/updraftplus/status&backup_uuid={backup.uuid_str}" \
                      f"&key={node.connection.auth_wordpress.key}" \
                      f"&t={time.time()}"
                log_file.write(f"Check backup status: {url} \n")
                result = requests.get(
                    url,
                    auth=auth,
                    headers=client,
                    verify=False,
                    timeout=180,
                )
                updraft_log_file = result.json().get("log_file")
                status = result.json().get("status")

                msg = f"Check counter no {check_counter}. Backup status: {status} Logfile: {updraft_log_file}."
                log_file.write(f"INFO: {msg} \n")

                if status:
                    backup_status = True

                    msg = f"Backup is complete. Validation using status flag from API."
                    log_file.write(f"INFO: {msg} \n")
                elif updraft_log_file:
                    # download the log file
                    url = f"{node.connection.auth_wordpress.url}" \
                          f"/?rest_route=/backupsheep/updraftplus/download&backup_file={updraft_log_file}" \
                          f"&key={node.connection.auth_wordpress.key}" \
                          f"&t={time.time()}"
                    log_file.write(f"Download updraft backup log: {url} \n")
                    r = requests.get(
                        url,
                        auth=auth,
                        headers=client,
                        verify=False,
                        allow_redirects=True,
                        stream=True,
                    )
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
                    msg = f"Unable to find log UpdraftPlus file in WordPress to validate status." \
                          f"Check counter no {check_counter}. Backup status: {status} Logfile: {updraft_log_file}."
                    log_file.write(f"INFO: {msg} \n")

                    raise NodeBackupFailedError(
                        node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        message=f"Unable to find log UpdraftPlus file in WordPress to validate status",
                    )
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

        url = f"{node.connection.auth_wordpress.url}" \
              f"/?rest_route=/backupsheep/updraftplus/files&backup_uuid={backup.uuid_str}" \
              f"&t={time.time()}" \
              f"&key={node.connection.auth_wordpress.key}"

        log_file.write(f"Get list of backup files: {url} \n")

        result = requests.get(
            url,
            auth=auth,
            headers=client,
            verify=False,
            timeout=180,
        )
        if result.status_code == 200:
            msg = f"We have list of backup files."
            log_file.write(f"INFO: {msg} \n")

            # We have change name names of file to add MD5 so files can be restored.
            md5_code = hashlib.md5(str(int(time.time())).encode()).hexdigest()[0:12]

            backup_files = result.json()["files"]
            for backup_file in backup_files:
                url = f"{node.connection.auth_wordpress.url}" \
                      f"/?rest_route=/backupsheep/updraftplus/download&backup_file={backup_file}" \
                      f"&key={node.connection.auth_wordpress.key}" \
                      f"&t={time.time()}"

                # download the file
                msg = f"Downloading file: {backup_file} using URL {url}"
                log_file.write(f"Downloading file: {backup_file} using URL {url} \n")

                r = requests.get(
                    url,
                    auth=auth,
                    headers=client,
                    verify=False,
                    allow_redirects=True,
                    stream=True,
                )
                # save downloaded file
                backup_file_alt = backup_file.replace(backup.uuid_str, md5_code)

                '''
                Sometime .gz files are sent by server as text. So we will add .zip so we can download it.
                It will be renamed back to .gz on BackupSheep server.
                This happens only to database backup files.
                '''
                if backup_file_alt.endswith('-db.gz.zip'):
                    backup_file_alt.replace("-db.gz.zip", "-db.gz")

                with open(f"{local_dir}{backup_file_alt}", "wb") as b_file:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            b_file.write(chunk)

                msg = f"Saved file as: {backup_file_alt}"
                log_file.write(f"INFO: {msg} \n")

            '''
            We downloaded all files. Now we we will delete files. 
            '''
            for backup_file in backup_files:
                url = f"{node.connection.auth_wordpress.url}" \
                      f"/?rest_route=/backupsheep/updraftplus/delete&backup_file={backup_file}" \
                      f"&backup_uuid={backup.uuid_str}&key={node.connection.auth_wordpress.key}" \
                      f"&t={time.time()}"

                log_file.write(f"Delete file: {url} \n")

                r_delete = requests.get(
                    url,
                    auth=auth,
                    headers=client,
                    verify=False,
                    allow_redirects=True,
                )

                if r_delete.status_code == 200:
                    if r_delete.json().get("deleted"):
                        msg = f"Deleted file from WordPress: {backup_file} using URL: {url}"
                        log_file.write(f"INFO: {msg} \n")
                    else:
                        msg = f"Unable to delete file from WordPress: {backup_file} using URL: {url}"
                        log_file.write(f"INFO: {msg} \n")
                else:
                    msg = f"Unable to delete file from WordPress: {backup_file} using URL: {url}"
                    log_file.write(f"INFO: {msg} \n")
        else:
            msg = f"Unable to get list of files from API call {url}"
            log_file.write(f"INFO: {msg} \n")

            raise NodeBackupFailedError(
                node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                message=msg,
            )

        # Rebuild backup history on Updraft
        url = f"{node.connection.auth_wordpress.url}"
        f"/?rest_route=/backupsheep/updraftplus/rebuild_history"
        f"&t={time.time()}"
        f"&key={node.connection.auth_wordpress.key}"
        requests.get(
            url,
            auth=auth,
            headers=client,
            verify=False,
            timeout=180,
        )
        log_file.write(f"Rebuild backup history on Updraft: {msg} \n")

        # Update Permissions
        execstr = f"sudo chown ubuntu:ubuntu ../{backup.uuid_str} -R"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=43200,
            shell=True,
            cwd=local_dir,
        )

        # ZIP all downloaded files.
        execstr = f"/usr/bin/zip -y -r ../{backup.uuid_str} . -i \*"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=43200,
            shell=True,
            cwd=local_dir,
        )

        # Generate Report
        try:
            execstr = f"sudo tree -a -f -h -F -v -i -N -n -o {tree_log_path}"

            subprocess.run(
                execstr,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                timeout=900,
                cwd=local_dir
            )
            log_file.write(f"---Directory Tree--- \n")

            # open both files
            with open(tree_log_path, 'r', errors="ignore") as tree_log_file:
                for line in tree_log_file:
                    log_file.write(f"{line} \n")
            os.remove(tree_log_path)
        except Exception as e:
            capture_exception(e)

        if os.path.exists(local_zip):
            backup.size = os.stat(local_zip).st_size
            backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
            backup.save()
            log_file.write(f"Size (compressed): {backup.size_display()} \n")


        """
        Delete directory because no need for it now that we have zip
        """
        queue = f"delete_from_disk__{node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
            queue=queue,
        )
    except Exception as e:
        log_file.write(f"Error: {e.__str__()} \n")
        capture_exception(e)
        """
        Delete files
        """
        queue = f"delete_from_disk__{node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
            queue=queue,
        )
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, e.__str__()
        )
    finally:
        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()

        # Upload first part of file here. Second will be pushed when files are uploaded.
        if os.path.exists(log_file_path):
            aws_s3_upload_log_file(log_file_path, f"{backup.uuid}.log")