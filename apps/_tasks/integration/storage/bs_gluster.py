import os
import subprocess
import time

import paramiko
from paramiko.ssh_exception import SSHException
from sentry_sdk import capture_exception, capture_message
from apps._tasks.exceptions import (
    NodeBackupSheepUploadFailedError,
    NodeBackupFailedError,
)


def storage_bs_gluster(stored_backup):
    backup = stored_backup.backup
    local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
    storage = stored_backup.storage

    try:
        node = None

        if hasattr(backup, "website"):
            node = getattr(backup, "website").node
        elif hasattr(backup, "database"):
            node = getattr(backup, "database").node
        elif hasattr(backup, "wordpress"):
            node = getattr(backup, "wordpress").node

        # This is directory in this case
        directory = f"/mnt/{storage.storage_bs.bucket_name}/{storage.storage_bs.prefix}"

        # This is server hostname
        hostname = storage.storage_bs.endpoint
        port = 22
        ssh_username = "root"

        working_dir = f"/home/ubuntu/backupsheep"

        docker_full_path = f"{working_dir}/_storage"

        # Stop any old container
        execstr = f"sudo docker stop {backup.uuid}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3600,
            shell=True,
        )

        lftp_version_path = f"sudo docker run --rm -v {docker_full_path}:{docker_full_path} --name {backup.uuid}-storage -t bs-lftp"

        protocol = "sftp"

        parallel = 3

        ssh_key_path = f"/home/ubuntu/backupsheep/_storage/ssh_storage_{backup.uuid}"

        # Copy SSH Key
        execstr = f"cp /home/ubuntu/.ssh/id_rsa {ssh_key_path}"
        process = subprocess.Popen(execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()
        process.terminate()

        lftp = {
            "host": f"{protocol}://{hostname}",
            "user": ssh_username,
            "port": port,
            "target": f"{working_dir}/{local_zip}",
            "source": f"{directory}",
        }

        execstr = (
            f"{lftp_version_path} -c '\n"
            f"set ssl:verify-certificate no\n"
            f"set net:reconnect-interval-base 5\n"
            f"set net:max-retries 2\n"
            f"set ftp:ssl-allow true\n"
            f"set sftp:auto-confirm true\n"
            f'set sftp:connect-program "ssh -a -x -p {lftp["port"]} -l "{lftp["user"]}" -i {ssh_key_path}"\n'
            f"set net:connection-limit {parallel}\n"
            f"set ftp:ssl-protect-data true\n"
            f"set ftp:use-mdtm off\n"
            f"set mirror:set-permissions off\n"
            f"open -p {lftp['port']} {lftp['host']}\n"
            f"mkdir {directory}\n"
            f'put -O "{lftp["source"]}" "{lftp["target"]}"\n'
            f"bye\n'"
        )

        process = subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=43200,
            universal_newlines=True,
            encoding="utf-8",
            errors="ignore",
            shell=True,
        )

        for line in process.stdout.splitlines():
            cleaned_line = line.replace(
                "/home/ubuntu/backupsheep/_storage/", ""
            )
            if (
                (
                    "fatal error" in cleaned_line.lower()
                    or "too many" in cleaned_line.lower()
                )
                or "docker: error" in cleaned_line.lower()
                or "login failed" in cleaned_line.lower()
                or "invalid preceding regular expression" in cleaned_line.lower()
                or "login incorrect" in cleaned_line.lower()
            ):
                if node:
                    node.connection.account.create_backup_log(
                        cleaned_line, node, backup
                    )
                raise NodeBackupFailedError(
                    node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=cleaned_line,
                )

        storage_file_id = f"{stored_backup.backup.uuid}.zip"

        """
        Validate Backups
        """
        stored_backup.status = stored_backup.Status.UPLOAD_VALIDATION
        stored_backup.save()

        check_counter = 0

        while stored_backup.status != stored_backup.Status.UPLOAD_COMPLETE:
            if check_counter > 60:
                raise ValueError("Unable to validate file on storage pool after 60 attempts"
                                 " remote storage is different. We will upload again and retry validation.")
            else:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path)
                    ssh.connect(
                        hostname,
                        auth_timeout=180,
                        banner_timeout=180,
                        timeout=180,
                        port=int(port),
                        username=ssh_username,
                        pkey=pkey,
                    )
                    sftp = ssh.open_sftp()
                    response = sftp.stat(f"{directory}{storage_file_id}")
                    storage_backup_size = response.st_size
                    sftp.close()
                    ssh.close()

                    if storage_backup_size == backup.size:
                        stored_backup.storage_file_id = storage_file_id
                        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
                        stored_backup.save()
                    else:
                        raise ValueError("File size on local and remote storage is different.")
                except SSHException as e:
                    if "error reading ssh protocol banner" in e.__str__().lower():
                        pass
                    else:
                        raise ValueError(e.__str__())

            check_counter += 1
            time.sleep(60)

        """
        Delete temp SSH Key
        """
        if ssh_key_path:
            if os.path.exists(ssh_key_path):
                os.remove(ssh_key_path)
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
    finally:
        """
        Stop any docker container
        """
        # Stop any old container
        execstr = f"sudo docker stop {backup.uuid}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3600,
            shell=True,
        )