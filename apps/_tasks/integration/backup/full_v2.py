import os
from sentry_sdk import capture_exception
import subprocess
from apps._tasks.exceptions import NodeBackupFailedError, NodeBackupTimeoutError
from apps.api.v1.utils.api_helpers import aws_s3_upload_log_file, mkdir_p
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import UtilBackup


def snapshot_full_v2(backup):
    node = backup.website.node
    auth_website = node.connection.auth_website

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_zip = f"_storage/{backup.uuid}.zip"
    local_dir = f"_storage/{backup.uuid}/"
    mkdir_p(local_dir)

    # Backup Log
    log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")

    # backup files log
    backup_file_list_path = f"{local_dir}{backup.uuid}.files"
    backup_file_list = open(backup_file_list_path, "a+")

    # 24 hours
    command_timeout = 24 * 3600

    try:
        # capture_message(f'Executing snapshot_website id {backup.uuid}')
        sources = []

        for path in node.website.paths:
            sources.append(path["path"])

        exclude_rules = '--exclude=="*.sock"'

        if node.website.tar_exclude_vcs_ignores:
            exclude_rules += f" --exclude-vcs-ignores"

        if node.website.tar_exclude_vcs:
            exclude_rules += f" --exclude-vcs"

        if node.website.tar_exclude_backups:
            exclude_rules += f" --exclude-backups"

        if node.website.tar_exclude_caches:
            exclude_rules += f" --exclude-caches"

        if node.website.excludes_glob:
            for glob in node.website.excludes_glob:
                exclude_rules += f' --exclude="{glob}"'

        """
        Checking for connection
        """
        auth_website.check_connection()

        sftp, ssh, ssh_key_path = auth_website.get_sftp_client()

        # BackupSheep directory path on user server
        bs_backup_directory = f"{node.website.tar_temp_backup_dir}/{node.uuid_str}"
        bs_backup_tar = f"{bs_backup_directory}/{backup.uuid_str}.tar"
        bs_backup_snar = f"{node.website.tar_temp_backup_dir}/{node.uuid_str}.snar"
        bs_backup_sources = " ".join('"{0}"'.format(x).strip() for x in sources)

        # sftp.mkdir(bs_backup_directory)

        # Create backup directory
        _stdin, _stdout, _stderr = ssh.exec_command(f"mkdir -p {bs_backup_directory}")
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        # Remove any existing backup tar
        _stdin, _stdout, _stderr = ssh.exec_command(f"rm -rf {bs_backup_tar}")
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        command = f'tar --create --no-check-device --file="{bs_backup_tar}" {bs_backup_sources}'
        _stdin, _stdout, _stderr = ssh.exec_command(command, timeout=command_timeout)
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        # signed_url = google_cloud_signed_upload_url(f"{node.uuid_str}/{backup.uuid_str}.tar.gz")
        #
        # # Upload file directory from user server to BackupSheep storage
        # _stdin, _stdout,_stderr = ssh.exec_command(f"curl -X PUT -H 'Content-Type: application/octet-stream' --upload-file {bs_backup_tar} '{signed_url}'", timeout=command_timeout)
        # _stdout.channel.set_combine_stderr(True)
        # output = _stdout.readlines()

        # Download Backup file
        sftp.get(bs_backup_tar, f"{local_dir}{backup.uuid}.tar")

        # Cleanup files from remote server.
        sftp.remove(bs_backup_tar)

        """
        Get list of files in tar and upload it. 
        """
        backup.total_files = 0

        execstr = f'tar -list --file="{backup.uuid}.tar"'
        process = subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            shell=True,
            cwd=local_dir,
            universal_newlines=True,
        )
        for line in process.stdout.splitlines():
            backup_file_list.write(f"{line}\n")
            if not line.endswith("/"):
                backup.total_files += 1
        backup.save()

        """
        Upload copy of files to bs storage.
        """
        if os.path.exists(backup_file_list_path):
            aws_s3_upload_log_file(backup_file_list_path, f"{backup.uuid}.files")
            backup_file_list.close()

        """
        Create final backup zip folder
        """
        execstr = f"/usr/bin/zip -y -r ../{backup.uuid_str} . -i \*"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            shell=True,
            cwd=local_dir,
        )

        if os.path.exists(local_zip):
            backup.size = os.stat(local_zip).st_size
            backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
            backup.save()
            log_file.write(f"Size (compressed): {backup.size_display()} \n")

        """
        Delete temp SSH Key
        """
        if ssh_key_path:
            if os.path.exists(ssh_key_path):
                os.remove(ssh_key_path)

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

        error = e.__str__()
        if "timed out after" in e.__str__():
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        else:
            raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, error)
    finally:
        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()
