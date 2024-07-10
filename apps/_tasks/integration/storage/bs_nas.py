import subprocess
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupSheepUploadFailedError
from apps.api.v1.utils.api_helpers import bs_decrypt


def storage_bs_nas(stored_backup):
    try:
        # 24 hours
        command_timeout = 2 * 24 * 3600

        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"

        storage = stored_backup.storage
        backup = stored_backup.backup
        encryption_key = storage.account.get_encryption_key()
        remote_file_path = f"{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"

        username = bs_decrypt(storage.storage_bs.username, encryption_key)
        password = bs_decrypt(storage.storage_bs.password, encryption_key)
        host = storage.storage_bs.host

        working_dir = f"/home/ubuntu/backupsheep"
        docker_full_path = f"{working_dir}/_storage"
        lftp_version_path = f"sudo docker run --rm -v {docker_full_path}:{docker_full_path} --name upload-{backup.uuid} -t bs-lftp"

        execstr = (
            f"{lftp_version_path} -c '\n"
            f"set ftps:initial-prot P\n"
            f"set ssl:verify-certificate no\n"
            f"set net:reconnect-interval-base 5\n"
            f"set net:max-retries 2\n"
            f"set ftp:ssl-allow true\n"
            f"set sftp:auto-confirm true\n"
            f"set net:connection-limit 10\n"
            f"set ftp:ssl-protect-data true\n"
            f"set ftp:use-mdtm off\n"
            f"set mirror:set-permissions off\n"
            f"open -p 21 ftp://{host}\n"
            f'user "{username}" "{password}"\n'
            f'mkdir -pf "{backup.node.name_slug}"\n'
            f'put -c -O "{backup.node.name_slug}" "{working_dir}/{local_zip}"\n'
            f'ls -la "{backup.node.name_slug}/{stored_backup.backup.uuid}.zip"\n'
            f"bye\n'"
        )

        process = subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command_timeout,
            universal_newlines=True,
            encoding='utf-8',
            errors="ignore",
            shell=True
        )

        for line in process.stdout.splitlines():
            cleaned_line = line.replace(
                "/home/ubuntu/backupsheep/", ""
            )
            if "fatal error" in cleaned_line.lower():
                raise NodeBackupSheepUploadFailedError(
                    stored_backup.backup.uuid_str,
                    stored_backup.backup.attempt_no,
                    stored_backup.backup.type,
                    cleaned_line,
                )
        stored_backup.storage_file_id = remote_file_path
        stored_backup.status = stored_backup.Status.UPLOAD_COMPLETE
        stored_backup.save()
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
