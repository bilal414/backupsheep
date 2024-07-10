import subprocess
import os
import paramiko
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError, NodeBackupTimeoutError
from apps.api.v1.utils.api_helpers import aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.api_helpers import mkdir_p,  create_directory_v2
from apps.console.connection.models import CoreAuthWebsite
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.storage.models import CoreStorageBS
from apps.console.utils.models import UtilBackup


def snapshot_incremental(backup):
    node = backup.website.node
    encryption_key = node.connection.account.get_encryption_key()

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    working_dir = f"/home/ubuntu/backupsheep"
    local_dir = f"_storage/{backup.uuid}/"
    local_dir_incremental = f"{working_dir}/_storage/{node.uuid_str}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)

    # Backup Log
    log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")

    # File
    tree_log_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}-dir-tree.log"

    # 24 hours
    command_timeout = 24 * 3600

    try:
        # capture_message(f'Executing snapshot_website id {backup.uuid}')

        """
        Checking for connection
        """
        node.connection.auth_website.check_connection()

        ssh_key_path = None

        if node.connection.auth_website.use_private_key:
            ssh_key_path = f"/home/ubuntu/backupsheep/_storage/ssh_{backup.uuid}"
            ssh_key_file = open(ssh_key_path, "w+")
            ssh_key_file.write(bs_decrypt(node.connection.auth_website.private_key, encryption_key))
            ssh_key_file.close()
        elif node.connection.auth_website.use_public_key:
            ssh_key_path = f"/home/ubuntu/backupsheep/_storage/ssh_{backup.uuid}"
            execstr = f"cp {settings.SSH_KEY_PATH} {ssh_key_path}"
            process = subprocess.Popen(execstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            process.communicate()
            process.terminate()
        # option_skip_no_access = ""
        # if node.website.option_skip_no_access:
        #     option_skip_no_access = "--skip-noaccess"

        """
        LFTP
        """

        sources = []

        # crete sources array with same pattern
        if node.website.all_paths:
            sources.append({"path": ".", "type": "directory"})
        else:
            for path in node.website.paths:
                sources.append({"path": path["path"], "type": path["type"]})

        # Now loop through list of files and folders we need to backup
        for source in sources:
            # try:
            # Don't do this when we are backing up full home(.) directory.
            if source["path"] != ".":
                # replace any double forward slash ... just in-case.
                full_path = (local_dir + source["path"]).replace("//", "/")
            else:
                full_path = local_dir

            create_directory_v2(full_path)

            # Exclude rules bases on user settings.
            exclude_rules = '--exclude-glob="*.sock"'
            include_rules = ''

            """
            Adding exclude rules
            """
            if node.website.excludes_regex:
                for regex in node.website.excludes_regex:
                    exclude_rules += f' --exclude="{regex}"'

            if node.website.excludes_glob:
                for glob in node.website.excludes_glob:
                    exclude_rules += f' --exclude-glob="{glob}"'

            """
            Adding include rules
            """
            if node.website.includes_regex:
                for regex in node.website.includes_regex:
                    include_rules += f' --include="{regex}"'

            if node.website.includes_glob:
                for glob in node.website.includes_glob:
                    include_rules += f' --include-glob="{glob}"'

            if node.website.verbose:
                verbose = "--verbose=1 --verbose=3"
            else:
                verbose = ""

            if node.website.parallel:
                parallel = node.website.parallel
            else:
                node.website.parallel = 10
                node.website.save()
                parallel = node.website.parallel

            # Add this log file
            log_file.write(f"Parallel Download: {parallel}\n")
            log_file.write(f"Include Rules: {include_rules}\n")
            log_file.write(f"Exclude Rules: {exclude_rules}\n")

            protocol = node.connection.auth_website.get_protocol_display().lower()

            # Stop any old container
            execstr = f"sudo docker stop {backup.uuid}"
            subprocess.run(
                execstr,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3600,
                shell=True,
            )

            docker_full_path = f"{working_dir}/_storage"

            lftp_version_path = (
                f"sudo docker run"
                f" --rm"
                f" -v {docker_full_path}:{docker_full_path}"
                f" --name {backup.uuid}"
                f" -t bs-lftp"
            )

            # capture_message(f'Executing lftp_version_path {lftp_version_path}')

            # Instead of using implicit (ftps) SSL we will use explicit ssl for FTPS https://lftp.uniyar.ac.narkive.com/3CfUWvqR/ftps-explicit-connection-problems
            if node.connection.auth_website.protocol == CoreAuthWebsite.Protocol.FTPS and node.connection.auth_website.ftps_use_explicit_ssl:
                protocol = "ftp"
            # Dict for lftp logins and commands
            lftp = {
                "host": f"{protocol}://{node.connection.auth_website.host}",
                "user": bs_decrypt(node.connection.auth_website.username, encryption_key),
                "pass": bs_decrypt(node.connection.auth_website.password, encryption_key),
                "port": node.connection.auth_website.port,
                "target": full_path,
                "source": source["path"],
                "exclude": exclude_rules,
                "include": include_rules,
                "options": f"--continue --recursion=always --ignore-time --no-perms --no-umask"
                           f" --ignore-size"
                           f" --use-pget=1 --parallel={parallel} {verbose}",
                # f" --use-pget={parallel} --parallel={parallel} --no-symlinks {verbose}",
                # "options": f"--use-pget-n={parallel}"
                #            f" --transfer-all"
                #            f" --skip-noaccess"
                #            f" --continue"
                #            f" --recursion=always"
                #            f" --ignore-time"
                #            f" --no-perms --no-umask "
                #            f" --ignore-size"
                #            f" --parallel={parallel} --no-symlinks {verbose}",
            }

            # Add this log file
            log_file.write(f"Source: {lftp['source']}\n")

            # Escape " if it's in password
            if lftp.get("pass"):
                lftp["pass"] = lftp["pass"].replace('"', '\"')

            # If it's a file then we don't need to use mirror. Then just use get.
            if source["type"] == "file":
                create_directory_v2(lftp["target"])

                if node.connection.auth_website.use_public_key:
                    execstr = (
                        f"{lftp_version_path} -c '\n"
                        f"set ssl:verify-certificate no\n"
                        f"set net:reconnect-interval-base 5\n"
                        f"set net:reconnect-interval-multiplier 1\n"
                        f"set net:max-retries 2\n"
                        f"set ftp:ssl-allow true\n"
                        f"set sftp:auto-confirm true\n"
                        f'set sftp:connect-program "ssh -a -x -p {lftp["port"]} -l "{lftp["user"]}" -i {ssh_key_path}"\n'
                        f"set net:connection-limit {node.website.parallel}\n"
                        f"set ftp:ssl-protect-data true\n"
                        f"set ftp:use-mdtm off\n"
                        f"set mirror:set-permissions off\n"
                        f"open -p {lftp['port']} {lftp['host']}\n"
                        f'get -P {parallel} "{lftp["source"]}" -o "{working_dir}/{lftp["target"]}"\n'
                        f"bye\n'"
                    )

                elif node.connection.auth_website.use_private_key:
                    # This is done to convert keys to RSA format. OpenSSL format doesn't work with lftp
                    pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=lftp["pass"])
                    pkey.write_private_key_file(ssh_key_path, password=lftp["pass"])

                    lftp_pass = lftp["pass"] or ''

                    execstr = (
                        f"{lftp_version_path} -c '\n"
                        f"set ssl:verify-certificate no\n"
                        f"set net:reconnect-interval-base 5\n"
                        f"set net:reconnect-interval-multiplier 1\n"
                        f"set net:max-retries 2\n"
                        f"set ftp:ssl-allow true\n"
                        f"set sftp:auto-confirm true\n"
                        f'set sftp:connect-program "ssh -a -x -p {lftp["port"]} -l "{lftp["user"]}" -i {ssh_key_path}"\n'
                        f"set net:connection-limit {node.website.parallel}\n"
                        f"set ftp:ssl-protect-data true\n"
                        f"set ftp:use-mdtm off\n"
                        f"set mirror:set-permissions off\n"
                        f"open -p {lftp['port']} {lftp['host']}\n"
                        f'user "{lftp["user"]}" "{lftp_pass}"\n'
                        f'get -P {parallel} "{lftp["source"]}" -o "{working_dir}/{lftp["target"]}"\n'
                        f"bye\n'"
                    )
                else:
                    if (
                            node.connection.auth_website.protocol
                            == CoreAuthWebsite.Protocol.FTPS
                    ):
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ftps:initial-prot P\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow true\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data true\n"
                            f"set ftp:use-mdtm off\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'get -P {parallel} "{lftp["source"]}" -o "{working_dir}/{lftp["target"]}"\n'
                            f"bye\n'"
                        )
                    elif (
                            node.connection.auth_website.protocol
                            == CoreAuthWebsite.Protocol.SFTP
                    ):
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow true\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data true\n"
                            f"set ftp:use-mdtm off\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'get -P {parallel} "{lftp["source"]}" -o "{working_dir}/{lftp["target"]}"\n'
                            f"bye\n'"
                        )
                    else:
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow false\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data false\n"
                            f"set ftp:use-mdtm off\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'get -P {parallel} "{lftp["source"]}" -o "{working_dir}/{lftp["target"]}"\n'
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
                    ).replace(local_dir, "").replace(
                        bs_decrypt(node.connection.auth_website.username, encryption_key),
                        "******",
                    )

                    if bs_decrypt(node.connection.auth_website.password, encryption_key):
                        cleaned_line = cleaned_line.replace(
                            bs_decrypt(node.connection.auth_website.password, encryption_key),
                            "******",
                        )

                    node.connection.account.create_backup_log(cleaned_line, node, backup)

                    if (
                            "fatal error" in cleaned_line.lower()
                            and "too many" in cleaned_line.lower()
                    ) or "docker: error" in cleaned_line.lower():
                        if "421 too many connections" in cleaned_line.lower():
                            node.website.parallel = 1
                            node.website.save()
                        raise NodeBackupFailedError(
                            node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            message=cleaned_line,
                        )

            # if it's not a file then its must be a directory
            else:
                if node.connection.auth_website.use_public_key:
                    execstr = (
                        f"{lftp_version_path} -c '\n"
                        f"set ssl:verify-certificate no\n"
                        f"set net:reconnect-interval-base 5\n"
                        f"set net:reconnect-interval-multiplier 1\n"
                        f"set net:max-retries 2\n"
                        f"set ftp:ssl-allow true\n"
                        f"set sftp:auto-confirm true\n"
                        f'set sftp:connect-program "ssh -a -x -p {lftp["port"]} -l "{lftp["user"]}" -i {ssh_key_path}"\n'
                        f"set net:connection-limit {node.website.parallel}\n"
                        f"set ftp:ssl-protect-data true\n"
                        f"set ftp:use-mdtm off\n"
                        f"set ftp:list-options -a\n"
                        f"set ftp:use-mode-z true\n"
                        f"set ftp:use-tvfs true\n"
                        f"set ftp:prefer-epsv true\n"
                        f"set mirror:parallel-directories true\n"
                        f"set mirror:set-permissions off\n"
                        f"open -p {lftp['port']} {lftp['host']}\n"
                        f'mirror {lftp["options"]} {lftp["include"]} {lftp["exclude"]} "{lftp["source"]}" "{working_dir}/{lftp["target"]}"\n'
                        f"bye\n'"
                    )

                elif node.connection.auth_website.use_private_key:
                    # This is done to convert keys to RSA format. OpenSSL format doesn't work with lftp
                    pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=lftp["pass"])
                    pkey.write_private_key_file(ssh_key_path, password=lftp["pass"])

                    lftp_pass = lftp["pass"] or ''

                    execstr = (
                        f"{lftp_version_path} -c '\n"
                        f"set ssl:verify-certificate no\n"
                        f"set net:reconnect-interval-base 5\n"
                        f"set net:reconnect-interval-multiplier 1\n"
                        f"set net:max-retries 2\n"
                        f"set ftp:ssl-allow true\n"
                        f"set sftp:auto-confirm true\n"
                        f'set sftp:connect-program "ssh -a -x -p {lftp["port"]} -l "{lftp["user"]}" -i {ssh_key_path}"\n'
                        f"set net:connection-limit {node.website.parallel}\n"
                        f"set ftp:ssl-protect-data true\n"
                        f"set ftp:use-mdtm off\n"
                        f"set ftp:list-options -a\n"
                        f"set ftp:use-mode-z true\n"
                        f"set ftp:use-tvfs true\n"
                        f"set ftp:prefer-epsv true\n"
                        f"set mirror:parallel-directories true\n"
                        f"set mirror:set-permissions off\n"
                        f"open -p {lftp['port']} {lftp['host']}\n"
                        f'user "{lftp["user"]}" "{lftp_pass}"\n'
                        f'mirror {lftp["options"]} {lftp["include"]} {lftp["exclude"]} "{lftp["source"]}" "{working_dir}/{lftp["target"]}"\n'
                        f"bye\n'"
                    )
                    # capture_message(lftp_version_path)
                    # capture_message(ssh_key_path)
                    # capture_message(lftp["target"])
                    # capture_message(execstr)
                else:
                    if (
                            node.connection.auth_website.protocol
                            == CoreAuthWebsite.Protocol.FTPS
                    ):
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ftps:initial-prot P\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow true\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data true\n"
                            f"set ftp:use-mdtm off\n"
                            f"set ftp:list-options -a\n"
                            f"set ftp:use-mode-z true\n"
                            f"set ftp:use-tvfs true\n"
                            f"set ftp:prefer-epsv true\n"
                            f"set mirror:parallel-directories true\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'mirror {lftp["options"]} {lftp["include"]} {lftp["exclude"]} "{lftp["source"]}" "{working_dir}/{lftp["target"]}"\n'
                            f"bye\n'"
                        )
                    elif (
                            node.connection.auth_website.protocol
                            == CoreAuthWebsite.Protocol.SFTP
                    ):
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow true\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data true\n"
                            f"set ftp:use-mdtm off\n"
                            f"set ftp:list-options -a\n"
                            f"set ftp:use-mode-z true\n"
                            f"set ftp:use-tvfs true\n"
                            f"set ftp:prefer-epsv true\n"
                            f"set mirror:parallel-directories true\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'mirror {lftp["options"]} {lftp["include"]} {lftp["exclude"]} "{lftp["source"]}" "{working_dir}/{lftp["target"]}"\n'
                            f"bye\n'"
                        )
                    else:
                        execstr = (
                            f"{lftp_version_path} -c '\n"
                            f"set ssl:verify-certificate no\n"
                            f"set net:reconnect-interval-base 5\n"
                            f"set net:reconnect-interval-multiplier 1\n"
                            f"set net:max-retries 2\n"
                            f"set ftp:ssl-allow false\n"
                            f"set sftp:auto-confirm true\n"
                            f"set net:connection-limit {node.website.parallel}\n"
                            f"set ftp:ssl-protect-data false\n"
                            f"set ftp:use-mdtm off\n"
                            f"set ftp:list-options -a\n"
                            f"set ftp:use-mode-z true\n"
                            f"set ftp:use-tvfs true\n"
                            f"set ftp:prefer-epsv true\n"
                            f"set mirror:parallel-directories true\n"
                            f"set mirror:set-permissions off\n"
                            f"open -p {lftp['port']} {lftp['host']}\n"
                            f'user "{lftp["user"]}" "{lftp["pass"]}"\n'
                            f'mirror {lftp["options"]} {lftp["include"]} {lftp["exclude"]} "{lftp["source"]}" "{working_dir}/{lftp["target"]}"\n'
                            f"bye\n'"
                        )
                        log_file.write(f"{execstr}\n")
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
                        "/home/ubuntu/backupsheep/_storage/", ""
                    ).replace(local_dir, "").replace(
                        bs_decrypt(node.connection.auth_website.username, encryption_key),
                        "******",
                    )

                    if bs_decrypt(node.connection.auth_website.password, encryption_key):
                        cleaned_line = cleaned_line.replace(
                            bs_decrypt(node.connection.auth_website.password, encryption_key),
                            "******",
                        )

                    log_file.write(f"{cleaned_line}\n")

                    if ("fatal error" in cleaned_line.lower() and "too many" in cleaned_line.lower()) \
                            or "docker: error" in cleaned_line.lower() \
                            or "login failed" in cleaned_line.lower() \
                            or "invalid preceding regular expression" in cleaned_line.lower() \
                            or "login incorrect" in cleaned_line.lower():
                        if "421 too many connections" in cleaned_line.lower():
                            node.website.parallel = 3
                            node.website.save()
                        node.connection.account.create_backup_log(cleaned_line, node, backup)
                        raise NodeBackupFailedError(
                            node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            message=cleaned_line,
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
        except Exception as e:
            capture_exception(e)

        # # All file paths
        # try:
        #     file_list_path = []
        #     execstr = "/usr/bin/tree -f -i"
        #
        #     process = subprocess.run(
        #         execstr,
        #         stdout=subprocess.PIPE,
        #         stderr=subprocess.PIPE,
        #         shell=True,
        #         cwd=local_dir
        #     )
        #
        #     for line in process.stdout.decode('utf-8', 'ignore').splitlines():
        #         file_list_path.append(line)
        #     backup.file_list_path = file_list_path
        #     backup.save()
        #
        #     # Save numbers
        #     backup.total_folders = backup.file_list_path[-1].split(",")[0] \
        #         .replace("directory", "") \
        #         .replace("directories", "").strip()
        #     backup.total_files = backup.file_list_path[-1].split(",")[1] \
        #         .replace("files", "") \
        #         .replace("file", "").strip()
        #     backup.total_files_n_folders_calculated = True
        #     backup.save()
        # except Exception as e:
        #     capture_exception(e)

        """
        Update Permissions
        """
        execstr = f"sudo chown ubuntu:ubuntu ../{backup.uuid_str} -R"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            shell=True,
            cwd=local_dir,
        )

        """
        ZIP all downloaded files.
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

        """
        Create Incremental Repo
        """
        account = node.connection.account
        storage_bs = CoreStorageBS.objects.get(storage__account=account, storage__name="Storage 04")
        host = storage_bs.host
        username = bs_decrypt(storage_bs.username, encryption_key)
        password = bs_decrypt(storage_bs.password, encryption_key)

        local_repo_folder = f"{working_dir}/_storage/_repos"
        os.makedirs(local_repo_folder, exist_ok=True)

        """
        Create RClone Config
        """
        execstr = (
            f'/usr/bin/rclone config create {backup.uuid_str} ftp --obscure pass="{password}" user="{username}" host="{host}"'
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
            if "fatal" in line.lower():
                raise Exception("rclone config create failed.")

        """
        Restic Repo Initialize - Don't care about output. If it already exists then it won't mess up existing
        """
        execstr = f"/usr/bin/restic --password-command='echo {password}' -r rclone:{backup.uuid_str}:/{node.name_slug}/incremental init"

        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command_timeout,
            universal_newlines=True,
            encoding='utf-8',
            errors="ignore",
            shell=True
        )

        """
        Move Directory
        """
        mkdir_p(f"{working_dir}/_storage/{node.uuid_str}/")
        execstr = f"mv {working_dir}/_storage/{backup.uuid} {working_dir}/_storage/{node.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command_timeout,
            universal_newlines=True,
            encoding='utf-8',
            errors="ignore",
            shell=True
        )
        log_file.write(f"restic :: {execstr} \n")

        """
        Restic Repo Backup
        """
        execstr = f"/usr/bin/restic --password-command='echo {password}' -r rclone:{backup.uuid_str}:/{node.name_slug}/incremental backup {local_dir_incremental} --ignore-inode"

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
        log_file.write(f"restic :: {execstr} \n")

        for line in process.stdout.splitlines():
            log_file.write(f"restic :: {line.__str__()} \n")
            if "fatal" in line.lower() or "unknown flag" in line.lower():
                raise Exception("restic repo backup failed.")

        """
        Delete RClone Config
        """
        execstr = (
            f'/usr/bin/rclone config delete {backup.uuid_str}'
        )

        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command_timeout,
            universal_newlines=True,
            encoding='utf-8',
            errors="ignore",
            shell=True
        )

        """
        Delete Directory
        """
        execstr = f"rm -rf {working_dir}/_storage/{node.uuid_str}/"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=command_timeout,
            universal_newlines=True,
            encoding='utf-8',
            errors="ignore",
            shell=True
        )

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
        Stop any docker container
        """
        # Stop any old container
        execstr = f"sudo docker stop {backup.uuid}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3600,
            shell=True,
        )

        """
        Upload log file and report file to BackupSheep storage.
        """
        log_file.close()
        # aws_s3_upload_log_file(log_file_path, f"{backup.uuid}.log")
        # os.remove(log_file_path)
        aws_s3_upload_log_file(tree_log_path, f"{backup.uuid}-dir-tree.log")
        os.remove(tree_log_path)

