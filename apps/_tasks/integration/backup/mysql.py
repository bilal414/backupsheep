import subprocess
import zipfile
import os
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps.api.v1.utils.api_helpers import bs_decrypt, aws_s3_upload_log_file
from apps.api.v1.utils.api_helpers import zipdir, mkdir_p


from django.core.cache import cache

from apps.console.utils.models import UtilBackup
from os import path


def snapshot_mysql(backup):
    node = backup.database.node
    encryption_key = node.connection.account.get_encryption_key()

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)
    ssh_key_path = None

    # Backup Log
    log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}.log"
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
        node.connection.auth_database.check_connection()

        # https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html#option_mysqldump_single-transaction
        option_single_transaction = ""
        if node.database.option_single_transaction:
            option_single_transaction = "--single-transaction"

        option_skip_opt = ""
        if node.database.option_skip_opt:
            option_skip_opt = "--skip-opt"

        option_compress = ""
        if "mysql_5" in node.connection.auth_database.version:
            if node.database.option_compress:
                option_compress = "--compress"

        option_routines = ""
        if node.connection.auth_database.include_stored_procedure:
            option_routines = "--routines"

        option_triggers = ""
        if node.connection.auth_database.include_stored_procedure:
            option_triggers = "--triggers"

        option_column_statistics = ""
        if "mysql_8" in node.connection.auth_database.version:
            option_column_statistics = "--column-statistics=0"

        option_ssl_mode = ""
        if node.connection.auth_database.use_ssl:
            option_ssl_mode = "--ssl-mode=PREFERRED"

        option_gtid_purged_off = ""
        if node.database.option_gtid_purged_off and "mysql_5_5" not in node.connection.auth_database.version:
            option_gtid_purged_off = "--set-gtid-purged=OFF"

        if "mysql_5_5" in node.connection.auth_database.version:
            cli_path = "/usr/local/mysql/bin/"
        else:
            cli_path = "/usr/bin/"

        database_version_path = f"sudo docker exec {node.connection.auth_database.version} {cli_path}"

        if (
            node.connection.auth_database.use_public_key
            or node.connection.auth_database.use_private_key
        ):
            ssh, ssh_key_path = node.connection.auth_database.get_ssh_client()

            # All database on node
            if node.database.all_databases:
                # Find all databases first.
                databases = []

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                execstr = (
                    f"mysql"
                    f" {option_ssl_mode}"
                    f" --disable-column-names"
                    f' -h"{node.connection.auth_database.host}"'
                    f' -u"{username}"'
                    f" -p'{bs_decrypt(node.connection.auth_database.password, encryption_key)}'"
                    f' --port="{node.connection.auth_database.port}"'
                    f' -e"show databases;"'
                )
                execstr = ' '.join(execstr.split())

                log_file.write(f"MYSQL: {execstr.replace(password, 'hidden')}\n")

                stdin, stdout, stderr = ssh.exec_command(execstr)

                # @Todo: Don't change error handing before solving this following ticket
                #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                # for line in stderr:
                #     error = line.strip("\n").strip()
                #     if "warning" not in error.lower():
                #         raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, message=error)

                for line in stdout:
                    database_name = line.strip("\n").strip()

                    if database_name:
                        databases.append(database_name)

                for database in databases:
                    db_file = f"{local_dir}{database}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = (
                        f"mysqldump"
                        f" {option_ssl_mode}"
                        f" {option_skip_opt}"
                        f" {option_routines}"
                        f" {option_triggers}"
                        f" --no-tablespaces"
                        f" --max_allowed_packet=512M"
                        f" --skip-extended-insert"
                        f" {option_single_transaction}"
                        f" {option_compress}"
                        f" {option_gtid_purged_off}"
                        f" -h {node.connection.auth_database.host}"
                        f" --port {node.connection.auth_database.port}"
                        f" -u {username}"
                        f" -p'{password}'"
                        f" {database}"
                    )
                    execstr = ' '.join(execstr.split())

                    log_file.write(f"MYSQL: {execstr.replace(password, 'hidden')}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower():
                    #         raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, message=error)

                    stdout._set_mode("rb")
                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)
            # Selected databases on node
            elif node.database.databases:
                for database in node.database.databases:
                    db_file = f"{local_dir}{database}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = (
                        f"mysqldump"
                        f" {option_ssl_mode}"
                        f" {option_skip_opt}"
                        f" {option_routines}"
                        f" {option_triggers}"
                        f" --no-tablespaces"
                        f" --max_allowed_packet=512M"
                        f" --skip-extended-insert"
                        f" {option_single_transaction}"
                        f" {option_compress}"
                        f" {option_gtid_purged_off}"
                        f" -h {node.connection.auth_database.host}"
                        f" --port {node.connection.auth_database.port}"
                        f" -u {username}"
                        f" -p'{password}'"
                        f" {database}"
                    )
                    execstr = ' '.join(execstr.split())

                    log_file.write(f"MYSQL: {execstr.replace(password, 'hidden')}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower():
                    #         raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, message=error)

                    stdout._set_mode("rb")
                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)
            # Means database name is selected at account level.
            elif node.database.all_tables:
                db_file = f"{local_dir}{node.connection.auth_database.database_name}.sql"

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                # Todo: Use https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html#option_mysqldump_result-file
                execstr = (
                    f"mysqldump"
                    f" {option_ssl_mode}"
                    f" {option_skip_opt}"
                    f" {option_routines}"
                    f" {option_triggers}"
                    f" --no-tablespaces"
                    f" --max_allowed_packet=512M"
                    f" --skip-extended-insert"
                    f" {option_single_transaction}"
                    f" {option_compress}"
                    f" {option_gtid_purged_off}"
                    f" -h {node.connection.auth_database.host}"
                    f" --port {node.connection.auth_database.port}"
                    f" -u {username}"
                    f" -p'{password}'"
                    f" {node.connection.auth_database.database_name}"
                )
                execstr = ' '.join(execstr.split())

                log_file.write(f"MYSQL: {execstr.replace(password, 'hidden')}\n")

                stdin, stdout, stderr = ssh.exec_command(execstr)

                # @Todo: Don't change error handing before solving this following ticket
                #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                # for line in stderr:
                #     error = line.strip("\n").strip()
                #     if "warning" not in error.lower():
                #         raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, message=error)

                stdout._set_mode("rb")
                for line in stdout:
                    with open(db_file, "ab") as tmp:
                        tmp.write(line)

            # Again! means database name is selected at account level.
            elif node.database.tables:
                for table in node.database.tables:
                    db_file = f"{local_dir}{table}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = (
                        f"mysqldump"
                        f" {option_ssl_mode}"
                        f" {option_skip_opt}"
                        f" {option_routines}"
                        f" {option_triggers}"
                        f" --no-tablespaces"
                        f" --max_allowed_packet=512M"
                        f" --skip-extended-insert"
                        f" {option_single_transaction}"
                        f" {option_compress}"
                        f" {option_gtid_purged_off}"
                        f" -h {node.connection.auth_database.host}"
                        f" --port {node.connection.auth_database.port}"
                        f" -u {username}"
                        f" -p'{password}'"
                        f" {node.connection.auth_database.database_name + ' '+ table}"
                    )
                    execstr = ' '.join(execstr.split())

                    log_file.write(f"MYSQL: {execstr.replace(password, 'hidden')}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower():
                    #         raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, message=error)

                    stdout._set_mode("rb")
                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)
            ssh.close()
        else:
            if node.database.all_tables:
                db_file = f"{local_dir}{node.connection.auth_database.database_name}.sql"

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                command = (
                    f"{database_version_path}mysqldump"
                    f" {option_ssl_mode}"
                    f" {option_skip_opt}"
                    f" {option_routines}"
                    f" {option_triggers}"
                    f" --no-tablespaces"
                    f" --max_allowed_packet=512M"
                    f" {option_column_statistics}"
                    f" --skip-extended-insert"
                    f" {option_single_transaction}"
                    f" {option_compress}"
                    f" {option_gtid_purged_off}"
                    f" -h {node.connection.auth_database.host}"
                    f" --port {node.connection.auth_database.port}"
                    f" -u {username}"
                    f" -p'{password}'"
                    f" {node.connection.auth_database.database_name} > {db_file}"
                )
                command = ' '.join(command.split())

                log_file.write(f"MYSQL: {command.replace(database_version_path, '').replace(password, 'hidden').replace(local_dir, '')}\n")

                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=True,
                    universal_newlines=True,
                )

                for line in process.stdout.splitlines():
                    log_file.write(f"INFO: {line}\n")

                    if (
                        len(line) > 0
                        and not "Using a password on the command line interface"
                        " can be insecure" in line
                    ):
                        error_text = line.replace(
                            bs_decrypt(node.connection.auth_database.password, encryption_key),
                            "******",
                        )
                        raise NodeBackupFailedError(
                            node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            message=error_text,
                        )
            else:
                for table in node.database.tables:
                    # try:
                    db_file = f"{local_dir}{table}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    command = (
                        f"{database_version_path}mysqldump"
                        f" {option_ssl_mode}"
                        f" {option_skip_opt}"
                        f" {option_routines}"
                        f" {option_triggers}"
                        f" --no-tablespaces"
                        f" --max_allowed_packet=512M"
                        f" {option_column_statistics}"
                        f" --skip-extended-insert"
                        f" {option_single_transaction}"
                        f" {option_compress}"
                        f" {option_gtid_purged_off}"
                        f" -h {node.connection.auth_database.host}"
                        f" --port {node.connection.auth_database.port}"
                        f" -u {username}"
                        f" -p'{password}'"
                        f" {node.connection.auth_database.database_name + ' ' + table} > {db_file}"
                    )
                    command = ' '.join(command.split())

                    log_file.write(f"MYSQL: {command.replace(database_version_path, '').replace(password, 'hidden').replace(local_dir, '')}\n")

                    process = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        shell=True,
                        universal_newlines=True,
                    )

                    for line in process.stdout.splitlines():
                        log_file.write(f"INFO: {line}\n")

                        if (
                            len(line) > 0
                            and not "Using a password on the command "
                            "line interface can be insecure" in line
                        ):
                            error_text = line.replace(
                                bs_decrypt(node.connection.auth_database.password, encryption_key),
                                "******",
                            )
                            raise NodeBackupFailedError(
                                node,
                                backup.uuid_str,
                                backup.attempt_no,
                                backup.type,
                                message=error_text,
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


        zipf = zipfile.ZipFile(local_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True)
        zipdir(local_dir, zipf)
        zipf.close()

        if path.exists(local_zip):
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

        """
        Delete temp SSH Key
        """
        if ssh_key_path:
            os.remove(ssh_key_path)



