import subprocess
import zipfile
import os
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps.api.v1.utils.api_helpers import bs_decrypt, aws_s3_upload_log_file, check_error
from apps.api.v1.utils.api_helpers import zipdir, mkdir_p
from apps.console.utils.models import UtilBackup
from os import path


def snapshot_postgresql(backup):
    node = backup.database.node
    encryption_key = node.connection.account.get_encryption_key()

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)
    ssh_key_path = None
    error_text = ''

    # Backup Log
    log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")
    tree_log_path = f"/home/ubuntu/backupsheep/_storage/{backup.uuid}-dir-tree.log"

    try:
        if node.database.option_postgres:
            option_postgres = f"-w {node.database.option_postgres}"
        else:
            option_postgres = "-w --clean"

        # Save backup options used
        backup.option_postgres = option_postgres
        backup.save()

        log_file.write(f"Using Options: {option_postgres} \n")

        """
        Checking for connection
        """
        node.connection.auth_database.check_connection()
        log_file.write(f"Integration Validation: Passed \n")

        database_version_path = f"sudo docker exec {node.connection.auth_database.version} /usr/bin/"

        if (
                node.connection.auth_database.use_public_key
                or node.connection.auth_database.use_private_key
        ):
            ssh, ssh_key_path = node.connection.auth_database.get_ssh_client()

            log_file.write(f"Connection: SSH using public/private key\n")

            # All database on node
            if node.database.all_databases:
                log_file.write(f"Backup: All Databases \n")
                # Find all databases first.
                databases = []

                # This is needed because we need database name to connect to psql
                if node.connection.auth_database.database_name:
                    database_name = node.connection.auth_database.database_name
                else:
                    database_name = "postgres"

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                execstr = (
                    f"psql 'host={node.connection.auth_database.host} "
                    f"user='{username}' "
                    f"password='{password}' "
                    f"dbname={database_name} "
                    f"port={node.connection.auth_database.port} "
                    f"sslmode=prefer' -lqt | cut -d \| -f 1"
                )

                log_file.write(f"PostgreSQL: {execstr}\n")

                # execstr = ' '.join(execstr.split())
                stdin, stdout, stderr = ssh.exec_command(execstr)

                # @Todo: Don't change error handing before solving this following ticket
                #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                # for line in stderr:
                #     error = line.strip("\n").strip()
                #     log_file.write(f"{error}\n")
                #     if "error" not in error.lower():
                #         raise NodeBackupFailedError(
                #           node, backup.uuid_str, backup.attempt_no, backup.type, message=error
                #         )

                for line in stdout:
                    database_name = line.strip("\n").strip()

                    if database_name:
                        databases.append(database_name)

                for database in databases:
                    log_file.write(f"Found Database: {database} \n")

                    db_file = f"{local_dir}{database}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = f"export PGPASSWORD='{password}'  &&" \
                              f" pg_dump" \
                              f" -h {node.connection.auth_database.host}" \
                              f" -p {node.connection.auth_database.port}" \
                              f" -U {username}" \
                              f" -d {database}" \
                              f" {option_postgres}"
                    execstr = ' '.join(execstr.split())

                    log_file.write(f"PostgreSQL: {execstr}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     log_file.write(f"{error}\n")
                    #     if "error" not in error.lower():
                    #         raise NodeBackupFailedError(
                    #           node, backup.uuid_str, backup.attempt_no, backup.type, message=error
                    #         )

                    stdout._set_mode("rb")

                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)
            elif node.database.databases:
                log_file.write(f"Backup: Specific Databases \n")

                for database in node.database.databases:
                    log_file.write(f"Database: {database} \n")

                    db_file = f"{local_dir}{database}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = f"export PGPASSWORD='{password}'  &&" \
                              f" pg_dump" \
                              f" -h {node.connection.auth_database.host}" \
                              f" -p {node.connection.auth_database.port}" \
                              f" -U {username}" \
                              f" -d {database}" \
                              f" {option_postgres}"
                    execstr = ' '.join(execstr.split())

                    log_file.write(f"PostgreSQL: {execstr}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     log_file.write(f"{error}\n")
                    #     if "error" not in error.lower():
                    #         raise NodeBackupFailedError(
                    #             node, backup.uuid_str, backup.attempt_no, backup.type, message=error
                    #         )

                    stdout._set_mode("rb")

                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)

            # Means database name is selected at account level.
            elif node.database.all_tables:
                log_file.write(f"Backup: All Tables \n")

                db_file = f"{local_dir}{node.connection.auth_database.database_name}.sql"

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                execstr = f"export PGPASSWORD='{password}'  &&" \
                          f" pg_dump" \
                          f" -h {node.connection.auth_database.host}" \
                          f" -p {node.connection.auth_database.port}" \
                          f" -U {username}" \
                          f" -d {node.connection.auth_database.database_name}" \
                          f" {option_postgres}"
                execstr = ' '.join(execstr.split())

                log_file.write(f"PostgreSQL: {execstr}\n")

                stdin, stdout, stderr = ssh.exec_command(execstr)

                # @Todo: Don't change error handing before solving this following ticket
                #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                # for line in stderr:
                #     error = line.strip("\n").strip()
                #     log_file.write(f"{error}\n")
                #     if "error" not in error.lower():
                #         raise NodeBackupFailedError(
                #             node, backup.uuid_str, backup.attempt_no, backup.type, message=error
                #         )

                stdout._set_mode("rb")

                for line in stdout:
                    with open(db_file, "ab") as tmp:
                        tmp.write(line)

            # Again! means database name is selected at account level.
            elif node.database.tables:
                log_file.write(f"Backup: Specific Tables \n")

                for table in node.database.tables:
                    log_file.write(f"Table: {table} \n")

                    db_file = f"{local_dir}{table}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    execstr = f"export PGPASSWORD='{password}'  &&" \
                              f" pg_dump" \
                              f" -h {node.connection.auth_database.host}" \
                              f" -p {node.connection.auth_database.port}" \
                              f" -U {username}" \
                              f" -d {node.connection.auth_database.database_name}" \
                              f" -t {table}" \
                              f" {option_postgres}"

                    execstr = ' '.join(execstr.split())

                    log_file.write(f"PostgreSQL: {execstr}\n")

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # @Todo: Don't change error handing before solving this following ticket
                    #  https://xtresoft.atlassian.net/browse/BS-10?atlOrigin=eyJpIjoiNDQ1ZjVmZjdjODI2NDMwZGE3NzIyZGRiZDcxZjJkYTUiLCJwIjoiaiJ9
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     log_file.write(f"{error}\n")
                    #     if "error" not in error.lower():
                    #         raise NodeBackupFailedError(
                    #             node, backup.uuid_str, backup.attempt_no, backup.type, message=error
                    #         )

                    stdout._set_mode("rb")

                    for line in stdout:
                        with open(db_file, "ab") as tmp:
                            tmp.write(line)
            ssh.close()
        else:
            log_file.write(f"Connection: Remote DB Connection \n")

            if node.database.all_tables:
                log_file.write(f"Backup: All Tables \n")

                db_file = f"{local_dir}{node.connection.auth_database.database_name}.sql"

                username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                command = f"sudo docker exec -e PGPASSWORD='{password}'" \
                          f" {node.connection.auth_database.version} /usr/bin/pg_dump" \
                          f" -h {node.connection.auth_database.host}" \
                          f" -p {node.connection.auth_database.port}" \
                          f" -U {username}" \
                          f" -d {node.connection.auth_database.database_name}" \
                          f" {option_postgres} > {db_file}"
                command = ' '.join(command.split())

                log_file.write(f"PostgreSQL: {command.replace(password, 'hidden').replace(local_dir, '')}\n")

                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=True,
                    universal_newlines=True
                )

                for line in process.stdout.splitlines():
                    log_file.write(f"INFO: {line}\n")

                    if len(line) > 0:
                        line = line.replace(
                            bs_decrypt(node.connection.auth_database.password, encryption_key), "******"
                        )
                        log_file.write(f"{line}\n")
                        error_text += line

                if check_error(error_text):
                    raise NodeBackupFailedError(
                        node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        message=error_text,
                    )
            else:
                log_file.write(f"Backup: Specific Tables \n")

                for table in node.database.tables:
                    log_file.write(f"Backup Table: {table} \n")

                    db_file = f"{local_dir}{table}.sql"

                    username = bs_decrypt(node.connection.auth_database.username, encryption_key)
                    password = bs_decrypt(node.connection.auth_database.password, encryption_key)

                    command = (
                        f"sudo docker exec -e PGPASSWORD='{password}'"
                        f" {node.connection.auth_database.version} /usr/bin/pg_dump"
                        f" -h {node.connection.auth_database.host}"
                        f" -p {node.connection.auth_database.port}"
                        f" -U {username}"
                        f" -d {node.connection.auth_database.database_name}"
                        f" -t {table}"
                        f" {option_postgres} > {db_file}"
                    )

                    command = " ".join(command.split())

                    log_file.write(f"PostgreSQL: {command.replace(password, 'hidden').replace(local_dir, '')}\n")

                    process = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        shell=True,
                        universal_newlines=True
                    )

                    for line in process.stdout.splitlines():
                        log_file.write(f"INFO: {line}\n")

                        if len(line) > 0:
                            line = line.replace(
                                bs_decrypt(node.connection.auth_database.password, encryption_key), "******"
                            )
                            log_file.write(f"{line}\n")
                            error_text += line

                    if check_error(error_text):
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
        raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, e.__str__())
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