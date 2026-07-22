"""PostgreSQL logical backup engine (pg_dump).

Two modes:

- DIRECT: runs the local pg_dump binary via subprocess with an argv list (no
  ``shell=True``, no ``>`` redirect). The password is passed through the
  ``PGPASSWORD`` environment variable (``env=``), never inline on a shell
  string. Dump stdout is streamed to ``_storage/{uuid}/{db|table}.sql``.
- SSH: runs psql/pg_dump on the remote host via paramiko. A pgpass file
  ``bs_{backup.uuid_str}.pgpass`` (chmod 600, ``host:port:*:user:password``) is
  SFTP-uploaded to the remote home directory, referenced with a
  ``PGPASSFILE=~/bs_....pgpass`` env prefix on every remote command, and
  removed (best-effort) in ``finally``. stdout is streamed back over the
  channel into the local .sql files in binary append mode. Database
  enumeration filters out template0/template1 (template0 has
  datallowconn=false and cannot be dumped).

Error detection (fixes the BS-10 silent-failure hole): every command's exit
status is checked and a non-zero status raises NodeBackupFailedError with the
redacted stderr tail. stderr of successful commands is written to the run log
as warnings (never fatal — pg_dump emits non-fatal warnings on stderr). A
0-byte dump file is always treated as a failure. On success the .sql files are
zipped to ``_storage/{uuid}.zip`` and the dump directory is deleted; on any
failure everything is deleted and NodeBackupFailedError is raised. A
disk-space preflight (~2x the node's most recent COMPLETE backup, 1 GiB
floor) runs before anything is dumped so a huge database fails fast instead of
filling the shared _storage volume mid-run.
"""

import subprocess
import zipfile
import os
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.api.v1.utils.api_helpers import zipdir, mkdir_p
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.backup._sanitize import (
    safe_token,
    safe_password,
    safe_options,
)
from os import path

COMMAND_TIMEOUT = 12 * 3600


def _redact(text, username, password):
    out = text or ""
    if password:
        out = out.replace(password, "******")
    if username:
        out = out.replace(username, "******")
    return out.replace("_storage/", "")


def _pgpass_escape(value):
    """Escape a pgpass field (backslash escapes backslashes and colons)."""
    return str(value).replace("\\", "\\\\").replace(":", "\\:")


def _sftp_write_remote_file(ssh, remote_name, content):
    sftp = ssh.open_sftp()
    try:
        with sftp.open(remote_name, "w") as fh:
            fh.write(content)
        sftp.chmod(remote_name, 0o600)
    finally:
        sftp.close()


def _decode(data):
    return data.decode("utf-8", "replace") if isinstance(data, bytes) else (data or "")


def _run_direct_dump(node, backup, argv, db_file, log_file, username, password, env):
    """Run a local pg_dump, streaming stdout to db_file; raise on any failure."""
    log_file.write(f"PostgreSQL: {_redact(' '.join(argv), username, password)}\n")
    with open(db_file, "wb") as out:
        proc = subprocess.run(
            argv,
            stdout=out,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT,
            env=env,
        )
    err_text = _decode(proc.stderr)
    if proc.returncode != 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message=f"pg_dump failed with exit code {proc.returncode}: "
                    f"{_redact(err_text[-2000:], username, password)}",
        )
    for line in err_text.splitlines():
        if line.strip():
            log_file.write(f"WARNING: {_redact(line, username, password)}\n")
    if os.path.getsize(db_file) == 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message="pg_dump produced an empty dump file (0 bytes).",
        )


def _ssh_check_result(node, backup, stdout, stderr, log_file, username, password, what):
    """Raise NodeBackupFailedError on non-zero remote exit status; log stderr as warnings."""
    err_text = _decode(stderr.read())
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message=f"{what} failed with exit code {exit_status}: "
                    f"{_redact(err_text[-2000:], username, password)}",
        )
    for line in err_text.splitlines():
        if line.strip():
            log_file.write(f"WARNING: {_redact(line, username, password)}\n")


def _ssh_run_capture(node, backup, ssh, command, log_file, username, password, what):
    """Run a remote command and return its stdout text; raise on non-zero exit."""
    log_file.write(f"PostgreSQL: {_redact(command, username, password)}\n")
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout._set_mode("rb")
    out_text = _decode(stdout.read())
    _ssh_check_result(node, backup, stdout, stderr, log_file, username, password, what)
    return out_text


def _ssh_dump_to_file(node, backup, ssh, command, db_file, log_file, username, password):
    """Run a remote pg_dump, streaming stdout to db_file (binary append); raise on failure."""
    log_file.write(f"PostgreSQL: {_redact(command, username, password)}\n")
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout._set_mode("rb")
    with open(db_file, "ab") as tmp:
        while True:
            chunk = stdout.read(65536)
            if not chunk:
                break
            tmp.write(chunk)
    _ssh_check_result(node, backup, stdout, stderr, log_file, username, password, "pg_dump")
    if os.path.getsize(db_file) == 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message="pg_dump produced an empty dump file (0 bytes).",
        )


def snapshot_postgresql(backup):
    node = backup.database.node
    encryption_key = node.connection.account.get_encryption_key()

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)
    ssh_key_path = None

    # Backup Log
    log_file_path = f"_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node:{node.name}\n")
    log_file.write(f"UUID: {backup.uuid} \n")
    log_file.write(f"Time: {backup.created} \n")
    log_file.write(f"Attempt Number: {backup.attempt_no} \n")

    try:
        # Disk-space preflight: a huge dump must not fill the shared _storage
        # volume mid-run. Estimate ~2x the node's most recent COMPLETE backup
        # (dump files plus the final zip), floored at 1 GiB.
        last = (
            backup.__class__.objects.filter(
                database__node=node, status=UtilBackup.Status.COMPLETE)
            .order_by("-created").first()
        )
        ensure_disk_space(
            int(max(2 * (last.size if last and last.size else 0), 1 << 30)),
            what="database backup",
        )

        if node.database.option_postgres:
            option_postgres = f"-w {safe_options(node.database.option_postgres, 'option_postgres')}"
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

        database_version_path = node.connection.auth_database.bin_path()

        username = bs_decrypt(node.connection.auth_database.username, encryption_key)
        password = bs_decrypt(node.connection.auth_database.password, encryption_key)
        if username is None or password is None:
            raise NodeBackupFailedError(
                node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                message="Unable to decrypt the database credentials.",
            )

        # Reject command-injection / path-traversal payloads in the user-supplied
        # connection fields before they are interpolated into the dump commands below.
        safe_token(node.connection.auth_database.host, "host")
        safe_token(node.connection.auth_database.port, "port")
        safe_token(node.connection.auth_database.database_name, "database_name")
        safe_token(username, "username")
        safe_password(password, "password")
        for _name in (node.database.databases or []):
            safe_token(_name, "databases")
        for _name in (node.database.tables or []):
            safe_token(_name, "tables")

        if (
                node.connection.auth_database.use_public_key
                or node.connection.auth_database.use_private_key
        ):
            ssh, ssh_key_path = node.connection.auth_database.get_ssh_client()
            remote_pgpass_name = f"bs_{backup.uuid_str}.pgpass"

            log_file.write(f"Connection: SSH using public/private key\n")

            try:
                _sftp_write_remote_file(
                    ssh,
                    remote_pgpass_name,
                    f"{_pgpass_escape(node.connection.auth_database.host)}"
                    f":{_pgpass_escape(node.connection.auth_database.port)}"
                    f":*:{_pgpass_escape(username)}:{_pgpass_escape(password)}\n",
                )

                def remote_pg_dump(database, table=None):
                    execstr = (
                        f"PGPASSFILE=~/{remote_pgpass_name} pg_dump"
                        f" -h {node.connection.auth_database.host}"
                        f" -p {node.connection.auth_database.port}"
                        f" -U {username}"
                        f" -d {database}"
                    )
                    if table:
                        execstr += f" -t {table}"
                    execstr += f" {option_postgres}"
                    return " ".join(execstr.split())

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

                    execstr = (
                        f"PGPASSFILE=~/{remote_pgpass_name} psql"
                        f" 'host={node.connection.auth_database.host}"
                        f" user={username}"
                        f" dbname={database_name}"
                        f" port={node.connection.auth_database.port}"
                        f" sslmode=prefer' -lqt | cut -d '|' -f 1"
                    )

                    out_text = _ssh_run_capture(
                        node,
                        backup,
                        ssh,
                        execstr,
                        log_file,
                        username,
                        password,
                        "psql -lqt",
                    )

                    for line in out_text.splitlines():
                        database_name = line.strip()
                        # template0 has datallowconn=false and cannot be dumped;
                        # template1 is a template too. Blank names are cut noise.
                        if database_name and database_name not in ("template0", "template1"):
                            databases.append(database_name)

                    if not databases:
                        raise NodeBackupFailedError(
                            node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            message="psql -lqt returned no databases to back up.",
                        )

                    for database in databases:
                        safe_token(database, "database")
                        log_file.write(f"Found Database: {database} \n")

                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_pg_dump(database),
                            f"{local_dir}{database}.sql",
                            log_file,
                            username,
                            password,
                        )
                elif node.database.databases:
                    log_file.write(f"Backup: Specific Databases \n")

                    for database in node.database.databases:
                        log_file.write(f"Database: {database} \n")

                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_pg_dump(database),
                            f"{local_dir}{database}.sql",
                            log_file,
                            username,
                            password,
                        )

                # Means database name is selected at account level.
                elif node.database.all_tables:
                    log_file.write(f"Backup: All Tables \n")

                    _ssh_dump_to_file(
                        node,
                        backup,
                        ssh,
                        remote_pg_dump(node.connection.auth_database.database_name),
                        f"{local_dir}{node.connection.auth_database.database_name}.sql",
                        log_file,
                        username,
                        password,
                    )

                # Again! means database name is selected at account level.
                elif node.database.tables:
                    log_file.write(f"Backup: Specific Tables \n")

                    for table in node.database.tables:
                        log_file.write(f"Table: {table} \n")

                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_pg_dump(node.connection.auth_database.database_name, table=table),
                            f"{local_dir}{table}.sql",
                            log_file,
                            username,
                            password,
                        )
            finally:
                try:
                    ssh.exec_command(f"rm -f ~/{remote_pgpass_name}")
                except Exception:
                    pass
                ssh.close()
        else:
            log_file.write(f"Connection: Remote DB Connection \n")

            # Password travels only in the process environment, never on argv.
            pg_env = os.environ.copy()
            pg_env["PGPASSWORD"] = password

            def local_pg_dump(database, table=None):
                argv = [
                    f"{database_version_path}pg_dump",
                    "-h", str(node.connection.auth_database.host),
                    "-p", str(node.connection.auth_database.port),
                    "-U", username,
                    "-d", database,
                ]
                if table:
                    argv += ["-t", table]
                argv += option_postgres.split()
                return argv

            if node.database.all_tables:
                log_file.write(f"Backup: All Tables \n")

                _run_direct_dump(
                    node,
                    backup,
                    local_pg_dump(node.connection.auth_database.database_name),
                    f"{local_dir}{node.connection.auth_database.database_name}.sql",
                    log_file,
                    username,
                    password,
                    pg_env,
                )
            else:
                log_file.write(f"Backup: Specific Tables \n")

                for table in node.database.tables:
                    log_file.write(f"Backup Table: {table} \n")

                    _run_direct_dump(
                        node,
                        backup,
                        local_pg_dump(node.connection.auth_database.database_name, table=table),
                        f"{local_dir}{table}.sql",
                        log_file,
                        username,
                        password,
                        pg_env,
                    )

        # Generate Report (no external binaries; sudo does not exist in the container).
        log_file.write(f"---Directory Tree--- \n")
        for root, dirs, files in os.walk(local_dir):
            for name in sorted(files):
                full_path = os.path.join(root, name)
                log_file.write(
                    f"{os.path.relpath(full_path, local_dir)} ({os.path.getsize(full_path)} bytes)\n"
                )

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
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
        )
    except Exception as e:
        log_file.write(f"Error: {e.__str__()} \n")
        capture_exception(e)
        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
        )
        raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, e.__str__())
    finally:
        log_file.close()

        """
        Delete temp SSH Key
        """
        if ssh_key_path:
            os.remove(ssh_key_path)
