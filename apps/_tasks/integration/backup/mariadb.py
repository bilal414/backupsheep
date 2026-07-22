"""MariaDB logical backup engine (mysqldump from the MariaDB client).

Two modes:

- DIRECT: runs the local mysqldump binary via subprocess with an argv list (no
  ``shell=True``, no ``>`` redirect). Credentials are passed through a temporary
  defaults file ``_storage/my_{backup.uuid}.cnf`` (mode 0600) referenced with
  ``--defaults-extra-file=`` as the first option, and deleted in ``finally``.
  Dump stdout is streamed to ``_storage/{uuid}/{db|table}.sql``.
- SSH: runs mysql/mysqldump on the remote host via paramiko. A defaults file
  ``bs_{backup.uuid_str}.cnf`` (chmod 600) is SFTP-uploaded to the remote home
  directory, referenced with ``--defaults-extra-file=`` as the first flag, and
  removed (best-effort) in ``finally``. stdout is streamed back over the
  channel into the local .sql files in binary append mode (including the
  specific-tables branch, which previously wrote text and skipped
  ``stdout._set_mode('rb')``).

Error detection (fixes the BS-10 silent-failure hole): every command's exit
status is checked and a non-zero status raises NodeBackupFailedError with the
redacted stderr tail. stderr of successful commands is written to the run log
as warnings (never fatal). A 0-byte dump file is always treated as a failure.
On success the .sql files are zipped to ``_storage/{uuid}.zip`` and the dump
directory is deleted; on any failure everything is deleted and
NodeBackupFailedError is raised. A disk-space preflight (~2x the node's most
recent COMPLETE backup, 1 GiB floor) runs before anything is dumped so a huge
database fails fast instead of filling the shared _storage volume mid-run.
"""

import subprocess
import zipfile
import os
from sentry_sdk import capture_exception
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.api.v1.utils.api_helpers import zipdir, mkdir_p
from apps._tasks.integration.backup._sanitize import safe_token, safe_password

from apps.console.utils.models import UtilBackup
from os import path

COMMAND_TIMEOUT = 12 * 3600


def _redact(text, username, password):
    out = text or ""
    if password:
        out = out.replace(password, "******")
    if username:
        out = out.replace(username, "******")
    return out.replace("_storage/", "")


def _quote_cnf(value):
    """Quote a value for a MySQL option file (double-quoted, backslash-escaped)."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _defaults_file_content(username, password, host, port, use_ssl):
    lines = [
        "[client]",
        f"user={_quote_cnf(username)}",
        f"password={_quote_cnf(password)}",
        f"host={_quote_cnf(host)}",
        f"port={_quote_cnf(port)}",
    ]
    if use_ssl:
        # MariaDB client boolean option style (no --ssl-mode support).
        lines.append("ssl=1")
    return "\n".join(lines) + "\n"


def _write_local_defaults_file(file_path, content):
    with open(file_path, "w") as fh:
        fh.write(content)
    os.chmod(file_path, 0o600)


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


def _run_direct_dump(node, backup, argv, db_file, log_file, username, password):
    """Run a local mysqldump, streaming stdout to db_file; raise on any failure."""
    log_file.write(f"MariaDB: {_redact(' '.join(argv), username, password)}\n")
    with open(db_file, "wb") as out:
        proc = subprocess.run(
            argv,
            stdout=out,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT,
        )
    err_text = _decode(proc.stderr)
    if proc.returncode != 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message=f"mysqldump failed with exit code {proc.returncode}: "
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
            message="mysqldump produced an empty dump file (0 bytes).",
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
    log_file.write(f"MariaDB: {_redact(command, username, password)}\n")
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout._set_mode("rb")
    out_text = _decode(stdout.read())
    _ssh_check_result(node, backup, stdout, stderr, log_file, username, password, what)
    return out_text


def _ssh_dump_to_file(node, backup, ssh, command, db_file, log_file, username, password):
    """Run a remote mysqldump, streaming stdout to db_file (binary append); raise on failure."""
    log_file.write(f"MariaDB: {_redact(command, username, password)}\n")
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout._set_mode("rb")
    with open(db_file, "ab") as tmp:
        while True:
            chunk = stdout.read(65536)
            if not chunk:
                break
            tmp.write(chunk)
    _ssh_check_result(node, backup, stdout, stderr, log_file, username, password, "mysqldump")
    if os.path.getsize(db_file) == 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message="mysqldump produced an empty dump file (0 bytes).",
        )


def snapshot_mariadb(backup):
    node = backup.database.node
    encryption_key = node.connection.account.get_encryption_key()
    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)
    ssh_key_path = None
    local_defaults_path = None

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

        """
        Checking for connection
        """
        node.connection.auth_database.check_connection()

        option_flags = []
        if node.database.option_single_transaction:
            option_flags.append("--single-transaction")

        if node.database.option_skip_opt:
            option_flags.append("--skip-opt")

        if node.database.option_compress:
            option_flags.append("--compress")

        if node.connection.auth_database.include_stored_procedure:
            option_flags.append("--routines")
            option_flags.append("--triggers")

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

        dump_flags = option_flags + [
            "--no-tablespaces",
            "--max_allowed_packet=512M",
            "--skip-extended-insert",
        ]

        if (
                node.connection.auth_database.use_public_key
                or node.connection.auth_database.use_private_key
        ):
            ssh, ssh_key_path = node.connection.auth_database.get_ssh_client()
            remote_defaults_name = f"bs_{backup.uuid_str}.cnf"

            try:
                _sftp_write_remote_file(
                    ssh,
                    remote_defaults_name,
                    _defaults_file_content(
                        username,
                        password,
                        node.connection.auth_database.host,
                        node.connection.auth_database.port,
                        node.connection.auth_database.use_ssl,
                    ),
                )

                def remote_mysqldump(targets):
                    return " ".join(
                        ["mysqldump", f"--defaults-extra-file={remote_defaults_name}"]
                        + dump_flags
                        + targets
                    )

                # All database on server
                if node.database.all_databases:
                    # Find all databases first.
                    databases = []

                    out_text = _ssh_run_capture(
                        node,
                        backup,
                        ssh,
                        f"mysql --defaults-extra-file={remote_defaults_name}"
                        f' --disable-column-names -e "show databases;"',
                        log_file,
                        username,
                        password,
                        "mysql show databases",
                    )

                    for line in out_text.splitlines():
                        database_name = line.strip()
                        if database_name:
                            databases.append(database_name)

                    for database in databases:
                        safe_token(database, "database")
                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_mysqldump([database]),
                            f"{local_dir}{database}.sql",
                            log_file,
                            username,
                            password,
                        )
                # Selected databases on node
                elif node.database.databases:
                    for database in node.database.databases:
                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_mysqldump([database]),
                            f"{local_dir}{database}.sql",
                            log_file,
                            username,
                            password,
                        )
                # Means database name is selected at account level.
                elif node.database.all_tables:
                    _ssh_dump_to_file(
                        node,
                        backup,
                        ssh,
                        remote_mysqldump([node.connection.auth_database.database_name]),
                        f"{local_dir}{node.connection.auth_database.database_name}.sql",
                        log_file,
                        username,
                        password,
                    )
                # Again! means database name is selected at account level.
                elif node.database.tables:
                    for table in node.database.tables:
                        _ssh_dump_to_file(
                            node,
                            backup,
                            ssh,
                            remote_mysqldump([node.connection.auth_database.database_name, table]),
                            f"{local_dir}{table}.sql",
                            log_file,
                            username,
                            password,
                        )
            finally:
                try:
                    ssh.exec_command(f"rm -f {remote_defaults_name}")
                except Exception:
                    pass
                ssh.close()
        else:
            local_defaults_path = f"_storage/my_{backup.uuid}.cnf"
            _write_local_defaults_file(
                local_defaults_path,
                _defaults_file_content(
                    username,
                    password,
                    node.connection.auth_database.host,
                    node.connection.auth_database.port,
                    node.connection.auth_database.use_ssl,
                ),
            )

            def local_mysqldump(targets):
                return (
                    [f"{database_version_path}mysqldump", f"--defaults-extra-file={local_defaults_path}"]
                    + dump_flags
                    + targets
                )

            if node.database.all_tables:
                _run_direct_dump(
                    node,
                    backup,
                    local_mysqldump([node.connection.auth_database.database_name]),
                    f"{local_dir}{node.connection.auth_database.database_name}.sql",
                    log_file,
                    username,
                    password,
                )
            else:
                for table in node.database.tables:
                    _run_direct_dump(
                        node,
                        backup,
                        local_mysqldump([node.connection.auth_database.database_name, table]),
                        f"{local_dir}{table}.sql",
                        log_file,
                        username,
                        password,
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
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, e.__str__()
        )
    finally:
        log_file.close()

        """
        Delete the temporary defaults file holding the credentials.
        """
        if local_defaults_path and os.path.exists(local_defaults_path):
            try:
                os.remove(local_defaults_path)
            except OSError:
                pass

        """
        Delete temp SSH Key
        """
        if ssh_key_path:
            os.remove(ssh_key_path)
