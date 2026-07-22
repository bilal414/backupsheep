"""Database restore engine (MySQL / MariaDB / PostgreSQL).

One public entry point -- `restore_database(backup, restore)`:

  1. fetch the stored backup zip and extract the .sql dumps,
  2. classify each dump: a tables-mode backup (backup.tables without all_tables)
     imports every {table}.sql into the connection's database_name; otherwise the
     file stem is the target database name,
  3. ensure each target database exists, then import the dump with the native
     client.

The hardened patterns of the backup engines are mirrored exactly:

  * DIRECT mode runs the local client binaries as argv lists (no shell): creds
    via a temp defaults-extra-file (mysql/mariadb, first argv token, mode 0600)
    or the PGPASSWORD env (pg); the dump is fed on stdin from the open file.
  * SSH mode sftp-uploads the creds file (defaults file / pgpass, chmod 600) and
    the .sql dump, runs the remote client with `<` redirection, and removes the
    remote files afterwards (best-effort, plus the creds file in `finally`).
  * A non-zero exit status fails the restore with the redacted stderr tail;
    stderr on success is logged as warnings (never fatal).
  * Every user-controlled value interpolated into a command is screened with
    safe_token/safe_password first (same guards as the backup engines).

Notes: mysqldump dumps include DROP TABLE unless the node used skip-opt, so
importing into a non-empty database can fail -- that surfaces as a normal FAILED
restore carrying the server's message. A disk-space preflight (~3x the stored
zip: zip copy + extraction + import headroom) runs before the zip is fetched.
"""
import os
import subprocess

from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup._sanitize import safe_password, safe_token
from apps._tasks.integration.backup.mysql import (
    _decode,
    _defaults_file_content,
    _redact,
    _sftp_write_remote_file,
    _write_local_defaults_file,
)
from apps._tasks.integration.backup.postgresql import _pgpass_escape
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.console.connection.models import CoreAuthDatabase

# Hard cap on a single client invocation (12h), same as the backup engines.
COMMAND_TIMEOUT = 12 * 3600


def _write_log(backup, text):
    """Append to the restore's run log (_storage/restore_{uuid}.log)."""
    with open(f"_storage/restore_{backup.uuid_str}.log", "a+") as log_file:
        log_file.write(text)


def _classify_dumps(backup, auth, tree_root):
    """Map the extracted *.sql dumps to (database_name, sql_path) import targets.

    Tables-mode dumps ({table}.sql) always import into the connection's
    database_name; otherwise the file stem is the database name. The
    backupsheep.txt placeholder and the {uuid}.files manifest never match *.sql.
    """
    tables_mode = (not backup.all_tables) and backup.tables
    sql_files = sorted(
        name
        for name in os.listdir(tree_root)
        if name.endswith(".sql") and os.path.isfile(os.path.join(tree_root, name))
    )
    if not sql_files:
        raise RestoreError("the backup archive does not contain any .sql dumps.")
    targets = []
    for name in sql_files:
        if tables_mode:
            database = auth.database_name
        else:
            database = os.path.splitext(name)[0]
        targets.append((database, os.path.join(tree_root, name)))
    return targets


def _run_direct(node, backup, argv, username, password, label, what,
                stdin_path=None, env=None):
    """Run a local client binary (argv list, no shell); raise on non-zero exit.

    The dump is streamed in via stdin=open(sql_path, "rb"); stderr of a
    successful command is logged as warnings. Returns the stdout text."""
    _write_log(backup, f"{label}: {_redact(' '.join(argv), username, password)}\n")
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
              "timeout": COMMAND_TIMEOUT}
    if env is not None:
        kwargs["env"] = env
    if stdin_path is not None:
        with open(stdin_path, "rb") as sql_in:
            proc = subprocess.run(argv, stdin=sql_in, **kwargs)
    else:
        proc = subprocess.run(argv, **kwargs)
    err_text = _decode(proc.stderr)
    if proc.returncode != 0:
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            message=f"{what} failed with exit code {proc.returncode}: "
                    f"{_redact(err_text[-2000:], username, password)}",
        )
    for line in err_text.splitlines():
        if line.strip():
            _write_log(backup, f"WARNING: {_redact(line, username, password)}\n")
    return _decode(proc.stdout)


def _ssh_run(node, backup, ssh, command, username, password, label, what):
    """Run a remote client command; raise on non-zero exit status. Returns stdout text."""
    _write_log(backup, f"{label}: {_redact(command, username, password)}\n")
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout._set_mode("rb")
    out_text = _decode(stdout.read())
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
            _write_log(backup, f"WARNING: {_redact(line, username, password)}\n")
    return out_text


def _sftp_put(ssh, local_path, remote_name):
    """Upload a local file to the remote home directory (chmod 600)."""
    sftp = ssh.open_sftp()
    try:
        sftp.put(local_path, remote_name)
        sftp.chmod(remote_name, 0o600)
    finally:
        sftp.close()


def _restore_mysql_family(node, backup, auth, targets, username, password):
    """mysql/mariadb import, direct (local client + defaults file) or over SSH."""
    bin_path = auth.bin_path()
    ssh_key_path = None
    local_defaults_path = None
    try:
        if auth.use_public_key or auth.use_private_key:
            ssh, ssh_key_path = auth.get_ssh_client()
            remote_defaults_name = f"bs_restore_{backup.uuid_str}.cnf"
            try:
                _sftp_write_remote_file(
                    ssh,
                    remote_defaults_name,
                    _defaults_file_content(
                        username, password, auth.host, auth.port, auth.use_ssl
                    ),
                )
                for database, sql_path in targets:
                    # Single-quoted shell context: backticks must stay literal.
                    _ssh_run(
                        node, backup, ssh,
                        f"mysql --defaults-extra-file={remote_defaults_name}"
                        f" -e 'CREATE DATABASE IF NOT EXISTS `{database}`;'",
                        username, password, "MYSQL",
                        "mysql create database",
                    )
                    remote_sql = f"bs_restore_{backup.uuid_str}_{database}.sql"
                    _sftp_put(ssh, sql_path, remote_sql)
                    try:
                        _ssh_run(
                            node, backup, ssh,
                            f"mysql --defaults-extra-file={remote_defaults_name}"
                            f" {database} < {remote_sql}",
                            username, password, "MYSQL",
                            f"mysql import into {database}",
                        )
                    finally:
                        try:
                            ssh.exec_command(f"rm -f {remote_sql}")
                        except Exception:
                            pass
            finally:
                try:
                    ssh.exec_command(f"rm -f {remote_defaults_name}")
                except Exception:
                    pass
                ssh.close()
        else:
            local_defaults_path = f"_storage/my_restore_{backup.uuid_str}.cnf"
            _write_local_defaults_file(
                local_defaults_path,
                _defaults_file_content(
                    username, password, auth.host, auth.port, auth.use_ssl
                ),
            )
            for database, sql_path in targets:
                _run_direct(
                    node, backup,
                    [f"{bin_path}mysql", f"--defaults-extra-file={local_defaults_path}",
                     "-e", f"CREATE DATABASE IF NOT EXISTS `{database}`;"],
                    username, password, "MYSQL", "mysql create database",
                )
                _run_direct(
                    node, backup,
                    [f"{bin_path}mysql", f"--defaults-extra-file={local_defaults_path}",
                     database],
                    username, password, "MYSQL",
                    f"mysql import into {database}", stdin_path=sql_path,
                )
    finally:
        if local_defaults_path and os.path.exists(local_defaults_path):
            try:
                os.remove(local_defaults_path)
            except OSError:
                pass
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)


def _restore_postgresql(node, backup, auth, targets, username, password):
    """PostgreSQL import, direct (local client + PGPASSWORD env) or over SSH."""
    bin_path = auth.bin_path()
    ssh_key_path = None
    try:
        if auth.use_public_key or auth.use_private_key:
            ssh, ssh_key_path = auth.get_ssh_client()
            remote_pgpass_name = f"bs_restore_{backup.uuid_str}.pgpass"
            try:
                _sftp_write_remote_file(
                    ssh,
                    remote_pgpass_name,
                    f"{_pgpass_escape(auth.host)}"
                    f":{_pgpass_escape(auth.port)}"
                    f":*:{_pgpass_escape(username)}:{_pgpass_escape(password)}\n",
                )
                for database, sql_path in targets:
                    out_text = _ssh_run(
                        node, backup, ssh,
                        f"PGPASSFILE=~/{remote_pgpass_name} psql"
                        f" 'host={auth.host} user={username} dbname=postgres"
                        f" port={auth.port} sslmode=prefer'"
                        f" -tAc \"SELECT 1 FROM pg_database WHERE datname = '{database}'\"",
                        username, password, "PostgreSQL",
                        "psql database check",
                    )
                    if not out_text.strip():
                        _ssh_run(
                            node, backup, ssh,
                            f"PGPASSFILE=~/{remote_pgpass_name} createdb"
                            f" -h {auth.host} -p {auth.port} -U {username} {database}",
                            username, password, "PostgreSQL", "createdb",
                        )
                    remote_sql = f"bs_restore_{backup.uuid_str}_{database}.sql"
                    _sftp_put(ssh, sql_path, remote_sql)
                    try:
                        _ssh_run(
                            node, backup, ssh,
                            f"PGPASSFILE=~/{remote_pgpass_name} psql"
                            f" -h {auth.host} -p {auth.port} -U {username}"
                            f" -d {database} < {remote_sql}",
                            username, password, "PostgreSQL",
                            f"psql import into {database}",
                        )
                    finally:
                        try:
                            ssh.exec_command(f"rm -f {remote_sql}")
                        except Exception:
                            pass
            finally:
                try:
                    ssh.exec_command(f"rm -f ~/{remote_pgpass_name}")
                except Exception:
                    pass
                ssh.close()
        else:
            # Password travels only in the process environment, never on argv.
            pg_env = os.environ.copy()
            pg_env["PGPASSWORD"] = password
            for database, sql_path in targets:
                out_text = _run_direct(
                    node, backup,
                    [f"{bin_path}psql", "-h", str(auth.host), "-p", str(auth.port),
                     "-U", username, "-d", "postgres", "-tAc",
                     f"SELECT 1 FROM pg_database WHERE datname = '{database}'"],
                    username, password, "PostgreSQL", "psql database check",
                    env=pg_env,
                )
                if not out_text.strip():
                    _run_direct(
                        node, backup,
                        [f"{bin_path}createdb", "-h", str(auth.host), "-p", str(auth.port),
                         "-U", username, database],
                        username, password, "PostgreSQL", "createdb",
                        env=pg_env,
                    )
                _run_direct(
                    node, backup,
                    [f"{bin_path}psql", "-h", str(auth.host), "-p", str(auth.port),
                     "-U", username, "-d", database],
                    username, password, "PostgreSQL",
                    f"psql import into {database}", stdin_path=sql_path, env=pg_env,
                )
    finally:
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)


def restore_database(backup, restore):
    node = backup.database.node
    auth = node.connection.auth_database
    encryption_key = node.connection.account.get_encryption_key()

    local_zip = f"_storage/restore_{backup.uuid_str}.zip"
    local_dir = f"_storage/restore_{backup.uuid_str}/"

    _write_log(backup, f"Node: {node.name}\n")
    _write_log(backup, f"Backup UUID: {backup.uuid}\n")
    _write_log(backup, f"Restore: {restore.name}\n")

    try:
        # Disk-space preflight: the fetched zip plus the extracted .sql dumps
        # plus import headroom (~3x the stored zip) must fit before fetching.
        ensure_disk_space(
            int(max(3 * (backup.size or 0), 1 << 30)),
            what="database restore",
        )

        stored_backup = restore.storage_point
        if stored_backup is None:
            raise RestoreError(
                "the storage point this restore was created from no longer exists."
            )

        _write_log(backup, f"Fetching backup zip from storage: {stored_backup.storage.name}\n")
        fetch_backup_zip(stored_backup, local_zip)
        extract_backup_zip(local_zip, local_dir)
        targets = _classify_dumps(backup, auth, local_dir)
        _write_log(
            backup,
            "Import targets: " + ", ".join(database for database, _ in targets) + "\n",
        )

        auth.check_connection()

        username = bs_decrypt(auth.username, encryption_key)
        password = bs_decrypt(auth.password, encryption_key)
        if username is None or password is None:
            raise RestoreError("Unable to decrypt the database credentials.")

        # Reject command-injection payloads in the user-supplied connection fields
        # before they are interpolated into the client commands below.
        safe_token(auth.host, "host")
        safe_token(auth.port, "port")
        safe_token(username, "username")
        safe_password(password, "password")
        for database, _sql_path in targets:
            safe_token(database, "database")

        if auth.type in (
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseType.MARIADB,
        ):
            _restore_mysql_family(node, backup, auth, targets, username, password)
        elif auth.type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
            _restore_postgresql(node, backup, auth, targets, username, password)
        else:
            raise RestoreError(
                f"restores are not supported for database type {auth.type}."
            )

        _write_log(backup, "Restore complete.\n")
    except (RestoreError, NodeBackupFailedError):
        raise
    except Exception as e:
        _write_log(backup, f"Error: {e}\n")
        capture_exception(e)
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, str(e)
        )
    finally:
        # The fetched zip + extracted dumps are always discarded; the run log is
        # kept (delete_from_disk never touches .log files).
        delete_from_disk.apply_async(args=[f"restore_{backup.uuid_str}", "both"])
