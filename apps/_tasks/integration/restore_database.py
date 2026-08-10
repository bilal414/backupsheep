"""Crash-safe logical database restore engine.

Database restores are deliberately materialised into a deterministic target.  A
target is considered safe to adopt only when it contains the exact
BackupSheep-owned marker for this restore, backup, source database, and dump
content.  This is important because a database name can survive a worker crash
while the database contents do not have a transactional commit record.

The default is a new fork.  In-place restores are supported only when the API
has persisted ``mode=in_place`` together with an exact target mapping and
confirmation.  MySQL/MariaDB targets are recreated only after an exact marker
proves that the target belongs to this restore.  PostgreSQL imports use one
``ON_ERROR_STOP`` transaction per target and commit the marker in that same
transaction.

Secrets and provider/client diagnostics never enter the restore log or raised
exceptions.  Client argv contains no password; direct MySQL credentials live
in a 0600 defaults file, and SSH credentials/files are uploaded with 0600
permissions and removed in ``finally`` blocks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from collections import OrderedDict

from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup._sanitize import safe_password, safe_token
from apps._tasks.integration.backup.mysql import (
    _decode,
    _defaults_file_content,
    _write_local_defaults_file,
)
from apps._tasks.integration.backup.postgresql import _pgpass_escape
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
)
from apps._tasks.integration.restore_lease import RestoreLeaseLost
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.console.backup.models import RestoreExecutionLeaseLostError
from apps.console.connection.models import CoreAuthDatabase


# The client invocation is intentionally bounded.  The Celery soft time limit
# is also bounded, but a direct function call and an SSH channel must remain
# safe if they are used outside that task.
COMMAND_TIMEOUT = 12 * 3600
CLIENT_CONNECT_TIMEOUT = 15
SFTP_CLEANUP_TIMEOUT = 30
MARKER_VERSION = "1"
MYSQL_MARKER_TABLE = "__backupsheep_restore_marker"
POSTGRES_MARKER_SCHEMA = "__backupsheep_restore"
POSTGRES_MARKER_TABLE = "marker"
MAX_DATABASE_IDENTIFIER_LENGTH = 63
DATABASE_RESTORE_PERMISSION_ERROR_CODE = "DATABASE_RESTORE_PERMISSION_DENIED"


def _database_restore_permission_error(database_type):
    """Return a stable, actionable error without provider/client diagnostics."""
    if database_type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
        message = (
            "The configured PostgreSQL role cannot create the deterministic restore "
            "fork. Grant CREATEDB to the role (or use a role with CREATEDB), or "
            "choose an explicit in-place restore target. No target was changed."
        )
    else:
        message = (
            "The configured MySQL/MariaDB account lacks CREATE and DROP privileges "
            "covering the deterministic fork target(s). Grant both privileges globally "
            "or on each target/database wildcard, or choose an explicit in-place "
            "restore target. No target was changed."
        )
    error = RestoreError(message)
    error.code = DATABASE_RESTORE_PERMISSION_ERROR_CODE
    error.retryable = False
    return error


def _write_log(backup, text):
    """Append only safe, already-redacted operational text to the run log."""
    with open(f"_storage/restore_{backup.uuid_str}.log", "a+") as log_file:
        log_file.write(text)


def _has_restore_fence(restore):
    return bool(
        getattr(restore, "_required_restore_lease_owner", "")
        and getattr(restore, "_required_restore_lease_token", "")
    )


def _ensure_restore_fence(restore):
    """Refuse an external action when the task's durable lease is no longer live.

    The task binds the model instance to the same fence, so ``save`` protects
    the durable commit.  This read protects the gap before an external client
    or lftp operation is started.  Small in-memory test doubles intentionally
    have no manager and therefore run without a production fence.
    """
    if not _has_restore_fence(restore):
        return
    manager = getattr(restore.__class__, "objects", None)
    if manager is None:
        return
    owned = manager.filter(
        pk=restore.pk,
        lease_owner=restore._required_restore_lease_owner,
        lease_token=restore._required_restore_lease_token,
        lease_expires_at__gt=timezone.now(),
    ).exists()
    if not owned:
        raise RestoreLeaseLost("Restore execution lease ownership was lost.")


def _restore_work_suffix(restore, backup):
    """Return a non-secret worker suffix for local/remote temporary files."""
    owner = str(getattr(restore, "_required_restore_lease_owner", "") or "")
    token = str(getattr(restore, "_required_restore_lease_token", "") or "")
    if owner or token:
        return hashlib.sha256(f"{owner}|{token}".encode("utf-8")).hexdigest()[:16]
    return str(backup.uuid_str)


def _safe_failure(node, backup, what, code="CLIENT_FAILED"):
    """Build a user-safe failure without retaining stderr or exception bodies."""
    _write_log(backup, f"{what}: {code}\n")
    return NodeBackupFailedError(
        node,
        backup.uuid_str,
        getattr(backup, "attempt_no", 0),
        getattr(backup, "type", "database"),
        message=(
            "The database restore command could not complete. "
            "Secured diagnostics contain the detailed cause."
        ),
    )


def _capture_safe(code):
    """Send only a category to secured diagnostics, never an exception body."""
    capture_exception(RuntimeError(f"database restore diagnostic: {code}"))


def _sql_literal(value):
    """Quote a previously validated value for a SQL string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _mysql_identifier(value):
    safe_token(value, "database identifier")
    return "`" + str(value).replace("`", "``") + "`"


def _postgres_identifier(value):
    safe_token(value, "database identifier")
    return '"' + str(value).replace('"', '""') + '"'


def _validate_database_name(value, field="database"):
    value = safe_token(value, field)
    if not value or len(value) > MAX_DATABASE_IDENTIFIER_LENGTH:
        raise RestoreError(
            f"{field} is empty or exceeds the database identifier safety limit."
        )
    return value


def deterministic_target_name(restore, source_database):
    """Return the stable fork name for one source database.

    The correlation id is stable for the restore row and the source digest
    prevents two source databases in one restore from sharing a target.  The
    resulting name is valid for both PostgreSQL and MySQL identifier limits.
    """
    source_database = _validate_database_name(source_database, "source database")
    correlation = str(
        getattr(restore, "correlation_id", getattr(restore, "pk", "restore"))
    ).replace("-", "")
    source_digest = hashlib.sha256(source_database.encode("utf-8")).hexdigest()[:12]
    source_slug = re.sub(r"[^a-zA-Z0-9]+", "_", source_database).strip("_").lower()
    source_slug = source_slug[:22] or "database"
    return f"bs_restore_{correlation[:12]}_{source_slug}_{source_digest}"[:MAX_DATABASE_IDENTIFIER_LENGTH]


def _canonical_mapping(mapping):
    return json.dumps(
        OrderedDict(sorted(mapping.items())),
        sort_keys=True,
        separators=(",", ":"),
    )


def in_place_confirmation(mapping):
    """The exact, human-visible confirmation string accepted by the API."""
    return f"IN_PLACE_RESTORE_TO:{_canonical_mapping(mapping)}"


def _normalise_mapping(raw, *, field="target_mapping"):
    if not isinstance(raw, dict) or not raw:
        raise RestoreError(f"{field} must be a non-empty source-to-target object.")
    result = OrderedDict()
    targets = set()
    for source, target in sorted(raw.items(), key=lambda pair: str(pair[0])):
        source = _validate_database_name(source, "source database")
        target = _validate_database_name(target, "target database")
        if target in targets:
            raise RestoreError("target mapping contains an ambiguous duplicate target.")
        targets.add(target)
        result[source] = target
    return dict(result)


def _restore_mode(restore):
    params = dict(getattr(restore, "params", None) or {})
    mode = str(params.get("mode") or "fork").strip().lower()
    if mode not in {"fork", "in_place"}:
        raise RestoreError("restore mode is invalid; use fork or in_place.")
    return mode, params


def _save_restore(restore, fields):
    """Save durable state while retaining the restore lease fence when present."""
    _ensure_restore_fence(restore)
    fields = list(dict.fromkeys(fields))
    if "modified" not in fields:
        fields.append("modified")
    restore.save(update_fields=fields)


def _metadata(restore):
    value = getattr(restore, "execution_metadata", None)
    return dict(value or {})


def _checkpoint(
    restore,
    *,
    phase,
    mapping=None,
    source_digests=None,
    checkpoints=None,
    progress_total=None,
):
    """Persist mapping/checkpoints as safe, monotonic restore state."""
    values = _metadata(restore)
    if mapping is not None:
        old_mapping = values.get("source_to_target")
        if old_mapping is not None and old_mapping != mapping:
            raise RestoreError("restore source-to-target mapping changed; manual review is required.")
        values["source_to_target"] = dict(mapping)
        values["mapping_locked"] = True
    if source_digests is not None:
        old_digests = values.get("source_digests")
        if old_digests is not None and old_digests != source_digests:
            raise RestoreError("restore source archive content changed; manual review is required.")
        values["source_digests"] = dict(source_digests)
    current_checkpoints = dict(values.get("target_checkpoints") or {})
    if checkpoints:
        for target, checkpoint in checkpoints.items():
            existing = current_checkpoints.get(target) or {}
            if existing and (
                existing.get("source") != checkpoint.get("source")
                or existing.get("source_digest") != checkpoint.get("source_digest")
            ):
                raise RestoreError(
                    "restore target checkpoint changed; manual review is required."
                )

            old_status = str(existing.get("status") or "pending")
            new_status = str(checkpoint.get("status") or old_status)
            status_order = {"pending": 0, "importing": 1, "complete": 2}
            if status_order.get(new_status, -1) < status_order.get(old_status, -1):
                raise RestoreError(
                    "restore target checkpoint moved backwards; manual review is required."
                )
            if old_status == "complete" and new_status != "complete":
                raise RestoreError(
                    "completed restore target cannot be reopened automatically."
                )

            merged = dict(existing)
            merged.update(dict(checkpoint))
            old_files = dict(existing.get("files") or {})
            requested_files = dict(checkpoint.get("files") or {})
            merged_files = dict(old_files)
            file_order = {"pending": 0, "in_progress": 1, "complete": 2}
            for filename, file_state in requested_files.items():
                old_file = old_files.get(filename) or {}
                if old_file and (
                    old_file.get("sha256") != file_state.get("sha256")
                    or int(old_file.get("bytes") or 0) != int(file_state.get("bytes") or 0)
                ):
                    raise RestoreError(
                        "restore file checkpoint identity changed; manual review is required."
                    )
                old_file_status = str(old_file.get("status") or "pending")
                new_file_status = str(file_state.get("status") or old_file_status)
                if file_order.get(new_file_status, -1) < file_order.get(
                    old_file_status, -1
                ):
                    raise RestoreError(
                        "restore file checkpoint moved backwards; manual review is required."
                    )
                merged_file = dict(old_file)
                merged_file.update(dict(file_state))
                merged_files[filename] = merged_file
            if merged_files:
                merged["files"] = merged_files
            current_checkpoints[target] = merged
    values["target_checkpoints"] = current_checkpoints
    restore.execution_metadata = values
    restore.execution_phase = str(phase)[:64]
    completed = sum(
        1 for value in current_checkpoints.values() if value.get("status") == "complete"
    )
    restore.progress_completed = max(int(getattr(restore, "progress_completed", 0) or 0), completed)
    if progress_total is not None:
        restore.progress_total = int(progress_total)
    restore.progress_unit = "databases"
    _save_restore(
        restore,
        [
            "execution_phase",
            "execution_metadata",
            "progress_completed",
            "progress_total",
            "progress_unit",
        ],
    )


def _lock_params_mapping(restore, params, mapping):
    """Persist a mapping once, and reject every later mutation."""
    current = params.get("target_mapping")
    if current:
        current = _normalise_mapping(current)
        if current != mapping:
            raise RestoreError("restore target mapping is immutable and no longer matches the archive.")
        if params.get("mapping_locked") is not True:
            params["mapping_locked"] = True
            restore.params = params
            _save_restore(restore, ["params"])
        return params
    params["target_mapping"] = dict(mapping)
    params["mapping_locked"] = True
    restore.params = params
    _save_restore(restore, ["params"])
    return params


def _validate_extracted_archive(backup, auth, tree_root):
    """Validate every extracted dump before opening a database client."""
    sql_files = []
    for root, directories, files in os.walk(tree_root, followlinks=False):
        if root != tree_root or directories:
            raise RestoreError("stored database backup contains nested archive members.")
        for directory in directories:
            path = os.path.join(root, directory)
            if os.path.islink(path):
                raise RestoreError("stored backup contains a symbolic link.")
        for filename in files:
            path = os.path.join(root, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                raise RestoreError("stored backup contains an unsupported file.")
            if root != tree_root:
                # Database logical dumps are flat.  Nested members are not
                # executable restore inputs and are rejected before mutation.
                raise RestoreError("stored database backup contains a nested file.")
            if filename.endswith(".sql"):
                source_name = os.path.splitext(filename)[0]
                source_name = auth.database_name if (backup.tables and not backup.all_tables) else source_name
                _validate_database_name(source_name, "source database")
                if os.path.getsize(path) <= 0:
                    raise RestoreError("stored database backup contains an empty SQL dump.")
                sql_files.append((filename, path))
    if not sql_files:
        raise RestoreError("the backup archive does not contain any .sql dumps.")

    source_digests = {}
    targets = OrderedDict()
    tables_mode = bool(backup.tables) and not bool(backup.all_tables)
    for filename, path in sorted(sql_files):
        source = auth.database_name if tables_mode else os.path.splitext(filename)[0]
        source = _validate_database_name(source, "source database")
        digest = hashlib.sha256()
        byte_count = 0
        # Read the complete file.  ZIP CRC validation happens in
        # extract_backup_zip; this second pass validates the actual restore
        # input and gives the marker an immutable content identity.
        with open(path, "rb") as sql_file:
            for line in sql_file:
                # Plain logical dumps do not need psql client meta-commands
                # that can switch databases, read arbitrary local files, or
                # execute a shell command.  ``\\.`` is deliberately allowed:
                # it is the normal COPY-data terminator.
                if re.search(
                    rb"(?im)^\s*(?:\\(?:connect|include|ir|!|copy)\b|"
                    rb"(?:source|system)\b|(?:drop|create|alter)\s+database\b|"
                    rb"use\s+[^;]+;|(?:begin|commit|rollback|end)\s*;)",
                    line,
                ):
                    raise RestoreError("stored SQL contains an unsafe client directive.")
                lowered = line.lower()
                if (
                    MYSQL_MARKER_TABLE.encode("ascii") in lowered
                    or POSTGRES_MARKER_SCHEMA.encode("ascii") in lowered
                ):
                    raise RestoreError(
                        "stored SQL conflicts with BackupSheep restore ownership metadata."
                    )
                byte_count += len(line)
                digest.update(line)
        if byte_count <= 0:
            raise RestoreError("stored database backup contains an empty SQL dump.")
        source_digests.setdefault(source, []).append(
            {
                "file": filename,
                "bytes": byte_count,
                "sha256": digest.hexdigest(),
            }
        )
        targets.setdefault(source, []).append(path)

    source_digests = {
        source: sorted(files, key=lambda item: item["file"])
        for source, files in sorted(source_digests.items())
    }
    return targets, source_digests


def _source_digest(source_digests, source):
    return hashlib.sha256(
        _canonical_mapping({source: source_digests[source]}).encode("utf-8")
    ).hexdigest()


def _file_checkpoint_specs(source_digests, source):
    return {
        item["file"]: {
            "sha256": item["sha256"],
            "bytes": int(item["bytes"]),
            "status": "pending",
        }
        for item in source_digests[source]
    }


def _verify_source_files(source_digests, source, sql_paths):
    """Re-hash restore inputs immediately before a database-side effect."""
    expected = {
        item["file"]: (int(item["bytes"]), item["sha256"])
        for item in source_digests[source]
    }
    actual = {}
    for sql_path in sql_paths:
        filename = os.path.basename(sql_path)
        digest = hashlib.sha256()
        byte_count = 0
        with open(sql_path, "rb") as sql_file:
            for chunk in iter(lambda: sql_file.read(1024 * 1024), b""):
                byte_count += len(chunk)
                digest.update(chunk)
        actual[filename] = (byte_count, digest.hexdigest())
    if actual != expected:
        raise RestoreError(
            "the staged database dump changed after validation; manual review is required."
        )


def _load_or_create_mapping(restore, params, sources):
    sources = sorted(_validate_database_name(source, "source database") for source in sources)
    if len(sources) != len(set(sources)):
        raise RestoreError("the archive contains an ambiguous duplicate source database.")

    requested = params.get("target_mapping")
    if requested:
        mapping = _normalise_mapping(requested)
        if set(mapping) != set(sources):
            raise RestoreError("the persisted target mapping does not match the archive.")
    elif params.get("mode", "fork") == "in_place":
        raise RestoreError("in-place restore has no immutable target mapping.")
    else:
        mapping = {
            source: deterministic_target_name(restore, source)
            for source in sources
        }
    if len(set(mapping.values())) != len(mapping):
        raise RestoreError(
            "restore target mapping contains a duplicate target; manual review is required."
        )

    params = _lock_params_mapping(restore, params, mapping)

    if params.get("mode", "fork") == "in_place":
        if params.get("target_confirmation") != in_place_confirmation(mapping):
            raise RestoreError("in-place restore target confirmation is missing or changed.")

    existing = _metadata(restore).get("source_to_target")
    if existing is not None and _normalise_mapping(existing) != mapping:
        raise RestoreError("restore source-to-target mapping changed; manual review is required.")
    return mapping


def _classify_dumps(backup, auth, tree_root):
    """Return ``source_database -> [sql_path, ...]`` after full validation."""
    return _validate_extracted_archive(backup, auth, tree_root)[0]


def _run_direct(
    node,
    backup,
    argv,
    username,
    password,
    label,
    what,
    *,
    stdin_path=None,
    env=None,
    restore=None,
):
    """Run an argv-list client with a hard timeout and safe failure output."""
    # argv can contain SQL and database names but never credentials.  Do not
    # write the SQL or stderr to the persistent log.
    if restore is not None:
        _ensure_restore_fence(restore)
    _write_log(backup, f"{label}: started {what}\n")
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": COMMAND_TIMEOUT,
        "check": False,
    }
    if env is not None:
        kwargs["env"] = env
    try:
        if stdin_path is not None:
            with open(stdin_path, "rb") as sql_in:
                proc = subprocess.run(argv, stdin=sql_in, **kwargs)
        else:
            proc = subprocess.run(argv, **kwargs)
    except subprocess.TimeoutExpired as error:
        _capture_safe("CLIENT_TIMEOUT")
        raise _safe_failure(node, backup, what, "CLIENT_TIMEOUT") from None
    except OSError as error:
        _capture_safe("CLIENT_UNAVAILABLE")
        raise _safe_failure(node, backup, what, "CLIENT_UNAVAILABLE") from None
    if restore is not None:
        _ensure_restore_fence(restore)
    if proc.returncode != 0:
        error = _safe_failure(node, backup, what, "CLIENT_REJECTED")
        _capture_safe("CLIENT_REJECTED")
        raise error
    return _decode(proc.stdout)


def _ssh_run(node, backup, ssh, command, username, password, label, what, *, restore=None):
    """Run one bounded SSH command without persisting stdout/stderr bodies."""
    if restore is not None:
        _ensure_restore_fence(restore)
    _write_log(backup, f"{label}: started {what}\n")
    try:
        _stdin, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT)
        channel = getattr(stdout, "channel", None)
        if channel is not None and hasattr(channel, "settimeout"):
            channel.settimeout(COMMAND_TIMEOUT)
        out_text = _decode(stdout.read())
        # Read stderr to prevent a full remote stderr pipe from blocking, but
        # never return or persist its body.
        stderr.read()
        exit_status = channel.recv_exit_status() if channel is not None else 0
    except Exception as error:
        _capture_safe("SSH_COMMAND_FAILED")
        raise _safe_failure(node, backup, what, "SSH_COMMAND_FAILED") from None
    if restore is not None:
        _ensure_restore_fence(restore)
    if exit_status != 0:
        error = _safe_failure(node, backup, what, "SSH_COMMAND_REJECTED")
        _capture_safe("SSH_COMMAND_REJECTED")
        raise error
    return out_text


def _sftp_put(ssh, local_path, remote_name, *, restore=None):
    """Upload a temporary SQL file with a 0600 mode."""
    if restore is not None:
        _ensure_restore_fence(restore)
    sftp = ssh.open_sftp()
    try:
        channel = getattr(sftp, "get_channel", lambda: None)()
        if channel is not None and hasattr(channel, "settimeout"):
            channel.settimeout(COMMAND_TIMEOUT)
        sftp.put(local_path, remote_name)
        sftp.chmod(remote_name, 0o600)
        if restore is not None:
            _ensure_restore_fence(restore)
    finally:
        sftp.close()


def _sftp_write(ssh, remote_name, content, *, restore=None):
    """Write a remote credential file with a bounded 0600 SFTP channel."""
    if restore is not None:
        _ensure_restore_fence(restore)
    sftp = ssh.open_sftp()
    try:
        channel = getattr(sftp, "get_channel", lambda: None)()
        if channel is not None and hasattr(channel, "settimeout"):
            channel.settimeout(COMMAND_TIMEOUT)
        with sftp.open(remote_name, "w") as output:
            output.write(content)
        sftp.chmod(remote_name, 0o600)
        if restore is not None:
            _ensure_restore_fence(restore)
    finally:
        sftp.close()


def _sftp_remove(ssh, remote_name, *, restore=None):
    """Best-effort bounded cleanup of one remote temporary file."""
    # Cleanup is deliberately not fenced: it is called from finally blocks after
    # a worker may have lost its lease.  Callers provide worker-scoped names, so
    # this can only remove that worker's own temporary artifact.
    try:
        sftp = ssh.open_sftp()
        try:
            channel = getattr(sftp, "get_channel", lambda: None)()
            if channel is not None and hasattr(channel, "settimeout"):
                channel.settimeout(SFTP_CLEANUP_TIMEOUT)
            sftp.remove(remote_name)
        finally:
            sftp.close()
    except Exception as error:
        _capture_safe("SFTP_CLEANUP_FAILED")


def _marker_values(restore, backup, source, target, source_digest, state):
    return {
        "marker_version": MARKER_VERSION,
        "correlation_id": str(restore.correlation_id),
        "backup_uuid": str(backup.uuid),
        "source_database": source,
        "target_database": target,
        "source_digest": source_digest,
        "state": state,
    }


def _marker_matches(row, expected):
    if not isinstance(row, dict):
        return False
    return all(str(row.get(key, "")) == str(value) for key, value in expected.items() if key != "state")


def _parse_marker_row(text, fields):
    rows = [line.split("\t") for line in str(text or "").splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != len(fields):
        if rows:
            raise RestoreError("database restore found an ambiguous BackupSheep marker.")
        return None
    return dict(zip(fields, rows[0]))


def _mysql_query(
    node,
    backup,
    auth,
    defaults_arg,
    sql,
    username,
    password,
    what,
    *,
    ssh=None,
    restore=None,
):
    if ssh is not None:
        command = (
            f'mysql --defaults-extra-file="$HOME/{defaults_arg}" '
            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT} --batch "
            f"--skip-column-names -e {shlex.quote(sql)}"
        )
        return _ssh_run(
            node,
            backup,
            ssh,
            command,
            username,
            password,
            "MYSQL",
            what,
            restore=restore,
        )
    return _run_direct(
        node,
        backup,
        [
            f"{auth.bin_path()}mysql",
            defaults_arg,
            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT}",
            "--batch",
            "--skip-column-names",
            "-e",
            sql,
        ],
        username,
        password,
        "MYSQL",
        what,
        restore=restore,
    )


def _mysql_scope_pattern_matches(pattern, target):
    """Match one MySQL/MariaDB database grant pattern without SQL execution."""
    if pattern == target:
        return True
    regex = []
    escaped = False
    for character in str(pattern):
        if escaped:
            regex.append(re.escape(character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "%":
            regex.append(".*")
        elif character == "_":
            regex.append(".")
        else:
            regex.append(re.escape(character))
    if escaped:
        regex.append(re.escape("\\"))
    return re.fullmatch("".join(regex), str(target)) is not None


def _mysql_grant_capabilities(grants, target_names):
    """Return CREATE/DROP coverage for every resolved fork target.

    ``SHOW GRANTS`` output is treated as an opaque capability document.  It is
    never persisted or included in an exception.  Global ``*.*`` grants and
    database-scoped ``database.*`` grants are accepted only when their scope
    covers every target.  Table/column grants and unrelated database scopes do
    not count.
    """
    target_names = [str(target) for target in dict.fromkeys(target_names or ())]
    capabilities = {
        target: {"create": False, "drop": False} for target in target_names
    }
    for line in str(grants or "").splitlines():
        match = re.search(
            r"^\s*GRANT\s+(?P<privileges>.+?)\s+ON\s+(?P<scope>[^\s]+)\s+TO\s+",
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        raw_scope = match.group("scope").strip()
        if raw_scope.endswith(".*"):
            database_pattern = raw_scope[:-2].strip().strip("`")
        else:
            continue
        privileges = match.group("privileges").upper().strip()
        privilege_tokens = {
            token.strip().replace("`", "")
            for token in privileges.split(",")
        }
        grants_create = "CREATE" in privilege_tokens
        grants_drop = "DROP" in privilege_tokens
        if "ALL" in privilege_tokens or "ALL PRIVILEGES" in privilege_tokens:
            grants_create = True
            grants_drop = True
        if not grants_create and not grants_drop:
            continue

        for target in target_names:
            covers_target = database_pattern == "*" or _mysql_scope_pattern_matches(
                database_pattern, target
            )
            if covers_target:
                capabilities[target]["create"] |= grants_create
                capabilities[target]["drop"] |= grants_drop
    return capabilities


def _preflight_mysql_fork_permissions(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    *,
    defaults_arg,
    target_names,
    ssh=None,
):
    """Check fork CREATE/DROP capability without creating or dropping anything."""
    grants = _mysql_query(
        node,
        backup,
        auth,
        defaults_arg,
        "SHOW GRANTS;",
        username,
        password,
        "check MySQL restore privileges",
        ssh=ssh,
        restore=restore,
    )
    capabilities = _mysql_grant_capabilities(grants, target_names)
    if not capabilities or any(
        not capability["create"] or not capability["drop"]
        for capability in capabilities.values()
    ):
        raise _database_restore_permission_error(auth.type)
    return {"create": True, "drop": True}


def _mysql_marker_sql(target, marker):
    table = f"{_mysql_identifier(target)}.{_mysql_identifier(MYSQL_MARKER_TABLE)}"
    return (
        f"CREATE TABLE {_mysql_identifier(target)}.{_mysql_identifier(MYSQL_MARKER_TABLE)} ("
        "marker_key varchar(32) NOT NULL PRIMARY KEY, marker_version varchar(8) NOT NULL, "
        "correlation_id varchar(64) NOT NULL, backup_uuid varchar(128) NOT NULL, "
        "source_database varchar(255) NOT NULL, target_database varchar(255) NOT NULL, "
        "source_digest varchar(64) NOT NULL, state varchar(16) NOT NULL"
        "); INSERT INTO "
        f"{table} (marker_key, marker_version, correlation_id, backup_uuid, source_database, "
        "target_database, source_digest, state) VALUES ("
        f"'primary', {_sql_literal(marker['marker_version'])}, {_sql_literal(marker['correlation_id'])}, "
        f"{_sql_literal(marker['backup_uuid'])}, {_sql_literal(marker['source_database'])}, "
        f"{_sql_literal(marker['target_database'])}, {_sql_literal(marker['source_digest'])}, "
        f"{_sql_literal(marker['state'])});"
    )


def _mysql_marker_query(target):
    table = f"{_mysql_identifier(target)}.{_mysql_identifier(MYSQL_MARKER_TABLE)}"
    return (
        "SELECT marker_version, correlation_id, backup_uuid, source_database, "
        f"target_database, source_digest, state FROM {table} ORDER BY marker_key;"
    )


def _mysql_marker_update(target, marker):
    table = f"{_mysql_identifier(target)}.{_mysql_identifier(MYSQL_MARKER_TABLE)}"
    return (
        f"UPDATE {table} SET state='complete' WHERE marker_key='primary' "
        f"AND marker_version={_sql_literal(marker['marker_version'])} "
        f"AND correlation_id={_sql_literal(marker['correlation_id'])} "
        f"AND backup_uuid={_sql_literal(marker['backup_uuid'])} "
        f"AND source_database={_sql_literal(marker['source_database'])} "
        f"AND target_database={_sql_literal(marker['target_database'])} "
        f"AND source_digest={_sql_literal(marker['source_digest'])};"
    )


def _ensure_mysql_target(
    node,
    backup,
    restore,
    auth,
    source,
    target,
    source_digest,
    username,
    password,
    *,
    in_place,
    defaults_arg,
    ssh=None,
):
    exists_sql = (
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
        f"WHERE SCHEMA_NAME={_sql_literal(target)};"
    )
    exists = bool(
        _mysql_query(
            node,
            backup,
            auth,
            defaults_arg,
            exists_sql,
            username,
            password,
            "check MySQL target",
            ssh=ssh,
            restore=restore,
        ).strip()
    )
    expected = _marker_values(restore, backup, source, target, source_digest, "importing")
    marker_fields = [
        "marker_version", "correlation_id", "backup_uuid", "source_database",
        "target_database", "source_digest", "state",
    ]
    row = None

    if not exists:
        try:
            _mysql_query(
                node,
                backup,
                auth,
                defaults_arg,
                f"CREATE DATABASE {_mysql_identifier(target)}; {_mysql_marker_sql(target, expected)}",
                username,
                password,
                "create owned MySQL target",
                ssh=ssh,
                restore=restore,
            )
            row = dict(expected, _new=True)
        except NodeBackupFailedError as error:
            # A lost response is recoverable only if the exact marker now
            # exists.  Otherwise the name is ambiguous and we fail closed.
            _capture_safe("MYSQL_CREATE_OUTCOME_UNKNOWN")
            exists_after = _mysql_query(
                node,
                backup,
                auth,
                defaults_arg,
                exists_sql,
                username,
                password,
                "reconcile MySQL target",
                ssh=ssh,
                restore=restore,
            ).strip()
            if not exists_after:
                raise
            row_text = _mysql_query(
                node,
                backup,
                auth,
                defaults_arg,
                _mysql_marker_query(target),
                username,
                password,
                "reconcile MySQL marker",
                ssh=ssh,
                restore=restore,
            )
            row = _parse_marker_row(row_text, marker_fields)
            if not row or not _marker_matches(row, expected):
                raise RestoreError("MySQL target ownership is ambiguous; no changes were retried.") from None
    else:
        row_text = _mysql_query(
            node,
            backup,
            auth,
            defaults_arg,
            _mysql_marker_query(target),
            username,
            password,
            "check MySQL restore marker",
            ssh=ssh,
            restore=restore,
        )
        row = _parse_marker_row(row_text, marker_fields)
        if row is None:
            if not in_place:
                raise RestoreError("fork target name collision: existing MySQL database is not BackupSheep-owned.")
            # Explicit in-place authorization permits installing the exact
            # marker into an existing target, but never adopts an old marker.
            _mysql_query(
                node,
                backup,
                auth,
                defaults_arg,
                _mysql_marker_sql(target, expected),
                username,
                password,
                "claim explicit MySQL in-place target",
                ssh=ssh,
                restore=restore,
            )
            row = dict(expected, _new=True)
        elif not _marker_matches(row, expected):
            raise RestoreError("MySQL target marker does not belong to this restore.")

    state = str((row or expected).get("state") or "importing")
    if state not in {"importing", "complete"}:
        raise RestoreError("MySQL target marker has an unsupported state.")
    return row or expected


def _drop_mysql_owned_target(
    node,
    backup,
    auth,
    target,
    username,
    password,
    *,
    defaults_arg,
    ssh=None,
    restore=None,
):
    _mysql_query(
        node,
        backup,
        auth,
        defaults_arg,
        f"DROP DATABASE {_mysql_identifier(target)};",
        username,
        password,
        "recreate owned MySQL fork",
        ssh=ssh,
        restore=restore,
    )


def _restore_mysql_family(node, backup, restore, auth, targets, mapping, source_digests, username, password):
    """Restore MySQL/MariaDB sources into owned forks or explicit targets."""
    local_defaults_path = None
    ssh_key_path = None
    ssh = None
    remote_defaults_name = None
    worker_suffix = _restore_work_suffix(restore, backup)
    credential_suffix = f"_{worker_suffix}" if _has_restore_fence(restore) else ""
    if auth.use_public_key or auth.use_private_key:
        ssh, ssh_key_path = auth.get_ssh_client()
        remote_defaults_name = f".backupsheep_restore_{backup.uuid_str}{credential_suffix}.cnf"
        try:
            _sftp_write(
                ssh,
                remote_defaults_name,
                _defaults_file_content(username, password, auth.host, auth.port, auth.use_ssl),
                restore=restore,
            )
        except Exception:
            _sftp_remove(ssh, remote_defaults_name)
            try:
                ssh.close()
            except Exception as error:
                _capture_safe("MYSQL_SSH_CLOSE_FAILED")
            if ssh_key_path and os.path.exists(ssh_key_path):
                try:
                    os.remove(ssh_key_path)
                except OSError:
                    pass
            raise
        defaults_arg = remote_defaults_name
    else:
        local_defaults_path = f"_storage/my_restore_{backup.uuid_str}{credential_suffix}.cnf"
        _write_local_defaults_file(
            local_defaults_path,
            _defaults_file_content(username, password, auth.host, auth.port, auth.use_ssl),
        )
        defaults_arg = f"--defaults-extra-file={local_defaults_path}"
    try:
        mode, _params = _restore_mode(restore)
        in_place = mode == "in_place"
        for source, sql_paths in targets.items():
            _ensure_restore_fence(restore)
            target = mapping[source]
            digest = _source_digest(source_digests, source)
            file_specs = _file_checkpoint_specs(source_digests, source)
            marker = _ensure_mysql_target(
                node, backup, restore, auth, source, target, digest,
                username, password, in_place=in_place,
                defaults_arg=defaults_arg,
                ssh=ssh,
            )
            checkpoint = (_metadata(restore).get("target_checkpoints") or {}).get(target) or {}
            if checkpoint.get("status") == "complete":
                if marker.get("state") != "complete":
                    raise RestoreError("restore checkpoint and MySQL marker disagree.")
                _checkpoint(
                    restore,
                    phase="database_adopted",
                    mapping=mapping,
                    source_digests=source_digests,
                    progress_total=len(mapping),
                )
                continue
            if marker.get("state") == "complete":
                _checkpoint(
                    restore,
                    phase="database_adopted",
                    mapping=mapping,
                    source_digests=source_digests,
                    checkpoints={target: {
                        "source": source,
                        "source_digest": digest,
                        "status": "complete",
                        "adopted": True,
                    }},
                    progress_total=len(mapping),
                )
                continue
            if in_place:
                # DDL is nontransactional.  A partial in-place import cannot
                # safely be reconstructed without destroying an explicit user
                # target, so it is manual-review only.
                if marker.get("state") == "importing" and not marker.get("_new") and (
                    not checkpoint.get("files")
                    or any(
                        state.get("status") == "in_progress"
                        for state in checkpoint.get("files", {}).values()
                    )
                ):
                    raise RestoreError("interrupted in-place MySQL restore requires manual review.")
            else:
                # A marker in importing state proves ownership.  Recreate only
                # that owned fork so nontransactional DDL cannot be replayed
                # onto an unknown or user-owned database.
                if marker.get("state") == "importing" and not marker.get("_new") and not checkpoint.get("files"):
                    _drop_mysql_owned_target(
                        node,
                        backup,
                        auth,
                        target,
                        username,
                        password,
                        defaults_arg=defaults_arg,
                        ssh=ssh,
                        restore=restore,
                    )
                    marker = _ensure_mysql_target(
                        node, backup, restore, auth, source, target, digest,
                        username, password, in_place=False,
                        defaults_arg=defaults_arg,
                        ssh=ssh,
                    )
                    checkpoint = {}
                elif marker.get("state") == "importing" and any(
                    state.get("status") == "in_progress"
                    for state in checkpoint.get("files", {}).values()
                ):
                    raise RestoreError(
                        "the MySQL import outcome is ambiguous; manual review is required."
                    )

            existing_files = dict(checkpoint.get("files") or {})
            if existing_files:
                for filename, expected_file in file_specs.items():
                    current_file = existing_files.get(filename)
                    if current_file is None or (
                        current_file.get("sha256") != expected_file["sha256"]
                        or int(current_file.get("bytes") or 0) != expected_file["bytes"]
                    ):
                        raise RestoreError(
                            "the MySQL file checkpoint does not match the archive."
                        )
            file_states = {
                filename: dict(
                    file_specs[filename],
                    status=(existing_files.get(filename) or {}).get(
                        "status", "pending"
                    ),
                )
                for filename in file_specs
            }
            _checkpoint(
                restore,
                phase="database_importing",
                mapping=mapping,
                source_digests=source_digests,
                checkpoints={target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "importing",
                    "files": file_states,
                }},
                progress_total=len(mapping),
            )
            for sql_path in sql_paths:
                filename = os.path.basename(sql_path)
                file_state = (
                    _metadata(restore).get("target_checkpoints", {})
                    .get(target, {})
                    .get("files", {})
                    .get(filename, {})
                )
                if file_state.get("status") == "complete":
                    continue
                if file_state.get("status") == "in_progress":
                    raise RestoreError(
                        "the MySQL file import outcome is ambiguous; manual review is required."
                    )
                _checkpoint(
                    restore,
                    phase="database_importing_file",
                    mapping=mapping,
                    source_digests=source_digests,
                    checkpoints={target: {
                        "source": source,
                        "source_digest": digest,
                        "status": "importing",
                        "files": {
                            filename: dict(file_specs[filename], status="in_progress")
                        },
                    }},
                    progress_total=len(mapping),
                )
                if _has_restore_fence(restore):
                    _verify_source_files(source_digests, source, sql_paths)
                _ensure_restore_fence(restore)
                if ssh is None:
                    _run_direct(
                        node,
                        backup,
                        [
                            f"{auth.bin_path()}mysql",
                            defaults_arg,
                            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT}",
                            target,
                        ],
                        username,
                        password,
                        "MYSQL",
                        f"import source database {source}",
                        stdin_path=sql_path,
                        restore=restore,
                    )
                else:
                    remote_sql = (
                        f".backupsheep_restore_{backup.uuid_str}_{worker_suffix}_"
                        f"{hashlib.sha256(source.encode()).hexdigest()[:12]}_{hashlib.sha256(filename.encode()).hexdigest()[:8]}.sql"
                    )
                    _sftp_put(ssh, sql_path, remote_sql, restore=restore)
                    try:
                        _ssh_run(
                            node,
                            backup,
                            ssh,
                            f'mysql --defaults-extra-file="$HOME/{remote_defaults_name}" '
                            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT} "
                            f"{shlex.quote(target)} < \"$HOME/{remote_sql}\"",
                            username,
                            password,
                            "MYSQL",
                            f"import source database {source}",
                            restore=restore,
                        )
                    finally:
                        _sftp_remove(ssh, remote_sql)
                _checkpoint(
                    restore,
                    phase="database_importing",
                    mapping=mapping,
                    source_digests=source_digests,
                    checkpoints={target: {
                        "source": source,
                        "source_digest": digest,
                        "status": "importing",
                        "files": {
                            filename: dict(file_specs[filename], status="complete")
                        },
                    }},
                    progress_total=len(mapping),
                )
            _mysql_query(
                node, backup, auth,
                defaults_arg,
                _mysql_marker_update(target, _marker_values(restore, backup, source, target, digest, "importing")),
                username, password, "commit MySQL restore marker", ssh=ssh,
                restore=restore,
            )
            marker_after = _ensure_mysql_target(
                node,
                backup,
                restore,
                auth,
                source,
                target,
                digest,
                username,
                password,
                in_place=in_place,
                defaults_arg=defaults_arg,
                ssh=ssh,
            )
            if marker_after.get("state") != "complete":
                raise RestoreError("MySQL import finished without an exact completion marker.")
            _checkpoint(
                restore,
                phase="database_complete",
                mapping=mapping,
                source_digests=source_digests,
                checkpoints={target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "complete",
                }},
                progress_total=len(mapping),
            )
    finally:
        try:
            if local_defaults_path and os.path.exists(local_defaults_path):
                os.remove(local_defaults_path)
        except OSError:
            pass
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.remove(ssh_key_path)
            except OSError:
                pass
        if ssh is not None and remote_defaults_name:
            _sftp_remove(ssh, remote_defaults_name)
            try:
                ssh.close()
            except Exception as error:
                _capture_safe("MYSQL_SSH_CLOSE_FAILED")


def _pgpass_content(auth, username, password):
    return (
        f"{_pgpass_escape(auth.host)}:{_pgpass_escape(auth.port)}:*:"
        f"{_pgpass_escape(username)}:{_pgpass_escape(password)}\n"
    )


def _postgres_command(
    auth,
    username,
    database,
    sql=None,
    *,
    pgpass=None,
    file_path=None,
    tuples_only=False,
):
    parts = [f"PGCONNECT_TIMEOUT={CLIENT_CONNECT_TIMEOUT}"]
    if pgpass:
        parts.append(f'PGPASSFILE="$HOME/{pgpass}"')
    parts.extend([
        "psql",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        f"--host={shlex.quote(str(auth.host))}",
        f"--port={shlex.quote(str(auth.port))}",
        f"--username={shlex.quote(str(username))}",
        f"--dbname={shlex.quote(str(database))}",
    ])
    if tuples_only:
        parts.extend(["--tuples-only", "--no-align", "--quiet"])
    if sql is not None:
        parts.append(f"--command={shlex.quote(sql)}")
    if file_path is not None:
        parts.extend(["--single-transaction", f"--file={file_path}"])
    return " ".join(parts)


def _postgres_createdb_command(auth, username, target, *, pgpass=None):
    parts = [f"PGCONNECT_TIMEOUT={CLIENT_CONNECT_TIMEOUT}"]
    if pgpass:
        parts.append(f'PGPASSFILE="$HOME/{pgpass}"')
    parts.extend([
        "createdb",
        "--no-password",
        f"--host={shlex.quote(str(auth.host))}",
        f"--port={shlex.quote(str(auth.port))}",
        f"--username={shlex.quote(str(username))}",
        shlex.quote(str(target)),
    ])
    return " ".join(parts)


def _postgres_query_direct(
    node, backup, auth, defaults_env, username, database, sql, what, *, restore=None
):
    return _run_direct(
        node, backup,
        [
            f"{auth.bin_path()}psql", "--no-password",
            "--set=ON_ERROR_STOP=1",
            f"--host={auth.host}", f"--port={auth.port}",
            f"--username={username}", f"--dbname={database}",
            "--tuples-only", "--no-align", "--quiet", "--command", sql,
        ],
        username, "", "PostgreSQL", what,
        env=defaults_env,
        restore=restore,
    )


def _postgres_query(
    node,
    backup,
    auth,
    pg_env,
    username,
    database,
    sql,
    what,
    *,
    ssh=None,
    remote_pgpass=None,
    restore=None,
):
    if ssh is not None:
        return _ssh_run(
            node,
            backup,
            ssh,
            _postgres_command(
                auth,
                username,
                database,
                sql,
                pgpass=remote_pgpass,
                tuples_only=True,
            ),
            username,
            "",
            "PostgreSQL",
            what,
            restore=restore,
        )
    return _postgres_query_direct(
        node, backup, auth, pg_env, username, database, sql, what, restore=restore
    )


def _preflight_postgresql_fork_permissions(
    node,
    backup,
    restore,
    auth,
    username,
    *,
    pg_env,
    ssh=None,
    remote_pgpass=None,
):
    """Check the connected role's CREATEDB capability without mutation."""
    result = _postgres_query(
        node,
        backup,
        auth,
        pg_env,
        username,
        "postgres",
        (
            "SELECT CASE WHEN rolsuper OR rolcreatedb THEN '1' ELSE '0' END "
            "FROM pg_roles WHERE rolname=current_user;"
        ),
        "check PostgreSQL restore privileges",
        ssh=ssh,
        remote_pgpass=remote_pgpass,
        restore=restore,
    )
    if str(result or "").strip() != "1":
        raise _database_restore_permission_error(auth.type)
    return {"createdb": True}


def _preflight_database_restore_permissions(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    *,
    mode,
    mapping,
):
    """Run the no-mutation fork capability check for direct and SSH paths.

    Explicit in-place restores retain their existing semantics and do not
    require cluster/database creation privileges.  Fork restores are checked
    once after archive/mapping validation and before any target mutation.
    """
    if mode == "in_place":
        return None

    worker_suffix = _restore_work_suffix(restore, backup)
    target_names = list(dict.fromkeys((mapping or {}).values()))
    ssh = None
    ssh_key_path = None
    remote_name = None
    local_path = None
    try:
        if auth.type in (
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseType.MARIADB,
        ):
            if auth.use_public_key or auth.use_private_key:
                ssh, ssh_key_path = auth.get_ssh_client()
                remote_name = (
                    f".backupsheep_restore_preflight_{backup.uuid_str}_"
                    f"{worker_suffix}.cnf"
                )
                _sftp_write(
                    ssh,
                    remote_name,
                    _defaults_file_content(
                        username, password, auth.host, auth.port, auth.use_ssl
                    ),
                    restore=restore,
                )
                return _preflight_mysql_fork_permissions(
                    node,
                    backup,
                    restore,
                    auth,
                    username,
                    password,
                    defaults_arg=remote_name,
                    target_names=target_names,
                    ssh=ssh,
                )
            local_path = f"_storage/db_restore_preflight_{worker_suffix}.cnf"
            _write_local_defaults_file(
                local_path,
                _defaults_file_content(
                    username, password, auth.host, auth.port, auth.use_ssl
                ),
            )
            return _preflight_mysql_fork_permissions(
                node,
                backup,
                restore,
                auth,
                username,
                password,
                defaults_arg=f"--defaults-extra-file={local_path}",
                target_names=target_names,
            )

        if auth.type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
            pg_env = os.environ.copy()
            pg_env.pop("PGPASSWORD", None)
            pg_env["PGCONNECT_TIMEOUT"] = str(CLIENT_CONNECT_TIMEOUT)
            if auth.use_public_key or auth.use_private_key:
                ssh, ssh_key_path = auth.get_ssh_client()
                remote_name = (
                    f".backupsheep_restore_preflight_{backup.uuid_str}_"
                    f"{worker_suffix}.pgpass"
                )
                _sftp_write(
                    ssh,
                    remote_name,
                    _pgpass_content(auth, username, password),
                    restore=restore,
                )
                return _preflight_postgresql_fork_permissions(
                    node,
                    backup,
                    restore,
                    auth,
                    username,
                    pg_env=pg_env,
                    ssh=ssh,
                    remote_pgpass=remote_name,
                )
            descriptor, local_path = tempfile.mkstemp(
                prefix="bs_restore_preflight_",
                suffix=".pgpass",
                dir="_storage",
            )
            try:
                os.fchmod(descriptor, 0o600)
                os.write(
                    descriptor,
                    _pgpass_content(auth, username, password).encode("utf-8"),
                )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            pg_env["PGPASSFILE"] = local_path
            return _preflight_postgresql_fork_permissions(
                node,
                backup,
                restore,
                auth,
                username,
                pg_env=pg_env,
            )
        return None
    finally:
        if ssh is not None and remote_name:
            _sftp_remove(ssh, remote_name)
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                _capture_safe("DATABASE_PREFLIGHT_SSH_CLOSE_FAILED")
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.remove(ssh_key_path)
            except OSError:
                pass
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass


def _postgres_marker_sql(marker):
    schema = _postgres_identifier(POSTGRES_MARKER_SCHEMA)
    table = f"{schema}.{_postgres_identifier(POSTGRES_MARKER_TABLE)}"
    return (
        f"CREATE SCHEMA {schema}; CREATE TABLE {table} ("
        "marker_key text PRIMARY KEY, marker_version text NOT NULL, "
        "correlation_id text NOT NULL, backup_uuid text NOT NULL, "
        "source_database text NOT NULL, target_database text NOT NULL, "
        "source_digest text NOT NULL, state text NOT NULL"
        "); INSERT INTO "
        f"{table} (marker_key, marker_version, correlation_id, backup_uuid, source_database, "
        "target_database, source_digest, state) VALUES ("
        f"'primary', {_sql_literal(marker['marker_version'])}, {_sql_literal(marker['correlation_id'])}, "
        f"{_sql_literal(marker['backup_uuid'])}, {_sql_literal(marker['source_database'])}, "
        f"{_sql_literal(marker['target_database'])}, {_sql_literal(marker['source_digest'])}, "
        f"{_sql_literal(marker['state'])});"
    )


def _postgres_marker_query():
    table = f"{_postgres_identifier(POSTGRES_MARKER_SCHEMA)}.{_postgres_identifier(POSTGRES_MARKER_TABLE)}"
    return (
        "SELECT marker_version, correlation_id, backup_uuid, source_database, "
        f"target_database, source_digest, state FROM {table} ORDER BY marker_key;"
    )


def _postgres_marker_update(marker):
    table = f"{_postgres_identifier(POSTGRES_MARKER_SCHEMA)}.{_postgres_identifier(POSTGRES_MARKER_TABLE)}"
    return (
        f"UPDATE {table} SET state='complete' WHERE marker_key='primary' "
        f"AND marker_version={_sql_literal(marker['marker_version'])} "
        f"AND correlation_id={_sql_literal(marker['correlation_id'])} "
        f"AND backup_uuid={_sql_literal(marker['backup_uuid'])} "
        f"AND source_database={_sql_literal(marker['source_database'])} "
        f"AND target_database={_sql_literal(marker['target_database'])} "
        f"AND source_digest={_sql_literal(marker['source_digest'])};"
    )


def _ensure_postgres_target(
    node,
    backup,
    restore,
    auth,
    source,
    target,
    source_digest,
    username,
    password,
    *,
    in_place,
    pg_env,
    ssh=None,
    remote_pgpass=None,
):
    exists_sql = f"SELECT 1 FROM pg_database WHERE datname={_sql_literal(target)};"
    exists = bool(
        _postgres_query(
            node,
            backup,
            auth,
            pg_env,
            username,
            "postgres",
            exists_sql,
            "check PostgreSQL target",
            ssh=ssh,
            remote_pgpass=remote_pgpass,
            restore=restore,
        ).strip()
    )
    expected = _marker_values(restore, backup, source, target, source_digest, "importing")
    fields = [
        "marker_version", "correlation_id", "backup_uuid", "source_database",
        "target_database", "source_digest", "state",
    ]
    row = None
    if not exists:
        try:
            if ssh is None:
                _run_direct(
                    node, backup,
                    [
                        f"{auth.bin_path()}createdb", "--no-password",
                        f"--host={auth.host}", f"--port={auth.port}",
                        f"--username={username}", target,
                    ],
                    username, password, "PostgreSQL", "create owned PostgreSQL target", env=pg_env,
                    restore=restore,
                )
            else:
                _ssh_run(
                    node,
                    backup,
                    ssh,
                    _postgres_createdb_command(
                        auth, username, target, pgpass=remote_pgpass
                    ),
                    username,
                    password,
                    "PostgreSQL",
                    "create owned PostgreSQL target",
                    restore=restore,
                )
            _postgres_query(
                node,
                backup,
                auth,
                pg_env,
                username,
                target,
                _postgres_marker_sql(expected),
                "create PostgreSQL restore marker",
                ssh=ssh,
                remote_pgpass=remote_pgpass,
                restore=restore,
            )
            # The marker was created by this execution, so the first import
            # may proceed even when a durable restore fence is present.  A
            # later worker only receives ``_new`` through this acknowledged
            # path; an exact pre-existing importing marker remains fail-closed.
            row = dict(expected, _new=True)
        except NodeBackupFailedError as error:
            # A remote channel can lose the response after PostgreSQL has
            # accepted either the CREATE DATABASE or marker command.  Query
            # both sides and adopt only the exact marker; an unmarked name is
            # never retried or overwritten.
            _capture_safe("POSTGRES_CREATE_OUTCOME_UNKNOWN")
            exists_after = _postgres_query(
                node,
                backup,
                auth,
                pg_env,
                username,
                "postgres",
                exists_sql,
                "reconcile PostgreSQL target",
                ssh=ssh,
                remote_pgpass=remote_pgpass,
                restore=restore,
            ).strip()
            if not exists_after:
                raise error from None
            row_text = _postgres_query(
                node,
                backup,
                auth,
                pg_env,
                username,
                target,
                _postgres_marker_query(),
                "reconcile PostgreSQL marker",
                ssh=ssh,
                remote_pgpass=remote_pgpass,
                restore=restore,
            )
            row = _parse_marker_row(row_text, fields)
            if not row or not _marker_matches(row, expected):
                raise RestoreError("PostgreSQL target ownership is ambiguous; no changes were retried.") from None
    else:
        row_text = _postgres_query(
            node,
            backup,
            auth,
            pg_env,
            username,
            target,
            _postgres_marker_query(),
            "check PostgreSQL restore marker",
            ssh=ssh,
            remote_pgpass=remote_pgpass,
            restore=restore,
        )
        row = _parse_marker_row(row_text, fields)
    if row is None:
        if not in_place:
            raise RestoreError("fork target name collision: existing PostgreSQL database is not BackupSheep-owned.")
        _postgres_query(
            node,
            backup,
            auth,
            pg_env,
            username,
            target,
            _postgres_marker_sql(expected),
            "claim explicit PostgreSQL in-place target",
            ssh=ssh,
            remote_pgpass=remote_pgpass,
            restore=restore,
        )
        return expected
    if not _marker_matches(row, expected):
        raise RestoreError("PostgreSQL target marker does not belong to this restore.")
    state = str(row.get("state") or "")
    if state not in {"importing", "complete"}:
        raise RestoreError("PostgreSQL target marker has an unsupported state.")
    return row


def _build_combined_postgres_sql(sql_paths, marker):
    descriptor, path = tempfile.mkstemp(prefix="bs_restore_", suffix=".sql", dir="_storage")
    os.chmod(path, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            for sql_path in sql_paths:
                with open(sql_path, "rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        output.write(chunk)
                output.write(b"\n")
            output.write(_postgres_marker_update(marker).encode("utf-8"))
            output.write(b"\n")
            output.flush()
            os.fsync(output.fileno())
        return path
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def _restore_postgresql(node, backup, restore, auth, targets, mapping, source_digests, username, password):
    """Restore PostgreSQL dumps in one ON_ERROR_STOP transaction per target."""
    pg_env = os.environ.copy()
    pg_env.pop("PGPASSWORD", None)
    pg_env["PGCONNECT_TIMEOUT"] = str(CLIENT_CONNECT_TIMEOUT)
    ssh = None
    ssh_key_path = None
    remote_pgpass = None
    local_pgpass = None
    try:
        mode, _params = _restore_mode(restore)
        in_place = mode == "in_place"
        worker_suffix = _restore_work_suffix(restore, backup)
        credential_suffix = f"_{worker_suffix}" if _has_restore_fence(restore) else ""
        if auth.use_public_key or auth.use_private_key:
            ssh, ssh_key_path = auth.get_ssh_client()
            remote_pgpass = f".backupsheep_restore_{backup.uuid_str}{credential_suffix}.pgpass"
            _sftp_write(
                ssh,
                remote_pgpass,
                _pgpass_content(auth, username, password),
                restore=restore,
            )
        else:
            descriptor, local_pgpass = tempfile.mkstemp(
                prefix="bs_restore_",
                suffix=".pgpass",
                dir="_storage",
            )
            try:
                os.fchmod(descriptor, 0o600)
                os.write(
                    descriptor,
                    _pgpass_content(auth, username, password).encode("utf-8"),
                )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            pg_env["PGPASSFILE"] = local_pgpass

        for source, sql_paths in targets.items():
            _ensure_restore_fence(restore)
            target = mapping[source]
            digest = _source_digest(source_digests, source)
            file_specs = _file_checkpoint_specs(source_digests, source)
            marker = _ensure_postgres_target(
                node, backup, restore, auth, source, target, digest,
                username, password, in_place=in_place, pg_env=pg_env,
                ssh=ssh, remote_pgpass=remote_pgpass,
            )
            checkpoint = (_metadata(restore).get("target_checkpoints") or {}).get(target) or {}
            if checkpoint.get("status") == "complete":
                if marker.get("state") != "complete":
                    raise RestoreError("restore checkpoint and PostgreSQL marker disagree.")
                _checkpoint(
                    restore,
                    phase="database_adopted",
                    mapping=mapping,
                    source_digests=source_digests,
                    progress_total=len(mapping),
                )
                continue
            if marker.get("state") == "complete":
                _checkpoint(
                    restore,
                    phase="database_adopted",
                    mapping=mapping,
                    source_digests=source_digests,
                    checkpoints={target: {
                        "source": source,
                        "source_digest": digest,
                        "status": "complete",
                        "adopted": True,
                    }},
                    progress_total=len(mapping),
                )
                continue
            if (
                _has_restore_fence(restore)
                and marker.get("state") == "importing"
                and not marker.get("_new")
                and not checkpoint.get("files")
            ):
                raise RestoreError(
                    "the PostgreSQL import outcome is ambiguous; manual review is required."
                )
            existing_files = dict(checkpoint.get("files") or {})
            if existing_files:
                for filename, expected_file in file_specs.items():
                    current_file = existing_files.get(filename)
                    if current_file is None or (
                        current_file.get("sha256") != expected_file["sha256"]
                        or int(current_file.get("bytes") or 0) != expected_file["bytes"]
                    ):
                        raise RestoreError(
                            "the PostgreSQL file checkpoint does not match the archive."
                        )
                if any(
                    state.get("status") == "in_progress"
                    for state in existing_files.values()
                ):
                    raise RestoreError(
                        "the PostgreSQL import outcome is ambiguous; manual review is required."
                    )
            file_states = {
                filename: dict(
                    file_specs[filename],
                    status=(existing_files.get(filename) or {}).get(
                        "status", "pending"
                    ),
                )
                for filename in file_specs
            }
            _checkpoint(
                restore,
                phase="database_importing",
                mapping=mapping,
                source_digests=source_digests,
                checkpoints={target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "importing",
                    "files": {
                        filename: dict(state, status="in_progress")
                        for filename, state in file_states.items()
                        if state.get("status") != "complete"
                    },
                }},
                progress_total=len(mapping),
            )
            if _has_restore_fence(restore):
                _verify_source_files(source_digests, source, sql_paths)
            _ensure_restore_fence(restore)
            marker_for_update = _marker_values(restore, backup, source, target, digest, "importing")
            local_sql = _build_combined_postgres_sql(sql_paths, marker_for_update)
            remote_sql = None
            try:
                if ssh is not None:
                    remote_sql = (
                        f".backupsheep_restore_{backup.uuid_str}_{worker_suffix}_"
                        f"{hashlib.sha256(source.encode()).hexdigest()[:12]}.sql"
                    )
                    _sftp_put(ssh, local_sql, remote_sql, restore=restore)
                    command = _postgres_command(
                        auth,
                        username,
                        target,
                        pgpass=remote_pgpass,
                        file_path=f'"$HOME/{remote_sql}"',
                    )
                    _ssh_run(
                        node,
                        backup,
                        ssh,
                        command,
                        username,
                        password,
                        "PostgreSQL",
                        f"import source database {source}",
                        restore=restore,
                    )
                else:
                    _run_direct(
                        node, backup,
                        [
                            f"{auth.bin_path()}psql", "--no-password",
                            f"--host={auth.host}", f"--port={auth.port}",
                            f"--username={username}", f"--dbname={target}",
                            "--single-transaction", "--set=ON_ERROR_STOP=1",
                            "--file", local_sql,
                        ],
                        username, password, "PostgreSQL", f"import source database {source}",
                        env=pg_env,
                        restore=restore,
                    )
            finally:
                if remote_sql and ssh is not None:
                    _sftp_remove(ssh, remote_sql)
                try:
                    os.remove(local_sql)
                except OSError:
                    pass
            # The marker update was part of the transaction.  Query it before
            # recording the database checkpoint so a lost client response can
            # be adopted only from exact provider-side evidence.
            marker_after = _ensure_postgres_target(
                node, backup, restore, auth, source, target, digest,
                username, password, in_place=in_place, pg_env=pg_env,
                ssh=ssh, remote_pgpass=remote_pgpass,
            )
            if marker_after.get("state") != "complete":
                raise RestoreError("PostgreSQL import finished without an exact completion marker.")
            _checkpoint(
                restore,
                phase="database_complete",
                mapping=mapping,
                source_digests=source_digests,
                checkpoints={target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "complete",
                }},
                progress_total=len(mapping),
            )
    finally:
        if ssh is not None and remote_pgpass:
            _sftp_remove(ssh, remote_pgpass)
        if ssh is not None:
            try:
                ssh.close()
            except Exception as error:
                _capture_safe("POSTGRES_SSH_CLOSE_FAILED")
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.remove(ssh_key_path)
            except OSError:
                pass
        if local_pgpass and os.path.exists(local_pgpass):
            try:
                os.remove(local_pgpass)
            except OSError:
                pass


def restore_database(backup, restore):
    """Fetch, validate, and resume a logical database restore safely."""
    node = backup.database.node
    auth = node.connection.auth_database
    encryption_key = node.connection.account.get_encryption_key()
    work_suffix = _restore_work_suffix(restore, backup)
    work_prefix = f"restore_{backup.uuid_str}"
    if _has_restore_fence(restore):
        work_prefix = f"{work_prefix}_{work_suffix}"
    local_zip = f"_storage/{work_prefix}.zip"
    local_dir = f"_storage/{work_prefix}/"

    _write_log(backup, "Database restore started.\n")
    _write_log(backup, f"Backup UUID: {backup.uuid}\n")
    try:
        _ensure_restore_fence(restore)
        ensure_disk_space(
            int(max(3 * (backup.size or 0), 1 << 30)),
            what="database restore",
        )
        mode, params = _restore_mode(restore)
        stored_backup = restore.storage_point
        if stored_backup is None:
            raise RestoreError("the storage point this restore was created from no longer exists.")

        # Fetch and extract (including provider checksum, ZIP CRC, path, type,
        # size, compression-ratio, and disk checks) happen before any DB client
        # is opened or any target is created.
        _ensure_restore_fence(restore)
        fetch_backup_zip(stored_backup, local_zip)
        _ensure_restore_fence(restore)
        extract_backup_zip(local_zip, local_dir)
        _ensure_restore_fence(restore)
        targets, source_digests = _validate_extracted_archive(backup, auth, local_dir)
        mapping = _load_or_create_mapping(restore, params, targets.keys())
        _checkpoint(
            restore,
            phase="archive_validated",
            mapping=mapping,
            source_digests=source_digests,
            progress_total=len(mapping),
        )

        # Connection validation happens only after archive validation and
        # immutable mapping persistence.
        _ensure_restore_fence(restore)
        auth.check_connection()
        _ensure_restore_fence(restore)
        username = bs_decrypt(auth.username, encryption_key)
        password = bs_decrypt(auth.password, encryption_key)
        if username is None or password is None:
            raise RestoreError("Unable to decrypt the database credentials.")
        safe_token(auth.host, "host")
        safe_token(auth.port, "port")
        safe_token(username, "username")
        safe_password(password, "password")

        # Fork restores require a provider-side capability check before the
        # first target mutation.  Archive validation and immutable mapping
        # persistence have already completed, so this check cannot weaken
        # source-integrity or target-mapping validation.  Explicit in-place
        # restores intentionally skip the fork privilege requirement.
        _preflight_database_restore_permissions(
            node,
            backup,
            restore,
            auth,
            username,
            password,
            mode=mode,
            mapping=mapping,
        )
        _checkpoint(
            restore,
            phase=(
                "database_permissions_verified"
                if mode == "fork"
                else "database_ready"
            ),
            mapping=mapping,
            source_digests=source_digests,
            progress_total=len(mapping),
        )

        if auth.type in (
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseType.MARIADB,
        ):
            _restore_mysql_family(
                node, backup, restore, auth, targets, mapping, source_digests,
                username, password,
            )
        elif auth.type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
            _restore_postgresql(
                node, backup, restore, auth, targets, mapping, source_digests,
                username, password,
            )
        else:
            raise RestoreError(f"restores are not supported for database type {auth.type}.")
        _checkpoint(
            restore,
            phase="database_restore_complete",
            mapping=mapping,
            source_digests=source_digests,
            progress_total=len(mapping),
        )
        _write_log(backup, "Restore complete.\n")
    except (RestoreError, NodeBackupFailedError, RestoreLeaseLost, RestoreExecutionLeaseLostError):
        raise
    except Exception as error:
        # Capture only the secured exception channel; the user-visible/logged
        # restore state remains a generic safe outcome.
        _capture_safe("INTERNAL_ERROR")
        _write_log(backup, "Restore failed: INTERNAL_ERROR\n")
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            getattr(backup, "attempt_no", 0),
            getattr(backup, "type", "database"),
            message="The database restore could not complete. Secured diagnostics contain the detailed cause.",
        ) from None
    finally:
        delete_from_disk.apply_async(args=[work_prefix, "both"])
