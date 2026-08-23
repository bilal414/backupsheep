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

import errno
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections import OrderedDict

from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup._mysql_schema import database_defaults_preamble
from apps._tasks.integration.backup._sanitize import safe_password, safe_token
from apps._tasks.integration.backup.mariadb import (
    _defaults_file_content as _mariadb_defaults_file_content,
)
from apps._tasks.integration.backup.mysql import (
    _decode,
    _defaults_file_content as _mysql_defaults_file_content,
    _write_local_defaults_file,
)
from apps._tasks.integration.backup.postgresql import _pgpass_escape
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
    stale_local_restore_work_prefixes,
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
POSTGRES_MARKER_RELATION_SENTINEL = "__BACKUPSHEEP_MARKER_RELATION_PRESENT__"
MAX_DATABASE_IDENTIFIER_LENGTH = 63
DATABASE_RESTORE_PERMISSION_ERROR_CODE = "DATABASE_RESTORE_PERMISSION_DENIED"
DATABASE_RESTORE_SYSTEM_DEFINER_ERROR_CODE = (
    "DATABASE_RESTORE_SYSTEM_DEFINER_REQUIRED"
)
MAX_MYSQL_DEFINER_LINE_WITNESSES = 4096
SFTP_OPEN_TIMEOUT = 30
REMOTE_RESTORE_PREFIX = ".backupsheep_restore_"
REMOTE_RESTORE_CORRELATION_RE = r"(?:[0-9a-f]{32}|[0-9a-f]{64})"
REMOTE_RESTORE_ARTIFACT_RE = re.compile(
    rf"^{re.escape(REMOTE_RESTORE_PREFIX)}"
    rf"(?P<backup>[0-9a-f]{{32}})_"
    rf"(?P<correlation>{REMOTE_RESTORE_CORRELATION_RE})_"
    rf"(?P<fence>[0-9a-f]{{16}})_"
    rf"(?P<kind>mysql_credentials|mysql_preflight_credentials|"
    rf"postgres_credentials|postgres_preflight_credentials|"
    rf"mysql_sql|postgres_sql)"
    rf"(?:_(?P<source>[0-9a-f]{{12}})_(?P<file>[0-9a-f]{{12}}))?"
    rf"\.(?P<extension>cnf|pgpass|sql)$"
)
REMOTE_RESTORE_CREDENTIAL_EXTENSIONS = {
    "mysql_credentials": "cnf",
    "mysql_preflight_credentials": "cnf",
    "postgres_credentials": "pgpass",
    "postgres_preflight_credentials": "pgpass",
}
REMOTE_RESTORE_SQL_KINDS = {"mysql_sql", "postgres_sql"}
_LEGACY_BACKUP_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# Historical BackupSheep PostgreSQL dumps used ``pg_dump --clean`` without
# ``--if-exists``. A strict import into a fresh fork therefore stopped at the
# first absent source object. Compatibility is deliberately limited to the
# database-local object classes emitted by pg_dump's cleanup preamble. Cluster
# scoped statements such as DROP DATABASE, DROP ROLE, DROP OWNED, and DROP
# TABLESPACE are not accepted.
POSTGRES_HISTORICAL_CLEANUP_OBJECTS = tuple(
    value.encode("ascii")
    for value in (
        "TEXT SEARCH CONFIGURATION",
        "TEXT SEARCH DICTIONARY",
        "TEXT SEARCH TEMPLATE",
        "TEXT SEARCH PARSER",
        "FOREIGN DATA WRAPPER",
        "MATERIALIZED VIEW",
        "OPERATOR FAMILY",
        "OPERATOR CLASS",
        "EVENT TRIGGER",
        "USER MAPPING",
        "FOREIGN TABLE",
        "AGGREGATE",
        "COLLATION",
        "CONVERSION",
        "PUBLICATION",
        "STATISTICS",
        "PROCEDURE",
        "EXTENSION",
        "TRANSFORM",
        "FUNCTION",
        "LANGUAGE",
        "OPERATOR",
        "POLICY",
        "ROUTINE",
        "SEQUENCE",
        "TRIGGER",
        "DOMAIN",
        "INDEX",
        "RULE",
        "SCHEMA",
        "SERVER",
        "TABLE",
        "TYPE",
        "VIEW",
        "CAST",
    )
)
POSTGRES_COMPAT_PREAMBLE_MAX_LINE_BYTES = 1024 * 1024
POSTGRES_COMPAT_TAIL_BYTES = 64 * 1024


class RemoteRestoreCleanupError(RestoreError):
    """Safe, classified failure proving that remote restore cleanup is incomplete."""

    def __init__(self, category, *, retryable):
        self.category = str(category)
        self.retryable = bool(retryable)
        self.code = (
            "RESTORE_TRANSIENT_FAILURE"
            if self.retryable
            else "RESTORE_RECONCILIATION_REQUIRED"
        )
        if self.retryable:
            message = (
                "Remote database restore cleanup could not be verified because the "
                "remote connection is temporarily unavailable. The restore will resume "
                "automatically."
            )
        else:
            message = (
                "Remote database restore cleanup could not be proven safe. The logical "
                "restore state was preserved and manual reconciliation is required "
                "before retrying."
            )
        super().__init__(message)


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


def _database_restore_definer_permission_error(database_type):
    """Return safe guidance when a dump contains foreign DEFINER clauses."""
    if database_type == CoreAuthDatabase.DatabaseType.MARIADB:
        privilege = "SET USER (or the legacy SUPER privilege)"
    else:
        privilege = (
            "SET_USER_ID for MySQL 8.0, or SET_ANY_DEFINER and "
            "ALLOW_NONEXISTENT_DEFINER for MySQL 8.4"
        )
    error = RestoreError(
        "The stored database dump contains explicit DEFINER clauses, but the "
        f"configured account cannot preserve them. Grant {privilege} to a "
        "dedicated restore account, then resume verification. No target was changed "
        "by this verification attempt."
    )
    error.code = DATABASE_RESTORE_PERMISSION_ERROR_CODE
    error.retryable = False
    return error


def _database_restore_system_definer_error():
    """Return safe MySQL 8.4 guidance for a SYSTEM_USER-owned object."""
    error = RestoreError(
        "The stored MySQL dump recreates an object whose definer is a protected "
        "SYSTEM_USER account. Grant SYSTEM_USER to a dedicated restore account, "
        "then resume verification. The source database was not changed, and the "
        "exact-owned restore fork was retained for safe reconciliation."
    )
    error.code = DATABASE_RESTORE_SYSTEM_DEFINER_ERROR_CODE
    error.retryable = False
    return error


def _database_restore_binlog_permission_error(*, verification_failed=False):
    """Return safe MySQL trigger/function binary-log guidance."""
    if verification_failed:
        message = (
            "BackupSheep could not verify the MySQL binary-log requirements for "
            "restoring stored functions or triggers. Verify the server's log_bin "
            "and log_bin_trust_function_creators settings, then resume verification. "
            "No target was changed."
        )
    else:
        message = (
            "The stored MySQL dump creates a trigger or stored function while "
            "binary logging is enabled and log_bin_trust_function_creators is off. "
            "Grant SUPER to a dedicated restore account, or have a database "
            "administrator explicitly review that server setting, then resume "
            "verification. No target was changed."
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


def _remote_identity_token(value):
    """Return a fixed-width, non-secret token for a restore identity value."""
    normalised = str(value or "").replace("-", "").lower()
    if re.fullmatch(r"[0-9a-f]{32}", normalised):
        return normalised
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:32]


def _remote_restore_identity(restore, backup):
    """Return the exact deterministic identity embedded in remote temp names."""
    backup_value = getattr(backup, "uuid_str", None)
    if backup_value is None:
        backup_value = getattr(backup, "uuid", "")
    return {
        "backup": _remote_identity_token(backup_value),
        "correlation": _remote_identity_token(
            getattr(restore, "correlation_id", getattr(restore, "pk", "restore"))
        ),
        "fence": hashlib.sha256(
            (
                f"{getattr(restore, '_required_restore_lease_owner', '')}|"
                f"{getattr(restore, '_required_restore_lease_token', '')}"
            ).encode("utf-8")
        ).hexdigest()[:16]
        if _has_restore_fence(restore)
        else hashlib.sha256(
            f"unfenced|{getattr(backup, 'uuid_str', getattr(backup, 'uuid', ''))}|"
            f"{getattr(restore, 'correlation_id', getattr(restore, 'pk', 'restore'))}".encode(
                "utf-8"
            )
        ).hexdigest()[:16],
    }


def _remote_restore_temp_name(
    restore,
    backup,
    kind,
    *,
    source=None,
    filename=None,
):
    """Build one strict, correlation- and fence-scoped remote basename."""
    identity = _remote_restore_identity(restore, backup)
    if kind in REMOTE_RESTORE_CREDENTIAL_EXTENSIONS:
        if source is not None or filename is not None:
            raise RestoreError("remote credential temp name has an invalid scope.")
        return (
            f"{REMOTE_RESTORE_PREFIX}{identity['backup']}_"
            f"{identity['correlation']}_{identity['fence']}_{kind}."
            f"{REMOTE_RESTORE_CREDENTIAL_EXTENSIONS[kind]}"
        )
    if kind not in REMOTE_RESTORE_SQL_KINDS or source is None or filename is None:
        raise RestoreError("remote SQL temp name has an invalid scope.")
    source_token = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:12]
    file_token = hashlib.sha256(str(filename).encode("utf-8")).hexdigest()[:12]
    return (
        f"{REMOTE_RESTORE_PREFIX}{identity['backup']}_"
        f"{identity['correlation']}_{identity['fence']}_{kind}_"
        f"{source_token}_{file_token}.sql"
    )


def _parse_remote_restore_temp_name(remote_name):
    """Parse only names in the private BackupSheep remote-temp namespace."""
    if not isinstance(remote_name, str) or remote_name != os.path.basename(remote_name):
        return None
    match = REMOTE_RESTORE_ARTIFACT_RE.fullmatch(remote_name)
    if not match:
        return None
    values = match.groupdict()
    kind = values["kind"]
    extension = values["extension"]
    if kind in REMOTE_RESTORE_CREDENTIAL_EXTENSIONS:
        if values["source"] or values["file"]:
            return None
        if REMOTE_RESTORE_CREDENTIAL_EXTENSIONS[kind] != extension:
            return None
    elif kind in REMOTE_RESTORE_SQL_KINDS:
        if not values["source"] or not values["file"] or extension != "sql":
            return None
    else:
        return None
    return values


def _remote_temp_name_matches_restore(
    remote_name,
    restore,
    backup,
    *,
    kinds=None,
    require_current_fence=False,
):
    """Return parsed ownership evidence for one exact restore/backup pair."""
    if backup is None:
        return None
    parsed = _parse_remote_restore_temp_name(remote_name)
    if parsed is None:
        return None
    if kinds is not None and parsed["kind"] not in set(kinds):
        return None
    identity = _remote_restore_identity(restore, backup)
    if (
        parsed["backup"] != identity["backup"]
        or parsed["correlation"] != identity["correlation"]
    ):
        return None
    if require_current_fence and parsed["fence"] != identity["fence"]:
        return None
    return parsed


def _legacy_remote_temp_name_matches_backup(remote_name, backup):
    """Match only the exact private filenames emitted by pre-fence workers.

    Legacy names did not carry a restore correlation.  The backup UUID and the
    known worker suffixes are therefore intentionally part of the strict
    parser; arbitrary dotfiles, another backup, and names with path components
    never enter the cleanup set.
    """
    if backup is None or not isinstance(remote_name, str):
        return None
    if remote_name != os.path.basename(remote_name):
        return None
    backup_uuid = str(getattr(backup, "uuid_str", getattr(backup, "uuid", ""))).lower()
    if not _LEGACY_BACKUP_UUID_RE.fullmatch(backup_uuid):
        return None
    suffix = rf"(?:[0-9a-f]{{16}}|{re.escape(backup_uuid)})"
    patterns = (
        (
            "legacy_credentials",
            re.compile(
                rf"^\.backupsheep_restore_{re.escape(backup_uuid)}"
                rf"(?:_{suffix})?\.(?P<extension>cnf|pgpass)$"
            ),
        ),
        (
            "legacy_preflight_credentials",
            re.compile(
                rf"^\.backupsheep_restore_preflight_{re.escape(backup_uuid)}"
                rf"_{suffix}\.(?P<extension>cnf|pgpass)$"
            ),
        ),
        (
            "legacy_mysql_sql",
            re.compile(
                rf"^\.backupsheep_restore_{re.escape(backup_uuid)}_{suffix}_"
                rf"[0-9a-f]{{12}}_[0-9a-f]{{8}}\.sql$"
            ),
        ),
        (
            "legacy_postgres_sql",
            re.compile(
                rf"^\.backupsheep_restore_{re.escape(backup_uuid)}_{suffix}_"
                rf"[0-9a-f]{{12}}\.sql$"
            ),
        ),
    )
    for kind, pattern in patterns:
        match = pattern.fullmatch(remote_name)
        if match:
            return {
                "legacy": True,
                "backup": backup_uuid,
                "kind": kind,
                "extension": match.groupdict().get("extension"),
            }
    return None


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


def _raise_remote_cleanup_failure(category, *, retryable=None):
    """Raise a safe cleanup outcome after recording only its category."""
    category = str(category or "SFTP_CLEANUP_FAILED")
    if retryable is None:
        # Residue may include credentials or SQL.  Never automatically retry
        # while cleanup is unproven; the only idempotent success path is a
        # NOT_FOUND response after the delete request was actually started.
        retryable = False
    _capture_safe(category)
    raise RemoteRestoreCleanupError(category, retryable=retryable)


def _open_sftp_bounded(ssh, timeout):
    """Open SFTP with Paramiko's bounded channel-open timeout.

    Paramiko's ``SSHClient.open_sftp`` delegates to ``Transport.open_session``;
    that call uses ``Transport.channel_timeout``.  Set it only around the open,
    then restore the transport value before any SFTP operation.  This keeps the
    channel-open wait bounded without creating helper threads that cannot be
    terminated safely.
    """
    transport = None
    get_transport = getattr(ssh, "get_transport", None)
    if callable(get_transport):
        transport = get_transport()
    sentinel = object()
    original_timeout = getattr(transport, "channel_timeout", sentinel)
    changed = original_timeout is not sentinel
    if changed:
        transport.channel_timeout = timeout
    try:
        return ssh.open_sftp()
    finally:
        if changed:
            transport.channel_timeout = original_timeout


def _sftp_channel(sftp, timeout):
    """Apply the bounded operation timeout to the SFTP channel when available."""
    channel = getattr(sftp, "get_channel", lambda: None)()
    if channel is not None and hasattr(channel, "settimeout"):
        channel.settimeout(timeout)
    return channel


def _close_ssh_and_remove_key(ssh, ssh_key_path, close_code):
    """Release SSH/key material even when a final remote sweep raises."""
    if ssh is not None:
        try:
            ssh.close()
        except Exception:
            _capture_safe(close_code)
    if ssh_key_path and os.path.exists(ssh_key_path):
        try:
            os.remove(ssh_key_path)
        except OSError:
            pass


def _has_competing_live_restore(restore, backup):
    """Return True/False, or None when a competing-restore proof is unavailable."""
    manager = getattr(restore.__class__, "objects", None)
    backup_pk = getattr(backup, "pk", None)
    status_class = getattr(restore, "Status", None)
    if manager is None or backup_pk is None or status_class is None:
        return None
    active_statuses = {
        value
        for value in (
            getattr(status_class, "PENDING", None),
            getattr(status_class, "IN_PROGRESS", None),
        )
        if value is not None
    }
    if not active_statuses:
        return None
    try:
        query = manager.filter(backup_id=backup_pk).exclude(pk=restore.pk)
        return query.filter(status__in=active_statuses).exists()
    except Exception:
        # A failed proof is not permission to delete a legacy file.  Do not
        # retain ORM/provider exception text in the user-facing outcome.
        _capture_safe("SFTP_CLEANUP_COMPETING_RESTORE_UNKNOWN")
        return None


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


_UNSAFE_SQL_CLIENT_DIRECTIVE_RE = re.compile(
    rb"(?im)^\s*(?:\\(?:connect|include|ir|!|copy)\b|"
    rb"(?:source|system)\b|(?:drop|create|alter)\s+database\b|"
    rb"use\s+[^;]+;)"
)
_SQL_TRANSACTION_CONTROL_RE = re.compile(
    rb"(?i)^\s*(begin|commit|rollback|end)\s*;\s*$"
)
_MYSQL_DUMP_AUTOCOMMIT_OFF_RE = re.compile(
    rb"(?i)^\s*set\s+@old_autocommit\s*=\s*@@autocommit\s*,\s*"
    rb"@@autocommit\s*=\s*0\s*;\s*$"
)
_MYSQL_DUMP_AUTOCOMMIT_RESTORE_RE = re.compile(
    rb"(?i)^\s*set\s+autocommit\s*=\s*@old_autocommit\s*;\s*$"
)
_MYSQL_EXPLICIT_DEFINER_RE = re.compile(rb"(?i)\bDEFINER\s*=")
_MYSQL_BINLOG_RESTRICTED_OBJECT_RE = re.compile(
    rb"(?i)\bCREATE\b[^\r\n]*\b(?:FUNCTION|TRIGGER)\b"
)
_MYSQL_CLIENT_ERROR_AT_LINE_RE = re.compile(
    rb"(?im)\bERROR\s+(?P<code>\d{3,5})\s+\([^\r\n)]*\)\s+"
    rb"at\s+line\s+(?P<line>\d+)\s*:"
)


def _mysql_line_has_explicit_definer(line):
    """Detect dump object definers without treating row data as SQL metadata."""
    stripped = line.lstrip()
    if not stripped or stripped.startswith((b"--", b"#")):
        return False
    if re.match(rb"(?i)^(?:INSERT|REPLACE)\s+", stripped):
        return False
    return _MYSQL_EXPLICIT_DEFINER_RE.search(stripped) is not None


def _mysql_line_has_binlog_restricted_object(line):
    """Detect MySQL stored functions/triggers affected by binary-log policy."""
    stripped = line.lstrip()
    if not stripped or stripped.startswith((b"--", b"#")):
        return False
    if re.match(rb"(?i)^(?:INSERT|REPLACE)\s+", stripped):
        return False
    return _MYSQL_BINLOG_RESTRICTED_OBJECT_RE.search(stripped) is not None


def _expected_mysql_database_defaults_preamble(backup, auth, source):
    """Return the exact product-owned schema preamble for contract-v2 dumps."""
    logical_dump = dict((getattr(backup, "metadata", None) or {}).get("logical_dump") or {})
    raw_contract = logical_dump.get("contract_version", 1)
    try:
        contract_version = int(raw_contract)
    except (TypeError, ValueError):
        raise RestoreError("stored backup schema metadata is malformed.") from None
    if contract_version < 2:
        return None

    expected_engine = (
        "mariadb"
        if auth.type == CoreAuthDatabase.DatabaseType.MARIADB
        else "mysql"
    )
    if logical_dump.get("engine") != expected_engine:
        raise RestoreError("stored backup schema metadata is malformed.")
    database_defaults = logical_dump.get("database_defaults")
    if not isinstance(database_defaults, dict) or source not in database_defaults:
        raise RestoreError("stored backup schema metadata is incomplete.")
    try:
        return database_defaults_preamble(database_defaults[source])
    except (TypeError, ValueError):
        raise RestoreError("stored backup schema metadata is malformed.") from None


def _validate_extracted_archive(
    backup,
    auth,
    tree_root,
    *,
    mode="fork",
    include_requirements=False,
):
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
    requirements = {
        "mysql_explicit_definer": False,
        "mysql_explicit_definer_lines": {},
        "mysql_binlog_restricted_object": False,
    }
    targets = OrderedDict()
    tables_mode = bool(backup.tables) and not bool(backup.all_tables)
    for filename, path in sorted(sql_files):
        source = auth.database_name if tables_mode else os.path.splitext(filename)[0]
        source = _validate_database_name(source, "source database")
        digest = hashlib.sha256()
        byte_count = 0
        mysql_fork_scaffolding = (
            mode == "fork"
            and auth.type
            in (
                CoreAuthDatabase.DatabaseType.MYSQL,
                CoreAuthDatabase.DatabaseType.MARIADB,
            )
        )
        mysql_family_restore = auth.type in (
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseType.MARIADB,
        )
        expected_database_preamble = (
            _expected_mysql_database_defaults_preamble(backup, auth, source)
            if mysql_family_restore
            else None
        )
        database_preamble_seen = False
        autocommit_state = "idle"
        # Read the complete file.  ZIP CRC validation happens in
        # extract_backup_zip; this second pass validates the actual restore
        # input and gives the marker an immutable content identity.
        with open(path, "rb") as sql_file:
            for line_number, line in enumerate(sql_file, start=1):
                if (
                    mysql_fork_scaffolding
                    and _MYSQL_DUMP_AUTOCOMMIT_OFF_RE.fullmatch(line)
                ):
                    if autocommit_state != "idle":
                        raise RestoreError(
                            "stored SQL contains malformed vendor transaction scaffolding."
                        )
                    autocommit_state = "open"
                elif (
                    mysql_fork_scaffolding
                    and _MYSQL_DUMP_AUTOCOMMIT_RESTORE_RE.fullmatch(line)
                ):
                    if autocommit_state != "committed":
                        raise RestoreError(
                            "stored SQL contains malformed vendor transaction scaffolding."
                        )
                    autocommit_state = "idle"

                # Plain logical dumps do not need psql client meta-commands
                # that can switch databases, read arbitrary local files, or
                # execute a shell command. ``\\.`` is deliberately allowed:
                # it is the normal COPY-data terminator. MariaDB/MySQL dumps
                # produced with --single-transaction include one exact
                # AUTOCOMMIT-off / COMMIT / AUTOCOMMIT-restore wrapper. Permit
                # that vendor wrapper only for an isolated fork; PostgreSQL
                # and in-place restores continue to reject every transaction
                # boundary supplied by the archive.
                transaction = _SQL_TRANSACTION_CONTROL_RE.fullmatch(line)
                if transaction:
                    command = transaction.group(1).lower()
                    if (
                        mysql_fork_scaffolding
                        and command == b"commit"
                        and autocommit_state == "open"
                    ):
                        autocommit_state = "committed"
                    else:
                        raise RestoreError(
                            "stored SQL contains an unsafe client directive."
                        )
                exact_database_preamble = bool(
                    expected_database_preamble is not None
                    and byte_count == 0
                    and line == expected_database_preamble
                )
                if exact_database_preamble:
                    database_preamble_seen = True
                if (
                    _UNSAFE_SQL_CLIENT_DIRECTIVE_RE.search(line)
                    and not exact_database_preamble
                ):
                    raise RestoreError("stored SQL contains an unsafe client directive.")
                lowered = line.lower()
                if (
                    auth.type
                    in (
                        CoreAuthDatabase.DatabaseType.MYSQL,
                        CoreAuthDatabase.DatabaseType.MARIADB,
                    )
                    and _mysql_line_has_explicit_definer(line)
                ):
                    requirements["mysql_explicit_definer"] = True
                    witnesses = requirements["mysql_explicit_definer_lines"].setdefault(
                        filename, []
                    )
                    if witnesses is not None:
                        if len(witnesses) < MAX_MYSQL_DEFINER_LINE_WITNESSES:
                            witnesses.append(line_number)
                        else:
                            # Keep memory bounded. An unindexed excess witness
                            # remains protected by the existing generic target
                            # rejection and same-row reconciliation path.
                            requirements["mysql_explicit_definer_lines"][filename] = None
                if (
                    auth.type == CoreAuthDatabase.DatabaseType.MYSQL
                    and _mysql_line_has_binlog_restricted_object(line)
                ):
                    requirements["mysql_binlog_restricted_object"] = True
                if (
                    MYSQL_MARKER_TABLE.encode("ascii") in lowered
                    or POSTGRES_MARKER_SCHEMA.encode("ascii") in lowered
                ):
                    raise RestoreError(
                        "stored SQL conflicts with BackupSheep restore ownership metadata."
                    )
                byte_count += len(line)
                digest.update(line)
        if mysql_fork_scaffolding and autocommit_state != "idle":
            raise RestoreError(
                "stored SQL contains malformed vendor transaction scaffolding."
            )
        if expected_database_preamble is not None and not database_preamble_seen:
            raise RestoreError(
                "stored SQL is missing its authenticated database schema preamble."
            )
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
    if include_requirements:
        return targets, source_digests, requirements
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


def _mysql_system_definer_rejection(stderr, auth, filename, requirements):
    """Classify only error 1227 at a validated MySQL 8.4 DEFINER line.

    Client stderr remains ephemeral. The validator's bounded line witnesses
    prevent an unrelated access-denied error elsewhere in a dump from being
    presented as a SYSTEM_USER definer failure.
    """
    if (
        auth.type != CoreAuthDatabase.DatabaseType.MYSQL
        or getattr(auth, "version", None)
        != CoreAuthDatabase.DatabaseVersion.MYSQL_8_4
    ):
        return None
    raw_witnesses = (requirements or {}).get("mysql_explicit_definer_lines")
    if not isinstance(raw_witnesses, dict):
        return None
    witnesses = raw_witnesses.get(filename)
    if not isinstance(witnesses, list) or not witnesses:
        return None
    witness_lines = {
        int(value)
        for value in witnesses
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    }
    if not witness_lines:
        return None
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", "replace")
    elif not isinstance(stderr, bytes):
        try:
            stderr = bytes(stderr or b"")
        except (TypeError, ValueError):
            return None
    for match in _MYSQL_CLIENT_ERROR_AT_LINE_RE.finditer(stderr):
        if int(match.group("code")) == 1227 and int(match.group("line")) in witness_lines:
            return _database_restore_system_definer_error()
    return None


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
    rejection_classifier=None,
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
        if rejection_classifier is not None:
            classified = rejection_classifier(proc.stderr)
            if classified is not None:
                code = str(getattr(classified, "code", "") or "CLIENT_REJECTED")
                _capture_safe(code)
                _write_log(backup, f"{what}: {code}\n")
                raise classified
        error = _safe_failure(node, backup, what, "CLIENT_REJECTED")
        _capture_safe("CLIENT_REJECTED")
        raise error
    return _decode(proc.stdout)


def _ssh_run(
    node,
    backup,
    ssh,
    command,
    username,
    password,
    label,
    what,
    *,
    restore=None,
    rejection_classifier=None,
):
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
        stderr_body = stderr.read()
        exit_status = channel.recv_exit_status() if channel is not None else 0
    except Exception as error:
        _capture_safe("SSH_COMMAND_FAILED")
        raise _safe_failure(node, backup, what, "SSH_COMMAND_FAILED") from None
    if restore is not None:
        _ensure_restore_fence(restore)
    if exit_status != 0:
        if rejection_classifier is not None:
            classified = rejection_classifier(stderr_body)
            if classified is not None:
                code = str(getattr(classified, "code", "") or "SSH_COMMAND_REJECTED")
                _capture_safe(code)
                _write_log(backup, f"{what}: {code}\n")
                raise classified
        error = _safe_failure(node, backup, what, "SSH_COMMAND_REJECTED")
        _capture_safe("SSH_COMMAND_REJECTED")
        raise error
    return out_text


def _sftp_put(ssh, local_path, remote_name, *, restore=None, backup=None):
    """Upload a temporary SQL file with a 0600 mode."""
    if restore is not None:
        if not _has_restore_fence(restore):
            raise RestoreLeaseLost("Remote restore upload requires a live lease fence.")
        _ensure_restore_fence(restore)
        if _remote_temp_name_matches_restore(
            remote_name,
            restore,
            backup,
            kinds=REMOTE_RESTORE_SQL_KINDS,
            require_current_fence=True,
        ) is None:
            raise RestoreError("remote SQL temp name is outside the BackupSheep namespace.")
    sftp = _open_sftp_bounded(ssh, SFTP_OPEN_TIMEOUT)
    try:
        _sftp_channel(sftp, COMMAND_TIMEOUT)
        if restore is not None:
            _ensure_restore_fence(restore)
        sftp.put(local_path, remote_name)
        sftp.chmod(remote_name, 0o600)
        if restore is not None:
            _ensure_restore_fence(restore)
    finally:
        sftp.close()


def _sftp_write(ssh, remote_name, content, *, restore=None, backup=None):
    """Write a remote credential file with a bounded 0600 SFTP channel."""
    if restore is not None:
        if not _has_restore_fence(restore):
            raise RestoreLeaseLost("Remote restore credential requires a live lease fence.")
        _ensure_restore_fence(restore)
        if _remote_temp_name_matches_restore(
            remote_name,
            restore,
            backup,
            kinds=REMOTE_RESTORE_CREDENTIAL_EXTENSIONS,
            require_current_fence=True,
        ) is None:
            raise RestoreError(
                "remote credential temp name is outside the BackupSheep namespace."
            )
    sftp = _open_sftp_bounded(ssh, SFTP_OPEN_TIMEOUT)
    try:
        _sftp_channel(sftp, COMMAND_TIMEOUT)
        if restore is not None:
            _ensure_restore_fence(restore)
        with sftp.open(remote_name, "w") as output:
            output.write(content)
        sftp.chmod(remote_name, 0o600)
        if restore is not None:
            _ensure_restore_fence(restore)
    finally:
        sftp.close()


def _sftp_cleanup_error_code(error):
    """Classify an SFTP failure without retaining provider diagnostics."""
    error_number = getattr(error, "errno", None)
    message = str(error or "").lower()
    if error_number == errno.ENOENT or "no such file" in message or "not found" in message:
        return "SFTP_CLEANUP_NOT_FOUND"
    if error_number in {errno.EACCES, errno.EPERM} or "permission denied" in message:
        return "SFTP_CLEANUP_PERMISSION_DENIED"
    if "authentication" in message or "auth failed" in message or "not authenticated" in message:
        return "SFTP_CLEANUP_AUTH_FAILED"
    if isinstance(error, TimeoutError) or "timed out" in message or "timeout" in message:
        return "SFTP_CLEANUP_TIMEOUT"
    if any(token in message for token in ("connection", "transport", "channel", "socket")):
        return "SFTP_CLEANUP_TRANSPORT_FAILED"
    return "SFTP_CLEANUP_FAILED"


def _sftp_remove(ssh, remote_name, *, restore=None, backup=None):
    """Remove one owned remote temp file only while the caller's fence is live."""
    parsed = _parse_remote_restore_temp_name(remote_name)
    legacy = _legacy_remote_temp_name_matches_backup(remote_name, backup)
    if parsed is None and legacy is None:
        _raise_remote_cleanup_failure("SFTP_CLEANUP_INVALID_NAME", retryable=False)
    if restore is None or not _has_restore_fence(restore):
        raise RestoreLeaseLost("Remote restore cleanup requires a live lease fence.")
    if parsed is not None:
        if backup is None or _remote_temp_name_matches_restore(
            remote_name, restore, backup
        ) is None:
            _raise_remote_cleanup_failure(
                "SFTP_CLEANUP_OWNERSHIP_MISMATCH", retryable=False
            )
    elif legacy is not None:
        competing = _has_competing_live_restore(restore, backup)
        if competing is not False:
            _raise_remote_cleanup_failure(
                "SFTP_CLEANUP_COMPETING_RESTORE", retryable=False
            )

    try:
        _ensure_restore_fence(restore)
    except RestoreLeaseLost:
        raise
    except Exception:
        _raise_remote_cleanup_failure(
            "SFTP_CLEANUP_FENCE_CHECK_FAILED", retryable=False
        )

    sftp = None
    operation_error = None
    lease_lost = None
    classified_error = None
    remove_started = False
    try:
        sftp = _open_sftp_bounded(ssh, SFTP_OPEN_TIMEOUT)
        _sftp_channel(sftp, SFTP_CLEANUP_TIMEOUT)
        # This is deliberately after open_sftp/channel setup and immediately
        # before the delete.  A lease may expire while the SFTP channel opens.
        _ensure_restore_fence(restore)
        if legacy is not None:
            competing = _has_competing_live_restore(restore, backup)
            if competing is not False:
                _raise_remote_cleanup_failure(
                    "SFTP_CLEANUP_COMPETING_RESTORE", retryable=False
                )
        remove_started = True
        sftp.remove(remote_name)
    except RestoreLeaseLost as error:
        lease_lost = error
    except RemoteRestoreCleanupError as error:
        classified_error = error
    except Exception as error:
        operation_error = error
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception as error:
                if operation_error is None and lease_lost is None and classified_error is None:
                    operation_error = error

    if lease_lost is not None:
        raise lease_lost
    if classified_error is not None:
        raise classified_error
    if operation_error is not None:
        code = _sftp_cleanup_error_code(operation_error)
        if code == "SFTP_CLEANUP_NOT_FOUND" and remove_started:
            return True
        if code == "SFTP_CLEANUP_NOT_FOUND":
            _raise_remote_cleanup_failure(
                "SFTP_CLEANUP_TARGET_UNAVAILABLE", retryable=False
            )
        _raise_remote_cleanup_failure(code)
    return True


def _remote_restore_artifact_inventory(ssh, restore, backup):
    """List only strict new/legacy BackupSheep artifacts for this backup scope."""
    if not _has_restore_fence(restore):
        raise RestoreLeaseLost("Remote restore inventory requires a live lease fence.")
    try:
        _ensure_restore_fence(restore)
    except RestoreLeaseLost:
        raise
    except Exception:
        _raise_remote_cleanup_failure(
            "SFTP_CLEANUP_FENCE_CHECK_FAILED", retryable=False
        )

    sftp = None
    operation_error = None
    lease_lost = None
    names = None
    try:
        sftp = _open_sftp_bounded(ssh, SFTP_OPEN_TIMEOUT)
        _sftp_channel(sftp, SFTP_CLEANUP_TIMEOUT)
        _ensure_restore_fence(restore)
        names = sftp.listdir(".")
    except RestoreLeaseLost as error:
        lease_lost = error
    except Exception as error:
        operation_error = error
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception as error:
                if operation_error is None and lease_lost is None:
                    operation_error = error

    if lease_lost is not None:
        raise lease_lost
    if operation_error is not None:
        code = _sftp_cleanup_error_code(operation_error)
        if code == "SFTP_CLEANUP_NOT_FOUND":
            _raise_remote_cleanup_failure(
                "SFTP_CLEANUP_INVENTORY_UNAVAILABLE", retryable=False
            )
        _raise_remote_cleanup_failure(code)

    if not isinstance(names, (list, tuple)):
        _raise_remote_cleanup_failure(
            "SFTP_CLEANUP_MALFORMED_INVENTORY", retryable=False
        )

    inventory = []
    for remote_name in names:
        parsed = _remote_temp_name_matches_restore(remote_name, restore, backup)
        if parsed is not None:
            inventory.append((remote_name, parsed))
            continue
        legacy = _legacy_remote_temp_name_matches_backup(remote_name, backup)
        if legacy is not None:
            inventory.append((remote_name, legacy))
    return inventory


def _cleanup_stale_remote_restore_artifacts(
    ssh, restore, backup, *, include_current=False
):
    """Delete namespaced artifacts for this exact restore correlation.

    The current lease/fence owns every artifact with its fence token.  A takeover
    can therefore remove prior-fence names after independently proving the
    current fence is still live.  Names outside the strict namespace, names for
    another backup, and names for another restore correlation are ignored.  A
    successful worker may set ``include_current`` during final cleanup so a
    transient earlier remove failure does not leave credentials or SQL behind.
    """
    if ssh is None:
        return
    if not _has_restore_fence(restore):
        raise RestoreLeaseLost("Remote restore cleanup requires a live lease fence.")
    _ensure_restore_fence(restore)
    identity = _remote_restore_identity(restore, backup)
    inventory = _remote_restore_artifact_inventory(ssh, restore, backup)
    cleanup_failure = None
    for remote_name, parsed in inventory:
        if not include_current and not parsed.get("legacy") and parsed["fence"] == identity["fence"]:
            continue
        # Re-check the live fence immediately before each delete.  A worker
        # takeover must never turn into an unfenced broad cleanup if the new
        # lease expires while a long artifact list is being processed.
        try:
            removed = _sftp_remove(ssh, remote_name, restore=restore, backup=backup)
            if removed is False:
                _capture_safe("SFTP_CLEANUP_FAILED")
                cleanup_failure = cleanup_failure or RemoteRestoreCleanupError(
                    "SFTP_CLEANUP_FAILED", retryable=False
                )
        except RestoreLeaseLost:
            raise
        except RemoteRestoreCleanupError as error:
            # Continue to the final inventory pass.  A timeout/lost response
            # may have been accepted remotely; if the exact artifact is gone,
            # cleanup is proven complete despite the failed delete response.
            cleanup_failure = cleanup_failure or error

    # Deletion responses can be lost and object stores/remote filesystems can
    # be eventually consistent.  A successful restore is therefore not allowed
    # to proceed until this exact backup/correlation inventory is proven empty.
    remaining = _remote_restore_artifact_inventory(ssh, restore, backup)
    if not include_current:
        remaining = [
            (remote_name, parsed)
            for remote_name, parsed in remaining
            if parsed.get("legacy") or parsed.get("fence") != identity["fence"]
        ]
    if remaining:
        if cleanup_failure is not None:
            raise cleanup_failure
        if any(parsed.get("legacy") for _name, parsed in remaining):
            _raise_remote_cleanup_failure(
                "SFTP_CLEANUP_LEGACY_RESIDUE", retryable=False
            )
        _raise_remote_cleanup_failure("SFTP_CLEANUP_RESIDUE")
    if cleanup_failure is not None:
        # The final inventory is empty, so a lost delete response was safely
        # reconciled and does not need another restore attempt.
        return


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


def _postgres_marker_result(text, fields):
    """Parse a legacy combined marker lookup response.

    Current workers use separate pure-SQL relation and row queries because
    ``psql --command`` cannot safely mix SQL with ``\\gset``/``\\if`` meta
    commands. Keep this parser for rolling-worker compatibility and old test
    responses that contain a sentinel or boolean prefix.
    """
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    relation_exists = False
    if lines and lines[0] == POSTGRES_MARKER_RELATION_SENTINEL:
        relation_exists = True
        lines = lines[1:]
    elif lines and lines[0].lower() in {"t", "true", "f", "false"}:
        relation_exists = lines[0].lower() in {"t", "true"}
        lines = lines[1:]
    row = _parse_marker_row("\n".join(lines), fields)
    return row, relation_exists or row is not None


def _mysql_family_client(auth):
    """Select the vendor CLI from the authenticated database engine."""
    try:
        return CoreAuthDatabase.mysql_family_client_binary(auth.type)
    except (AttributeError, TypeError, ValueError):
        raise RestoreError("database restore received an unsupported MySQL-family engine.") from None


def _mysql_family_defaults_file_content(auth, username, password):
    """Build a vendor-correct TLS/credential file for restore clients."""
    values = (username, password, auth.host, auth.port, auth.use_ssl)
    if auth.type == CoreAuthDatabase.DatabaseType.MARIADB:
        return _mariadb_defaults_file_content(*values)
    if auth.type == CoreAuthDatabase.DatabaseType.MYSQL:
        return _mysql_defaults_file_content(*values)
    raise RestoreError(
        "database restore received an unsupported MySQL-family engine."
    )


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
    client = _mysql_family_client(auth)
    label = client.upper()
    if ssh is not None:
        command = (
            f'{client} --defaults-extra-file="$HOME/{defaults_arg}" '
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
            label,
            what,
            restore=restore,
        )
    return _run_direct(
        node,
        backup,
        [
            f"{auth.bin_path()}{client}",
            defaults_arg,
            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT}",
            "--batch",
            "--skip-column-names",
            "-e",
            sql,
        ],
        username,
        password,
        label,
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
        # SHOW GRANTS doubles the backslash used to escape literal ``_`` and
        # ``%`` characters in database-level wildcard scopes. Collapse that
        # display escaping once before applying the grant-pattern matcher.
        # Restore target names cannot contain a backslash, so this cannot turn
        # an unrelated literal database name into a matching target.
        database_pattern = database_pattern.replace("\\\\", "\\")
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


def _mysql_global_privilege_tokens(grants):
    """Return only global privilege tokens from an opaque SHOW GRANTS result."""
    privilege_tokens = set()
    for line in str(grants or "").splitlines():
        match = re.search(
            r"^\s*GRANT\s+(?P<privileges>.+?)\s+ON\s+(?P<scope>[^\s]+)\s+TO\s+",
            line,
            flags=re.IGNORECASE,
        )
        if not match or match.group("scope").replace("`", "") != "*.*":
            continue
        privilege_tokens.update(
            token.strip().upper().replace("`", "")
            for token in match.group("privileges").split(",")
        )
    return privilege_tokens


def _mysql_has_global_static_privilege(grants, privilege):
    privilege_tokens = _mysql_global_privilege_tokens(grants)
    return bool(
        str(privilege).upper() in privilege_tokens
        or privilege_tokens.intersection({"ALL", "ALL PRIVILEGES"})
    )


def _mysql_has_definer_privilege(grants, database_type, database_version=None):
    """Return whether global grants can preserve explicit object definers."""
    privilege_tokens = _mysql_global_privilege_tokens(grants)

    if database_type == CoreAuthDatabase.DatabaseType.MARIADB:
        return bool(
            privilege_tokens.intersection(
                {"ALL", "ALL PRIVILEGES", "SUPER", "SET USER"}
            )
        )

    if database_version == CoreAuthDatabase.DatabaseVersion.MYSQL_8_4:
        return {
            "SET_ANY_DEFINER",
            "ALLOW_NONEXISTENT_DEFINER",
        }.issubset(privilege_tokens)

    # MySQL 8.0 uses SET_USER_ID (or its legacy SUPER equivalent).  Accept the
    # 8.4 pair too so an upgraded server remains compatible with a connection
    # whose saved version has not yet been refreshed.
    return bool(
        privilege_tokens.intersection(
            {"ALL", "ALL PRIVILEGES", "SUPER", "SET_USER_ID"}
        )
        or {
            "SET_ANY_DEFINER",
            "ALLOW_NONEXISTENT_DEFINER",
        }.issubset(privilege_tokens)
    )


def _mysql_setting_boolean(value):
    value = str(value or "").strip().casefold()
    if value in {"1", "on", "true"}:
        return True
    if value in {"0", "off", "false"}:
        return False
    return None


def _mysql_binlog_super_required(result):
    """Parse the two non-secret global settings used by MySQL error 1419."""
    rows = [
        line.split("\t")
        for line in str(result or "").splitlines()
        if line.strip()
    ]
    if len(rows) != 1 or len(rows[0]) != 2:
        raise _database_restore_binlog_permission_error(verification_failed=True)
    log_bin, trust_creators = map(_mysql_setting_boolean, rows[0])
    if log_bin is None or trust_creators is None:
        raise _database_restore_binlog_permission_error(verification_failed=True)
    return log_bin and not trust_creators


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
    requires_definer_privilege=False,
    requires_binlog_super_check=False,
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
    if requires_definer_privilege and not _mysql_has_definer_privilege(
        grants, auth.type, getattr(auth, "version", None)
    ):
        raise _database_restore_definer_permission_error(auth.type)
    if (
        requires_binlog_super_check
        and auth.type == CoreAuthDatabase.DatabaseType.MYSQL
        and not _mysql_has_global_static_privilege(grants, "SUPER")
    ):
        settings_result = _mysql_query(
            node,
            backup,
            auth,
            defaults_arg,
            "SELECT @@GLOBAL.log_bin, @@GLOBAL.log_bin_trust_function_creators;",
            username,
            password,
            "check MySQL binary-log restore privileges",
            ssh=ssh,
            restore=restore,
        )
        if _mysql_binlog_super_required(settings_result):
            raise _database_restore_binlog_permission_error()
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
            # The database and its ownership marker are one external
            # mutation.  Re-check the durable fence immediately before it so
            # an expired worker cannot create a target after a takeover.
            _ensure_restore_fence(restore)
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
        try:
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
        except NodeBackupFailedError:
            # A marker query against a foreign database fails when the marker
            # table does not exist.  Distinguish that expected collision from
            # connection and query failures without mutating the target.
            marker_exists_sql = (
                "SELECT TABLE_NAME FROM information_schema.TABLES "
                f"WHERE TABLE_SCHEMA={_sql_literal(target)} "
                f"AND TABLE_NAME={_sql_literal(MYSQL_MARKER_TABLE)} LIMIT 1;"
            )
            marker_exists = _mysql_query(
                node,
                backup,
                auth,
                defaults_arg,
                marker_exists_sql,
                username,
                password,
                "check MySQL restore marker table",
                ssh=ssh,
                restore=restore,
            ).strip()
            if marker_exists:
                raise
            row = None
        else:
            row = _parse_marker_row(row_text, marker_fields)
        if row is None:
            if not in_place:
                raise RestoreError("fork target name collision: existing MySQL database is not BackupSheep-owned.")
            # Explicit in-place authorization permits installing the exact
            # marker into an existing target, but never adopts an old marker.
            _ensure_restore_fence(restore)
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
    source,
    source_digest,
    username,
    password,
    *,
    defaults_arg,
    ssh=None,
    restore=None,
):
    # This is destructive even though the name is deterministic.  The caller
    # has already verified the exact marker.  Re-read it here as well: a
    # target can be changed between adoption and this destructive operation.
    # The final fence check below closes the worker-takeover window immediately
    # before DROP.
    if restore is None:
        raise RestoreLeaseLost("Dropping a MySQL fork requires a live lease fence.")
    if hasattr(restore, "assert_live_execution_fence") and not _has_restore_fence(restore):
        raise RestoreLeaseLost("Dropping a MySQL fork requires a live lease fence.")

    expected = _marker_values(
        restore, backup, source, target, source_digest, "importing"
    )
    marker_fields = [
        "marker_version",
        "correlation_id",
        "backup_uuid",
        "source_database",
        "target_database",
        "source_digest",
        "state",
    ]
    marker_text = _mysql_query(
        node,
        backup,
        auth,
        defaults_arg,
        _mysql_marker_query(target),
        username,
        password,
        "recheck MySQL fork ownership before drop",
        ssh=ssh,
        restore=restore,
    )
    marker = _parse_marker_row(marker_text, marker_fields)
    if not marker or not _marker_matches(marker, expected) or marker.get("state") != "importing":
        raise RestoreError(
            "MySQL target marker changed before fork recreation; manual review is required."
        )

    # This check must remain immediately before the DROP request.  The SQL
    # client also checks its bound fence, giving the command boundary two
    # independent lease checks without ever permitting an unfenced drop.
    _ensure_restore_fence(restore)
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


def _validate_mysql_checkpoint(checkpoint, *, file_specs, source, source_digest):
    """Validate one durable MySQL checkpoint without making provider changes."""
    if not isinstance(checkpoint, dict):
        raise RestoreError(
            "restore target checkpoint is malformed; manual review is required."
        )
    if (
        checkpoint.get("source") != source
        or checkpoint.get("source_digest") != source_digest
    ):
        raise RestoreError(
            "restore target checkpoint changed; manual review is required."
        )
    if not checkpoint.get("status"):
        raise RestoreError(
            "restore target checkpoint is missing its state; manual review is required."
        )
    status = str(checkpoint["status"])
    if status not in {"pending", "importing", "complete"}:
        raise RestoreError(
            "restore target checkpoint has an unsupported state; manual review is required."
        )
    raw_files = checkpoint.get("files")
    if raw_files is None:
        files = {}
    elif not isinstance(raw_files, dict):
        raise RestoreError(
            "restore file checkpoints are malformed; manual review is required."
        )
    else:
        files = dict(raw_files)
    for filename, file_state in files.items():
        expected_file = file_specs.get(filename)
        identity_matches = False
        if expected_file is not None and isinstance(file_state, dict):
            try:
                identity_matches = (
                    file_state.get("sha256") == expected_file.get("sha256")
                    and int(file_state.get("bytes"))
                    == int(expected_file.get("bytes"))
                )
            except (TypeError, ValueError):
                identity_matches = False
        if not identity_matches:
            raise RestoreError(
                "restore file checkpoint identity changed; manual review is required."
            )
        if not file_state.get("status"):
            raise RestoreError(
                "restore file checkpoint is missing its state; manual review is required."
            )
        if str(file_state["status"]) not in {"pending", "in_progress", "complete"}:
            raise RestoreError(
                "restore file checkpoint has an unsupported state; manual review is required."
            )
    return status, files


def _mysql_target_checkpoint(restore, target):
    """Read one MySQL checkpoint, failing closed on malformed metadata."""
    checkpoints = _metadata(restore).get("target_checkpoints")
    if checkpoints is None:
        return {}
    if not isinstance(checkpoints, dict):
        raise RestoreError(
            "restore target checkpoints are malformed; manual review is required."
        )
    checkpoint = checkpoints.get(target)
    if checkpoint is None:
        return {}
    if not isinstance(checkpoint, dict):
        raise RestoreError(
            "restore target checkpoint is malformed; manual review is required."
        )
    return dict(checkpoint)


def _reset_mysql_fork_checkpoint(
    restore,
    *,
    mapping,
    source_digests,
    source,
    target,
    source_digest,
    file_specs,
):
    """Reset an owned fork's replay state after discarding its partial data.

    ``_checkpoint`` is intentionally monotonic for ordinary progress, so it
    cannot be used to move an ``in_progress`` file back to ``pending``.  This
    reset is a narrowly scoped exception: the caller has already verified the
    exact BackupSheep marker and is about to drop/recreate the fork (or has
    observed that the fork was newly created empty).  Validate every durable
    identity before replacing the file states so a stale or foreign checkpoint
    can never be converted into permission to drop a database.
    """
    values = _metadata(restore)
    old_mapping = values.get("source_to_target")
    if old_mapping is not None and old_mapping != mapping:
        raise RestoreError(
            "restore source-to-target mapping changed; manual review is required."
        )
    old_digests = values.get("source_digests")
    if old_digests is not None and old_digests != source_digests:
        raise RestoreError(
            "restore source archive content changed; manual review is required."
        )

    raw_checkpoints = values.get("target_checkpoints")
    if raw_checkpoints is None:
        checkpoints = {}
    elif not isinstance(raw_checkpoints, dict):
        raise RestoreError(
            "restore target checkpoints are malformed; manual review is required."
        )
    else:
        checkpoints = dict(raw_checkpoints)
    raw_existing = checkpoints.get(target)
    if raw_existing is None:
        existing = {}
    elif not isinstance(raw_existing, dict):
        raise RestoreError(
            "restore target checkpoint is malformed; manual review is required."
        )
    else:
        existing = dict(raw_existing)
    if existing:
        existing_status, _old_files = _validate_mysql_checkpoint(
            existing,
            file_specs=file_specs,
            source=source,
            source_digest=source_digest,
        )
        if existing_status == "complete":
            raise RestoreError(
                "completed restore target cannot be reopened automatically."
            )

    checkpoints[target] = {
        "source": source,
        "source_digest": source_digest,
        "status": "importing",
        "files": {
            filename: dict(specification, status="pending")
            for filename, specification in file_specs.items()
        },
    }
    values["source_to_target"] = dict(mapping)
    values["mapping_locked"] = True
    values["source_digests"] = dict(source_digests)
    values["target_checkpoints"] = checkpoints
    restore.execution_metadata = values
    restore.execution_phase = "database_importing"
    restore.progress_completed = sum(
        1
        for checkpoint in checkpoints.values()
        if checkpoint.get("status") == "complete"
    )
    restore.progress_unit = "databases"
    _save_restore(
        restore,
        [
            "execution_phase",
            "execution_metadata",
            "progress_completed",
            "progress_unit",
        ],
    )


def _restore_mysql_family(
    node,
    backup,
    restore,
    auth,
    targets,
    mapping,
    source_digests,
    username,
    password,
    *,
    archive_requirements=None,
):
    """Restore MySQL/MariaDB sources into owned forks or explicit targets."""
    client = _mysql_family_client(auth)
    label = client.upper()
    local_defaults_path = None
    ssh_key_path = None
    ssh = None
    remote_defaults_name = None
    worker_suffix = _restore_work_suffix(restore, backup)
    credential_suffix = f"_{worker_suffix}" if _has_restore_fence(restore) else ""
    if auth.use_public_key or auth.use_private_key:
        ssh, ssh_key_path = auth.get_ssh_client()
        remote_defaults_name = _remote_restore_temp_name(
            restore, backup, "mysql_credentials"
        )
        try:
            _cleanup_stale_remote_restore_artifacts(ssh, restore, backup)
            _sftp_write(
                ssh,
                remote_defaults_name,
                _mysql_family_defaults_file_content(auth, username, password),
                restore=restore,
                backup=backup,
            )
        except Exception:
            try:
                _cleanup_stale_remote_restore_artifacts(
                    ssh, restore, backup, include_current=True
                )
            finally:
                _close_ssh_and_remove_key(
                    ssh, ssh_key_path, "MYSQL_SSH_CLOSE_FAILED"
                )
            raise
        defaults_arg = remote_defaults_name
    else:
        local_defaults_path = f"_storage/my_restore_{backup.uuid_str}{credential_suffix}.cnf"
        _write_local_defaults_file(
            local_defaults_path,
            _mysql_family_defaults_file_content(auth, username, password),
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
            expected_marker = _marker_values(
                restore, backup, source, target, digest, "importing"
            )
            if not isinstance(marker, dict) or (
                not _marker_matches(marker, expected_marker)
                and not marker.get("_new")
                and marker.get("state") != "complete"
            ):
                # The fork branch is destructive only when the exact marker
                # proves ownership.  This guard is intentionally independent
                # of _ensure_mysql_target so a stale/partial observation can
                # never be treated as permission to replay or drop.  New
                # targets and completion witnesses have already been checked
                # by _ensure_mysql_target; the exact re-read in
                # _drop_mysql_owned_target remains mandatory before DROP.
                raise RestoreError(
                    "the MySQL import outcome is ambiguous; exact ownership "
                    "marker evidence is required for automatic recovery."
                )
            checkpoint = _mysql_target_checkpoint(restore, target)
            if checkpoint:
                _validate_mysql_checkpoint(
                    checkpoint,
                    file_specs=file_specs,
                    source=source,
                    source_digest=digest,
                )
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
                # An exact importing marker proves ownership of this fork.
                # MySQL/MariaDB DDL is not transactional, so every ambiguous
                # partial fork import converges by replaying the verified
                # archive into a fresh exact target.  This covers both sides
                # of the durable checkpoint boundary: the worker may have
                # persisted ``in_progress`` before the client ran, or the
                # client may have committed before the checkpoint write.
                #
                # A target created above in this execution is already empty;
                # do not drop it again.  A target adopted from a prior
                # execution is dropped only after _ensure_mysql_target has
                # proved the complete marker and _drop_mysql_owned_target has
                # rechecked the live lease immediately before DROP.
                if marker.get("state") == "importing":
                    # Validate and persist the reset before DROP.  If the
                    # worker dies between these two durable/external steps,
                    # the next fenced worker sees an importing exact marker
                    # and converges through the same safe fork restart.
                    _reset_mysql_fork_checkpoint(
                        restore,
                        mapping=mapping,
                        source_digests=source_digests,
                        source=source,
                        target=target,
                        source_digest=digest,
                        file_specs=file_specs,
                    )
                    if not marker.get("_new"):
                        _drop_mysql_owned_target(
                            node,
                            backup,
                            auth,
                            target,
                            source,
                            digest,
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
                    checkpoint = _mysql_target_checkpoint(restore, target)

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

                def classify_import_rejection(stderr, _filename=filename):
                    return _mysql_system_definer_rejection(
                        stderr,
                        auth,
                        _filename,
                        archive_requirements,
                    )

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
                    _ensure_restore_fence(restore)
                    _run_direct(
                        node,
                        backup,
                        [
                            f"{auth.bin_path()}{client}",
                            defaults_arg,
                            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT}",
                            target,
                        ],
                        username,
                        password,
                        label,
                        f"import source database {source}",
                        stdin_path=sql_path,
                        restore=restore,
                        rejection_classifier=classify_import_rejection,
                    )
                else:
                    remote_sql = _remote_restore_temp_name(
                        restore,
                        backup,
                        "mysql_sql",
                        source=source,
                        filename=filename,
                    )
                    try:
                        _sftp_put(
                            ssh, sql_path, remote_sql, restore=restore, backup=backup
                        )
                        _ensure_restore_fence(restore)
                        _ssh_run(
                            node,
                            backup,
                            ssh,
                            f'{client} --defaults-extra-file="$HOME/{remote_defaults_name}" '
                            f"--connect-timeout={CLIENT_CONNECT_TIMEOUT} "
                            f"{shlex.quote(target)} < \"$HOME/{remote_sql}\"",
                            username,
                            password,
                            label,
                            f"import source database {source}",
                            restore=restore,
                            rejection_classifier=classify_import_rejection,
                        )
                    finally:
                        if remote_sql:
                            _sftp_remove(
                                ssh, remote_sql, restore=restore, backup=backup
                            )
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
            _ensure_restore_fence(restore)
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
        if ssh is not None:
            try:
                if remote_defaults_name:
                    _cleanup_stale_remote_restore_artifacts(
                        ssh, restore, backup, include_current=True
                    )
            finally:
                _close_ssh_and_remove_key(
                    ssh, ssh_key_path, "MYSQL_SSH_CLOSE_FAILED"
                )
        else:
            _close_ssh_and_remove_key(None, ssh_key_path, "MYSQL_SSH_CLOSE_FAILED")


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
        # Marker reconciliation is parsed as a fixed tab-delimited record.
        # psql's unaligned default separator is ``|``; pinning it here keeps
        # SSH and direct execution on the same unambiguous wire format.
        parts.extend(
            [
                "--tuples-only",
                "--no-align",
                "--quiet",
                f"--field-separator={shlex.quote(chr(9))}",
            ]
        )
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
            "--tuples-only", "--no-align", "--quiet",
            f"--field-separator={chr(9)}", "--command", sql,
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


def _read_postgres_marker(
    node,
    backup,
    restore,
    auth,
    pg_env,
    username,
    target,
    fields,
    what,
    *,
    ssh=None,
    remote_pgpass=None,
):
    """Read a marker using two bounded, read-only SQL statements.

    ``psql --command`` accepts SQL, not conditional psql meta-commands. If the
    relation disappears between these queries, the row query fails closed.
    """
    exists_text = _postgres_query(
        node,
        backup,
        auth,
        pg_env,
        username,
        target,
        _postgres_marker_exists_query(),
        f"{what} relation",
        ssh=ssh,
        remote_pgpass=remote_pgpass,
        restore=restore,
    )
    if not _postgres_relation_exists(exists_text):
        return None, False
    row_text = _postgres_query(
        node,
        backup,
        auth,
        pg_env,
        username,
        target,
        _postgres_marker_query(),
        what,
        ssh=ssh,
        remote_pgpass=remote_pgpass,
        restore=restore,
    )
    return _parse_marker_row(row_text, fields), True


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
    archive_requirements=None,
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
    requires_definer_privilege = bool(
        (archive_requirements or {}).get("mysql_explicit_definer")
    )
    requires_binlog_super_check = bool(
        (archive_requirements or {}).get("mysql_binlog_restricted_object")
    )
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
                _cleanup_stale_remote_restore_artifacts(ssh, restore, backup)
                remote_name = _remote_restore_temp_name(
                    restore, backup, "mysql_preflight_credentials"
                )
                _sftp_write(
                    ssh,
                    remote_name,
                    _mysql_family_defaults_file_content(
                        auth, username, password
                    ),
                    restore=restore,
                    backup=backup,
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
                    requires_definer_privilege=requires_definer_privilege,
                    requires_binlog_super_check=requires_binlog_super_check,
                    ssh=ssh,
                )
            local_path = f"_storage/db_restore_preflight_{worker_suffix}.cnf"
            _write_local_defaults_file(
                local_path,
                _mysql_family_defaults_file_content(auth, username, password),
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
                requires_definer_privilege=requires_definer_privilege,
                requires_binlog_super_check=requires_binlog_super_check,
            )

        if auth.type == CoreAuthDatabase.DatabaseType.POSTGRESQL:
            pg_env = os.environ.copy()
            pg_env.pop("PGPASSWORD", None)
            pg_env["PGCONNECT_TIMEOUT"] = str(CLIENT_CONNECT_TIMEOUT)
            if auth.use_public_key or auth.use_private_key:
                ssh, ssh_key_path = auth.get_ssh_client()
                _cleanup_stale_remote_restore_artifacts(ssh, restore, backup)
                remote_name = _remote_restore_temp_name(
                    restore, backup, "postgres_preflight_credentials"
                )
                _sftp_write(
                    ssh,
                    remote_name,
                    _pgpass_content(auth, username, password),
                    restore=restore,
                    backup=backup,
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
        if ssh is not None:
            try:
                if remote_name:
                    _cleanup_stale_remote_restore_artifacts(
                        ssh, restore, backup, include_current=True
                    )
            finally:
                _close_ssh_and_remove_key(
                    ssh, ssh_key_path, "DATABASE_PREFLIGHT_SSH_CLOSE_FAILED"
                )
        else:
            _close_ssh_and_remove_key(
                None, ssh_key_path, "DATABASE_PREFLIGHT_SSH_CLOSE_FAILED"
            )
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


def _postgres_marker_exists_query():
    table = f"{_postgres_identifier(POSTGRES_MARKER_SCHEMA)}.{_postgres_identifier(POSTGRES_MARKER_TABLE)}"
    table_literal = _sql_literal(table)
    return f"SELECT to_regclass({table_literal}) IS NOT NULL;"


def _postgres_marker_query():
    table = f"{_postgres_identifier(POSTGRES_MARKER_SCHEMA)}.{_postgres_identifier(POSTGRES_MARKER_TABLE)}"
    return (
        "SELECT marker_version, correlation_id, backup_uuid, source_database, "
        f"target_database, source_digest, state FROM {table} ORDER BY marker_key;"
    )


def _postgres_relation_exists(text):
    values = [
        line.strip().lower()
        for line in str(text or "").splitlines()
        if line.strip()
    ]
    if len(values) != 1 or values[0] not in {
        "t",
        "true",
        "1",
        "f",
        "false",
        "0",
    }:
        raise RestoreError("PostgreSQL marker relation lookup was malformed.")
    return values[0] in {"t", "true", "1"}


def _postgres_dump_options(backup):
    """Return the exact persisted pg_dump option tokens, or ``None``."""
    raw_options = getattr(backup, "option_postgres", None)
    if not isinstance(raw_options, str) or not raw_options.strip():
        return None
    try:
        return set(shlex.split(raw_options))
    except ValueError:
        return None


def _postgres_in_place_dump_is_safe(backup):
    """Return whether persisted pg_dump options safely support in-place replay.

    An in-place restore can encounter objects that are already present or
    absent after a partial/failed attempt.  ``--clean`` supplies the drop
    semantics and ``--if-exists`` makes those drops idempotent.  Only the
    options persisted on the backup are trusted; the current node settings
    may have changed since that backup was created.
    """
    options = _postgres_dump_options(backup)
    if options is None:
        return False
    has_clean = bool({"-c", "--clean"}.intersection(options))
    return has_clean and "--if-exists" in options


def _postgres_historical_clean_compatibility_required(backup):
    """Return whether an exact persisted legacy cleanup contract needs repair."""
    options = _postgres_dump_options(backup)
    if options is None:
        return False
    return bool({"-c", "--clean"}.intersection(options)) and "--if-exists" not in options


def _ensure_postgresql_in_place_dump_is_safe(backup):
    """Reject unsafe in-place dumps before any target-side mutation."""
    if _postgres_in_place_dump_is_safe(backup):
        return
    raise RestoreError(
        "PostgreSQL in-place restore is blocked because the persisted backup "
        "options do not prove idempotent cleanup. The backup must include both "
        "--clean and --if-exists; no target was changed."
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
            row, marker_relation_exists = _read_postgres_marker(
                node,
                backup,
                restore,
                auth,
                pg_env,
                username,
                target,
                fields,
                "reconcile PostgreSQL marker",
                ssh=ssh,
                remote_pgpass=remote_pgpass,
            )
            if not row or not _marker_matches(row, expected):
                raise RestoreError("PostgreSQL target ownership is ambiguous; no changes were retried.") from None
    else:
        row, marker_relation_exists = _read_postgres_marker(
            node,
            backup,
            restore,
            auth,
            pg_env,
            username,
            target,
            fields,
            "check PostgreSQL restore marker",
            ssh=ssh,
            remote_pgpass=remote_pgpass,
        )
    if row is None:
        if marker_relation_exists:
            raise RestoreError(
                "PostgreSQL target has a BackupSheep marker relation without an "
                "exact restore marker; no changes were made."
            )
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


def _validate_postgres_cleanup_statement(statement):
    """Reject anything other than one complete pg_dump cleanup statement."""
    if (
        not statement.endswith(b";")
        or statement.count(b";") != 1
        or b"\x00" in statement
    ):
        raise RestoreError(
            "Historical PostgreSQL cleanup compatibility rejected an unsupported "
            "dump statement before the restore target was changed."
        )


def _rewrite_postgres_cleanup_line(line):
    """Add IF EXISTS to one recognized pg_dump cleanup line.

    Return ``(payload, recognized)``. A drop-like but unrecognized line fails
    closed instead of being passed to a target that may already exist.
    """
    ending = b""
    statement = line
    if statement.endswith(b"\r\n"):
        statement, ending = statement[:-2], b"\r\n"
    elif statement.endswith(b"\n"):
        statement, ending = statement[:-1], b"\n"

    stripped = statement.lstrip()
    drop_like = stripped.startswith(b"DROP ") or (
        stripped.startswith(b"ALTER ") and b" DROP " in stripped
    )
    if drop_like and stripped != statement:
        raise RestoreError(
            "Historical PostgreSQL cleanup compatibility rejected an unsupported "
            "dump statement before the restore target was changed."
        )

    for object_type in POSTGRES_HISTORICAL_CLEANUP_OBJECTS:
        safe_prefix = b"DROP " + object_type + b" IF EXISTS "
        unsafe_prefix = b"DROP " + object_type + b" "
        if statement.startswith(safe_prefix):
            _validate_postgres_cleanup_statement(statement)
            return line, True
        if statement.startswith(unsafe_prefix):
            _validate_postgres_cleanup_statement(statement)
            return (
                unsafe_prefix
                + b"IF EXISTS "
                + statement[len(unsafe_prefix) :]
                + ending,
                True,
            )

    constraint = b" DROP CONSTRAINT "
    safe_constraint = b" DROP CONSTRAINT IF EXISTS "
    table_prefixes = (
        (b"ALTER TABLE IF EXISTS ONLY ", b"ALTER TABLE IF EXISTS ONLY "),
        (b"ALTER TABLE IF EXISTS ", b"ALTER TABLE IF EXISTS "),
        (b"ALTER TABLE ONLY ", b"ALTER TABLE IF EXISTS ONLY "),
        (b"ALTER TABLE ", b"ALTER TABLE IF EXISTS "),
    )
    for input_prefix, output_prefix in table_prefixes:
        if not statement.startswith(input_prefix):
            continue
        if safe_constraint in statement:
            _validate_postgres_cleanup_statement(statement)
            return output_prefix + statement[len(input_prefix) :] + ending, True
        if constraint in statement:
            _validate_postgres_cleanup_statement(statement)
            if statement.count(constraint) != 1:
                break
            normalized = output_prefix + statement[len(input_prefix) :]
            return normalized.replace(constraint, safe_constraint, 1) + ending, True
        break

    if drop_like:
        raise RestoreError(
            "Historical PostgreSQL cleanup compatibility rejected an unsupported "
            "dump statement before the restore target was changed."
        )
    return line, False


def _copy_historical_postgres_dump(source_path, output):
    """Copy a pg_dump file while bounding legacy cleanup repair.

    Only the signed pg_dump preamble is examined line-by-line. Once object
    creation begins, the remainder is copied in bounded binary chunks so large
    COPY rows and non-UTF-8 database encodings never enter Python text parsing.
    """
    saw_header = False
    saw_dumped_by = False
    cleanup_started = False
    tail = b""

    def write(payload):
        nonlocal tail
        output.write(payload)
        tail = (tail + payload)[-POSTGRES_COMPAT_TAIL_BYTES:]

    with open(source_path, "rb") as source:
        while True:
            line = source.readline(POSTGRES_COMPAT_PREAMBLE_MAX_LINE_BYTES + 1)
            if not line:
                break
            if (
                len(line) > POSTGRES_COMPAT_PREAMBLE_MAX_LINE_BYTES
                and not line.endswith(b"\n")
            ):
                raise RestoreError(
                    "Historical PostgreSQL cleanup compatibility rejected a malformed "
                    "dump preamble before the restore target was changed."
                )

            stripped = line.strip()
            if stripped == b"-- PostgreSQL database dump":
                saw_header = True
            elif stripped.startswith(b"-- Dumped by pg_dump version "):
                saw_dumped_by = True

            rewritten, recognized = _rewrite_postgres_cleanup_line(line)
            if recognized:
                cleanup_started = True
                write(rewritten)
                continue

            is_comment_or_blank = not stripped or stripped.startswith(b"--")
            is_psql_guard = stripped.startswith((b"\\restrict ", b"\\unrestrict "))
            is_setup = stripped.startswith(b"SET ") or stripped.startswith(
                b"SELECT pg_catalog.set_config("
            )
            is_large_object_cleanup = stripped.startswith(
                b"SELECT pg_catalog.lo_unlink("
            )
            if (
                is_comment_or_blank
                or is_psql_guard
                or (not cleanup_started and is_setup)
                or (cleanup_started and is_large_object_cleanup)
            ):
                write(line)
                continue

            # The first non-cleanup SQL statement starts the ordinary dump
            # body. It remains byte-for-byte unchanged and strict psql error
            # handling applies to it and every following statement.
            write(line)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                write(chunk)
            break

    if (
        not saw_header
        or not saw_dumped_by
        or b"-- PostgreSQL database dump complete" not in tail
    ):
        raise RestoreError(
            "Historical PostgreSQL cleanup compatibility rejected a malformed "
            "pg_dump artifact before the restore target was changed."
        )


def _build_combined_postgres_sql(
    sql_paths, marker, *, historical_clean_compatibility=False
):
    descriptor, path = tempfile.mkstemp(prefix="bs_restore_", suffix=".sql", dir="_storage")
    os.chmod(path, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            for sql_path in sql_paths:
                if historical_clean_compatibility:
                    _copy_historical_postgres_dump(sql_path, output)
                else:
                    with open(sql_path, "rb") as source:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
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
    combined_sql_paths = set()
    try:
        mode, _params = _restore_mode(restore)
        in_place = mode == "in_place"
        if in_place:
            # This must run before creating credentials, a target database, or
            # the ownership marker.  The persisted backup options are the only
            # reliable record of how this dump was produced.
            _ensure_postgresql_in_place_dump_is_safe(backup)
        if auth.use_public_key or auth.use_private_key:
            ssh, ssh_key_path = auth.get_ssh_client()
            _cleanup_stale_remote_restore_artifacts(ssh, restore, backup)
            remote_pgpass = _remote_restore_temp_name(
                restore, backup, "postgres_credentials"
            )
            _sftp_write(
                ssh,
                remote_pgpass,
                _pgpass_content(auth, username, password),
                restore=restore,
                backup=backup,
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
            if _has_restore_fence(restore):
                _verify_source_files(source_digests, source, sql_paths)
            marker_for_update = _marker_values(
                restore, backup, source, target, digest, "importing"
            )
            historical_clean_compatibility = (
                not in_place
                and _postgres_historical_clean_compatibility_required(backup)
            )
            local_sql = None
            if historical_clean_compatibility:
                # Build and validate the compatibility artifact before
                # _ensure_postgres_target can create a database or marker.
                local_sql = _build_combined_postgres_sql(
                    sql_paths,
                    marker_for_update,
                    historical_clean_compatibility=True,
                )
                combined_sql_paths.add(local_sql)
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
                    checkpoints={target: {
                        "source": source,
                        "source_digest": digest,
                        "status": "complete",
                        "files": {
                            filename: dict(specification, status="complete")
                            for filename, specification in file_specs.items()
                        },
                    }},
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
                        "files": {
                            filename: dict(specification, status="complete")
                            for filename, specification in file_specs.items()
                        },
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
            replaying_atomic_import = False
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
                file_statuses = {
                    str(state.get("status") or "pending")
                    for state in existing_files.values()
                }
                if not file_statuses.issubset({"pending", "in_progress", "complete"}):
                    raise RestoreError(
                        "the PostgreSQL file checkpoint has an unsupported state."
                    )
                if "complete" in file_statuses:
                    raise RestoreError(
                        "the PostgreSQL import outcome is ambiguous; manual review is required."
                    )
                # PostgreSQL runs every dump plus the ownership-marker update in
                # one ON_ERROR_STOP transaction. An exact marker still in the
                # importing state proves the previous transaction did not
                # commit; a committed transaction would have atomically changed
                # that marker to complete and been adopted above. Replaying the
                # same verified archive is therefore safe after a worker crash.
                replaying_atomic_import = "in_progress" in file_statuses
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
                phase=(
                    "database_replaying"
                    if replaying_atomic_import
                    else "database_importing"
                ),
                mapping=mapping,
                source_digests=source_digests,
                checkpoints={target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "importing",
                    **(
                        {
                            "transaction_replay_count": int(
                                checkpoint.get("transaction_replay_count") or 0
                            )
                            + 1
                        }
                        if replaying_atomic_import
                        else {}
                    ),
                    "files": {
                        filename: dict(state, status="in_progress")
                        for filename, state in file_states.items()
                        if state.get("status") != "complete"
                    },
                }},
                progress_total=len(mapping),
            )
            _ensure_restore_fence(restore)
            if local_sql is None:
                local_sql = _build_combined_postgres_sql(
                    sql_paths, marker_for_update
                )
                combined_sql_paths.add(local_sql)
            remote_sql = None
            try:
                if ssh is not None:
                    remote_sql = _remote_restore_temp_name(
                        restore,
                        backup,
                        "postgres_sql",
                        source=source,
                        filename="__combined__",
                    )
                    try:
                        _sftp_put(
                            ssh, local_sql, remote_sql, restore=restore, backup=backup
                        )
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
                    finally:
                        if remote_sql:
                            _sftp_remove(
                                ssh, remote_sql, restore=restore, backup=backup
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
                try:
                    os.remove(local_sql)
                except OSError:
                    pass
                combined_sql_paths.discard(local_sql)
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
                    "files": {
                        filename: dict(specification, status="complete")
                        for filename, specification in file_specs.items()
                    },
                }},
                progress_total=len(mapping),
            )
    finally:
        for combined_sql_path in combined_sql_paths:
            try:
                os.remove(combined_sql_path)
            except OSError:
                pass
        if local_pgpass and os.path.exists(local_pgpass):
            try:
                os.remove(local_pgpass)
            except OSError:
                pass
        if ssh is not None:
            try:
                if remote_pgpass:
                    _cleanup_stale_remote_restore_artifacts(
                        ssh, restore, backup, include_current=True
                    )
            finally:
                _close_ssh_and_remove_key(
                    ssh, ssh_key_path, "POSTGRES_SSH_CLOSE_FAILED"
                )
        else:
            _close_ssh_and_remove_key(None, ssh_key_path, "POSTGRES_SSH_CLOSE_FAILED")


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
        validated_archive = _validate_extracted_archive(
            backup,
            auth,
            local_dir,
            mode=mode,
            include_requirements=True,
        )
        targets, source_digests = validated_archive[:2]
        archive_requirements = (
            validated_archive[2] if len(validated_archive) > 2 else {}
        )
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
            archive_requirements=archive_requirements,
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
                username, password, archive_requirements=archive_requirements,
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
        if _has_restore_fence(restore):
            cleanup_prefixes = stale_local_restore_work_prefixes(restore, backup)
            cleanup_prefixes.append(work_prefix)
            for cleanup_prefix in dict.fromkeys(cleanup_prefixes):
                delete_from_disk.apply_async(args=[cleanup_prefix, "restore"])
        else:
            delete_from_disk.apply_async(args=[work_prefix, "both"])
