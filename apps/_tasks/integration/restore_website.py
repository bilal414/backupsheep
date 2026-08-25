"""Crash-safe website/files restore engine.

The worker first validates and hashes the complete local restore tree.  When a
restore is running under the normal durable restore lease, non-root targets are
uploaded to a deterministic, restore-owned sibling and published with remote
rename operations.  A publish whose outcome cannot be observed is never
replayed automatically.  The root target (``all_paths``) cannot be atomically
renamed on FTP/SFTP, so it uses convergent mirror semantics unless ``delete``
was explicitly requested; delete-mode ambiguity is manual-review only.

The direct function path remains compatible with the historical unit-test and
operator call surface.  Production Celery deliveries bind the restore fence in
``restore.py`` and take the staged path below.  Temporary local files and
remote staging names are worker-scoped so a stale worker cannot clean up a
replacement worker's artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import sqlite3
import stat
import subprocess
import tempfile

from django.conf import settings
from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup.website import (
    COMMAND_TIMEOUT,
    _PREFLIGHT_FLOOR,
    _build_lftp_script,
    _lftp_quote,
    _lftp_url_host,
    _materialize_ssh_private_key,
    _normalize_ssh_key,
    _redact,
    _lftp_depth_stack_exhausted,
    _serial_lftp_script,
)
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
    maybe_extract_tar,
    stale_local_restore_work_prefixes,
)
from apps._tasks.integration.restore_lease import RestoreLeaseLost
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.console.backup.models import RestoreExecutionLeaseLostError
from apps.console.connection.models import CoreAuthWebsite
from apps.console.connection.ssh import managed_private_key_path


WEBSITE_MARKER_VERSION = "1"
WEBSITE_MARKER_NAME = ".backupsheep-restore-marker"
SOURCE_MANIFEST_VERSION = 2
SOURCE_MANIFEST_COMMIT_INTERVAL = 10_000
SOURCE_MANIFEST_DOMAIN = b"backupsheep-website-source-manifest-v2\x00"
RESTORE_NAME_FIDELITY_PROBES = (
    "Case-sensitive-name.bin",
    "case-sensitive-name.bin",
    "caf\u00e9-normalization-name.bin",
    "cafe\u0301-normalization-name.bin",
)


def _write_log(backup, text):
    """Append only fixed, non-secret operational text to the restore log."""
    with open(f"_storage/restore_{backup.uuid_str}.log", "a+") as log_file:
        log_file.write(text)


def _has_restore_fence(restore):
    return bool(
        getattr(restore, "_required_restore_lease_owner", "")
        and getattr(restore, "_required_restore_lease_token", "")
    )


def _ensure_restore_fence(restore):
    """Refuse a new external action after the durable restore lease is lost."""
    if not _has_restore_fence(restore):
        return
    manager = getattr(restore.__class__, "objects", None)
    if manager is None:
        return
    if not manager.filter(
        pk=restore.pk,
        lease_owner=restore._required_restore_lease_owner,
        lease_token=restore._required_restore_lease_token,
        lease_expires_at__gt=timezone.now(),
    ).exists():
        raise RestoreLeaseLost("Restore execution lease ownership was lost.")


def _restore_work_suffix(restore, backup):
    owner = str(getattr(restore, "_required_restore_lease_owner", "") or "")
    token = str(getattr(restore, "_required_restore_lease_token", "") or "")
    if owner or token:
        return hashlib.sha256(f"{owner}|{token}".encode("utf-8")).hexdigest()[:16]
    return str(backup.uuid_str)


def _save_restore(restore, fields):
    _ensure_restore_fence(restore)
    fields = list(dict.fromkeys(fields))
    if "modified" not in fields:
        fields.append("modified")
    restore.save(update_fields=fields)


def _metadata(restore):
    return dict(getattr(restore, "execution_metadata", None) or {})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _safe_failure(node, backup, code):
    _write_log(backup, f"Website restore stopped: {code}.\n")
    return NodeBackupFailedError(
        node,
        backup.uuid_str,
        getattr(backup, "attempt_no", 0),
        getattr(backup, "type", "website"),
        "The website restore could not complete. Secured diagnostics contain the detailed cause.",
    )


def _capture_safe(code):
    capture_exception(RuntimeError(f"website restore diagnostic: {code}"))


def _run_lftp(
    node,
    backup,
    restore,
    auth,
    script,
    username,
    password,
    *,
    what,
    enforce_fence=True,
    check_result=True,
):
    """Run lftp with credentials on stdin and only safe failure details."""
    def run_lftp(current_script):
        if enforce_fence:
            _ensure_restore_fence(restore)
        try:
            current_proc = subprocess.run(
                ["lftp"],
                input=current_script,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=COMMAND_TIMEOUT,
                text=True,
                errors="ignore",
            )
        except subprocess.TimeoutExpired:
            _capture_safe("LFTP_TIMEOUT")
            raise _safe_failure(node, backup, "LFTP_TIMEOUT") from None
        except (FileNotFoundError, OSError):
            _capture_safe("LFTP_UNAVAILABLE")
            raise _safe_failure(node, backup, "LFTP_UNAVAILABLE") from None
        if enforce_fence:
            _ensure_restore_fence(restore)
        return current_proc

    proc = run_lftp(script)
    if check_result and _lftp_depth_stack_exhausted(proc):
        serial_script = _serial_lftp_script(script)
        if serial_script != script:
            _write_log(
                backup,
                "Website restore reached the lftp deep-tree limit; retrying the "
                "same staged transfer with serial directory traversal.\n",
            )
            proc = run_lftp(serial_script)

    # A process may have completed a remote action just before losing its
    # lease.  Do not commit the result or continue to another action then.
    output = str(proc.stdout or "")
    # lftp normally preserves a failed transfer's exit status, but some login
    # failures have historically exited zero after a trailing ``bye``. Treat only
    # explicit fatal/authentication lines as failure so warnings cannot silently
    # turn into a successful restore.
    fatal_output = re.search(
        r"(?im)(?:^|\s)(?:login failed|authentication failed|fatal error(?:\s*:|\b))",
        output,
    )
    if check_result and (proc.returncode != 0 or fatal_output):
        _capture_safe("LFTP_REJECTED")
        raise _safe_failure(node, backup, "LFTP_REJECTED") from None
    return proc


def _safe_remote_parent(parent, username="", password=""):
    """Return a bounded, credential-redacted remote path for diagnostics."""
    value = str(parent or ".").replace("\r", "").replace("\n", "")
    value = _redact(value, username, password)
    return value[:200]


def _website_restore_target_rejected(
    node, backup, parent, username, password, *, reason="write/create/rename"
):
    """Build an actionable terminal target rejection without exposing secrets."""
    safe_parent = _safe_remote_parent(parent, username, password)
    message = (
        "Permission denied: the configured SSH user cannot "
        f"{reason} the website restore staging probe in remote parent "
        f"{safe_parent}. Grant that user create/write/rename/delete permission "
        "on the parent, then retry the restore."
    )
    _write_log(
        backup,
        "Website restore stopped: WEBSITE_TARGET_PERMISSION_DENIED; "
        f"{message}\n",
    )
    failure = NodeBackupFailedError(
        node,
        backup.uuid_str,
        getattr(backup, "attempt_no", 0),
        getattr(backup, "type", "website"),
        message=message,
    )
    # NodeBackupFailedError is the existing restore-task target rejection
    # contract. Override its generic backup classification for direct callers
    # and diagnostics as well; the restore task still classifies by type.
    failure.error_code = "RESTORE_TARGET_REJECTED"
    failure.retryable = False
    failure.public_message = (
        "The restore target rejected the website staging permission preflight. "
        "Grant the configured SSH user write access to the remote parent and retry."
    )
    return failure


def _website_restore_preflight_error(backup, code, *, retryable=True):
    """Return a safe structured error for an unconfirmed remote preflight."""
    if code == "PROVIDER_TIMEOUT":
        message = (
            "The restore target permission preflight timed out; no website data "
            "was uploaded or published. The restore will resume safely."
        )
    elif code == "PROVIDER_AUTH_FAILED":
        message = (
            "The SSH/SFTP connection rejected the configured restore credentials; "
            "no website data was uploaded or published."
        )
        retryable = False
    else:
        code = "PROVIDER_TRANSIENT_FAILURE"
        message = (
            "The restore target permission preflight could not confirm the remote "
            "staging parent; no website data was uploaded or published. The restore "
            "will resume safely."
        )
    error = RestoreError(message)
    error.code = code
    error.retryable = bool(retryable)
    _write_log(backup, f"Website restore stopped: {code}; {message}\n")
    return error


def _website_restore_name_fidelity_error(backup):
    """Return a terminal safe error before a destination can merge names."""
    message = (
        "The restore target cannot preserve distinct case-sensitive and Unicode "
        "website filenames. No website data was uploaded or published. Choose a "
        "destination filesystem that preserves exact filenames, then retry."
    )
    error = RestoreError(message)
    error.code = "RESTORE_TARGET_NAME_COLLISION"
    error.retryable = False
    _write_log(
        backup,
        "Website restore stopped: RESTORE_TARGET_NAME_COLLISION; no target data "
        "was published.\n",
    )
    return error


def _website_restore_cleanup_error(backup, code="PROVIDER_TRANSIENT_FAILURE"):
    """Return a safe retryable error for cleanup that was not confirmed."""
    if code == "PROVIDER_AUTH_FAILED":
        message = (
            "The SSH/SFTP connection rejected the configured restore credentials "
            "while cleaning website restore data. The restore will not publish "
            "again."
        )
        retryable = False
    else:
        code = "PROVIDER_TRANSIENT_FAILURE"
        message = (
            "Website restore cleanup could not be confirmed; the restore will "
            "retry cleanup safely without publishing the website again."
        )
        retryable = True
    error = RestoreError(message)
    error.code = code
    error.retryable = retryable
    _write_log(backup, f"Website restore cleanup pending: {code}.\n")
    return error


def _website_restore_cleanup_ownership_error(backup, *, proof=False):
    """Return a terminal safe error when exact restore ownership is unproven."""
    if proof:
        message = (
            "Website restore cleanup could not prove the newly published target "
            "and restore marker; the previous target was retained. Manual review "
            "is required."
        )
    else:
        message = (
            "Website restore cleanup refused an unowned or non-deterministic path; "
            "the previous target was retained. Manual review is required."
        )
    error = RestoreError(message)
    error.code = "PROVIDER_OWNERSHIP_MISMATCH"
    error.retryable = False
    _write_log(backup, "Website restore cleanup stopped: PROVIDER_OWNERSHIP_MISMATCH.\n")
    return error


def _probe_output_is_permission_denial(output):
    """Identify target permission failures, excluding SSH authentication errors."""
    value = str(output or "").lower()
    if any(
        marker in value
        for marker in (
            "permission denied (publickey)",
            "publickey",
            "login failed",
            "authentication failed",
            "host key verification failed",
        )
    ):
        return False
    return bool(
        re.search(
            r"permission denied|access denied|operation not permitted",
            value,
        )
    )


def _probe_output_is_auth_failure(output):
    value = str(output or "").lower()
    return any(
        marker in value
        for marker in (
            "permission denied (publickey)",
            "publickey",
            "login failed",
            "authentication failed",
            "host key verification failed",
        )
    )


def _probe_output_is_target_rejection(output):
    """Identify a remote target that cannot support the staged restore plan."""
    value = str(output or "").lower()
    if _probe_output_is_auth_failure(value):
        return False
    return _probe_output_is_permission_denial(value) or bool(
        re.search(
            r"no such file or directory|not a directory|cannot create|file exists",
            value,
        )
    )


def _probe_output_is_transport_failure(output):
    value = str(output or "").lower()
    return bool(
        re.search(
            r"connection reset|connection closed|connection refused|"
            r"network is unreachable|no route to host|broken pipe|"
            r"timed out|timeout|could not connect|couldn't connect|"
            r"failed to connect|server unexpectedly closed|not connected|"
            r"temporary failure in name resolution|name or service not known|"
            r"could not resolve|host not found",
            value,
        )
    )


def _remote_output_is_not_found(output):
    value = str(output or "").lower()
    return bool(
        re.search(
            r"no such file|file not found|not found|does not exist|cannot find",
            value,
        )
    )


def _run_restore_target_probe(
    node,
    backup,
    restore,
    auth,
    script,
    username,
    password,
    parent,
):
    """Run the same lftp/OpenSSH path used for transfers and classify safely."""
    _ensure_restore_fence(restore)
    try:
        proc = subprocess.run(
            ["lftp"],
            input=script,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT,
            text=True,
            errors="ignore",
        )
    except subprocess.TimeoutExpired:
        _capture_safe("WEBSITE_TARGET_PREFLIGHT_TIMEOUT")
        raise _website_restore_preflight_error(
            backup, "PROVIDER_TIMEOUT", retryable=True
        ) from None
    except FileNotFoundError:
        _capture_safe("WEBSITE_TARGET_PREFLIGHT_UNAVAILABLE")
        raise _website_restore_preflight_error(
            backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
        ) from None
    except OSError:
        _capture_safe("WEBSITE_TARGET_PREFLIGHT_UNAVAILABLE")
        raise _website_restore_preflight_error(
            backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
        ) from None

    # A probe may have completed remotely immediately before the lease was
    # lost. Never continue to archive transfer or publication afterward.
    _ensure_restore_fence(restore)
    output = str(proc.stdout or "")
    fatal_output = re.search(
        r"(?im)(?:^|\s)(?:login failed|authentication failed|fatal error(?:\s*:|\b))",
        output,
    )
    if _probe_output_is_target_rejection(output):
        _capture_safe("WEBSITE_TARGET_PERMISSION_DENIED")
        raise _website_restore_target_rejected(
            node,
            backup,
            parent,
            username,
            password,
        ) from None
    if _probe_output_is_auth_failure(output):
        _capture_safe("WEBSITE_TARGET_AUTH_FAILED")
        raise _website_restore_preflight_error(
            backup, "PROVIDER_AUTH_FAILED", retryable=False
        ) from None
    if proc.returncode == 0 and not fatal_output and not _probe_output_is_transport_failure(output):
        return proc
    _capture_safe("WEBSITE_TARGET_PREFLIGHT_UNCERTAIN")
    raise _website_restore_preflight_error(
        backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
    ) from None


def _validate_remote_path(path):
    value = "" if path is None else str(path)
    if not value or "\x00" in value or any(ord(char) < 32 for char in value):
        raise RestoreError("website restore contains an invalid remote path.")
    # A path is sent as an lftp quoted token, but parent traversal would still
    # let a restore rename or delete data outside the configured site.
    if any(part == ".." for part in value.split("/")):
        raise RestoreError("website restore remote paths may not contain '..'.")
    return value


def _normalise_sources(website):
    return _normalise_source_selection(website.all_paths, website.paths)


def _normalise_source_selection(all_paths, paths):
    if all_paths:
        return [{"path": ".", "type": "directory"}]
    sources = []
    seen = set()
    for item in paths or []:
        if not isinstance(item, dict):
            raise RestoreError("website restore path configuration is malformed.")
        path = _validate_remote_path(item.get("path"))
        source_type = str(item.get("type") or "").lower()
        if source_type not in {"file", "directory"}:
            raise RestoreError("website restore path type is invalid.")
        target_key = (source_type, posixpath.normpath(path))
        if target_key in seen:
            raise RestoreError("website restore contains a duplicate target path.")
        seen.add(target_key)
        sources.append({"path": path, "type": source_type})
    if not sources:
        raise RestoreError("website restore has no configured paths.")
    return sources


def _restore_sources(backup, website):
    """Resolve the archive layout without trusting later node-path edits.

    Older rows predate source-selection snapshots and keep their historical fallback
    to the current website configuration.  A row with either snapshot field present
    is authoritative, including the explicit ``all_paths=False`` case.
    """
    if backup.all_paths is not None or backup.paths is not None:
        return _normalise_source_selection(backup.all_paths, backup.paths)
    return _normalise_sources(website)


def _local_source_path(tree_root, source):
    root = os.path.realpath(tree_root)
    candidate = os.path.realpath(
        os.path.join(root, source["path"].lstrip("/"))
        if source["path"] != "."
        else root
    )
    if candidate != root and not candidate.startswith(root + os.sep):
        raise RestoreError("website restore archive path escapes its extraction root.")
    if source["type"] == "file":
        if not os.path.isfile(candidate) or os.path.islink(candidate):
            raise RestoreError(f"the backup archive does not contain {source['path']}.")
    elif not os.path.isdir(candidate) or os.path.islink(candidate):
        raise RestoreError(f"the backup archive does not contain {source['path']}.")
    return candidate


def _file_identity(path):
    digest = hashlib.sha256()
    byte_count = 0
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            byte_count += len(chunk)
            digest.update(chunk)
    return {"bytes": byte_count, "sha256": digest.hexdigest()}


def _source_manifest_inline_limit():
    try:
        value = int(
            getattr(settings, "WEBSITE_RESTORE_INLINE_FILE_LIMIT", 1_000)
        )
    except (TypeError, ValueError):
        value = 1_000
    return max(0, min(value, 10_000))


def _update_source_manifest_digest(
    digest, *, path_bytes, kind, byte_count=0, checksum=b""
):
    """Bind one ordered member without ambiguous string concatenation."""
    digest.update(b"D" if kind == 1 else b"F")
    digest.update(len(path_bytes).to_bytes(8, "big"))
    digest.update(path_bytes)
    digest.update(int(byte_count).to_bytes(8, "big"))
    digest.update(checksum if kind == 0 else b"\x00" * 32)


def _source_manifest(source, local_path, *, inline_limit=None):
    """Return a bounded, deterministic identity for one extracted source.

    Path ordering, traversal state, and per-file identities are disk-spooled. The
    returned ``files`` list is retained only for small restores so existing detailed
    checkpoints remain useful without making durable JSON scale with member count.
    """
    if inline_limit is None:
        inline_limit = _source_manifest_inline_limit()
    inline_limit = max(0, min(int(inline_limit), 10_000))
    digest = hashlib.sha256(SOURCE_MANIFEST_DOMAIN)

    if source["type"] == "file":
        identity = _file_identity(local_path)
        path = posixpath.basename(source["path"])
        path_bytes = os.fsencode(path)
        checksum = bytes.fromhex(identity["sha256"])
        _update_source_manifest_digest(
            digest,
            path_bytes=path_bytes,
            kind=0,
            byte_count=identity["bytes"],
            checksum=checksum,
        )
        summary = {
            "version": SOURCE_MANIFEST_VERSION,
            "algorithm": "sha256",
            "sha256": digest.hexdigest(),
            "file_count": 1,
            "directory_count": 0,
            "member_count": 1,
            "byte_count": int(identity["bytes"]),
        }
        files = [{"path": path, **identity}] if inline_limit else []
        return {
            "summary": summary,
            "files": files,
            "inlined": bool(inline_limit),
        }

    root = os.path.realpath(local_path)
    root_bytes = os.fsencode(root)
    parent = os.path.dirname(root)
    descriptor, index_path = tempfile.mkstemp(
        prefix=".backupsheep-source-manifest-",
        suffix=".sqlite3",
        dir=parent,
    )
    os.close(descriptor)
    index = None
    try:
        index = sqlite3.connect(index_path)
        index.execute("PRAGMA journal_mode=OFF")
        index.execute("PRAGMA synchronous=OFF")
        index.execute("PRAGMA temp_store=FILE")
        index.execute("PRAGMA cache_size=-2048")
        index.execute(
            "CREATE TABLE members ("
            "path BLOB PRIMARY KEY, kind INTEGER NOT NULL, "
            "byte_count INTEGER NOT NULL, checksum BLOB"
            ") WITHOUT ROWID"
        )
        index.execute(
            "CREATE TABLE directories (path BLOB PRIMARY KEY) WITHOUT ROWID"
        )
        index.execute("INSERT INTO directories(path) VALUES (?)", (b"",))
        index.commit()

        member_count = 0
        scanned_directories = 0
        while True:
            queued = index.execute(
                "SELECT path FROM directories ORDER BY path LIMIT 1"
            ).fetchone()
            if queued is None:
                break
            relative_root = bytes(queued[0])
            absolute_root = (
                root_bytes
                if not relative_root
                else os.path.join(root_bytes, relative_root)
            )
            try:
                entries = os.scandir(absolute_root)
            except OSError as error:
                raise RestoreError(
                    "the staged website files changed after validation; manual review is required."
                ) from error
            with entries:
                for entry in entries:
                    relative = (
                        entry.name
                        if not relative_root
                        else relative_root + b"/" + entry.name
                    )
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except OSError as error:
                        raise RestoreError(
                            "the staged website files changed after validation; manual review is required."
                        ) from error
                    if stat.S_ISLNK(mode):
                        raise RestoreError(
                            "website restore archive contains a symbolic link."
                        )
                    if stat.S_ISDIR(mode):
                        index.execute(
                            "INSERT INTO members(path, kind, byte_count, checksum) "
                            "VALUES (?, 1, 0, NULL)",
                            (relative,),
                        )
                        index.execute(
                            "INSERT INTO directories(path) VALUES (?)", (relative,)
                        )
                    elif stat.S_ISREG(mode):
                        identity = _file_identity(entry.path)
                        index.execute(
                            "INSERT INTO members(path, kind, byte_count, checksum) "
                            "VALUES (?, 0, ?, ?)",
                            (
                                relative,
                                int(identity["bytes"]),
                                bytes.fromhex(identity["sha256"]),
                            ),
                        )
                    else:
                        raise RestoreError(
                            "website restore archive contains an unsupported file."
                        )
                    member_count += 1
                    if member_count % SOURCE_MANIFEST_COMMIT_INTERVAL == 0:
                        index.commit()
            index.execute("DELETE FROM directories WHERE path = ?", (relative_root,))
            scanned_directories += 1
            if scanned_directories % 1_000 == 0:
                index.commit()

        index.commit()

        file_count = 0
        directory_count = 0
        byte_count = 0
        for path_value, kind, member_bytes, checksum in index.execute(
            "SELECT path, kind, byte_count, checksum FROM members ORDER BY path"
        ):
            path_bytes = bytes(path_value)
            kind = int(kind)
            member_bytes = int(member_bytes)
            checksum_bytes = bytes(checksum or b"")
            _update_source_manifest_digest(
                digest,
                path_bytes=path_bytes,
                kind=kind,
                byte_count=member_bytes,
                checksum=checksum_bytes,
            )
            if kind == 1:
                directory_count += 1
            else:
                file_count += 1
                byte_count += member_bytes

        summary = {
            "version": SOURCE_MANIFEST_VERSION,
            "algorithm": "sha256",
            "sha256": digest.hexdigest(),
            "file_count": file_count,
            "directory_count": directory_count,
            "member_count": file_count + directory_count,
            "byte_count": byte_count,
        }
        files = []
        if file_count <= inline_limit:
            files = [
                {
                    "path": os.fsdecode(bytes(path_value)),
                    "bytes": int(member_bytes),
                    "sha256": bytes(checksum).hex(),
                }
                for path_value, member_bytes, checksum in index.execute(
                    "SELECT path, byte_count, checksum FROM members "
                    "WHERE kind = 0 ORDER BY path"
                )
            ]
        return {
            "summary": summary,
            "files": files,
            "inlined": file_count <= inline_limit,
        }
    except sqlite3.Error as error:
        raise RestoreError(
            "unable to build the website source safety index."
        ) from error
    finally:
        if index is not None:
            index.close()
        try:
            os.remove(index_path)
        except FileNotFoundError:
            pass


def _prepare_sources(tree_root, sources, backup):
    records = []
    manifest = {}
    for source in sources:
        local_path = _local_source_path(tree_root, source)
        source_manifest = _source_manifest(source, local_path)
        file_manifest = source_manifest["summary"]
        files = source_manifest["files"]
        if source_manifest["inlined"]:
            # Keep the historical identity for bounded small restores so an
            # in-progress restore survives deployment without changing its
            # durable fingerprint or remote stage names.
            identity = {
                "backup_uuid": str(backup.uuid),
                "path": source["path"],
                "type": source["type"],
                "files": files,
            }
        else:
            identity = {
                "version": SOURCE_MANIFEST_VERSION,
                "backup_uuid": str(backup.uuid),
                "path": source["path"],
                "type": source["type"],
                "file_manifest": file_manifest,
            }
        source_digest = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()
        fingerprint = hashlib.sha256(
            f"{backup.uuid}|{source_digest}".encode("utf-8")
        ).hexdigest()
        source_key = f"{source['type']}:{source['path']}"
        record = {
            **source,
            "local_path": local_path,
            "files": files,
            "file_manifest": file_manifest,
            "source_digest": source_digest,
            "fingerprint": fingerprint,
            "source_key": source_key,
        }
        records.append(record)
        manifest[source_key] = {
            "path": source["path"],
            "type": source["type"],
            "source_digest": source_digest,
        }
        if source_manifest["inlined"]:
            manifest[source_key]["files"] = files
        else:
            manifest[source_key]["file_manifest"] = file_manifest
    return records, manifest


def _verify_source_manifest(record):
    expected = record.get("file_manifest")
    if expected:
        current = _source_manifest(
            record, record["local_path"], inline_limit=0
        )["summary"]
        matches = current == expected
    else:
        # Compatibility for an already-checkpointed legacy restore. New large
        # restores always carry the bounded v2 summary above.
        expected_files = list(record.get("files") or [])
        current = _source_manifest(
            record,
            record["local_path"],
            inline_limit=min(len(expected_files), 10_000),
        )
        matches = (
            current["summary"]["file_count"] == len(expected_files)
            and current["files"] == expected_files
        )
    if not matches:
        raise RestoreError(
            "the staged website files changed after validation; manual review is required."
        )


def _file_states(record, status):
    return {
        item["path"]: {
            "bytes": int(item["bytes"]),
            "sha256": item["sha256"],
            "status": status,
        }
        for item in record.get("files") or []
    }


def _remote_stage_paths(restore, record):
    target = posixpath.normpath(record["path"])
    if target in {".", "/"}:
        return None
    parent, basename = posixpath.split(target)
    parent = parent or "."
    correlation = str(getattr(restore, "correlation_id", "restore")).replace("-", "")
    stage_root = posixpath.join(
        parent,
        f".backupsheep_restore_{correlation[:16]}_{record['fingerprint'][:16]}",
    )
    old_path = posixpath.join(
        parent,
        f".{basename}.backupsheep_previous_{correlation[:16]}_{record['fingerprint'][:16]}",
    )
    return {
        "stage_root": stage_root,
        "payload": posixpath.join(stage_root, "payload"),
        "marker": posixpath.join(stage_root, WEBSITE_MARKER_NAME),
        "old": old_path,
    }


def _remote_restore_parent(path):
    """Return the existing parent required by the staged publish plan."""
    target = posixpath.normpath(path)
    if target in {".", "/"}:
        return None
    return posixpath.dirname(target) or "."


def _remote_probe_paths(restore, backup, source):
    """Build restore-scoped probe paths without using the final target path."""
    parent = _remote_restore_parent(source["path"])
    if parent is None:
        # Root/all-path restores cannot use the sibling atomic-publish plan, but
        # an exact hidden child remains a safe, restore-owned capability probe.
        parent = "."
    restore_scope = hashlib.sha256(
        f"{getattr(restore, 'correlation_id', '')}|{backup.uuid}".encode("utf-8")
    ).hexdigest()[:16]
    source_scope = hashlib.sha256(
        f"{source['type']}|{posixpath.normpath(source['path'])}".encode("utf-8")
    ).hexdigest()[:16]
    name = f".backupsheep_restore_probe_{restore_scope}_{source_scope}"
    root = posixpath.join(parent, name)
    return {
        "parent": parent,
        "root": root,
        "payload": posixpath.join(root, "payload"),
        "renamed": posixpath.join(parent, f"{name}_renamed"),
        "name_fidelity": [
            posixpath.join(root, probe_name)
            for probe_name in RESTORE_NAME_FIDELITY_PROBES
        ],
    }


def _write_restore_probe_file():
    """Create a tiny owner-only local payload for the SFTP probe."""
    descriptor, path = tempfile.mkstemp(
        prefix="website_restore_probe_", suffix=".bin", dir="_storage"
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(b"BackupSheep restore target preflight\n")
            output.flush()
            os.fsync(output.fileno())
        return path
    except Exception:
        try:
            if descriptor is not None:
                os.close(descriptor)
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def _probe_preserves_distinct_names(output, probe):
    """Require all exact probe basenames in the bounded remote listing."""
    expected = {
        posixpath.basename(path)
        for path in probe.get("name_fidelity") or []
    }
    if expected != set(RESTORE_NAME_FIDELITY_PROBES):
        return False
    observed = set()
    for line in str(output or "").splitlines():
        value = line.strip().rstrip("/")
        if not value:
            continue
        basename = posixpath.basename(value)
        if basename in expected:
            observed.add(basename)
    return observed == expected


def _cleanup_restore_target_probe(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    ssh_key_path,
    host_url,
    parallel,
    probe,
):
    """Best-effort cleanup of only the exact restore-owned probe paths.

    Cleanup is allowed after fence loss because these names are derived solely
    from this restore and source, never from user-controlled final targets.
    It can therefore remove a stale probe left by a crashed worker without
    granting a stale worker permission to publish or delete website data.
    """
    if not probe:
        return True
    try:
        proc = _run_lftp(
            node,
            backup,
            restore,
            auth,
            _build_lftp_script(
                auth=auth,
                host_url=host_url,
                port=auth.port,
                username=username,
                password=password,
                ssh_key_path=ssh_key_path,
                parallel=parallel,
                transfer="\n".join(
                    [
                        "set cmd:fail-exit no",
                        f"rm -r {_lftp_quote(probe['renamed'])}",
                        f"rm -r {_lftp_quote(probe['root'])}",
                    ]
                ),
                mirror=False,
            ),
            username,
            password,
            what="clean website restore permission probe",
            enforce_fence=False,
            check_result=False,
        )
        output = str(getattr(proc, "stdout", "") or "")
        if (
            _probe_output_is_auth_failure(output)
            or _probe_output_is_permission_denial(output)
            or _probe_output_is_transport_failure(output)
        ):
            return False
        # A crashed predecessor may already have removed either exact,
        # restore-owned probe path. lftp reports that idempotent state with a
        # non-zero process status, so inspect the bounded output before the
        # generic return-code check.
        if _remote_output_is_not_found(output):
            return True
        return getattr(proc, "returncode", 1) == 0
    except Exception:
        _capture_safe("WEBSITE_TARGET_PROBE_CLEANUP_FAILED")
        return False


def _preflight_restore_target(
    node,
    backup,
    restore,
    auth,
    website,
    sources,
    host_url,
    username,
    password,
    ssh_key_path,
):
    """Verify every non-root SFTP restore parent before archive download.

    The probe creates a tiny staging directory, writes one tiny payload, moves
    that payload to a sibling, and then removes both paths. It never addresses
    the configured final target. A transport loss is retryable but no upload or
    publication is attempted by this call.
    """
    if auth.protocol != CoreAuthWebsite.Protocol.SFTP:
        return
    probes = []
    for source in sources:
        if _remote_restore_parent(source["path"]) is None:
            continue
        probe = _remote_probe_paths(restore, backup, source)
        if probe is not None:
            probes.append((source, probe))
    if not probes:
        return

    local_probe = _write_restore_probe_file()
    parallel = website.parallel or 3
    try:
        for source, probe in probes:
            primary_error = None
            try:
                _ensure_restore_fence(restore)
                # A hard worker crash can leave the exact probe behind. It is
                # restore-scoped and therefore safe to remove before creating
                # the next probe attempt; this keeps redelivery convergent.
                if not _cleanup_restore_target_probe(
                    node,
                    backup,
                    restore,
                    auth,
                    username,
                    password,
                    ssh_key_path,
                    host_url,
                    parallel,
                    probe,
                ):
                    raise _website_restore_preflight_error(
                        backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
                    )
                if source["type"] == "file":
                    payload_command = (
                        f"put -P {_lftp_quote(local_probe)} "
                        f"-o {_lftp_quote(probe['payload'])}"
                    )
                else:
                    payload_command = f"mkdir {_lftp_quote(probe['payload'])}"
                script = _build_lftp_script(
                    auth=auth,
                    host_url=host_url,
                    port=auth.port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    parallel=parallel,
                    transfer="\n".join(
                        [
                            f"mkdir {_lftp_quote(probe['root'])}",
                            payload_command,
                            f"mv {_lftp_quote(probe['payload'])} "
                            f"{_lftp_quote(probe['renamed'])}",
                            f"cls -1 {_lftp_quote(probe['renamed'])}",
                        ]
                    ),
                    mirror=False,
                )
                _run_restore_target_probe(
                    node,
                    backup,
                    restore,
                    auth,
                    script,
                    username,
                    password,
                    probe["parent"],
                )
            except Exception as error:
                primary_error = error
            cleaned = _cleanup_restore_target_probe(
                node,
                backup,
                restore,
                auth,
                username,
                password,
                ssh_key_path,
                host_url,
                parallel,
                probe,
            )
            if primary_error is not None:
                raise primary_error
            if not cleaned:
                raise _website_restore_preflight_error(
                    backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
                )
    finally:
        try:
            os.remove(local_probe)
        except OSError:
            pass


def _preflight_restore_name_fidelity(
    node,
    backup,
    restore,
    auth,
    website,
    sources,
    host_url,
    username,
    password,
    ssh_key_path,
):
    """Prove the target preserves exact case and Unicode names.

    This check intentionally runs only after the backup archive is available
    and its source tree has been validated. Archive-provider retries therefore
    do not repeatedly touch the restore target. Every probe remains hidden,
    restore-owned, and is removed before any website data is uploaded.
    """
    if auth.protocol != CoreAuthWebsite.Protocol.SFTP:
        return

    probes = [_remote_probe_paths(restore, backup, source) for source in sources]
    probes = [probe for probe in probes if probe is not None]
    if not probes:
        return

    local_probe = _write_restore_probe_file()
    parallel = website.parallel or 3
    try:
        for probe in probes:
            primary_error = None
            try:
                _ensure_restore_fence(restore)
                if not _cleanup_restore_target_probe(
                    node,
                    backup,
                    restore,
                    auth,
                    username,
                    password,
                    ssh_key_path,
                    host_url,
                    parallel,
                    probe,
                ):
                    raise _website_restore_preflight_error(
                        backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
                    )
                script = _build_lftp_script(
                    auth=auth,
                    host_url=host_url,
                    port=auth.port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    parallel=parallel,
                    transfer="\n".join(
                        [
                            f"mkdir {_lftp_quote(probe['root'])}",
                            f"mkdir {_lftp_quote(probe['payload'])}",
                            *[
                                f"put -P {_lftp_quote(local_probe)} "
                                f"-o {_lftp_quote(remote_path)}"
                                for remote_path in probe["name_fidelity"]
                            ],
                            f"cls -1 {_lftp_quote(probe['root'])}",
                            f"mv {_lftp_quote(probe['payload'])} "
                            f"{_lftp_quote(probe['renamed'])}",
                            f"cls -1 {_lftp_quote(probe['renamed'])}",
                        ]
                    ),
                    mirror=False,
                )
                result = _run_restore_target_probe(
                    node,
                    backup,
                    restore,
                    auth,
                    script,
                    username,
                    password,
                    probe["parent"],
                )
                if not _probe_preserves_distinct_names(
                    getattr(result, "stdout", ""), probe
                ):
                    _capture_safe("WEBSITE_TARGET_NAME_COLLISION")
                    raise _website_restore_name_fidelity_error(backup)
            except Exception as error:
                primary_error = error
            cleaned = _cleanup_restore_target_probe(
                node,
                backup,
                restore,
                auth,
                username,
                password,
                ssh_key_path,
                host_url,
                parallel,
                probe,
            )
            if primary_error is not None:
                raise primary_error
            if not cleaned:
                raise _website_restore_preflight_error(
                    backup, "PROVIDER_TRANSIENT_FAILURE", retryable=True
                )
    finally:
        try:
            os.remove(local_probe)
        except OSError:
            pass


def _write_stage_marker(backup, restore, record):
    descriptor, path = tempfile.mkstemp(
        prefix="website_restore_marker_", suffix=".json", dir="_storage"
    )
    try:
        os.fchmod(descriptor, 0o600)
        marker = {
            "version": WEBSITE_MARKER_VERSION,
            "backup_uuid": str(backup.uuid),
            "correlation_id": str(restore.correlation_id),
            "source_path": record["path"],
            "source_type": record["type"],
            "source_digest": record["source_digest"],
            "target_path": record["path"],
            "fingerprint": record["fingerprint"],
        }
        payload = (_canonical(marker) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
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


def _checkpoint(restore, *, phase, manifest, records=None, progress_total=None):
    """Merge immutable source/file checkpoints without allowing regression."""
    values = _metadata(restore)
    old_manifest = values.get("source_manifest")
    if old_manifest is not None and old_manifest != manifest:
        raise RestoreError(
            "the website source manifest changed; manual review is required."
        )
    values["source_manifest"] = manifest
    states = dict(values.get("source_states") or {})
    state_order = {
        "pending": 0,
        "staging": 1,
        "transferring": 1,
        "staged": 2,
        "publishing": 3,
        "cleanup_pending": 4,
        "complete": 5,
    }
    file_order = {
        "pending": 0,
        "in_progress": 1,
        "staging": 1,
        "staged": 2,
        "complete": 3,
    }
    for record in records or []:
        fingerprint = record["fingerprint"]
        requested = dict(record["state"])
        existing = dict(states.get(fingerprint) or {})
        for identity_field in (
            "path",
            "type",
            "source_digest",
            "target_path",
            "file_manifest",
        ):
            if existing.get(identity_field) not in (None, requested.get(identity_field)):
                raise RestoreError(
                    "the website target mapping changed; manual review is required."
                )
        old_status = str(existing.get("status") or "pending")
        new_status = str(requested.get("status") or old_status)
        if state_order.get(new_status, -1) < state_order.get(old_status, -1):
            raise RestoreError(
                "the website restore checkpoint moved backwards; manual review is required."
            )
        merged = dict(existing)
        merged.update(requested)
        old_files = dict(existing.get("files") or {})
        requested_files = dict(requested.get("files") or {})
        merged_files = dict(old_files)
        for filename, file_state in requested_files.items():
            old_file = dict(old_files.get(filename) or {})
            if old_file and (
                old_file.get("sha256") != file_state.get("sha256")
                or int(old_file.get("bytes") or 0) != int(file_state.get("bytes") or 0)
            ):
                raise RestoreError(
                    "the website file checkpoint identity changed; manual review is required."
                )
            old_file_status = str(old_file.get("status") or "pending")
            new_file_status = str(file_state.get("status") or old_file_status)
            if file_order.get(new_file_status, -1) < file_order.get(
                old_file_status, -1
            ):
                raise RestoreError(
                    "the website file checkpoint moved backwards; manual review is required."
                )
            merged_file = dict(old_file)
            merged_file.update(file_state)
            merged_files[filename] = merged_file
        if merged_files:
            merged["files"] = merged_files
        states[fingerprint] = merged
    values["source_states"] = states
    values["completed_sources"] = sorted(
        fingerprint
        for fingerprint, state in states.items()
        if state.get("status") == "complete"
    )
    restore.execution_metadata = values
    restore.execution_phase = str(phase)[:64]
    completed = len(values["completed_sources"])
    restore.progress_completed = max(
        int(getattr(restore, "progress_completed", 0) or 0), completed
    )
    if progress_total is not None:
        restore.progress_total = int(progress_total)
    restore.progress_unit = "paths"
    _save_restore(
        restore,
        [
            "execution_metadata",
            "execution_phase",
            "progress_completed",
            "progress_total",
            "progress_unit",
        ],
    )


def _state_for(record, status, *, files_status=None, stage=None):
    state = {
        "path": record["path"],
        "target_path": record["path"],
        "type": record["type"],
        "source_digest": record["source_digest"],
        "status": status,
    }
    if record.get("file_manifest"):
        state["file_manifest"] = record["file_manifest"]
    file_states = _file_states(record, files_status or "pending")
    if file_states:
        state["files"] = file_states
    if stage:
        state.update(stage)
    return state


def _record_state(restore, record):
    return dict(
        (_metadata(restore).get("source_states") or {}).get(record["fingerprint"])
        or {}
    )


def _expected_restore_stage(restore, record):
    stage = _remote_stage_paths(restore, record)
    if stage is None:
        return None
    return {**stage, "target_path": record["path"]}


def _require_exact_restore_stage(backup, restore, record, stage):
    """Refuse cleanup unless every remote path is this restore's exact plan."""
    expected = _expected_restore_stage(restore, record)
    if expected is None or not isinstance(stage, dict):
        raise _website_restore_cleanup_ownership_error(backup)
    for name, value in expected.items():
        if stage.get(name) != value:
            raise _website_restore_cleanup_ownership_error(backup)
    return expected


def _run_observed_lftp(
    node,
    backup,
    restore,
    auth,
    script,
    username,
    password,
    *,
    what,
):
    """Run a read/cleanup command while preserving its safe result for parsing."""
    try:
        return _run_lftp(
            node,
            backup,
            restore,
            auth,
            script,
            username,
            password,
            what=what,
            check_result=False,
        )
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError):
        raise
    except Exception:
        _capture_safe("WEBSITE_RESTORE_CLEANUP_UNCERTAIN")
        raise _website_restore_cleanup_error(backup) from None


def _verify_published_target(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    ssh_key_path,
    host_url,
    parallel,
    record,
    stage,
):
    """Prove both the published target and this restore's marker exist."""
    expected = _require_exact_restore_stage(backup, restore, record, stage)
    script = _build_lftp_script(
        auth=auth,
        host_url=host_url,
        port=auth.port,
        username=username,
        password=password,
        ssh_key_path=ssh_key_path,
        parallel=parallel,
        transfer="\n".join(
            [
                "set cmd:fail-exit yes",
                f"cls -1 {_lftp_quote(expected['target_path'])}",
                f"cls -1 {_lftp_quote(expected['marker'])}",
            ]
        ),
        mirror=False,
    )
    proc = _run_observed_lftp(
        node,
        backup,
        restore,
        auth,
        script,
        username,
        password,
        what="verify published website target",
    )
    output = str(getattr(proc, "stdout", "") or "")
    if (
        getattr(proc, "returncode", 1) == 0
        and not _remote_output_is_not_found(output)
        and not _probe_output_is_transport_failure(output)
    ):
        return True
    if _probe_output_is_auth_failure(output):
        raise _website_restore_cleanup_error(backup, "PROVIDER_AUTH_FAILED")
    if (
        _remote_output_is_not_found(output)
        or _probe_output_is_permission_denial(output)
    ):
        raise _website_restore_cleanup_ownership_error(backup, proof=True)
    raise _website_restore_cleanup_error(backup)


def _cleanup_exact_remote_path(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    ssh_key_path,
    host_url,
    parallel,
    path,
    *,
    what,
):
    """Delete one already-validated path; remote absence is idempotent success."""
    script = _build_lftp_script(
        auth=auth,
        host_url=host_url,
        port=auth.port,
        username=username,
        password=password,
        ssh_key_path=ssh_key_path,
        parallel=parallel,
        transfer="\n".join(
            [
                "set cmd:fail-exit no",
                f"rm -r {_lftp_quote(path)}",
            ]
        ),
        mirror=False,
    )
    proc = _run_observed_lftp(
        node,
        backup,
        restore,
        auth,
        script,
        username,
        password,
        what=what,
    )
    output = str(getattr(proc, "stdout", "") or "")
    if _probe_output_is_auth_failure(output):
        raise _website_restore_cleanup_error(backup, "PROVIDER_AUTH_FAILED")
    if _probe_output_is_permission_denial(output):
        raise _website_restore_cleanup_ownership_error(backup)
    if _probe_output_is_transport_failure(output):
        raise _website_restore_cleanup_error(backup)
    if _remote_output_is_not_found(output):
        return True
    if getattr(proc, "returncode", 1) != 0:
        raise _website_restore_cleanup_error(backup)
    return True


def _cleanup_previous_target(
    node,
    backup,
    restore,
    auth,
    username,
    password,
    ssh_key_path,
    host_url,
    parallel,
    record,
    stage,
):
    expected = _require_exact_restore_stage(backup, restore, record, stage)
    return _cleanup_exact_remote_path(
        node,
        backup,
        restore,
        auth,
        username,
        password,
        ssh_key_path,
        host_url,
        parallel,
        expected["old"],
        what="remove previous website target",
    )


def _publish_script(auth, host_url, port, username, password, ssh_key_path, parallel, stage):
    # The first mv is intentionally non-fatal because the target may not exist.
    # The second mv and final listing are fatal.  If the publish process dies
    # between the two renames, the durable state is ``publishing`` and the next
    # worker stops for manual review rather than guessing which path is live.
    transfer = "\n".join(
        [
            "set cmd:fail-exit no",
            f"mv {_lftp_quote(stage['target_path'])} {_lftp_quote(stage['old'])}",
            "set cmd:fail-exit yes",
            f"mv {_lftp_quote(stage['payload'])} {_lftp_quote(stage['target_path'])}",
            f"cls -1 {_lftp_quote(stage['target_path'])}",
            f"cls -1 {_lftp_quote(stage['marker'])}",
        ]
    )
    return _build_lftp_script(
        auth=auth,
        host_url=host_url,
        port=port,
        username=username,
        password=password,
        ssh_key_path=ssh_key_path,
        parallel=parallel,
        transfer=transfer,
        mirror=False,
    )


def _cleanup_remote_stage(
    node, backup, restore, auth, username, password, ssh_key_path, host_url, parallel, stage
):
    """Remove only the exact stage directory created for this restore source."""
    if not stage:
        return True
    try:
        return _cleanup_exact_remote_path(
            node,
            backup,
            restore,
            auth,
            username,
            password,
            ssh_key_path,
            host_url,
            parallel,
            stage["stage_root"],
            what="clean restore staging",
        )
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError):
        raise
    except RestoreError:
        _capture_safe("REMOTE_STAGE_CLEANUP_FAILED")
        raise
    except Exception:
        _capture_safe("REMOTE_STAGE_CLEANUP_FAILED")
        return False


def _restore_published_source_cleanup(
    node,
    backup,
    restore,
    auth,
    record,
    website,
    host_url,
    username,
    password,
    ssh_key_path,
    stage,
    state,
):
    """Prove publication, remove the old target, then remove staging durably."""
    expected = _require_exact_restore_stage(backup, restore, record, stage)
    cleanup = dict(state.get("cleanup") or {})
    previous_status = str(cleanup.get("previous_target") or "pending")
    staging_status = str(cleanup.get("staging") or "pending")
    if previous_status not in {"pending", "complete"} or staging_status not in {
        "pending",
        "complete",
    }:
        raise _website_restore_cleanup_ownership_error(backup)

    parallel = website.parallel or 3
    if previous_status != "complete":
        # Persist this before any delete. A worker crash or lost response now
        # redelivers into cleanup-only recovery instead of terminal complete.
        pending_status = (
            "complete" if str(state.get("status")) == "complete" else "cleanup_pending"
        )
        pending = _state_for(
            record,
            pending_status,
            files_status="complete",
            stage=expected,
        )
        pending["cleanup"] = {
            "previous_target": "pending",
            "staging": staging_status,
        }
        _checkpoint(
            restore,
            phase="website_cleanup_pending",
            manifest=_metadata(restore).get("source_manifest") or {},
            records=[{**record, "state": pending}],
            progress_total=int(getattr(restore, "progress_total", 1) or 1),
        )
        _verify_published_target(
            node,
            backup,
            restore,
            auth,
            username,
            password,
            ssh_key_path,
            host_url,
            parallel,
            record,
            expected,
        )
        _cleanup_previous_target(
            node,
            backup,
            restore,
            auth,
            username,
            password,
            ssh_key_path,
            host_url,
            parallel,
            record,
            expected,
        )
        previous_status = "complete"
        progressed = _state_for(
            record,
            "complete" if str(state.get("status")) == "complete" else "cleanup_pending",
            files_status="complete",
            stage=expected,
        )
        progressed["cleanup"] = {
            "previous_target": previous_status,
            "staging": staging_status,
        }
        _checkpoint(
            restore,
            phase="website_cleanup_pending",
            manifest=_metadata(restore).get("source_manifest") or {},
            records=[{**record, "state": progressed}],
            progress_total=int(getattr(restore, "progress_total", 1) or 1),
        )

    if staging_status != "complete":
        if not _cleanup_remote_stage(
            node,
            backup,
            restore,
            auth,
            username,
            password,
            ssh_key_path,
            host_url,
            parallel,
            expected,
        ):
            raise _website_restore_cleanup_error(backup)
        staging_status = "complete"

    complete = _state_for(
        record,
        "complete",
        files_status="complete",
        stage=expected,
    )
    complete["cleanup"] = {
        "previous_target": previous_status,
        "staging": staging_status,
    }
    _checkpoint(
        restore,
        phase="website_complete",
        manifest=_metadata(restore).get("source_manifest") or {},
        records=[{**record, "state": complete}],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )


def _legacy_restore_source(
    node,
    backup,
    restore,
    auth,
    record,
    website,
    host_url,
    username,
    password,
    ssh_key_path,
):
    state = _record_state(restore, record)
    if state.get("status") == "complete":
        return
    delete = bool((_metadata(restore).get("restore_params") or {}).get("delete"))
    if state.get("status") == "transferring" and delete:
        raise RestoreError(
            "website delete-mode transfer outcome is ambiguous; manual review is required."
        )
    _verify_source_manifest(record)
    files = _file_states(record, "in_progress")
    _checkpoint(
        restore,
        phase="website_transferring",
        manifest=_metadata(restore)["source_manifest"],
        records=[
            {
                **record,
                "state": _state_for(record, "transferring", files_status="in_progress"),
            }
        ],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )

    parallel = website.parallel or 3
    verbose = "--verbose=3" if website.verbose else ""
    delete_flag = "--delete" if delete else ""
    exclude_rules = [
        f"--exclude-glob={_lftp_quote(f'{backup.uuid}.files')}",
        f"--exclude-glob={_lftp_quote('backupsheep.txt')}",
    ]
    mirror_opts = (
        f"-R --continue --no-perms --no-umask --use-pget=1 "
        f"--parallel={parallel} {verbose} {delete_flag}"
    )
    source_path = record["local_path"]
    if record["type"] == "file":
        transfer = (
            f"put -P {_lftp_quote(source_path)} "
            f"-o {_lftp_quote(record['path'])}"
        )
        mirror = False
    else:
        transfer = (
            f"mirror {mirror_opts} {' '.join(exclude_rules)} "
            f"{_lftp_quote(source_path)} {_lftp_quote(record['path'])}"
        )
        mirror = True
    script = _build_lftp_script(
        auth=auth,
        host_url=host_url,
        port=auth.port,
        username=username,
        password=password,
        ssh_key_path=ssh_key_path,
        parallel=parallel,
        transfer=transfer,
        mirror=mirror,
    )
    _write_log(backup, f"Website path prepared: {record['path']}\n")
    _run_lftp(
        node,
        backup,
        restore,
        auth,
        script,
        username,
        password,
        what="website transfer",
    )
    _checkpoint(
        restore,
        phase="website_complete",
        manifest=_metadata(restore)["source_manifest"],
        records=[
            {
                **record,
                "state": _state_for(record, "complete", files_status="complete"),
            }
        ],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )


def _staged_restore_source(
    node,
    backup,
    restore,
    auth,
    record,
    website,
    host_url,
    username,
    password,
    ssh_key_path,
):
    stage = _expected_restore_stage(restore, record)
    if stage is None:
        return _legacy_restore_source(
            node,
            backup,
            restore,
            auth,
            record,
            website,
            host_url,
            username,
            password,
            ssh_key_path,
        )
    state = _record_state(restore, record)
    status = str(state.get("status") or "pending")
    if status == "complete":
        cleanup = dict(state.get("cleanup") or {})
        if cleanup.get("previous_target") == "complete" and cleanup.get(
            "staging"
        ) == "complete":
            return
        return _restore_published_source_cleanup(
            node,
            backup,
            restore,
            auth,
            record,
            website,
            host_url,
            username,
            password,
            ssh_key_path,
            stage,
            state,
        )
    if status == "cleanup_pending":
        return _restore_published_source_cleanup(
            node,
            backup,
            restore,
            auth,
            record,
            website,
            host_url,
            username,
            password,
            ssh_key_path,
            stage,
            state,
        )
    if status == "publishing":
        raise RestoreError(
            "website publish outcome is ambiguous; manual review is required."
        )
    if status not in {"pending", "staging", "staged"}:
        raise RestoreError(
            "website staging checkpoint is not safely adoptable; manual review is required."
        )
    stage_state = _state_for(
        record,
        "staged" if status == "staged" else "staging",
        files_status="staged" if status == "staged" else "staging",
        stage=stage,
    )
    if status != "staged":
        _verify_source_manifest(record)
        _checkpoint(
            restore,
            phase="website_staging",
            manifest=_metadata(restore)["source_manifest"],
            records=[{**record, "state": stage_state}],
            progress_total=int(getattr(restore, "progress_total", 1) or 1),
        )
        marker_path = _write_stage_marker(backup, restore, record)
        try:
            parallel = website.parallel or 3
            if record["type"] == "file":
                transfer = "\n".join(
                    [
                        f"mkdir -p {_lftp_quote(stage['stage_root'])}",
                        f"put -P {_lftp_quote(record['local_path'])} "
                        f"-o {_lftp_quote(stage['payload'])}",
                    ]
                )
                mirror = False
            else:
                mirror_opts = (
                    f"-R --continue --no-perms --no-umask --use-pget=1 "
                    f"--parallel={parallel}"
                )
                transfer = (
                    f"mirror {mirror_opts} "
                    f"--exclude-glob={_lftp_quote(f'{backup.uuid}.files')} "
                    f"--exclude-glob={_lftp_quote('backupsheep.txt')} "
                    f"{_lftp_quote(record['local_path'])} {_lftp_quote(stage['payload'])}"
                )
                mirror = True
            transfer += (
                f"\nput -P {_lftp_quote(marker_path)} "
                f"-o {_lftp_quote(stage['marker'])}"
            )
            script = _build_lftp_script(
                auth=auth,
                host_url=host_url,
                port=auth.port,
                username=username,
                password=password,
                ssh_key_path=ssh_key_path,
                parallel=parallel,
                transfer=transfer,
                mirror=mirror,
            )
            _write_log(backup, f"Website path staged: {record['path']}\n")
            _run_lftp(
                node,
                backup,
                restore,
                auth,
                script,
                username,
                password,
                what="stage website files",
            )
        finally:
            try:
                os.remove(marker_path)
            except OSError:
                pass
        _checkpoint(
            restore,
            phase="website_staged",
            manifest=_metadata(restore)["source_manifest"],
            records=[
                {
                    **record,
                    "state": _state_for(
                        record, "staged", files_status="staged", stage=stage
                    ),
                }
            ],
            progress_total=int(getattr(restore, "progress_total", 1) or 1),
        )

    _checkpoint(
        restore,
        phase="website_publishing",
        manifest=_metadata(restore)["source_manifest"],
        records=[
            {
                **record,
                "state": _state_for(
                    record, "publishing", files_status="staged", stage=stage
                ),
            }
        ],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )
    parallel = website.parallel or 3
    script = _publish_script(
        auth,
        host_url,
        auth.port,
        username,
        password,
        ssh_key_path,
        parallel,
        stage,
    )
    _run_lftp(
        node,
        backup,
        restore,
        auth,
        script,
        username,
        password,
        what="publish website files",
    )
    cleanup_pending = _state_for(
        record,
        "cleanup_pending",
        files_status="complete",
        stage=stage,
    )
    cleanup_pending["cleanup"] = {
        "previous_target": "pending",
        "staging": "pending",
    }
    _checkpoint(
        restore,
        phase="website_cleanup_pending",
        manifest=_metadata(restore)["source_manifest"],
        records=[{**record, "state": cleanup_pending}],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )
    _restore_published_source_cleanup(
        node,
        backup,
        restore,
        auth,
        record,
        website,
        host_url,
        username,
        password,
        ssh_key_path,
        stage,
        cleanup_pending,
    )


def restore_website(backup, restore):
    """Fetch, validate, stage, publish, and safely resume a website restore."""
    node = backup.website.node
    auth = node.connection.auth_website
    website = node.website
    encryption_key = node.connection.account.get_encryption_key()
    work_suffix = _restore_work_suffix(restore, backup)
    work_prefix = f"restore_{backup.uuid_str}"
    if _has_restore_fence(restore):
        work_prefix = f"{work_prefix}_{work_suffix}"
    local_zip = f"_storage/{work_prefix}.zip"
    local_dir = f"_storage/{work_prefix}/"
    ssh_key_path = None
    approved_known_hosts_path = None
    temporary_ssh_key = False

    _write_log(backup, "Website restore started.\n")
    _write_log(backup, f"Backup UUID: {backup.uuid}\n")
    try:
        _ensure_restore_fence(restore)
        ensure_disk_space(
            int(max(3 * (backup.size or 0), _PREFLIGHT_FLOOR)),
            what="website restore",
        )
        stored_backup = restore.storage_point
        if stored_backup is None:
            raise RestoreError(
                "the storage point this restore was created from no longer exists."
            )
        sources = _restore_sources(backup, website)
        params = dict(restore.params or {})
        metadata = _metadata(restore)
        old_params = metadata.get("restore_params")
        if old_params is not None and old_params != params:
            raise RestoreError(
                "website restore options changed; manual review is required."
            )
        metadata["restore_params"] = params
        restore.execution_metadata = metadata
        _save_restore(restore, ["execution_metadata"])

        _ensure_restore_fence(restore)
        auth.check_connection()
        if auth.protocol == CoreAuthWebsite.Protocol.SFTP:
            approved_known_hosts_path = auth.materialize_lftp_known_hosts()
        _ensure_restore_fence(restore)
        if auth.use_public_key:
            ssh_key_path = managed_private_key_path(
                account_id=auth.connection.account_id
            )
        username = bs_decrypt(auth.username, encryption_key) or ""
        password = bs_decrypt(auth.password, encryption_key) or ""

        if auth.use_private_key:
            ssh_key_path = _materialize_ssh_private_key(
                bs_decrypt(auth.private_key, encryption_key)
            )
            _normalize_ssh_key(ssh_key_path, password)
            temporary_ssh_key = True

        protocol = auth.get_protocol_display().lower()
        if auth.protocol == CoreAuthWebsite.Protocol.FTPS and auth.ftps_use_explicit_ssl:
            protocol = "ftp"
        host_url = f"{protocol}://{_lftp_url_host(auth.host)}"

        # Permission checks run before archive download and before any remote
        # website upload or publication. Root/all_paths keeps its historical
        # convergent mirror semantics and is excluded from sibling staging.
        _preflight_restore_target(
            node,
            backup,
            restore,
            auth,
            website,
            sources,
            host_url,
            username,
            password,
            ssh_key_path,
        )
        _ensure_restore_fence(restore)
        fetch_backup_zip(stored_backup, local_zip, restore=restore)
        _ensure_restore_fence(restore)
        extract_backup_zip(local_zip, local_dir)
        tree_root = maybe_extract_tar(local_dir, backup.uuid_str)
        _ensure_restore_fence(restore)

        records, manifest = _prepare_sources(tree_root, sources, backup)
        # Filename representability is checked only after the archive is
        # available and validated, but still before any target data is staged.
        # This avoids touching the target on every archive-provider retry.
        _preflight_restore_name_fidelity(
            node,
            backup,
            restore,
            auth,
            website,
            sources,
            host_url,
            username,
            password,
            ssh_key_path,
        )
        existing_states = dict(
            _metadata(restore).get("source_states") or {}
        )
        initial_records = [
            {
                **record,
                "state": existing_states.get(record["fingerprint"])
                or _state_for(
                    record,
                    "pending",
                    files_status="pending",
                    stage=_remote_stage_paths(restore, record),
                ),
            }
            for record in records
        ]
        _checkpoint(
            restore,
            phase="archive_validated",
            manifest=manifest,
            records=initial_records,
            progress_total=len(records),
        )

        for record in records:
            if _has_restore_fence(restore):
                _staged_restore_source(
                    node,
                    backup,
                    restore,
                    auth,
                    record,
                    website,
                    host_url,
                    username,
                    password,
                    ssh_key_path,
                )
            else:
                _legacy_restore_source(
                    node,
                    backup,
                    restore,
                    auth,
                    record,
                    website,
                    host_url,
                    username,
                    password,
                    ssh_key_path,
                )

        if website.incremental:
            _write_log(
                backup,
                "Restore complete. The incremental snapshot cache re-syncs automatically on the next backup.\n",
            )
        else:
            _write_log(backup, "Restore complete.\n")
    except (RestoreError, NodeBackupFailedError, RestoreLeaseLost, RestoreExecutionLeaseLostError):
        raise
    except Exception:
        _capture_safe("INTERNAL_ERROR")
        _write_log(backup, "Website restore stopped: INTERNAL_ERROR.\n")
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            getattr(backup, "attempt_no", 0),
            getattr(backup, "type", "website"),
            "The website restore could not complete. Secured diagnostics contain the detailed cause.",
        ) from None
    finally:
        # The local path includes the lease token for production deliveries;
        # stale-worker cleanup can therefore never remove a replacement's tree.
        if _has_restore_fence(restore):
            cleanup_prefixes = stale_local_restore_work_prefixes(restore, backup)
            cleanup_prefixes.append(work_prefix)
            for cleanup_prefix in dict.fromkeys(cleanup_prefixes):
                delete_from_disk.apply_async(args=[cleanup_prefix, "restore"])
        else:
            delete_from_disk.apply_async(args=[work_prefix, "both"])
        if temporary_ssh_key and ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.remove(ssh_key_path)
            except OSError:
                pass
        if approved_known_hosts_path and os.path.exists(approved_known_hosts_path):
            try:
                os.remove(approved_known_hosts_path)
            except OSError:
                pass
