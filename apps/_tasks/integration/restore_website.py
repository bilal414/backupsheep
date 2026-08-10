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
import subprocess
import tempfile

from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup.website import (
    COMMAND_TIMEOUT,
    _PREFLIGHT_FLOOR,
    _build_lftp_script,
    _lftp_quote,
    _materialize_ssh_private_key,
    _normalize_ssh_key,
)
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
    maybe_extract_tar,
)
from apps._tasks.integration.restore_lease import RestoreLeaseLost
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.console.backup.models import RestoreExecutionLeaseLostError
from apps.console.connection.models import CoreAuthWebsite
from apps.console.connection.ssh import managed_private_key_path


WEBSITE_MARKER_VERSION = "1"
WEBSITE_MARKER_NAME = ".backupsheep-restore-marker"


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
):
    """Run lftp with credentials on stdin and only safe failure details."""
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
        _capture_safe("LFTP_TIMEOUT")
        raise _safe_failure(node, backup, "LFTP_TIMEOUT") from None
    except FileNotFoundError:
        _capture_safe("LFTP_UNAVAILABLE")
        raise _safe_failure(node, backup, "LFTP_UNAVAILABLE") from None
    except OSError:
        _capture_safe("LFTP_UNAVAILABLE")
        raise _safe_failure(node, backup, "LFTP_UNAVAILABLE") from None

    # A process may have completed a remote action just before losing its
    # lease.  Do not commit the result or continue to another action then.
    _ensure_restore_fence(restore)
    output = str(proc.stdout or "")
    # lftp normally preserves a failed transfer's exit status, but some login
    # failures have historically exited zero after a trailing ``bye``. Treat only
    # explicit fatal/authentication lines as failure so warnings cannot silently
    # turn into a successful restore.
    fatal_output = re.search(
        r"(?im)(?:^|\s)(?:login failed|authentication failed|fatal error(?:\s*:|\b))",
        output,
    )
    if proc.returncode != 0 or fatal_output:
        _capture_safe("LFTP_REJECTED")
        raise _safe_failure(node, backup, "LFTP_REJECTED") from None
    return proc


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
    if website.all_paths:
        return [{"path": ".", "type": "directory"}]
    sources = []
    seen = set()
    for item in website.paths or []:
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


def _source_files(source, local_path):
    if source["type"] == "file":
        return [{"path": posixpath.basename(source["path"]), **_file_identity(local_path)}]

    entries = []
    for root, directories, files in os.walk(local_path, followlinks=False):
        for directory in directories:
            if os.path.islink(os.path.join(root, directory)):
                raise RestoreError("website restore archive contains a symbolic link.")
        for filename in files:
            path = os.path.join(root, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                raise RestoreError("website restore archive contains an unsupported file.")
            relative = os.path.relpath(path, local_path).replace(os.sep, "/")
            entries.append({"path": relative, **_file_identity(path)})
    return sorted(entries, key=lambda item: item["path"])


def _prepare_sources(tree_root, sources, backup):
    records = []
    manifest = {}
    for source in sources:
        local_path = _local_source_path(tree_root, source)
        files = _source_files(source, local_path)
        identity = {
            "backup_uuid": str(backup.uuid),
            "path": source["path"],
            "type": source["type"],
            "files": files,
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
            "source_digest": source_digest,
            "fingerprint": fingerprint,
            "source_key": source_key,
        }
        records.append(record)
        manifest[source_key] = {
            "path": source["path"],
            "type": source["type"],
            "source_digest": source_digest,
            "files": files,
        }
    return records, manifest


def _verify_source_manifest(record):
    current = _source_files(record, record["local_path"])
    if current != record["files"]:
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
        for item in record["files"]
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
        "complete": 4,
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
        for identity_field in ("path", "type", "source_digest", "target_path"):
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
        "files": _file_states(record, files_status or "pending"),
    }
    if stage:
        state.update(stage)
    return state


def _record_state(restore, record):
    return dict(
        (_metadata(restore).get("source_states") or {}).get(record["fingerprint"])
        or {}
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
        return
    try:
        _run_lftp(
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
                transfer=f"rm -r {_lftp_quote(stage['stage_root'])}",
                mirror=False,
            ),
            username,
            password,
            what="clean restore staging",
        )
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError):
        raise
    except Exception:
        _capture_safe("REMOTE_STAGE_CLEANUP_FAILED")


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
    stage = _remote_stage_paths(restore, record)
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
        return
    if status == "publishing":
        raise RestoreError(
            "website publish outcome is ambiguous; manual review is required."
        )
    if status not in {"pending", "staging", "staged"}:
        raise RestoreError(
            "website staging checkpoint is not safely adoptable; manual review is required."
        )
    stage = {**stage, "target_path": record["path"]}
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
    _checkpoint(
        restore,
        phase="website_complete",
        manifest=_metadata(restore)["source_manifest"],
        records=[
            {
                **record,
                "state": _state_for(
                    record, "complete", files_status="complete", stage=stage
                ),
            }
        ],
        progress_total=int(getattr(restore, "progress_total", 1) or 1),
    )
    # This is after the durable complete checkpoint.  The stage name is fully
    # restore/fingerprint scoped; the previous target is intentionally retained
    # for rollback and is never deleted by automatic cleanup.
    _cleanup_remote_stage(
        node,
        backup,
        restore,
        auth,
        username,
        password,
        ssh_key_path,
        host_url,
        parallel,
        stage,
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
        _ensure_restore_fence(restore)
        fetch_backup_zip(stored_backup, local_zip)
        _ensure_restore_fence(restore)
        extract_backup_zip(local_zip, local_dir)
        tree_root = maybe_extract_tar(local_dir, backup.uuid_str)
        _ensure_restore_fence(restore)

        sources = _normalise_sources(website)
        records, manifest = _prepare_sources(tree_root, sources, backup)
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

        _ensure_restore_fence(restore)
        auth.check_connection()
        _ensure_restore_fence(restore)
        if auth.use_public_key:
            ssh_key_path = managed_private_key_path()
        username = bs_decrypt(auth.username, encryption_key) or ""
        password = bs_decrypt(auth.password, encryption_key) or ""

        if auth.use_private_key:
            suffix = f"_{work_suffix}" if _has_restore_fence(restore) else ""
            ssh_key_path = f"_storage/ssh_restore_{backup.uuid_str}{suffix}"
            _materialize_ssh_private_key(
                ssh_key_path,
                bs_decrypt(auth.private_key, encryption_key),
            )
            _normalize_ssh_key(ssh_key_path, password)
            temporary_ssh_key = True

        protocol = auth.get_protocol_display().lower()
        if auth.protocol == CoreAuthWebsite.Protocol.FTPS and auth.ftps_use_explicit_ssl:
            protocol = "ftp"
        host_url = f"{protocol}://{auth.host}"

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
        delete_from_disk.apply_async(args=[work_prefix, "both"])
        if temporary_ssh_key and ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.remove(ssh_key_path)
            except OSError:
                pass
