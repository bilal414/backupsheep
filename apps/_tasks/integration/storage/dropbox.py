"""Crash-safe, integrity-verified Dropbox backup uploads.

Dropbox does not expose user-defined object metadata for ordinary app files.  The
immutable ownership marker for a BackupSheep object is therefore its exact,
deterministic path (``/<backup uuid>.zip``), combined with the verified byte
count and SHA-256 recorded in the storage point.  Uploads use ``add`` mode so a
retry can never overwrite an object already present at that path.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket

import dropbox
from django.conf import settings
from dropbox.exceptions import AuthError, HttpError
from dropbox.files import CommitInfo, UploadSessionCursor, WriteMode

try:
    import requests as _requests
except ImportError:  # pragma: no cover - requests is a Dropbox SDK dependency.
    _requests = None

from apps._tasks.exceptions import (
    NodeDropboxFileIDMissingError,
    NodeDropboxNotEnoughStorageError,
    NodeDropboxTokenExpiredError,
    NodeDropboxUploadFailedError,
    NodeSnapshotDeleteFailed,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreWebsiteBackup,
    CoreWordPressBackup,
)
from apps.console.node.models import CoreNode
from django.utils import timezone


DROPBOX_METADATA_KEY = "dropbox_object"
CHECKSUM_ALGORITHM = "sha256"
DROPBOX_BLOCK_SIZE = 4 * 1024 * 1024
# Keep each worker request comfortably bounded.  Dropbox permits much larger
# session chunks, but 140 MiB per concurrent upload causes avoidable memory
# pressure because the SDK accepts each chunk as an in-memory bytes object.
DROPBOX_DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
DROPBOX_DEFAULT_TIMEOUT = 60.0
SAFE_UPLOAD_FAILURE = (
    "Unable to upload the backup to Dropbox because the destination could not "
    "be verified. Please retry or contact an administrator."
)
SAFE_TIMEOUT_FAILURE = (
    "The Dropbox request timed out before the backup destination could be verified. "
    "Please retry."
)
SAFE_AUTH_FAILURE = (
    "Dropbox rejected the configured credentials or permissions. Please reconnect "
    "Dropbox and retry."
)
SAFE_QUOTA_FAILURE = (
    "The Dropbox account does not have enough available storage capacity."
)
SAFE_INTEGRITY_FAILURE = (
    "Dropbox returned content that did not match the local backup artifact."
)
SAFE_DUPLICATE_FAILURE = (
    "Multiple Dropbox objects match this backup; automatic reconciliation was "
    "stopped for safety."
)
SAFE_RECONCILIATION_FAILURE = (
    "Dropbox accepted an upload request but the completed destination could not "
    "yet be verified. Reconciliation is required."
)


class DropboxStorageAdapterError(RuntimeError):
    """Safe, structured internal error; never stores provider response bodies."""

    def __init__(self, code, message=SAFE_UPLOAD_FAILURE, *, retryable=False):
        self.code = str(code)[:64]
        self.retryable = bool(retryable)
        self.safe_message = str(message)
        super().__init__(self.safe_message)


class _DropboxSourceMissing(DropboxStorageAdapterError):
    def __init__(self):
        super().__init__("SOURCE_ARTIFACT_MISSING", SAFE_UPLOAD_FAILURE)


class _DropboxIntegrityError(DropboxStorageAdapterError):
    def __init__(self, message=SAFE_INTEGRITY_FAILURE):
        super().__init__("INTEGRITY_MISMATCH", message)


class _DropboxDuplicateError(DropboxStorageAdapterError):
    def __init__(self):
        super().__init__("DUPLICATE_MATCH", SAFE_DUPLICATE_FAILURE)


class _DropboxReconciliationError(DropboxStorageAdapterError):
    def __init__(self, *, retryable=True):
        super().__init__(
            "RECONCILIATION_REQUIRED",
            SAFE_RECONCILIATION_FAILURE,
            retryable=retryable,
        )


def _value(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _setting_float(name, default):
    try:
        value = float(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = float(default)
    return max(0.1, min(value, 24 * 3600.0))


def _dropbox_timeout():
    # The SDK timeout is the maximum wait for a packet.  Keeping this bounded is
    # preferable to allowing a storage worker to remain leased indefinitely.
    return _setting_float("DROPBOX_API_TIMEOUT", _setting_float("PROVIDER_HTTP_READ_TIMEOUT", DROPBOX_DEFAULT_TIMEOUT))


def _dropbox_chunk_size():
    try:
        configured = int(
            getattr(settings, "DROPBOX_UPLOAD_CHUNK_SIZE_BYTES", DROPBOX_DEFAULT_CHUNK_SIZE)
        )
    except (TypeError, ValueError):
        configured = DROPBOX_DEFAULT_CHUNK_SIZE
    # Dropbox permits a maximum of 150 MiB per upload-session request.  A small
    # lower bound also prevents a malformed setting from creating an endless loop.
    return max(1, min(configured, 150 * 1024 * 1024))


def _backup_identifier(backup):
    identifier = str(getattr(backup, "uuid_str", None) or getattr(backup, "uuid", ""))
    if (
        not identifier
        or identifier in {".", ".."}
        or "\x00" in identifier
        or "/" in identifier
        or "\\" in identifier
        or os.path.basename(identifier) != identifier
    ):
        raise _DropboxIntegrityError("The backup identifier is invalid.")
    return identifier


def _deterministic_path(identifier):
    return f"/{identifier}.zip"


def _file_identity(path):
    digest = hashlib.sha256()
    dropbox_blocks = []
    size_bytes = 0
    try:
        with open(path, "rb") as source:
            while True:
                block = source.read(DROPBOX_BLOCK_SIZE)
                if not block:
                    break
                digest.update(block)
                dropbox_blocks.append(hashlib.sha256(block).digest())
                size_bytes += len(block)
    except FileNotFoundError:
        raise _DropboxSourceMissing from None
    return {
        "sha256": digest.hexdigest(),
        "sha256_base64": base64.b64encode(digest.digest()).decode("ascii"),
        "size_bytes": size_bytes,
        # Dropbox's content hash is SHA-256 over the SHA-256 digest of each 4 MiB
        # block.  It is useful as an upload-time provider check, but is not used as
        # the BackupSheep artifact checksum (which remains ordinary SHA-256).
        "dropbox_content_hash": hashlib.sha256(b"".join(dropbox_blocks)).hexdigest(),
    }


def _expected_identity(state):
    sha256 = state.get("sha256")
    size_bytes = state.get("size_bytes")
    if not sha256 and size_bytes is None:
        return None
    if not isinstance(sha256, str) or len(sha256) != 64:
        raise _DropboxIntegrityError("The persisted backup checksum is invalid.")
    try:
        size_bytes = int(size_bytes)
    except (TypeError, ValueError):
        raise _DropboxIntegrityError("The persisted backup size is invalid.") from None
    if size_bytes < 0:
        raise _DropboxIntegrityError("The persisted backup size is invalid.")
    return {"sha256": sha256.lower(), "size_bytes": size_bytes}


def _state(stored_backup):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    state = dict(metadata.get(DROPBOX_METADATA_KEY) or {})
    return metadata, state


def _save_state(stored_backup, state, *, status=None):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    metadata[DROPBOX_METADATA_KEY] = dict(state)
    stored_backup.metadata = metadata
    if state.get("provider_id"):
        stored_backup.storage_file_id = str(state["provider_id"])
    fields = ["metadata", "modified"]
    if state.get("provider_id"):
        fields.insert(0, "storage_file_id")
    if status is not None:
        stored_backup.status = status
        fields.insert(0, "status")
    stored_backup.save(update_fields=list(dict.fromkeys(fields)))


def _status(stored_backup, name):
    return getattr(getattr(stored_backup, "Status", None), name, None)


def _safe_provider_metadata(candidate, *, path, identifier, identity):
    provider_id = _value(candidate, "id") or _value(candidate, "provider_id")
    revision = _value(candidate, "rev") or _value(candidate, "revision") or ""
    content_hash = _value(candidate, "content_hash") or ""
    return {
        "provider": "dropbox",
        "ownership_marker": f"backupsheep:{identifier}",
        "path": path,
        "provider_id": str(provider_id or ""),
        "revision": str(revision or ""),
        "version_id": str(revision or ""),
        "content_hash": str(content_hash or ""),
        "size_bytes": int(identity["size_bytes"]),
        "sha256": identity["sha256"],
    }


def _normalize_path(path):
    value = str(path or "")
    if not value.startswith("/"):
        value = f"/{value}"
    return value.rstrip("/") or "/"


def _normalize_dropbox_metadata(candidate):
    path = _value(candidate, "path_display") or _value(candidate, "path_lower") or _value(candidate, "path")
    provider_id = _value(candidate, "id") or _value(candidate, "provider_id")
    return {
        "raw": candidate,
        "path": _normalize_path(path),
        "path_lower": _normalize_path(path).lower(),
        "provider_id": str(provider_id or ""),
        "name": str(_value(candidate, "name") or ""),
        "size_bytes": _value(candidate, "size"),
        "revision": str(_value(candidate, "rev") or _value(candidate, "revision") or ""),
        "content_hash": str(_value(candidate, "content_hash") or ""),
    }


def _is_not_found(error):
    if isinstance(error, HttpError):
        return int(getattr(error, "status_code", 0) or 0) == 404
    inner = getattr(error, "error", None)
    for predicate_name in ("is_path", "is_lookup", "is_download"):
        predicate = getattr(inner, predicate_name, None)
        if not callable(predicate):
            continue
        try:
            union = predicate()
        except Exception:
            continue
        for not_found_name in ("is_not_found", "is_lookup", "is_path"):
            not_found = getattr(union, not_found_name, None)
            if callable(not_found):
                try:
                    if bool(not_found()):
                        return True
                except Exception:
                    pass
    return type(error).__name__ in {"NotFoundError", "PathNotFoundError"}


def _correct_session_offset(error):
    """Extract Dropbox's explicit correct offset without inspecting raw error text."""
    inner = getattr(error, "error", None)
    for predicate_name in ("is_incorrect_offset", "is_upload_session_offset"):
        predicate = getattr(inner, predicate_name, None)
        if not callable(predicate):
            continue
        try:
            union = predicate()
        except Exception:
            continue
        for getter_name in ("get_incorrect_offset", "get_upload_session_offset"):
            getter = getattr(union, getter_name, None)
            if callable(getter):
                try:
                    value = getter()
                except Exception:
                    continue
                if isinstance(value, int):
                    return value
    return None


def _provider_error(error):
    if isinstance(error, AuthError):
        return DropboxStorageAdapterError("AUTH_FAILED", SAFE_AUTH_FAILURE)
    if isinstance(error, HttpError):
        status_code = int(getattr(error, "status_code", 0) or 0)
        if status_code == 401 or status_code == 403:
            return DropboxStorageAdapterError("AUTH_FAILED", SAFE_AUTH_FAILURE)
        if status_code == 507:
            return DropboxStorageAdapterError("QUOTA_EXCEEDED", SAFE_QUOTA_FAILURE)
        if status_code == 429:
            return DropboxStorageAdapterError(
                "RATE_LIMITED",
                "Dropbox rate-limited the request; processing will resume later.",
                retryable=True,
            )
        if status_code >= 500 or status_code in {408, 425}:
            return DropboxStorageAdapterError(
                "TRANSIENT_OUTAGE",
                "Dropbox is temporarily unavailable; processing will resume later.",
                retryable=True,
            )
    timeout_types = (TimeoutError, socket.timeout)
    if _requests is not None:
        timeout_types = timeout_types + (_requests.exceptions.Timeout,)
    if isinstance(error, timeout_types):
        return DropboxStorageAdapterError("TIMEOUT", SAFE_TIMEOUT_FAILURE, retryable=True)
    if isinstance(error, DropboxStorageAdapterError):
        return error
    return DropboxStorageAdapterError("PROVIDER_REQUEST_FAILED", SAFE_UPLOAD_FAILURE)


def _candidate_key(candidate):
    normalized = _normalize_dropbox_metadata(candidate)
    if normalized["provider_id"]:
        return ("id", normalized["provider_id"])
    return ("path", normalized["path_lower"])


def _append_unique(candidates, candidate):
    key = _candidate_key(candidate)
    if not any(_candidate_key(existing) == key for existing in candidates):
        candidates.append(candidate)


def _dropbox_candidates(dbx, path):
    """Find only objects carrying this backup's deterministic path marker."""
    expected_path = _normalize_path(path)
    filename = os.path.basename(expected_path)
    candidates = []
    try:
        exact = dbx.files_get_metadata(expected_path)
    except Exception as error:
        if not _is_not_found(error):
            raise
        exact = None
    if exact is not None:
        _append_unique(candidates, exact)

    # Dropbox paths are unique, but listing the parent catches malformed mocks,
    # legacy autorename uploads, and provider responses that disagree about the
    # path.  Any such ambiguity is handled fail-closed by _reconcile.
    list_folder = getattr(dbx, "files_list_folder", None)
    if not callable(list_folder):
        return candidates
    parent = os.path.dirname(expected_path) or ""
    # Dropbox represents the root folder with an empty path, not a slash.
    if parent == "/":
        parent = ""
    seen_cursors = set()
    try:
        page = list_folder(parent, recursive=False)
        while True:
            entries = _value(page, "entries", []) or []
            if isinstance(page, dict):
                entries = page.get("entries") or []
            for entry in entries:
                normalized = _normalize_dropbox_metadata(entry)
                name = normalized["name"]
                # A renamed UUID object is evidence of a prior collision.  It is
                # intentionally included so the retry fails closed instead of
                # silently creating a second object.
                stem = filename[:-4] if filename.endswith(".zip") else filename
                is_uuid_variant = name.startswith(f"{stem} (") and name.endswith(".zip")
                if normalized["path_lower"] == expected_path.lower() or name == filename or is_uuid_variant:
                    _append_unique(candidates, entry)
            has_more = bool(_value(page, "has_more", False))
            if isinstance(page, dict):
                has_more = bool(page.get("has_more"))
            if not has_more:
                break
            cursor = _value(page, "cursor")
            if isinstance(page, dict):
                cursor = page.get("cursor")
            if not cursor:
                raise _DropboxReconciliationError(retryable=False)
            if cursor in seen_cursors:
                raise _DropboxReconciliationError(retryable=False)
            seen_cursors.add(cursor)
            continue_page = getattr(dbx, "files_list_folder_continue", None)
            if not callable(continue_page):
                raise _DropboxReconciliationError(retryable=False)
            page = continue_page(cursor)
    except Exception as error:
        if _is_not_found(error):
            return candidates
        raise
    return candidates


def _remote_identity(dbx, candidate, identity, expected_path):
    normalized = _normalize_dropbox_metadata(candidate)
    if normalized["path_lower"] != _normalize_path(expected_path).lower():
        raise _DropboxIntegrityError("The Dropbox object path is not this backup's deterministic destination.")
    if not normalized["provider_id"]:
        raise DropboxStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    try:
        remote_metadata, response = dbx.files_download(normalized["provider_id"] or normalized["path"])
    except Exception as error:
        raise _provider_error(error) from None

    remote_normalized = _normalize_dropbox_metadata(remote_metadata)
    if remote_normalized["provider_id"] and remote_normalized["provider_id"] != normalized["provider_id"]:
        raise _DropboxIntegrityError()
    if remote_normalized["path"] != normalized["path"]:
        raise _DropboxIntegrityError()

    digest = hashlib.sha256()
    size_bytes = 0
    try:
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            chunks = iterator(chunk_size=1024 * 1024)
        else:
            read = getattr(response, "read", None)
            if callable(read):
                def _read_chunks():
                    while True:
                        chunk = read(1024 * 1024)
                        if not chunk:
                            break
                        yield chunk
                chunks = _read_chunks()
            else:
                content = getattr(response, "content", b"")
                chunks = (content,)
        for chunk in chunks:
            if not chunk:
                continue
            digest.update(chunk)
            size_bytes += len(chunk)
    except Exception as error:
        raise _provider_error(error) from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    if size_bytes != int(identity["size_bytes"]) or digest.hexdigest() != identity["sha256"]:
        raise _DropboxIntegrityError()
    remote_normalized["size_bytes"] = size_bytes
    remote_normalized["sha256"] = digest.hexdigest()
    return remote_normalized


def _reconcile(dbx, path, identity):
    candidates = _dropbox_candidates(dbx, path)
    if len(candidates) > 1:
        raise _DropboxDuplicateError()
    if not candidates:
        return None
    return _remote_identity(dbx, candidates[0], identity, path)


def _record_destination_artifact(stored_backup, state, identity):
    recorder = getattr(stored_backup.backup, "record_artifact_integrity", None)
    if not callable(recorder):
        raise DropboxStorageAdapterError("ARTIFACT_RECORD_MISSING", SAFE_UPLOAD_FAILURE)
    recorder(
        role="destination",
        # The durable artifact key is the same immutable provider ID stored on
        # the storage-point row. The human-readable path remains provider state,
        # never an alternate restore selector.
        object_key=state["provider_id"],
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm=CHECKSUM_ALGORITHM,
        checksum_value=identity["sha256"],
        etag=state.get("content_hash", ""),
        version_id=state.get("version_id", ""),
        verified_at=timezone.now(),
        metadata={
            "storage_metadata_key": DROPBOX_METADATA_KEY,
            "provider": "dropbox",
            "ownership_marker": state.get("ownership_marker", ""),
            "provider_id": state.get("provider_id", ""),
            "revision": state.get("revision", ""),
        },
    )


def _finalize(stored_backup, state, remote, identity, identifier):
    state.update(
        {
            "phase": "committed",
            "path": remote["path"],
            "provider_id": remote["provider_id"],
            "revision": remote.get("revision", ""),
            "version_id": remote.get("revision", ""),
            "content_hash": remote.get("content_hash", ""),
            "size_bytes": int(identity["size_bytes"]),
            "sha256": identity["sha256"],
            "checksum_algorithm": CHECKSUM_ALGORITHM,
            "ownership_marker": f"backupsheep:{identifier}",
        }
    )
    state.pop("session", None)
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
    # The artifact is durable evidence and must exist before the visible terminal
    # storage status.  record_artifact_integrity is idempotent for this object key.
    _record_destination_artifact(stored_backup, state, identity)
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_COMPLETE"))


def _upload_small(dbx, path, local_zip, identity, state, stored_backup):
    state["phase"] = "uploading"
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
    try:
        with open(local_zip, "rb") as source:
            dbx.files_upload(
                source.read(),
                path,
                mode=WriteMode.add,
                autorename=False,
                strict_conflict=True,
                content_hash=identity["dropbox_content_hash"],
            )
    except Exception as error:
        # The request may have reached Dropbox before the worker observed the
        # failure.  A verified exact-path object is adopted; no second upload is
        # issued in that case.
        remote = _reconcile(dbx, path, identity)
        if remote is not None:
            return remote
        raise _provider_error(error) from None
    remote = _reconcile(dbx, path, identity)
    if remote is None:
        raise _DropboxReconciliationError()
    return remote


def _upload_session(dbx, path, local_zip, identity, state, stored_backup):
    chunk_size = _dropbox_chunk_size()
    session = dict(state.get("session") or {})
    session_id = session.get("session_id")
    try:
        with open(local_zip, "rb") as source:
            if session_id:
                try:
                    offset = int(session.get("offset", 0))
                except (TypeError, ValueError):
                    raise _DropboxIntegrityError("The persisted Dropbox session offset is invalid.") from None
                if offset < 0 or offset > identity["size_bytes"]:
                    raise _DropboxIntegrityError("The persisted Dropbox session offset is invalid.")
            else:
                first = source.read(min(chunk_size, identity["size_bytes"]))
                try:
                    result = dbx.files_upload_session_start(first)
                except Exception as error:
                    remote = _reconcile(dbx, path, identity)
                    if remote is not None:
                        return remote
                    raise _provider_error(error) from None
                session_id = str(_value(result, "session_id") or "")
                if not session_id:
                    raise DropboxStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
                offset = len(first)
                session = {"session_id": session_id, "offset": offset, "chunk_size": chunk_size}
                state.update({"phase": "uploading", "session": session})
                _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))

            while offset < identity["size_bytes"]:
                remaining = identity["size_bytes"] - offset
                body_size = min(chunk_size, remaining)
                source.seek(offset)
                body = source.read(body_size)
                if len(body) != body_size:
                    raise _DropboxSourceMissing()
                cursor = UploadSessionCursor(session_id, offset=offset)
                if remaining <= chunk_size:
                    commit = CommitInfo(
                        path=path,
                        mode=WriteMode.add,
                        autorename=False,
                        strict_conflict=True,
                    )
                    try:
                        dbx.files_upload_session_finish(body, cursor, commit)
                    except Exception as error:
                        remote = _reconcile(dbx, path, identity)
                        if remote is not None:
                            return remote
                        raise _provider_error(error) from None
                    offset += body_size
                    session["offset"] = offset
                    state["session"] = session
                    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
                    break
                try:
                    dbx.files_upload_session_append_v2(body, cursor)
                except Exception as error:
                    correct_offset = _correct_session_offset(error)
                    if correct_offset is not None and 0 <= correct_offset <= identity["size_bytes"]:
                        offset = correct_offset
                        session["offset"] = offset
                        state["session"] = session
                        _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
                        continue
                    remote = _reconcile(dbx, path, identity)
                    if remote is not None:
                        return remote
                    raise _provider_error(error) from None
                offset += body_size
                session["offset"] = offset
                state["session"] = session
                _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
            if identity["size_bytes"] == 0:
                # This branch is normally handled by the small uploader, but it
                # keeps the session helper total for test/configuration overrides.
                commit = CommitInfo(path=path, mode=WriteMode.add, autorename=False, strict_conflict=True)
                dbx.files_upload_session_finish(b"", UploadSessionCursor(session_id, offset=0), commit)
    except _DropboxSourceMissing:
        raise
    except DropboxStorageAdapterError:
        raise
    except Exception as error:
        remote = _reconcile(dbx, path, identity)
        if remote is not None:
            return remote
        raise _provider_error(error) from None

    remote = _reconcile(dbx, path, identity)
    if remote is None:
        raise _DropboxReconciliationError()
    return remote


def storage_dropbox(stored_backup):
    """Upload one backup, adopting a verified Dropbox object on every retry."""
    try:
        backup = stored_backup.backup
        identifier = _backup_identifier(backup)
        local_zip = os.path.join("_storage", f"{identifier}.zip")
        path = _deterministic_path(identifier)
        metadata, state = _state(stored_backup)
        persisted_identity = _expected_identity(state)
        identity = persisted_identity
        state.update(
            {
                "provider": "dropbox",
                "path": state.get("path") or path,
                "ownership_marker": f"backupsheep:{identifier}",
            }
        )
        path = state["path"]
        if _normalize_path(path).lower() != _normalize_path(_deterministic_path(identifier)).lower():
            raise _DropboxIntegrityError("The persisted Dropbox path is not this backup's deterministic destination.")
        if identity is None:
            identity = _file_identity(local_zip)
            state.update(
                {
                    "sha256": identity["sha256"],
                    "size_bytes": identity["size_bytes"],
                    "checksum_algorithm": CHECKSUM_ALGORITHM,
                    "dropbox_content_hash": identity["dropbox_content_hash"],
                }
            )
        elif not state.get("dropbox_content_hash") and os.path.exists(local_zip):
            # The source checksum is durable; recomputing the Dropbox block hash is
            # optional on an adoption-only retry, but is useful before a new upload.
            source_identity = _file_identity(local_zip)
            if source_identity["sha256"] != identity["sha256"] or source_identity["size_bytes"] != identity["size_bytes"]:
                raise _DropboxIntegrityError("The local backup changed after upload state was persisted.")
            identity = {**identity, "dropbox_content_hash": source_identity["dropbox_content_hash"]}
            state["dropbox_content_hash"] = source_identity["dropbox_content_hash"]
        _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))

        dbx = dropbox.Dropbox(
            oauth2_access_token=bs_decrypt(
                stored_backup.storage.storage_dropbox.access_token,
                stored_backup.storage.account.get_encryption_key(),
            ),
            oauth2_refresh_token=bs_decrypt(
                stored_backup.storage.storage_dropbox.refresh_token,
                stored_backup.storage.account.get_encryption_key(),
            ),
            app_key=settings.DROPBOX_APP_KEY,
            app_secret=settings.DROPBOX_APP_SECRET,
            timeout=_dropbox_timeout(),
            # Task-level reconciliation owns retries.  A Dropbox SDK replay
            # after a lost upload response could otherwise create a second
            # session or repeat a non-idempotent commit.
            max_retries_on_error=0,
            max_retries_on_rate_limit=0,
            auto_content_hash=True,
        )

        remote = _reconcile(dbx, path, identity)
        if remote is None:
            threshold = _dropbox_chunk_size()
            if identity["size_bytes"] <= threshold:
                remote = _upload_small(dbx, path, local_zip, identity, state, stored_backup)
            else:
                remote = _upload_session(dbx, path, local_zip, identity, state, stored_backup)
        _finalize(stored_backup, state, remote, identity, identifier)
    except _DropboxSourceMissing:
        try:
            stored_backup.status = _status(stored_backup, "UPLOAD_FAILED_FILE_NOT_FOUND")
            stored_backup.save(update_fields=["status", "modified"])
        except Exception:
            raise StorageDropboxSafeError(stored_backup, "SOURCE_ARTIFACT_MISSING") from None
    except StorageDropboxSafeError:
        raise
    except Exception as error:
        safe_error = _provider_error(error)
        raise _public_error(stored_backup, safe_error) from None


class StorageDropboxSafeError(NodeDropboxUploadFailedError):
    """Public Dropbox error carrying a safe machine-readable adapter code."""

    def __init__(self, stored_backup, code, message=SAFE_UPLOAD_FAILURE, *, retryable=False):
        super().__init__(
            getattr(stored_backup.backup, "uuid_str", None),
            getattr(stored_backup.backup, "attempt_no", None),
            getattr(stored_backup.backup, "type", None),
            message,
        )
        self.error_code = str(code)[:64]
        self.retryable = bool(retryable)


def _public_error(stored_backup, error):
    code = getattr(error, "code", "PROVIDER_REQUEST_FAILED")
    message = getattr(error, "safe_message", SAFE_UPLOAD_FAILURE)
    retryable = bool(getattr(error, "retryable", False))
    if code == "AUTH_FAILED":
        public = NodeDropboxTokenExpiredError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            SAFE_AUTH_FAILURE,
        )
    elif code == "QUOTA_EXCEEDED":
        public = NodeDropboxNotEnoughStorageError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            SAFE_QUOTA_FAILURE,
        )
    elif code == "MALFORMED_RESPONSE":
        public = NodeDropboxFileIDMissingError(
            stored_backup.backup.uuid_str,
            stored_backup.backup.attempt_no,
            stored_backup.backup.type,
            SAFE_UPLOAD_FAILURE,
        )
    else:
        public = StorageDropboxSafeError(
            stored_backup,
            code,
            message,
            retryable=retryable,
        )
    public.error_code = str(code)[:64]
    public.retryable = retryable
    return public


def storage_dropbox_delete(node, backup_name):
    try:
        backup = None
        encryption_key = node.connection.account.get_encryption_key()

        if node.type == CoreNode.Type.WEBSITE:
            backup = CoreWebsiteBackup.objects.get(uuid=backup_name)
        elif node.type == CoreNode.Type.DATABASE:
            backup = CoreDatabaseBackup.objects.get(uuid=backup_name)
        elif node.type == CoreNode.Type.SAAS:
            backup = CoreWordPressBackup.objects.get(uuid=backup_name)

        if backup:
            dbx = dropbox.Dropbox(
                oauth2_access_token=bs_decrypt(
                    backup.storage_byo.storage_dropbox.access_token, encryption_key
                ),
                oauth2_refresh_token=bs_decrypt(
                    backup.storage_byo.storage_dropbox.refresh_token, encryption_key
                ),
                app_key=settings.DROPBOX_APP_KEY,
                app_secret=settings.DROPBOX_APP_SECRET,
                timeout=_dropbox_timeout(),
                max_retries_on_error=0,
                max_retries_on_rate_limit=0,
            )

            file_path = dbx.files_get_metadata(backup.storage_file_id).path_lower

            dbx.files_delete_v2(file_path)
    except Exception:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
