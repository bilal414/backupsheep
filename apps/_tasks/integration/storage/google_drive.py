"""Crash-safe Google Drive backup uploads.

Google Drive resumable sessions are opaque and cannot be listed.  The adapter
therefore creates (or adopts) one provider-owned placeholder first and attaches
every resumable session to that file ID.  A lost session response can create a
new session, but it can never create a second Drive file for the backup.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from urllib.parse import quote

from django.utils import timezone
from requests import exceptions as requests_exceptions
from sentry_sdk import capture_exception

from apps._tasks.exceptions import (
    NodeGoogleDriveNotEnoughStorageError,
    NodeGoogleDriveTooManyRequestsError,
    NodeGoogleDriveUploadFailedError,
    NodeSnapshotDeleteFailed,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.api.v1.utils.http import request_timeout
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadReconciliationRequired,
)
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreWebsiteBackup,
)


DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3"
FOLDER_MIME = "application/vnd.google-apps.folder"
ZIP_MIME = "application/zip"
STATE_KEY = "google_drive_upload"
NAMESPACE = "backupsheep-v1"
CHUNK_SIZE = 40 * 256 * 1024  # Google requires resumable chunks in 256 KiB units.
SAFE_FAILURE = "Google Drive could not verify the backup upload. Please retry."
SAFE_TIMEOUT = "Google Drive did not respond before the request deadline. Please retry."
SAFE_AUTH = "Google Drive rejected the configured credentials or permissions."
SAFE_QUOTA = "Google Drive does not have enough available storage capacity."
SAFE_RATE = "Google Drive rate limited the upload; it will resume automatically."
SAFE_RECONCILIATION = (
    "Google Drive returned ambiguous upload state; automatic writes were stopped safely."
)
SAFE_INTEGRITY = "Google Drive returned bytes that do not match the backup artifact."
SAFE_OWNERSHIP = "Google Drive ownership verification failed; no provider object was changed."
SAFE_DELETE_RECONCILIATION = (
    "Google Drive deletion has an ambiguous provider outcome; manual reconciliation is required."
)
SAFE_DELETE_NOT_FOUND = (
    "Google Drive backup object was not found before a deletion request was recorded."
)
DELETE_STATE_KEY = "delete"


class GoogleDriveUploadFailure(NodeGoogleDriveUploadFailedError):
    """Structured, deliberately redacted provider failure."""

    def __init__(self, code="PROVIDER_FAILURE", *, status_code=None, retryable=True, message=None):
        self.code = str(code)
        self.provider_status = int(status_code) if status_code is not None else None
        self.retryable = bool(retryable)
        super().__init__(message=message or SAFE_FAILURE)


class GoogleDriveQuotaFailure(NodeGoogleDriveNotEnoughStorageError):
    def __init__(self, *, status_code=None):
        self.code = "STORAGE_QUOTA_EXCEEDED"
        self.provider_status = int(status_code) if status_code is not None else None
        self.retryable = False
        super().__init__(message=SAFE_QUOTA)


class GoogleDriveRateLimitFailure(NodeGoogleDriveTooManyRequestsError):
    def __init__(self, *, status_code=None):
        self.code = "STORAGE_RATE_LIMITED"
        self.provider_status = int(status_code) if status_code is not None else None
        self.retryable = True
        super().__init__(message=SAFE_RATE)


class GoogleDriveReconciliationRequired(
    GoogleDriveUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self, message=SAFE_RECONCILIATION):
        super().__init__(
            "STORAGE_RECONCILIATION_REQUIRED",
            retryable=False,
            message=message,
        )


class GoogleDriveIntegrityFailure(GoogleDriveUploadFailure, S3ObjectIntegrityError):
    def __init__(self, message=SAFE_INTEGRITY):
        super().__init__("STORAGE_INTEGRITY_FAILED", retryable=False, message=message)


class GoogleDriveOwnershipFailure(
    GoogleDriveUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self):
        super().__init__(
            "PROVIDER_OWNERSHIP_MISMATCH",
            retryable=False,
            message=SAFE_OWNERSHIP,
        )


class GoogleDriveDeleteReconciliationRequired(RuntimeError):
    """A persisted Google Drive delete request must be reconciled manually."""

    code = "STORAGE_DELETE_RECONCILIATION_REQUIRED"

    def __init__(self, message=SAFE_DELETE_RECONCILIATION):
        self.message = message
        super().__init__(message)


class GoogleDriveDeleteNotFound(RuntimeError):
    """The exact owned object was absent before any delete request was sent."""

    code = "PROVIDER_NOT_FOUND"

    def __init__(self, message=SAFE_DELETE_NOT_FOUND):
        self.message = message
        super().__init__(message)


class _SourceArtifactInvalid(GoogleDriveUploadFailure, S3ObjectIntegrityError):
    def __init__(self):
        super().__init__(
            "SOURCE_ARTIFACT_INVALID",
            retryable=False,
            message="The committed local backup artifact failed integrity validation.",
        )


def _backup_uuid(stored_backup):
    backup = stored_backup.backup
    value = str(getattr(backup, "uuid_str", None) or getattr(backup, "uuid", ""))
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise GoogleDriveUploadFailure("INVALID_BACKUP_ID", retryable=False)
    return value


def _safe_node_slug(stored_backup):
    value = str(getattr(stored_backup.backup.node, "name_slug", "") or "")
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise GoogleDriveUploadFailure("INVALID_PROVIDER_PATH", retryable=False)
    return value


def _committed_source_identity(stored_backup):
    relation = getattr(stored_backup.backup, "artifact_records", None)
    if relation is None:
        raise _SourceArtifactInvalid()
    try:
        artifact = relation.filter(
            role="source",
            storage__isnull=True,
            verified_at__isnull=False,
        ).order_by("-verified_at").first()
    except Exception:
        raise _SourceArtifactInvalid()
    if artifact is None:
        raise _SourceArtifactInvalid()
    checksum = str(getattr(artifact, "checksum_value", "")).lower()
    byte_count = int(getattr(artifact, "byte_count", -1))
    if (
        str(getattr(artifact, "checksum_algorithm", "")).lower() != "sha256"
        or len(checksum) != 64
        or byte_count < 0
    ):
        raise _SourceArtifactInvalid()
    return {
        "sha256": checksum,
        "size_bytes": byte_count,
        "checksum_algorithm": "sha256",
    }


def _source_identity(stored_backup, local_path):
    """Verify the local source when present against the durable source artifact.

    A completed provider object can still be adopted after the worker has cleaned
    up the temporary ZIP.  In that case the durable artifact remains the source of
    truth and the provider bytes are streamed and checked before completion.
    """
    expected = _committed_source_identity(stored_backup)
    try:
        source_file = open(local_path, "rb")
    except FileNotFoundError:
        return expected
    digest = hashlib.sha256()
    byte_count = 0
    with source_file:
        while True:
            chunk = source_file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
    if digest.hexdigest() != expected["sha256"] or byte_count != expected["size_bytes"]:
        raise _SourceArtifactInvalid()
    return expected


def _escape_query(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _timeout():
    return request_timeout()


def _json(response):
    try:
        payload = response.json()
    except Exception:
        raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    if not isinstance(payload, dict):
        raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    return payload


def _error_reason(response):
    """Read only a bounded provider error code; never retain the response body."""
    try:
        payload = response.json()
    except Exception:
        return ""
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return ""
    errors = error.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        return str(errors[0].get("reason") or "")[:80].lower()
    return str(error.get("status") or error.get("code") or "")[:80].lower()


def _raise_response(response, operation, allowed=(200,)):
    status = int(getattr(response, "status_code", 0) or 0)
    if status in allowed:
        return
    reason = _error_reason(response)
    if status == 403 and "quota" in reason:
        raise GoogleDriveQuotaFailure(status_code=status)
    if status == 403 and any(
        value in reason
        for value in ("ratelimit", "userlimit", "rate_limit", "too_many")
    ):
        raise GoogleDriveRateLimitFailure(status_code=status)
    if status == 429:
        raise GoogleDriveRateLimitFailure(status_code=status)
    if status in {401, 403}:
        raise GoogleDriveUploadFailure(
            "STORAGE_AUTH_FAILED", status_code=status, retryable=False, message=SAFE_AUTH
        )
    if status in {408, 425} or status >= 500 or status == 0:
        raise GoogleDriveUploadFailure(
            "PROVIDER_TRANSIENT_FAILURE", status_code=status, retryable=True
        )
    if status == 404:
        raise GoogleDriveUploadFailure(
            "PROVIDER_NOT_FOUND", status_code=status, retryable=True
        )
    raise GoogleDriveUploadFailure(
        "PROVIDER_REQUEST_FAILED", status_code=status, retryable=False
    )


def _call(client, method, url, **kwargs):
    kwargs.setdefault("timeout", _timeout())
    try:
        response = getattr(client, method)(url, **kwargs)
    except (requests_exceptions.Timeout, TimeoutError):
        raise GoogleDriveUploadFailure("PROVIDER_TIMEOUT", retryable=True, message=SAFE_TIMEOUT)
    except requests_exceptions.RequestException:
        raise GoogleDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)
    except OSError:
        raise GoogleDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)
    return response


def _list_files(client, query, fields):
    files = []
    page_token = None
    while True:
        params = {"q": query, "fields": f"nextPageToken,files({fields})", "pageSize": 1000}
        if page_token:
            params["pageToken"] = page_token
        response = _call(client, "get", f"{DRIVE_API}/files", params=params)
        _raise_response(response, "list")
        payload = _json(response)
        page_files = payload.get("files") or []
        if not isinstance(page_files, list):
            raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
        files.extend(item for item in page_files if isinstance(item, dict))
        next_token = payload.get("nextPageToken")
        if not next_token:
            return files
        if next_token == page_token:
            raise GoogleDriveReconciliationRequired()
        page_token = str(next_token)


def _file_fields():
    return "id,name,mimeType,parents,trashed,size,md5Checksum,version,headRevisionId,appProperties"


def _get_file(client, file_id):
    response = _call(
        client,
        "get",
        f"{DRIVE_API}/files/{quote(str(file_id), safe='')}",
        params={"fields": _file_fields()},
    )
    if int(getattr(response, "status_code", 0) or 0) == 404:
        return None
    _raise_response(response, "get file")
    payload = _json(response)
    payload["_response_etag"] = str((getattr(response, "headers", {}) or {}).get("ETag") or "")
    return payload


def _marker_values(backup_uuid, identity, *, role, node_slug=None):
    values = {
        "backupsheep_namespace": NAMESPACE,
        "backupsheep_role": role,
        "backupsheep_backup_uuid": backup_uuid,
        "backupsheep_sha256": identity["sha256"],
        "backupsheep_bytes": str(identity["size_bytes"]),
    }
    if node_slug is not None:
        values["backupsheep_node_slug"] = node_slug
    return values


def _properties(item):
    return {str(key): str(value) for key, value in (item.get("appProperties") or {}).items()}


def _validate_owned(item, *, name, parent_id, markers, mime_type=None):
    if not isinstance(item, dict) or not item.get("id"):
        raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    if item.get("trashed") is True or item.get("name") != name:
        raise GoogleDriveOwnershipFailure()
    if mime_type and item.get("mimeType") != mime_type:
        raise GoogleDriveOwnershipFailure()
    parents = {str(parent) for parent in item.get("parents") or []}
    if parent_id and str(parent_id) not in parents:
        raise GoogleDriveOwnershipFailure()
    actual = _properties(item)
    if any(actual.get(key) != str(value) for key, value in markers.items()):
        raise GoogleDriveOwnershipFailure()
    return item


def _find_owned_or_collision(client, *, name, parent_id, markers, mime_type):
    parent_clause = f"'{_escape_query(parent_id)}' in parents"
    base = (
        f"name = '{_escape_query(name)}' and {parent_clause} and trashed = false "
        f"and mimeType = '{_escape_query(mime_type)}'"
    )
    marker_query = base + (
        " and appProperties has { key='backupsheep_namespace' "
        f"and value='{_escape_query(NAMESPACE)}' }}"
    )
    owned = _list_files(client, marker_query, _file_fields())
    if len(owned) > 1:
        raise GoogleDriveReconciliationRequired()
    if owned:
        return _validate_owned(
            owned[0], name=name, parent_id=parent_id, markers=markers, mime_type=mime_type
        )
    collisions = _list_files(client, base, _file_fields())
    if collisions:
        # A same-name object without our marker is never safe to overwrite or
        # adopt, even though Drive would otherwise permit another same-name item.
        raise GoogleDriveOwnershipFailure()
    return None


def _create_file(client, metadata):
    response = _call(
        client,
        "post",
        f"{DRIVE_API}/files",
        data=json.dumps(metadata, separators=(",", ":")),
        headers={"Content-Type": "application/json; charset=UTF-8"},
    )
    _raise_response(response, "create file", allowed=(200, 201))
    payload = _json(response)
    if not payload.get("id"):
        raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    return payload


def _ensure_folder(client, *, name, parent_id, markers):
    folder = _find_owned_or_collision(
        client,
        name=name,
        parent_id=parent_id,
        markers=markers,
        mime_type=FOLDER_MIME,
    )
    if folder:
        return folder["id"]
    metadata = {"name": name, "mimeType": FOLDER_MIME, "appProperties": markers}
    if parent_id != "root":
        metadata["parents"] = [parent_id]
    return _create_file(client, metadata)["id"]


def _seal_session(storage, session_url):
    try:
        key = storage.account.get_encryption_key()
        encrypted = bs_encrypt(session_url, key)
    except Exception:
        encrypted = None
    if not encrypted:
        raise GoogleDriveUploadFailure("SESSION_STATE_UNAVAILABLE", retryable=False)
    return {
        "url_encrypted": base64.b64encode(bytes(encrypted)).decode("ascii"),
        "fingerprint": hashlib.sha256(session_url.encode("utf-8")).hexdigest(),
    }


def _unseal_session(storage, session):
    if not isinstance(session, dict):
        return None
    encoded = session.get("url_encrypted")
    fingerprint = str(session.get("fingerprint") or "")
    if not encoded or len(fingerprint) != 64:
        return None
    try:
        key = storage.account.get_encryption_key()
        value = bs_decrypt(base64.b64decode(encoded), key)
    except Exception:
        return None
    if not value or hashlib.sha256(value.encode("utf-8")).hexdigest() != fingerprint:
        return None
    return value


def _save_state(stored_backup, state, *, status=None, storage_file_id=None):
    metadata = dict(stored_backup.metadata or {})
    metadata[STATE_KEY] = dict(state)
    stored_backup.metadata = metadata
    if storage_file_id is not None:
        stored_backup.storage_file_id = str(storage_file_id)
    if status is not None:
        stored_backup.status = status
    stored_backup.save()


def _google_drive_delete_state(stored_backup):
    upload_state = dict((stored_backup.metadata or {}).get(STATE_KEY) or {})
    value = upload_state.get(DELETE_STATE_KEY)
    return upload_state, dict(value or {}) if isinstance(value, dict) else {}


def _google_drive_delete_context(stored_backup, upload_state):
    """Build the immutable application/provider identity for one delete."""
    expected = stored_backup.committed_integrity_identity()
    backup_uuid = _backup_uuid(stored_backup)
    node_slug = _safe_node_slug(stored_backup)
    backup = stored_backup.backup
    node = backup.node
    storage = stored_backup.storage
    account_id = getattr(storage, "account_id", None)
    node_account_id = getattr(getattr(node, "connection", None), "account_id", None)
    provider_id = str(upload_state.get("provider_id") or "")
    parent_id = str(upload_state.get("parent_id") or "")
    version_id = str(upload_state.get("version_id") or "")
    if (
        str(upload_state.get("phase") or "") != "committed"
        or not provider_id
        or provider_id != str(stored_backup.storage_file_id or "")
        or expected is None
        or not parent_id
        or not version_id
        or account_id is None
        or node_account_id is None
        or str(account_id) != str(node_account_id)
    ):
        raise GoogleDriveOwnershipFailure()
    return {
        "schema": 1,
        "provider": "google_drive",
        "account_id": str(account_id),
        "node_id": str(node.pk),
        "backup_id": str(backup.pk),
        "backup_uuid": backup_uuid,
        "storage_id": str(storage.pk),
        "provider_id": provider_id,
        "parent_id": parent_id,
        "name": f"{backup_uuid}.zip",
        "mime_type": ZIP_MIME,
        "version_id": version_id,
        "revision": str(upload_state.get("revision") or ""),
        "size_bytes": int(expected["size_bytes"]),
        "sha256": str(expected["sha256"]).lower(),
        "node_slug": node_slug,
        "markers": _marker_values(
            backup_uuid,
            expected,
            role="backup",
            node_slug=node_slug,
        ),
    }


def _google_drive_witness_digest(witness):
    encoded = json.dumps(witness, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _validate_google_drive_delete_witness(stored_backup, upload_state, delete_state):
    witness = delete_state.get("witness")
    digest = str(delete_state.get("witness_sha256") or "")
    if not isinstance(witness, dict) or not digest:
        raise GoogleDriveDeleteReconciliationRequired()
    if _google_drive_witness_digest(witness) != digest:
        raise GoogleDriveDeleteReconciliationRequired()
    current = _google_drive_delete_context(stored_backup, upload_state)
    if current != witness:
        raise GoogleDriveDeleteReconciliationRequired()
    return witness


def _validate_google_drive_delete_remote(item, witness):
    _validate_owned(
        item,
        name=witness["name"],
        parent_id=witness["parent_id"],
        markers=witness["markers"],
        mime_type=witness["mime_type"],
    )
    try:
        remote_size = int(item.get("size"))
    except (AttributeError, TypeError, ValueError):
        raise GoogleDriveOwnershipFailure()
    if (
        str(item.get("id") or "") != witness["provider_id"]
        or remote_size != witness["size_bytes"]
        or str(item.get("version") or "") != witness["version_id"]
        or (
            witness["revision"]
            and str(item.get("headRevisionId") or "") != witness["revision"]
        )
    ):
        raise GoogleDriveOwnershipFailure()
    return item


def _save_google_drive_delete_state(
    stored_backup,
    upload_state,
    delete_state,
    *,
    error_code=None,
    error_message=None,
):
    metadata = dict(stored_backup.metadata or {})
    persisted_upload_state = dict(upload_state)
    persisted_upload_state[DELETE_STATE_KEY] = dict(delete_state)
    metadata[STATE_KEY] = persisted_upload_state
    stored_backup.metadata = metadata
    if error_code is not None:
        stored_backup.last_error_code = str(error_code)
    if error_message is not None:
        stored_backup.last_error_message = str(error_message)
    stored_backup.save()


def _mark_google_drive_delete_ambiguous(
    stored_backup, upload_state, delete_state, *, error_code="PROVIDER_TRANSIENT_FAILURE"
):
    state = dict(delete_state)
    state["phase"] = "ambiguous"
    state["ambiguous_at"] = timezone.now().isoformat()
    _save_google_drive_delete_state(
        stored_backup,
        upload_state,
        state,
        error_code=GoogleDriveDeleteReconciliationRequired.code,
        error_message=SAFE_DELETE_RECONCILIATION,
    )
    return state


def _mark_google_drive_delete_complete(stored_backup, upload_state, delete_state):
    state = dict(delete_state)
    state["phase"] = "complete"
    state["completed_at"] = timezone.now().isoformat()
    _save_google_drive_delete_state(
        stored_backup,
        upload_state,
        state,
        error_code="",
        error_message="",
    )
    return state


def delete_google_drive_storage_point(stored_backup):
    """Delete one exact Drive object with a durable, single-mutation protocol.

    The ownership witness is committed before the first DELETE.  Once that
    checkpoint exists, a later worker may only observe the exact object, adopt a
    confirmed 404 as completion, or stop for reconciliation; it never sends a
    second DELETE for the same ambiguous request.
    """
    upload_state, delete_state = _google_drive_delete_state(stored_backup)
    phase = str(delete_state.get("phase") or "")
    if delete_state:
        witness = _validate_google_drive_delete_witness(
            stored_backup, upload_state, delete_state
        )
        if phase == "complete":
            return True
        client = stored_backup.storage.storage_google_drive.get_client()
        try:
            remote = _get_file(client, witness["provider_id"])
        except Exception as error:
            _mark_google_drive_delete_ambiguous(
                stored_backup,
                upload_state,
                delete_state,
                error_code=getattr(error, "code", "PROVIDER_TRANSIENT_FAILURE"),
            )
            raise GoogleDriveDeleteReconciliationRequired() from error
        if remote is None:
            _mark_google_drive_delete_complete(
                stored_backup, upload_state, delete_state
            )
            return True
        try:
            _validate_google_drive_delete_remote(remote, witness)
        except Exception as error:
            _mark_google_drive_delete_ambiguous(
                stored_backup,
                upload_state,
                delete_state,
                error_code=getattr(error, "code", "PROVIDER_OWNERSHIP_MISMATCH"),
            )
            raise GoogleDriveDeleteReconciliationRequired() from error
        _mark_google_drive_delete_ambiguous(
            stored_backup,
            upload_state,
            delete_state,
            error_code="PROVIDER_DELETE_OUTCOME_UNKNOWN",
        )
        raise GoogleDriveDeleteReconciliationRequired()

    witness = _google_drive_delete_context(stored_backup, upload_state)
    client = stored_backup.storage.storage_google_drive.get_client()
    try:
        remote = _get_file(client, witness["provider_id"])
    except Exception:
        raise
    if remote is None:
        stored_backup.last_error_code = GoogleDriveDeleteNotFound.code
        stored_backup.last_error_message = SAFE_DELETE_NOT_FOUND
        stored_backup.save()
        raise GoogleDriveDeleteNotFound()
    _validate_google_drive_delete_remote(remote, witness)

    delete_state = {
        "schema": 1,
        "phase": "delete_requested",
        "witness": witness,
        "witness_sha256": _google_drive_witness_digest(witness),
        "requested_at": timezone.now().isoformat(),
    }
    # This save is the mutation fence: no provider DELETE occurs before the
    # exact tenant/node/backup/storage-point/version identity is durable.
    _save_google_drive_delete_state(
        stored_backup,
        upload_state,
        delete_state,
        error_code="",
        error_message="",
    )
    try:
        response = _call(
            client,
            "delete",
            f"{DRIVE_API}/files/{quote(witness['provider_id'], safe='')}",
        )
    except Exception as error:
        _mark_google_drive_delete_ambiguous(
            stored_backup,
            upload_state,
            delete_state,
            error_code=getattr(error, "code", "PROVIDER_TRANSIENT_FAILURE"),
        )
        raise GoogleDriveDeleteReconciliationRequired() from error
    if int(getattr(response, "status_code", 0) or 0) == 404:
        _mark_google_drive_delete_complete(stored_backup, upload_state, delete_state)
        return True
    try:
        _raise_response(response, "delete Google Drive file", allowed=(200, 204))
    except Exception as error:
        _mark_google_drive_delete_ambiguous(
            stored_backup,
            upload_state,
            delete_state,
            error_code=getattr(error, "code", "PROVIDER_REQUEST_FAILED"),
        )
        raise GoogleDriveDeleteReconciliationRequired() from error
    _mark_google_drive_delete_complete(stored_backup, upload_state, delete_state)
    return True


def _restart_session(stored_backup, state, file_id):
    try:
        count = int(state.get("session_restart_count") or 0) + 1
    except (TypeError, ValueError):
        raise GoogleDriveReconciliationRequired()
    if count > 5:
        raise GoogleDriveReconciliationRequired()
    state["session_restart_count"] = count
    state.pop("session", None)
    state.pop("next_offset", None)
    _save_state(stored_backup, state, storage_file_id=file_id)


def _session_status(client, session_url, total_bytes):
    response = _call(
        client,
        "put",
        session_url,
        data=b"",
        headers={
            "Content-Length": "0",
            "Content-Range": f"bytes */{total_bytes}",
        },
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if status in {200, 201}:
        return "complete", _json(response)
    if status == 404:
        return "expired", None
    if status != 308:
        _raise_response(response, "query upload session")
    value = str((getattr(response, "headers", {}) or {}).get("Range") or "")
    if not value:
        return 0, None
    match = re.fullmatch(r"bytes=0-(\d+)", value)
    if not match:
        raise GoogleDriveReconciliationRequired()
    offset = int(match.group(1)) + 1
    if offset < 0 or offset > int(total_bytes):
        raise GoogleDriveReconciliationRequired()
    return offset, None


def _iter_response_bytes(response):
    iterator = getattr(response, "iter_content", None)
    if callable(iterator):
        for chunk in iterator(chunk_size=1024 * 1024):
            if chunk:
                yield chunk
        return
    content = getattr(response, "content", b"")
    if content:
        yield content


def _remote_identity(client, file_id, expected):
    response = _call(
        client,
        "get",
        f"{DRIVE_API}/files/{quote(str(file_id), safe='')}?alt=media",
        headers={"Accept": "application/octet-stream"},
        stream=True,
    )
    _raise_response(response, "download for verification", allowed=(200,))
    digest = hashlib.sha256()
    size = 0
    for chunk in _iter_response_bytes(response):
        digest.update(chunk)
        size += len(chunk)
    actual = {"sha256": digest.hexdigest(), "size_bytes": size}
    if actual != {"sha256": expected["sha256"], "size_bytes": expected["size_bytes"]}:
        raise GoogleDriveIntegrityFailure()
    return actual


def _verify_and_commit(
    stored_backup,
    client,
    item,
    identity,
    *,
    provider_path,
    parent_id,
    session,
):
    backup_uuid = _backup_uuid(stored_backup)
    node_slug = _safe_node_slug(stored_backup)
    markers = _marker_values(backup_uuid, identity, role="backup", node_slug=node_slug)
    _validate_owned(
        item,
        name=f"{backup_uuid}.zip",
        parent_id=parent_id,
        markers=markers,
        mime_type=ZIP_MIME,
    )
    _remote_identity(client, item["id"], identity)
    metadata = dict(stored_backup.metadata or {})
    state = dict(metadata.get(STATE_KEY) or {})
    state.update(
        {
            "schema": 1,
            "provider": "google_drive",
            "phase": "committed",
            "object_key": str(item["id"]),
            "provider_id": str(item["id"]),
            "provider_path": provider_path,
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": "sha256",
            "md5_checksum": item.get("md5Checksum"),
            "etag": str(item.get("etag") or item.get("_response_etag") or ""),
            "version_id": str(item.get("version") or ""),
            "revision": str(item.get("headRevisionId") or ""),
            "parent_id": str((item.get("parents") or [""])[0]),
            "session_fingerprint": (session or {}).get("fingerprint"),
        }
    )
    state.pop("session", None)
    state.pop("next_offset", None)
    _save_state(
        stored_backup,
        state,
        status=stored_backup.Status.UPLOAD_VALIDATION,
        storage_file_id=item["id"],
    )
    stored_backup.backup.record_artifact_integrity(
        role="destination",
        object_key=str(item["id"]),
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm="sha256",
        checksum_value=identity["sha256"],
        etag=state.get("etag") or "",
        version_id=state.get("version_id") or "",
        multipart_upload_id=(session or {}).get("fingerprint") or "",
        verified_at=timezone.now(),
        metadata={
            "provider": "google_drive",
            "provider_id": str(item["id"]),
            "provider_path": provider_path,
            "revision": state.get("revision") or "",
            "md5_checksum": item.get("md5Checksum"),
            "storage_metadata_key": STATE_KEY,
        },
    )
    _save_state(stored_backup, state, status=stored_backup.Status.UPLOAD_COMPLETE, storage_file_id=item["id"])
    return state


def _upload_resumable(stored_backup, client, file_id, identity, state):
    storage = stored_backup.storage
    local_zip = f"_storage/{_backup_uuid(stored_backup)}.zip"
    session = state.get("session")
    session_url = _unseal_session(storage, session)
    if not session_url:
        response = _call(
            client,
            "patch",
            f"{DRIVE_UPLOAD_API}/files/{quote(str(file_id), safe='')}?uploadType=resumable",
            data=json.dumps(
                {"name": f"{_backup_uuid(stored_backup)}.zip", "mimeType": ZIP_MIME},
                separators=(",", ":"),
            ),
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "X-Upload-Content-Type": ZIP_MIME,
                "X-Upload-Content-Length": str(identity["size_bytes"]),
            },
        )
        _raise_response(response, "create resumable session", allowed=(200, 201))
        session_url = str((getattr(response, "headers", {}) or {}).get("Location") or "")
        if not session_url.startswith("https://"):
            raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
        state["session"] = _seal_session(storage, session_url)
        state["phase"] = "session_created"
        state["next_offset"] = 0
        _save_state(stored_backup, state, storage_file_id=file_id)

    offset_result, completed_item = _session_status(client, session_url, identity["size_bytes"])
    if offset_result == "expired":
        existing = _get_file(client, file_id)
        if existing and int(existing.get("size") or 0) == identity["size_bytes"]:
            return existing
        _restart_session(stored_backup, state, file_id)
        return _upload_resumable(stored_backup, client, file_id, identity, state)
    if offset_result == "complete":
        return completed_item
    offset = int(offset_result)
    state["phase"] = "uploading"
    state["next_offset"] = offset
    state["uploaded_bytes"] = offset
    _save_state(stored_backup, state, storage_file_id=file_id)

    with open(local_zip, "rb") as source:
        while offset < identity["size_bytes"]:
            source.seek(offset)
            chunk = source.read(min(CHUNK_SIZE, identity["size_bytes"] - offset))
            if not chunk:
                raise GoogleDriveIntegrityFailure()
            end = offset + len(chunk) - 1
            try:
                response = _call(
                    client,
                    "put",
                    session_url,
                    data=chunk,
                    headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{end}/{identity['size_bytes']}",
                    },
                )
            except GoogleDriveUploadFailure as error:
                # A timeout after the provider accepted a chunk is resolved by a
                # status probe, not by sending the same bytes blindly.
                if not error.retryable:
                    raise
                status_result, completed_item = _session_status(
                    client, session_url, identity["size_bytes"]
                )
                if status_result == "complete":
                    return completed_item
                if status_result == "expired":
                    _restart_session(stored_backup, state, file_id)
                    return _upload_resumable(stored_backup, client, file_id, identity, state)
                offset = int(status_result)
                state["next_offset"] = offset
                state["uploaded_bytes"] = offset
                _save_state(stored_backup, state, storage_file_id=file_id)
                continue
            status = int(getattr(response, "status_code", 0) or 0)
            if status in {200, 201}:
                return _json(response)
            if status == 308:
                range_value = str((getattr(response, "headers", {}) or {}).get("Range") or "")
                match = re.fullmatch(r"bytes=0-(\d+)", range_value)
                if not match:
                    status_result, completed_item = _session_status(
                        client, session_url, identity["size_bytes"]
                    )
                    if status_result in {"expired", "complete"}:
                        if status_result == "complete":
                            return completed_item
                        _restart_session(stored_backup, state, file_id)
                        return _upload_resumable(stored_backup, client, file_id, identity, state)
                    next_offset = int(status_result)
                else:
                    next_offset = int(match.group(1)) + 1
                if next_offset <= offset or next_offset > identity["size_bytes"]:
                    raise GoogleDriveReconciliationRequired()
                offset = next_offset
                state["next_offset"] = offset
                state["uploaded_bytes"] = offset
                _save_state(stored_backup, state, storage_file_id=file_id)
                continue
            if status == 404:
                existing = _get_file(client, file_id)
                if existing and int(existing.get("size") or 0) == identity["size_bytes"]:
                    return existing
                _restart_session(stored_backup, state, file_id)
                return _upload_resumable(stored_backup, client, file_id, identity, state)
            _raise_response(response, "upload chunk")
    raise GoogleDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)


def storage_google_drive(stored_backup):
    """Upload one verified archive, adopting a single owned Drive file on retry."""
    local_zip = f"_storage/{_backup_uuid(stored_backup)}.zip"
    try:
        identity = _source_identity(stored_backup, local_zip)
        backup_uuid = _backup_uuid(stored_backup)
        node_slug = _safe_node_slug(stored_backup)
        storage = stored_backup.storage
        client = storage.storage_google_drive.get_client()
        root_id = _ensure_folder(
            client,
            name="BackupSheep",
            parent_id="root",
            markers={"backupsheep_namespace": NAMESPACE, "backupsheep_role": "root"},
        )
        node_id = _ensure_folder(
            client,
            name=node_slug,
            parent_id=root_id,
            markers={
                "backupsheep_namespace": NAMESPACE,
                "backupsheep_role": "node",
                "backupsheep_node_slug": node_slug,
            },
        )
        provider_path = f"BackupSheep/{node_slug}/{backup_uuid}.zip"
        markers = _marker_values(backup_uuid, identity, role="backup", node_slug=node_slug)
        metadata = dict(stored_backup.metadata or {})
        state = dict(metadata.get(STATE_KEY) or {})
        state.update(
            {
                "schema": 1,
                "provider": "google_drive",
                "phase": state.get("phase") or "preparing",
                "provider_path": provider_path,
                "root_folder_id": root_id,
                "node_folder_id": node_id,
                "parent_id": node_id,
                "sha256": identity["sha256"],
                "size_bytes": identity["size_bytes"],
                "checksum_algorithm": "sha256",
            }
        )
        _save_state(stored_backup, state)
        item = None
        provider_id = state.get("provider_id") or stored_backup.storage_file_id
        if provider_id:
            item = _get_file(client, provider_id)
            if item:
                _validate_owned(
                    item,
                    name=f"{backup_uuid}.zip",
                    parent_id=node_id,
                    markers=markers,
                    mime_type=ZIP_MIME,
                )
        if item is None:
            item = _find_owned_or_collision(
                client,
                name=f"{backup_uuid}.zip",
                parent_id=node_id,
                markers=markers,
                mime_type=ZIP_MIME,
            )
        if item:
            provider_id = item["id"]
            state["provider_id"] = str(provider_id)
            state["object_key"] = str(provider_id)
            _save_state(stored_backup, state, storage_file_id=provider_id)
            # A completed object is adopted only after streaming its provider
            # bytes.  A zero-byte placeholder continues through the session.
            if int(item.get("size") or 0) == identity["size_bytes"]:
                return _verify_and_commit(
                    stored_backup,
                    client,
                    item,
                    identity,
                    provider_path=provider_path,
                    parent_id=node_id,
                    session=state.get("session"),
                )
        else:
            if not os.path.isfile(local_zip):
                raise FileNotFoundError(local_zip)
            item = _create_file(
                client,
                {
                    "name": f"{backup_uuid}.zip",
                    "mimeType": ZIP_MIME,
                    "parents": [node_id],
                    "appProperties": markers,
                },
            )
            provider_id = item["id"]
            state["provider_id"] = str(provider_id)
            state["object_key"] = str(provider_id)
            state["phase"] = "placeholder_created"
            _save_state(stored_backup, state, storage_file_id=provider_id)
        _upload_resumable(stored_backup, client, provider_id, identity, state)
        # The resumable response can be partial or lost.  Re-read the
        # authoritative Drive resource before accepting ownership or completion.
        final_item = _get_file(client, provider_id)
        if not final_item:
            raise GoogleDriveReconciliationRequired()
        return _verify_and_commit(
            stored_backup,
            client,
            final_item,
            identity,
            provider_path=provider_path,
            parent_id=node_id,
            session=state.get("session"),
        )
    except FileNotFoundError:
        try:
            stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
            stored_backup.save()
        except Exception as error:
            capture_exception(error)
        return None
    except (GoogleDriveUploadFailure, GoogleDriveQuotaFailure, GoogleDriveRateLimitFailure):
        raise
    except (requests_exceptions.Timeout, TimeoutError):
        raise GoogleDriveUploadFailure("PROVIDER_TIMEOUT", retryable=True, message=SAFE_TIMEOUT)
    except Exception:
        # Provider SDK/request/DB details are intentionally not included in the
        # worker exception.  The task layer records the structured safe outcome.
        raise GoogleDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)


def storage_google_drive_delete(node, backup_name):
    """Compatibility entry point scoped to one node, account, and storage point."""
    node_id = getattr(node, "pk", None)
    account_id = getattr(getattr(node, "connection", None), "account_id", None)
    if node_id is None or account_id is None:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )

    candidates = []
    for backup_model, owner_relation, storage_relation in (
        (CoreWebsiteBackup, "website", "stored_website_backups"),
        (CoreDatabaseBackup, "database", "stored_database_backups"),
    ):
        backup = (
            backup_model.objects.filter(
                uuid=backup_name,
                **{
                    f"{owner_relation}__node_id": node_id,
                    f"{owner_relation}__node__connection__account_id": account_id,
                },
            )
            .first()
        )
        if backup is None:
            continue
        candidates.extend(
            getattr(backup, storage_relation)
            .filter(
                storage__account_id=account_id,
                storage__type__code="google_drive",
            )
        )

    if len(candidates) != 1:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        )
    try:
        return candidates[0].soft_delete()
    except Exception as error:
        raise NodeSnapshotDeleteFailed(
            node, backup_name, message="Unable to delete backup."
        ) from error
