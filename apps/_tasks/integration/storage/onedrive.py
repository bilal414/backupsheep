"""Crash-safe Microsoft Graph/OneDrive backup uploads."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from urllib.parse import quote

from django.conf import settings
from django.utils import timezone
from requests import exceptions as requests_exceptions
from sentry_sdk import capture_exception

from apps._tasks.artifact_encryption import (
    storage_artifact_identity,
    validate_storage_object_key,
)
from apps._tasks.exceptions import NodeOneDriveUploadFailedError
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.api.v1.utils.http import request_timeout, requests
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadReconciliationRequired,
)
from apps.console.backup.models import CoreBackupArtifact


STATE_KEY = "onedrive_upload"
CHUNK_SIZE = 32 * 320 * 1024  # 10 MiB, a multiple of Graph's 320 KiB unit.
SAFE_FAILURE = "OneDrive could not verify the backup upload. Please retry."
SAFE_TIMEOUT = "OneDrive did not respond before the request deadline. Please retry."
SAFE_AUTH = "OneDrive rejected the configured credentials or permissions."
SAFE_RATE = "OneDrive rate limited the upload; it will resume automatically."
SAFE_RECONCILIATION = (
    "OneDrive returned ambiguous upload state; automatic writes were stopped safely."
)
SAFE_INTEGRITY = "OneDrive returned bytes that do not match the backup artifact."
SAFE_OWNERSHIP = "OneDrive ownership verification failed; no provider object was changed."


class OneDriveUploadFailure(NodeOneDriveUploadFailedError):
    """Structured provider error whose public message never contains provider data."""

    def __init__(self, code="PROVIDER_FAILURE", *, status_code=None, retryable=True, retry_after=None, message=None):
        self.code = str(code)
        self.provider_status = int(status_code) if status_code is not None else None
        self.retryable = bool(retryable)
        self.retry_after = int(retry_after) if retry_after is not None else None
        super().__init__(message=message or SAFE_FAILURE)


class OneDriveReconciliationRequired(
    OneDriveUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self, message=SAFE_RECONCILIATION):
        super().__init__("STORAGE_RECONCILIATION_REQUIRED", retryable=False, message=message)


class OneDriveIntegrityFailure(OneDriveUploadFailure, S3ObjectIntegrityError):
    def __init__(self, message=SAFE_INTEGRITY):
        super().__init__("STORAGE_INTEGRITY_FAILED", retryable=False, message=message)


class OneDriveOwnershipFailure(
    OneDriveUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self):
        super().__init__("PROVIDER_OWNERSHIP_MISMATCH", retryable=False, message=SAFE_OWNERSHIP)


class _SourceArtifactInvalid(OneDriveUploadFailure, S3ObjectIntegrityError):
    def __init__(self):
        super().__init__(
            "SOURCE_ARTIFACT_INVALID",
            retryable=False,
            message="The committed local backup artifact failed integrity validation.",
        )


def _node_slug(stored_backup):
    value = str(getattr(stored_backup.backup.node, "name_slug", "") or "")
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise OneDriveUploadFailure("INVALID_PROVIDER_PATH", retryable=False)
    return value


def _committed_source_identity(stored_backup):
    try:
        relation = getattr(stored_backup.backup, "artifact_records", None)
    except Exception:
        relation = None
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
    return {"sha256": checksum, "size_bytes": byte_count, "checksum_algorithm": "sha256"}


def _source_identity(stored_backup, local_path):
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


def _timeout():
    return request_timeout()


def _json(response):
    try:
        payload = response.json()
    except Exception:
        raise OneDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    if not isinstance(payload, dict):
        raise OneDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    return payload


def _retry_after(response):
    value = str((getattr(response, "headers", {}) or {}).get("Retry-After") or "")
    try:
        return max(1, min(int(value), 86400))
    except (TypeError, ValueError):
        return None


def _request(method, url, **kwargs):
    kwargs.setdefault("timeout", _timeout())
    try:
        return getattr(requests, method)(url, **kwargs)
    except (requests_exceptions.Timeout, TimeoutError):
        raise OneDriveUploadFailure("PROVIDER_TIMEOUT", retryable=True, message=SAFE_TIMEOUT)
    except requests_exceptions.RequestException:
        raise OneDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)
    except OSError:
        raise OneDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)


def _raise_response(response, operation, allowed=(200,), *, not_found_ok=False):
    status = int(getattr(response, "status_code", 0) or 0)
    if status in allowed:
        return
    if not_found_ok and status == 404:
        return
    if status == 429:
        raise OneDriveUploadFailure(
            "STORAGE_RATE_LIMITED",
            status_code=status,
            retryable=True,
            retry_after=_retry_after(response),
            message=SAFE_RATE,
        )
    if status in {401, 403}:
        raise OneDriveUploadFailure(
            "STORAGE_AUTH_FAILED", status_code=status, retryable=False, message=SAFE_AUTH
        )
    if status in {408, 425} or status >= 500 or status == 0:
        raise OneDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", status_code=status, retryable=True)
    if status == 404:
        raise OneDriveUploadFailure("PROVIDER_NOT_FOUND", status_code=status, retryable=True)
    if status == 409:
        raise OneDriveOwnershipFailure()
    raise OneDriveUploadFailure("PROVIDER_REQUEST_FAILED", status_code=status, retryable=False)


def _graph_path(storage, target_path):
    drive_id = quote(str(storage.storage_onedrive.drive_id), safe="")
    encoded_path = "/".join(quote(part, safe="") for part in target_path.split("/"))
    endpoint = str(settings.MS_GRAPH_ENDPOINT).rstrip("/")
    return f"{endpoint}/drives/{drive_id}/root:/{encoded_path}"


def _client_headers(storage):
    headers = dict(storage.storage_onedrive.get_client() or {})
    headers.setdefault("Content-Type", "application/json")
    return headers


def _marker(artifact_identity, identity):
    if not hasattr(artifact_identity, "artifact_format"):
        owner = f"backup uuid={artifact_identity}"
    elif artifact_identity.artifact_format == CoreBackupArtifact.Format.BSE1:
        owner = f"artifact={artifact_identity.ownership_marker}"
    else:
        owner = f"backup uuid={artifact_identity.identifier}"
    return f"BackupSheep {owner};sha256={identity['sha256']};bytes={identity['size_bytes']}"


def _validate_item(item, *, target_path, marker, allow_missing_marker=False):
    if not isinstance(item, dict) or not item.get("id"):
        raise OneDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    if item.get("name") != target_path.rsplit("/", 1)[-1]:
        raise OneDriveOwnershipFailure()
    description = item.get("description")
    if description not in (None, "", marker):
        raise OneDriveOwnershipFailure()
    if description in (None, "") and not allow_missing_marker:
        raise OneDriveOwnershipFailure()
    if isinstance(item.get("folder"), dict):
        raise OneDriveOwnershipFailure()
    parent = item.get("parentReference") or {}
    if not isinstance(parent, dict):
        raise OneDriveOwnershipFailure()
    return item


def _graph_item_id(storage, provider_id):
    drive_id = quote(str(storage.storage_onedrive.drive_id), safe="")
    item_id = quote(str(provider_id), safe="")
    endpoint = str(settings.MS_GRAPH_ENDPOINT).rstrip("/")
    return f"{endpoint}/drives/{drive_id}/items/{item_id}"


def _get_item(storage, target_path, marker, *, allow_missing_marker=False):
    response = _request(
        "get",
        _graph_path(storage, target_path),
        params={"$select": "id,name,size,description,eTag,cTag,lastModifiedDateTime,parentReference,file"},
        headers=_client_headers(storage),
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if status == 404:
        return None
    _raise_response(response, "get OneDrive item")
    payload = _json(response)
    # A mocked/list-style response is treated as a reconciliation result.  The
    # real path endpoint returns one item, but this protects future search-based
    # adapters from silently choosing the first duplicate.
    if isinstance(payload.get("value"), list):
        matches = [item for item in payload["value"] if isinstance(item, dict)]
        if len(matches) > 1:
            raise OneDriveReconciliationRequired()
        return (
            _validate_item(
                matches[0],
                target_path=target_path,
                marker=marker,
                allow_missing_marker=allow_missing_marker,
            )
            if matches
            else None
        )
    return _validate_item(
        payload,
        target_path=target_path,
        marker=marker,
        allow_missing_marker=allow_missing_marker,
    )


def _get_item_by_id(
    storage, provider_id, target_path, marker, *, allow_missing_marker=False
):
    response = _request(
        "get",
        _graph_item_id(storage, provider_id),
        params={
            "$select": (
                "id,name,size,description,eTag,cTag,lastModifiedDateTime,"
                "parentReference,file"
            )
        },
        headers=_client_headers(storage),
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if status == 404:
        return None
    _raise_response(response, "get OneDrive item by id")
    return _validate_item(
        _json(response),
        target_path=target_path,
        marker=marker,
        allow_missing_marker=allow_missing_marker,
    )


def _seal_session(storage, session_url):
    try:
        encrypted = bs_encrypt(session_url, storage.account.get_encryption_key())
    except Exception:
        encrypted = None
    if not encrypted:
        raise OneDriveUploadFailure("SESSION_STATE_UNAVAILABLE", retryable=False)
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
        value = bs_decrypt(
            base64.b64decode(encoded), storage.account.get_encryption_key()
        )
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


def _restart_session(stored_backup, state, target_path):
    try:
        count = int(state.get("session_restart_count") or 0) + 1
    except (TypeError, ValueError):
        raise OneDriveReconciliationRequired()
    if count > 5:
        raise OneDriveReconciliationRequired()
    state["session_restart_count"] = count
    state.pop("session", None)
    state.pop("next_expected_ranges", None)
    state.pop("next_offset", None)
    _save_state(stored_backup, state, storage_file_id=target_path)


def _ranges(payload):
    raw = payload.get("nextExpectedRanges")
    if not isinstance(raw, list) or not raw:
        raise OneDriveReconciliationRequired()
    parsed = []
    for value in raw:
        match = re.fullmatch(r"(\d+)(?:-(\d*))?", str(value))
        if not match:
            raise OneDriveReconciliationRequired()
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else None
        if end is not None and end < start:
            raise OneDriveReconciliationRequired()
        parsed.append((start, end))
    parsed.sort()
    return parsed


def _session_status(session_url, total_bytes):
    # Graph explicitly documents that the upload URL is used without the bearer
    # token.  Persisted state is encrypted, and no auth header is sent here.
    response = _request("get", session_url, headers={})
    status = int(getattr(response, "status_code", 0) or 0)
    if status == 404:
        return "expired", None, []
    _raise_response(response, "query OneDrive upload session", allowed=(200, 202))
    payload = _json(response)
    if payload.get("id") and not payload.get("nextExpectedRanges"):
        return "complete", payload, []
    ranges = _ranges(payload)
    if ranges[0][0] > total_bytes:
        raise OneDriveReconciliationRequired()
    return ranges[0][0], None, ranges


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


def _remote_identity(storage, target_path, expected, marker):
    response = _request(
        "get",
        _graph_path(storage, target_path) + ":/content",
        headers={"Accept": "application/octet-stream", **_client_headers(storage)},
        stream=True,
    )
    _raise_response(response, "download OneDrive item for verification", allowed=(200,))
    digest = hashlib.sha256()
    size = 0
    for chunk in _iter_response_bytes(response):
        digest.update(chunk)
        size += len(chunk)
    if {"sha256": digest.hexdigest(), "size_bytes": size} != {
        "sha256": expected["sha256"],
        "size_bytes": expected["size_bytes"],
    }:
        raise OneDriveIntegrityFailure()
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _verify_and_commit(stored_backup, storage, item, identity, *, target_path, marker, session):
    persisted = dict((stored_backup.metadata or {}).get(STATE_KEY) or {})
    session_fingerprint = (
        (session or {}).get("fingerprint")
        if isinstance(session, dict)
        else str(persisted.get("session_fingerprint") or "")
    )
    session_proof = session or session_fingerprint
    item = _validate_item(
        item,
        target_path=target_path,
        marker=marker,
        allow_missing_marker=bool(session_proof),
    )
    _remote_identity(storage, target_path, identity, marker)
    state = dict((stored_backup.metadata or {}).get(STATE_KEY) or {})
    etag = str(item.get("eTag") or "")
    revision = str(item.get("cTag") or "")
    state.update(
        {
            "schema": 1,
            "provider": "onedrive",
            "phase": "committed",
            "object_key": target_path,
            "provider_path": target_path,
            "provider_id": str(item["id"]),
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": "sha256",
            "etag": etag,
            "version_id": revision,
            "revision": revision,
            "last_modified": str(item.get("lastModifiedDateTime") or ""),
            "session_fingerprint": session_fingerprint,
            "ownership_proof": (
                "marker_and_session"
                if item.get("description") == marker
                else "session_and_verified_content"
            ),
        }
    )
    state.pop("session", None)
    state.pop("next_expected_ranges", None)
    state.pop("next_offset", None)
    _save_state(
        stored_backup,
        state,
        status=stored_backup.Status.UPLOAD_VALIDATION,
        storage_file_id=target_path,
    )
    stored_backup.backup.record_artifact_integrity(
        role="destination",
        object_key=target_path,
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm="sha256",
        checksum_value=identity["sha256"],
        etag=etag,
        version_id=revision,
        multipart_upload_id=session_fingerprint,
        verified_at=timezone.now(),
        metadata={
            "provider": "onedrive",
            "provider_id": str(item["id"]),
            "provider_path": target_path,
            "revision": revision,
            "storage_metadata_key": STATE_KEY,
        },
    )
    _save_state(
        stored_backup,
        state,
        status=stored_backup.Status.UPLOAD_COMPLETE,
        storage_file_id=target_path,
    )
    return state


def _create_session(stored_backup, storage, target_path, identity, marker, state):
    response = _request(
        "post",
        _graph_path(storage, target_path) + ":/createUploadSession",
        headers=_client_headers(storage),
        data=json.dumps(
            {
                "item": {
                    "@microsoft.graph.conflictBehavior": "fail",
                    "description": marker,
                }
            },
            separators=(",", ":"),
        ),
    )
    _raise_response(response, "create OneDrive upload session", allowed=(200, 201))
    payload = _json(response)
    session_url = str(payload.get("uploadUrl") or "")
    if not session_url.startswith("https://"):
        raise OneDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)
    state["session"] = _seal_session(storage, session_url)
    state["phase"] = "session_created"
    state["next_offset"] = 0
    state["next_expected_ranges"] = ["0-"]
    _save_state(stored_backup, state, storage_file_id=target_path)
    return session_url


def _upload_session(
    stored_backup,
    storage,
    target_path,
    identity,
    marker,
    state,
    artifact_identity,
):
    local_artifact = f"_storage/{artifact_identity.filename}"
    session_url = _unseal_session(storage, state.get("session"))
    if not session_url:
        session_url = _create_session(stored_backup, storage, target_path, identity, marker, state)

    status_result, completed_item, ranges = _session_status(session_url, identity["size_bytes"])
    if status_result == "expired":
        _restart_session(stored_backup, state, target_path)
        return _upload_session(
            stored_backup,
            storage,
            target_path,
            identity,
            marker,
            state,
            artifact_identity,
        )
    if status_result == "complete":
        return completed_item
    offset = int(status_result)
    state.update(
        {
            "phase": "uploading",
            "next_offset": offset,
            "uploaded_bytes": offset,
            "next_expected_ranges": [
                f"{start}-{end if end is not None else ''}" for start, end in ranges
            ],
        }
    )
    _save_state(stored_backup, state, storage_file_id=target_path)

    with open(local_artifact, "rb") as source:
        while offset < identity["size_bytes"]:
            # The first missing range may be bounded.  Never send bytes outside
            # that range, and never infer acceptance from a timed-out request.
            range_end = None
            for start, end in ranges:
                if start == offset:
                    range_end = end
                    break
            limit = min(
                identity["size_bytes"],
                offset + CHUNK_SIZE,
                (range_end + 1) if range_end is not None else identity["size_bytes"],
            )
            source.seek(offset)
            chunk = source.read(limit - offset)
            if not chunk:
                raise OneDriveIntegrityFailure()
            end = offset + len(chunk) - 1
            try:
                response = _request(
                    "put",
                    session_url,
                    data=chunk,
                    headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{end}/{identity['size_bytes']}",
                    },
                )
            except OneDriveUploadFailure as error:
                if not error.retryable:
                    raise
                status_result, completed_item, ranges = _session_status(
                    session_url, identity["size_bytes"]
                )
                if status_result == "complete":
                    return completed_item
                if status_result == "expired":
                    _restart_session(stored_backup, state, target_path)
                    return _upload_session(
                        stored_backup,
                        storage,
                        target_path,
                        identity,
                        marker,
                        state,
                        artifact_identity,
                    )
                offset = int(status_result)
                state["next_offset"] = offset
                state["uploaded_bytes"] = offset
                state["next_expected_ranges"] = [
                    f"{start}-{end if end is not None else ''}" for start, end in ranges
                ]
                _save_state(stored_backup, state, storage_file_id=target_path)
                continue
            status = int(getattr(response, "status_code", 0) or 0)
            if status in {200, 201}:
                return _json(response)
            if status == 202:
                payload = _json(response)
                ranges = _ranges(payload)
                next_offset = ranges[0][0]
                if next_offset <= offset and next_offset < identity["size_bytes"]:
                    raise OneDriveReconciliationRequired()
                offset = next_offset
                state["next_offset"] = offset
                state["uploaded_bytes"] = offset
                state["next_expected_ranges"] = [
                    f"{start}-{end if end is not None else ''}" for start, end in ranges
                ]
                _save_state(stored_backup, state, storage_file_id=target_path)
                continue
            if status == 416:
                status_result, completed_item, ranges = _session_status(
                    session_url, identity["size_bytes"]
                )
                if status_result == "complete":
                    return completed_item
                if status_result == "expired":
                    _restart_session(stored_backup, state, target_path)
                    return _upload_session(
                        stored_backup,
                        storage,
                        target_path,
                        identity,
                        marker,
                        state,
                        artifact_identity,
                    )
                offset = int(status_result)
                state["next_offset"] = offset
                state["uploaded_bytes"] = offset
                continue
            if status == 404:
                existing = _get_item(
                    storage,
                    target_path,
                    marker,
                    allow_missing_marker=bool(state.get("session")),
                )
                if existing:
                    return existing
                _restart_session(stored_backup, state, target_path)
                return _upload_session(
                    stored_backup,
                    storage,
                    target_path,
                    identity,
                    marker,
                    state,
                    artifact_identity,
                )
            if status == 409:
                # A second session can race after a worker lost the first
                # session-creation response.  Reconcile the deterministic path;
                # never replace a non-owned object and never choose among matches.
                existing = _get_item(
                    storage,
                    target_path,
                    marker,
                    allow_missing_marker=bool(state.get("session")),
                )
                if existing:
                    return existing
                raise OneDriveUploadFailure(
                    "PROVIDER_CONFLICT",
                    status_code=status,
                    retryable=True,
                    message=SAFE_RECONCILIATION,
                )
            _raise_response(response, "upload OneDrive range")
    raise OneDriveUploadFailure("PROVIDER_MALFORMED_RESPONSE", retryable=False)


def storage_onedrive(stored_backup):
    """Upload/adopt one deterministic path and commit verified destination evidence."""
    artifact_identity = storage_artifact_identity(stored_backup.backup)
    local_artifact = f"_storage/{artifact_identity.filename}"
    try:
        identity = _source_identity(stored_backup, local_artifact)
        if artifact_identity.artifact_format == CoreBackupArtifact.Format.BSE1:
            target_path = f"backupsheep/{artifact_identity.filename}"
        else:
            target_path = (
                f"backupsheep/{_node_slug(stored_backup)}/"
                f"{artifact_identity.filename}"
            )
        validate_storage_object_key(stored_backup.backup, target_path)
        marker = _marker(artifact_identity, identity)
        storage = stored_backup.storage
        state = dict((stored_backup.metadata or {}).get(STATE_KEY) or {})
        state.update(
            {
                "schema": 1,
                "provider": "onedrive",
                "phase": state.get("phase") or "preparing",
                "object_key": target_path,
                "provider_path": target_path,
                "sha256": identity["sha256"],
                "size_bytes": identity["size_bytes"],
                "checksum_algorithm": "sha256",
            }
        )
        _save_state(stored_backup, state, storage_file_id=target_path)

        session_proof = state.get("session") or state.get("session_fingerprint")
        item = _get_item(
            storage,
            target_path,
            marker,
            allow_missing_marker=bool(session_proof),
        )
        if item:
            if int(item.get("size") or 0) != identity["size_bytes"]:
                raise OneDriveIntegrityFailure()
            return _verify_and_commit(
                stored_backup,
                storage,
                item,
                identity,
                target_path=target_path,
                marker=marker,
                session=state.get("session"),
            )

        if not os.path.isfile(local_artifact):
            raise FileNotFoundError(local_artifact)
        final_item = _upload_session(
            stored_backup,
            storage,
            target_path,
            identity,
            marker,
            state,
            artifact_identity,
        )
        # The final response may be lost or may omit description/eTag fields;
        # reconcile through the deterministic path before accepting completion.
        item = _get_item(
            storage,
            target_path,
            marker,
            allow_missing_marker=bool(state.get("session")),
        )
        if item is None:
            if isinstance(final_item, dict) and final_item.get("id"):
                item = _validate_item(
                    final_item,
                    target_path=target_path,
                    marker=marker,
                    allow_missing_marker=bool(state.get("session")),
                )
            else:
                raise OneDriveReconciliationRequired()
        return _verify_and_commit(
            stored_backup,
            storage,
            item,
            identity,
            target_path=target_path,
            marker=marker,
            session=state.get("session"),
        )
    except FileNotFoundError:
        try:
            stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
            stored_backup.save()
        except Exception as error:
            capture_exception(error)
        return None
    except OneDriveUploadFailure:
        raise
    except (requests_exceptions.Timeout, TimeoutError):
        raise OneDriveUploadFailure("PROVIDER_TIMEOUT", retryable=True, message=SAFE_TIMEOUT)
    except Exception:
        raise OneDriveUploadFailure("PROVIDER_TRANSIENT_FAILURE", retryable=True)
