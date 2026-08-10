"""Crash-safe, integrity-verified Azure Blob Storage uploads.

Block IDs are deterministic per BackupSheep backup and are persisted before
provider writes.  A retry reconciles Azure's uncommitted block list, skips only
blocks with the expected ID and exact size, and commits with an ``If-None-Match``
precondition.  A committed blob is adopted only when its Azure metadata proves
BackupSheep ownership and a complete remote SHA-256 stream matches the durable
source artifact.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
from typing import Any

from azure.core import MatchConditions
from azure.core import exceptions as azure_exceptions
from azure.storage.blob import BlobBlock, ContentSettings
from django.utils import timezone
from requests import exceptions as requests_exceptions

from apps._tasks.exceptions import StorageAzureUploadFailedError
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadReconciliationRequired,
)
from apps.api.v1.utils.http import request_timeout
from apps.console.backup.models import StoragePointLeaseLostError


STATE_KEY = "azure_blob_object"
CHECKSUM_ALGORITHM = "sha256"
NAMESPACE = "backupsheep-v1"
OBJECT_CONTENT_TYPE = "application/zip"
BLOCK_SIZE = 4 * 1024 * 1024
MAX_PROVIDER_ATTEMPTS = 3
SAFE_UPLOAD = "Azure Blob Storage could not verify the backup upload. Please retry."
SAFE_TIMEOUT = "Azure Blob Storage did not respond before the request deadline. Please retry."
SAFE_AUTH = "Azure Blob Storage rejected the configured credentials or permissions."
SAFE_NOT_FOUND = "The configured Azure Blob Storage container was not found."
SAFE_RECONCILIATION = (
    "Azure Blob Storage returned ambiguous upload state; automatic writes were stopped safely."
)
SAFE_INTEGRITY = "Azure Blob Storage returned bytes that do not match the backup artifact."
SAFE_OWNERSHIP = (
    "Azure Blob Storage ownership verification failed; no unrelated blob was changed."
)


class AzureUploadFailure(StorageAzureUploadFailedError):
    """A bounded, redacted adapter failure."""

    def __init__(
        self,
        code="PROVIDER_TRANSIENT_FAILURE",
        *,
        status_code=None,
        retryable=True,
        retry_after=None,
        message=SAFE_UPLOAD,
        stored_backup=None,
    ):
        self.code = str(code)[:64]
        self.error_code = self.code
        self.provider_status = int(status_code) if status_code is not None else None
        self.retryable = bool(retryable)
        try:
            self.retry_after = max(1, min(int(retry_after), 86400))
        except (TypeError, ValueError):
            self.retry_after = None
        backup = getattr(stored_backup, "backup", None)
        super().__init__(
            getattr(backup, "uuid_str", None),
            getattr(backup, "attempt_no", None),
            getattr(backup, "type", None),
            message,
        )


class AzureIntegrityFailure(AzureUploadFailure, S3ObjectIntegrityError):
    def __init__(self, message=SAFE_INTEGRITY, *, stored_backup=None):
        super().__init__(
            "STORAGE_INTEGRITY_FAILED",
            retryable=False,
            message=message,
            stored_backup=stored_backup,
        )


class AzureReconciliationRequired(
    AzureUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self, message=SAFE_RECONCILIATION, *, stored_backup=None):
        super().__init__(
            "STORAGE_RECONCILIATION_REQUIRED",
            retryable=False,
            message=message,
            stored_backup=stored_backup,
        )


class AzureOwnershipFailure(AzureUploadFailure, S3UploadReconciliationRequired):
    def __init__(self, *, stored_backup=None):
        super().__init__(
            "PROVIDER_OWNERSHIP_MISMATCH",
            retryable=False,
            message=SAFE_OWNERSHIP,
            stored_backup=stored_backup,
        )


class _AzureSourceInvalid(AzureIntegrityFailure):
    def __init__(self, *, stored_backup=None):
        super().__init__(
            "The committed local backup artifact failed integrity validation.",
            stored_backup=stored_backup,
        )
        self.code = "SOURCE_ARTIFACT_INVALID"
        self.error_code = self.code


class _AzureSourceMissing(FileNotFoundError):
    """Internal source marker whose message intentionally contains no path."""


class _DigestWriter:
    """Minimal file-like sink used when Azure exposes ``readinto`` only."""

    def __init__(self, digest):
        self.digest = digest
        self.size = 0

    def write(self, value):
        if value:
            self.digest.update(value)
            self.size += len(value)
        return len(value)

    def tell(self):
        return self.size

    def flush(self):
        return None


def _status_code(error):
    value = getattr(error, "status_code", None)
    if value is None:
        value = getattr(error, "status", None)
    if value is None:
        value = getattr(error, "code", None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 100 <= value <= 599 else None


def _provider_failure(error, *, stored_backup=None):
    status = _status_code(error)
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None) or {}
    retry_after = headers.get("Retry-After") or headers.get("retry-after")
    if isinstance(
        error,
        (
            TimeoutError,
            requests_exceptions.Timeout,
            azure_exceptions.ServiceRequestError,
            azure_exceptions.ServiceResponseError,
        ),
    ):
        return AzureUploadFailure(
            "PROVIDER_TIMEOUT",
            status_code=status,
            retryable=True,
            message=SAFE_TIMEOUT,
            stored_backup=stored_backup,
        )
    if status in {401, 403}:
        return AzureUploadFailure(
            "STORAGE_AUTH_FAILED",
            status_code=status,
            retryable=False,
            message=SAFE_AUTH,
            stored_backup=stored_backup,
        )
    if status == 404:
        return AzureUploadFailure(
            "STORAGE_DESTINATION_NOT_FOUND",
            status_code=status,
            retryable=False,
            message=SAFE_NOT_FOUND,
            stored_backup=stored_backup,
        )
    if status == 429:
        return AzureUploadFailure(
            "STORAGE_RATE_LIMITED",
            status_code=status,
            retryable=True,
            retry_after=retry_after,
            message="Azure Blob Storage rate limited the upload; it will resume automatically.",
            stored_backup=stored_backup,
        )
    if status in {408, 409, 412, 425} or (status is not None and status >= 500):
        return AzureUploadFailure(
            "PROVIDER_TRANSIENT_FAILURE",
            status_code=status,
            retryable=True,
            stored_backup=stored_backup,
        )
    # Azure SDK and transport exceptions can contain request URLs or response
    # bodies.  Only expose the stable, redacted category to callers.
    return AzureUploadFailure(
        "PROVIDER_TRANSIENT_FAILURE",
        status_code=status,
        retryable=True,
        stored_backup=stored_backup,
    )


def _provider_call(operation, function, *args, stored_backup=None, **kwargs):
    last_failure = None
    for attempt in range(MAX_PROVIDER_ATTEMPTS):
        try:
            return function(*args, **kwargs)
        except (
            AzureUploadFailure,
            AzureIntegrityFailure,
            AzureReconciliationRequired,
            AzureOwnershipFailure,
        ):
            raise
        except Exception as error:
            failure = _provider_failure(error, stored_backup=stored_backup)
            last_failure = failure
            if not failure.retryable or attempt + 1 >= MAX_PROVIDER_ATTEMPTS:
                raise failure from None
    raise last_failure or AzureUploadFailure(stored_backup=stored_backup)


def _backup_identifier(stored_backup):
    backup = stored_backup.backup
    value = str(getattr(backup, "uuid_str", None) or getattr(backup, "uuid", ""))
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or os.path.basename(value) != value
    ):
        raise AzureUploadFailure("INVALID_BACKUP_ID", retryable=False, stored_backup=stored_backup)
    return value


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
        raise AzureUploadFailure(
            "INVALID_PROVIDER_PATH", retryable=False, stored_backup=stored_backup
        )
    return value


def _identity_from_file(filename):
    digest = hashlib.sha256()
    size = 0
    try:
        with open(filename, "rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except FileNotFoundError:
        raise _AzureSourceMissing from None
    return {"sha256": digest.hexdigest(), "size_bytes": size, "checksum_algorithm": CHECKSUM_ALGORITHM}


def _valid_identity(value):
    if not isinstance(value, dict):
        return None
    checksum = str(value.get("sha256") or "").lower()
    try:
        size = int(value.get("size_bytes"))
    except (TypeError, ValueError):
        return None
    if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum) or size < 0:
        return None
    return {"sha256": checksum, "size_bytes": size, "checksum_algorithm": CHECKSUM_ALGORITHM}


def _committed_source_identity(stored_backup):
    relation = getattr(stored_backup.backup, "artifact_records", None)
    if relation is None:
        return None
    try:
        artifact = relation.filter(
            role="source",
            storage__isnull=True,
            verified_at__isnull=False,
        ).order_by("-verified_at").first()
    except Exception:
        return None
    if artifact is None:
        return None
    return _valid_identity(
        {
            "sha256": getattr(artifact, "checksum_value", ""),
            "size_bytes": getattr(artifact, "byte_count", None),
        }
    )


def _source_identity(stored_backup, local_filename, state):
    expected = _committed_source_identity(stored_backup) or _valid_identity(state)
    try:
        actual = _identity_from_file(local_filename)
    except _AzureSourceMissing:
        if expected is not None:
            return expected
        raise
    if expected is not None and actual != expected:
        raise _AzureSourceInvalid(stored_backup=stored_backup)
    return expected or actual


def _timeout():
    return request_timeout()


def _state(stored_backup):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    value = metadata.get(STATE_KEY)
    return metadata, dict(value) if isinstance(value, dict) else {}


def _save_state(stored_backup, state, *, status=None, storage_file_id=None):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    metadata[STATE_KEY] = dict(state)
    stored_backup.metadata = metadata
    if storage_file_id is not None:
        stored_backup.storage_file_id = str(storage_file_id)
    if status is not None:
        stored_backup.status = status
    try:
        stored_backup.save()
    except StoragePointLeaseLostError:
        raise
    except Exception:
        raise AzureUploadFailure(
            "STATE_PERSISTENCE_FAILED",
            retryable=True,
            message="Backup upload state could not be saved; the upload will resume safely.",
            stored_backup=stored_backup,
        ) from None


def _status(stored_backup, name):
    return getattr(getattr(stored_backup, "Status", None), name, None)


def _marker_values(identifier, identity):
    return {
        "backupsheep_namespace": NAMESPACE,
        "backupsheep_backup_uuid": identifier,
        "backupsheep_sha256": identity["sha256"],
        "backupsheep_bytes": str(identity["size_bytes"]),
    }


def _property(value, name, default=None):
    result = getattr(value, name, default)
    if result is not None:
        return result
    if isinstance(value, dict):
        return value.get(name, default)
    return default


def _metadata(properties):
    value = _property(properties, "metadata", {})
    return {str(key).lower(): str(item) for key, item in (value or {}).items()}


def _owned_properties(properties, markers, *, stored_backup=None):
    actual = _metadata(properties)
    if any(actual.get(str(name).lower()) != str(value) for name, value in markers.items()):
        raise AzureOwnershipFailure(stored_backup=stored_backup)
    return properties


def _not_found(error):
    status = _status_code(error)
    if status == 404:
        return True
    name = type(error).__name__
    return name in {"ResourceNotFoundError", "BlobNotFoundError"}


def _get_properties(blob_client, *, stored_backup=None, missing_ok=False):
    try:
        return _provider_call(
            "get blob properties",
            blob_client.get_blob_properties,
            timeout=_timeout(),
            stored_backup=stored_backup,
        )
    except AzureUploadFailure as error:
        if missing_ok and error.code == "STORAGE_DESTINATION_NOT_FOUND":
            return None
        raise


def _block_id(identifier, index):
    raw = f"backupsheep:{identifier}:{index:012d}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _block_plan(identifier, size):
    count = max(1, int(math.ceil(size / BLOCK_SIZE)))
    return [
        {
            "index": index,
            "id": _block_id(identifier, index),
            "offset": index * BLOCK_SIZE,
            "size": max(0, min(BLOCK_SIZE, size - index * BLOCK_SIZE)),
        }
        for index in range(count)
    ]


def _block_id_value(block):
    return str(_property(block, "id", _property(block, "name", "")) or "")


def _block_size(block):
    value = _property(block, "size", None)
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _uncommitted(response):
    if isinstance(response, tuple) and len(response) >= 2:
        return list(response[1] or [])
    if isinstance(response, dict):
        return list(response.get("uncommitted_blocks") or response.get("uncommitted") or [])
    return list(getattr(response, "uncommitted_blocks", []) or [])


def _list_uncommitted(blob_client, *, stored_backup=None):
    response = _provider_call(
        "list uncommitted blocks",
        blob_client.get_block_list,
        block_list_type="all",
        timeout=_timeout(),
        stored_backup=stored_backup,
    )
    return _uncommitted(response)


def _reconcile_blocks(blob_client, state, plan, *, stored_backup=None):
    existing = _list_uncommitted(blob_client, stored_backup=stored_backup)
    expected = {str(item["id"]): item for item in plan}
    # The provider's uncommitted-block listing is authoritative.  A DB write
    # may have succeeded before the provider request, so stale DB-only entries
    # must not be treated as uploaded without provider evidence.
    uploaded = {}
    for block in existing:
        identifier = _block_id_value(block)
        if identifier not in expected:
            # An uncommitted block with an unrelated ID must never be committed
            # by this backup, even if it is on the same deterministic blob name.
            raise AzureOwnershipFailure(stored_backup=stored_backup)
        if _block_size(block) != int(expected[identifier]["size"]):
            raise AzureReconciliationRequired(stored_backup=stored_backup)
        uploaded[identifier] = int(expected[identifier]["size"])
    state["uploaded_blocks"] = uploaded
    state["uploaded_bytes"] = sum(
        int(item["size"]) for item in plan if str(item["id"]) in uploaded
    )
    return uploaded


def _remote_stream_identity(blob_client, *, stored_backup=None):
    digest = hashlib.sha256()
    size = 0
    try:
        downloader = _provider_call(
            "download blob for verification",
            blob_client.download_blob,
            offset=0,
            length=None,
            max_concurrency=1,
            timeout=_timeout(),
            stored_backup=stored_backup,
        )
        chunks = getattr(downloader, "chunks", None)
        if callable(chunks):
            stream = chunks()
            for chunk in stream:
                if chunk:
                    digest.update(chunk)
                    size += len(chunk)
        else:
            readinto = getattr(downloader, "readinto", None)
            if not callable(readinto):
                raise AzureUploadFailure(
                    "STREAMING_VERIFICATION_UNAVAILABLE",
                    retryable=False,
                    message=(
                        "Azure Blob Storage cannot stream this blob for "
                        "integrity verification."
                    ),
                    stored_backup=stored_backup,
                )
            sink = _DigestWriter(digest)
            readinto(sink)
            size = sink.size
    except (TimeoutError, requests_exceptions.Timeout):
        raise AzureUploadFailure(
            "PROVIDER_TIMEOUT",
            retryable=True,
            message=SAFE_TIMEOUT,
            stored_backup=stored_backup,
        ) from None
    except AzureUploadFailure:
        raise
    except Exception as error:
        raise _provider_failure(error, stored_backup=stored_backup) from None
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _remote_identity(blob_client, properties, identity, markers, *, stored_backup=None):
    _owned_properties(properties, markers, stored_backup=stored_backup)
    content_length = _property(properties, "size", _property(properties, "content_length", None))
    if content_length is not None:
        try:
            if int(content_length) != int(identity["size_bytes"]):
                raise AzureIntegrityFailure(stored_backup=stored_backup)
        except (TypeError, ValueError):
            raise AzureIntegrityFailure(stored_backup=stored_backup)
    actual = _remote_stream_identity(blob_client, stored_backup=stored_backup)
    if actual != {"sha256": identity["sha256"], "size_bytes": identity["size_bytes"]}:
        raise AzureIntegrityFailure(stored_backup=stored_backup)
    return actual


def _provider_fields(properties):
    etag = str(_property(properties, "etag", "") or "")
    version_id = str(
        _property(properties, "version_id", _property(properties, "version", "")) or ""
    )
    content_settings = _property(properties, "content_settings", None)
    md5 = _property(content_settings, "content_md5", "") if content_settings else ""
    if isinstance(md5, bytes):
        md5 = base64.b64encode(md5).decode("ascii")
    md5 = str(md5 or "")
    return {
        "etag": etag,
        "version_id": version_id,
        "provider_checksum": md5,
        "provider_checksum_algorithm": "md5" if md5 else "",
        "content_md5": md5,
        "last_modified": str(_property(properties, "last_modified", "") or ""),
    }


def _commit_verified(stored_backup, state, blob_client, properties, identity, markers):
    _remote_identity(blob_client, properties, identity, markers, stored_backup=stored_backup)
    provider = _provider_fields(properties)
    state.update(
        {
            "schema": 1,
            "provider": "azure",
            "phase": "committed",
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": CHECKSUM_ALGORITHM,
            "ownership_marker": markers,
            **provider,
        }
    )
    _save_state(
        stored_backup,
        state,
        status=_status(stored_backup, "UPLOAD_VALIDATION"),
        storage_file_id=state["object_key"],
    )
    recorder = getattr(stored_backup.backup, "record_artifact_integrity", None)
    if not callable(recorder):
        raise AzureUploadFailure(
            "ARTIFACT_PERSISTENCE_FAILED",
            retryable=True,
            message="Verified destination evidence could not be saved.",
            stored_backup=stored_backup,
        )
    recorder(
        role="destination",
        object_key=state["object_key"],
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm=CHECKSUM_ALGORITHM,
        checksum_value=identity["sha256"],
        etag=provider["etag"],
        version_id=provider["version_id"],
        verified_at=timezone.now(),
        metadata={
            "provider": "azure",
            "provider_checksum": provider["provider_checksum"],
            "provider_checksum_algorithm": provider["provider_checksum_algorithm"],
            "content_md5": provider["content_md5"],
            "last_modified": provider["last_modified"],
            "storage_metadata_key": STATE_KEY,
        },
    )
    _save_state(
        stored_backup,
        state,
        status=_status(stored_backup, "UPLOAD_COMPLETE"),
        storage_file_id=state["object_key"],
    )
    return state


def _mark_source_missing(stored_backup):
    try:
        stored_backup.status = _status(stored_backup, "UPLOAD_FAILED_FILE_NOT_FOUND")
        stored_backup.save()
    except StoragePointLeaseLostError:
        raise
    except Exception:
        raise AzureUploadFailure(
            "STATE_PERSISTENCE_FAILED",
            retryable=True,
            message="Backup upload state could not be saved; the upload will resume safely.",
            stored_backup=stored_backup,
        ) from None


def delete_owned_azure_blob(stored_backup):
    """Delete only the exact Azure version/ETag committed by this storage row."""
    state = dict((getattr(stored_backup, "metadata", None) or {}).get(STATE_KEY) or {})
    expected = stored_backup.committed_integrity_identity()
    object_key = str(state.get("object_key") or "")
    etag = str(state.get("etag") or "")
    version_id = str(state.get("version_id") or "")
    committed_version = str(stored_backup.committed_version_id() or "")
    if (
        state.get("phase") != "committed"
        or object_key != str(stored_backup.storage_file_id or "")
        or expected is None
        or not etag
        or (committed_version and committed_version != version_id)
    ):
        raise AzureOwnershipFailure(stored_backup=stored_backup)
    markers = _marker_values(stored_backup.backup.uuid_str, expected)
    if dict(state.get("ownership_marker") or {}) != markers:
        raise AzureOwnershipFailure(stored_backup=stored_backup)

    config = stored_backup.storage.storage_azure
    service = _provider_call(
        "create client",
        config.get_client,
        stored_backup=stored_backup,
    )
    blob_client = _provider_call(
        "select blob version",
        service.get_blob_client,
        container=config.bucket_name,
        blob=object_key,
        version_id=version_id or None,
        stored_backup=stored_backup,
    )
    properties = _get_properties(
        blob_client,
        stored_backup=stored_backup,
        missing_ok=True,
    )
    if properties is None:
        return False
    _owned_properties(properties, markers, stored_backup=stored_backup)
    try:
        remote_size = int(
            _property(properties, "size", _property(properties, "content_length", -1))
        )
    except (TypeError, ValueError):
        raise AzureOwnershipFailure(stored_backup=stored_backup) from None
    remote_version = str(
        _property(properties, "version_id", _property(properties, "version", "")) or ""
    )
    if (
        remote_size != expected["size_bytes"]
        or str(_property(properties, "etag", "") or "") != etag
        or (version_id and remote_version != version_id)
    ):
        raise AzureOwnershipFailure(stored_backup=stored_backup)

    try:
        blob_client.delete_blob(
            etag=etag,
            match_condition=MatchConditions.IfNotModified,
            timeout=_timeout(),
        )
    except Exception as error:
        status = _status_code(error)
        if status == 404:
            return False
        if status == 412:
            raise AzureOwnershipFailure(stored_backup=stored_backup) from None
        raise _provider_failure(error, stored_backup=stored_backup) from None
    return True


def _build_block_list(plan):
    return [BlobBlock(block_id=str(item["id"])) for item in plan]


def _stage_blocks(stored_backup, blob_client, state, plan, identity):
    uploaded = dict(state.get("uploaded_blocks") or {})
    local_filename = os.path.join("_storage", f"{_backup_identifier(stored_backup)}.zip")
    source_exists = os.path.isfile(local_filename)
    if not source_exists and len(uploaded) != len(plan):
        raise _AzureSourceMissing from None

    digest = hashlib.sha256()
    total = 0
    source = open(local_filename, "rb") if source_exists else None
    try:
        for item in plan:
            size = int(item["size"])
            if source is not None:
                chunk = source.read(size)
                if len(chunk) != size:
                    raise _AzureSourceInvalid(stored_backup=stored_backup)
                digest.update(chunk)
                total += len(chunk)
            if str(item["id"]) in uploaded:
                continue
            if source is None:
                raise _AzureSourceMissing from None
            _provider_call(
                "stage block",
                blob_client.stage_block,
                block_id=str(item["id"]),
                data=chunk,
                length=size,
                timeout=_timeout(),
                stored_backup=stored_backup,
            )
            uploaded[str(item["id"])] = size
            state["uploaded_blocks"] = uploaded
            state["uploaded_bytes"] = sum(
                int(part["size"]) for part in plan if str(part["id"]) in uploaded
            )
            state["phase"] = "uploading"
            _save_state(stored_backup, state, storage_file_id=state["object_key"])
    finally:
        if source is not None:
            source.close()
    if source_exists:
        if digest.hexdigest() != identity["sha256"] or total != identity["size_bytes"]:
            raise _AzureSourceInvalid(stored_backup=stored_backup)
    return uploaded


def _commit_blocks(stored_backup, blob_client, state, plan, markers):
    return _provider_call(
        "commit block list",
        blob_client.commit_block_list,
        _build_block_list(plan),
        content_settings=ContentSettings(content_type=OBJECT_CONTENT_TYPE),
        metadata=markers,
        if_none_match="*",
        timeout=_timeout(),
        stored_backup=stored_backup,
    )


def storage_azure(stored_backup):
    """Upload/adopt one deterministic Azure blob and commit verified evidence."""
    try:
        identifier = _backup_identifier(stored_backup)
        node_slug = _node_slug(stored_backup)
        local_filename = os.path.join("_storage", f"{identifier}.zip")
        config = stored_backup.storage.storage_azure
        prefix = str(config.prefix or "")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        object_key = f"{prefix}{node_slug}/{identifier}.zip"
        metadata, state = _state(stored_backup)
        persisted_key = str(state.get("object_key") or stored_backup.storage_file_id or object_key)
        if persisted_key != object_key:
            raise AzureOwnershipFailure(stored_backup=stored_backup)
        state["object_key"] = object_key
        identity = _source_identity(stored_backup, local_filename, state)
        persisted = _valid_identity(state)
        if persisted is not None and persisted != identity:
            raise _AzureSourceInvalid(stored_backup=stored_backup)
        state.update(
            {
                "provider": "azure",
                "phase": state.get("phase") or "preparing",
                "sha256": identity["sha256"],
                "size_bytes": identity["size_bytes"],
                "checksum_algorithm": CHECKSUM_ALGORITHM,
                "ownership_marker": _marker_values(identifier, identity),
                "block_size": BLOCK_SIZE,
            }
        )
        markers = dict(state["ownership_marker"])
        plan = state.get("blocks")
        if not isinstance(plan, list) or plan != _block_plan(identifier, identity["size_bytes"]):
            plan = _block_plan(identifier, identity["size_bytes"])
            state["blocks"] = plan
            state["uploaded_blocks"] = {}
        _save_state(
            stored_backup,
            state,
            status=_status(stored_backup, "UPLOAD_VALIDATION"),
            storage_file_id=object_key,
        )

        service = _provider_call(
            "create client",
            config.get_client,
            stored_backup=stored_backup,
        )
        blob_client = _provider_call(
            "select blob",
            service.get_blob_client,
            container=config.bucket_name,
            blob=object_key,
            stored_backup=stored_backup,
        )
        properties = _get_properties(blob_client, stored_backup=stored_backup, missing_ok=True)
        if properties is not None:
            _owned_properties(properties, markers, stored_backup=stored_backup)
            return _commit_verified(
                stored_backup,
                state,
                blob_client,
                properties,
                identity,
                markers,
            )

        # A committed object was not found.  The following list is safe to use
        # for continuation because every accepted block ID is derived from this
        # backup UUID and its exact index.  Any other ID is an ownership failure.
        _reconcile_blocks(blob_client, state, plan, stored_backup=stored_backup)
        _stage_blocks(stored_backup, blob_client, state, plan, identity)
        try:
            _commit_blocks(stored_backup, blob_client, state, plan, markers)
        except AzureUploadFailure as commit_error:
            # A lost commit response is reconciled before considering another
            # commit.  If all deterministic blocks remain, retrying the same
            # conditional commit is safe; it cannot overwrite a foreign blob.
            properties = _get_properties(blob_client, stored_backup=stored_backup, missing_ok=True)
            if properties is not None:
                _owned_properties(properties, markers, stored_backup=stored_backup)
                return _commit_verified(
                    stored_backup,
                    state,
                    blob_client,
                    properties,
                    identity,
                    markers,
                )
            if commit_error.code not in {"PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_FAILURE"}:
                raise
            _reconcile_blocks(blob_client, state, plan, stored_backup=stored_backup)
            if len(dict(state.get("uploaded_blocks") or {})) != len(plan):
                raise AzureReconciliationRequired(stored_backup=stored_backup)
            _commit_blocks(stored_backup, blob_client, state, plan, markers)

        properties = _get_properties(blob_client, stored_backup=stored_backup, missing_ok=True)
        if properties is None:
            raise AzureReconciliationRequired(stored_backup=stored_backup)
        _owned_properties(properties, markers, stored_backup=stored_backup)
        return _commit_verified(
            stored_backup,
            state,
            blob_client,
            properties,
            identity,
            markers,
        )
    except _AzureSourceMissing:
        _mark_source_missing(stored_backup)
        return None
    except StoragePointLeaseLostError:
        raise
    except (
        AzureIntegrityFailure,
        AzureReconciliationRequired,
        AzureOwnershipFailure,
        AzureUploadFailure,
    ):
        raise
    except Exception as error:
        raise _provider_failure(error, stored_backup=stored_backup) from None


__all__ = [
    "AzureIntegrityFailure",
    "AzureOwnershipFailure",
    "AzureReconciliationRequired",
    "AzureUploadFailure",
    "STATE_KEY",
    "delete_owned_azure_blob",
    "storage_azure",
]
