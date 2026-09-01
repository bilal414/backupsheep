"""Shared helpers for the website/database restore engines.

A restore starts by materializing the stored backup zip onto the local disk:

  * Local Storage remains mounted only in the storage lane. Encrypted objects
    cross a storage-owned, source-read-only BSE1 handoff whose exact bytes are
    checked against the durable ledger before authenticated decryption.
  * Committed Dropbox, pCloud, Google Drive, OneDrive, Google Cloud Storage,
    and Azure copies are fetched through authenticated provider APIs using
    their durable object identity, ownership markers, and version/revision
    guards. The response is streamed through the atomic SHA-256/byte-count
    validator before publication.
  * S3-compatible DigitalOcean Spaces, UpCloud, Oracle Object Storage, and
    Vultr copies committed by ``upload_verified_s3`` are fetched through the
    same authenticated provider clients used for upload. Other remote
    backends, plus pre-ledger legacy copies, use the historical
    ``stored_backup.generate_download_url()`` path explicitly and safely.
  * Glacier/Deep Archive copies are cold: generate_download_url() returns the
    "restore_requested" / "restore_in_progress" sentinels instead of a URL,
    which becomes a clear RestoreError telling the user to thaw the archive
    with the storage provider first.

Extraction is path-traversal-safe for both the outer zip and the legacy
tar-wrapped website layout (backup_type FULL_V2 zips wrap {uuid}.tar).
"""
import copy
import hashlib
import inspect
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import uuid
from datetime import datetime
from urllib.parse import quote

from apps.api.v1.utils.http import requests
from apps.api.v1.utils.http import request_timeout
from apps.api.v1.utils.api_helpers import bs_decrypt
from django.conf import settings
from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.integration.backup._archive import (
    iter_zip_members,
    mark_utf8_zip_names,
)
from apps._tasks.artifact_encryption import (
    ArtifactPipelineError,
    _handoff_timestamp,
    local_restore_phase_task_id,
    restore_ciphertext_handoff_identity,
    restore_encryption_plan,
    storage_artifact_identity,
    unseal_downloaded_artifact,
    validate_storage_object_key,
)

# (connect, read) timeout for the download URL fetch; 1 MiB stream chunks.
DOWNLOAD_TIMEOUT = (30, 300)
CHUNK_SIZE = 1024 * 1024

GLACIER_SENTINELS = ("restore_requested", "restore_in_progress")


def stale_local_restore_work_prefixes(restore, backup):
    """Return exact prior fence generations recorded for one restore row."""
    prefixes = []
    metadata = dict(getattr(restore, "execution_metadata", None) or {})
    for takeover in metadata.get("stale_lease_takeovers") or []:
        if not isinstance(takeover, dict):
            continue
        suffix = str(takeover.get("previous_work_suffix") or "").lower()
        if len(suffix) != 16 or any(
            character not in "0123456789abcdef" for character in suffix
        ):
            continue
        prefix = f"restore_{backup.uuid_str}_{suffix}"
        if prefix not in prefixes:
            prefixes.append(prefix)
    return prefixes

# These providers historically exposed a browser/view URL from
# ``generate_download_url``.  A committed upload now contains a durable
# provider identity, so restore must authenticate to the provider directly and
# never turn a stored path into an unauthenticated/current-object download.
EXACT_PROVIDER_CODES = frozenset(
    {
        "aws_s3",
        "do_spaces",
        "azure",
        "dropbox",
        "google_cloud",
        "google_drive",
        "onedrive",
        "pcloud",
        "idrive",
        "oracle",
        "upcloud",
        "vultr",
    }
)
PROVIDER_STATE_KEYS = {
    "azure": "azure_blob_object",
    "dropbox": "dropbox_object",
    "google_cloud": "google_cloud_object",
    "pcloud": "pcloud_object",
    "google_drive": "google_drive_upload",
    "onedrive": "onedrive_upload",
    "idrive": "idrive_s3_object",
}
S3_COMPATIBLE_PROVIDER_STATE_KEYS = {
    "do_spaces": "do_spaces_s3_object",
    "upcloud": "upcloud_s3_object",
    "oracle": "oracle_s3_object",
    "vultr": "vultr_s3_object",
}
S3_COMPATIBLE_PROVIDER_LABELS = {
    "do_spaces": "DigitalOcean Spaces",
    "upcloud": "UpCloud Object Storage",
    "oracle": "Oracle Object Storage",
    "vultr": "Vultr Object Storage",
}
ALL_PROVIDER_STATE_KEYS = frozenset(
    set(PROVIDER_STATE_KEYS.values())
    | set(S3_COMPATIBLE_PROVIDER_STATE_KEYS.values())
)


class RestoreError(Exception):
    """Fatal, user-facing restore failure; the task marks the restore FAILED with it."""


class _SafeProviderRestoreError(RestoreError):
    """Provider restore failure with no provider response/body attached."""

    def __init__(
        self,
        code,
        message,
        *,
        retryable=False,
        retry_after=None,
        provider_status=None,
    ):
        self.code = str(code)[:64]
        self.retryable = bool(retryable)
        try:
            self.retry_after = max(1, min(int(retry_after), 86400))
        except (TypeError, ValueError):
            self.retry_after = None
        try:
            status = int(provider_status)
        except (TypeError, ValueError):
            status = None
        self.provider_status = status if status and 100 <= status <= 599 else None
        super().__init__(message)


def _normalise_sha256(value):
    value = str(value or "").strip().lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def _integrity_restore_error(stored_backup, code, message):
    """Keep committed IDrive ledger failures on the safe provider error path."""
    try:
        provider_code = str(stored_backup.storage.type.code or "")
    except AttributeError:
        provider_code = ""
    if provider_code == "idrive":
        return _SafeProviderRestoreError(code, message)
    return RestoreError(message)


def _expected_integrity(stored_backup, selected_artifact=None):
    """Return the one committed SHA-256 identity for this exact storage object.

    New backup pipelines commit both a destination artifact row and provider-local
    metadata before they expose a storage point as complete.  Reading both copies
    lets restore detect a partially persisted upload as well as metadata tampering.
    Backups created before the integrity ledger existed remain restorable, but a
    backup with a committed source identity may never silently fall back to legacy
    unverified restore behaviour.
    """
    candidates = []
    backup = stored_backup.backup
    storage_id = stored_backup.storage_id
    object_key = str(stored_backup.storage_file_id or "")
    if not object_key or "\x00" in object_key:
        raise _integrity_restore_error(
            stored_backup,
            "MALFORMED_PROVIDER_STATE",
            "the selected storage copy has no valid object identity.",
        )

    artifacts = list(
        backup.artifact_records.filter(
            storage_id=storage_id,
            object_key=object_key,
            verified_at__isnull=False,
            role__in=("archive", "destination"),
        )
    )
    if selected_artifact is not None:
        if (
            selected_artifact.storage_id != storage_id
            or selected_artifact.object_key != object_key
            or selected_artifact.verified_at is None
            or selected_artifact.pk not in {artifact.pk for artifact in artifacts}
        ):
            raise _integrity_restore_error(
                stored_backup,
                "INTEGRITY_LEDGER_CONFLICT",
                "the selected encrypted artifact does not belong to this storage object.",
            )
    if len(artifacts) > 1:
        raise _integrity_restore_error(
            stored_backup,
            "INTEGRITY_LEDGER_CONFLICT",
            "multiple verified artifacts claim the selected storage object.",
        )
    for artifact in artifacts:
        checksum = _normalise_sha256(artifact.checksum_value)
        if str(artifact.checksum_algorithm or "").lower() == "sha256" and checksum:
            try:
                byte_count = int(artifact.byte_count)
            except (TypeError, ValueError):
                raise _integrity_restore_error(
                    stored_backup,
                    "MALFORMED_PROVIDER_STATE",
                    "stored backup integrity metadata is invalid.",
                ) from None
            candidates.append(
                {
                    "size_bytes": byte_count,
                    "sha256": checksum,
                    "etag": str(artifact.etag or ""),
                    "version_id": str(artifact.version_id or ""),
                    "source": "artifact ledger",
                }
            )

    for state in (stored_backup.metadata or {}).values():
        if not isinstance(state, dict):
            continue
        state_identities = {
            str(state[field])
            for field in (
                "storage_file_id",
                "object_key",
                "provider_id",
                "path",
                "provider_path",
                "file_id",
                "fileid",
            )
            if state.get(field) not in (None, "")
        }
        checksum = _normalise_sha256(state.get("sha256"))
        byte_count = state.get("size_bytes")
        if (
            object_key not in state_identities
            or str(state.get("phase") or "").lower() != "committed"
            or checksum is None
            or byte_count is None
        ):
            continue
        try:
            candidates.append(
                {
                    "size_bytes": int(byte_count),
                    "sha256": checksum,
                    "etag": str(
                        state.get("etag")
                        or state.get("content_hash")
                        or state.get("provider_hash")
                        or ""
                    ),
                    "version_id": str(
                        state.get("version_id")
                        or state.get("generation")
                        or state.get("revision")
                        or ""
                    ),
                    "source": "storage metadata",
                }
            )
        except (TypeError, ValueError):
            raise _integrity_restore_error(
                stored_backup,
                "MALFORMED_PROVIDER_STATE",
                "stored backup integrity metadata is invalid.",
            ) from None

    identities = {
        (candidate["size_bytes"], candidate["sha256"])
        for candidate in candidates
    }
    if len(identities) > 1:
        raise _integrity_restore_error(
            stored_backup,
            "INTEGRITY_LEDGER_CONFLICT",
            "stored backup integrity records disagree; restore was stopped safely.",
        )
    if identities:
        size, checksum = identities.pop()
        if size <= 0:
            raise _integrity_restore_error(
                stored_backup,
                "MALFORMED_PROVIDER_STATE",
                "stored backup integrity metadata has an invalid size.",
            )
        etags = {
            candidate["etag"]
            for candidate in candidates
            if candidate["etag"] not in {"", "null"}
        }
        versions = {
            candidate["version_id"]
            for candidate in candidates
            if candidate["version_id"] not in {"", "null"}
        }
        if len(etags) > 1 or len(versions) > 1:
            raise _integrity_restore_error(
                stored_backup,
                "INTEGRITY_LEDGER_CONFLICT",
                "stored backup object version records disagree; restore was stopped safely.",
            )
        expected = {"size_bytes": size, "sha256": checksum}
        if etags:
            expected["etag"] = etags.pop()
        if versions:
            expected["version_id"] = versions.pop()
        return expected

    source_is_committed = backup.artifact_records.filter(
        storage__isnull=True,
        role="source",
        verified_at__isnull=False,
    ).exists()
    if source_is_committed:
        raise _integrity_restore_error(
            stored_backup,
            "MISSING_PROVIDER_STATE",
            "this backup has no committed integrity record for the selected storage copy.",
        )
    return None


def _materialize_stream(chunks, dest_zip_path, expected):
    """Write a streamed object durably and atomically, returning its identity."""
    destination = os.path.realpath(dest_zip_path)
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    temporary = f"{destination}.{uuid.uuid4().hex}.partial"
    digest = hashlib.sha256()
    byte_count = 0
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            for chunk in chunks:
                if not chunk:
                    continue
                byte_count += len(chunk)
                if expected and byte_count > expected["size_bytes"]:
                    raise RestoreError(
                        "downloaded backup exceeds its committed byte count."
                    )
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())

        checksum = digest.hexdigest()
        if byte_count <= 0:
            raise RestoreError("stored backup zip is empty (0 bytes).")
        if expected and (
            byte_count != expected["size_bytes"]
            or checksum != expected["sha256"]
        ):
            raise RestoreError(
                "downloaded backup failed its committed SHA-256 integrity check."
            )

        os.replace(temporary, destination)
        try:
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            # Some network filesystems do not allow fsync on directories.  The
            # file itself is already fsync'd and atomically renamed.
            pass
        return {"size_bytes": byte_count, "sha256": checksum}
    finally:
        try:
            os.remove(temporary)
        except FileNotFoundError:
            pass


def _local_source_path(storage_file_id):
    """Resolve a Local Storage backend's storage_file_id, confined to LOCAL_STORAGE_ROOT."""
    root = os.path.realpath(settings.LOCAL_STORAGE_ROOT)
    target = os.path.realpath(storage_file_id or "")
    if target == root or not target.startswith(root + os.sep):
        raise RestoreError("stored backup path escapes the local storage root.")
    if not os.path.isfile(target):
        raise RestoreError("stored backup file was not found on local storage.")
    return target


def _restore_node_slug(stored_backup):
    value = str(getattr(stored_backup.backup.node, "name_slug", "") or "")
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise _SafeProviderRestoreError(
            "INVALID_PROVIDER_PATH",
            "stored backup provider state contains an invalid provider path.",
        )
    return value


def _restore_artifact_identity(stored_backup, *, object_key=None):
    """Resolve and, when applicable, bind one opaque provider object name.

    New encrypted restores get their public identity only from the durable source
    envelope ledger.  The backup UUID/node slug reconstruction below remains
    reachable solely when ``storage_artifact_identity`` has selected the explicit
    legacy-ZIP mode.
    """

    try:
        identity = storage_artifact_identity(stored_backup.backup)
        if object_key is not None:
            validate_storage_object_key(stored_backup.backup, object_key)
    except (ArtifactPipelineError, TypeError, ValueError) as error:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "the committed provider path is not bound to this encrypted artifact.",
        ) from error
    return identity


def _legacy_artifact_identity(identity):
    return str(getattr(identity, "artifact_format", "")) == "legacy_zip"


def _destination_ledger_exists(stored_backup):
    """Return whether a durable destination artifact exists for this row."""
    relation = getattr(stored_backup.backup, "artifact_records", None)
    if relation is None:
        return False
    object_key = str(getattr(stored_backup, "storage_file_id", "") or "")
    if not object_key or "\x00" in object_key:
        return False
    try:
        return bool(
            relation.filter(
                storage_id=stored_backup.storage_id,
                object_key=object_key,
                role__in=("archive", "destination"),
                verified_at__isnull=False,
            ).exists()
        )
    except (AttributeError, TypeError, ValueError):
        # Small in-memory doubles used by unit tests and import-time checks can
        # expose a list rather than a Django related manager.  This fallback is
        # deliberately conservative and only recognises an explicitly verified
        # destination record for this exact storage id.
        try:
            records = relation.all() if callable(getattr(relation, "all", None)) else relation
            for record in records:
                if (
                    getattr(record, "storage_id", None) == stored_backup.storage_id
                    and str(getattr(record, "object_key", "") or "")
                    == object_key
                    and getattr(record, "role", "") in {"archive", "destination"}
                    and getattr(record, "verified_at", None) is not None
                ):
                    return True
        except Exception:
            return False
    return False


def _provider_state(stored_backup, provider_code, expected):
    """Load a committed provider state or select the explicit legacy path.

    A provider metadata key is never treated as an advisory hint.  Once present,
    it must describe one committed object completely.  A row with a destination
    artifact but no provider state is also stopped rather than silently switching
    to the old browser/current-path URL behavior.
    """
    metadata = getattr(stored_backup, "metadata", None) or {}
    if not isinstance(metadata, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    state_key = PROVIDER_STATE_KEYS[provider_code]
    if state_key not in metadata:
        if _destination_ledger_exists(stored_backup):
            raise _SafeProviderRestoreError(
                "MISSING_PROVIDER_STATE",
                "the committed backup has no provider identity for restore.",
            )
        return None

    raw_state = metadata.get(state_key)
    if not isinstance(raw_state, dict) or not raw_state:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    # Provider validation normalizes aliases below. Never mutate the JSONField
    # value hanging off the model instance while merely preparing a restore.
    state = copy.deepcopy(raw_state)
    if str(state.get("provider") or "") != provider_code:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "stored backup provider state belongs to a different provider.",
        )
    if str(state.get("phase") or "").lower() != "committed":
        raise _SafeProviderRestoreError(
            "UNCOMMITTED_PROVIDER_STATE",
            "the selected backup provider object was not durably committed.",
        )
    provider_id_fields = ["provider_id", "file_id", "fileid"]
    if provider_code in {"google_cloud", "azure"}:
        provider_id_fields.append("object_key")
    provider_ids = {
        str(state[field])
        for field in provider_id_fields
        if state.get(field) not in (None, "")
    }
    if len(provider_ids) != 1:
        raise _SafeProviderRestoreError(
            "AMBIGUOUS_PROVIDER_STATE",
            "the selected backup has an ambiguous provider identity.",
        )
    provider_id = next(iter(provider_ids), "")
    if not provider_id:
        raise _SafeProviderRestoreError(
            "MISSING_PROVIDER_ID",
            "the selected backup has no committed provider identity.",
        )

    state_checksum = _normalise_sha256(state.get("sha256"))
    try:
        state_size = int(state.get("size_bytes"))
    except (TypeError, ValueError):
        state_size = -1
    if state_checksum is None or state_size <= 0:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has invalid committed integrity metadata.",
        )
    if not expected or (
        expected["sha256"] != state_checksum
        or int(expected["size_bytes"]) != state_size
    ):
        raise _SafeProviderRestoreError(
            "INTEGRITY_LEDGER_CONFLICT",
            "the selected backup integrity records disagree; restore was stopped safely.",
        )

    path_fields = {
        "azure": ("object_key",),
        "dropbox": ("path",),
        "google_cloud": ("object_key",),
        "pcloud": ("path",),
        "google_drive": ("provider_path",),
        "onedrive": ("provider_path", "object_key"),
    }[provider_code]
    paths = {
        str(state[field])
        for field in path_fields
        if state.get(field) not in (None, "")
    }
    if len(paths) != 1:
        raise _SafeProviderRestoreError(
            "AMBIGUOUS_PROVIDER_STATE",
            "the selected backup has an ambiguous provider path.",
        )
    provider_path = next(iter(paths), "")
    if not provider_path or "\x00" in provider_path:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup provider path is malformed.",
        )

    # Storage file IDs are historically paths for pCloud/OneDrive and provider
    # IDs for Dropbox/Drive.  Validate the relevant form in each provider helper;
    # this common check only rejects a contradictory duplicate provider ID.
    state["provider_id"] = provider_id
    state["provider_path"] = provider_path
    state["sha256"] = state_checksum
    state["size_bytes"] = state_size
    return state


def _response_status(response):
    return _coerce_status(getattr(response, "status_code", None)) or 0


def _coerce_status(value):
    if callable(value):
        try:
            value = value()
        except Exception:
            return None
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        value = enum_value
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 100 <= value <= 599 else None


def _bounded_retry_after(value):
    try:
        return max(1, min(int(value), 86400))
    except (TypeError, ValueError):
        return None


def _headers_retry_after(headers):
    headers = headers or {}
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return None
    value = getter("Retry-After") or getter("retry-after")
    if value is None:
        items = getattr(headers, "items", None)
        if callable(items):
            for key, candidate in items():
                if str(key).lower() == "retry-after":
                    value = candidate
                    break
    return _bounded_retry_after(value)


def _error_status(error):
    for candidate in (
        getattr(error, "provider_status", None),
        getattr(error, "status_code", None),
        getattr(error, "status", None),
        getattr(error, "code", None),
        getattr(getattr(error, "response", None), "status_code", None),
    ):
        status = _coerce_status(candidate)
        if status is not None:
            return status
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata") or {}
        return _coerce_status(
            response.get("status_code")
            or response.get("StatusCode")
            or metadata.get("HTTPStatusCode")
        ) or 0
    return 0


def _safe_provider_failure(
    provider,
    error=None,
    *,
    status=None,
    retry_after=None,
):
    """Map provider/transport failures without retaining exception text."""
    if isinstance(error, _SafeProviderRestoreError):
        return error
    if isinstance(error, RestoreError):
        return error
    response = getattr(error, "response", None)
    provider_error = response.get("Error") if isinstance(response, dict) else None
    code_value = (
        getattr(error, "error_code", None)
        or getattr(error, "code", "")
        or (provider_error or {}).get("Code")
    )
    if callable(code_value):
        try:
            code_value = code_value()
        except Exception:
            code_value = ""
    code = str(code_value or "").upper()
    status = _coerce_status(status) or _error_status(error) or 0
    if retry_after is None:
        retry_after = _bounded_retry_after(getattr(error, "retry_after", None))
    if retry_after is None:
        retry_after = _headers_retry_after(
            getattr(getattr(error, "response", None), "headers", None)
        )
    timeout_types = (TimeoutError, socket.timeout)
    transient_types = (ConnectionError,)
    try:
        timeout_types += (requests.exceptions.Timeout,)
        transient_types += (requests.exceptions.ConnectionError,)
    except AttributeError:
        pass
    try:
        from azure.core import exceptions as azure_exceptions

        transient_types += (
            azure_exceptions.ServiceRequestError,
            azure_exceptions.ServiceResponseError,
        )
    except (ImportError, AttributeError):
        pass
    try:
        from google.api_core import exceptions as google_exceptions

        timeout_types += (google_exceptions.DeadlineExceeded,)
    except (ImportError, AttributeError):
        pass
    try:
        from botocore import exceptions as botocore_exceptions

        timeout_types += (
            botocore_exceptions.ConnectTimeoutError,
            botocore_exceptions.ReadTimeoutError,
        )
        transient_types += (
            botocore_exceptions.ConnectionClosedError,
            botocore_exceptions.EndpointConnectionError,
            botocore_exceptions.ProxyConnectionError,
            botocore_exceptions.SSLError,
        )
    except (ImportError, AttributeError):
        pass

    # Permanent identity and authorization failures take precedence over a
    # coincidental transport/status hint. They must never become retryable.
    if status == 404 or code in {
        "404",
        "NOSUCHBUCKET",
        "NOSUCHKEY",
        "NOSUCHVERSION",
        "NOT_FOUND",
        "PROVIDER_NOT_FOUND",
        "STORAGE_DESTINATION_NOT_FOUND",
    }:
        return _SafeProviderRestoreError(
            "PROVIDER_NOT_FOUND",
            f"the committed {provider} backup object was not found.",
            provider_status=status or None,
        )
    if status in {401, 403} or code in {
        "ACCESSDENIED",
        "INVALIDACCESSKEYID",
        "SIGNATUREDOESNOTMATCH",
        "AUTH_FAILED",
        "PROVIDER_AUTH_FAILED",
        "STORAGE_AUTH_FAILED",
    }:
        return _SafeProviderRestoreError(
            "PROVIDER_AUTH_FAILED",
            f"{provider} rejected the credentials or permissions for restore.",
            provider_status=status or None,
        )
    if status in {409, 412} or code in {
        "PRECONDITION_FAILED",
        "PROVIDER_VERSION_DRIFT",
    }:
        return _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            f"the committed {provider} object changed before it could be restored.",
            provider_status=status or None,
        )
    if code in {
        "INTEGRITY_MISMATCH",
        "PROVIDER_OWNERSHIP_MISMATCH",
        "STORAGE_INTEGRITY_FAILED",
        "STORAGE_RECONCILIATION_REQUIRED",
    }:
        return _SafeProviderRestoreError(
            code,
            f"the committed {provider} object failed ownership or integrity verification.",
            provider_status=status or None,
        )
    if isinstance(error, timeout_types) or code in {
        "TIMEOUT",
        "PROVIDER_TIMEOUT",
        "STORAGE_TIMEOUT",
    }:
        return _SafeProviderRestoreError(
            "PROVIDER_TIMEOUT",
            f"{provider} did not respond before the restore deadline; retry later.",
            retryable=True,
            retry_after=retry_after,
            provider_status=status or None,
        )
    if status == 429 or code in {
        "RATE_LIMITED",
        "STORAGE_RATE_LIMITED",
        "SLOWDOWN",
        "THROTTLING",
        "THROTTLINGEXCEPTION",
    }:
        return _SafeProviderRestoreError(
            "PROVIDER_RATE_LIMITED",
            f"{provider} rate-limited restore; retry later.",
            retryable=True,
            retry_after=retry_after,
            provider_status=status or None,
        )
    if (
        status in {408, 425}
        or status >= 500
        or isinstance(error, transient_types)
        or code in {
            "INTERNALERROR",
            "REQUESTTIMEOUT",
            "REQUESTTIMEOUTEXCEPTION",
            "SERVICEUNAVAILABLE",
            "TRANSIENT_OUTAGE",
            "PROVIDER_TRANSIENT_FAILURE",
        }
    ):
        return _SafeProviderRestoreError(
            "PROVIDER_TRANSIENT_FAILURE",
            f"{provider} is temporarily unavailable; retry later.",
            retryable=True,
            retry_after=retry_after,
            provider_status=status or None,
        )
    return _SafeProviderRestoreError(
        "PROVIDER_REQUEST_FAILED",
        f"{provider} could not provide the committed backup object.",
        provider_status=status or None,
    )


def _check_provider_response(response, provider, *, allowed=(200,)):
    status = _response_status(response)
    if status in allowed:
        return
    raise _safe_provider_failure(
        provider,
        status=status,
        retry_after=_headers_retry_after(getattr(response, "headers", None)),
    )


def _response_json(response, provider):
    try:
        payload = response.json()
    except Exception:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned malformed restore metadata.",
        ) from None
    if not isinstance(payload, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned malformed restore metadata.",
        )
    return payload


def _response_chunks(response):
    iterator = getattr(response, "iter_content", None)
    if callable(iterator):
        return iterator(chunk_size=CHUNK_SIZE)
    raw = getattr(response, "raw", None)
    read = getattr(raw, "read", None)
    if callable(read):
        def _read_chunks():
            while True:
                chunk = read(CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk
        return _read_chunks()
    raise _SafeProviderRestoreError(
        "MALFORMED_PROVIDER_RESPONSE",
        "the storage provider returned no readable backup stream.",
    )


def _close_response(response):
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _materialize_provider_stream(chunks, dest_zip_path, expected, verify_remote):
    """Validate a provider stream, recheck identity, then publish atomically."""
    destination = os.path.realpath(dest_zip_path)
    staging = f"{destination}.{uuid.uuid4().hex}.provider.partial"
    try:
        _materialize_stream(chunks, staging, expected)
        verify_remote()
        os.replace(staging, destination)
        parent = os.path.dirname(destination)
        try:
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass
    finally:
        try:
            os.remove(staging)
        except FileNotFoundError:
            pass


class _VerifiedProviderWriter:
    """Sequential SDK sink that hashes while writing the one staging file."""

    def __init__(self, output, expected):
        self.output = output
        self.expected = expected
        self.digest = hashlib.sha256()
        self.byte_count = 0

    def write(self, value):
        if not value:
            return 0
        self.byte_count += len(value)
        if self.expected and self.byte_count > self.expected["size_bytes"]:
            raise RestoreError(
                "downloaded backup exceeds its committed byte count."
            )
        written = self.output.write(value)
        if written != len(value):
            raise OSError("The restore staging file accepted a partial write.")
        self.digest.update(value)
        return written

    def tell(self):
        return self.output.tell()

    def flush(self):
        return self.output.flush()

    def fileno(self):
        return self.output.fileno()


def _materialize_provider_sdk_download(
    download_to_writer,
    dest_zip_path,
    expected,
    verify_remote,
):
    """Download through an SDK writer without a second full-size temp copy."""
    destination = os.path.realpath(dest_zip_path)
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    staging = f"{destination}.{uuid.uuid4().hex}.provider.partial"
    try:
        descriptor = os.open(
            staging,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            writer = _VerifiedProviderWriter(output, expected)
            download_to_writer(writer)
            writer.flush()
            os.fsync(writer.fileno())
            checksum = writer.digest.hexdigest()
            if writer.byte_count <= 0:
                raise RestoreError("stored backup zip is empty (0 bytes).")
            if expected and (
                writer.byte_count != expected["size_bytes"]
                or checksum != expected["sha256"]
            ):
                raise RestoreError(
                    "downloaded backup failed its committed SHA-256 integrity check."
                )
        verify_remote()
        os.replace(staging, destination)
        try:
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass
        return {"size_bytes": writer.byte_count, "sha256": checksum}
    finally:
        try:
            os.remove(staging)
        except FileNotFoundError:
            pass


def _normalise_remote_path(value, *, absolute):
    path = str(value or "").replace("\\", "/")
    if absolute and not path.startswith("/"):
        path = f"/{path}"
    while "//" in path:
        path = path.replace("//", "/")
    if "\x00" in path or any(part == ".." for part in path.split("/")):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the committed provider path is unsafe.",
        )
    return path.rstrip("/") or ("/" if absolute else "")


def _dropbox_value(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _dropbox_client(stored_backup):
    try:
        import dropbox as dropbox_sdk

        storage_config = stored_backup.storage.storage_dropbox
        key = stored_backup.storage.account.get_encryption_key()
        access_token = bs_decrypt(storage_config.access_token, key)
        refresh_token = None
        if getattr(storage_config, "refresh_token", None):
            refresh_token = bs_decrypt(storage_config.refresh_token, key)
        kwargs = {
            "oauth2_access_token": access_token,
            "app_key": getattr(settings, "DROPBOX_APP_KEY", None),
            "app_secret": getattr(settings, "DROPBOX_APP_SECRET", None),
            "timeout": max(
                0.1,
                float(
                    getattr(
                        settings,
                        "DROPBOX_API_TIMEOUT",
                        request_timeout()[1],
                    )
                ),
            ),
        }
        if refresh_token:
            kwargs["oauth2_refresh_token"] = refresh_token
        return dropbox_sdk.Dropbox(**kwargs)
    except _SafeProviderRestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("Dropbox", error) from None


def _validate_dropbox_metadata(entry, state, expected, artifact_identity):
    if entry is None:
        raise _safe_provider_failure("Dropbox", status=404)
    provider_id = str(
        _dropbox_value(entry, "id")
        or _dropbox_value(entry, "provider_id")
        or ""
    )
    path = _dropbox_value(entry, "path_display") or _dropbox_value(entry, "path")
    path_lower = _dropbox_value(entry, "path_lower")
    path = _normalise_remote_path(path, absolute=True)
    if path_lower:
        path_lower = _normalise_remote_path(path_lower, absolute=True).lower()
    if provider_id != state["provider_id"]:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Dropbox returned a different object identity for this backup.",
        )
    expected_path = _normalise_remote_path(state["provider_path"], absolute=True)
    if expected_path != f"/{artifact_identity.filename}":
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Dropbox backup path is not the deterministic BackupSheep destination.",
        )
    if path.lower() != expected_path.lower() or (
        path_lower and path_lower != expected_path.lower()
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Dropbox returned a different object path for this backup.",
        )
    try:
        remote_size = int(_dropbox_value(entry, "size"))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "Dropbox returned malformed backup metadata.",
        ) from None
    if remote_size != expected["size_bytes"]:
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "Dropbox backup metadata does not match the committed integrity record.",
        )
    revision = str(
        _dropbox_value(entry, "rev")
        or _dropbox_value(entry, "revision")
        or ""
    )
    committed_revision = str(state.get("revision") or state.get("version_id") or "")
    if not committed_revision or not revision or revision != committed_revision:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "Dropbox backup revision no longer matches the committed restore identity.",
        )
    committed_hash = str(state.get("content_hash") or "")
    remote_hash = str(_dropbox_value(entry, "content_hash") or "")
    if committed_hash and (not remote_hash or remote_hash != committed_hash):
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "Dropbox backup content metadata does not match the committed record.",
        )
    if state.get("ownership_marker") != (
        f"backupsheep:{artifact_identity.identifier}"
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Dropbox backup ownership metadata is not valid for this backup.",
        )
    return entry


def _dropbox_download(stored_backup, dest_zip_path, expected, state):
    artifact_identity = _restore_artifact_identity(
        stored_backup,
        object_key=state["provider_path"],
    )
    client = _dropbox_client(stored_backup)
    provider_id = state["provider_id"]
    if stored_backup.storage_file_id not in (None, "") and str(
        stored_backup.storage_file_id
    ) != provider_id:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "Dropbox storage identity disagrees with its committed provider ID.",
        )
    try:
        initial = client.files_get_metadata(provider_id)
        _validate_dropbox_metadata(initial, state, expected, artifact_identity)

        downloader = getattr(client, "files_download", None)
        if not callable(downloader):
            raise _SafeProviderRestoreError(
                "PROVIDER_UNSUPPORTED",
                "Dropbox does not expose an authenticated restore download.",
            )
        # Current Dropbox SDKs accept ``rev``.  If an older SDK does not expose
        # that keyword, the immutable file ID plus the pre/post revision checks
        # still prevents a silent path/current-object substitution.
        try:
            parameters = inspect.signature(downloader).parameters
        except (TypeError, ValueError):
            parameters = {}
        kwargs = {"rev": str(state.get("revision") or state.get("version_id"))}
        if parameters and "rev" not in parameters and not any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        ):
            kwargs = {}
        downloaded = downloader(provider_id, **kwargs)
        if not isinstance(downloaded, (tuple, list)) or len(downloaded) != 2:
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_RESPONSE",
                "Dropbox returned malformed restore download metadata.",
            )
        download_metadata, response = downloaded
        _validate_dropbox_metadata(
            download_metadata, state, expected, artifact_identity
        )
        try:
            def _verify_final():
                final = client.files_get_metadata(provider_id)
                _validate_dropbox_metadata(
                    final, state, expected, artifact_identity
                )

            _materialize_provider_stream(
                _response_chunks(response),
                dest_zip_path,
                expected,
                _verify_final,
            )
        except RestoreError:
            raise
        except Exception as error:
            raise _safe_provider_failure("Dropbox", error) from None
        finally:
            _close_response(response)
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("Dropbox", error) from None


def _pcloud_config_and_token(stored_backup):
    try:
        from apps._tasks.integration.storage import pcloud as pcloud_adapter

        config = stored_backup.storage.storage_pcloud
        getter = getattr(config, "get_access_token", None)
        if callable(getter):
            token = getter()
        else:
            key = stored_backup.storage.account.get_encryption_key()
            token = bs_decrypt(config.access_token, key)
        return pcloud_adapter, config, token
    except _SafeProviderRestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("pCloud", error) from None


def _pcloud_metadata(payload):
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    if isinstance(metadata, dict):
        return metadata
    if isinstance(metadata, list) and len(metadata) == 1 and isinstance(metadata[0], dict):
        return metadata[0]
    raise _SafeProviderRestoreError(
        "MALFORMED_PROVIDER_RESPONSE",
        "pCloud returned ambiguous backup metadata.",
    )


def _validate_pcloud_metadata(candidate, state, expected):
    if not isinstance(candidate, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "pCloud returned malformed backup metadata.",
        )
    provider_id = str(
        candidate.get("fileid") or candidate.get("file_id") or candidate.get("id") or ""
    )
    if provider_id != state["provider_id"]:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "pCloud returned a different object identity for this backup.",
        )
    path = _normalise_remote_path(candidate.get("path"), absolute=True)
    if path != _normalise_remote_path(state["provider_path"], absolute=True):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "pCloud returned a different object path for this backup.",
        )
    try:
        size = int(candidate.get("size"))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "pCloud returned malformed backup metadata.",
        ) from None
    if size != expected["size_bytes"]:
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "pCloud backup metadata does not match the committed integrity record.",
        )
    for state_field, candidate_fields in (
        ("revision", ("revision_id", "revisionid", "revision")),
        ("version_id", ("version_id", "revision_id", "revisionid", "revision")),
        ("provider_hash", ("hash",)),
    ):
        committed = str(state.get(state_field) or "")
        if not committed:
            continue
        remote = next(
            (str(candidate.get(field) or "") for field in candidate_fields if candidate.get(field)),
            "",
        )
        if not remote or remote != committed:
            raise _SafeProviderRestoreError(
                "PROVIDER_VERSION_DRIFT",
                "pCloud backup metadata no longer matches the committed restore identity.",
            )
    return candidate


def _pcloud_download(stored_backup, dest_zip_path, expected, state):
    adapter, config, token = _pcloud_config_and_token(stored_backup)
    provider_id = state["provider_id"]
    provider_path = _normalise_remote_path(state["provider_path"], absolute=True)
    artifact_identity = _restore_artifact_identity(
        stored_backup,
        object_key=provider_path,
    )
    expected_path = (
        f"/{_restore_node_slug(stored_backup)}/{artifact_identity.filename}"
        if _legacy_artifact_identity(artifact_identity)
        else f"/{artifact_identity.filename}"
    )
    if provider_path != expected_path:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "pCloud backup path is not the deterministic BackupSheep destination.",
        )
    if state.get("ownership_marker") != (
        f"backupsheep:{artifact_identity.identifier}"
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "pCloud backup ownership metadata is not valid for this artifact.",
        )
    if stored_backup.storage_file_id not in (None, "") and str(
        stored_backup.storage_file_id
    ) != provider_path:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "pCloud storage identity disagrees with its committed provider path.",
        )
    folder, filename = provider_path.rsplit("/", 1)
    folder = folder or "/"
    if not filename:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "pCloud backup provider path is malformed.",
        )
    try:
        metadata_payload = adapter._request_json(
            config,
            token,
            "GET",
            "stat",
            data={"fileid": provider_id},
        )
        candidate = _pcloud_metadata(metadata_payload)
        _validate_pcloud_metadata(candidate, state, expected)

        # Reuse the adapter's exact-file-id verification, including its provider
        # checksum fallback for pCloud regions that do not return SHA-256 from
        # checksumfile.  It intentionally receives the committed candidate and
        # never searches by the current path.
        try:
            verified = adapter._verify_candidate(
                config, token, candidate, folder, filename, expected
            )
        except Exception as error:
            raise _safe_provider_failure("pCloud", error) from None
        _validate_pcloud_metadata(verified, state, expected)

        link_payload = adapter._request_json(
            config,
            token,
            "GET",
            "getfilelink",
            data={"fileid": provider_id, "forcedownload": 1, "skipfilename": 1},
        )
        hosts = link_payload.get("hosts") or []
        path = str(link_payload.get("path") or "")
        if not isinstance(hosts, list) or len(hosts) != 1 or not path:
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_RESPONSE",
                "pCloud returned ambiguous restore download metadata.",
            )
        host = str(hosts[0]).lower()
        if host != "pcloud.com" and not host.endswith(".pcloud.com"):
            raise _SafeProviderRestoreError(
                "PROVIDER_OWNERSHIP_MISMATCH",
                "pCloud returned an untrusted restore download host.",
            )
        url = f"https://{host}{path if path.startswith('/') else '/' + path}"
        response = requests.get(
            url,
            stream=True,
            verify=True,
            timeout=DOWNLOAD_TIMEOUT,
        )
        _check_provider_response(response, "pCloud", allowed=(200,))
        try:
            def _verify_final():
                final_payload = adapter._request_json(
                    config,
                    token,
                    "GET",
                    "stat",
                    data={"fileid": provider_id},
                )
                _validate_pcloud_metadata(_pcloud_metadata(final_payload), state, expected)

            _materialize_provider_stream(
                _response_chunks(response),
                dest_zip_path,
                expected,
                _verify_final,
            )
        except RestoreError:
            raise
        except Exception as error:
            raise _safe_provider_failure("pCloud", error) from None
        finally:
            _close_response(response)
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("pCloud", error) from None


def _google_drive_item(client, provider_id):
    from apps._tasks.integration.storage import google_drive as google_adapter

    response = client.get(
        f"{google_adapter.DRIVE_API}/files/{quote(str(provider_id), safe='')}",
        params={"fields": google_adapter._file_fields()},
        headers={"Accept": "application/json"},
        timeout=DOWNLOAD_TIMEOUT,
    )
    _check_provider_response(response, "Google Drive", allowed=(200,))
    item = _response_json(response, "Google Drive")
    if not item or not item.get("id"):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "Google Drive returned malformed backup metadata.",
        )
    return item


def _validate_google_item(
    item,
    state,
    expected,
    artifact_identity,
    *,
    node_slug=None,
):
    from apps._tasks.integration.storage import google_drive as google_adapter

    if state.get("ownership_marker") not in (
        None,
        "",
        f"backupsheep:{artifact_identity.identifier}",
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive backup ownership metadata is not valid for this backup.",
        )
    if str(item.get("id") or "") != state["provider_id"]:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned a different object identity for this backup.",
        )
    expected_path = (
        f"BackupSheep/{node_slug}/{artifact_identity.filename}"
        if _legacy_artifact_identity(artifact_identity)
        else f"BackupSheep/{artifact_identity.filename}"
    )
    if (
        state["provider_path"] != expected_path
        or item.get("name") != artifact_identity.filename
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned a different object path for this backup.",
        )
    if (
        item.get("trashed") is True
        or item.get("mimeType") != artifact_identity.content_type
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned an object that is not the committed backup.",
        )
    parent_id = str(state.get("parent_id") or "")
    parents = {str(parent) for parent in item.get("parents") or []}
    if not parent_id or parent_id not in parents:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned a backup from a different folder.",
        )
    markers = google_adapter._marker_values(
        artifact_identity,
        expected,
        role="backup",
        node_slug=node_slug,
    )
    properties = {
        str(key): str(value) for key, value in (item.get("appProperties") or {}).items()
    }
    if any(properties.get(key) != str(value) for key, value in markers.items()):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive ownership metadata does not match this backup.",
        )
    try:
        size = int(item.get("size"))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "Google Drive returned malformed backup metadata.",
        ) from None
    if size != expected["size_bytes"]:
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "Google Drive backup metadata does not match the committed integrity record.",
        )
    version = str(item.get("version") or "")
    revision = str(item.get("headRevisionId") or "")
    if not state.get("version_id") or not state.get("revision"):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "Google Drive committed version metadata is incomplete.",
        )
    if version != str(state["version_id"]) or revision != str(state["revision"]):
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "Google Drive backup version no longer matches the committed restore identity.",
        )
    if state.get("md5_checksum") and str(item.get("md5Checksum") or "") != str(
        state["md5_checksum"]
    ):
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "Google Drive backup checksum metadata does not match the committed record.",
        )
    return item


def _google_drive_download(stored_backup, dest_zip_path, expected, state):
    try:
        from apps._tasks.integration.storage import google_drive as google_adapter

        storage_config = stored_backup.storage.storage_google_drive
        client = storage_config.get_client()
        artifact_identity = _restore_artifact_identity(
            stored_backup,
            object_key=state["provider_path"],
        )
        node_slug = (
            _restore_node_slug(stored_backup)
            if _legacy_artifact_identity(artifact_identity)
            else None
        )
        expected_path = (
            f"BackupSheep/{node_slug}/{artifact_identity.filename}"
            if node_slug is not None
            else f"BackupSheep/{artifact_identity.filename}"
        )
        if state["provider_path"] != expected_path:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Google Drive path disagrees with its encrypted artifact identity.",
            )
        if stored_backup.storage_file_id not in (None, "") and str(
            stored_backup.storage_file_id
        ) != state["provider_id"]:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Google Drive storage identity disagrees with its committed provider ID.",
            )
        item = _google_drive_item(client, state["provider_id"])
        _validate_google_item(
            item,
            state,
            expected,
            artifact_identity,
            node_slug=node_slug,
        )
        media_url = (
            f"{google_adapter.DRIVE_API}/files/"
            f"{quote(state['provider_id'], safe='')}?alt=media"
        )
        response = client.get(
            media_url,
            headers={"Accept": "application/octet-stream"},
            stream=True,
            timeout=DOWNLOAD_TIMEOUT,
        )
        _check_provider_response(response, "Google Drive", allowed=(200,))
        try:
            def _verify_final():
                final = _google_drive_item(client, state["provider_id"])
                _validate_google_item(
                    final,
                    state,
                    expected,
                    artifact_identity,
                    node_slug=node_slug,
                )

            _materialize_provider_stream(
                _response_chunks(response),
                dest_zip_path,
                expected,
                _verify_final,
            )
        except RestoreError:
            raise
        except Exception as error:
            raise _safe_provider_failure("Google Drive", error) from None
        finally:
            _close_response(response)
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("Google Drive", error) from None


def _object_marker_values(provider_adapter, artifact_identity, expected):
    markers = provider_adapter._marker_values(artifact_identity, expected)
    if not isinstance(markers, dict) or not markers:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the storage provider ownership marker is malformed.",
        )
    return {str(key): str(value) for key, value in markers.items()}


def _exact_object_key(stored_backup, config, artifact_identity):
    prefix = str(getattr(config, "prefix", "") or "")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    if _legacy_artifact_identity(artifact_identity):
        return (
            f"{prefix}{_restore_node_slug(stored_backup)}/"
            f"{artifact_identity.filename}"
        )
    return f"{prefix}{artifact_identity.filename}"


def _sdk_value(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    result = getattr(value, name, default)
    return default if result is None else result


def _sdk_metadata(value):
    metadata = _sdk_value(value, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "the storage provider returned malformed ownership metadata.",
        )
    return {str(key).lower(): str(item) for key, item in metadata.items()}


def _validate_google_cloud_blob(blob, state, expected, object_key, markers):
    if str(_sdk_value(blob, "name", "") or "") != object_key:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Cloud Storage returned a different object identity.",
        )
    if dict(state.get("ownership_marker") or {}) != markers:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Cloud Storage committed ownership metadata is invalid.",
        )
    remote_metadata = _sdk_metadata(blob)
    if any(
        remote_metadata.get(str(key).lower()) != str(value)
        for key, value in markers.items()
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Cloud Storage ownership metadata does not match this backup.",
        )
    try:
        remote_size = int(_sdk_value(blob, "size", -1))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "Google Cloud Storage returned malformed object metadata.",
        ) from None
    generation = str(state.get("generation") or state.get("version_id") or "")
    metageneration = str(state.get("metageneration") or "")
    etag = str(state.get("etag") or "")
    if (
        not generation
        or not metageneration
        or not etag
        or (state.get("version_id") and str(state["version_id"]) != generation)
    ):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "Google Cloud Storage committed generation metadata is incomplete.",
        )
    if (
        remote_size != expected["size_bytes"]
        or str(_sdk_value(blob, "generation", "") or "") != generation
        or str(_sdk_value(blob, "metageneration", "") or "") != metageneration
        or str(_sdk_value(blob, "etag", "") or "") != etag
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "Google Cloud Storage generation no longer matches the committed restore identity.",
        )
    return blob


def _google_cloud_download(stored_backup, dest_zip_path, expected, state):
    try:
        from apps._tasks.integration.storage import google_cloud as google_adapter

        config = stored_backup.storage.storage_google_cloud
        object_key = str(state["provider_path"])
        artifact_identity = _restore_artifact_identity(
            stored_backup,
            object_key=object_key,
        )
        expected_object_key = _exact_object_key(
            stored_backup,
            config,
            artifact_identity,
        )
        if (
            object_key != expected_object_key
            or state["provider_id"] != object_key
            or state["provider_path"] != object_key
            or str(state.get("object_key") or "") != object_key
            or str(stored_backup.storage_file_id or "") != object_key
        ):
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Google Cloud Storage identity disagrees with its committed object key.",
            )
        markers = _object_marker_values(
            google_adapter,
            artifact_identity,
            expected,
        )
        generation = str(state.get("generation") or state.get("version_id") or "")
        metageneration = str(state.get("metageneration") or "")
        try:
            generation_number = int(generation)
            metageneration_number = int(metageneration)
        except (TypeError, ValueError):
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_STATE",
                "Google Cloud Storage generation metadata is invalid.",
            ) from None

        credentials = config.get_credentials()
        client = google_adapter.gc_storage.Client(credentials=credentials)
        bucket = client.bucket(config.bucket_name)
        blob = bucket.blob(
            object_key,
            generation=generation_number,
            chunk_size=CHUNK_SIZE,
        )

        def _reload_and_verify():
            blob.reload(
                if_generation_match=generation_number,
                if_metageneration_match=metageneration_number,
                timeout=request_timeout(),
                retry=None,
            )
            _validate_google_cloud_blob(
                blob, state, expected, object_key, markers
            )

        _reload_and_verify()
        downloader = getattr(blob, "download_to_file", None)
        if not callable(downloader):
            raise _SafeProviderRestoreError(
                "STREAMING_DOWNLOAD_UNAVAILABLE",
                "Google Cloud Storage cannot stream this committed generation.",
            )
        # ``Blob.open`` is intentionally avoided: the current GCS SDK's reader
        # delegates each read to an in-memory byte-returning helper.  Write the
        # public chunked download directly through the hashing staging sink so a
        # multi-terabyte restore never requires two complete local copies.
        def _download(writer):
            downloader(
                writer,
                if_generation_match=generation_number,
                if_metageneration_match=metageneration_number,
                timeout=request_timeout(),
                retry=None,
                checksum=None,
                single_shot_download=False,
            )

        _materialize_provider_sdk_download(
            _download,
            dest_zip_path,
            expected,
            _reload_and_verify,
        )
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("Google Cloud Storage", error) from None


def _validate_azure_properties(properties, state, expected, markers):
    if dict(state.get("ownership_marker") or {}) != markers:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Azure Blob Storage committed ownership metadata is invalid.",
        )
    remote_metadata = _sdk_metadata(properties)
    if any(
        remote_metadata.get(str(key).lower()) != str(value)
        for key, value in markers.items()
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Azure Blob Storage ownership metadata does not match this backup.",
        )
    try:
        remote_size = int(
            _sdk_value(
                properties,
                "size",
                _sdk_value(properties, "content_length", -1),
            )
        )
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "Azure Blob Storage returned malformed object metadata.",
        ) from None
    version_id = str(state.get("version_id") or "")
    etag = str(state.get("etag") or "")
    remote_version = str(
        _sdk_value(
            properties,
            "version_id",
            _sdk_value(properties, "version", ""),
        )
        or ""
    )
    if not version_id or not etag:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "Azure Blob Storage committed version metadata is incomplete.",
        )
    if (
        remote_size != expected["size_bytes"]
        or str(_sdk_value(properties, "etag", "") or "") != etag
        or remote_version != version_id
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "Azure Blob Storage version no longer matches the committed restore identity.",
        )
    return properties


def _azure_timeout_kwargs():
    connect_timeout, read_timeout = request_timeout()
    return {
        "timeout": max(1, int(read_timeout)),
        "connection_timeout": connect_timeout,
        "read_timeout": read_timeout,
    }


def _azure_download(stored_backup, dest_zip_path, expected, state):
    try:
        from azure.core import MatchConditions
        from apps._tasks.integration.storage import azure as azure_adapter

        config = stored_backup.storage.storage_azure
        object_key = str(state["provider_path"])
        artifact_identity = _restore_artifact_identity(
            stored_backup,
            object_key=object_key,
        )
        expected_object_key = _exact_object_key(
            stored_backup,
            config,
            artifact_identity,
        )
        if (
            object_key != expected_object_key
            or state["provider_id"] != object_key
            or state["provider_path"] != object_key
            or str(state.get("object_key") or "") != object_key
            or str(stored_backup.storage_file_id or "") != object_key
        ):
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Azure Blob Storage identity disagrees with its committed object key.",
            )
        version_id = str(state.get("version_id") or "")
        etag = str(state.get("etag") or "")
        if not version_id or not etag:
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_STATE",
                "Azure Blob Storage committed version metadata is incomplete.",
            )
        markers = _object_marker_values(
            azure_adapter,
            artifact_identity,
            expected,
        )
        service = config.get_client()
        blob_client = service.get_blob_client(
            container=config.bucket_name,
            blob=object_key,
            version_id=version_id,
        )

        def _properties_and_verify():
            properties = blob_client.get_blob_properties(**_azure_timeout_kwargs())
            return _validate_azure_properties(
                properties, state, expected, markers
            )

        _properties_and_verify()
        downloader = blob_client.download_blob(
            offset=0,
            length=None,
            max_concurrency=1,
            etag=etag,
            match_condition=MatchConditions.IfNotModified,
            **_azure_timeout_kwargs(),
        )
        chunks = getattr(downloader, "chunks", None)
        if not callable(chunks):
            raise _SafeProviderRestoreError(
                "STREAMING_DOWNLOAD_UNAVAILABLE",
                "Azure Blob Storage cannot stream this committed blob version.",
            )
        _materialize_provider_stream(
            chunks(),
            dest_zip_path,
            expected,
            _properties_and_verify,
        )
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("Azure Blob Storage", error) from None


def _onedrive_headers(storage_config, *, media=False, etag=None):
    try:
        headers = dict(storage_config.get_client() or {})
    except Exception as error:
        raise _safe_provider_failure("OneDrive", error) from None
    if media:
        headers["Accept"] = "application/octet-stream"
    if etag:
        # Graph's content endpoint honours If-Match and returns 412 if the item
        # changed after the committed metadata was read.
        headers["If-Match"] = str(etag)
    return headers


def _onedrive_item(storage_config, provider_id):
    endpoint = str(settings.MS_GRAPH_ENDPOINT).rstrip("/")
    drive_id = quote(str(storage_config.drive_id), safe="")
    item_id = quote(str(provider_id), safe="")
    response = requests.get(
        f"{endpoint}/drives/{drive_id}/items/{item_id}",
        params={
            "$select": (
                "id,name,size,description,eTag,cTag,lastModifiedDateTime,"
                "parentReference,file,folder"
            )
        },
        headers=_onedrive_headers(storage_config),
        timeout=DOWNLOAD_TIMEOUT,
    )
    _check_provider_response(response, "OneDrive", allowed=(200,))
    item = _response_json(response, "OneDrive")
    if not item or not item.get("id"):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "OneDrive returned malformed backup metadata.",
        )
    return item


def _validate_onedrive_item(
    item,
    state,
    expected,
    artifact_identity,
    drive_id,
    *,
    node_slug=None,
):
    from apps._tasks.integration.storage import onedrive as onedrive_adapter

    persisted_marker = state.get("ownership_marker")
    expected_state_marker = f"backupsheep:{artifact_identity.identifier}"
    if persisted_marker not in (None, "", expected_state_marker):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive backup ownership metadata is not valid for this backup.",
        )
    provider_id = str(item.get("id") or "")
    if provider_id != state["provider_id"]:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive returned a different object identity for this backup.",
        )
    expected_path = (
        f"backupsheep/{node_slug}/{artifact_identity.filename}"
        if _legacy_artifact_identity(artifact_identity)
        else f"backupsheep/{artifact_identity.filename}"
    )
    if (
        state["provider_path"] != expected_path
        or item.get("name") != artifact_identity.filename
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive returned a different object path for this backup.",
        )
    marker = onedrive_adapter._marker(artifact_identity, expected)
    description = item.get("description")
    if description not in (None, ""):
        # A nonempty Graph description is authoritative. Business tenants may
        # omit it, but a wrong value must never be bypassed by session evidence.
        if description != marker:
            raise _SafeProviderRestoreError(
                "PROVIDER_OWNERSHIP_MISMATCH",
                "OneDrive ownership metadata does not match this backup.",
            )
    elif (
        _normalise_sha256(state.get("session_fingerprint")) is None
        or state.get("ownership_proof") != "session_and_verified_content"
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive Business omitted ownership metadata without a committed session proof.",
        )
    if isinstance(item.get("folder"), dict) or not isinstance(
        item.get("parentReference"), dict
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive returned a folder instead of the committed backup file.",
        )
    parent = item.get("parentReference") or {}
    remote_drive = str(parent.get("driveId") or "")
    if remote_drive and remote_drive != str(drive_id):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive returned a backup from a different drive.",
        )
    try:
        size = int(item.get("size"))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "OneDrive returned malformed backup metadata.",
        ) from None
    if size != expected["size_bytes"]:
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "OneDrive backup metadata does not match the committed integrity record.",
        )
    etag = str(item.get("eTag") or "")
    revision = str(item.get("cTag") or "")
    committed_etag = str(state.get("etag") or "")
    committed_revision = str(state.get("revision") or state.get("version_id") or "")
    if not committed_etag and not committed_revision:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "OneDrive committed version metadata is incomplete.",
        )
    if committed_etag and etag != committed_etag:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "OneDrive backup ETag no longer matches the committed restore identity.",
        )
    if committed_revision and revision != committed_revision:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "OneDrive backup revision no longer matches the committed restore identity.",
        )
    return item


def _onedrive_download(stored_backup, dest_zip_path, expected, state):
    try:
        storage_config = stored_backup.storage.storage_onedrive
        artifact_identity = _restore_artifact_identity(
            stored_backup,
            object_key=state["provider_path"],
        )
        node_slug = (
            _restore_node_slug(stored_backup)
            if _legacy_artifact_identity(artifact_identity)
            else None
        )
        drive_id = str(storage_config.drive_id)
        if stored_backup.storage_file_id not in (None, "") and str(
            stored_backup.storage_file_id
        ) != state["provider_path"]:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "OneDrive storage identity disagrees with its committed provider path.",
            )
        item = _onedrive_item(storage_config, state["provider_id"])
        _validate_onedrive_item(
            item,
            state,
            expected,
            artifact_identity,
            drive_id,
            node_slug=node_slug,
        )
        endpoint = str(settings.MS_GRAPH_ENDPOINT).rstrip("/")
        content_url = (
            f"{endpoint}/drives/{quote(drive_id, safe='')}"
            f"/items/{quote(state['provider_id'], safe='')}/content"
        )
        response = requests.get(
            content_url,
            headers=_onedrive_headers(
                storage_config,
                media=True,
                etag=state.get("etag"),
            ),
            stream=True,
            timeout=DOWNLOAD_TIMEOUT,
        )
        _check_provider_response(response, "OneDrive", allowed=(200,))
        try:
            def _verify_final():
                final = _onedrive_item(storage_config, state["provider_id"])
                _validate_onedrive_item(
                    final,
                    state,
                    expected,
                    artifact_identity,
                    drive_id,
                    node_slug=node_slug,
                )

            _materialize_provider_stream(
                _response_chunks(response),
                dest_zip_path,
                expected,
                _verify_final,
            )
        except RestoreError:
            raise
        except Exception as error:
            raise _safe_provider_failure("OneDrive", error) from None
        finally:
            _close_response(response)
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("OneDrive", error) from None


def _normalise_s3_version(value):
    value = str(value or "").strip()
    return "" if value.lower() == "null" else value


def _persist_s3_bucket_binding(stored_backup, state_key, expected_state, bucket):
    metadata = copy.deepcopy(getattr(stored_backup, "metadata", None) or {})
    current = metadata.get(state_key) if isinstance(metadata, dict) else None
    if not isinstance(current, dict) or not current:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed provider state changed during bucket verification.",
        )
    for field in (
        "phase",
        "object_key",
        "sha256",
        "size_bytes",
        "ownership_marker",
        "etag",
        "version_id",
    ):
        if current.get(field) != expected_state.get(field):
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "the committed provider state changed during bucket verification.",
            )
    existing = current.get("bucket")
    if existing is not None and existing != bucket:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed storage bucket binding changed during verification.",
        )
    current["bucket"] = bucket
    metadata[state_key] = current
    stored_backup.metadata = metadata
    stored_backup.save(update_fields=["metadata", "modified"])


def _committed_s3_etag(stored_backup, state, provider):
    """Return one committed ETag for an exact S3-compatible object."""
    etags = set()
    state_etag = str(state.get("etag") or "").strip()
    if state_etag and state_etag.lower() != "null":
        etags.add(state_etag)

    object_key = str(stored_backup.storage_file_id or "")
    try:
        artifact_etags = (
            stored_backup.backup.artifact_records.filter(
                storage_id=stored_backup.storage_id,
                role__in=("archive", "destination"),
                object_key=object_key,
                verified_at__isnull=False,
            )
            .exclude(etag__in=("", "null"))
            .values_list("etag", flat=True)
        )
        etags.update(
            str(etag).strip()
            for etag in artifact_etags
            if str(etag or "").strip().lower() != "null"
        )
    except (AttributeError, TypeError, ValueError):
        # In-memory restore doubles do not always expose the complete Django
        # queryset API. The durable provider state remains authoritative for
        # those callers; production models always take the query path above.
        pass

    if len(etags) > 1:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            f"the committed {provider} object ETag records disagree.",
        )
    return next(iter(etags), "")


def _s3_compatible_state(stored_backup, expected, provider_code):
    """Load one committed ``upload_verified_s3`` identity.

    The four S3-compatible adapters intentionally persist the same provider
    state shape.  Keep this validation strict: a row with a destination ledger
    but no complete provider state must stop, not become an unauthenticated
    current-object download.
    """
    metadata = getattr(stored_backup, "metadata", None) or {}
    if not isinstance(metadata, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    state_key = S3_COMPATIBLE_PROVIDER_STATE_KEYS[provider_code]
    if state_key not in metadata:
        has_other_committed_state = any(
            key in ALL_PROVIDER_STATE_KEYS
            and isinstance(candidate, dict)
            and str(candidate.get("phase") or "").lower() == "committed"
            for key, candidate in metadata.items()
        )
        if _destination_ledger_exists(stored_backup) or has_other_committed_state:
            raise _SafeProviderRestoreError(
                "MISSING_PROVIDER_STATE",
                "the committed backup has no provider identity for restore.",
            )
        return None

    raw_state = metadata.get(state_key)
    if not isinstance(raw_state, dict) or not raw_state:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    state = copy.deepcopy(raw_state)
    provider = str(state.get("provider") or "")
    if provider and provider != provider_code:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "stored backup provider state belongs to a different provider.",
        )
    if str(state.get("phase") or "").lower() != "committed":
        raise _SafeProviderRestoreError(
            "UNCOMMITTED_PROVIDER_STATE",
            "the selected backup provider object was not durably committed.",
        )
    bucket_is_unbound = "bucket" not in state
    bucket = state.get("bucket")
    if not bucket_is_unbound and (
        not isinstance(bucket, str) or not bucket or bucket != bucket.strip()
    ):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the committed backup has a malformed exact bucket binding.",
        )
    if str(state.get("checksum_algorithm") or "sha256").lower() != "sha256":
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has unsupported committed integrity metadata.",
        )

    object_key = str(state.get("object_key") or "")
    storage_file_id = str(getattr(stored_backup, "storage_file_id", "") or "")
    if not object_key or "\x00" in object_key or object_key != storage_file_id:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed object key disagrees with the storage point.",
        )
    artifact_identity = _restore_artifact_identity(
        stored_backup,
        object_key=object_key,
    )

    ownership_marker = str(state.get("ownership_marker") or "")
    if (
        not ownership_marker
        or ownership_marker != artifact_identity.ownership_marker
    ):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            f"the committed {S3_COMPATIBLE_PROVIDER_LABELS[provider_code]} object is not owned by this backup.",
        )

    state_checksum = _normalise_sha256(state.get("sha256"))
    try:
        state_size = int(state.get("size_bytes"))
    except (TypeError, ValueError):
        state_size = -1
    if state_checksum is None or state_size <= 0:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has invalid committed integrity metadata.",
        )
    if not expected or (
        expected["sha256"] != state_checksum
        or int(expected["size_bytes"]) != state_size
    ):
        raise _SafeProviderRestoreError(
            "INTEGRITY_LEDGER_CONFLICT",
            "the selected backup integrity records disagree; restore was stopped safely.",
        )

    state_etag = str(state.get("etag") or "").strip()
    if not state_etag or state_etag.lower() == "null":
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has no committed object ETag.",
        )
    committed_etag = _committed_s3_etag(
        stored_backup,
        state,
        S3_COMPATIBLE_PROVIDER_LABELS[provider_code],
    )
    if not committed_etag or committed_etag != state_etag:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed object ETag records disagree.",
        )

    if "version_id" not in state:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has no committed object version record.",
        )
    state_version = _normalise_s3_version(state.get("version_id"))
    try:
        committed_version = _normalise_s3_version(
            stored_backup.committed_version_id()
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed object version records disagree.",
        ) from None
    if state_version and committed_version and state_version != committed_version:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed object version records disagree.",
        )

    state.update(
        {
            "object_key": object_key,
            "sha256": state_checksum,
            "size_bytes": state_size,
            "etag": state_etag,
            "version_id": committed_version or state_version,
            "ownership_marker": ownership_marker,
            "bucket": bucket,
            "_legacy_bucket_unbound": bucket_is_unbound,
        }
    )
    return state


def _s3_compatible_binding(stored_backup, provider_code, *, expected_bucket=None):
    """Return the exact upload-time client, bucket, and safe provider label."""
    storage = stored_backup.storage
    encryption_key = storage.account.get_encryption_key()
    if provider_code == "do_spaces":
        from apps._tasks.integration.storage.do_spaces import _s3_client

        config = storage.storage_do_spaces
        client = _s3_client(config, encryption_key)
    elif provider_code == "upcloud":
        from apps._tasks.integration.storage.upcloud import _s3_client

        config = storage.storage_upcloud
        # This reuses normalize_upcloud_endpoint and the upload adapter's
        # explicit SigV4 configuration; an UpCloud endpoint is not a region.
        client = _s3_client(config, encryption_key)
    elif provider_code == "oracle":
        from apps._tasks.integration.storage.oracle import _s3_client

        config = storage.storage_oracle
        client = _s3_client(config, encryption_key)
    elif provider_code == "vultr":
        from apps._tasks.integration.storage.vultr import _s3_client

        config = storage.storage_vultr
        client = _s3_client(storage, encryption_key)
    else:
        raise _SafeProviderRestoreError(
            "PROVIDER_UNSUPPORTED",
            "the selected storage provider does not support exact restore materialization.",
        )
    bucket = str(getattr(config, "bucket_name", "") or "").strip()
    if not bucket:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected storage provider has no configured backup bucket.",
        )
    if expected_bucket is not None and bucket != expected_bucket:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the configured storage bucket differs from the committed backup binding.",
        )
    return client, bucket, S3_COMPATIBLE_PROVIDER_LABELS[provider_code]


def _is_multipart_etag(value):
    value = str(value or "").strip().strip('"').lower()
    digest, separator, part_count = value.rpartition("-")
    return bool(
        separator
        and len(digest) == 32
        and all(character in "0123456789abcdef" for character in digest)
        and part_count.isdigit()
        and int(part_count) > 1
    )


def _vultr_archive_restore_in_progress(head, provider_code):
    """Return whether Vultr is still rehydrating an authenticated archive."""
    if provider_code != "vultr" or not isinstance(head, dict):
        return False
    storage_class = str(head.get("StorageClass") or "").strip().upper()
    restore_state = str(head.get("Restore") or "").strip().lower()
    return (
        storage_class == "VULTR_ARCHIVE"
        and 'ongoing-request="true"' in restore_state
    )


def _validate_s3_compatible_head(
    head,
    state,
    expected,
    *,
    provider,
    allow_vultr_zero_length=False,
    allow_vultr_archive_etag_change=False,
    expected_transport_etag=None,
):
    """Verify provider metadata for the exact committed object version."""
    if not isinstance(head, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned malformed backup metadata.",
        )
    metadata = head.get("Metadata")
    if not isinstance(metadata, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned malformed backup metadata.",
        )
    normalized = {
        str(key).lower(): str(value)
        for key, value in metadata.items()
    }
    ownership_marker = str(state["ownership_marker"])
    artifact_marker = normalized.get("backupsheep-artifact-id")
    legacy_marker = normalized.get("backupsheep-backup-id")
    if ownership_marker.startswith("bse2:"):
        if legacy_marker is not None or normalized.get("backup") is not None:
            raise _SafeProviderRestoreError(
                "PROVIDER_OWNERSHIP_MISMATCH",
                f"the committed {provider} object has ambiguous ownership metadata.",
            )
        remote_marker = artifact_marker
    else:
        if artifact_marker is not None:
            raise _SafeProviderRestoreError(
                "PROVIDER_OWNERSHIP_MISMATCH",
                f"the committed {provider} object has ambiguous ownership metadata.",
            )
        remote_marker = legacy_marker
    if remote_marker != ownership_marker:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            f"the committed {provider} object is not owned by this backup.",
        )
    if normalized.get("backupsheep-sha256") != expected["sha256"]:
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            f"the committed {provider} object SHA-256 does not match the backup.",
        )
    try:
        remote_bytes = int(normalized["backupsheep-bytes"])
        content_length = int(head["ContentLength"])
    except (KeyError, TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned malformed backup size metadata.",
        ) from None
    # Vultr currently returns ``Content-Length: 0`` for HEAD on some committed
    # large multipart objects even though its immutable upload metadata, ETag,
    # and subsequent GET identify the full object.  Permit that response only
    # for an already-bound Vultr multipart ETag.  The GET response must still
    # declare the exact size, and the atomic materializer independently requires
    # the full committed byte count and SHA-256 before publication.
    safe_vultr_zero_length = bool(
        allow_vultr_zero_length
        and provider == S3_COMPATIBLE_PROVIDER_LABELS["vultr"]
        and content_length == 0
        and _is_multipart_etag(state.get("etag"))
    )
    if remote_bytes != expected["size_bytes"] or (
        content_length != expected["size_bytes"] and not safe_vultr_zero_length
    ):
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            f"the committed {provider} object byte count does not match the backup.",
        )

    remote_etag = str(head.get("ETag") or "").strip()
    if not remote_etag:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            f"{provider} returned no object ETag.",
        )
    committed_etag = str(state.get("etag") or "").strip()
    required_etag = (
        str(expected_transport_etag or "").strip()
        if expected_transport_etag is not None
        else committed_etag
    )
    restore_state = str(head.get("Restore") or "").strip().lower()
    # Vultr can rehydrate one archived multipart object into a different internal
    # multipart layout, changing only its transport ETag. The committed ETag stays
    # immutable in our ledger; the caller must pin this newly observed ETag across
    # GET and the final HEAD, while the streamed byte count and SHA remain exact.
    safe_vultr_archive_etag_change = bool(
        allow_vultr_archive_etag_change
        and provider == S3_COMPATIBLE_PROVIDER_LABELS["vultr"]
        and str(head.get("StorageClass") or "").strip().upper()
        == "VULTR_ARCHIVE"
        and (
            'ongoing-request="true"' in restore_state
            or 'ongoing-request="false"' in restore_state
        )
        and _is_multipart_etag(committed_etag)
    )
    if remote_etag != required_etag and not safe_vultr_archive_etag_change:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            f"the committed {provider} object ETag changed.",
        )

    expected_version = _normalise_s3_version(state.get("version_id"))
    remote_version = _normalise_s3_version(head.get("VersionId"))
    if remote_version != expected_version:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            f"the committed {provider} object version changed.",
        )
    return head


def _s3_compatible_download(stored_backup, dest_zip_path, expected, state, provider_code):
    """Download one exact committed S3-compatible object atomically."""
    client = None
    body = None
    provider = S3_COMPATIBLE_PROVIDER_LABELS[provider_code]
    try:
        legacy_bucket_unbound = bool(state.get("_legacy_bucket_unbound"))
        client, bucket, provider = _s3_compatible_binding(
            stored_backup,
            provider_code,
            expected_bucket=None if legacy_bucket_unbound else state["bucket"],
        )
        request = {
            "Bucket": bucket,
            "Key": state["object_key"],
        }
        version_id = _normalise_s3_version(state.get("version_id"))
        if version_id:
            request["VersionId"] = version_id

        def verified_head(expected_transport_etag=None):
            return _validate_s3_compatible_head(
                client.head_object(**request),
                state,
                expected,
                provider=provider,
                allow_vultr_zero_length=True,
                allow_vultr_archive_etag_change=(
                    provider_code == "vultr" and expected_transport_etag is None
                ),
                expected_transport_etag=expected_transport_etag,
            )

        initial = verified_head()
        transport_etag = str(initial.get("ETag") or "").strip()
        if legacy_bucket_unbound:
            _persist_s3_bucket_binding(
                stored_backup,
                S3_COMPATIBLE_PROVIDER_STATE_KEYS[provider_code],
                state,
                bucket,
            )
            state["bucket"] = bucket
            state["_legacy_bucket_unbound"] = False
        if _vultr_archive_restore_in_progress(initial, provider_code):
            raise _SafeProviderRestoreError(
                "RESTORE_ARCHIVE_NOT_READY",
                f"the committed {provider} archive is still being restored.",
                retryable=True,
                retry_after=120,
            )
        response = client.get_object(**request)
        _validate_s3_compatible_head(
            response,
            state,
            expected,
            provider=provider,
            expected_transport_etag=transport_etag,
        )
        body = response.get("Body") if isinstance(response, dict) else None
        if body is None or not callable(getattr(body, "read", None)):
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_RESPONSE",
                f"{provider} returned no readable backup stream.",
            )
        _materialize_provider_stream(
            iter(lambda: body.read(CHUNK_SIZE), b""),
            dest_zip_path,
            expected,
            lambda: verified_head(transport_etag),
        )
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure(provider, error) from None
    finally:
        _close_response(body)


def _idrive_s3_state(stored_backup, expected):
    """Load and validate the committed IDrive/S3-compatible object identity."""
    metadata = getattr(stored_backup, "metadata", None) or {}
    if not isinstance(metadata, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    state_key = PROVIDER_STATE_KEYS["idrive"]
    if state_key not in metadata:
        if _destination_ledger_exists(stored_backup):
            raise _SafeProviderRestoreError(
                "MISSING_PROVIDER_STATE",
                "the committed backup has no provider identity for restore.",
            )
        # Rows from before the object ledger was introduced remain on the
        # explicit legacy generate_download_url path.
        return None

    raw_state = metadata.get(state_key)
    if not isinstance(raw_state, dict) or not raw_state:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "stored backup provider state is malformed; restore was stopped safely.",
        )
    state = copy.deepcopy(raw_state)
    if str(state.get("phase") or "").lower() != "committed":
        raise _SafeProviderRestoreError(
            "UNCOMMITTED_PROVIDER_STATE",
            "the selected backup provider object was not durably committed.",
        )
    if str(state.get("checksum_algorithm") or "sha256").lower() != "sha256":
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has unsupported committed integrity metadata.",
        )

    object_key = str(state.get("object_key") or "")
    storage_file_id = str(stored_backup.storage_file_id or "")
    if not object_key or "\x00" in object_key:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has an invalid committed object key.",
        )
    if not storage_file_id or object_key != storage_file_id:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed object key disagrees with the storage point.",
        )
    _restore_artifact_identity(stored_backup, object_key=object_key)

    state_checksum = _normalise_sha256(state.get("sha256"))
    try:
        state_size = int(state.get("size_bytes"))
    except (TypeError, ValueError):
        state_size = -1
    if state_checksum is None or state_size <= 0:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has invalid committed integrity metadata.",
        )
    if not expected or (
        expected["sha256"] != state_checksum
        or int(expected["size_bytes"]) != state_size
    ):
        raise _SafeProviderRestoreError(
            "INTEGRITY_LEDGER_CONFLICT",
            "the selected backup integrity records disagree; restore was stopped safely.",
        )

    bucket_candidates = {
        str(state[field]).strip()
        for field in ("bucket", "bucket_name")
        if state.get(field) not in (None, "", "null")
    }
    if len(bucket_candidates) > 1:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed object bucket records disagree.",
        )

    state["object_key"] = object_key
    state["sha256"] = state_checksum
    state["size_bytes"] = state_size
    state["etag"] = _committed_s3_etag(
        stored_backup, state, "IDrive Object Storage"
    )
    if not state["etag"]:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the selected backup has no committed object ETag.",
        )

    state_version = _normalise_s3_version(state.get("version_id"))
    try:
        committed_version = _normalise_s3_version(
            stored_backup.committed_version_id()
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed object version records disagree.",
        ) from None
    if state_version and committed_version and state_version != committed_version:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed object version records disagree.",
        )
    state["version_id"] = committed_version or state_version
    if bucket_candidates:
        state["bucket_name"] = next(iter(bucket_candidates))
    return state


def _validate_idrive_s3_head(
    stored_backup,
    head,
    state,
    expected,
    *,
    bucket,
    object_key,
    etag,
    version_id,
):
    if not isinstance(head, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "IDrive Object Storage returned malformed backup metadata.",
        )
    reported_bucket = head.get("Bucket")
    reported_key = head.get("Key")
    if reported_bucket not in (None, bucket) or reported_key not in (None, object_key):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "IDrive Object Storage returned a different backup object.",
        )
    try:
        remote_size = int(head.get("ContentLength"))
    except (TypeError, ValueError):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "IDrive Object Storage returned malformed backup size metadata.",
        ) from None
    if not expected or remote_size != int(expected["size_bytes"]):
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "the committed IDrive Object Storage byte count changed.",
        )
    try:
        stored_backup.verify_s3_head_ownership(head)
    except Exception as error:
        message = str(error).lower()
        code = (
            "PROVIDER_VERSION_DRIFT"
            if "version" in message
            else "INTEGRITY_MISMATCH"
            if "integrity" in message
            else "PROVIDER_OWNERSHIP_MISMATCH"
        )
        raise _SafeProviderRestoreError(
            code,
            "the committed IDrive Object Storage object failed ownership or integrity verification.",
        ) from None

    remote_etag = str(head.get("ETag") or "").strip()
    if not remote_etag:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "IDrive Object Storage returned no object ETag.",
        )
    if remote_etag != etag:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed IDrive Object Storage object ETag changed.",
        )

    remote_version = _normalise_s3_version(head.get("VersionId"))
    if version_id and remote_version != version_id:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed IDrive Object Storage object version changed.",
        )
    if not version_id and remote_version:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed IDrive Object Storage object version was not recorded.",
        )
    return head


def _idrive_s3_download(stored_backup, dest_zip_path, expected, state):
    """Download one committed IDrive/S3-compatible object by exact identity."""
    provider = "IDrive Object Storage"
    response = None
    body = None
    try:
        storage_config = stored_backup.storage.storage_idrive
        bucket = str(getattr(storage_config, "bucket_name", "") or "").strip()
        object_key = state["object_key"]
        if not bucket:
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_STATE",
                "IDrive Object Storage has no configured backup bucket.",
            )
        if state.get("bucket_name") and state["bucket_name"] != bucket:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "the committed object bucket disagrees with the storage configuration.",
            )

        from apps._tasks.integration.storage import idrive as idrive_adapter

        # The adapter owns credential decryption and bounded/retrying boto
        # configuration. Credentials are passed only as the in-memory account
        # encryption key and never copied into restore metadata or exceptions.
        client = idrive_adapter._s3_client(
            storage_config,
            stored_backup.storage.account.get_encryption_key(),
        )
        version_id = _normalise_s3_version(state.get("version_id"))
        request = {"Bucket": bucket, "Key": object_key}
        if version_id:
            request["VersionId"] = version_id

        def verify_head():
            head = client.head_object(**request)
            return _validate_idrive_s3_head(
                stored_backup,
                head,
                state,
                expected,
                bucket=bucket,
                object_key=object_key,
                etag=state["etag"],
                version_id=version_id,
            )

        verify_head()
        response = client.get_object(**request)
        _validate_idrive_s3_head(
            stored_backup,
            response,
            state,
            expected,
            bucket=bucket,
            object_key=object_key,
            etag=state["etag"],
            version_id=version_id,
        )
        body = response.get("Body") if isinstance(response, dict) else None
        read = getattr(body, "read", None)
        if not callable(read):
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_RESPONSE",
                "IDrive Object Storage returned no readable backup stream.",
            )

        def chunks():
            while True:
                value = read(CHUNK_SIZE)
                if value == b"":
                    return
                if value is None or isinstance(value, str):
                    raise _SafeProviderRestoreError(
                        "MALFORMED_PROVIDER_RESPONSE",
                        "IDrive Object Storage returned a malformed backup stream.",
                    )
                try:
                    value = bytes(value)
                except (TypeError, ValueError):
                    raise _SafeProviderRestoreError(
                        "MALFORMED_PROVIDER_RESPONSE",
                        "IDrive Object Storage returned a malformed backup stream.",
                    ) from None
                if not value:
                    raise _SafeProviderRestoreError(
                        "MALFORMED_PROVIDER_RESPONSE",
                        "IDrive Object Storage returned a malformed backup stream.",
                    )
                yield value

        _materialize_provider_stream(
            chunks(),
            dest_zip_path,
            expected,
            verify_head,
        )
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure(provider, error) from None
    finally:
        _close_response(body)
        if response is not None and response is not body:
            _close_response(response)


def _aws_s3_committed_etag(stored_backup):
    """Return the one committed ETag for this exact storage object."""
    object_key = str(stored_backup.storage_file_id or "")
    etags = set(
        stored_backup.backup.artifact_records.filter(
            storage_id=stored_backup.storage_id,
            role__in=("archive", "destination"),
            object_key=object_key,
            verified_at__isnull=False,
        )
        .exclude(etag="")
        .values_list("etag", flat=True)
    )
    state = (stored_backup.metadata or {}).get("aws_s3_object") or {}
    if isinstance(state, dict) and state.get("etag"):
        etags.add(str(state["etag"]))
    if len(etags) > 1:
        raise _SafeProviderRestoreError(
            "PROVIDER_STATE_CONFLICT",
            "the committed AWS S3 ETag records disagree.",
        )
    return next(iter(etags), "")


def _aws_s3_committed_bucket(stored_backup):
    metadata = getattr(stored_backup, "metadata", None) or {}
    state = metadata.get("aws_s3_object") if isinstance(metadata, dict) else None
    if not isinstance(state, dict) or not state:
        raise _SafeProviderRestoreError(
            "MISSING_PROVIDER_STATE",
            "the committed AWS S3 backup has no durable provider state.",
        )
    if str(state.get("phase") or "").lower() != "committed":
        raise _SafeProviderRestoreError(
            "UNCOMMITTED_PROVIDER_STATE",
            "the selected AWS S3 object was not durably committed.",
        )
    if "bucket" not in state:
        return None
    bucket = state.get("bucket")
    if not isinstance(bucket, str) or not bucket or bucket != bucket.strip():
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the committed AWS S3 backup has a malformed exact bucket binding.",
        )
    return bucket


def _validate_aws_s3_head(stored_backup, head, expected, *, etag, version_id):
    if not isinstance(head, dict):
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_RESPONSE",
            "AWS S3 returned malformed backup metadata.",
        )
    try:
        stored_backup.verify_s3_head_ownership(head)
    except (TypeError, ValueError, RuntimeError) as error:
        message = str(error).lower()
        code = (
            "PROVIDER_VERSION_DRIFT"
            if "version" in message
            else "INTEGRITY_MISMATCH"
            if "integrity" in message
            else "PROVIDER_OWNERSHIP_MISMATCH"
        )
        raise _SafeProviderRestoreError(
            code,
            "the committed AWS S3 object failed ownership or integrity verification.",
        ) from error
    if expected and int(head.get("ContentLength", -1)) != int(expected["size_bytes"]):
        raise _SafeProviderRestoreError(
            "INTEGRITY_MISMATCH",
            "the committed AWS S3 object byte count changed.",
        )
    if etag and str(head.get("ETag") or "") != etag:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed AWS S3 object ETag changed.",
        )
    if version_id and str(head.get("VersionId") or "") != version_id:
        raise _SafeProviderRestoreError(
            "PROVIDER_VERSION_DRIFT",
            "the committed AWS S3 object version changed.",
        )
    return head


def _aws_s3_download(stored_backup, dest_zip_path, expected):
    """Download the exact committed S3 version through the authenticated SDK."""
    object_key = str(stored_backup.storage_file_id or "")
    if not object_key or "\x00" in object_key:
        raise _SafeProviderRestoreError(
            "INVALID_PROVIDER_PATH",
            "the committed AWS S3 object key is invalid.",
        )
    _restore_artifact_identity(stored_backup, object_key=object_key)
    try:
        storage_config = stored_backup.storage.storage_aws_s3
        values = storage_config._connection_values()
        committed_bucket = _aws_s3_committed_bucket(stored_backup)
        current_bucket = str(values.get("bucket_name") or "")
        if not current_bucket or current_bucket != current_bucket.strip():
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_STATE",
                "the configured AWS S3 backup bucket is invalid.",
            )
        if committed_bucket is not None and current_bucket != committed_bucket:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "the configured AWS S3 bucket differs from the committed backup binding.",
            )
        request_bucket = committed_bucket or current_bucket
        client = storage_config._s3_client(values)
        version_id = stored_backup.committed_version_id()
        etag = _aws_s3_committed_etag(stored_backup)
        request = {
            "Bucket": request_bucket,
            "Key": object_key,
            **storage_config.expected_bucket_owner_kwargs(
                values.get("expected_bucket_owner")
            ),
        }
        if version_id:
            request["VersionId"] = version_id

        def verified_head():
            head = client.head_object(**request)
            return _validate_aws_s3_head(
                stored_backup,
                head,
                expected,
                etag=etag,
                version_id=version_id,
            )

        initial = verified_head()
        if committed_bucket is None:
            legacy_state = copy.deepcopy(
                (getattr(stored_backup, "metadata", None) or {}).get(
                    "aws_s3_object"
                )
                or {}
            )
            _persist_s3_bucket_binding(
                stored_backup,
                "aws_s3_object",
                legacy_state,
                request_bucket,
            )
        if str(initial.get("StorageClass") or "") in {"GLACIER", "DEEP_ARCHIVE"}:
            if 'ongoing-request="false"' not in str(initial.get("Restore") or ""):
                raise RestoreError(
                    "backup is archived in Glacier/Deep Archive — restore it with the storage provider first"
                )
        response = client.get_object(**request)
        _validate_aws_s3_head(
            stored_backup,
            response,
            expected,
            etag=etag,
            version_id=version_id,
        )
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise _SafeProviderRestoreError(
                "MALFORMED_PROVIDER_RESPONSE",
                "AWS S3 returned no readable backup stream.",
            )
        try:
            _materialize_provider_stream(
                iter(lambda: body.read(CHUNK_SIZE), b""),
                dest_zip_path,
                expected,
                verified_head,
            )
        finally:
            _close_response(body)
    except RestoreError:
        raise
    except Exception as error:
        raise _safe_provider_failure("AWS S3", error) from None


def _fetch_exact_provider(stored_backup, dest_zip_path, expected, provider_code, state):
    if provider_code == "aws_s3":
        return _aws_s3_download(stored_backup, dest_zip_path, expected)
    if provider_code in S3_COMPATIBLE_PROVIDER_STATE_KEYS:
        return _s3_compatible_download(
            stored_backup,
            dest_zip_path,
            expected,
            state,
            provider_code,
        )
    if provider_code == "idrive":
        return _idrive_s3_download(stored_backup, dest_zip_path, expected, state)
    if provider_code == "azure":
        return _azure_download(stored_backup, dest_zip_path, expected, state)
    if provider_code == "dropbox":
        return _dropbox_download(stored_backup, dest_zip_path, expected, state)
    if provider_code == "google_cloud":
        return _google_cloud_download(
            stored_backup, dest_zip_path, expected, state
        )
    if provider_code == "pcloud":
        return _pcloud_download(stored_backup, dest_zip_path, expected, state)
    if provider_code == "google_drive":
        return _google_drive_download(stored_backup, dest_zip_path, expected, state)
    if provider_code == "onedrive":
        return _onedrive_download(stored_backup, dest_zip_path, expected, state)
    raise _SafeProviderRestoreError(
        "PROVIDER_UNSUPPORTED",
        "the selected storage provider does not support exact restore materialization.",
    )


def _local_restore_model_key(restore):
    model_name = str(getattr(getattr(restore, "_meta", None), "model_name", ""))
    value = {
        "corewebsiterestore": "website",
        "coredatabaserestore": "database",
    }.get(model_name)
    if value is None:
        raise RestoreError("the local restore handoff model is unsupported.")
    return value


def _open_local_restore_ciphertext(restore, stored_backup, encryption_plan):
    if restore is None or restore.storage_point_id != stored_backup.pk:
        raise RestoreError(
            "an encrypted local restore requires its durable restore handoff."
        )
    try:
        expected = restore_ciphertext_handoff_identity(restore, encryption_plan)
    except ArtifactPipelineError:
        raise RestoreError("the local restore handoff identity is invalid.") from None
    state = dict(
        (restore.execution_metadata or {}).get(
            "local_restore_ciphertext_handoff"
        )
        or {}
    )
    identity_matches = all(state.get(key) == value for key, value in expected.items())
    if state.get("status") in {"ready", "authenticated"} and not identity_matches:
        raise RestoreError("the local restore handoff evidence conflicts with its ledger.")
    if not identity_matches or state.get("status") not in {"ready", "authenticated"}:
        should_publish = True
        if identity_matches and state.get("status") == "staging":
            try:
                lease_expires_at = datetime.fromisoformat(
                    str(state.get("lease_expires_at") or "")
                )
                if timezone.is_naive(lease_expires_at):
                    lease_expires_at = timezone.make_aware(lease_expires_at)
                should_publish = lease_expires_at <= timezone.now()
            except (TypeError, ValueError):
                should_publish = True
        if should_publish:
            from apps._tasks.integration.storage.tasks import (
                stage_local_restore_ciphertext,
            )

            stage_local_restore_ciphertext.apply_async(
                args=[_local_restore_model_key(restore), restore.pk],
                task_id=local_restore_phase_task_id(restore, "stage"),
            )
        raise _SafeProviderRestoreError(
            "RESTORE_CIPHERTEXT_HANDOFF_PENDING",
            "the storage worker is preparing the authenticated local restore object.",
            retryable=True,
            retry_after=30,
        )

    from backupsheep.staging import open_restore_ciphertext

    try:
        return open_restore_ciphertext(
            expected["handoff_uuid"],
            expected["artifact_name"],
            backup_uuid=expected["backup_uuid"],
            target_lane=expected["target_lane"],
            installation_id=encryption_plan.context.installation_id,
        )
    except Exception:
        raise RestoreError(
            "the encrypted local restore handoff is missing or unsafe."
        ) from None


def _mark_local_restore_ciphertext_authenticated(restore, encryption_plan):
    expected = restore_ciphertext_handoff_identity(restore, encryption_plan)
    metadata = dict(restore.execution_metadata or {})
    state = dict(metadata.get("local_restore_ciphertext_handoff") or {})
    if not all(state.get(key) == value for key, value in expected.items()) or state.get(
        "status"
    ) not in {"ready", "authenticated"}:
        raise RestoreError("the local restore handoff witness changed during decryption.")
    try:
        allowed_fields = set(expected) | {"status", "ready_at"}
        if state["status"] == "authenticated":
            allowed_fields.add("authenticated_at")
        if set(state) != allowed_fields:
            raise ArtifactPipelineError(
                "The local restore handoff contains unreviewed evidence fields."
            )
        observed_at = timezone.now()
        ready_at, ready_time = _handoff_timestamp(state, "ready_at")
        authenticated_at = state.get("authenticated_at")
        if state["status"] == "authenticated":
            authenticated_at, authenticated_time = _handoff_timestamp(
                state, "authenticated_at"
            )
            if authenticated_time < ready_time:
                raise ArtifactPipelineError(
                    "The restore handoff authentication predates ciphertext readiness."
                )
            if authenticated_time > observed_at:
                raise ArtifactPipelineError(
                    "The restore handoff authentication is in the future."
                )
        else:
            if authenticated_at is not None:
                raise ArtifactPipelineError(
                    "A ready restore handoff contains an uncommitted authentication witness."
                )
            authenticated_at = observed_at.isoformat()
            _, authenticated_time = _handoff_timestamp(
                {"authenticated_at": authenticated_at}, "authenticated_at"
            )
            if authenticated_time < ready_time:
                raise ArtifactPipelineError(
                    "The restore handoff authentication clock predates ciphertext readiness."
                )
    except ArtifactPipelineError:
        raise RestoreError(
            "the local restore handoff timestamp witness is invalid."
        ) from None
    metadata["local_restore_ciphertext_handoff"] = {
        **expected,
        "status": "authenticated",
        "ready_at": ready_at,
        "authenticated_at": authenticated_at,
    }
    restore.execution_metadata = metadata
    restore.save(update_fields=["execution_metadata", "modified"])


def fetch_backup_zip(stored_backup, dest_zip_path, *, restore=None):
    """Materialize a verified ZIP; BSE1 is authenticated before ZIP publication."""

    try:
        encryption_plan = restore_encryption_plan(stored_backup)
    except ArtifactPipelineError:
        raise RestoreError(
            "stored backup encryption evidence is incomplete or inconsistent."
        ) from None
    expected = _expected_integrity(
        stored_backup,
        selected_artifact=(
            encryption_plan.artifact if encryption_plan is not None else None
        ),
    )
    if encryption_plan is not None:
        from backupsheep.staging import require_private_capacity

        require_private_capacity(
            required_bytes=(
                int(expected["size_bytes"])
                + int(encryption_plan.envelope.plaintext_byte_count)
            ),
            required_inodes=3,
        )
    materialized_path = (
        dest_zip_path
        if encryption_plan is None
        else f"{dest_zip_path}.{uuid.uuid4().hex}.bse1"
    )
    try:
        if stored_backup.storage.type.code == "local":
            if encryption_plan is None:
                source_path = _local_source_path(stored_backup.storage_file_id)
                source_context = open(source_path, "rb")
            else:
                source_context = _open_local_restore_ciphertext(
                    restore,
                    stored_backup,
                    encryption_plan,
                )
            with source_context as source:
                _materialize_stream(
                    iter(lambda: source.read(CHUNK_SIZE), b""),
                    materialized_path,
                    expected,
                )
        else:
            provider_code = str(
                getattr(stored_backup.storage.type, "code", "") or ""
            )
            downloaded_exact = False
            if provider_code in EXACT_PROVIDER_CODES:
                aws_s3_exact = provider_code == "aws_s3" and (
                    _destination_ledger_exists(stored_backup)
                    or "aws_s3_object" in (stored_backup.metadata or {})
                )
                # S3 identity is split across the destination artifact, version ID,
                # storage metadata, and provider-owned object metadata rather than a
                # single generic provider-state record.
                if provider_code == "aws_s3":
                    state = None
                elif provider_code == "idrive":
                    state = _idrive_s3_state(stored_backup, expected)
                elif provider_code in S3_COMPATIBLE_PROVIDER_STATE_KEYS:
                    state = _s3_compatible_state(
                        stored_backup,
                        expected,
                        provider_code,
                    )
                else:
                    state = _provider_state(stored_backup, provider_code, expected)
                if aws_s3_exact or state is not None:
                    _fetch_exact_provider(
                        stored_backup,
                        materialized_path,
                        expected,
                        provider_code,
                        state,
                    )
                    downloaded_exact = True
            if not downloaded_exact:
                # Provider-transport legacy is distinct from plaintext-artifact
                # legacy. A BSE1 object may still use this historical URL only when
                # no committed provider identity exists; its ciphertext digest and
                # full AEAD are verified below before any ZIP becomes visible.
                try:
                    if encryption_plan is None:
                        url = stored_backup.generate_download_url()
                    else:
                        url = stored_backup.generate_download_url(for_restore=True)
                except Exception:
                    raise RestoreError(
                        "unable to prepare the stored backup for download."
                    ) from None
                if url in GLACIER_SENTINELS:
                    raise RestoreError(
                        "backup is archived in Glacier/Deep Archive — restore it with the storage provider first"
                    )
                if not url:
                    raise RestoreError(
                        "unable to generate a download URL for the stored backup."
                    )
                try:
                    with requests.get(
                        url, stream=True, timeout=DOWNLOAD_TIMEOUT
                    ) as response:
                        response.raise_for_status()
                        _materialize_stream(
                            response.iter_content(chunk_size=CHUNK_SIZE),
                            materialized_path,
                            expected,
                        )
                except RestoreError:
                    raise
                except Exception:
                    raise RestoreError(
                        "unable to download the stored backup from its storage provider."
                    ) from None
        if encryption_plan is not None:
            try:
                unseal_downloaded_artifact(
                    encryption_plan,
                    materialized_path,
                    dest_zip_path,
                )
                if stored_backup.storage.type.code == "local":
                    _mark_local_restore_ciphertext_authenticated(
                        restore,
                        encryption_plan,
                    )
            except Exception:
                try:
                    os.remove(dest_zip_path)
                except FileNotFoundError:
                    pass
                raise RestoreError(
                    "stored backup ciphertext failed authenticated decryption."
                ) from None
        return dest_zip_path
    finally:
        if encryption_plan is not None:
            try:
                os.remove(materialized_path)
            except FileNotFoundError:
                pass


def _check_members(names, dest_root, kind):
    """Reject archive members whose extraction path would escape dest_root."""
    for name in names:
        target = os.path.realpath(os.path.join(dest_root, name))
        if target != dest_root and not target.startswith(dest_root + os.sep):
            raise RestoreError(f"unsafe path in backup {kind}: {name}")


def _normalise_zip_member_path(name):
    """Return the contract path and directory bit for one central entry."""
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or any(ord(character) < 32 for character in name)
        or (len(name) >= 2 and name[0].isalpha() and name[1] == ":")
    ):
        raise RestoreError("stored backup contains an unsafe archive path.")
    is_directory = name.endswith("/")
    lexical_name = name[:-1] if is_directory else name
    components = lexical_name.split("/")
    if not lexical_name or any(
        component in ("", ".", "..") for component in components
    ):
        raise RestoreError("stored backup contains an unsafe archive path.")
    return "/".join(components), is_directory


def _zip_member_kind(member, is_directory):
    unix_mode = (member.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if file_type and not (
        stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)
    ):
        raise RestoreError(
            "stored backup contains an unsupported special file."
        )
    if file_type and stat.S_ISDIR(unix_mode) != is_directory:
        raise RestoreError("stored backup contains an inconsistent member type.")
    if member.flag_bits & (0x1 | 0x40):
        raise RestoreError(
            "encrypted ZIP members are not supported for restore."
        )
    if member.compress_type not in (0, 8):
        raise RestoreError(
            "stored backup uses an unsupported ZIP compression method."
        )
    return 1 if is_directory else 0


def _check_file_ancestors(index, path):
    components = path.split("/")
    ancestors = [
        "/".join(components[:position])
        for position in range(1, len(components))
    ]
    for start in range(0, len(ancestors), 500):
        chunk = ancestors[start:start + 500]
        placeholders = ",".join("?" for _value in chunk)
        if chunk and index.execute(
            f"SELECT 1 FROM members WHERE kind = 0 AND path IN ({placeholders}) LIMIT 1",
            chunk,
        ).fetchone():
            raise RestoreError("stored backup contains conflicting archive paths.")


def _preflight_zip_members(zip_path, parent):
    """Spool collision state to SQLite while enforcing restore safety limits."""
    descriptor, index_path = tempfile.mkstemp(
        prefix=".backupsheep-zip-index-", suffix=".sqlite3", dir=parent
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
            "path TEXT PRIMARY KEY, kind INTEGER NOT NULL"
            ") WITHOUT ROWID"
        )

        maximum_members = int(
            getattr(settings, "RESTORE_MAX_ARCHIVE_MEMBERS", 2_100_000)
        )
        maximum_bytes = int(
            getattr(settings, "RESTORE_MAX_UNCOMPRESSED_BYTES", 2 * 1024 ** 4)
        )
        member_count = 0
        total_uncompressed = 0
        total_compressed = 0
        index.execute("BEGIN")
        for member in iter_zip_members(zip_path):
            member_count += 1
            if member_count > maximum_members:
                raise RestoreError(
                    "stored backup contains too many archive members."
                )
            path, is_directory = _normalise_zip_member_path(member.filename)
            kind = _zip_member_kind(member, is_directory)
            _check_file_ancestors(index, path)
            if kind == 0:
                prefix = path + "/"
                if index.execute(
                    "SELECT 1 FROM members "
                    "WHERE path >= ? AND path < ? LIMIT 1",
                    (prefix, path + "0"),
                ).fetchone():
                    raise RestoreError(
                        "stored backup contains conflicting archive paths."
                    )
            try:
                index.execute(
                    "INSERT INTO members(path, kind) VALUES (?, ?)",
                    (path, kind),
                )
            except sqlite3.IntegrityError as error:
                raise RestoreError(
                    "stored backup contains duplicate archive paths."
                ) from error

            total_uncompressed += int(member.file_size)
            total_compressed += int(member.compress_size)
            if total_uncompressed > maximum_bytes:
                raise RestoreError(
                    "stored backup expands beyond the configured restore safety limit."
                )
            if member_count % 10_000 == 0:
                index.commit()
                index.execute("BEGIN")
        index.commit()

        maximum_ratio = int(
            getattr(settings, "RESTORE_MAX_COMPRESSION_RATIO", 1000)
        )
        if total_uncompressed and (
            not total_compressed
            or total_uncompressed > total_compressed * maximum_ratio
        ):
            raise RestoreError(
                "stored backup has an unsafe compression expansion ratio."
            )
        free_bytes = shutil.disk_usage(parent).free
        reserve_bytes = int(
            getattr(settings, "RESTORE_DISK_RESERVE_BYTES", 512 * 1024 ** 2)
        )
        if total_uncompressed + reserve_bytes > free_bytes:
            raise RestoreError(
                "there is not enough free disk space to extract this backup safely."
            )
        return member_count
    except sqlite3.Error as error:
        raise RestoreError(
            "unable to build the archive safety index."
        ) from error
    finally:
        if index is not None:
            index.close()
        try:
            os.remove(index_path)
        except FileNotFoundError:
            pass


def extract_backup_zip(zip_path, dest_dir):
    """CRC-check and atomically extract a ZIP while rejecting unsafe members."""
    dest_root = os.path.realpath(dest_dir)
    parent = os.path.dirname(dest_root)
    os.makedirs(parent, exist_ok=True)
    staging_root = f"{dest_root}.{uuid.uuid4().hex}.partial"
    os.makedirs(staging_root, mode=0o700)
    try:
        # BackupSheep historically used Info-ZIP on UTF-8 Linux filesystems.
        # Info-ZIP preserved those raw UTF-8 filename bytes but omitted language
        # encoding bit 11, so standards-compliant readers decoded them as CP437
        # mojibake. ``zip_path`` is the worker-owned downloaded copy, not the
        # committed provider object. Repair only its header flags before the
        # normal CRC, collision, path, type, expansion, and disk checks.
        try:
            mark_utf8_zip_names(zip_path)
        except ValueError as error:
            raise RestoreError(
                "stored backup has inconsistent ZIP filename headers."
            ) from error
        try:
            member_count = _preflight_zip_members(zip_path, parent)
        except ValueError as error:
            raise RestoreError("stored backup is not a valid zip file.") from error

        if member_count:
            unzip_environment = os.environ.copy()
            unzip_environment.pop("UNZIPOPT", None)
            unzip_environment.pop("ZIPINFOOPT", None)
            try:
                process = subprocess.Popen(
                    ["unzip", "-UU", "-qq", "-o", zip_path, "-d", staging_root],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=unzip_environment,
                )
                process.wait()
            except OSError as error:
                raise RestoreError(
                    "unable to run the safe ZIP extractor."
                ) from error
            if process.returncode != 0:
                raise RestoreError("stored backup failed ZIP CRC validation.")
        if os.path.exists(dest_root):
            shutil.rmtree(dest_root)
        os.replace(staging_root, dest_root)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    return dest_root


def maybe_extract_tar(dest_dir, backup_uuid_str):
    """Unwrap legacy tar-wrapped website zips (backup_type FULL_V2).

    Those zips contain {uuid}.tar (+ {uuid}.files, backupsheep.txt) instead of the
    mirrored tree. When the tar is present it is extracted (same traversal safety)
    and removed. Returns the directory holding the restored tree (dest_dir either
    way).
    """
    dest_root = os.path.realpath(dest_dir)
    tar_path = os.path.join(dest_root, f"{backup_uuid_str}.tar")
    if not os.path.exists(tar_path):
        return dest_root
    with tarfile.open(tar_path) as tf:
        _check_members(tf.getnames(), dest_root, "tar")
        # filter="data" additionally blocks link members pointing outside dest_root.
        tf.extractall(dest_root, filter="data")
    os.remove(tar_path)
    return dest_root


# ---------------------------------------------------------------------------
# Restore notifications (email + activity log)
#
# The restore tasks in restore.py call the three notify_restore_* helpers at each
# status transition. One durable activity-log row carries a reviewed email-fanout
# request; only the logs lane resolves member identities and provider credentials.
#
# `backup` is None-tolerant throughout: a cloud restore only stores backup_id,
# and the source snapshot may be gone by the time the poll task finalizes.
# ---------------------------------------------------------------------------


def _restore_backup_name(backup, restore):
    if backup is not None:
        return backup.uuid_str
    return getattr(restore, "backup_id", None)


def _restore_context(node, backup, restore, message, error=None):
    """Context shared by the restore_* email templates. The action_url back to
    the node page is built in-template from the injected site_app_url + node_id."""
    return {
        "message": message,
        "node_id": node.id,
        "node_name": node.name,
        "connection_id": node.connection.id,
        "connection_name": node.connection.name,
        "backup_id": backup.id if backup is not None else None,
        "backup_name": _restore_backup_name(backup, restore),
        "restore_id": restore.id,
        "restore_name": restore.name,
        # Never place exception/provider text into email. Restore workers persist a
        # categorized safe status and keep full diagnostics in Sentry under the
        # correlation id.
        "error_details": (
            "The restore failed safely. Review its status and correlation ID in BackupSheep."
            if error
            else ""
        ),
        "help_url": "https://support.backupsheep.com",
        "sender_name": "BackupSheep - Notification Bot",
    }


def _record_restore_event(
    node,
    backup,
    restore,
    message,
    *,
    email_event,
    email_template,
    email_context,
):
    """Persist one RESTORE log plus a logs-lane email fanout request."""
    try:
        from apps.console.log.models import CoreLog

        account = node.connection.account
        account.create_log(
            data=email_context,
            email_event=email_event,
            email_template=email_template,
            log_type=CoreLog.Type.RESTORE,
        )
    except Exception as e:
        capture_exception(e)


def notify_restore_started(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has started."
    )
    _record_restore_event(
        node,
        backup,
        restore,
        message,
        email_event="fail",
        email_template="restore_started",
        email_context=_restore_context(node, backup, restore, message),
    )


def notify_restore_completed(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has completed."
    )
    _record_restore_event(
        node,
        backup,
        restore,
        message,
        email_event="success",
        email_template="restore_completed",
        email_context=_restore_context(node, backup, restore, message),
    )


def notify_restore_failed(node, backup, restore, error):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has failed."
    )
    _record_restore_event(
        node,
        backup,
        restore,
        message,
        email_event="fail",
        email_template="restore_failed",
        email_context=_restore_context(node, backup, restore, message, error=error),
    )
