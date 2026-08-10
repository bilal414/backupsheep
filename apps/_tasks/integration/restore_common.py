"""Shared helpers for the website/database restore engines.

A restore starts by materializing the stored backup zip onto the local disk:

  * 'Local Storage' backends keep the zip as a plain file under
    settings.LOCAL_STORAGE_ROOT (storage_file_id is its absolute path) -- it is
    copied from there, confined to the storage root.
  * Committed Dropbox, pCloud, Google Drive, OneDrive, Google Cloud Storage,
    and Azure copies are fetched through authenticated provider APIs using
    their durable object identity, ownership markers, and version/revision
    guards. The response is streamed through the atomic SHA-256/byte-count
    validator before publication.
  * Other remote backends, plus pre-ledger legacy copies, use the historical
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
import stat
import tarfile
import uuid
import zipfile
from urllib.parse import quote

from apps.api.v1.utils.http import requests
from apps.api.v1.utils.http import request_timeout
from apps.api.v1.utils.api_helpers import bs_decrypt
from django.conf import settings
from sentry_sdk import capture_exception

# (connect, read) timeout for the download URL fetch; 1 MiB stream chunks.
DOWNLOAD_TIMEOUT = (30, 300)
CHUNK_SIZE = 1024 * 1024

GLACIER_SENTINELS = ("restore_requested", "restore_in_progress")

# These providers historically exposed a browser/view URL from
# ``generate_download_url``.  A committed upload now contains a durable
# provider identity, so restore must authenticate to the provider directly and
# never turn a stored path into an unauthenticated/current-object download.
EXACT_PROVIDER_CODES = frozenset(
    {
        "aws_s3",
        "azure",
        "dropbox",
        "google_cloud",
        "google_drive",
        "onedrive",
        "pcloud",
    }
)
PROVIDER_STATE_KEYS = {
    "azure": "azure_blob_object",
    "dropbox": "dropbox_object",
    "google_cloud": "google_cloud_object",
    "pcloud": "pcloud_object",
    "google_drive": "google_drive_upload",
    "onedrive": "onedrive_upload",
}


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


def _expected_integrity(stored_backup):
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

    def key_matches(candidate):
        candidate = str(candidate or "")
        if candidate == object_key:
            return True
        if stored_backup.storage.type.code != "local" or not candidate:
            return False
        try:
            root = stored_backup.storage.storage_local.storage_root()
            candidate_path = os.path.realpath(os.path.join(root, candidate))
            return candidate_path == os.path.realpath(object_key)
        except (AttributeError, OSError, ValueError):
            return False

    artifacts = backup.artifact_records.filter(
        storage_id=storage_id,
        verified_at__isnull=False,
        role__in=("archive", "destination"),
    )
    for artifact in artifacts:
        if artifact.object_key and not key_matches(artifact.object_key):
            continue
        checksum = _normalise_sha256(artifact.checksum_value)
        if str(artifact.checksum_algorithm or "").lower() == "sha256" and checksum:
            candidates.append((int(artifact.byte_count), checksum, "artifact ledger"))

    for state in (stored_backup.metadata or {}).values():
        if not isinstance(state, dict):
            continue
        state_key = str(state.get("object_key") or object_key)
        checksum = _normalise_sha256(state.get("sha256"))
        byte_count = state.get("size_bytes")
        if not key_matches(state_key) or checksum is None or byte_count is None:
            continue
        try:
            candidates.append((int(byte_count), checksum, "storage metadata"))
        except (TypeError, ValueError):
            raise RestoreError("stored backup integrity metadata is invalid.")

    identities = {(size, checksum) for size, checksum, _source in candidates}
    if len(identities) > 1:
        raise RestoreError(
            "stored backup integrity records disagree; restore was stopped safely."
        )
    if identities:
        size, checksum = identities.pop()
        if size <= 0:
            raise RestoreError("stored backup integrity metadata has an invalid size.")
        return {"size_bytes": size, "sha256": checksum}

    source_is_committed = backup.artifact_records.filter(
        storage__isnull=True,
        role="source",
        verified_at__isnull=False,
    ).exists()
    if source_is_committed:
        raise RestoreError(
            "this backup has no committed integrity record for the selected storage copy."
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


def _restore_backup_uuid(stored_backup):
    value = str(
        getattr(stored_backup.backup, "uuid_str", None)
        or getattr(stored_backup.backup, "uuid", "")
        or ""
    )
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or os.path.basename(value) != value
    ):
        raise _SafeProviderRestoreError(
            "INVALID_BACKUP_ID",
            "stored backup provider state contains an invalid backup identity.",
        )
    return value


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


def _destination_ledger_exists(stored_backup):
    """Return whether a durable destination artifact exists for this row."""
    relation = getattr(stored_backup.backup, "artifact_records", None)
    if relation is None:
        return False
    try:
        return bool(
            relation.filter(
                storage_id=stored_backup.storage_id,
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


def _validate_dropbox_metadata(entry, state, expected, backup_uuid):
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
    if expected_path != f"/{backup_uuid}.zip":
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
    if state.get("ownership_marker") != f"backupsheep:{backup_uuid}":
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Dropbox backup ownership metadata is not valid for this backup.",
        )
    return entry


def _dropbox_download(stored_backup, dest_zip_path, expected, state):
    backup_uuid = _restore_backup_uuid(stored_backup)
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
        _validate_dropbox_metadata(initial, state, expected, backup_uuid)

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
            download_metadata, state, expected, backup_uuid
        )
        try:
            def _verify_final():
                final = client.files_get_metadata(provider_id)
                _validate_dropbox_metadata(final, state, expected, backup_uuid)

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
    expected_path = f"/{_restore_node_slug(stored_backup)}/{_restore_backup_uuid(stored_backup)}.zip"
    if provider_path != expected_path:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "pCloud backup path is not the deterministic BackupSheep destination.",
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


def _validate_google_item(item, state, expected, backup_uuid, node_slug):
    from apps._tasks.integration.storage import google_drive as google_adapter

    if state.get("ownership_marker") not in (None, "", f"backupsheep:{backup_uuid}"):
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive backup ownership metadata is not valid for this backup.",
        )
    if str(item.get("id") or "") != state["provider_id"]:
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned a different object identity for this backup.",
        )
    expected_path = f"BackupSheep/{node_slug}/{backup_uuid}.zip"
    if state["provider_path"] != expected_path or item.get("name") != f"{backup_uuid}.zip":
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "Google Drive returned a different object path for this backup.",
        )
    if item.get("trashed") is True or item.get("mimeType") != google_adapter.ZIP_MIME:
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
        backup_uuid,
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
        backup_uuid = _restore_backup_uuid(stored_backup)
        node_slug = _restore_node_slug(stored_backup)
        if stored_backup.storage_file_id not in (None, "") and str(
            stored_backup.storage_file_id
        ) != state["provider_id"]:
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Google Drive storage identity disagrees with its committed provider ID.",
            )
        item = _google_drive_item(client, state["provider_id"])
        _validate_google_item(item, state, expected, backup_uuid, node_slug)
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
                _validate_google_item(final, state, expected, backup_uuid, node_slug)

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


def _object_marker_values(provider_adapter, backup_uuid, expected):
    markers = provider_adapter._marker_values(backup_uuid, expected)
    if not isinstance(markers, dict) or not markers:
        raise _SafeProviderRestoreError(
            "MALFORMED_PROVIDER_STATE",
            "the storage provider ownership marker is malformed.",
        )
    return {str(key): str(value) for key, value in markers.items()}


def _exact_object_key(stored_backup, config):
    prefix = str(getattr(config, "prefix", "") or "")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return f"{prefix}{_restore_node_slug(stored_backup)}/{_restore_backup_uuid(stored_backup)}.zip"


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
        object_key = _exact_object_key(stored_backup, config)
        if (
            state["provider_id"] != object_key
            or state["provider_path"] != object_key
            or str(state.get("object_key") or "") != object_key
            or str(stored_backup.storage_file_id or "") != object_key
        ):
            raise _SafeProviderRestoreError(
                "PROVIDER_STATE_CONFLICT",
                "Google Cloud Storage identity disagrees with its committed object key.",
            )
        backup_uuid = _restore_backup_uuid(stored_backup)
        markers = _object_marker_values(google_adapter, backup_uuid, expected)
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
        object_key = _exact_object_key(stored_backup, config)
        if (
            state["provider_id"] != object_key
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
            _restore_backup_uuid(stored_backup),
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


def _validate_onedrive_item(item, state, expected, backup_uuid, node_slug, drive_id):
    if state.get("ownership_marker") not in (None, "", f"backupsheep:{backup_uuid}"):
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
    expected_path = f"backupsheep/{node_slug}/{backup_uuid}.zip"
    if state["provider_path"] != expected_path or item.get("name") != f"{backup_uuid}.zip":
        raise _SafeProviderRestoreError(
            "PROVIDER_OWNERSHIP_MISMATCH",
            "OneDrive returned a different object path for this backup.",
        )
    marker = (
        f"BackupSheep backup uuid={backup_uuid};"
        f"sha256={expected['sha256']};bytes={expected['size_bytes']}"
    )
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
        backup_uuid = _restore_backup_uuid(stored_backup)
        node_slug = _restore_node_slug(stored_backup)
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
            item, state, expected, backup_uuid, node_slug, drive_id
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
                    final, state, expected, backup_uuid, node_slug, drive_id
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
    try:
        storage_config = stored_backup.storage.storage_aws_s3
        values = storage_config._connection_values()
        client = storage_config._s3_client(values)
        version_id = stored_backup.committed_version_id()
        etag = _aws_s3_committed_etag(stored_backup)
        request = {
            "Bucket": values["bucket_name"],
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


def fetch_backup_zip(stored_backup, dest_zip_path):
    """Materialize the stored backup zip at dest_zip_path (a local file path)."""
    expected = _expected_integrity(stored_backup)
    if stored_backup.storage.type.code == "local":
        source_path = _local_source_path(stored_backup.storage_file_id)
        with open(source_path, "rb") as source:
            _materialize_stream(
                iter(lambda: source.read(CHUNK_SIZE), b""),
                dest_zip_path,
                expected,
            )
    else:
        provider_code = str(getattr(stored_backup.storage.type, "code", "") or "")
        if provider_code in EXACT_PROVIDER_CODES:
            aws_s3_exact = provider_code == "aws_s3" and (
                _destination_ledger_exists(stored_backup)
                or "aws_s3_object" in (stored_backup.metadata or {})
            )
            # S3 identity is split across the destination artifact, version ID,
            # storage metadata, and provider-owned object metadata rather than a
            # single generic provider-state record.
            state = (
                None
                if provider_code == "aws_s3"
                else _provider_state(stored_backup, provider_code, expected)
            )
            if aws_s3_exact or state is not None:
                _fetch_exact_provider(
                    stored_backup,
                    dest_zip_path,
                    expected,
                    provider_code,
                    state,
                )
                return dest_zip_path
        # Explicit legacy path: only a row with no destination ledger and no
        # committed provider state may use the historical URL method.  This is
        # retained for backups created before provider identity ledgers existed;
        # it is never a fallback for a missing/mismatched committed object.
        try:
            url = stored_backup.generate_download_url()
        except Exception:
            raise RestoreError(
                "unable to prepare the stored backup for download."
            ) from None
        if url in GLACIER_SENTINELS:
            raise RestoreError(
                "backup is archived in Glacier/Deep Archive — restore it with the storage provider first"
            )
        if not url:
            raise RestoreError("unable to generate a download URL for the stored backup.")
        try:
            with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as response:
                response.raise_for_status()
                _materialize_stream(
                    response.iter_content(chunk_size=CHUNK_SIZE),
                    dest_zip_path,
                    expected,
                )
        except RestoreError:
            raise
        except Exception:
            raise RestoreError(
                "unable to download the stored backup from its storage provider."
            ) from None
    return dest_zip_path


def _check_members(names, dest_root, kind):
    """Reject archive members whose extraction path would escape dest_root."""
    for name in names:
        target = os.path.realpath(os.path.join(dest_root, name))
        if target != dest_root and not target.startswith(dest_root + os.sep):
            raise RestoreError(f"unsafe path in backup {kind}: {name}")


def extract_backup_zip(zip_path, dest_dir):
    """CRC-check and atomically extract a ZIP while rejecting unsafe members."""
    dest_root = os.path.realpath(dest_dir)
    parent = os.path.dirname(dest_root)
    os.makedirs(parent, exist_ok=True)
    staging_root = f"{dest_root}.{uuid.uuid4().hex}.partial"
    os.makedirs(staging_root, mode=0o700)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            maximum_members = int(
                getattr(settings, "RESTORE_MAX_ARCHIVE_MEMBERS", 1_000_000)
            )
            if len(infos) > maximum_members:
                raise RestoreError("stored backup contains too many archive members.")

            _check_members((info.filename for info in infos), staging_root, "zip")
            normalised_names = set()
            total_uncompressed = 0
            total_compressed = 0
            for info in infos:
                normalised = os.path.normcase(os.path.normpath(info.filename))
                if normalised in normalised_names:
                    raise RestoreError(
                        "stored backup contains duplicate archive paths."
                    )
                normalised_names.add(normalised)
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if file_type and not (
                    stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)
                ):
                    raise RestoreError(
                        "stored backup contains an unsupported special file."
                    )
                if info.flag_bits & 0x1:
                    raise RestoreError(
                        "encrypted ZIP members are not supported for restore."
                    )
                total_uncompressed += int(info.file_size)
                total_compressed += int(info.compress_size)

            maximum_bytes = int(
                getattr(settings, "RESTORE_MAX_UNCOMPRESSED_BYTES", 2 * 1024 ** 4)
            )
            if total_uncompressed > maximum_bytes:
                raise RestoreError(
                    "stored backup expands beyond the configured restore safety limit."
                )
            maximum_ratio = int(
                getattr(settings, "RESTORE_MAX_COMPRESSION_RATIO", 1000)
            )
            if total_compressed > 0 and total_uncompressed > total_compressed * maximum_ratio:
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

            bad_member = zf.testzip()
            if bad_member:
                raise RestoreError(
                    "stored backup failed ZIP CRC validation."
                )
            zf.extractall(staging_root)
        if os.path.exists(dest_root):
            shutil.rmtree(dest_root)
        os.replace(staging_root, dest_root)
    except zipfile.BadZipFile as e:
        raise RestoreError("stored backup is not a valid zip file.") from e
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
# The restore tasks in restore.py call the three notify_restore_* helpers at
# each status transition. Both side effects are individually wrapped so a
# notification problem can never break the restore itself:
#
#   * an activity-log entry via CoreLog.record(account, CoreLog.Type.RESTORE, data)
#   * an email (restore_started / restore_completed / restore_failed template)
#     to every get_notification_recipients() member -- "success" for a completed
#     restore, "fail" for started/failed.
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


def _record_restore_event(node, backup, restore, message):
    """Emit a RESTORE activity-log entry; a log failure never breaks a restore."""
    try:
        from apps.console.log.models import CoreLog

        account = node.connection.account
        data = {
            "message": message,
            "node_id": node.id,
            "node_name": node.name,
            "connection_id": node.connection.id,
            "connection_name": node.connection.name,
            "backup_id": backup.id if backup is not None else None,
            "backup_name": _restore_backup_name(backup, restore),
            "restore_id": restore.id,
            "restore_name": restore.name,
        }
        CoreLog.record(account, CoreLog.Type.RESTORE, data)
    except Exception as e:
        capture_exception(e)


def _email_restore_recipients(node, event, template, context):
    """Email a restore notification to every eligible member for `event`."""
    try:
        from apps._tasks.helper.tasks import send_postmark_email

        account = node.connection.account
        for _member, to_email in account.get_notification_recipients(event):
            send_postmark_email.delay(to_email, template, context)
    except Exception as e:
        capture_exception(e)


def notify_restore_started(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has started."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "fail", "restore_started", _restore_context(node, backup, restore, message)
    )


def notify_restore_completed(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has completed."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "success", "restore_completed", _restore_context(node, backup, restore, message)
    )


def notify_restore_failed(node, backup, restore, error):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has failed."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "fail", "restore_failed",
        _restore_context(node, backup, restore, message, error=error),
    )
