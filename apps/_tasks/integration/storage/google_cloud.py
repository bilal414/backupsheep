"""Crash-safe, integrity-verified Google Cloud Storage uploads.

The durable recovery boundary combines an encrypted resumable-session URL with
an immutable object name and generation precondition.  Before any provider
write, the adapter persists the target identity and ownership markers.  A new
worker can therefore resume the same session or adopt exactly one committed
generation without creating a second object.
"""

from __future__ import annotations

import hashlib
import os
import base64

from django.utils import timezone
from google.api_core import exceptions as google_exceptions
from google.cloud import storage as gc_storage
from requests import exceptions as requests_exceptions

from apps._tasks.exceptions import StorageGoogleCloudUploadFailedError
from apps._tasks.artifact_encryption import (
    storage_artifact_identity,
    validate_storage_object_key,
)
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadReconciliationRequired,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.api.v1.utils.http import request_timeout
from apps.console.backup.models import StoragePointLeaseLostError
from apps.console.connection.models import (
    _BoundedGoogleAuthorizedSession,
    _provider_sdk_timeout,
)


STATE_KEY = "google_cloud_object"
CHECKSUM_ALGORITHM = "sha256"
NAMESPACE = "backupsheep-v1"
OBJECT_CONTENT_TYPE = "application/octet-stream"
CHUNK_SIZE = 8 * 1024 * 1024
MAX_PROVIDER_ATTEMPTS = 3
SAFE_UPLOAD = "Google Cloud Storage could not verify the backup upload. Please retry."
SAFE_TIMEOUT = (
    "Google Cloud Storage did not respond before the request deadline. Please retry."
)
SAFE_AUTH = "Google Cloud Storage rejected the configured credentials or permissions."
SAFE_NOT_FOUND = "The configured Google Cloud Storage bucket was not found."
SAFE_RECONCILIATION = (
    "Google Cloud Storage returned ambiguous upload state; automatic writes were stopped safely."
)
SAFE_INTEGRITY = "Google Cloud Storage returned bytes that do not match the backup artifact."
SAFE_OWNERSHIP = (
    "Google Cloud Storage ownership verification failed; no unrelated object was changed."
)


class GoogleCloudUploadFailure(StorageGoogleCloudUploadFailedError):
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


class GoogleCloudIntegrityFailure(GoogleCloudUploadFailure, S3ObjectIntegrityError):
    def __init__(self, message=SAFE_INTEGRITY, *, stored_backup=None):
        super().__init__(
            "STORAGE_INTEGRITY_FAILED",
            retryable=False,
            message=message,
            stored_backup=stored_backup,
        )


class GoogleCloudReconciliationRequired(
    GoogleCloudUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self, message=SAFE_RECONCILIATION, *, stored_backup=None):
        super().__init__(
            "STORAGE_RECONCILIATION_REQUIRED",
            retryable=False,
            message=message,
            stored_backup=stored_backup,
        )


class GoogleCloudOwnershipFailure(
    GoogleCloudUploadFailure, S3UploadReconciliationRequired
):
    def __init__(self, *, stored_backup=None):
        super().__init__(
            "PROVIDER_OWNERSHIP_MISMATCH",
            retryable=False,
            message=SAFE_OWNERSHIP,
            stored_backup=stored_backup,
        )


class _GoogleCloudSourceInvalid(GoogleCloudIntegrityFailure):
    def __init__(self, *, stored_backup=None):
        super().__init__(
            "The committed local backup artifact failed integrity validation.",
            stored_backup=stored_backup,
        )
        self.code = "SOURCE_ARTIFACT_INVALID"
        self.error_code = self.code


class _GoogleCloudSourceMissing(FileNotFoundError):
    """Internal source marker whose message intentionally contains no path."""


class _DigestWriter:
    """Minimal file-like sink that hashes a provider stream without buffering it."""

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
    """Extract only a numeric provider status; never stringify the exception."""
    value = getattr(error, "status_code", None)
    if value is None:
        response = getattr(error, "response", None)
        value = getattr(response, "status_code", None)
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
            google_exceptions.DeadlineExceeded,
        ),
    ):
        return GoogleCloudUploadFailure(
            "PROVIDER_TIMEOUT",
            status_code=status,
            retryable=True,
            message=SAFE_TIMEOUT,
            stored_backup=stored_backup,
        )
    if status in {401, 403}:
        return GoogleCloudUploadFailure(
            "STORAGE_AUTH_FAILED",
            status_code=status,
            retryable=False,
            message=SAFE_AUTH,
            stored_backup=stored_backup,
        )
    if status == 404:
        return GoogleCloudUploadFailure(
            "STORAGE_DESTINATION_NOT_FOUND",
            status_code=status,
            retryable=False,
            message=SAFE_NOT_FOUND,
            stored_backup=stored_backup,
        )
    if status == 429:
        return GoogleCloudUploadFailure(
            "STORAGE_RATE_LIMITED",
            status_code=status,
            retryable=True,
            retry_after=retry_after,
            message="Google Cloud Storage rate limited the upload; it will resume automatically.",
            stored_backup=stored_backup,
        )
    if status in {408, 425, 409, 412} or (status is not None and status >= 500):
        return GoogleCloudUploadFailure(
            "PROVIDER_TRANSIENT_FAILURE",
            status_code=status,
            retryable=True,
            stored_backup=stored_backup,
        )
    # google-auth and the GCS transport can raise non-HTTP network errors.  They
    # are retryable, but their text can contain URLs, headers, or credentials.
    return GoogleCloudUploadFailure(
        "PROVIDER_TRANSIENT_FAILURE",
        status_code=status,
        retryable=True,
        stored_backup=stored_backup,
    )


def _provider_call(operation, function, *args, stored_backup=None, **kwargs):
    """Call a provider operation with a finite retry budget and redaction."""
    last_failure = None
    for attempt in range(MAX_PROVIDER_ATTEMPTS):
        try:
            return function(*args, **kwargs)
        except (
            GoogleCloudUploadFailure,
            GoogleCloudIntegrityFailure,
            GoogleCloudReconciliationRequired,
            GoogleCloudOwnershipFailure,
        ):
            raise
        except Exception as error:
            failure = _provider_failure(error, stored_backup=stored_backup)
            last_failure = failure
            # Never retry authentication, not-found, or malformed/ownership
            # outcomes.  The same object precondition makes transient retries safe.
            if not failure.retryable or attempt + 1 >= MAX_PROVIDER_ATTEMPTS:
                raise failure from None
    raise last_failure or GoogleCloudUploadFailure(stored_backup=stored_backup)


def _backup_identifier(stored_backup):
    value = storage_artifact_identity(stored_backup.backup).identifier
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or os.path.basename(value) != value
    ):
        raise GoogleCloudUploadFailure("INVALID_BACKUP_ID", retryable=False, stored_backup=stored_backup)
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
        raise GoogleCloudUploadFailure(
            "INVALID_PROVIDER_PATH", retryable=False, stored_backup=stored_backup
        )
    return value


def _identity_from_file(filename, *, stored_backup=None):
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
        raise _GoogleCloudSourceMissing from None
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
    expected = _committed_source_identity(stored_backup)
    if expected is None:
        expected = _valid_identity(state)
    try:
        actual = _identity_from_file(local_filename, stored_backup=stored_backup)
    except _GoogleCloudSourceMissing:
        if expected is not None:
            return expected
        raise
    if expected is not None and actual != expected:
        raise _GoogleCloudSourceInvalid(stored_backup=stored_backup)
    return expected or actual


def _timeout():
    return request_timeout()


def _storage_client(credentials):
    """Build GCS with a bounded auth session and no transport replay."""
    session = _BoundedGoogleAuthorizedSession(
        credentials, timeout=_provider_sdk_timeout()
    )
    return gc_storage.Client(credentials=credentials, _http=session)


class _BoundedResumableTransport:
    """Force the resumable-media helper's hidden recovery request deadline."""

    def __init__(self, transport, timeout):
        self._transport = transport
        self._timeout = timeout

    def request(self, method, url, **kwargs):
        kwargs["timeout"] = self._timeout
        return self._transport.request(method, url, **kwargs)


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
    except Exception as error:
        raise GoogleCloudUploadFailure(
            "STATE_PERSISTENCE_FAILED",
            retryable=True,
            message="Backup upload state could not be saved; the upload will resume safely.",
            stored_backup=stored_backup,
        ) from None


def _status(stored_backup, name):
    return getattr(getattr(stored_backup, "Status", None), name, None)


def _marker_values(artifact_identity, identity):
    values = {
        "backupsheep_namespace": NAMESPACE,
        "backupsheep_sha256": identity["sha256"],
        "backupsheep_bytes": str(identity["size_bytes"]),
    }
    if not hasattr(artifact_identity, "artifact_format"):
        values["backupsheep_backup_uuid"] = str(artifact_identity)
    elif artifact_identity.artifact_format == "bse1":
        values["backupsheep_artifact_id"] = artifact_identity.ownership_marker
    else:
        values["backupsheep_backup_uuid"] = artifact_identity.identifier
    return values


def _blob_value(blob, name, default=None):
    value = getattr(blob, name, default)
    if value is not None:
        return value
    if isinstance(blob, dict):
        return blob.get(name, default)
    return default


def _blob_metadata(blob):
    value = _blob_value(blob, "metadata", {})
    return {str(key).lower(): str(item) for key, item in (value or {}).items()}


def _owned_blob(blob, key, markers, *, stored_backup=None):
    if blob is None or str(_blob_value(blob, "name", "")) != str(key):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    metadata = _blob_metadata(blob)
    if any(metadata.get(str(name).lower()) != str(value) for name, value in markers.items()):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    if "backupsheep_artifact_id" in markers and "backupsheep_backup_uuid" in metadata:
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    return blob


def _list_exact_blobs(bucket, key, *, stored_backup=None):
    try:
        try:
            items = _provider_call(
                "list objects",
                bucket.list_blobs,
                prefix=key,
                versions=True,
                timeout=_timeout(),
                retry=None,
                stored_backup=stored_backup,
            )
        except TypeError:
            # Older google-cloud-storage releases do not accept timeout on the
            # iterator constructor.  The request itself remains client-bounded.
            items = _provider_call(
                "list objects",
                bucket.list_blobs,
                prefix=key,
                versions=True,
                retry=None,
                stored_backup=stored_backup,
            )
        matches = [item for item in list(items or []) if str(_blob_value(item, "name", "")) == str(key)]
    except GoogleCloudUploadFailure:
        raise
    except Exception:
        raise GoogleCloudReconciliationRequired(stored_backup=stored_backup) from None
    if len(matches) > 1:
        raise GoogleCloudReconciliationRequired(stored_backup=stored_backup)
    return matches[0] if matches else None


def _remote_stream_identity(blob, *, stored_backup=None):
    digest = hashlib.sha256()
    size = 0
    reader = None
    try:
        opener = getattr(blob, "open", None)
        if callable(opener):
            reader = opener(
                "rb",
                chunk_size=CHUNK_SIZE,
                timeout=_timeout(),
                retry=None,
            )
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        else:
            downloader = getattr(blob, "download_to_file", None)
            if not callable(downloader):
                raise GoogleCloudUploadFailure(
                    "STREAMING_VERIFICATION_UNAVAILABLE",
                    retryable=False,
                    message=(
                        "Google Cloud Storage cannot stream this object for "
                        "integrity verification."
                    ),
                    stored_backup=stored_backup,
                )
            sink = _DigestWriter(digest)
            # Do not let an SDK retry append a second partial response into the
            # same digest.  Celery retries the complete verification instead.
            downloader(
                sink,
                timeout=_timeout(),
                retry=None,
                checksum=None,
            )
            size = sink.size
    except (TimeoutError, requests_exceptions.Timeout):
        raise GoogleCloudUploadFailure(
            "PROVIDER_TIMEOUT",
            retryable=True,
            message=SAFE_TIMEOUT,
            stored_backup=stored_backup,
        ) from None
    except GoogleCloudUploadFailure:
        raise
    except Exception as error:
        raise _provider_failure(error, stored_backup=stored_backup) from None
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _remote_identity(blob, identity, markers, *, stored_backup=None):
    _owned_blob(blob, _blob_value(blob, "name", ""), markers, stored_backup=stored_backup)
    size = _blob_value(blob, "size", None)
    if size is not None:
        try:
            if int(size) != int(identity["size_bytes"]):
                raise GoogleCloudIntegrityFailure(stored_backup=stored_backup)
        except (TypeError, ValueError):
            raise GoogleCloudIntegrityFailure(stored_backup=stored_backup)
    actual = _remote_stream_identity(blob, stored_backup=stored_backup)
    if actual["sha256"] != identity["sha256"] or actual["size_bytes"] != identity["size_bytes"]:
        raise GoogleCloudIntegrityFailure(stored_backup=stored_backup)
    return actual


def _provider_fields(blob):
    md5 = _blob_value(blob, "md5_hash", "") or ""
    crc32c = _blob_value(blob, "crc32c", "") or ""
    provider_checksum = crc32c or md5
    return {
        "provider_checksum": str(provider_checksum),
        "provider_checksum_algorithm": "crc32c" if crc32c else ("md5" if md5 else ""),
        "md5_hash": str(md5),
        "crc32c": str(crc32c),
        "etag": str(_blob_value(blob, "etag", "") or ""),
        "generation": str(_blob_value(blob, "generation", "") or ""),
        "metageneration": str(_blob_value(blob, "metageneration", "") or ""),
        "version_id": str(_blob_value(blob, "generation", "") or ""),
    }


def _seal_session(storage, session_url, *, stored_backup=None):
    """Persist only an encrypted/fingerprinted GCS session URL."""
    try:
        key = storage.account.get_encryption_key()
        encrypted = bs_encrypt(str(session_url), key)
        if not encrypted:
            raise ValueError
        return {
            "encrypted": base64.b64encode(bytes(encrypted)).decode("ascii"),
            "fingerprint": hashlib.sha256(str(session_url).encode("utf-8")).hexdigest(),
        }
    except Exception:
        raise GoogleCloudUploadFailure(
            "SESSION_STATE_UNAVAILABLE",
            retryable=False,
            message="Google Cloud Storage resumable upload state could not be protected.",
            stored_backup=stored_backup,
        ) from None


def _unseal_session(storage, value):
    if not isinstance(value, dict):
        return None
    encoded = str(value.get("encrypted") or "")
    fingerprint = str(value.get("fingerprint") or "")
    if not encoded or len(fingerprint) != 64:
        return None
    try:
        key = storage.account.get_encryption_key()
        session_url = bs_decrypt(base64.b64decode(encoded), key)
        if not session_url:
            return None
        if hashlib.sha256(session_url.encode("utf-8")).hexdigest() != fingerprint:
            return None
        return session_url
    except Exception:
        return None


def _resumable_upload(
    stored_backup,
    storage_client,
    blob,
    local_filename,
    identity,
    state,
    *,
    session_recreated=False,
):
    """Use GCS's resumable-media transport with a durable encrypted session."""
    from google.resumable_media.requests import ResumableUpload

    storage = stored_backup.storage
    content_type = str(state.get("content_type") or "")
    if content_type not in {"application/octet-stream", "application/zip"}:
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    session_url = _unseal_session(storage, state.get("session"))
    resumed = bool(session_url)
    if not session_url:
        session_url = _provider_call(
            "create resumable session",
            blob.create_resumable_upload_session,
            content_type=content_type,
            size=identity["size_bytes"],
            client=storage_client,
            timeout=_timeout(),
            checksum=None,
            if_generation_match=0,
            retry=None,
            stored_backup=stored_backup,
        )
        if not session_url:
            raise GoogleCloudUploadFailure(
                "PROVIDER_MALFORMED_RESPONSE",
                retryable=False,
                stored_backup=stored_backup,
            )
        state["session"] = _seal_session(
            storage,
            session_url,
            stored_backup=stored_backup,
        )
        state["phase"] = "uploading"
        state["uploaded_bytes"] = 0
        _save_state(stored_backup, state, storage_file_id=state["object_key"])

    transport = _BoundedResumableTransport(
        blob._get_transport(storage_client), _timeout()
    )
    upload = ResumableUpload(session_url, CHUNK_SIZE, checksum=None)
    from google.resumable_media import common as resumable_common

    # The durable task owns retries.  Resumable session/range identity makes
    # adoption safe, but SDK backoff would hide progress and can outlive the
    # execution lease.
    upload._retry_strategy = resumable_common.RetryStrategy(max_retries=0)
    completed = False
    try:
        with open(local_filename, "rb") as source:
            upload._stream = source
            upload._total_bytes = identity["size_bytes"]
            upload._content_type = content_type
            if resumed:
                try:
                    upload.recover(transport)
                except Exception as error:
                    status = _status_code(error)
                    if status == 404 and not session_recreated:
                        # The opaque session expired without creating an object;
                        # the deterministic object reconciliation already ran
                        # immediately before this call, so creating a fresh
                        # session cannot overwrite a foreign object.
                        state.pop("session", None)
                        _save_state(stored_backup, state, storage_file_id=state["object_key"])
                        return _resumable_upload(
                            stored_backup,
                            storage_client,
                            blob,
                            local_filename,
                            identity,
                            state,
                            session_recreated=True,
                        )
                    if status == 404:
                        raise GoogleCloudReconciliationRequired(stored_backup=stored_backup)
                    if status != 200:
                        raise _provider_failure(error, stored_backup=stored_backup) from None
                    upload._finished = True
            state["uploaded_bytes"] = int(upload.bytes_uploaded)
            _save_state(stored_backup, state, storage_file_id=state["object_key"])
            while not upload.finished:
                try:
                    upload.transmit_next_chunk(transport, timeout=_timeout())
                except Exception as error:
                    raise _provider_failure(error, stored_backup=stored_backup) from None
                state["uploaded_bytes"] = int(upload.bytes_uploaded)
                _save_state(stored_backup, state, storage_file_id=state["object_key"])
            completed = True
    finally:
        if completed:
            # The URL is no longer useful after the provider has accepted the
            # final chunk; verification is the authoritative completion point.
            state.pop("session", None)
            state["phase"] = "verifying"
            state["uploaded_bytes"] = identity["size_bytes"]
            _save_state(stored_backup, state, storage_file_id=state["object_key"])


def _commit_verified(stored_backup, state, blob, identity, markers):
    _remote_identity(blob, identity, markers, stored_backup=stored_backup)
    provider = _provider_fields(blob)
    state.update(
        {
            "schema": 1,
            "provider": "google_cloud",
            "phase": "committed",
            "object_key": state["object_key"],
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": CHECKSUM_ALGORITHM,
            "ownership_marker": markers,
            **provider,
            "version_id": provider["generation"],
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
        raise GoogleCloudUploadFailure(
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
            "provider": "google_cloud",
            "provider_checksum": provider["provider_checksum"],
            "provider_checksum_algorithm": provider["provider_checksum_algorithm"],
            "md5_hash": provider["md5_hash"],
            "crc32c": provider["crc32c"],
            "generation": provider["generation"],
            "metageneration": provider["metageneration"],
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
        raise GoogleCloudUploadFailure(
            "STATE_PERSISTENCE_FAILED",
            retryable=True,
            message="Backup upload state could not be saved; the upload will resume safely.",
            stored_backup=stored_backup,
        ) from None


def delete_owned_google_cloud_object(stored_backup):
    """Delete only the immutable GCS generation committed by this storage row."""
    state = dict((getattr(stored_backup, "metadata", None) or {}).get(STATE_KEY) or {})
    expected = stored_backup.committed_integrity_identity()
    object_key = str(state.get("object_key") or "")
    generation = str(state.get("generation") or state.get("version_id") or "")
    etag = str(state.get("etag") or "")
    metageneration = str(state.get("metageneration") or "")
    committed_version = str(stored_backup.committed_version_id() or "")
    if (
        state.get("phase") != "committed"
        or object_key != str(stored_backup.storage_file_id or "")
        or expected is None
        or not generation
        or not etag
        or not metageneration
        or (committed_version and committed_version != generation)
    ):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    artifact_identity = validate_storage_object_key(stored_backup.backup, object_key)
    markers = _marker_values(artifact_identity, expected)
    if dict(state.get("ownership_marker") or {}) != markers:
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
    try:
        generation_number = int(generation)
        metageneration_number = int(metageneration)
    except (TypeError, ValueError):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup) from None

    config = stored_backup.storage.storage_google_cloud
    credentials = _provider_call(
        "load credentials",
        config.get_credentials,
        stored_backup=stored_backup,
    )
    client = _provider_call(
        "create client",
        _storage_client,
        credentials,
        stored_backup=stored_backup,
    )
    bucket = _provider_call(
        "select bucket",
        client.bucket,
        config.bucket_name,
        stored_backup=stored_backup,
    )
    blob = _provider_call(
        "select object generation",
        bucket.blob,
        object_key,
        generation=generation_number,
        stored_backup=stored_backup,
    )
    try:
        blob.reload(
            if_generation_match=generation_number,
            timeout=_timeout(),
            retry=None,
        )
    except Exception as error:
        if _status_code(error) == 404:
            return False
        raise _provider_failure(error, stored_backup=stored_backup) from None

    _owned_blob(blob, object_key, markers, stored_backup=stored_backup)
    try:
        remote_size = int(_blob_value(blob, "size", -1))
    except (TypeError, ValueError):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup) from None
    if (
        remote_size != expected["size_bytes"]
        or str(_blob_value(blob, "generation", "") or "") != generation
        or str(_blob_value(blob, "etag", "") or "") != etag
        or str(_blob_value(blob, "metageneration", "") or "") != metageneration
    ):
        raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)

    try:
        blob.delete(
            if_generation_match=generation_number,
            if_metageneration_match=metageneration_number,
            timeout=_timeout(),
            retry=None,
        )
    except Exception as error:
        status = _status_code(error)
        if status == 404:
            return False
        if status == 412:
            raise GoogleCloudOwnershipFailure(stored_backup=stored_backup) from None
        raise _provider_failure(error, stored_backup=stored_backup) from None
    return True


def storage_google_cloud(stored_backup):
    """Upload/adopt one deterministic GCS object and commit verified evidence."""
    try:
        artifact_identity = storage_artifact_identity(stored_backup.backup)
        identifier = artifact_identity.identifier
        local_filename = os.path.join("_storage", artifact_identity.filename)
        config = stored_backup.storage.storage_google_cloud
        prefix = str(config.prefix or "")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        object_key = (
            f"{prefix}{_node_slug(stored_backup)}/{artifact_identity.filename}"
            if artifact_identity.artifact_format == "legacy_zip"
            else f"{prefix}{artifact_identity.filename}"
        )
        validate_storage_object_key(stored_backup.backup, object_key)
        metadata, state = _state(stored_backup)
        persisted_key = str(state.get("object_key") or stored_backup.storage_file_id or object_key)
        if persisted_key != object_key:
            raise GoogleCloudOwnershipFailure(stored_backup=stored_backup)
        state["object_key"] = object_key
        identity = _source_identity(stored_backup, local_filename, state)
        persisted = _valid_identity(state)
        if persisted is not None and persisted != identity:
            raise _GoogleCloudSourceInvalid(stored_backup=stored_backup)
        state.update(
            {
                "provider": "google_cloud",
                "phase": state.get("phase") or "preparing",
                "sha256": identity["sha256"],
                "size_bytes": identity["size_bytes"],
                "checksum_algorithm": CHECKSUM_ALGORITHM,
                "ownership_marker": _marker_values(artifact_identity, identity),
                "content_type": artifact_identity.content_type,
            }
        )
        markers = dict(state["ownership_marker"])
        _save_state(
            stored_backup,
            state,
            status=_status(stored_backup, "UPLOAD_VALIDATION"),
            storage_file_id=object_key,
        )

        storage_client = _provider_call(
            "create client",
            _storage_client,
            config.get_credentials(),
            stored_backup=stored_backup,
        )
        bucket = _provider_call(
            "select bucket",
            storage_client.bucket,
            config.bucket_name,
            stored_backup=stored_backup,
        )
        existing = _list_exact_blobs(bucket, object_key, stored_backup=stored_backup)
        if existing is not None:
            _owned_blob(existing, object_key, markers, stored_backup=stored_backup)
            return _commit_verified(stored_backup, state, existing, identity, markers)

        if not os.path.isfile(local_filename):
            raise _GoogleCloudSourceMissing from None

        blob = _provider_call(
            "create object handle",
            bucket.blob,
            object_key,
            stored_backup=stored_backup,
        )
        blob.metadata = dict(markers)
        blob.content_type = artifact_identity.content_type
        # The client automatically switches to a resumable upload for large
        # files; setting chunk_size makes chunk boundaries deterministic.  The
        # generation precondition prevents a race from overwriting another
        # object's key.
        blob.chunk_size = CHUNK_SIZE
        state["phase"] = "uploading"
        state["upload_chunk_size"] = CHUNK_SIZE
        _save_state(stored_backup, state, storage_file_id=object_key)
        try:
            if (
                callable(getattr(blob, "create_resumable_upload_session", None))
                and callable(getattr(blob, "_get_transport", None))
                and hasattr(storage_client, "_http")
            ):
                _resumable_upload(
                    stored_backup,
                    storage_client,
                    blob,
                    local_filename,
                    identity,
                    state,
                )
            else:
                _provider_call(
                    "upload object",
                    blob.upload_from_filename,
                    local_filename,
                    content_type=artifact_identity.content_type,
                    if_generation_match=0,
                    timeout=_timeout(),
                    retry=None,
                    stored_backup=stored_backup,
                )
        except GoogleCloudUploadFailure as upload_error:
            # The upload response may have been lost.  Reconciliation is safe
            # because adoption still requires the marker and full remote hash.
            existing = _list_exact_blobs(bucket, object_key, stored_backup=stored_backup)
            if existing is not None:
                _owned_blob(existing, object_key, markers, stored_backup=stored_backup)
                return _commit_verified(stored_backup, state, existing, identity, markers)
            raise upload_error

        refreshed = _provider_call(
            "reload object",
            bucket.get_blob,
            object_key,
            timeout=_timeout(),
            retry=None,
            stored_backup=stored_backup,
        )
        if refreshed is None:
            raise GoogleCloudReconciliationRequired(stored_backup=stored_backup)
        _owned_blob(refreshed, object_key, markers, stored_backup=stored_backup)
        return _commit_verified(stored_backup, state, refreshed, identity, markers)
    except _GoogleCloudSourceMissing:
        _mark_source_missing(stored_backup)
        return None
    except StoragePointLeaseLostError:
        raise
    except (
        GoogleCloudIntegrityFailure,
        GoogleCloudReconciliationRequired,
        GoogleCloudOwnershipFailure,
        GoogleCloudUploadFailure,
    ):
        raise
    except Exception as error:
        raise _provider_failure(error, stored_backup=stored_backup) from None


__all__ = [
    "GoogleCloudIntegrityFailure",
    "GoogleCloudOwnershipFailure",
    "GoogleCloudReconciliationRequired",
    "GoogleCloudUploadFailure",
    "STATE_KEY",
    "delete_owned_google_cloud_object",
    "storage_google_cloud",
]
