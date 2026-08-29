"""Crash-safe, integrity-verified pCloud backup uploads.

pCloud has no user-defined object metadata on ordinary files. BackupSheep uses
the exact opaque ``/<random envelope uuid>.bse1`` path as the ownership marker
and uses pCloud's file ID plus provider revision/hash fields as the durable
provider identity. ``renameifexists`` and ``nopartial`` make the upload
collision-safe: an existing object is never overwritten by a retry or a
concurrent request.
"""

from __future__ import annotations

import hashlib
import os
import socket
from urllib.parse import urlsplit

from django.conf import settings
from django.utils import timezone

from apps._tasks.exceptions import StoragePCloudUploadFailedError
from apps._tasks.artifact_encryption import storage_artifact_identity
from apps.api.v1.utils.http import request_timeout, requests


PCLOUD_METADATA_KEY = "pcloud_object"
CHECKSUM_ALGORITHM = "sha256"
PCLOUD_DEFAULT_TIMEOUT = 60.0
PCLOUD_API_HOSTNAMES = frozenset({"api.pcloud.com", "eapi.pcloud.com"})
SAFE_UPLOAD_FAILURE = (
    "Unable to upload the backup to pCloud because the destination could not be "
    "verified. Please retry or contact an administrator."
)
SAFE_TIMEOUT_FAILURE = (
    "The pCloud request timed out before the backup destination could be verified. "
    "Please retry."
)
SAFE_AUTH_FAILURE = (
    "pCloud rejected the configured credentials or permissions. Please reconnect "
    "pCloud and retry."
)
SAFE_QUOTA_FAILURE = "The pCloud account does not have enough available storage capacity."
SAFE_INTEGRITY_FAILURE = (
    "pCloud returned content that did not match the local backup artifact."
)
SAFE_DUPLICATE_FAILURE = (
    "Multiple pCloud objects match this backup; automatic reconciliation was stopped "
    "for safety."
)
SAFE_RECONCILIATION_FAILURE = (
    "pCloud accepted an upload request but the completed destination could not yet "
    "be verified. Reconciliation is required."
)


class PCloudStorageAdapterError(RuntimeError):
    """Safe, structured internal error; provider bodies never leave this module."""

    def __init__(self, code, message=SAFE_UPLOAD_FAILURE, *, retryable=False, result=None):
        self.code = str(code)[:64]
        self.retryable = bool(retryable)
        self.result = result if isinstance(result, int) else None
        self.safe_message = str(message)
        super().__init__(self.safe_message)


class _PCloudSourceMissing(PCloudStorageAdapterError):
    def __init__(self):
        super().__init__("SOURCE_ARTIFACT_MISSING", SAFE_UPLOAD_FAILURE)


class _PCloudIntegrityError(PCloudStorageAdapterError):
    def __init__(self, message=SAFE_INTEGRITY_FAILURE):
        super().__init__("INTEGRITY_MISMATCH", message)


class _PCloudDuplicateError(PCloudStorageAdapterError):
    def __init__(self):
        super().__init__("DUPLICATE_MATCH", SAFE_DUPLICATE_FAILURE)


class _PCloudReconciliationError(PCloudStorageAdapterError):
    def __init__(self, *, retryable=True):
        super().__init__(
            "RECONCILIATION_REQUIRED",
            SAFE_RECONCILIATION_FAILURE,
            retryable=retryable,
        )


def _setting_float(name, default):
    try:
        value = float(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = float(default)
    return max(0.1, min(value, 24 * 3600.0))


def _pcloud_timeout():
    configured = _setting_float(
        "PCLOUD_API_TIMEOUT",
        _setting_float("PROVIDER_HTTP_READ_TIMEOUT", PCLOUD_DEFAULT_TIMEOUT),
    )
    # A provider-specific override may shorten the deadline, never extend the
    # process-wide bounded provider policy.
    return min(configured, request_timeout()[1])


def _value(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _artifact_filename(backup):
    filename = storage_artifact_identity(backup).filename
    if (
        not filename
        or filename in {".", ".."}
        or "\x00" in filename
        or "/" in filename
        or "\\" in filename
        or os.path.basename(filename) != filename
    ):
        raise _PCloudIntegrityError("The artifact object name is invalid.")
    return filename


def _safe_folder(value):
    folder = str(value or "").strip()
    if not folder:
        raise _PCloudIntegrityError("The pCloud destination folder is invalid.")
    if not folder.startswith("/"):
        folder = f"/{folder}"
    folder = folder.rstrip("/") or "/"
    if "\x00" in folder or ".." in folder or "//" in folder:
        raise _PCloudIntegrityError("The pCloud destination folder is invalid.")
    return folder


def _deterministic_folder(backup):
    slug = getattr(getattr(backup, "node", None), "name_slug", None)
    if not slug:
        raise _PCloudIntegrityError("The pCloud destination folder is invalid.")
    return _safe_folder(f"/{slug}")


def _deterministic_path(folder, filename):
    return f"{folder.rstrip('/')}/{filename}" if folder != "/" else f"/{filename}"


def _normalize_path(value):
    path = str(value or "").replace("\\", "/")
    if not path.startswith("/"):
        path = f"/{path}"
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/") or "/"


def _file_identity(path):
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with open(path, "rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size_bytes += len(chunk)
    except FileNotFoundError:
        raise _PCloudSourceMissing from None
    return {"sha256": digest.hexdigest(), "size_bytes": size_bytes}


def _expected_identity(state):
    sha256 = state.get("sha256")
    size_bytes = state.get("size_bytes")
    if not sha256 and size_bytes is None:
        return None
    if not isinstance(sha256, str) or len(sha256) != 64:
        raise _PCloudIntegrityError("The persisted backup checksum is invalid.")
    try:
        size_bytes = int(size_bytes)
    except (TypeError, ValueError):
        raise _PCloudIntegrityError("The persisted backup size is invalid.") from None
    if size_bytes < 0:
        raise _PCloudIntegrityError("The persisted backup size is invalid.")
    return {"sha256": sha256.lower(), "size_bytes": size_bytes}


def _state(stored_backup):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    state = dict(metadata.get(PCLOUD_METADATA_KEY) or {})
    return metadata, state


def _save_state(stored_backup, state, *, status=None):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    metadata[PCLOUD_METADATA_KEY] = dict(state)
    stored_backup.metadata = metadata
    if state.get("path"):
        # Preserve the historical pCloud contract: storage_file_id is the path;
        # the numeric provider file ID remains in metadata for deletion/adoption.
        stored_backup.storage_file_id = str(state["path"])
    fields = ["metadata", "modified"]
    if state.get("path"):
        fields.insert(0, "storage_file_id")
    if status is not None:
        stored_backup.status = status
        fields.insert(0, "status")
    stored_backup.save(update_fields=list(dict.fromkeys(fields)))


def _status(stored_backup, name):
    return getattr(getattr(stored_backup, "Status", None), name, None)


def _endpoint(hostname, method):
    raw = str(hostname or "").strip()
    if not raw:
        raise PCloudStorageAdapterError("CONFIGURATION_INVALID", SAFE_UPLOAD_FAILURE)
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlsplit(raw)
    try:
        parsed_port = parsed.port
    except ValueError:
        raise PCloudStorageAdapterError(
            "CONFIGURATION_INVALID", SAFE_UPLOAD_FAILURE
        ) from None
    normalized_hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or normalized_hostname not in PCLOUD_API_HOSTNAMES
        or parsed.username is not None
        or parsed.password is not None
        or parsed_port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise PCloudStorageAdapterError("CONFIGURATION_INVALID", SAFE_UPLOAD_FAILURE)
    operation = str(method or "").strip().strip("/")
    if not operation or "/" in operation or "\\" in operation:
        raise PCloudStorageAdapterError("CONFIGURATION_INVALID", SAFE_UPLOAD_FAILURE)
    return f"https://{normalized_hostname}/{operation}"


def _provider_error_from_status(status_code):
    if status_code in {401, 403}:
        return PCloudStorageAdapterError("AUTH_FAILED", SAFE_AUTH_FAILURE)
    if status_code == 429:
        return PCloudStorageAdapterError(
            "RATE_LIMITED",
            "pCloud rate-limited the request; processing will resume later.",
            retryable=True,
        )
    if status_code >= 500 or status_code in {408, 425}:
        return PCloudStorageAdapterError(
            "TRANSIENT_OUTAGE",
            "pCloud is temporarily unavailable; processing will resume later.",
            retryable=True,
        )
    return PCloudStorageAdapterError("PROVIDER_REQUEST_FAILED", SAFE_UPLOAD_FAILURE)


def _provider_error(error):
    if isinstance(error, PCloudStorageAdapterError):
        return error
    timeout_types = (TimeoutError, socket.timeout)
    exceptions = getattr(requests, "exceptions", None)
    if exceptions is not None:
        timeout_types = timeout_types + tuple(
            exception_type
            for exception_type in (getattr(exceptions, "Timeout", None),)
            if exception_type is not None
        )
    if isinstance(error, timeout_types):
        return PCloudStorageAdapterError("TIMEOUT", SAFE_TIMEOUT_FAILURE, retryable=True)
    return PCloudStorageAdapterError("PROVIDER_REQUEST_FAILED", SAFE_UPLOAD_FAILURE)


def _result_code(payload):
    value = payload.get("result") if isinstance(payload, dict) else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _pcloud_result_error(result):
    if result in {1000, 2000, 2003}:
        return PCloudStorageAdapterError("AUTH_FAILED", SAFE_AUTH_FAILURE, result=result)
    if result == 2008:
        return PCloudStorageAdapterError("QUOTA_EXCEEDED", SAFE_QUOTA_FAILURE, result=result)
    if result in {2002, 2005, 2009, 2010}:
        return PCloudStorageAdapterError(
            "NOT_FOUND",
            "The pCloud destination was not found.",
            result=result,
        )
    if result in {4000}:
        return PCloudStorageAdapterError(
            "RATE_LIMITED",
            "pCloud rate-limited the request; processing will resume later.",
            retryable=True,
            result=result,
        )
    if result in {2041, 5000, 5001, 5002}:
        return PCloudStorageAdapterError(
            "TRANSIENT_OUTAGE",
            "pCloud is temporarily unavailable; processing will resume later.",
            retryable=True,
            result=result,
        )
    return PCloudStorageAdapterError("PROVIDER_REQUEST_FAILED", SAFE_UPLOAD_FAILURE, result=result)


def _request_json(storage_config, token, method, operation, *, data=None, files=None):
    url = _endpoint(storage_config.hostname, operation)
    request = getattr(requests, method.lower())
    request_kwargs = {
        # pCloud supports OAuth bearer authentication in this header. Keeping
        # the non-expiring token out of the URI prevents it from leaking into
        # reverse-proxy, provider, browser-history, and exception logs.
        "headers": {"Authorization": f"Bearer {token}"},
        "params": {},
        "verify": True,
        "timeout": _pcloud_timeout(),
        "allow_redirects": False,
    }
    if method.upper() == "GET":
        # pCloud's JSON API expects global parameters in the query string for GET
        # requests.  A GET request body is not portable across proxies and may be
        # discarded, which would turn a safe exact-path lookup into a false miss.
        request_kwargs["params"].update(dict(data or {}))
    else:
        request_kwargs["data"] = data
        if files is not None:
            request_kwargs["files"] = files
    try:
        response = request(url, **request_kwargs)
    except Exception as error:
        raise _provider_error(error) from None
    status_code = int(getattr(response, "status_code", 200) or 200)
    if status_code >= 400:
        raise _provider_error_from_status(status_code)
    try:
        payload = response.json()
    except Exception:
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE) from None
    if not isinstance(payload, dict):
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    result = _result_code(payload)
    if result != 0:
        raise _pcloud_result_error(result)
    return payload


def _candidate_key(candidate, folder, filename):
    file_id = str(_value(candidate, "fileid") or _value(candidate, "file_id") or _value(candidate, "id") or "")
    path = _normalize_path(_value(candidate, "path") or f"{folder.rstrip('/')}/{_value(candidate, 'name') or filename}")
    if file_id:
        return "id", file_id
    return "path", path


def _append_unique(candidates, candidate, folder, filename):
    key = _candidate_key(candidate, folder, filename)
    if not any(_candidate_key(existing, folder, filename) == key for existing in candidates):
        candidates.append(candidate)


def _pcloud_candidates(storage_config, token, folder, filename, *, hint=None):
    expected_path = _normalize_path(_deterministic_path(folder, filename))
    candidates = []
    if hint is not None:
        _append_unique(candidates, hint, folder, filename)
    try:
        stat = _request_json(
            storage_config,
            token,
            "GET",
            "stat",
            data={"path": expected_path},
        )
        stat_metadata = stat.get("metadata")
        if isinstance(stat_metadata, dict):
            _append_unique(candidates, stat_metadata, folder, filename)
    except PCloudStorageAdapterError as error:
        if error.code != "NOT_FOUND":
            raise

    try:
        listed = _request_json(
            storage_config,
            token,
            "GET",
            "listfolder",
            data={"path": folder},
        )
    except PCloudStorageAdapterError as error:
        if error.code == "NOT_FOUND":
            return candidates
        raise
    listed_metadata = listed.get("metadata") or {}
    if isinstance(listed_metadata, dict):
        # The documented pCloud response wraps folder children in
        # metadata.contents.  Accepting a flat list as well keeps this boundary
        # compatible with older test doubles and SDK wrappers.
        entries = listed_metadata.get("contents") or []
    elif isinstance(listed_metadata, list):
        entries = listed_metadata
    else:
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    stem, suffix = os.path.splitext(filename)
    for entry in entries:
        if not isinstance(entry, dict) or bool(entry.get("isfolder")):
            continue
        name = str(entry.get("name") or "")
        path = _normalize_path(entry.get("path") or f"{folder.rstrip('/')}/{name}")
        is_variant = bool(
            suffix and name.startswith(f"{stem} (") and name.endswith(suffix)
        )
        if path == expected_path or name == filename or is_variant:
            _append_unique(candidates, entry, folder, filename)
    return candidates


def _download_identity(storage_config, token, candidate, expected):
    file_id = _value(candidate, "fileid") or _value(candidate, "file_id") or _value(candidate, "id")
    if not file_id:
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    link_payload = _request_json(
        storage_config,
        token,
        "GET",
        "getfilelink",
        data={"fileid": str(file_id), "forcedownload": 1, "skipfilename": 1},
    )
    hosts = link_payload.get("hosts") or []
    path = str(link_payload.get("path") or "")
    if not hosts or not path:
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    host = str(hosts[0])
    # The content host is provider-supplied but must remain within pCloud.  This
    # prevents a malicious/malformed response from turning verification into SSRF.
    if not host.endswith(".pcloud.com") and host != "pcloud.com":
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    url = f"https://{host}{path if path.startswith('/') else '/' + path}"
    try:
        response = requests.get(
            url,
            stream=True,
            verify=True,
            timeout=_pcloud_timeout(),
        )
    except Exception as error:
        raise _provider_error(error) from None
    if int(getattr(response, "status_code", 200) or 200) >= 400:
        raise _provider_error_from_status(int(getattr(response, "status_code", 0) or 0))
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            chunks = iterator(chunk_size=1024 * 1024)
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
    actual = digest.hexdigest()
    if size_bytes != int(expected["size_bytes"]) or actual != expected["sha256"]:
        raise _PCloudIntegrityError()
    return {"sha256": actual, "size_bytes": size_bytes}


def _verify_candidate(storage_config, token, candidate, folder, filename, expected):
    path = _normalize_path(_value(candidate, "path") or f"{folder.rstrip('/')}/{_value(candidate, 'name') or filename}")
    expected_path = _normalize_path(_deterministic_path(folder, filename))
    if path != expected_path or str(_value(candidate, "name") or filename) != filename:
        raise _PCloudIntegrityError("The pCloud object path is not this backup's deterministic destination.")
    try:
        provider_size = int(_value(candidate, "size"))
    except (TypeError, ValueError):
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE) from None
    if provider_size != int(expected["size_bytes"]):
        raise _PCloudIntegrityError()

    file_id = _value(candidate, "fileid") or _value(candidate, "file_id") or _value(candidate, "id")
    if not file_id:
        raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
    checksum = _request_json(
        storage_config,
        token,
        "GET",
        "checksumfile",
        data={"fileid": str(file_id)},
    )
    provider_sha256 = str(checksum.get("sha256") or "").lower()
    if provider_sha256:
        if provider_sha256 != expected["sha256"]:
            raise _PCloudIntegrityError()
        remote_identity = {"sha256": provider_sha256, "size_bytes": provider_size}
    else:
        # The US pCloud API does not return SHA-256 from checksumfile.  Download
        # through the provider-issued link so adoption remains cryptographically
        # verified rather than trusting only pCloud's size/hash fields.
        remote_identity = _download_identity(storage_config, token, candidate, expected)
    normalized = dict(candidate)
    normalized["path"] = path
    normalized["fileid"] = str(file_id)
    normalized["sha256"] = remote_identity["sha256"]
    normalized["size"] = remote_identity["size_bytes"]
    return normalized


def _reconcile(storage_config, token, folder, filename, expected, *, hint=None):
    candidates = _pcloud_candidates(storage_config, token, folder, filename, hint=hint)
    if len(candidates) > 1:
        raise _PCloudDuplicateError()
    if not candidates:
        return None
    return _verify_candidate(storage_config, token, candidates[0], folder, filename, expected)


def _safe_provider_metadata(candidate, *, folder, filename, identifier, identity):
    file_id = str(_value(candidate, "fileid") or _value(candidate, "file_id") or _value(candidate, "id") or "")
    revision = _value(candidate, "revision_id") or _value(candidate, "revisionid") or _value(candidate, "revision") or ""
    provider_hash = _value(candidate, "hash") or ""
    version_id = _value(candidate, "version_id") or revision or provider_hash
    return {
        "provider": "pcloud",
        "ownership_marker": f"backupsheep:{identifier}",
        "path": _normalize_path(_value(candidate, "path") or f"{folder.rstrip('/')}/{filename}"),
        "provider_id": file_id,
        "file_id": file_id,
        "fileid": file_id,
        "revision": str(revision or ""),
        "revision_id": str(revision or ""),
        "version_id": str(version_id or ""),
        "provider_hash": str(provider_hash or ""),
        "size_bytes": int(identity["size_bytes"]),
        "sha256": identity["sha256"],
        "modified": str(_value(candidate, "modified") or ""),
        "parentfolderid": _value(candidate, "parentfolderid"),
    }


def _record_destination_artifact(stored_backup, state, identity):
    recorder = getattr(stored_backup.backup, "record_artifact_integrity", None)
    if not callable(recorder):
        raise PCloudStorageAdapterError("ARTIFACT_RECORD_MISSING", SAFE_UPLOAD_FAILURE)
    recorder(
        role="destination",
        object_key=state["path"],
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm=CHECKSUM_ALGORITHM,
        checksum_value=identity["sha256"],
        etag=state.get("provider_hash", ""),
        version_id=state.get("version_id", ""),
        verified_at=timezone.now(),
        metadata={
            "storage_metadata_key": PCLOUD_METADATA_KEY,
            "provider": "pcloud",
            "ownership_marker": state.get("ownership_marker", ""),
            "provider_id": state.get("provider_id", ""),
            "revision": state.get("revision", ""),
        },
    )


def _finalize(stored_backup, state, candidate, identity, identifier, folder, filename):
    provider = _safe_provider_metadata(
        candidate,
        folder=folder,
        filename=filename,
        identifier=identifier,
        identity=identity,
    )
    state.update(
        {
            **provider,
            "phase": "committed",
            "checksum_algorithm": CHECKSUM_ALGORITHM,
        }
    )
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
    _record_destination_artifact(stored_backup, state, identity)
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_COMPLETE"))


def _upload(
    storage_config,
    token,
    folder,
    filename,
    local_artifact,
    identity,
    state,
    stored_backup,
    artifact_identity,
):
    state.update(
        {
            "phase": "uploading",
            "progress_hash": f"backupsheep-{artifact_identity.identifier}",
            "path": _deterministic_path(folder, filename),
            "sha256": identity["sha256"],
            "size_bytes": identity["size_bytes"],
            "checksum_algorithm": CHECKSUM_ALGORITHM,
        }
    )
    _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))
    hint = None
    try:
        with open(local_artifact, "rb") as source:
            payload = _request_json(
                storage_config,
                token,
                "POST",
                "uploadfile",
                data={
                    "path": folder,
                    "filename": filename,
                    "renameifexists": 1,
                    "nopartial": 1,
                    "progresshash": state["progress_hash"],
                },
                files={"file": (filename, source, artifact_identity.content_type)},
            )
        metadata = payload.get("metadata") or []
        if not isinstance(metadata, list):
            raise PCloudStorageAdapterError("MALFORMED_RESPONSE", SAFE_UPLOAD_FAILURE)
        if len(metadata) > 1:
            raise _PCloudDuplicateError()
        hint = metadata[0] if metadata else None
    except Exception as error:
        if isinstance(error, PCloudStorageAdapterError) and error.code in {"DUPLICATE_MATCH", "INTEGRITY_MISMATCH"}:
            raise
        # A timeout/lost response can still have committed a file.  Reconcile the
        # exact deterministic path before considering another provider request.
        remote = _reconcile(storage_config, token, folder, filename, identity)
        if remote is not None:
            return remote
        raise _provider_error(error) from None
    remote = _reconcile(storage_config, token, folder, filename, identity, hint=hint)
    if remote is None:
        raise _PCloudReconciliationError()
    return remote


def storage_pcloud(stored_backup):
    """Upload one backup and adopt one verified pCloud object on retry."""
    try:
        backup = stored_backup.backup
        artifact_identity = storage_artifact_identity(backup)
        identifier = artifact_identity.identifier
        filename = _artifact_filename(backup)
        local_artifact = os.path.join("_storage", filename)
        storage_config = stored_backup.storage.storage_pcloud
        token = storage_config.get_access_token()
        metadata, state = _state(stored_backup)
        expected = _expected_identity(state)
        default_folder = (
            _deterministic_folder(backup)
            if artifact_identity.artifact_format == "legacy_zip"
            else "/"
        )
        folder = _safe_folder(state.get("folder") or default_folder)
        persisted_path = state.get("path")
        expected_path = _deterministic_path(folder, filename)
        if persisted_path and _normalize_path(persisted_path) != _normalize_path(expected_path):
            raise _PCloudIntegrityError("The persisted pCloud path is not this backup's deterministic destination.")
        state.update(
            {
                "provider": "pcloud",
                "folder": folder,
                "path": expected_path,
                "ownership_marker": f"backupsheep:{identifier}",
            }
        )
        if expected is None:
            expected = _file_identity(local_artifact)
            state.update(
                {
                    "sha256": expected["sha256"],
                    "size_bytes": expected["size_bytes"],
                    "checksum_algorithm": CHECKSUM_ALGORITHM,
                }
            )
        elif os.path.exists(local_artifact):
            source_identity = _file_identity(local_artifact)
            if source_identity != expected:
                raise _PCloudIntegrityError("The local backup changed after upload state was persisted.")
        _save_state(stored_backup, state, status=_status(stored_backup, "UPLOAD_VALIDATION"))

        try:
            remote = _reconcile(storage_config, token, folder, filename, expected)
        except PCloudStorageAdapterError as error:
            if error.code not in {"NOT_FOUND"}:
                raise
            remote = None
        if remote is None:
            # pCloud's folder creation endpoint is idempotent.  It is performed
            # only after exact-path reconciliation so no provider object is touched
            # during a lost-response retry.
            _request_json(
                storage_config,
                token,
                "POST",
                "createfolderifnotexists",
                data={"path": folder},
            )
            remote = _upload(
                storage_config,
                token,
                folder,
                filename,
                local_artifact,
                expected,
                state,
                stored_backup,
                artifact_identity,
            )
        _finalize(stored_backup, state, remote, expected, identifier, folder, filename)
    except _PCloudSourceMissing:
        try:
            stored_backup.status = _status(stored_backup, "UPLOAD_FAILED_FILE_NOT_FOUND")
            stored_backup.save(update_fields=["status", "modified"])
        except Exception:
            raise StoragePCloudSafeError(stored_backup, "SOURCE_ARTIFACT_MISSING") from None
    except StoragePCloudSafeError:
        raise
    except Exception as error:
        safe_error = _provider_error(error)
        raise _public_error(stored_backup, safe_error) from None


class StoragePCloudSafeError(StoragePCloudUploadFailedError):
    """Public pCloud error carrying only safe structured information."""

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
    public = StoragePCloudSafeError(
        stored_backup,
        getattr(error, "code", "PROVIDER_REQUEST_FAILED"),
        getattr(error, "safe_message", SAFE_UPLOAD_FAILURE),
        retryable=bool(getattr(error, "retryable", False)),
    )
    return public
