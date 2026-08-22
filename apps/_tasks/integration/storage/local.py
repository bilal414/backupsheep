"""Crash-safe uploads for the local storage backend.

The local backend has no provider-side upload ID to reconcile.  Its durable
identity is therefore the confined, deterministic destination plus the
SHA-256/byte-count pair persisted on the storage point.  A retry can adopt a
verified destination even when the worker lost the response to its final DB
write.
"""

import hashlib
import os
import stat
import tempfile

from django.utils import timezone

from apps._tasks.exceptions import StorageLocalUploadFailedError
from apps._tasks.integration.storage.lease import StorageUploadLeaseLost
from apps.console.backup.models import StoragePointLeaseLostError


LOCAL_OBJECT_METADATA_KEY = "local_object"
CHECKSUM_ALGORITHM = "sha256"
CHUNK_SIZE = 1024 * 1024
SAFE_UPLOAD_FAILURE = (
    "Unable to upload the backup to Local Storage because the destination "
    "could not be verified. Please retry or contact an administrator."
)


class _LocalSourceMissing(Exception):
    """Internal marker; never exposed to an API response or user-facing log."""


class _LocalStorageIntegrityError(Exception):
    """Internal marker for a destination/source identity mismatch."""


def _backup_identifier(backup):
    value = str(getattr(backup, "uuid_str", None) or getattr(backup, "uuid", ""))
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or os.path.basename(value) != value
    ):
        raise _LocalStorageIntegrityError("The backup identifier is invalid.")
    return value


def _confined_path(root, path, *, allow_relative=True):
    """Return a real path below ``root`` without disclosing either path."""
    root = os.path.realpath(root)
    if not path:
        raise _LocalStorageIntegrityError("The local destination is invalid.")
    if os.path.isabs(path):
        candidate = path
    elif allow_relative:
        candidate = os.path.join(root, path)
    else:
        raise _LocalStorageIntegrityError("The local destination is invalid.")
    target = os.path.realpath(candidate)
    if target == root or not target.startswith(root + os.sep):
        raise _LocalStorageIntegrityError("The local destination is outside Local Storage.")
    return target


def _object_key(root, target):
    """Persist a root-relative key so metadata does not disclose server paths."""
    return os.path.relpath(target, os.path.realpath(root))


def _regular_file(path, *, source=False):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if source:
            raise _LocalSourceMissing from None
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _LocalStorageIntegrityError("The local file is not a regular file.")
    return True


def _pulse_upload_lease(stored_backup):
    heartbeat = getattr(stored_backup, "_renew_upload_lease", None)
    if callable(heartbeat):
        heartbeat()


def _file_identity(path, *, source=False, stored_backup=None):
    _regular_file(path, source=source)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with open(path, "rb") as source_file:
            while True:
                chunk = source_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                byte_count += len(chunk)
                _pulse_upload_lease(stored_backup)
    except FileNotFoundError:
        if source:
            raise _LocalSourceMissing from None
        return None
    return {"sha256": digest.hexdigest(), "size_bytes": byte_count}


def _same_identity(actual, expected):
    return bool(
        actual
        and expected
        and actual["sha256"] == expected["sha256"]
        and int(actual["size_bytes"]) == int(expected["size_bytes"])
    )


def _state(stored_backup):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    state = dict(metadata.get(LOCAL_OBJECT_METADATA_KEY) or {})
    return metadata, state


def _persist_state(stored_backup, state, target, *, status=None):
    metadata = dict(getattr(stored_backup, "metadata", None) or {})
    metadata[LOCAL_OBJECT_METADATA_KEY] = dict(state)
    stored_backup.metadata = metadata
    # The download and deletion paths use this confined absolute pointer.  The
    # durable metadata above intentionally keeps only a root-relative object key.
    stored_backup.storage_file_id = target
    if status is not None:
        stored_backup.status = status
    stored_backup.save()


def _status(stored_backup, name):
    return getattr(getattr(stored_backup, "Status", None), name, None)


def _fsync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_atomically(source, target, expected, *, stored_backup=None):
    """Copy into a private temp file, fsync it, then atomically publish it."""
    parent = os.path.dirname(target)
    temporary = None
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=parent,
            prefix=f".{os.path.basename(target)}.",
            suffix=".tmp",
            delete=False,
        ) as destination:
            temporary = destination.name
            os.fchmod(destination.fileno(), 0o600)
            try:
                with open(source, "rb") as source_file:
                    while True:
                        chunk = source_file.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        destination.write(chunk)
                        digest.update(chunk)
                        byte_count += len(chunk)
                        _pulse_upload_lease(stored_backup)
            except FileNotFoundError:
                raise _LocalSourceMissing from None
            _pulse_upload_lease(stored_backup)
            destination.flush()
            os.fsync(destination.fileno())
            _pulse_upload_lease(stored_backup)

        actual = {"sha256": digest.hexdigest(), "size_bytes": byte_count}
        if not _same_identity(actual, expected):
            raise _LocalStorageIntegrityError("The local source changed during upload.")

        os.replace(temporary, target)
        temporary = None
        _fsync_directory(parent)
        _pulse_upload_lease(stored_backup)
        return actual
    finally:
        if temporary:
            try:
                os.remove(temporary)
            except FileNotFoundError:
                pass


def _target_from_state(root, default_target, filename, state, storage_file_id):
    persisted_key = state.get("object_key")
    if persisted_key:
        target = _confined_path(root, str(persisted_key))
    elif storage_file_id:
        target = _confined_path(root, str(storage_file_id))
    else:
        target = default_target
    if os.path.basename(target) != filename:
        raise _LocalStorageIntegrityError("The local destination is not this backup.")
    return target, _object_key(root, target)


def _expected_identity(state):
    sha256 = state.get("sha256")
    size_bytes = state.get("size_bytes")
    if not sha256 and size_bytes is None:
        return None
    if not isinstance(sha256, str) or len(sha256) != 64:
        raise _LocalStorageIntegrityError("The persisted local checksum is invalid.")
    try:
        size_bytes = int(size_bytes)
    except (TypeError, ValueError):
        raise _LocalStorageIntegrityError("The persisted local size is invalid.") from None
    if size_bytes < 0:
        raise _LocalStorageIntegrityError("The persisted local size is invalid.")
    return {"sha256": sha256, "size_bytes": size_bytes}


def _record_destination_artifact(stored_backup, object_key, identity):
    """Record evidence before the point becomes visibly complete.

    Older unit-test doubles do not implement the durable artifact API.  Real
    backup models do; retaining the compatibility guard keeps this backend
    usable by those doubles without weakening production behavior.
    """
    recorder = getattr(stored_backup.backup, "record_artifact_integrity", None)
    if not callable(recorder):
        return
    recorder(
        role="destination",
        object_key=object_key,
        byte_count=identity["size_bytes"],
        storage=stored_backup.storage,
        checksum_algorithm=CHECKSUM_ALGORITHM,
        checksum_value=identity["sha256"],
        verified_at=timezone.now(),
        metadata={
            "storage_metadata_key": LOCAL_OBJECT_METADATA_KEY,
            "path_scope": "local_storage_root",
        },
    )


def _mark_missing_source(stored_backup):
    try:
        stored_backup.status = _status(stored_backup, "UPLOAD_FAILED_FILE_NOT_FOUND")
        stored_backup.save()
    except Exception as error:
        raise StorageLocalUploadFailedError(
            getattr(stored_backup.backup, "uuid_str", None),
            getattr(stored_backup.backup, "attempt_no", None),
            getattr(stored_backup.backup, "type", None),
            SAFE_UPLOAD_FAILURE,
        ) from error


def storage_local(stored_backup):
    """Upload one local backup with atomic publication and verified adoption."""
    try:
        backup = stored_backup.backup
        identifier = _backup_identifier(backup)
        filename = f"{identifier}.zip"
        local_zip = os.path.join("_storage", filename)
        storage_local_config = stored_backup.storage.storage_local
        root = storage_local_config.storage_root()
        target_dir = storage_local_config.resolve_path()
        os.makedirs(target_dir, exist_ok=True)
        default_target = _confined_path(root, os.path.join(target_dir, filename))

        _metadata, state = _state(stored_backup)
        target, object_key = _target_from_state(
            root,
            default_target,
            filename,
            state,
            getattr(stored_backup, "storage_file_id", None),
        )
        expected = _expected_identity(state)
        target_exists = _regular_file(target)

        if target_exists:
            actual = _file_identity(target, stored_backup=stored_backup)
            if expected is not None:
                if not _same_identity(actual, expected):
                    raise _LocalStorageIntegrityError(
                        "The existing committed local target has different content."
                    )
                identity = expected
            else:
                try:
                    source_identity = _file_identity(
                        local_zip,
                        source=True,
                        stored_backup=stored_backup,
                    )
                except _LocalSourceMissing:
                    _mark_missing_source(stored_backup)
                    return
                if not _same_identity(actual, source_identity):
                    raise _LocalStorageIntegrityError(
                        "The existing local target has different content."
                    )
                identity = source_identity
        else:
            try:
                source_identity = _file_identity(
                    local_zip,
                    source=True,
                    stored_backup=stored_backup,
                )
            except _LocalSourceMissing:
                _mark_missing_source(stored_backup)
                return
            if expected is not None and not _same_identity(source_identity, expected):
                raise _LocalStorageIntegrityError(
                    "The local source does not match the persisted upload identity."
                )
            identity = expected or source_identity

            state.update(
                {
                    "object_key": object_key,
                    "sha256": identity["sha256"],
                    "size_bytes": identity["size_bytes"],
                    "checksum_algorithm": CHECKSUM_ALGORITHM,
                    "phase": "copying",
                }
            )
            _persist_state(
                stored_backup,
                state,
                target,
                status=_status(stored_backup, "UPLOAD_VALIDATION"),
            )
            _copy_atomically(
                local_zip,
                target,
                identity,
                stored_backup=stored_backup,
            )
            actual = _file_identity(target, stored_backup=stored_backup)
            if not _same_identity(actual, identity):
                raise _LocalStorageIntegrityError(
                    "The local destination failed integrity verification."
                )

        # An existing target is adopted only after the same verification as a new
        # copy.  This is the lost-response/crashed-worker recovery path.
        state.update(
            {
                "object_key": object_key,
                "sha256": identity["sha256"],
                "size_bytes": identity["size_bytes"],
                "checksum_algorithm": CHECKSUM_ALGORITHM,
                "phase": "committed",
            }
        )
        _persist_state(
            stored_backup,
            state,
            target,
            status=_status(stored_backup, "UPLOAD_VALIDATION"),
        )
        _record_destination_artifact(stored_backup, object_key, identity)
        _persist_state(
            stored_backup,
            state,
            target,
            status=_status(stored_backup, "UPLOAD_COMPLETE"),
        )
    except _LocalSourceMissing:
        _mark_missing_source(stored_backup)
    except (StorageUploadLeaseLost, StoragePointLeaseLostError):
        # The task wrapper owns retry policy. Preserve fence loss instead of
        # converting it into a generic provider failure and attempting a stale save.
        raise
    except StorageLocalUploadFailedError:
        raise
    except Exception as error:
        # The exception is intentionally not interpolated: local paths and OS
        # errors can disclose the server layout or mounted credentials.
        raise StorageLocalUploadFailedError(
            getattr(stored_backup.backup, "uuid_str", None),
            getattr(stored_backup.backup, "attempt_no", None),
            getattr(stored_backup.backup, "type", None),
            SAFE_UPLOAD_FAILURE,
        ) from error
