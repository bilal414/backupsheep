"""Small, dependency-free helpers for producing and validating backup archives."""

import errno
import os
import subprocess
import uuid
import zipfile


def _decode_output(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def validate_zip_archive(archive_path, *, required_suffix=None):
    """Validate that *archive_path* is a readable, non-empty ZIP archive.

    ``zip`` can leave a zero-byte or otherwise incomplete output behind after a
    failed transfer.  Checking both the central directory and every member CRC
    catches those cases before the backup is made available for upload.

    ``required_suffix`` is used by logical database backups to ensure that the
    archive contains a real dump rather than only the placeholder file created
    for an empty working directory.
    """
    if not os.path.isfile(archive_path) or os.path.getsize(archive_path) <= 0:
        raise ValueError(f"Backup archive was not created: {archive_path}")

    try:
        with zipfile.ZipFile(archive_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                raise ValueError(f"Backup archive failed CRC validation: {bad_member}")

            if required_suffix and not any(
                name.lower().endswith(required_suffix.lower())
                for name in archive.namelist()
            ):
                raise ValueError(
                    f"Backup archive contains no {required_suffix} dump: {archive_path}"
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Backup archive is not a valid ZIP: {archive_path}") from exc

    return archive_path


def _staged_archive_path(archive_path):
    parent = os.path.dirname(archive_path) or "."
    name = os.path.basename(archive_path)
    return os.path.join(parent, f".{name}.{uuid.uuid4().hex}.partial.zip")


def _fsync_file(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_parent(path):
    descriptor = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            # Some network/pseudo filesystems do not support directory fsync.
            # The archive itself was still fsynced before the atomic rename.
            if error.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EBADF):
                raise
    finally:
        os.close(descriptor)


def _publish_archive(
    staged_path,
    archive_path,
    *,
    required_suffix=None,
    before_publish=None,
):
    validate_zip_archive(staged_path, required_suffix=required_suffix)
    _fsync_file(staged_path)
    if before_publish is not None:
        before_publish()
    os.replace(staged_path, archive_path)
    _fsync_parent(archive_path)
    return validate_zip_archive(archive_path, required_suffix=required_suffix)


def create_zip(
    source_dir,
    archive_path,
    *,
    timeout,
    required_suffix=None,
    before_publish=None,
):
    """Build, fsync, and atomically publish a validated ZIP archive."""
    archive_path = os.path.abspath(archive_path)
    staged_path = _staged_archive_path(archive_path)
    try:
        result = subprocess.run(
            ["zip", "-y", "-r", staged_path, ".", "-i", "*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=source_dir,
        )
        if result.returncode != 0:
            stderr = _decode_output(result.stderr).strip()
            raise RuntimeError(
                f"zip failed with exit code {result.returncode}"
                + (f": {stderr[-1000:]}" if stderr else "")
            )
        return _publish_archive(
            staged_path,
            archive_path,
            required_suffix=required_suffix,
            before_publish=before_publish,
        )
    finally:
        try:
            os.remove(staged_path)
        except FileNotFoundError:
            pass


def create_python_zip(
    source_dir,
    archive_path,
    *,
    required_suffix=None,
    before_publish=None,
):
    """Python ZIP writer with the same atomic publication contract as ``zip``."""
    archive_path = os.path.abspath(archive_path)
    staged_path = _staged_archive_path(archive_path)
    try:
        with zipfile.ZipFile(
            staged_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            for root, _dirs, files in os.walk(
                source_dir, onerror=None, followlinks=False
            ):
                for name in files:
                    path = os.path.join(root, name)
                    archive.write(path, os.path.relpath(path, source_dir))
        return _publish_archive(
            staged_path,
            archive_path,
            required_suffix=required_suffix,
            before_publish=before_publish,
        )
    finally:
        try:
            os.remove(staged_path)
        except FileNotFoundError:
            pass
