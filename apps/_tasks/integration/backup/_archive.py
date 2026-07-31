"""Small, dependency-free helpers for producing and validating backup archives."""

import os
import subprocess
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


def create_zip(source_dir, archive_path, *, timeout):
    """Create and validate a ZIP archive without invoking a shell."""
    archive_path = os.path.abspath(archive_path)
    result = subprocess.run(
        ["zip", "-y", "-r", archive_path, ".", "-i", "*"],
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

    return validate_zip_archive(archive_path)
