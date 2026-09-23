"""Stable, secret-free failure contracts for materialized backup engines."""

from __future__ import annotations

import errno
import re
import subprocess
import zipfile
from dataclasses import dataclass

from celery.exceptions import SoftTimeLimitExceeded

from apps._tasks.integration.backup._archive import (
    ArchiveSourcePolicyError,
    ArchiveValidationError,
)
from apps.console.connection.reliability import (
    DATABASE_EVENT_PRIVILEGE_DETAIL,
    classify_connection_error,
)


@dataclass(frozen=True)
class SafeBackupFailure:
    code: str
    detail: str
    retryable: bool


class BackupStageError(RuntimeError):
    """Attach a stable website stage without exposing the underlying exception."""

    def __init__(self, stage, error):
        self.stage = str(stage or "website_backup")[:64]
        self.error = error
        super().__init__("website backup stage failed")


_WEBSITE_STAGE_FAILURES = {
    "website_mirror": SafeBackupFailure(
        "WEBSITE_MIRROR_FAILED",
        "The website source could not be mirrored completely. Check source access "
        "and file permissions, then retry.",
        True,
    ),
    "website_manifest": SafeBackupFailure(
        "WEBSITE_MANIFEST_FAILED",
        "BackupSheep could not build a stable manifest of the mirrored website. "
        "Retry after checking worker capacity and source stability.",
        True,
    ),
    "website_archive": SafeBackupFailure(
        "ARCHIVE_CREATION_FAILED",
        "BackupSheep could not create the website archive from its verified mirror. "
        "Retry after checking worker capacity.",
        True,
    ),
}


def safe_backup_failure(error, *, stage="backup"):
    """Classify an exception without returning its provider or command text."""
    underlying = error.error if isinstance(error, BackupStageError) else error
    if isinstance(underlying, ArchiveSourcePolicyError):
        return SafeBackupFailure(
            "SOURCE_SPECIAL_FILE_UNSUPPORTED",
            "Website backups support regular files and directories only. "
            "Remove or exclude symbolic links, special files, and invalid paths, "
            "then run a new backup.",
            False,
        )
    if isinstance(
        underlying,
        (SoftTimeLimitExceeded, TimeoutError, subprocess.TimeoutExpired),
    ) or getattr(underlying, "errno", None) == errno.ETIMEDOUT:
        return SafeBackupFailure(
            "BACKUP_TIMEOUT",
            "The source did not finish the backup operation before its timeout.",
            True,
        )
    if getattr(underlying, "errno", None) == errno.ENAMETOOLONG:
        return SafeBackupFailure(
            "SOURCE_PATH_LIMIT_EXCEEDED",
            "A website source path exceeds the worker filesystem limit. Shorten "
            "that path or exclude it, then run a new backup.",
            False,
        )
    if isinstance(underlying, (ArchiveValidationError, zipfile.BadZipFile)):
        return SafeBackupFailure(
            "ARCHIVE_VALIDATION_FAILED",
            "The generated backup archive failed integrity validation.",
            True,
        )

    # Inspect only for classification. The source string is never returned,
    # persisted, logged, or placed in notifications.
    message = str(underlying).lower()
    event_privilege_denied = (
        DATABASE_EVENT_PRIVILEGE_DETAIL.lower() in message
        or (
            (
                "show events" in message
                or "event privilege" in message
                or "event privilege(s)" in message
            )
            and any(
                marker in message
                for marker in (
                    "access denied",
                    "command denied",
                    "permission denied",
                    "you need",
                    "required",
                )
            )
        )
    )
    if event_privilege_denied:
        return SafeBackupFailure(
            "DATABASE_EVENT_PRIVILEGE_REQUIRED",
            DATABASE_EVENT_PRIVILEGE_DETAIL,
            False,
        )
    disk_match = re.fullmatch(
        r"not enough free disk space for ([a-z0-9 _-]{1,64}): "
        r"need ~([0-9]+(?:\.[0-9]+)?) gb, "
        r"have ~([0-9]+(?:\.[0-9]+)?) gb free",
        message,
    )
    if disk_match:
        workload, needed, available = disk_match.groups()
        return SafeBackupFailure(
            "WORKER_DISK_FULL",
            f"Not enough free disk space for {workload}: need ~{needed} GB, "
            f"have ~{available} GB free.",
            True,
        )
    inode_match = re.search(
        r"not enough free inodes for [a-z0-9 _-]{1,64}: "
        r"need ~[0-9]+, have ~[0-9]+ free",
        message,
    )
    if inode_match or (
        getattr(underlying, "errno", None) == errno.ENOSPC
        and "inode" in message
    ):
        return SafeBackupFailure(
            "WORKER_INODE_EXHAUSTED",
            "The backup worker does not have enough free filesystem entries for "
            "this website backup.",
            True,
        )
    if "no space left" in message or "disk full" in message:
        return SafeBackupFailure(
            "WORKER_DISK_FULL",
            "The backup worker does not have enough free disk space.",
            True,
        )
    if any(
        marker in message
        for marker in (
            "bad zip",
            "corrupt zip",
            "invalid zip",
            "archive integrity",
            "crc",
        )
    ):
        return SafeBackupFailure(
            "ARCHIVE_VALIDATION_FAILED",
            "The generated backup archive failed integrity validation.",
            True,
        )

    if isinstance(error, BackupStageError):
        failure = _WEBSITE_STAGE_FAILURES.get(error.stage)
        if failure is not None:
            return failure

    connection = classify_connection_error(error, stage=stage)
    if connection.code != "CONNECTION_VALIDATION_FAILED":
        return SafeBackupFailure(
            connection.code,
            connection.detail,
            connection.retryable,
        )
    return SafeBackupFailure(
        "SOURCE_EXPORT_FAILED",
        "The source export failed. BackupSheep will retry without exposing sensitive diagnostics.",
        True,
    )
