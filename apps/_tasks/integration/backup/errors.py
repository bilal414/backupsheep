"""Stable, secret-free failure contracts for materialized backup engines."""

from __future__ import annotations

import errno
import re
import zipfile
from dataclasses import dataclass

from celery.exceptions import SoftTimeLimitExceeded

from apps.console.connection.reliability import (
    DATABASE_EVENT_PRIVILEGE_DETAIL,
    classify_connection_error,
)


@dataclass(frozen=True)
class SafeBackupFailure:
    code: str
    detail: str
    retryable: bool


def safe_backup_failure(error, *, stage="backup"):
    """Classify an exception without returning its provider or command text."""
    if isinstance(error, (SoftTimeLimitExceeded, TimeoutError)) or getattr(
        error, "errno", None
    ) == errno.ETIMEDOUT:
        return SafeBackupFailure(
            "BACKUP_TIMEOUT",
            "The source did not finish the backup operation before its timeout.",
            True,
        )
    if isinstance(error, zipfile.BadZipFile):
        return SafeBackupFailure(
            "ARCHIVE_VALIDATION_FAILED",
            "The generated backup archive failed integrity validation.",
            True,
        )

    # Inspect only for classification. The source string is never returned,
    # persisted, logged, or placed in notifications.
    message = str(error).lower()
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
