"""Fail-closed capability policy for source families without recovery parity.

Basecamp can create archive rows, but the current BSE1 pipeline has no authenticated
plaintext export or automatic restore for that family. A successful backup is
therefore not a recoverable enterprise backup. Keep one small policy module at every
creation/dispatch boundary so a UI flag, stale schedule, direct API call, or replayed
Celery message cannot bypass that fact.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException


RECOVERY_INCOMPLETE_SOURCE_FAMILIES = frozenset({"basecamp"})
RETIRED_SOURCE_FAMILIES = frozenset({"wordpress"})
SOURCE_CREATION_POLICY_FAMILIES = (
    RECOVERY_INCOMPLETE_SOURCE_FAMILIES | RETIRED_SOURCE_FAMILIES
)

SOURCE_RECOVERY_UNAVAILABLE_MESSAGE = (
    "New protection and backup runs for this source are unavailable because this "
    "installation cannot provide a complete recovery workflow. Existing backup "
    "records remain available for inspection. Use a source with a tested restore "
    "workflow."
)


class SourceRecoveryUnavailable(APIException):
    """Public-safe refusal shared by HTTP and worker entry points."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
    default_code = "source_recovery_unavailable"


def _strict_setting_true(name: str) -> bool:
    """Treat missing, malformed, and string-valued policy settings as disabled."""

    return getattr(settings, name, None) is True


def source_backup_creation_available(integration_code: str | None) -> bool:
    """Return whether this installation may create backups for ``integration_code``.

    Supported source families are unaffected.  Recovery-incomplete families are
    never available in enterprise mode or with BSE1 because their only currently
    usable recovery path is an authenticated download of a legacy plaintext
    archive.  That compatibility path requires every prerequisite to be explicit.
    """

    code = str(integration_code or "").strip().lower()
    if code in RETIRED_SOURCE_FAMILIES:
        return False
    if code not in RECOVERY_INCOMPLETE_SOURCE_FAMILIES:
        return True

    if _strict_setting_true("BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE"):
        return False
    if str(
        getattr(settings, "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE", "")
    ).strip().lower() != "legacy-only":
        return False
    if not _strict_setting_true("BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE"):
        return False

    feature_setting = f"{code.upper()}_INTEGRATION_ENABLED"
    return _strict_setting_true(feature_setting)


def require_source_backup_creation(integration_code: str | None) -> None:
    """Raise a stable conflict before any source/backup mutation or dispatch."""

    if not source_backup_creation_available(integration_code):
        raise SourceRecoveryUnavailable()


def available_backup_endpoints(endpoints) -> list[str]:
    """Remove unavailable source families from a public capability list."""

    return [
        str(endpoint)
        for endpoint in endpoints
        if source_backup_creation_available(str(endpoint))
    ]
