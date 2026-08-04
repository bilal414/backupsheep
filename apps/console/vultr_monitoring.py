"""Read-only monitoring helpers for provider-managed Vultr backups.

Vultr automatic instance backups are owned and retained by Vultr.  They are
intentionally kept outside the BackupSheep snapshot lifecycle: this module only
lists and sanitizes their status for observability and never mutates them.
"""

from __future__ import annotations

from typing import Any

import requests
from django.conf import settings


DEFAULT_VULTR_TIMEOUT = (10, 60)


class VultrMonitoringError(Exception):
    """A safe, user-facing error from a read-only Vultr monitoring call."""

    def __init__(self, message: str, *, classification: str, status_code: int | None = None):
        super().__init__(message)
        self.classification = classification
        self.status_code = status_code


def _request_timeout():
    return getattr(settings, "VULTR_API_TIMEOUT", DEFAULT_VULTR_TIMEOUT)


def _safe_backup(record: Any) -> dict[str, Any]:
    """Return only non-sensitive provider backup fields."""

    if not isinstance(record, dict):
        return {}
    allowed = (
        "id",
        "instance_id",
        "date_created",
        "status",
        "size",
        "type",
        "description",
        "region",
    )
    return {key: record[key] for key in allowed if key in record}


def list_instance_backups(auth, *, instance_id: str | None = None) -> list[dict[str, Any]]:
    """List Vultr-managed instance backups using cursor pagination.

    The function is deliberately strict: a failed page, malformed JSON, or a
    repeated cursor raises instead of returning a partial inventory that could
    be mistaken for a complete monitoring result.
    """

    params: dict[str, Any] = {"per_page": 500}
    if instance_id:
        params["instance_id"] = instance_id
    cursor = None
    seen_cursors: set[str] = set()
    backups: list[dict[str, Any]] = []

    while True:
        page_params = dict(params)
        if cursor:
            page_params["cursor"] = cursor
        try:
            response = requests.get(
                f"{settings.VULTR_API}/v2/backups",
                headers=auth.get_client(),
                params=page_params,
                verify=True,
                timeout=_request_timeout(),
            )
        except requests.Timeout as error:
            raise VultrMonitoringError(
                "Vultr automatic-backup monitoring timed out.",
                classification="transient_timeout",
            ) from error
        except requests.RequestException as error:
            raise VultrMonitoringError(
                "Vultr automatic-backup monitoring is temporarily unavailable.",
                classification="transient_unavailable",
            ) from error

        try:
            status_code = response.status_code
            if status_code in (401, 403):
                raise VultrMonitoringError(
                    "Vultr authentication was rejected.",
                    classification="authentication",
                    status_code=status_code,
                )
            if status_code == 429:
                raise VultrMonitoringError(
                    "Vultr rate limit reached while monitoring automatic backups.",
                    classification="rate_limited",
                    status_code=status_code,
                )
            if status_code >= 500:
                raise VultrMonitoringError(
                    "Vultr is temporarily unavailable.",
                    classification="provider_unavailable",
                    status_code=status_code,
                )
            if status_code != 200:
                raise VultrMonitoringError(
                    "Vultr rejected the automatic-backup monitoring request.",
                    classification="provider_error",
                    status_code=status_code,
                )
            payload = response.json()
        except VultrMonitoringError:
            raise
        except (ValueError, TypeError) as error:
            raise VultrMonitoringError(
                "Vultr returned malformed automatic-backup data.",
                classification="malformed_response",
                status_code=getattr(response, "status_code", None),
            ) from error
        finally:
            close = getattr(response, "close", None)
            if close:
                close()

        if not isinstance(payload, dict) or not isinstance(payload.get("backups"), list):
            raise VultrMonitoringError(
                "Vultr returned malformed automatic-backup data.",
                classification="malformed_response",
                status_code=200,
            )
        backups.extend(_safe_backup(item) for item in payload["backups"])

        next_cursor = ((payload.get("meta") or {}).get("links") or {}).get("next")
        if not next_cursor:
            return backups
        if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
            raise VultrMonitoringError(
                "Vultr returned a repeated or malformed pagination cursor.",
                classification="malformed_pagination",
                status_code=200,
            )
        seen_cursors.add(next_cursor)
        cursor = next_cursor
