"""Read-only monitoring helpers for provider-managed Vultr backups.

Vultr automatic instance backups are owned and retained by Vultr.  They are
intentionally kept outside the BackupSheep snapshot lifecycle: this module only
lists and sanitizes their status for observability and never mutates them.
"""

from __future__ import annotations

from typing import Any

from apps.api.v1.utils.http import requests
from django.conf import settings

from apps.console.vultr import vultr_request_timeout


DEFAULT_VULTR_TIMEOUT = (10, 60)

VULTR_MONITORING_PUBLIC_MESSAGES = {
    "authentication": "Vultr authentication was rejected.",
    "not_found": "Vultr could not find the automatic-backup resource.",
    "rate_limited": "Vultr rate-limited automatic-backup monitoring.",
    "transient_timeout": "Vultr automatic-backup monitoring timed out.",
    "transient_unavailable": "Vultr automatic-backup monitoring is temporarily unavailable.",
    "provider_unavailable": "Vultr is temporarily unavailable.",
    "provider_error": "Vultr rejected the automatic-backup monitoring request.",
    "malformed_response": "Vultr returned malformed automatic-backup data.",
    "malformed_pagination": "Vultr returned malformed automatic-backup pagination.",
    "duplicate_inventory": "Vultr returned duplicate automatic-backup records.",
}


def vultr_monitoring_public_message(classification, status_code=None):
    """Return a constant allowlisted message without exposing exception text."""

    safe_message = VULTR_MONITORING_PUBLIC_MESSAGES.get(
        classification, VULTR_MONITORING_PUBLIC_MESSAGES["provider_error"]
    )
    if status_code is not None:
        try:
            safe_message = f"{safe_message} (HTTP {int(status_code)})."
        except (TypeError, ValueError):
            pass
    return safe_message


class VultrMonitoringError(Exception):
    """A safe, user-facing error from a read-only Vultr monitoring call."""

    def __init__(
        self,
        message: str | None = None,
        *,
        classification: str,
        status_code: int | None = None,
        retry_after: int | None = None,
    ):
        # ``message`` is intentionally ignored for the public exception text;
        # callers may pass provider response text, which must never be durable.
        safe_message = vultr_monitoring_public_message(classification, status_code)
        super().__init__(safe_message)
        self.classification = classification
        self.status_code = status_code
        self.retry_after = retry_after


def _request_timeout():
    return vultr_request_timeout()


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
                classification="transient_timeout",
            ) from error
        except requests.RequestException as error:
            raise VultrMonitoringError(
                classification="transient_unavailable",
            ) from error
        except Exception as error:
            raise VultrMonitoringError(
                classification="authentication",
            ) from error

        try:
            status_code = response.status_code
            if status_code in (401, 403):
                raise VultrMonitoringError(
                    classification="authentication",
                    status_code=status_code,
                )
            if status_code == 404:
                raise VultrMonitoringError(
                    classification="not_found", status_code=status_code
                )
            if status_code == 429:
                retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")
                try:
                    retry_after = max(1, min(int(retry_after), 3600))
                except (TypeError, ValueError):
                    retry_after = None
                raise VultrMonitoringError(
                    classification="rate_limited",
                    status_code=status_code,
                    retry_after=retry_after,
                )
            if status_code in (408, 425, 504):
                raise VultrMonitoringError(
                    classification="transient_timeout", status_code=status_code
                )
            if status_code >= 500:
                raise VultrMonitoringError(
                    classification="provider_unavailable",
                    status_code=status_code,
                )
            if status_code != 200:
                raise VultrMonitoringError(
                    classification="provider_error",
                    status_code=status_code,
                )
            payload = response.json()
        except VultrMonitoringError:
            raise
        except (ValueError, TypeError) as error:
            raise VultrMonitoringError(
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
        safe_page = []
        page_ids = set()
        for item in payload["backups"]:
            if not isinstance(item, dict):
                raise VultrMonitoringError(
                    classification="malformed_response", status_code=200
                )
            provider_id = item.get("id")
            if provider_id in (None, ""):
                raise VultrMonitoringError(
                    classification="malformed_response", status_code=200
                )
            if str(provider_id) in page_ids:
                raise VultrMonitoringError(
                    classification="duplicate_inventory", status_code=200
                )
            page_ids.add(str(provider_id))
            safe_page.append(_safe_backup(item))
        known_ids = {str(item.get("id")) for item in backups if item.get("id")}
        if known_ids.intersection(page_ids):
            raise VultrMonitoringError(
                classification="duplicate_inventory", status_code=200
            )
        backups.extend(safe_page)

        next_cursor = ((payload.get("meta") or {}).get("links") or {}).get("next")
        if not next_cursor:
            return backups
        if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
            raise VultrMonitoringError(
                classification="malformed_pagination",
                status_code=200,
            )
        seen_cursors.add(next_cursor)
        cursor = next_cursor
