"""Vultr Managed Database API primitives.

This module deliberately keeps managed-database semantics separate from the
instance/block-storage Vultr adapter.  Vultr's database backups are provider
managed: BackupSheep records and reconciles the provider's backup metadata, but
does not enable or change the source cluster's backup schedule.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests
from django.conf import settings


VULTR_DATABASE_API_TIMEOUT = (10, 60)
SUPPORTED_ENGINES = {"postgresql", "mysql", "mariadb", "valkey"}
PITR_ENGINES = {"postgresql", "mysql", "mariadb"}


class VultrDatabaseError(Exception):
    """A provider error with a stable classification for polling/recovery."""

    def __init__(self, message, *, category="terminal_failure", status_code=None, payload=None):
        super().__init__(message)
        self.category = category
        self.status_code = status_code
        self.payload = payload if isinstance(payload, dict) else {}


class VultrDatabaseUnsupportedError(VultrDatabaseError):
    def __init__(self, message):
        super().__init__(message, category="unsupported")


class VultrDatabaseDuplicateError(VultrDatabaseError):
    def __init__(self, message):
        super().__init__(message, category="duplicate_candidates")


@dataclass(frozen=True)
class VultrDatabaseCapabilities:
    engine: str
    plan: str

    @property
    def normalized_engine(self):
        return (self.engine or "").strip().lower()

    @property
    def normalized_plan(self):
        return (self.plan or "").strip().lower()

    def require_backup_support(self):
        if self.normalized_engine not in SUPPORTED_ENGINES:
            raise VultrDatabaseUnsupportedError(
                f"Vultr managed database engine '{self.engine}' is not supported; "
                f"supported engines are {', '.join(sorted(SUPPORTED_ENGINES))}."
            )

    def require_fork_support(self, mode="basebackup"):
        self.require_backup_support()
        if "hobbyist" in self.normalized_plan:
            raise VultrDatabaseUnsupportedError(
                "Vultr user-initiated managed-database recovery/fork is not "
                "available on Hobbyist plans."
            )
        if mode == "pitr" and self.normalized_engine not in PITR_ENGINES:
            raise VultrDatabaseUnsupportedError(
                f"Point-in-time recovery is not supported for engine '{self.engine}'."
            )
        if mode not in {"basebackup", "pitr"}:
            raise VultrDatabaseUnsupportedError(
                f"Unsupported Vultr managed-database recovery mode '{mode}'."
            )


class VultrManagedDatabaseClient:
    """Small, timeout-bound client for the documented Vultr v2 database API."""

    def __init__(self, auth):
        self.auth = auth
        self.base_url = settings.VULTR_API.rstrip("/") + "/v2"

    def _request(self, method, path, *, params=None, body=None):
        try:
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                headers=self.auth.get_client(),
                params=params,
                json=body,
                timeout=getattr(settings, "VULTR_API_TIMEOUT", VULTR_DATABASE_API_TIMEOUT),
                verify=True,
            )
        except requests.RequestException as exc:
            raise VultrDatabaseError(
                f"Vultr managed database API is temporarily unreachable: {exc}",
                category="transient_outage",
            ) from exc

        try:
            status_code = response.status_code
            try:
                payload = response.json() if getattr(response, "content", b"") else {}
            except (TypeError, ValueError) as exc:
                raise VultrDatabaseError(
                    "Vultr managed database API returned malformed JSON.",
                    category="terminal_failure",
                    status_code=status_code,
                ) from exc

            if not isinstance(payload, dict):
                raise VultrDatabaseError(
                    "Vultr managed database API returned a malformed response object.",
                    category="terminal_failure",
                    status_code=status_code,
                )

            if status_code >= 400:
                if status_code == 404:
                    category = "not_found"
                elif status_code == 429:
                    category = "rate_limited"
                elif status_code >= 500:
                    category = "transient_outage"
                else:
                    category = "terminal_failure"
                message = payload.get("error") or payload.get("message") or getattr(
                    response, "reason", "provider error"
                )
                raise VultrDatabaseError(
                    f"Vultr managed database API returned HTTP {status_code}: {message}",
                    category=category,
                    status_code=status_code,
                    payload=payload,
                )
            return payload
        finally:
            close = getattr(response, "close", None)
            if close:
                close()

    def list_databases(self):
        """Return every database using Vultr's cursor link, with loop protection."""
        databases = []
        cursor = None
        seen_cursors = set()
        while True:
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            payload = self._request("GET", "/databases", params=params)
            page = payload.get("databases")
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise VultrDatabaseError(
                    "Vultr managed database API returned malformed database inventory.",
                    category="terminal_failure",
                )
            databases.extend(page)
            links = (payload.get("meta") or {}).get("links") or {}
            if not isinstance(links, dict):
                raise VultrDatabaseError(
                    "Vultr managed database API returned malformed pagination links.",
                    category="terminal_failure",
                )
            next_cursor = links.get("next")
            if next_cursor in (None, ""):
                return databases
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                raise VultrDatabaseError(
                    "Vultr managed database API returned a malformed pagination cursor.",
                    category="terminal_failure",
                )
            if next_cursor in seen_cursors:
                raise VultrDatabaseError(
                    "Vultr managed database pagination repeated a cursor.",
                    category="terminal_failure",
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor

    def get_database(self, database_id):
        return self._request("GET", f"/databases/{database_id}").get("database") or {}

    def get_usage(self, database_id):
        return self._request("GET", f"/databases/{database_id}/usage")

    def get_backup_metadata(self, database_id):
        return self._request("GET", f"/databases/{database_id}/backup")

    def list_backup_records(self, database_id):
        """Normalize the provider's backup metadata into a list of records."""
        payload = self.get_backup_metadata(database_id)
        records = payload.get("backups")
        if isinstance(records, list):
            if any(not isinstance(record, dict) for record in records):
                raise VultrDatabaseError(
                    "Vultr managed database API returned malformed backup metadata.",
                    category="terminal_failure",
                )
            return records
        records = []
        for key in ("latest_backup", "oldest_backup", "backup"):
            value = payload.get(key)
            if isinstance(value, dict) and value not in records:
                records.append(value)
        return records

    def discover_databases(self):
        discovered = []
        for database in self.list_databases():
            database_id = database.get("id")
            if not database_id:
                raise VultrDatabaseError(
                    "Vultr managed database inventory contained a record without an id.",
                    category="terminal_failure",
                )
            detail = self.get_database(database_id)
            usage = self.get_usage(database_id)
            if not isinstance(detail, dict) or not isinstance(usage, dict):
                raise VultrDatabaseError(
                    "Vultr managed database detail or usage response was malformed.",
                    category="terminal_failure",
                )
            merged = dict(database)
            merged.update(detail)
            merged["usage"] = usage
            merged["_bs_unique_id"] = database_id
            merged["_bs_name"] = merged.get("label") or database_id
            merged["_bs_region"] = merged.get("region")
            merged["_bs_size"] = (
                (usage.get("disk") or {}).get("usage")
                if isinstance(usage.get("disk"), dict)
                else usage.get("disk")
            )
            engine = str(merged.get("database_engine") or merged.get("engine") or "").lower()
            merged["_bs_engine"] = engine
            merged["_bs_supported"] = engine in SUPPORTED_ENGINES
            if not merged["_bs_supported"]:
                merged["_bs_unsupported_reason"] = (
                    f"Vultr managed database engine '{engine or 'unknown'}' is not supported."
                )
            discovered.append(merged)
        return discovered

    def fork_database(self, database_id, body):
        return self._request("POST", f"/databases/{database_id}/fork", body=body)


def provider_backup_id(record):
    return str(
        record.get("id")
        or record.get("backup_id")
        or record.get("date")
        or record.get("created_at")
        or record.get("created")
        or ""
    )


def provider_backup_state(record):
    return str(record.get("state") or record.get("status") or "").strip().lower()


def provider_database_id(payload):
    database = payload.get("database") if isinstance(payload, dict) else None
    database = database if isinstance(database, dict) else payload
    return database.get("id") if isinstance(database, dict) else None
