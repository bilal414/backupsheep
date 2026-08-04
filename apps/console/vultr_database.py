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
SUPPORTED_ENGINES = {"postgresql", "mysql", "mariadb"}
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
            payload = response.json() if response.content else {}
        except (TypeError, ValueError) as exc:
            raise VultrDatabaseError(
                "Vultr managed database API returned malformed JSON.",
                category="terminal_failure",
                status_code=response.status_code,
            ) from exc

        if response.status_code >= 400:
            if response.status_code == 404:
                category = "not_found"
            elif response.status_code == 429:
                category = "rate_limited"
            elif response.status_code >= 500:
                category = "transient_outage"
            else:
                category = "terminal_failure"
            message = payload.get("error") or payload.get("message") or response.reason
            raise VultrDatabaseError(
                f"Vultr managed database API returned HTTP {response.status_code}: {message}",
                category=category,
                status_code=response.status_code,
                payload=payload,
            )
        return payload

    def list_databases(self):
        """Return every database using Vultr's cursor link, with loop protection."""
        databases = []
        cursor = None
        seen_cursors = set()
        while True:
            params = {"per_page": 500}
            if cursor:
                if cursor in seen_cursors:
                    raise VultrDatabaseError(
                        "Vultr managed database pagination repeated a cursor.",
                        category="terminal_failure",
                    )
                seen_cursors.add(cursor)
                params["cursor"] = cursor
            payload = self._request("GET", "/databases", params=params)
            databases.extend(payload.get("databases") or [])
            cursor = ((payload.get("meta") or {}).get("links") or {}).get("next")
            if not cursor:
                return databases

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
                continue
            detail = self.get_database(database_id)
            usage = self.get_usage(database_id)
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
