"""Vultr Managed Database API primitives.

This module deliberately keeps managed-database semantics separate from the
instance/block-storage Vultr adapter.  Vultr's database backups are provider
managed: BackupSheep records and reconciles the provider's backup metadata, but
does not enable or change the source cluster's backup schedule.
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.api.v1.utils.http import requests
from django.conf import settings
from apps.console.vultr import vultr_request_timeout


VULTR_DATABASE_API_TIMEOUT = (10, 60)
SUPPORTED_ENGINES = {"postgresql", "mysql", "mariadb", "valkey"}
PITR_ENGINES = {"postgresql", "mysql", "mariadb"}


VULTR_DATABASE_ERROR_MESSAGES = {
    "auth_failed": "Vultr managed database authentication failed.",
    "not_found": "Vultr could not find the managed database resource.",
    "rate_limited": "Vultr rate-limited the managed database request; it will resume automatically.",
    "timeout": "The Vultr managed database request timed out; its outcome is being reconciled.",
    "transient_outage": "Vultr is temporarily unavailable; the managed database operation will resume.",
    "malformed_response": "Vultr returned an invalid managed database response.",
    "duplicate_candidates": "Multiple Vultr managed database resources matched; manual review is required.",
    "unsupported": "The requested Vultr managed database operation is not supported.",
    "terminal_failure": "Vultr rejected the managed database operation.",
}


def safe_vultr_database_message(category, status_code=None):
    """Return an allowlisted message suitable for durable/user-visible state."""
    message = VULTR_DATABASE_ERROR_MESSAGES.get(
        str(category or "terminal_failure"),
        VULTR_DATABASE_ERROR_MESSAGES["terminal_failure"],
    )
    if status_code is not None:
        try:
            return f"{message} (HTTP {int(status_code)})."
        except (TypeError, ValueError):
            pass
    return message


_SAFE_DATABASE_RECORD_KEYS = frozenset(
    {
        "id", "label", "name", "database_engine", "engine", "region", "plan",
        "status", "state", "date", "time", "date_created", "created_at", "updated_at",
        "latest_backup", "oldest_backup", "backup", "backups", "disk", "usage", "size",
        "size_gb", "type", "source_id", "source_database_id", "database_id", "parent_id",
        "job_id", "operation_id", "storage_bytes", "storageBytes", "version",
    }
)


def safe_vultr_database_record(value, *, _depth=0):
    """Keep provider metadata useful while excluding bodies and credentials."""
    if _depth > 3:
        return None
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text not in _SAFE_DATABASE_RECORD_KEYS:
                continue
            sanitized = safe_vultr_database_record(item, _depth=_depth + 1)
            if sanitized is not None:
                result[key_text] = sanitized
        return result
    if isinstance(value, list):
        return [
            sanitized
            for item in value[:500]
            if (sanitized := safe_vultr_database_record(item, _depth=_depth + 1)) is not None
        ]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)[:512] if isinstance(value, str) else value
    return None


class VultrDatabaseError(Exception):
    """A provider error with a stable classification for polling/recovery."""

    def __init__(
        self,
        message,
        *,
        category="terminal_failure",
        status_code=None,
        payload=None,
        retry_after=None,
        unknown_outcome=False,
    ):
        self.category = category
        self.status_code = status_code
        # Do not retain provider response bodies or exception text on an
        # exception that may be written to a restore/backup row by a caller.
        self.payload = {"status_code": status_code} if status_code is not None else {}
        self.retry_after = retry_after
        self.unknown_outcome = bool(unknown_outcome)
        super().__init__(safe_vultr_database_message(category, status_code))


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
        method = str(method or "GET").upper()
        mutation = method in {"POST", "PUT", "PATCH", "DELETE"}
        try:
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                headers=self.auth.get_client(),
                params=params,
                json=body,
                timeout=vultr_request_timeout(),
                verify=True,
            )
        except requests.RequestException as exc:
            raise VultrDatabaseError(
                None,
                category=(
                    "timeout" if isinstance(exc, requests.Timeout) else "transient_outage"
                ),
                unknown_outcome=mutation,
            ) from exc
        except Exception as exc:
            # Auth/decryption/client setup failures must not escape with their
            # provider/client text, and a failed mutating call is conservative.
            name = exc.__class__.__name__.lower()
            category = "auth_failed" if any(
                marker in name for marker in ("auth", "credential", "permission")
            ) else "terminal_failure"
            raise VultrDatabaseError(
                None, category=category, unknown_outcome=mutation
            ) from exc

        try:
            status_code = response.status_code
            try:
                payload = response.json() if getattr(response, "content", b"") else {}
            except (TypeError, ValueError) as exc:
                raise VultrDatabaseError(
                    None,
                    category="malformed_response",
                    status_code=status_code,
                    unknown_outcome=mutation,
                ) from exc

            if not isinstance(payload, dict):
                raise VultrDatabaseError(
                    None,
                    category="malformed_response",
                    status_code=status_code,
                    unknown_outcome=mutation,
                )

            if status_code >= 400:
                if status_code in (401, 403):
                    category = "auth_failed"
                elif status_code == 404:
                    category = "not_found"
                elif status_code == 429:
                    category = "rate_limited"
                elif status_code >= 500:
                    category = "transient_outage"
                else:
                    category = "terminal_failure"
                raise VultrDatabaseError(
                    None,
                    category=category,
                    status_code=status_code,
                    retry_after=(
                        (getattr(response, "headers", {}) or {}).get("Retry-After")
                        if status_code == 429
                        else None
                    ),
                    # A rate-limit/auth/not-found response is an explicit
                    # rejection.  A 5xx response to a mutation may have been
                    # accepted and therefore requires reconciliation.
                    unknown_outcome=mutation and status_code >= 500,
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
        # Vultr's managed-database API exposes this as the plural ``backups``
        # collection.  The singular path may look intuitive but returns 404.
        return self._request("GET", f"/databases/{database_id}/backups")

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
            return [safe_vultr_database_record(record) for record in records]
        records = []
        for key in ("latest_backup", "oldest_backup", "backup"):
            value = payload.get(key)
            if isinstance(value, dict) and value not in records:
                records.append(safe_vultr_database_record(value))
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
            detail = safe_vultr_database_record(self.get_database(database_id))
            usage = safe_vultr_database_record(self.get_usage(database_id))
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
        try:
            return self._request("POST", f"/databases/{database_id}/fork", body=body)
        except VultrDatabaseError as error:
            # A test double or an alternate client may raise a categorized
            # transient error without setting the mutation fence. Treat it as
            # unknown conservatively: never issue a second fork automatically.
            if error.category in {"timeout", "transient_outage"}:
                error.unknown_outcome = True
            raise


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
    state = str(record.get("state") or record.get("status") or "").strip().lower()
    # The documented ``/databases/{id}/backups`` response exposes
    # ``latest_backup``/``oldest_backup`` as available date/time metadata and
    # does not include a state field. Presence of that record is therefore an
    # available provider backup, not an indeterminate in-progress operation.
    return state or "available"


def provider_database_id(payload):
    database = payload.get("database") if isinstance(payload, dict) else None
    database = database if isinstance(database, dict) else payload
    return database.get("id") if isinstance(database, dict) else None
