"""Safety-gated live Vultr E2E test for BackupSheep.

This harness is intentionally opt-in and destructive only for resources that it
creates itself.  It creates disposable Vultr compute, block-storage, managed
database, and object-storage resources with a unique run marker, drives the
existing BackupSheep adapters against those resources, records provider/local
evidence, and deletes only resources whose exact IDs and ownership fields match
the run ledger.

Run inside the application image (which has Django, requests, and boto3):

    VULTR_API_KEY=... \
    VULTR_E2E_ALLOW_MUTATION=YES \
    BACKUPSHEEP_E2E_RUN_ID=bs-e2e-vultr-20260810-a1b2c3d4 \
    BACKUPSHEEP_E2E_LEDGER_PATH=/code/_storage/e2e-ledgers/vultr.json \
    BACKUPSHEEP_E2E_CLEANUP=YES \
      python scripts/vultr_live_e2e.py --report /code/docs/vultr-live-e2e-test-report.md

The token is read only from the environment and is never written to the report
or printed.  ``VULTR_E2E_ALLOW_MUTATION=YES`` remains a compatibility alias for
``BACKUPSHEEP_E2E_APPLY=YES``. Cleanup is an independent provider write and is
performed only when both apply and cleanup are explicitly enabled. This test has
real provider cost and may take 20-45 minutes, mostly because managed database
provisioning and deletion are asynchronous. Reuse the same run ID and ledger
path after a crash to reconcile the exact run-owned resources.
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import fcntl
import hashlib
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import boto3
import django
import requests
from botocore.client import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


def _prefer_ipv6_for_live_provider_egress() -> None:
    """Prefer the API-key allow-listed address family in this process.

    The test machine's Vultr key permits IPv6 but not its Docker/NAT IPv4
    address.  Requests delegates address selection to ``socket.getaddrinfo``;
    reordering the returned addresses keeps TLS/SNI and request behavior intact
    while allowing the live harness to use the already-authorized path.  This
    is scoped to this executable and never changes application provider code.
    """

    original = socket.getaddrinfo

    def getaddrinfo_ipv6_first(host, port, *args, **kwargs):
        values = original(host, port, *args, **kwargs)
        return sorted(values, key=lambda item: 0 if item[0] == socket.AF_INET6 else 1)

    socket.getaddrinfo = getaddrinfo_ipv6_first


_prefer_ipv6_for_live_provider_egress()
django.setup()

from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from django.conf import settings as django_settings  # noqa: E402
from apps.console.account.models import CoreAccount  # noqa: E402
from apps.console.backup.models import (  # noqa: E402
    CoreCloudRestore,
    CoreVultrBackup,
    CoreVultrDatabaseBackup,
    CoreVultrDatabaseRestore,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.connection.models import (  # noqa: E402
    CoreAuthVultr,
    CoreConnection,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.console.node.models import (  # noqa: E402
    CoreNode,
    CoreVultr,
    CoreVultrDatabase,
)
import apps.console.node.models as node_models  # noqa: E402
from apps.console.storage.models import (  # noqa: E402
    CoreStorage,
    CoreStorageType,
    CoreStorageVultr,
)
from apps.console.utils.models import UtilBackup  # noqa: E402
from apps.tests import factories  # noqa: E402
from apps._tasks.integration.storage.vultr import (  # noqa: E402
    VULTR_OBJECT_METADATA_KEY,
    storage_vultr,
)
from apps._tasks.integration.storage.s3_verified import _save_state  # noqa: E402
from apps.console.vultr_monitoring import list_instance_backups  # noqa: E402


class HarnessError(RuntimeError):
    """A fail-closed harness error."""


class ProviderNotFound(HarnessError):
    """The exact requested Vultr resource does not exist."""


class ProviderRateLimited(HarnessError):
    """A provider read remains resumable after rate limiting."""

    category = "PROVIDER_RATE_LIMITED"


class ProviderTransientFailure(HarnessError):
    """A provider read remains resumable after an outage or timeout."""

    category = "PROVIDER_TRANSIENT_FAILURE"


class ProviderTerminalFailure(HarnessError):
    """The provider returned a terminal operation state."""

    category = "PROVIDER_TERMINAL_FAILURE"


class AmbiguousMutation(HarnessError):
    """A provider mutation may have been accepted but its response was lost."""


def _validate_vultr_api_base(value: str) -> str:
    """Return the only API origin this harness is allowed to call.

    The live harness carries a bearer token, so an endpoint override is not a
    harmless convenience.  Keep this exact and intentionally stricter than the
    production setting: no redirectable host, port, path, query, or fragment.
    """

    raw = str(value or "")
    try:
        parsed = urlsplit(raw)
        has_port = parsed.port is not None
    except ValueError:
        has_port = True
        parsed = None
    if (
        raw != "https://api.vultr.com/v2"
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != "api.vultr.com"
        or parsed.username is not None
        or parsed.password is not None
        or has_port
        or parsed.path != "/v2"
        or parsed.query
        or parsed.fragment
    ):
        raise HarnessError(
            "Vultr API base must be exactly https://api.vultr.com/v2."
        )
    return raw


def _canonical_request(value: dict[str, Any]) -> str:
    """Serialize an immutable, non-secret request deterministically."""

    if not isinstance(value, dict):
        raise HarnessError("Vultr mutation request parameters must be an object.")
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise HarnessError("Vultr mutation request parameters are not canonicalizable.") from error


def _request_fingerprint(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_request(value).encode("utf-8")).hexdigest()


def _credential_scope(api_base: str, run_id: str, token: str) -> str:
    """Bind a durable ledger to this credential without storing a fast hash.

    API tokens are high-entropy credentials, but a truncated unsalted digest still
    gives anyone who obtains the ledger a cheap offline token oracle. A run-scoped
    scrypt fingerprint preserves deterministic crash recovery while making that
    oracle deliberately expensive and domain-separated from every other use.
    """

    token_bytes = str(token or "").encode("utf-8")
    if not token_bytes:
        raise HarnessError("A Vultr credential is required for the ledger scope.")
    salt = f"backupsheep:vultr-live-e2e:{require_run_id(run_id)}".encode("utf-8")
    fingerprint = hashlib.scrypt(
        token_bytes,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    ).hex()
    return f"{api_base}:credential-scrypt-{fingerprint}"


def _retry_after_seconds(value: Any, *, now: dt.datetime | None = None) -> int | None:
    """Parse Retry-After seconds or HTTP-date, bounded for this harness."""

    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = int(value)
    else:
        text = str(value).strip()
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            seconds = int(text)
        else:
            try:
                target = email.utils.parsedate_to_datetime(text)
            except (TypeError, ValueError, OverflowError):
                return None
            if target is None:
                return None
            if target.tzinfo is None:
                target = target.replace(tzinfo=dt.timezone.utc)
            current = now or dt.datetime.now(dt.timezone.utc)
            seconds = int((target - current).total_seconds())
    return max(1, min(30, seconds))


def _validate_vultr_object_storage_hostname(value: str) -> str:
    """Validate a provider-returned S3 hostname before credentials are used.

    Vultr documents Object Storage endpoints as ``<location>.vultrobjects.com``.
    Accept one DNS label under that suffix only.  The returned value is a bare
    hostname because callers add the HTTPS scheme themselves.
    """

    raw = str(value or "")
    labels = raw.split(".")
    label = labels[0] if len(labels) == 3 else ""
    label_ok = bool(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(char.isalnum() or char == "-" for char in label)
        and all(ord(char) < 128 for char in raw)
    )
    try:
        parsed = urlsplit(f"https://{raw}")
        has_port = parsed.port is not None
    except ValueError:
        parsed = None
        has_port = True
    if (
        not label_ok
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != raw
        or parsed.username is not None
        or parsed.password is not None
        or has_port
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not raw.endswith(".vultrobjects.com")
    ):
        raise HarnessError(
            "Vultr Object Storage s3_hostname must be a bare HTTPS hostname "
            "under *.vultrobjects.com."
        )
    return raw


class MutationIntentStore:
    """Atomic sidecar recording non-idempotent mutation intent.

    The shared ``DurableResourceLedger`` deliberately records only confirmed
    provider IDs.  This sidecar fills the gap before a create request: after a
    worker crash or lost response, a restart must reconcile the deterministic
    marker and must never blindly submit the create request a second time.
    """

    def __init__(self, ledger_path: str | os.PathLike[str], *, run_id: str, scope: str):
        if not ledger_path:
            raise LedgerError("A ledger path is required for Vultr mutation intents.")
        self.path = Path(ledger_path).expanduser().resolve().with_name(
            Path(ledger_path).name + ".intents.json"
        )
        self.run_id = require_run_id(run_id)
        self.scope = str(scope)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        with self._locked():
            if self.path.exists():
                self._validate(self._read())
            else:
                self._write(
                    {
                        "schema": 1,
                        "provider": "vultr",
                        "run_id": self.run_id,
                        "scope": self.scope,
                        "pending": {},
                    }
                )

    def _locked(self):
        store = self

        class Lock:
            def __enter__(self):
                self.handle = open(store.lock_path, "a+", encoding="utf-8")
                os.chmod(store.lock_path, 0o600)
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self.handle

            def __exit__(self, exc_type, exc, tb):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                self.handle.close()

        return Lock()

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as source:
                return json.load(source)
        except (OSError, ValueError) as error:
            raise LedgerError("The Vultr mutation intent sidecar could not be read.") from error

    def _validate(self, payload):
        if not isinstance(payload, dict) or payload.get("schema") != 1:
            raise LedgerError("The Vultr mutation intent sidecar is malformed.")
        if (
            payload.get("provider") != "vultr"
            or payload.get("run_id") != self.run_id
            or payload.get("scope") != self.scope
        ):
            raise LedgerError("The Vultr mutation intent sidecar scope does not match.")
        if not isinstance(payload.get("pending"), dict):
            raise LedgerError("The Vultr mutation intent pending map is malformed.")
        for key, value in payload["pending"].items():
            if not isinstance(value, dict):
                raise LedgerError(f"The Vultr mutation intent {key} is malformed.")
            marker = str(value.get("marker") or "")
            operation = str(value.get("operation") or "")
            request = value.get("request")
            fingerprint = str(value.get("fingerprint") or "")
            if not marker or not operation or not isinstance(request, dict):
                raise LedgerError(
                    f"The Vultr mutation intent {key} lacks its immutable witness."
                )
            if len(fingerprint) != 64 or any(
                character not in "0123456789abcdef" for character in fingerprint
            ) or fingerprint != _request_fingerprint(request):
                raise LedgerError(
                    f"The Vultr mutation intent {key} has an invalid request fingerprint."
                )
        return payload

    def _write(self, payload):
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, key):
        with self._locked():
            payload = self._validate(self._read())
            value = payload["pending"].get(str(key))
            return dict(value) if isinstance(value, dict) else None

    def set(self, key, value):
        if not isinstance(value, dict) or not value.get("marker"):
            raise LedgerError("A Vultr mutation intent requires a deterministic marker.")
        request = value.get("request")
        fingerprint = str(value.get("fingerprint") or "")
        if not isinstance(request, dict) or fingerprint != _request_fingerprint(request):
            raise LedgerError(
                "A Vultr mutation intent requires a canonical request fingerprint."
            )
        with self._locked():
            payload = self._validate(self._read())
            current = payload["pending"].get(str(key))
            if current is not None and current != value:
                raise LedgerError("A Vultr mutation intent already has another witness.")
            payload["pending"][str(key)] = dict(value)
            self._write(payload)

    def clear(self, key):
        with self._locked():
            payload = self._validate(self._read())
            payload["pending"].pop(str(key), None)
            self._write(payload)

    def clear_all(self):
        with self._locked():
            payload = self._validate(self._read())
            payload["pending"] = {}
            self._write(payload)

    def pending(self):
        with self._locked():
            payload = self._validate(self._read())
            return {
                key: dict(value)
                for key, value in payload["pending"].items()
                if isinstance(value, dict)
            }


class LiveVultrHarness:
    api_base = "https://api.vultr.com/v2"
    timeout = (10, 60)
    region = "ewr"
    server_plan = "vc2-1c-1gb"
    os_id = 2284  # Ubuntu 24.04 LTS x64, selected by read-only preflight.
    block_size_gb = 10
    database_plan = "vultr-dbaas-startup-cc-1-55-2"
    database_engine = "pg"
    database_engine_version = "16"
    object_cluster_id = 2  # ewr1.vultrobjects.com
    object_tier_id = 2  # Standard; selected from the live tier inventory.

    def __init__(self, report_path: str | None = None):
        try:
            self.prefix = self._explicit_run_id()
        except LedgerError as error:
            raise HarnessError(str(error)) from error
        self.token = os.environ.get("VULTR_API_KEY", "").strip()
        if not self.token:
            raise HarnessError("VULTR_API_KEY is required; it is never read from a repository file.")
        self.api_base = _validate_vultr_api_base(self.api_base)
        adapter_base = str(getattr(django_settings, "VULTR_API", ""))
        if adapter_base != "https://api.vultr.com":
            raise HarnessError(
                "The configured BackupSheep Vultr adapter base must be exactly "
                "https://api.vultr.com before this live harness can run."
            )
        self.apply = (
            os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
            or os.environ.get("VULTR_E2E_ALLOW_MUTATION") == "YES"
        )
        self.cleanup_requested = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
        if self.cleanup_requested and not self.apply:
            raise HarnessError(
                "Vultr cleanup is a provider write and requires both "
                "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES."
            )
        if not self.apply:
            raise HarnessError(
                "Refusing provider mutations. Set VULTR_E2E_ALLOW_MUTATION=YES "
                "or BACKUPSHEEP_E2E_APPLY=YES for this disposable run."
            )

        ledger_path = (
            os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH")
            or str(ROOT / "_storage" / "e2e-ledgers" / f"{self.prefix}.json")
        )
        scope = _credential_scope(self.api_base, self.prefix, self.token)
        self.ledger = DurableResourceLedger(
            ledger_path,
            provider="vultr",
            run_id=self.prefix,
            scope=scope,
        )
        self.intents = MutationIntentStore(
            ledger_path,
            run_id=self.prefix,
            scope=scope,
        )
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        )
        self.report_path = Path(report_path) if report_path else None
        self.created: dict[str, list[str]] = {
            "instances": [],
            "snapshots": [],
            "blocks": [],
            "block_snapshots": [],
            "databases": [],
            "object_storages": [],
            "object_buckets": [],
            "object_keys": [],  # cache only; the ledger is cleanup authority.
        }
        self.local_ids: dict[str, Any] = {}
        # Provider fork targets use durable restore markers as labels; the
        # durable ledger remains the cleanup authority for those exact IDs.
        self.object_credentials: dict[str, str] = {}
        self.report: dict[str, Any] = {
            "run_id": self.prefix,
            "execution_mode": "LIVE_PROVIDER",
            "provider": "Vultr",
            "api_endpoint": self.api_base,
            "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "tests": {},
            "ledger": [],
            "cleanup": {"status": "NOT_RUN", "errors": []},
            "limitations": [
                "Celery redelivery was exercised by repeating the durable adapter operation; a physical host reboot was not performed.",
                "Vultr managed-database backup metadata is provider-owned; the harness never deletes it.",
            ],
        }
        self.account = self.member = self.user = None
        self.connection = None
        self._hydrate_active_ledger()
        self._assert_cleanup_gate()

    @staticmethod
    def _explicit_run_id(environ: dict[str, str] | None = None) -> str:
        """Require a restartable run identity from the caller.

        A process-generated value is unsafe here: if the process dies before
        the caller records it, a subsequent invocation cannot find the ledger
        or reconcile an accepted provider mutation. Keep the legacy variable
        as an explicit alias, but never synthesize a value.
        """

        source = os.environ if environ is None else environ
        configured = [
            str(source.get(name) or "").strip()
            for name in ("BACKUPSHEEP_E2E_RUN_ID", "VULTR_E2E_RUN_ID")
            if str(source.get(name) or "").strip()
        ]
        if not configured:
            raise LedgerError(
                "BACKUPSHEEP_E2E_RUN_ID is required; provide the same durable "
                "run ID again after a crash."
            )
        if len(set(configured)) != 1:
            raise LedgerError(
                "BACKUPSHEEP_E2E_RUN_ID and VULTR_E2E_RUN_ID must match when both are supplied."
            )
        return require_run_id(configured[0])

    def _assert_cleanup_gate(self) -> None:
        if self.cleanup_requested and not self.apply:
            raise HarnessError(
                "Vultr cleanup requires BACKUPSHEEP_E2E_APPLY=YES plus "
                "BACKUPSHEEP_E2E_CLEANUP=YES."
            )

    def _hydrate_active_ledger(self) -> None:
        """Recover exact IDs and witnesses after a process restart.

        A ledger entry is the only source for ``created`` after construction;
        the map is merely a compatibility/cache view used by the existing live
        test flow.  Unknown entries, duplicate roles, or a missing immutable
        run witness fail closed before any provider mutation or cleanup.
        """

        role_to_cache = {
            "source-instance": ("instances", "source_instance_id"),
            "restore-instance": ("instances", "restore_instance_id"),
            "source-block": ("blocks", "source_block_id"),
            "restore-block": ("blocks", "restore_block_id"),
            "instance-snapshot": ("snapshots", "instance_snapshot_id"),
            "block-snapshot": ("block_snapshots", "block_snapshot_id"),
            "object-storage": ("object_storages", "object_storage_id"),
            "object-bucket": ("object_buckets", "object_bucket"),
            "object-bucket-marker": ("object_keys", "object_bucket_marker_key"),
            "object-key": ("object_keys", "object_key"),
            "source-database": ("databases", "source_database_id"),
            "restore-database": ("databases", "restore_database_id"),
        }
        seen_roles: set[str] = set()
        for entry in self.ledger.entries():
            if entry.get("cleanup_state") not in {"eligible", "failed"}:
                continue
            ownership = entry.get("ownership") or {}
            role = str(ownership.get("role") or "")
            provider_id = str(entry.get("resource_id") or "")
            if role not in role_to_cache or not provider_id:
                raise HarnessError(
                    "The Vultr durable ledger contains a resource outside this exact run."
                )
            if ownership.get("run_id") != self.prefix:
                raise HarnessError("The Vultr durable ledger ownership witness is invalid.")
            if role in seen_roles:
                raise HarnessError(f"Multiple durable Vultr resources exist for {role}.")
            seen_roles.add(role)
            cache_key, scalar_key = role_to_cache[role]
            setattr(self, scalar_key, provider_id)
            if scalar_key in self.created:
                self.created[scalar_key] = provider_id
            if provider_id not in self.created[cache_key]:
                self.created[cache_key].append(provider_id)

    def _intent(
        self,
        key: str,
        marker: str,
        operation: str,
        request: dict[str, Any] | None = None,
        *,
        kind: str = "",
    ) -> None:
        fingerprint = _request_fingerprint(request)
        pending = self.intents.get(key)
        if pending:
            self._pending_intent_witness(
                key,
                marker,
                operation,
                request,
                required=True,
            )
            raise HarnessError(
                f"Pending Vultr {operation} intent exists for {marker}; "
                "reconcile read-only before retry."
            )
        self.intents.set(
            key,
            {
                "marker": str(marker),
                "operation": str(operation),
                "kind": str(kind or ""),
                "role": str(key),
                "request": dict(request),
                "fingerprint": fingerprint,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
        )

    def _pending_intent_witness(
        self,
        key: str,
        marker: str,
        operation: str,
        request: dict[str, Any],
        *,
        required: bool = False,
    ) -> dict[str, Any] | None:
        """Return one exact durable intent or fail closed on any mismatch."""

        pending = self.intents.get(key)
        if pending is None:
            if required:
                raise HarnessError(
                    f"Vultr {operation} found an unledgered provider collision without "
                    "an exact pending intent; manual review required."
                )
            return None
        if (
            str(pending.get("marker") or "") != str(marker)
            or str(pending.get("operation") or "") != str(operation)
            or str(pending.get("fingerprint") or "") != _request_fingerprint(request)
            or pending.get("request") != request
        ):
            raise HarnessError(
                f"Pending Vultr {operation} intent has a different marker or operation "
                "or request fingerprint "
                "witness; manual review required."
            )
        return pending

    def _mutation(
        self,
        key: str,
        marker: str,
        operation: str,
        request: dict[str, Any],
        callback: Callable[[], Any],
        *,
        kind: str = "",
    ):
        """Persist intent before a one-shot provider mutation."""

        self._intent(key, marker, operation, request, kind=kind)
        try:
            return callback()
        except Exception as error:
            raise AmbiguousMutation(
                f"Vultr {operation} outcome is unknown for {marker}; "
                "no retry was issued."
            ) from error

    def _prepare_cleanup_intent(
        self,
        key: str,
        marker: str,
        operation: str,
        request: dict[str, Any],
        *,
        kind: str,
    ) -> None:
        """Fence a delete before issuing it, while allowing exact recovery."""

        fingerprint = _request_fingerprint(request)
        pending = self.intents.get(key)
        if pending and (
            str(pending.get("marker") or "") != str(marker)
            or str(pending.get("operation") or "") != str(operation)
            or str(pending.get("fingerprint") or "") != fingerprint
            or pending.get("request") != request
        ):
            raise HarnessError(f"Cleanup intent {key} has a different ownership witness.")
        if not pending:
            self.intents.set(
                key,
                {
                    "marker": str(marker),
                    "operation": str(operation),
                    "kind": str(kind),
                    "role": str(key),
                    "request": dict(request),
                    "fingerprint": fingerprint,
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                },
            )

    def _remember_resource(
        self,
        *,
        kind: str,
        role: str,
        provider_id: str,
        name: str,
        ownership: dict[str, Any],
        request: dict[str, Any],
        source_witness: str = "",
        cache_key: str | None = None,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        if request is None:
            raise HarnessError(
                f"Vultr {role} cannot be adopted without an immutable request fingerprint."
            )
        proof = {
            "run_id": self.prefix,
            "role": role,
            "request_fingerprint": _request_fingerprint(request),
            **ownership,
        }
        entry = self.ledger.record(
            kind=kind,
            resource_id=str(provider_id),
            name=name,
            ownership=proof,
            source_witness=source_witness,
        )
        if cache_key and str(provider_id) not in self.created[cache_key]:
            self.created[cache_key].append(str(provider_id))
        if operation_key:
            self.intents.clear(operation_key)
        self._report_ledger_entry(entry)
        return entry

    def _report_ledger_entry(self, entry: dict[str, Any]) -> None:
        provider_id = str(entry.get("resource_id") or "")
        if any(
            str(item.get("provider_id")) == provider_id
            and item.get("kind") == entry.get("kind")
            for item in self.report["ledger"]
        ):
            return
        self.report["ledger"].append(
            {
                "kind": entry.get("kind"),
                "resource_class": entry.get("ownership", {}).get("role"),
                "provider_service": "Vultr",
                "provider_id": provider_id,
                "ownership_proof": entry.get("ownership", {}),
                "created_by_run": True,
                "cleanup_allowed": True,
            }
        )

    @staticmethod
    def _resource_id(resource: dict[str, Any]) -> str:
        return str(resource.get("id") or resource.get("uuid") or "")

    @staticmethod
    def _tags(resource: dict[str, Any]) -> set[str]:
        values = resource.get("tags") or []
        if isinstance(values, str):
            values = [values]
        return {str(value) for value in values}

    @staticmethod
    def _ownership_value_matches(field: str, observed: Any, expected: Any) -> bool:
        if observed in (None, ""):
            return False
        # Vultr returns managed-database region slugs in uppercase even though
        # create requests and other resource families use lowercase slugs.
        # Region identifiers are case-insensitive; every other ownership field
        # remains byte-for-byte strict.
        if field == "region":
            return str(observed).strip().casefold() == str(expected).strip().casefold()
        return str(observed) == str(expected)

    def _resource_matches_entry(self, resource: dict[str, Any], entry: dict[str, Any]) -> bool:
        if not isinstance(resource, dict):
            return False
        if self._resource_id(resource) != str(entry.get("resource_id")):
            return False
        ownership = entry.get("ownership") or {}
        fingerprint = str(ownership.get("request_fingerprint") or "")
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            return False
        for field in (
            "label",
            "hostname",
            "description",
            "region",
            "plan",
            "size_gb",
            "endpoint",
            "os_id",
            "cluster_id",
            "tier_id",
            "database_engine",
            "database_engine_version",
            "engine",
            "version",
        ):
            if field in ownership and not self._ownership_value_matches(
                field, resource.get(field), ownership[field]
            ):
                return False
        if "snapshot_id" in ownership:
            observed_snapshot = resource.get("snapshot_id")
            expected_snapshot = ownership["snapshot_id"]
            # Vultr clears snapshot_id from a restored block after it becomes
            # active. Exact ID, restore label, region, size, request fingerprint,
            # and the durable source witness remain mandatory; a contradictory
            # non-empty snapshot ID is always rejected.
            if observed_snapshot not in (None, "") and str(observed_snapshot) != str(
                expected_snapshot
            ):
                return False
            if (
                observed_snapshot in (None, "")
                and (
                    str(ownership.get("role") or "") != "restore-block"
                    or str(entry.get("source_witness") or "")
                    != str(expected_snapshot)
                )
            ):
                return False
        expected_tags = {str(value) for value in ownership.get("tags") or []}
        if expected_tags and not expected_tags.issubset(self._tags(resource)):
            return False
        restore_marker = str(ownership.get("restore_marker") or "")
        if restore_marker and restore_marker not in self._tags(resource) and str(
            resource.get("label") or ""
        ) != restore_marker:
            return False
        for field in ("source_id", "instance_id", "block_id"):
            if field not in ownership:
                continue
            observed = resource.get(field)
            if observed not in (None, "", ownership[field]) and str(observed) != str(ownership[field]):
                return False
        if ownership.get("s3_hostname"):
            try:
                _validate_vultr_object_storage_hostname(resource.get("s3_hostname"))
            except HarnessError:
                return False
            if resource.get("s3_hostname") != ownership["s3_hostname"]:
                return False
        return True

    def _ensure_provider_resource(
        self,
        *,
        kind: str,
        role: str,
        marker: str,
        name: str,
        cache_key: str,
        candidates: Callable[[], list[dict[str, Any]]],
        readback: Callable[[str], dict[str, Any] | None],
        create: Callable[[], dict[str, Any] | None],
        id_from_response: Callable[[dict[str, Any]], str],
        ownership: Callable[[dict[str, Any]], dict[str, Any]],
        request: dict[str, Any],
        source_witness: str = "",
    ) -> tuple[str, dict[str, Any]]:
        """Adopt one exact resource or create it once behind a durable fence."""

        entries = [
            entry
            for entry in self.ledger.entries(kind)
            if entry.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        matching_entries = [
            entry for entry in entries if (entry.get("ownership") or {}).get("role") == role
        ]
        if len(matching_entries) > 1:
            raise HarnessError(f"Multiple durable Vultr resources exist for {role}.")
        if entries and not matching_entries:
            raise HarnessError(f"Durable Vultr ledger has an unexpected {kind} resource.")
        if matching_entries:
            entry = matching_entries[0]
            if entry.get("cleanup_state") == "manual_review":
                raise HarnessError(
                    f"Ledgered Vultr {role} requires manual review; no mutation is allowed."
                )
            if str((entry.get("ownership") or {}).get("request_fingerprint") or "") != _request_fingerprint(request):
                raise HarnessError(f"Ledgered Vultr {role} has a different request fingerprint.")
            pending = self.intents.get(role)
            if pending:
                self._pending_intent_witness(role, marker, role, request, required=True)
            resource_id = str(entry.get("resource_id") or "")
            resource = readback(resource_id)
            if resource is None:
                raise HarnessError(f"Ledgered Vultr {role} {resource_id} is absent; use a new run ID.")
            if not self._resource_matches_entry(resource, entry):
                raise HarnessError(f"Ledgered Vultr {role} failed ownership read-back.")
            self._report_ledger_entry(entry)
            if resource_id not in self.created[cache_key]:
                self.created[cache_key].append(resource_id)
            if pending:
                self.intents.clear(role)
            return resource_id, resource

        matches = []
        for candidate in candidates():
            provider_id = self._resource_id(candidate)
            if provider_id and str(candidate.get("id") or candidate.get("uuid")) and marker in {
                str(candidate.get("label") or ""),
                str(candidate.get("hostname") or ""),
                str(candidate.get("description") or ""),
                *self._tags(candidate),
            }:
                matches.append(candidate)
        if len(matches) > 1:
            raise HarnessError(f"Multiple exact owned Vultr {role} matches found.")
        pending = self._pending_intent_witness(role, marker, role, request)
        if matches:
            self._pending_intent_witness(role, marker, role, request, required=True)
            resource_id = self._resource_id(matches[0])
            resource = readback(resource_id)
            if resource is None or not self._resource_matches_entry(
                resource,
                {
                    "resource_id": resource_id,
                    "ownership": {
                        "run_id": self.prefix,
                        "role": role,
                        "request_fingerprint": _request_fingerprint(request),
                        **ownership(matches[0]),
                    },
                },
            ):
                raise HarnessError(f"Vultr {role} candidate failed exact ownership read-back.")
            self._remember_resource(
                kind=kind,
                role=role,
                provider_id=resource_id,
                name=name,
                ownership=ownership(resource),
                source_witness=source_witness,
                cache_key=cache_key,
                operation_key=role,
                request=request,
            )
            return resource_id, resource

        if pending:
            raise HarnessError(
                f"No exact Vultr {role} resource is visible for a pending intent; "
                "manual review required."
            )
        response = self._mutation(role, marker, role, request, create, kind=kind)
        response = response if isinstance(response, dict) else {}
        resource_id = str(id_from_response(response) or "")
        if not resource_id:
            raise AmbiguousMutation(f"Vultr {role} returned no provider resource ID.")
        resource = readback(resource_id)
        if resource is None:
            raise AmbiguousMutation(f"Vultr {role} was not visible after create.")
        expected_entry = {
            "resource_id": resource_id,
            "ownership": {
                "run_id": self.prefix,
                "role": role,
                "request_fingerprint": _request_fingerprint(request),
                **ownership(resource),
            },
        }
        if not self._resource_matches_entry(resource, expected_entry):
            raise AmbiguousMutation(f"Vultr {role} failed ownership read-back.")
        self._remember_resource(
            kind=kind,
            role=role,
            provider_id=resource_id,
            name=name,
            ownership=ownership(resource),
            source_witness=source_witness,
            cache_key=cache_key,
            operation_key=role,
            request=request,
        )
        return resource_id, resource

    def _ledger_role_entry(
        self,
        kind: str,
        role: str,
        *,
        allow_manual_review: bool = False,
    ) -> dict[str, Any] | None:
        entries = [
            entry
            for entry in self.ledger.entries(kind)
            if (entry.get("ownership") or {}).get("role") == role
            and entry.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if len(entries) > 1:
            raise HarnessError(f"Multiple durable Vultr resources exist for {role}.")
        if (
            entries
            and entries[0].get("cleanup_state") == "manual_review"
            and not allow_manual_review
        ):
            raise HarnessError(
                f"Ledgered Vultr {role} requires manual review; no mutation is allowed."
            )
        return entries[0] if entries else None

    def _recovery_marker(self, kind: str, role: str, default: str) -> str:
        entry = self._ledger_role_entry(kind, role)
        if entry:
            ownership = entry.get("ownership") or {}
            marker = ownership.get("restore_marker") or ownership.get("label")
            if marker:
                if self.intents.get(role):
                    pending = self.intents.get(role)
                    self._pending_intent_witness(
                        role,
                        str(marker),
                        role,
                        pending["request"],
                        required=True,
                    )
                return str(marker)
        pending = self.intents.get(role)
        if pending and pending.get("marker"):
            self._pending_intent_witness(
                role,
                str(pending["marker"]),
                role,
                pending["request"],
                required=True,
            )
            return str(pending["marker"])
        return str(default)

    def _prepare_adapter_resource(
        self,
        *,
        kind: str,
        role: str,
        marker: str,
        name: str,
        candidates: Callable[[], list[dict[str, Any]]],
        readback: Callable[[str], dict[str, Any] | None],
        ownership: Callable[[dict[str, Any]], dict[str, Any]],
        request: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Prepare an adapter mutation, adopting an exact prior outcome."""

        entry = self._ledger_role_entry(kind, role)
        if entry:
            if str((entry.get("ownership") or {}).get("request_fingerprint") or "") != _request_fingerprint(request):
                raise HarnessError(f"Ledgered Vultr {role} has a different request fingerprint.")
            pending = self.intents.get(role)
            if pending:
                self._pending_intent_witness(role, marker, role, request, required=True)
            provider_id = str(entry.get("resource_id") or "")
            resource = readback(provider_id)
            if resource is None or not self._resource_matches_entry(resource, entry):
                raise HarnessError(f"Ledgered Vultr {role} failed ownership read-back.")
            self._report_ledger_entry(entry)
            if pending:
                self.intents.clear(role)
            return provider_id, resource

        matches = []
        for candidate in candidates():
            candidate_id = self._resource_id(candidate)
            candidate_marker_values = {
                str(candidate.get("label") or ""),
                str(candidate.get("hostname") or ""),
                str(candidate.get("description") or ""),
                *self._tags(candidate),
            }
            if candidate_id and marker in candidate_marker_values:
                matches.append(candidate)
        if len(matches) > 1:
            raise HarnessError(f"Multiple exact owned Vultr {role} matches found.")
        pending = self._pending_intent_witness(role, marker, role, request)
        if matches:
            self._pending_intent_witness(role, marker, role, request, required=True)
            provider_id = self._resource_id(matches[0])
            resource = readback(provider_id)
            expected = {
                "resource_id": provider_id,
                "ownership": {
                    "run_id": self.prefix,
                    "role": role,
                    "request_fingerprint": _request_fingerprint(request),
                    **ownership(matches[0]),
                },
            }
            if resource is None or not self._resource_matches_entry(resource, expected):
                raise HarnessError(f"Vultr {role} candidate failed ownership read-back.")
            self._remember_resource(
                kind=kind,
                role=role,
                provider_id=provider_id,
                name=name,
                ownership=ownership(resource),
                source_witness=str(resource.get("snapshot_id") or ""),
                cache_key={
                    "snapshot": "snapshots",
                    "block_snapshot": "block_snapshots",
                    "instance": "instances",
                    "block": "blocks",
                    "database": "databases",
                }.get(kind, "instances"),
                operation_key=role,
                request=request,
            )
            return provider_id, resource

        if pending:
            raise HarnessError(
                f"No exact Vultr {role} resource is visible for a pending intent; "
                "manual review required."
            )
        self._intent(role, marker, role, request, kind=kind)
        return None, None

    def _finish_adapter_resource(
        self,
        *,
        kind: str,
        role: str,
        name: str,
        provider_id: str,
        readback: Callable[[str], dict[str, Any] | None],
        ownership: Callable[[dict[str, Any]], dict[str, Any]],
        cache_key: str,
        request: dict[str, Any],
        source_witness: str = "",
    ) -> dict[str, Any]:
        provider_id = str(provider_id or "")
        if not provider_id:
            raise AmbiguousMutation(f"Vultr {role} returned no provider resource ID.")
        resource = readback(provider_id)
        if resource is None:
            raise AmbiguousMutation(f"Vultr {role} was not visible after the adapter call.")
        expected = {
            "resource_id": provider_id,
            "run_id": self.prefix,
            "role": role,
            "request_fingerprint": _request_fingerprint(request),
            **ownership(resource),
        }
        if not self._resource_matches_entry(resource, {"resource_id": provider_id, "ownership": expected}):
            raise AmbiguousMutation(f"Vultr {role} failed ownership read-back.")
        self._remember_resource(
            kind=kind,
            role=role,
            provider_id=provider_id,
            name=name,
            ownership=ownership(resource),
            source_witness=source_witness,
            cache_key=cache_key,
            operation_key=role,
            request=request,
        )
        return resource

    # ---------- provider client ----------

    def _safe_error(self, value: Any) -> str:
        provider_response = getattr(value, "response", None)
        if provider_response is not None or value.__class__.__module__.startswith(
            ("botocore", "requests")
        ):
            category = str(getattr(value, "category", "provider_failure") or "provider_failure")
            text = f"{value.__class__.__name__} ({category})"
        else:
            text = str(value)
        secrets_to_redact = {
            str(getattr(self, "token", "") or ""),
            str((getattr(self, "object_credentials", {}) or {}).get("access_key") or ""),
            str((getattr(self, "object_credentials", {}) or {}).get("secret_key") or ""),
        }
        for secret in secrets_to_redact:
            if secret:
                text = text.replace(secret, "<redacted>")
        return text[:400]

    def _read_detail(self, path: str, key: str) -> dict[str, Any] | None:
        try:
            payload = self.request("GET", path, expected=(200, 202)) or {}
        except ProviderNotFound:
            return None
        if key == "snapshot" and key not in payload and payload.get("id"):
            return payload
        value = payload.get(key)
        return value if isinstance(value, dict) else None

    def _read_cleanup_resource(
        self,
        entry: dict[str, Any],
        path: str,
        response_key: str,
    ) -> dict[str, Any] | None:
        """Read one cleanup target with explicit Vultr database semantics.

        A managed-database detail endpoint returns HTTP 422 once deletion has
        been accepted. That response alone is not absence proof. Only a full,
        bounded inventory with zero occurrences of the durable provider ID may
        turn it into an absent result.
        """

        try:
            return self._read_detail(path, response_key)
        except ProviderTerminalFailure as error:
            if (
                str(entry.get("kind") or "") != "database"
                or getattr(error, "status_code", None) != 422
            ):
                raise
        provider_id = str(entry.get("resource_id") or "")
        matches = [
            item
            for item in self.collection("/databases", "databases")
            if self._resource_id(item) == provider_id
        ]
        if len(matches) > 1:
            raise HarnessError(
                "Vultr database cleanup inventory returned duplicate provider IDs."
            )
        return matches[0] if matches else None

    def _poll_detail(self, path: str, key: str) -> dict[str, Any]:
        """Read a provider detail without converting a 404 into an empty state."""

        payload = self.request("GET", path, expected=(200, 202)) or {}
        value = payload.get(key)
        if not isinstance(value, dict):
            raise ProviderTerminalFailure(
                f"Vultr polling for {path} returned a malformed response."
            )
        return value

    @staticmethod
    def _assert_backup_records_ownership(value: Any, database_id: str) -> None:
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise HarnessError("Vultr managed database backup metadata ownership failed.")
        for item in value:
            for field in ("database_id", "source_database_id"):
                observed = item.get(field)
                if observed not in (None, "") and str(observed) != str(database_id):
                    raise HarnessError(
                        "Vultr managed database backup metadata belongs to another source."
                    )

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: tuple[int, ...] = (200,),
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        response = None
        # Provider reads are safe to retry and Vultr may briefly return a 5xx
        # while a newly-created subscription becomes visible.  Keep writes
        # single-shot so a lost response can never create a duplicate.
        attempts = 8 if method.upper() == "GET" else 1
        for attempt in range(attempts):
            try:
                response = self.session.request(
                    method,
                    f"{self.api_base}{path}",
                    params=params,
                    json=body,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as error:
                if attempt + 1 >= attempts:
                    raise ProviderTransientFailure(
                        f"Vultr {method} {path} request is resumable after a transient outage."
                    ) from error
                time.sleep(3 * (attempt + 1))
                continue
            if (
                method.upper() == "GET"
                and response.status_code in {429, 500, 502, 503, 504}
                and attempt + 1 < attempts
            ):
                retry_after = response.headers.get("Retry-After")
                delay = _retry_after_seconds(retry_after) or max(
                    1, min(30, 3 * (attempt + 1))
                )
                response.close()
                response = None
                time.sleep(delay)
                continue
            break
        if response is None:
            raise HarnessError(f"Vultr {method} {path} returned no response")
        try:
            if response.status_code not in expected:
                if response.status_code == 404:
                    raise ProviderNotFound(f"Vultr {method} {path} returned HTTP 404")
                if response.status_code == 429:
                    retry_after = _retry_after_seconds(
                        response.headers.get("Retry-After")
                    )
                    suffix = f" retry_after={retry_after}s" if retry_after else ""
                    raise ProviderRateLimited(
                        f"Vultr {method} {path} is rate limited and resumable.{suffix}"
                    )
                if response.status_code in {408, 425, 500, 502, 503, 504}:
                    raise ProviderTransientFailure(
                        f"Vultr {method} {path} is temporarily unavailable and resumable."
                    )
                failure = ProviderTerminalFailure(
                    f"Vultr {method} {path} was rejected with HTTP {response.status_code}."
                )
                failure.status_code = response.status_code
                raise failure
            if response.status_code == 204 or not response.content:
                return None
            try:
                payload = response.json()
            except ValueError as error:
                raise ProviderTerminalFailure(
                    f"Vultr {method} {path} returned a malformed response."
                ) from error
            if not isinstance(payload, dict):
                raise ProviderTerminalFailure(
                    f"Vultr {method} {path} returned a malformed response."
                )
            return payload
        finally:
            response.close()

    def collection(
        self,
        path: str,
        item_key: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 1000,
        max_items: int = 100_000,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        base = dict(params or {})
        per_page = int(base.setdefault("per_page", 500))
        if per_page < 1 or per_page > 500:
            raise HarnessError(f"Malformed Vultr {path} page size")
        cursor = None
        seen: set[str] = set()
        seen_ids: set[str] = set()
        for page_number in range(max_pages):
            query = dict(base)
            if cursor:
                query["cursor"] = cursor
            payload = self.request("GET", path, params=query) or {}
            page = payload.get(item_key)
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise HarnessError(f"Malformed Vultr {path} inventory")
            meta = payload.get("meta")
            if not isinstance(meta, dict):
                raise HarnessError(f"Malformed Vultr {path} pagination metadata")
            total = meta.get("total")
            if total is not None and (
                isinstance(total, bool) or not isinstance(total, int) or total < 0
            ):
                raise HarnessError(f"Malformed Vultr {path} pagination total")
            links = meta.get("links")
            if links is None:
                # Vultr currently returns only ``meta.total`` for some
                # unpaginated managed-database endpoints.  That shape is safe
                # only when the current response proves the inventory is
                # complete; a larger total without a continuation cursor must
                # fail closed.
                if total is None:
                    raise HarnessError(f"Malformed Vultr {path} pagination metadata")
                links = {}
            if not isinstance(links, dict):
                raise HarnessError(f"Malformed Vultr {path} pagination links")
            for link_name in ("next", "prev"):
                link = links.get(link_name)
                if link not in (None, "") and (
                    not isinstance(link, str)
                    or not link.strip()
                    or "?" in link
                    or "/" in link
                    or "=" in link
                ):
                    raise HarnessError(f"Malformed Vultr {path} {link_name} cursor")
            for item in page:
                item_id = item.get("id") or item.get("uuid")
                if item_id in (None, ""):
                    raise HarnessError(f"Vultr {path} returned an item without a provider ID")
                item_id = str(item_id)
                if item_id in seen_ids:
                    raise HarnessError(f"Vultr {path} returned duplicate provider ID {item_id}")
                seen_ids.add(item_id)
            items.extend(page)
            if len(items) > max_items:
                raise HarnessError(f"Vultr {path} inventory exceeded the bounded item limit")
            next_cursor = links.get("next")
            if next_cursor in (None, ""):
                if total is not None and len(items) != total:
                    raise HarnessError(
                        f"Incomplete Vultr {path} inventory without a continuation cursor"
                    )
                return items
            if total is not None and len(items) >= total:
                raise HarnessError(f"Inconsistent Vultr {path} pagination metadata")
            if not isinstance(next_cursor, str) or not next_cursor.strip() or next_cursor in seen:
                raise HarnessError(f"Repeated or malformed Vultr {path} cursor")
            seen.add(next_cursor)
            cursor = next_cursor
        raise HarnessError(f"Vultr {path} inventory exceeded the bounded page limit")

    @staticmethod
    def _provider_state(value: Any) -> str:
        if not isinstance(value, dict):
            return ""
        for field in ("status", "state", "phase", "lifecycle_state"):
            state = value.get(field)
            if isinstance(state, str) and state.strip():
                return state.strip().lower()
        return ""

    @staticmethod
    def _assert_poll_ownership(
        value: Any,
        *,
        provider_id: str,
        expected: dict[str, Any],
    ) -> None:
        if not isinstance(value, dict):
            raise HarnessError("Vultr polling returned a malformed ownership witness.")
        observed_id = str(value.get("id") or value.get("uuid") or "")
        if observed_id != str(provider_id):
            raise HarnessError("Vultr polling returned a different provider resource.")
        for field, expected_value in expected.items():
            observed = value.get(field)
            if not LiveVultrHarness._ownership_value_matches(
                field, observed, expected_value
            ):
                raise HarnessError(
                    f"Vultr polling ownership verification failed for {field}."
                )

    def wait_for(
        self,
        label: str,
        read: Callable[[], Any],
        done: Callable[[Any], bool],
        *,
        timeout_seconds: int = 1800,
        interval_seconds: int = 10,
        provider: bool = False,
        ownership: Callable[[Any], None] | None = None,
        terminal_states: set[str] | None = None,
    ) -> Any:
        if provider and ownership is None:
            raise HarnessError(
                f"Vultr polling for {label} requires an exact ownership witness."
            )
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                current = read()
            except ProviderNotFound:
                raise ProviderNotFound(
                    f"Vultr polling for {label} returned 404; reconciliation is required."
                ) from None
            except (ProviderRateLimited, ProviderTransientFailure):
                raise
            except ProviderTerminalFailure:
                raise
            except Exception as error:
                if provider:
                    category = str(getattr(error, "category", "") or "").lower()
                    if category in {"not_found", "provider_not_found"}:
                        raise ProviderNotFound(
                            f"Vultr polling for {label} returned 404; reconciliation is required."
                        ) from None
                    if category in {"rate_limited", "provider_rate_limited"}:
                        raise ProviderRateLimited(
                            f"Vultr polling for {label} is rate limited and resumable."
                        ) from None
                    if category in {"terminal_failure", "malformed_response", "auth_failed"}:
                        raise ProviderTerminalFailure(
                            f"Vultr polling for {label} returned a terminal provider failure."
                        ) from None
                    raise ProviderTransientFailure(
                        f"Vultr polling for {label} encountered a resumable provider failure."
                    ) from error
                raise
            if provider:
                ownership(current)
                state = self._provider_state(current)
                if state in (terminal_states or {"failed", "error", "errored", "cancelled", "canceled", "deleted"}):
                    raise ProviderTerminalFailure(
                        f"Vultr polling for {label} reached terminal state {state}."
                    )
            if done(current):
                return current
            time.sleep(interval_seconds)
        if provider:
            raise ProviderTransientFailure(
                f"Vultr polling for {label} timed out; the operation remains resumable."
            )
        raise HarnessError(f"Timed out waiting for {label}; the operation remains resumable.")

    # ---------- safety ledger ----------

    def _has_marker(self, resource: dict[str, Any]) -> bool:
        tags = resource.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        values = [
            resource.get("id"),
            resource.get("label"),
            resource.get("hostname"),
            resource.get("description"),
            resource.get("snapshot_id"),
            *tags,
        ]
        return any(self.prefix in str(value) for value in values if value not in (None, ""))

    @staticmethod
    def _has_exact_marker(resource: dict[str, Any], marker: str) -> bool:
        tags = resource.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        values = [
            resource.get("label"),
            resource.get("hostname"),
            resource.get("description"),
            *tags,
        ]
        return str(marker) in {str(value) for value in values if value not in (None, "")}

    def baseline(self) -> None:
        account = self.request("GET", "/account") or {}
        self.report["account"] = {
            "authenticated": True,
            "acl_count": len((account.get("account") or {}).get("acls") or []),
        }
        inventories = {
            "instances": self.collection("/instances", "instances"),
            "snapshots": self.collection("/snapshots", "snapshots"),
            "blocks": self.collection("/blocks", "blocks"),
            "block_snapshots": self.collection("/blocks/snapshots", "snapshots"),
            "databases": self.collection("/databases", "databases"),
            "object_storages": self.collection("/object-storage", "object_storages"),
            "backups": self.collection("/backups", "backups"),
        }
        ledger_ids = {
            str(entry.get("resource_id"))
            for entry in self.ledger.entries()
            if entry.get("cleanup_state") in {"eligible", "failed"}
        }
        pending_markers = {
            str(value.get("marker"))
            for value in self.intents.pending().values()
            if isinstance(value, dict) and value.get("marker")
            and not str(value.get("operation") or "").startswith("cleanup")
        }
        collisions = {
            key: [
                item.get("id")
                for item in values
                if self._has_marker(item)
                and str(item.get("id")) not in ledger_ids
                and not any(self._has_exact_marker(item, marker) for marker in pending_markers)
            ]
            for key, values in inventories.items()
        }
        self.report["baseline"] = {
            "counts": {key: len(values) for key, values in inventories.items()},
            "collisions": collisions,
        }
        if any(collisions.values()):
            raise HarnessError(f"Run marker collision before mutation: {collisions}")

        plans = self.collection("/databases/plans", "plans", params={"region": self.region})
        matching = [
            plan for plan in plans
            if plan.get("id") == self.database_plan
            and plan.get("number_of_nodes") == 1
            and (plan.get("supported_engines") or {}).get("pg")
            and "hobbyist" not in str(plan.get("id", "")).lower()
        ]
        if not matching:
            raise HarnessError("Selected non-Hobbyist PostgreSQL managed-database plan is unavailable")
        clusters = self.request("GET", "/object-storage/clusters") or {}
        cluster_values = [
            item for item in clusters.get("clusters", [])
            if isinstance(item, dict) and str(item.get("id", "")).isdigit()
        ]
        cluster_ids = {int(item["id"]) for item in cluster_values}
        if self.object_cluster_id not in cluster_ids:
            if not cluster_ids:
                raise HarnessError("Vultr Object Storage has no available clusters")
            self.object_cluster_id = min(cluster_ids)

        tiers = self.request("GET", "/object-storage/tiers") or {}
        tier_values = [
            item for item in tiers.get("tiers", [])
            if isinstance(item, dict) and str(item.get("id", "")).isdigit()
        ]
        tier_ids = {int(item["id"]) for item in tier_values}
        preferred_tier = next(
            (item for item in tier_values if int(item["id"]) == self.object_tier_id),
            None,
        )
        preferred_locations = preferred_tier.get("locations", []) if preferred_tier else []
        preferred_supports_region = not preferred_locations or any(
            str(location.get("region", "")).lower() == self.region.lower()
            for location in preferred_locations
            if isinstance(location, dict)
        )
        if self.object_tier_id not in tier_ids or not preferred_supports_region:
            standard = next(
                (
                    item for item in tier_values
                    if str(item.get("sales_name", "")).strip().lower() == "standard"
                    and any(
                        str(location.get("region", "")).lower() == self.region.lower()
                        for location in item.get("locations", [])
                        if isinstance(location, dict)
                    )
                ),
                None,
            )
            if standard is None:
                standard = next(
                    (
                        item for item in tier_values
                        if str(item.get("sales_name", "")).strip().lower() == "standard"
                    ),
                    None,
                )
            if standard is None:
                raise HarnessError("Vultr Object Storage has no usable standard tier")
            self.object_tier_id = int(standard["id"])
        self.report["object_storage_selection"] = {
            "cluster_id": self.object_cluster_id,
            "tier_id": self.object_tier_id,
        }

    def record_test(self, test_id: str, status: str, **evidence: Any) -> None:
        self.report["tests"][test_id] = {"status": status, **evidence}
        if status != "PASS":
            raise HarnessError(f"Vultr live acceptance case {test_id} failed.")

    # ---------- local BackupSheep graph ----------

    def _discard_exact_previous_local_fixture(self) -> None:
        """Remove only this run's exact local graph before replaying the harness.

        Provider resources remain governed by the external durable ledger.  A
        prior process can fail after creating local rows, and the deterministic
        provider markers must then be replayed without colliding on the test
        user or creating different restore markers from stale rows.  Deleting
        the whole account is safe only after proving the unique run identity,
        membership graph, Vultr credential, and durable provider intent/ledger.
        """

        email = f"{self.prefix}@example.invalid"
        User = get_user_model()
        users = list(User.objects.filter(username=email, email=email))
        accounts = list(CoreAccount.objects.filter(name=self.prefix))
        locations = list(CoreConnectionLocation.objects.filter(code=self.prefix))
        if not users and not accounts:
            if locations:
                if len(locations) != 1 or locations[0].connections.exists():
                    raise HarnessError(
                        "A conflicting local Vultr E2E location exists for this run."
                    )
                if not (self.ledger.entries() or self.intents.pending()):
                    raise HarnessError(
                        "An unledgered local Vultr E2E location collision exists."
                    )
                locations[0].delete()
            return
        if not (self.ledger.entries() or self.intents.pending()):
            raise HarnessError(
                "A local Vultr E2E account collision exists without durable provider state."
            )
        if len(users) != 1 or len(accounts) != 1 or len(locations) > 1:
            raise HarnessError("The prior local Vultr E2E graph is ambiguous.")
        user = users[0]
        account = accounts[0]
        try:
            member = user.member
        except Exception as error:
            raise HarnessError("The prior local Vultr E2E user has no exact member.") from error
        memberships = list(member.memberships.filter(account=account))
        if (
            len(memberships) != 1
            or member.memberships.exclude(account=account).exists()
            or account.memberships.exclude(member=member).exists()
            or not memberships[0].current
            or not memberships[0].primary
        ):
            raise HarnessError("The prior local Vultr E2E membership graph changed.")
        vultr_connections = list(
            account.connections.filter(
                integration__code="vultr", name=self.prefix, added_by=member
            )
        )
        if len(vultr_connections) != 1:
            raise HarnessError("The prior local Vultr E2E connection is ambiguous.")
        connection = vultr_connections[0]
        auth = getattr(connection, "auth_vultr", None)
        if auth is None or bs_decrypt(
            auth.api_key, account.get_encryption_key()
        ) != self.token:
            raise HarnessError("The prior local Vultr E2E credential witness changed.")
        if locations and connection.location_id != locations[0].id:
            raise HarnessError("The prior local Vultr E2E location witness changed.")
        account_id = account.id
        user_id = user.id
        location_id = locations[0].id if locations else None
        account.delete()
        user.delete()
        if locations and not locations[0].connections.exists():
            locations[0].delete()
        self.report["local_restart_recovery"] = {
            "discarded_account_id": account_id,
            "discarded_user_id": user_id,
            "discarded_location_id": location_id,
            "provider_state_retained": True,
        }

    def setup_local(self) -> None:
        self._discard_exact_previous_local_fixture()
        self.account, self.member, self.user = factories.make_account(
            email=f"{self.prefix}@example.invalid"
        )
        self.account.name = self.prefix
        self.account.save(update_fields=["name"])
        location = CoreConnectionLocation.objects.create(code=self.prefix)
        self.connection = CoreConnection.objects.create(
            account=self.account,
            integration=CoreIntegration.objects.get(code="vultr"),
            location=location,
            name=self.prefix,
            added_by=self.member,
        )
        CoreAuthVultr.objects.create(
            connection=self.connection,
            api_key=bs_encrypt(self.token, self.account.get_encryption_key()),
        )
        self.local_ids["account_id"] = self.account.id
        self.local_ids["connection_id"] = self.connection.id

    def local_node(self, node_type: int, name: str, provider_id: str) -> tuple[CoreNode, Any]:
        node = CoreNode.objects.create(
            connection=self.connection,
            type=node_type,
            status=CoreNode.Status.ACTIVE,
            name=name,
            added_by=self.member,
        )
        if node_type in (CoreNode.Type.CLOUD, CoreNode.Type.VOLUME):
            obj = CoreVultr.objects.create(node=node, name=name, unique_id=provider_id)
        else:
            obj = CoreVultrDatabase.objects.create(
                node=node,
                name=name,
                unique_id=provider_id,
                engine="postgresql",
                region=self.region,
                plan=self.database_plan,
            )
        self.local_ids.setdefault("node_ids", []).append(node.id)
        return node, obj

    # ---------- compute and block storage ----------

    def create_sources(self) -> None:
        instance_label = f"{self.prefix}-source-instance"
        instance_hostname = f"{self.prefix}-source"
        instance_id, source_instance = self._ensure_provider_resource(
            kind="instance",
            role="source-instance",
            marker=instance_label,
            name=instance_label,
            cache_key="instances",
            candidates=lambda: self.collection("/instances", "instances"),
            readback=lambda resource_id: self._read_detail(
                f"/instances/{resource_id}", "instance"
            ),
            create=lambda: self.request(
                "POST",
                "/instances",
                expected=(201, 202),
                body={
                    "region": self.region,
                    "plan": self.server_plan,
                    "os_id": self.os_id,
                    "label": instance_label,
                    "hostname": instance_hostname,
                    "tags": [self.prefix],
                    "backups": "disabled",
                },
            ),
            id_from_response=lambda payload: (payload.get("instance") or {}).get("id"),
            ownership=lambda item: {
                "label": instance_label,
                "hostname": instance_hostname,
                "tags": [self.prefix],
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
            },
            request={
                "resource_type": "instance",
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
                "label": instance_label,
                "hostname": instance_hostname,
                "tags": [self.prefix],
                "backups": "disabled",
            },
        )
        source_instance = self.wait_for(
            "source instance active",
            lambda: self._poll_detail(f"/instances/{instance_id}", "instance"),
            lambda item: (
                str(item.get("status", "")).lower() == "active"
                and str(item.get("power_status", "")).lower() in {"running", "on"}
                and str(item.get("server_status", "")).lower() in {"ok", "running", "active"}
                and str(item.get("main_ip", "")).strip() not in {"", "0.0.0.0"}
            ),
            timeout_seconds=900,
            provider=True,
            ownership=lambda item: self._assert_poll_ownership(
                item,
                provider_id=instance_id,
                expected={
                    "region": self.region,
                    "plan": self.server_plan,
                    "os_id": self.os_id,
                },
            ),
        )
        self.source_instance = source_instance
        # Vultr can report an instance as active while the snapshot lock is
        # still settling.  Requiring the provider's running/readiness fields
        # above and allowing a short stabilization window avoids treating a
        # transient provider 400 as a completed snapshot operation.
        time.sleep(20)

        block_label = f"{self.prefix}-source-block"
        block_id, _source_block = self._ensure_provider_resource(
            kind="block",
            role="source-block",
            marker=block_label,
            name=block_label,
            cache_key="blocks",
            candidates=lambda: self.collection("/blocks", "blocks"),
            readback=lambda resource_id: self._read_detail(
                f"/blocks/{resource_id}", "block"
            ),
            create=lambda: self.request(
                "POST",
                "/blocks",
                expected=(201, 202),
                body={
                    "region": self.region,
                    "size_gb": self.block_size_gb,
                    "label": block_label,
                },
            ),
            id_from_response=lambda payload: (payload.get("block") or {}).get("id"),
            ownership=lambda item: {
                "label": block_label,
                "region": self.region,
                "size_gb": self.block_size_gb,
            },
            request={
                "resource_type": "block",
                "region": self.region,
                "size_gb": self.block_size_gb,
                "label": block_label,
            },
        )
        self.source_block = self.wait_for(
            "source block active",
            lambda: self._poll_detail(f"/blocks/{block_id}", "block"),
            lambda item: str(item.get("status", "")).lower() == "active",
            timeout_seconds=900,
            provider=True,
            ownership=lambda item: self._assert_poll_ownership(
                item,
                provider_id=block_id,
                expected={"region": self.region, "size_gb": self.block_size_gb},
            ),
        )
        self.source_instance_id = instance_id
        self.source_block_id = block_id

    def _wait_local_backup(self, backup: CoreVultrBackup) -> None:
        def read():
            backup.refresh_from_db()
            return backup.poll_status()

        def done(state):
            if state == UtilBackup.Status.FAILED:
                metadata = backup.metadata or {}
                raise HarnessError(
                    f"BackupSheep marked snapshot {backup.uuid_str} failed: "
                    f"{metadata.get('vultr_last_result') or 'provider status failure'}"
                )
            return state == UtilBackup.Status.COMPLETE

        self.wait_for(
            f"BackupSheep snapshot {backup.uuid_str}",
            read,
            done,
            # Vultr documents instance snapshots as taking up to 30 minutes.
            timeout_seconds=1800,
            interval_seconds=10,
        )

    def _snapshot_matches_source(self, snapshot: dict[str, Any], *, source_key: str, source_id: str, description: str) -> bool:
        """Match a provider snapshot while recording Vultr's omitted source field."""
        return (
            snapshot.get("description") == description
            and snapshot.get(source_key) in {None, "", source_id}
        )

    def snapshot_and_restore(self) -> None:
        cloud_node, cloud = self.local_node(CoreNode.Type.CLOUD, f"{self.prefix}-cloud", self.source_instance_id)
        block_node, block = self.local_node(CoreNode.Type.VOLUME, f"{self.prefix}-block", self.source_block_id)
        self.local_ids["cloud_node_id"] = cloud_node.id
        self.local_ids["block_node_id"] = block_node.id

        cloud_backup = CoreVultrBackup.objects.create(
            vultr=cloud,
            uuid=f"{self.prefix}-instance-snapshot",
            name=f"{self.prefix}-instance-snapshot",
            unique_id="",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        snapshot_role = "instance-snapshot"
        snapshot_id, _snapshot = self._prepare_adapter_resource(
            kind="snapshot",
            role=snapshot_role,
            marker=cloud_backup.uuid_str,
            name=cloud_backup.uuid_str,
            candidates=lambda: [
                item
                for item in self.collection("/snapshots", "snapshots")
                if self._snapshot_matches_source(
                    item,
                    source_key="instance_id",
                    source_id=self.source_instance_id,
                    description=cloud_backup.uuid_str,
                )
            ],
            readback=lambda resource_id: self._read_detail(
                f"/snapshots/{resource_id}", "snapshot"
            ),
            ownership=lambda item: {
                "description": cloud_backup.uuid_str,
                "instance_id": self.source_instance_id,
            },
            request={
                "resource_type": "instance_snapshot",
                "description": cloud_backup.uuid_str,
                "source_instance_id": self.source_instance_id,
            },
        )
        if snapshot_id:
            cloud_backup.unique_id = snapshot_id
            cloud_backup.save(update_fields=["unique_id", "modified"])
        original_post = node_models.requests.post

        def capture_snapshot_post(*args, **kwargs):
            response = original_post(*args, **kwargs)
            url = str(args[0] if args else kwargs.get("url", ""))
            if url.rstrip("/") == f"{self.api_base}/snapshots":
                try:
                    detail = response.json()
                except ValueError:
                    detail = response.text[:1000]
                self.report.setdefault("provider_diagnostics", []).append(
                    {
                        "method": "POST",
                        "path": "/snapshots",
                        "status": response.status_code,
                        "request_id": response.headers.get("x-request-id") or response.headers.get("X-Request-ID"),
                        "detail": self._safe_error(detail),
                    }
                )
            return response

        node_models.requests.post = capture_snapshot_post
        try:
            try:
                cloud.create_snapshot(cloud_backup)
            except Exception as error:
                raise AmbiguousMutation(
                    "Vultr instance-snapshot outcome is unknown; reconcile before retry."
                ) from error
        finally:
            node_models.requests.post = original_post
        if not snapshot_id:
            cloud_backup.refresh_from_db()
            try:
                snapshot_resource = self._finish_adapter_resource(
                    kind="snapshot",
                    role=snapshot_role,
                    name=cloud_backup.uuid_str,
                    provider_id=cloud_backup.unique_id,
                    readback=lambda resource_id: self._read_detail(
                        f"/snapshots/{resource_id}", "snapshot"
                    ),
                    ownership=lambda item: {
                        "description": cloud_backup.uuid_str,
                        "instance_id": self.source_instance_id,
                    },
                    cache_key="snapshots",
                    request={
                        "resource_type": "instance_snapshot",
                        "description": cloud_backup.uuid_str,
                        "source_instance_id": self.source_instance_id,
                    },
                    source_witness=self.source_instance_id,
                )
            except Exception as error:
                if isinstance(error, AmbiguousMutation):
                    raise
                raise AmbiguousMutation(
                    f"Vultr {snapshot_role} outcome is unknown; reconcile before retry."
                ) from error
            snapshot_id = str(cloud_backup.unique_id)
        if not snapshot_id:
            raise HarnessError("Instance snapshot did not persist provider ID")
        self._wait_local_backup(cloud_backup)
        snapshots = self.collection("/snapshots", "snapshots")
        matching = [
            item for item in snapshots
            if self._snapshot_matches_source(
                item,
                source_key="instance_id",
                source_id=self.source_instance_id,
                description=cloud_backup.uuid_str,
            )
        ]
        self.record_test(
            "VUL-04",
            "PASS" if len(matching) == 1 else "FAIL",
            provider={"snapshot_id": cloud_backup.unique_id, "matches": len(matching), "state": matching[0].get("status") if matching else None, "source_field_omitted": bool(matching and matching[0].get("instance_id") in (None, ""))},
            local={"backup_id": cloud_backup.id, "status": cloud_backup.get_status_display()},
        )
        before = len(matching)
        self._mutation(
            "instance-snapshot-replay",
            cloud_backup.uuid_str,
            "instance snapshot replay",
            {
                "resource_type": "instance_snapshot",
                "description": cloud_backup.uuid_str,
                "source_instance_id": self.source_instance_id,
            },
            lambda: cloud.create_snapshot(cloud_backup),
            kind="snapshot",
        )
        self.intents.clear("instance-snapshot-replay")
        after = len(
            [
                item for item in self.collection("/snapshots", "snapshots")
                if self._snapshot_matches_source(
                    item,
                    source_key="instance_id",
                    source_id=self.source_instance_id,
                    description=cloud_backup.uuid_str,
                )
            ]
        )
        self.record_test("VUL-06-instance", "PASS" if before == after == 1 else "FAIL", provider_snapshot_count=after)

        cloud_restore = CoreCloudRestore.objects.create(
            node=cloud_node,
            backup_id=cloud_backup.id,
            name=f"{self.prefix}-instance-restore",
            params={"region": self.region, "plan": self.server_plan},
        )
        cloud_restore.restore_marker = self._recovery_marker(
            "instance", "restore-instance", f"backupsheep-restore-{cloud_restore.id}"
        )[:128]
        cloud_restore.save(update_fields=["restore_marker", "modified"])
        restore_role = "restore-instance"
        restore_instance_id, _restore_instance = self._prepare_adapter_resource(
            kind="instance",
            role=restore_role,
            marker=cloud_restore.restore_marker,
            name=cloud_restore.name,
            candidates=lambda: [
                item
                for item in self.collection("/instances", "instances")
                if cloud_restore.restore_marker in self._tags(item)
                and str(item.get("snapshot_id") or "") == str(snapshot_id)
            ],
            readback=lambda resource_id: self._read_detail(
                f"/instances/{resource_id}", "instance"
            ),
            ownership=lambda item: {
                "tags": [cloud_restore.restore_marker],
                "restore_marker": cloud_restore.restore_marker,
                "snapshot_id": snapshot_id,
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
            },
            request={
                "resource_type": "instance_restore",
                "restore_marker": cloud_restore.restore_marker,
                "snapshot_id": snapshot_id,
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
            },
        )
        if restore_instance_id:
            cloud_restore.resource_id = restore_instance_id
            cloud_restore.save(update_fields=["resource_id", "modified"])
        else:
            try:
                cloud.restore_snapshot(cloud_backup, cloud_restore)
            except Exception as error:
                raise AmbiguousMutation(
                    "Vultr restore-instance outcome is unknown; reconcile before retry."
                ) from error
            cloud_restore.refresh_from_db()
            restore_instance_id = str(cloud_restore.resource_id or "")
            self._finish_adapter_resource(
                kind="instance",
                role=restore_role,
                name=cloud_restore.name,
                provider_id=restore_instance_id,
                readback=lambda resource_id: self._read_detail(
                    f"/instances/{resource_id}", "instance"
                ),
                    ownership=lambda item: {
                        "tags": [cloud_restore.restore_marker],
                        "restore_marker": cloud_restore.restore_marker,
                        "snapshot_id": snapshot_id,
                        "region": self.region,
                        "plan": self.server_plan,
                        "os_id": self.os_id,
                    },
                    cache_key="instances",
                    request={
                        "resource_type": "instance_restore",
                        "restore_marker": cloud_restore.restore_marker,
                        "snapshot_id": snapshot_id,
                        "region": self.region,
                        "plan": self.server_plan,
                        "os_id": self.os_id,
                    },
                    source_witness=snapshot_id,
            )
        if not restore_instance_id:
            raise HarnessError("Instance restore did not persist target ID")
        self.wait_for(
            "restored instance active",
            lambda: self._poll_detail(
                f"/instances/{restore_instance_id}", "instance"
            ),
            lambda item: str(item.get("status", "")).lower() in {"active", "running"},
            timeout_seconds=1200,
            interval_seconds=15,
            provider=True,
            ownership=lambda item: self._assert_poll_ownership(
                item,
                provider_id=restore_instance_id,
                expected={
                    "snapshot_id": snapshot_id,
                    "region": self.region,
                    "plan": self.server_plan,
                },
            ),
        )
        self._mutation(
            "restore-instance-replay",
            cloud_restore.restore_marker,
            "instance restore replay",
            {
                "resource_type": "instance_restore",
                "restore_marker": cloud_restore.restore_marker,
                "snapshot_id": snapshot_id,
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
            },
            lambda: cloud.restore_snapshot(cloud_backup, cloud_restore),
            kind="instance",
        )
        self.intents.clear("restore-instance-replay")
        restored_instances = [
            item for item in self.collection("/instances", "instances")
            if (
                str(item.get("id")) == restore_instance_id
                and cloud_restore.restore_marker in (
                    item.get("tags") if isinstance(item.get("tags"), list)
                    else [item.get("tags")]
                )
                and str(item.get("snapshot_id")) == str(cloud_backup.unique_id)
            )
        ]
        self.record_test(
            "VUL-07",
            "PASS" if len(restored_instances) == 1 else "FAIL",
            provider={"restore_id": restore_instance_id, "matches": len(restored_instances), "status": cloud_restore.provider_status if hasattr(cloud_restore, "provider_status") else None},
            local={"restore_id": cloud_restore.id, "status": cloud_restore.get_status_display(), "phase": cloud_restore.operation_phase},
        )

        block_backup = CoreVultrBackup.objects.create(
            vultr=block,
            uuid=f"{self.prefix}-block-snapshot",
            name=f"{self.prefix}-block-snapshot",
            unique_id="",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        block_snapshot_role = "block-snapshot"
        block_snapshot_id, _block_snapshot = self._prepare_adapter_resource(
            kind="block_snapshot",
            role=block_snapshot_role,
            marker=block_backup.uuid_str,
            name=block_backup.uuid_str,
            candidates=lambda: [
                item
                for item in self.collection("/blocks/snapshots", "snapshots")
                if self._snapshot_matches_source(
                    item,
                    source_key="block_id",
                    source_id=self.source_block_id,
                    description=block_backup.uuid_str,
                )
            ],
            readback=lambda resource_id: self._read_detail(
                f"/blocks/snapshots/{resource_id}", "snapshot"
            ),
            ownership=lambda item: {
                "description": block_backup.uuid_str,
                "block_id": self.source_block_id,
            },
            request={
                "resource_type": "block_snapshot",
                "description": block_backup.uuid_str,
                "source_block_id": self.source_block_id,
            },
        )
        if block_snapshot_id:
            block_backup.unique_id = block_snapshot_id
            block_backup.save(update_fields=["unique_id", "modified"])
        else:
            try:
                block.create_snapshot(block_backup)
            except Exception as error:
                raise AmbiguousMutation(
                    "Vultr block-snapshot outcome is unknown; reconcile before retry."
                ) from error
            block_backup.refresh_from_db()
            self._finish_adapter_resource(
                kind="block_snapshot",
                role=block_snapshot_role,
                name=block_backup.uuid_str,
                provider_id=block_backup.unique_id,
                readback=lambda resource_id: self._read_detail(
                    f"/blocks/snapshots/{resource_id}", "snapshot"
                ),
                ownership=lambda item: {
                    "description": block_backup.uuid_str,
                    "block_id": self.source_block_id,
                },
                cache_key="block_snapshots",
                request={
                    "resource_type": "block_snapshot",
                    "description": block_backup.uuid_str,
                    "source_block_id": self.source_block_id,
                },
                source_witness=self.source_block_id,
            )
            block_snapshot_id = str(block_backup.unique_id or "")
        if not block_snapshot_id:
            raise HarnessError("Block snapshot did not persist provider ID")
        self._wait_local_backup(block_backup)
        block_snapshots = self.collection("/blocks/snapshots", "snapshots")
        matching_blocks = [
            item for item in block_snapshots
            if self._snapshot_matches_source(
                item,
                source_key="block_id",
                source_id=self.source_block_id,
                description=block_backup.uuid_str,
            )
        ]
        self.record_test(
            "VUL-05",
            "PASS" if len(matching_blocks) == 1 else "FAIL",
            provider={"snapshot_id": block_backup.unique_id, "matches": len(matching_blocks), "state": matching_blocks[0].get("state") if matching_blocks else None},
            local={"backup_id": block_backup.id, "status": block_backup.get_status_display()},
        )

        block_restore = CoreCloudRestore.objects.create(
            node=block_node,
            backup_id=block_backup.id,
            name=f"{self.prefix}-block-restore",
            params={"region": self.region, "size_gb": self.block_size_gb},
        )
        block_restore.restore_marker = self._recovery_marker(
            "block", "restore-block", f"backupsheep-restore-{block_restore.id}"
        )[:128]
        block_restore.save(update_fields=["restore_marker", "modified"])
        block_restore_role = "restore-block"
        restore_block_id, _restore_block = self._prepare_adapter_resource(
            kind="block",
            role=block_restore_role,
            marker=block_restore.restore_marker,
            name=block_restore.name,
            candidates=lambda: [
                item
                for item in self.collection("/blocks", "blocks")
                if block_restore.restore_marker == str(item.get("label") or "")
                and str(item.get("snapshot_id") or "") == str(block_snapshot_id)
            ],
            readback=lambda resource_id: self._read_detail(
                f"/blocks/{resource_id}", "block"
            ),
            ownership=lambda item: {
                "label": block_restore.restore_marker,
                "restore_marker": block_restore.restore_marker,
                "snapshot_id": block_snapshot_id,
                "region": self.region,
                "size_gb": self.block_size_gb,
            },
            request={
                "resource_type": "block_restore",
                "restore_marker": block_restore.restore_marker,
                "snapshot_id": block_snapshot_id,
                "region": self.region,
                "size_gb": self.block_size_gb,
            },
        )
        if restore_block_id:
            block_restore.resource_id = restore_block_id
            block_restore.save(update_fields=["resource_id", "modified"])
        else:
            try:
                block.restore_snapshot(block_backup, block_restore)
            except Exception as error:
                raise AmbiguousMutation(
                    "Vultr restore-block outcome is unknown; reconcile before retry."
                ) from error
            block_restore.refresh_from_db()
            restore_block_id = str(block_restore.resource_id or "")
            self._finish_adapter_resource(
                kind="block",
                role=block_restore_role,
                name=block_restore.name,
                provider_id=restore_block_id,
                readback=lambda resource_id: self._read_detail(
                    f"/blocks/{resource_id}", "block"
                ),
                ownership=lambda item: {
                    "label": block_restore.restore_marker,
                    "restore_marker": block_restore.restore_marker,
                    "snapshot_id": block_snapshot_id,
                    "region": self.region,
                    "size_gb": self.block_size_gb,
                },
                cache_key="blocks",
                request={
                    "resource_type": "block_restore",
                    "restore_marker": block_restore.restore_marker,
                    "snapshot_id": block_snapshot_id,
                    "region": self.region,
                    "size_gb": self.block_size_gb,
                },
                source_witness=block_snapshot_id,
            )
        if not restore_block_id:
            raise HarnessError("Block restore did not persist target ID")
        self.wait_for(
            "restored block active",
            lambda: self._poll_detail(
                f"/blocks/{restore_block_id}", "block"
            ),
            lambda item: str(item.get("status", "")).lower() in {"active", "running"},
            timeout_seconds=900,
            interval_seconds=15,
            provider=True,
            ownership=lambda item: self._assert_poll_ownership(
                item,
                provider_id=restore_block_id,
                expected={
                    "snapshot_id": block_snapshot_id,
                    "region": self.region,
                    "size_gb": self.block_size_gb,
                },
            ),
        )
        self._mutation(
            "restore-block-replay",
            block_restore.restore_marker,
            "block restore replay",
            {
                "resource_type": "block_restore",
                "restore_marker": block_restore.restore_marker,
                "snapshot_id": block_snapshot_id,
                "region": self.region,
                "size_gb": self.block_size_gb,
            },
            lambda: block.restore_snapshot(block_backup, block_restore),
            kind="block",
        )
        self.intents.clear("restore-block-replay")
        restored_blocks = [
            item for item in self.collection("/blocks", "blocks")
            if item.get("label") == block_restore.restore_marker
            and str(item.get("snapshot_id")) == str(block_backup.unique_id)
        ]
        self.record_test(
            "VUL-08-block",
            "PASS" if len(restored_blocks) == 1 else "FAIL",
            provider={"restore_id": restore_block_id, "matches": len(restored_blocks)},
            local={"restore_id": block_restore.id, "status": block_restore.get_status_display(), "phase": block_restore.operation_phase},
        )

        try:
            monitoring = list_instance_backups(
                self.connection.auth_vultr,
                instance_id=self.source_instance_id,
            )
            self.record_test("VUL-09", "PASS", provider={"automatic_backup_count": len(monitoring), "read_only": True})
        except Exception as error:
            self.record_test("VUL-09", "FAIL", error=self._safe_error(error))
            raise

    # ---------- object storage ----------

    def _object_client(self, object_storage: dict[str, Any], fallback: dict[str, Any] | None = None):
        fallback = fallback or {}
        endpoint = object_storage.get("s3_hostname") or fallback.get("s3_hostname")
        # Validate the untrusted provider hostname before reading the returned
        # credentials into any SDK/client configuration.
        endpoint = _validate_vultr_object_storage_hostname(endpoint)
        access_key = object_storage.get("s3_access_key") or fallback.get("s3_access_key")
        secret_key = object_storage.get("s3_secret_key") or fallback.get("s3_secret_key")
        if not access_key or not secret_key:
            raise HarnessError(
                "Vultr Object Storage response omitted S3 credentials for this run."
            )
        self.object_credentials = {
            "access_key": str(access_key),
            "secret_key": str(secret_key),
            "endpoint": endpoint,
        }
        return boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                connect_timeout=10,
                read_timeout=60,
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )

    def _object_storage_ownership(self, item: dict[str, Any]) -> dict[str, Any]:
        """Build a read-back proof while tolerating Vultr's omitted tier field.

        The selected tier remains immutable in the durable request fingerprint.
        Vultr's current detail response returns ``tier_id: null`` even when the
        accepted create request included a tier.  A non-empty provider value is
        still required to match exactly; an omitted value is not fabricated as
        provider evidence.
        """

        observed_tier = item.get("tier_id")
        if observed_tier not in (None, "") and str(observed_tier) != str(
            self.object_tier_id
        ):
            raise HarnessError("Vultr Object Storage returned a different tier.")
        proof = {
            "label": f"{self.prefix}-object-storage",
            "region": str(item.get("region") or self.region),
            "cluster_id": self.object_cluster_id,
            "s3_hostname": _validate_vultr_object_storage_hostname(
                item.get("s3_hostname")
            ),
        }
        if observed_tier not in (None, ""):
            proof["tier_id"] = observed_tier
        return proof

    @staticmethod
    def _object_marker_body(prefix: str) -> bytes:
        return json.dumps(
            {"provider": "vultr", "run_id": prefix, "purpose": "BackupSheep live E2E ownership"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @staticmethod
    def _normalise_object_version(value: Any) -> str:
        value = str(value or "")
        return "" if value.lower() == "null" else value

    def _object_identity(
        self,
        client,
        bucket: str,
        key: str,
        version_id: str = "",
    ) -> tuple[dict[str, Any], bytes]:
        kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
        normalized_version = self._normalise_object_version(version_id)
        if normalized_version:
            kwargs["VersionId"] = normalized_version
        head = client.head_object(**kwargs)
        response = client.get_object(**kwargs)
        stream = response["Body"]
        try:
            body = stream.read()
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        return head, body

    def _verify_object_marker(self, client, bucket: str) -> dict[str, Any]:
        marker_key = f"{self.prefix}/ownership.json"
        entry = self._ledger_role_entry("object_key", "object-bucket-marker")
        if not entry:
            raise HarnessError(
                "Object Storage ownership marker is not durably ledgered; manual review required."
            )
        key, _version, _body = self._verify_ledgered_object(client, bucket, entry)
        if key != marker_key:
            raise HarnessError("Object Storage ownership marker witness changed.")
        return entry

    def _find_exact_object_versions(
        self,
        client,
        *,
        bucket: str,
        key: str,
        sha256: str,
        size_bytes: int,
    ) -> list[dict[str, Any]]:
        """Return complete, byte-and-digest verified versions for one key."""

        listed = self._bounded_object_inventory(client, bucket)
        versions, delete_markers = self._bounded_object_version_inventory(client, bucket)
        if delete_markers:
            raise HarnessError(
                "Object Storage key/version inventory contains delete markers; manual review required."
            )
        candidates = [
            item
            for item in versions
            if str(item.get("Key") or "") == key
        ]
        if not candidates and any(str(item.get("Key") or "") == key for item in listed):
            candidates = [{"Key": key, "VersionId": "null"}]
        verified: list[dict[str, Any]] = []
        conflicting = False
        for candidate in candidates:
            version_id = self._normalise_object_version(candidate.get("VersionId"))
            try:
                head, body = self._object_identity(client, bucket, key, version_id)
            except Exception as error:
                raise HarnessError(
                    "Object Storage version inventory could not be verified; manual review required."
                ) from error
            observed_size = int(head.get("ContentLength", len(body)))
            observed_hash = hashlib.sha256(body).hexdigest()
            observed_version = self._normalise_object_version(head.get("VersionId"))
            if observed_size == size_bytes and len(body) == size_bytes and observed_hash == sha256:
                verified.append(
                    {
                        "key": key,
                        "version_id": observed_version,
                        "etag": str(head.get("ETag") or ""),
                        "sha256": observed_hash,
                        "size_bytes": observed_size,
                        "provider_checksum_sha256": str(head.get("ChecksumSHA256") or "") or None,
                    }
                )
            else:
                conflicting = True
        if conflicting:
            raise HarnessError(
                "A conflicting Vultr Object Storage version already exists for this key; manual review required."
            )
        return verified

    @staticmethod
    def _persist_adopted_object_metadata(point, *, key: str, identity: dict[str, Any]) -> dict[str, Any]:
        """Use the production adapter's durable metadata writer without a PUT."""

        state = {
            "phase": "committed",
            "object_key": key,
            "sha256": identity["sha256"],
            "size_bytes": int(identity["size_bytes"]),
            "checksum_algorithm": "sha256",
            "etag": identity.get("etag") or "",
            "version_id": identity.get("version_id") or "",
            "provider_checksum_sha256": identity.get("provider_checksum_sha256"),
        }
        _save_state(
            point,
            VULTR_OBJECT_METADATA_KEY,
            state,
            status=point.Status.UPLOAD_COMPLETE,
        )
        return state

    def _ensure_object_bucket(self, client, bucket: str) -> str:
        marker_key = f"{self.prefix}/ownership.json"
        marker_body = self._object_marker_body(self.prefix)
        marker_hash = hashlib.sha256(marker_body).hexdigest()
        bucket_request = {
            "resource_type": "object_bucket",
            "bucket": bucket,
            "object_storage_id": str(getattr(self, "object_storage_id", "") or ""),
            "marker_key": marker_key,
            "marker_sha256": marker_hash,
        }
        marker_request = {
            "resource_type": "object_marker",
            "bucket": bucket,
            "key": marker_key,
            "sha256": marker_hash,
            "size_bytes": len(marker_body),
        }
        bucket_entry = self._ledger_role_entry("object_bucket", "object-bucket")
        marker_entry = self._ledger_role_entry("object_key", "object-bucket-marker")
        bucket_pending = self._pending_intent_witness(
            "object-bucket", bucket, "Object Storage bucket create", bucket_request
        )
        marker_pending = self._pending_intent_witness(
            "object-bucket-marker", marker_key, "Object Storage ownership marker", marker_request
        )

        if bucket_entry:
            ownership = bucket_entry.get("ownership") or {}
            if (
                str(bucket_entry.get("resource_id") or "") != bucket
                or ownership.get("run_id") != self.prefix
                or ownership.get("role") != "object-bucket"
                or str(ownership.get("bucket") or "") != bucket
                or str(ownership.get("marker_key") or "") != marker_key
                or str(ownership.get("marker_sha256") or "") != marker_hash
            ):
                raise HarnessError(
                    "Ledgered Vultr Object Storage bucket has a different ownership witness."
                )
        if marker_entry:
            ownership = marker_entry.get("ownership") or {}
            if (
                str(marker_entry.get("resource_id") or "") != f"{bucket}/{marker_key}"
                or ownership.get("run_id") != self.prefix
                or ownership.get("role") != "object-bucket-marker"
                or str(ownership.get("bucket") or "") != bucket
                or str(ownership.get("key") or "") != marker_key
                or str(ownership.get("sha256") or "") != marker_hash
                or int(ownership.get("size_bytes") or -1) != len(marker_body)
            ):
                raise HarnessError(
                    "Ledgered Vultr Object Storage marker has a different ownership witness."
                )

        # Recover the narrow crash windows between persisting the two exact
        # resource records. A missing record still requires its own exact intent.
        if bucket_entry or marker_entry:
            if not bucket_entry:
                self._pending_intent_witness(
                    "object-bucket",
                    bucket,
                    "Object Storage bucket create",
                    bucket_request,
                    required=True,
                )
            if not marker_entry:
                self._pending_intent_witness(
                    "object-bucket-marker",
                    marker_key,
                    "Object Storage ownership marker",
                    marker_request,
                    required=True,
                )
            try:
                marker_head, observed_marker = self._object_identity(
                    client, bucket, marker_key
                )
            except Exception as error:
                raise HarnessError(
                    "Ledgered Vultr Object Storage bucket failed ownership read-back."
                ) from error
            if observed_marker != marker_body:
                raise HarnessError(
                    "Ledgered Vultr Object Storage ownership marker changed."
                )
            if not marker_entry:
                marker_entry = self._remember_resource(
                    kind="object_key",
                    role="object-bucket-marker",
                    provider_id=f"{bucket}/{marker_key}",
                    name=marker_key,
                    ownership={
                        "bucket": bucket,
                        "key": marker_key,
                        "etag": str(marker_head.get("ETag") or ""),
                        "version_id": self._normalise_object_version(
                            marker_head.get("VersionId")
                        ),
                        "sha256": marker_hash,
                        "size_bytes": len(marker_body),
                    },
                    source_witness=bucket,
                    cache_key="object_keys",
                    operation_key="object-bucket-marker",
                    request=marker_request,
                )
            if not bucket_entry:
                bucket_entry = self._remember_resource(
                    kind="object_bucket",
                    role="object-bucket",
                    provider_id=bucket,
                    name=bucket,
                    ownership={
                        "bucket": bucket,
                        "marker_key": marker_key,
                        "marker_sha256": marker_hash,
                    },
                    cache_key="object_buckets",
                    operation_key="object-bucket",
                    request=bucket_request,
                )
            self._report_ledger_entry(marker_entry)
            self._report_ledger_entry(bucket_entry)
            if marker_pending:
                self.intents.clear("object-bucket-marker")
            if bucket_pending:
                self.intents.clear("object-bucket")
            return bucket

        try:
            names = [item.get("Name") for item in client.list_buckets().get("Buckets", [])]
        except Exception as error:
            raise HarnessError("Unable to reconcile the exact Vultr Object Storage bucket.") from error
        if bucket in names:
            # A deterministic name and marker are not ownership authority on a
            # clean run. Both writes must already have durable intent witnesses.
            self._pending_intent_witness(
                    "object-bucket",
                    bucket,
                    "Object Storage bucket create",
                    bucket_request,
                    required=True,
            )
            self._pending_intent_witness(
                    "object-bucket-marker",
                    marker_key,
                    "Object Storage ownership marker",
                    marker_request,
                    required=True,
            )
            try:
                marker_head, observed_marker = self._object_identity(
                    client, bucket, marker_key
                )
            except Exception as error:
                raise HarnessError(
                    "An exact Vultr Object Storage bucket exists without the run ownership marker; "
                    "manual review required."
                ) from error
            if observed_marker != marker_body:
                raise HarnessError(
                    "An exact Vultr Object Storage bucket has a changed ownership marker; "
                    "manual review required."
                )
            self._remember_resource(
                kind="object_key",
                role="object-bucket-marker",
                provider_id=f"{bucket}/{marker_key}",
                name=marker_key,
                ownership={
                    "bucket": bucket,
                    "key": marker_key,
                    "etag": str(marker_head.get("ETag") or ""),
                    "version_id": self._normalise_object_version(
                        marker_head.get("VersionId")
                    ),
                    "sha256": marker_hash,
                    "size_bytes": len(marker_body),
                },
                source_witness=bucket,
                cache_key="object_keys",
                operation_key="object-bucket-marker",
                request=marker_request,
            )
            self._remember_resource(
                kind="object_bucket",
                role="object-bucket",
                provider_id=bucket,
                name=bucket,
                ownership={
                    "bucket": bucket,
                    "marker_key": marker_key,
                    "marker_sha256": marker_hash,
                },
                cache_key="object_buckets",
                operation_key="object-bucket",
                request=bucket_request,
            )
            return bucket

        if bucket_pending or marker_pending:
            raise HarnessError(
                "Vultr Object Storage bucket create outcome is unknown and no exact bucket "
                "is visible; manual review required."
            )
        # Persist both deterministic mutation witnesses before either provider
        # write so a crash between bucket creation and marker creation cannot be
        # mistaken for a clean-run name collision.
        self._intent(
            "object-bucket", bucket, "Object Storage bucket create", bucket_request,
            kind="object_bucket",
        )
        self._intent(
            "object-bucket-marker",
            marker_key,
            "Object Storage ownership marker",
            marker_request,
            kind="object_key",
        )
        try:
            client.create_bucket(Bucket=bucket)
        except Exception as error:
            raise AmbiguousMutation(
                "Vultr Object Storage bucket create outcome is unknown; reconcile before retry."
            ) from error
        try:
            client.head_bucket(Bucket=bucket)
        except Exception as error:
            raise AmbiguousMutation(
                "Vultr Object Storage bucket was not visible after create."
            ) from error
        try:
            client.put_object(
                Bucket=bucket,
                Key=marker_key,
                Body=marker_body,
                Metadata={"backupsheep-run": self.prefix},
            )
        except Exception as error:
            raise AmbiguousMutation(
                "Vultr Object Storage ownership marker outcome is unknown; "
                "reconcile before retry."
            ) from error
        try:
            marker_head, observed_marker = self._object_identity(client, bucket, marker_key)
        except Exception as error:
            raise AmbiguousMutation(
                "Vultr Object Storage ownership marker was not visible after create."
            ) from error
        if observed_marker != marker_body:
            raise AmbiguousMutation("Vultr Object Storage ownership marker failed read-back.")
        self._remember_resource(
            kind="object_key",
            role="object-bucket-marker",
            provider_id=f"{bucket}/{marker_key}",
            name=marker_key,
            ownership={
                "bucket": bucket,
                "key": marker_key,
                "etag": str(marker_head.get("ETag") or ""),
                "version_id": self._normalise_object_version(
                    marker_head.get("VersionId")
                ),
                "sha256": marker_hash,
                "size_bytes": len(marker_body),
            },
            source_witness=bucket,
            cache_key="object_keys",
            operation_key="object-bucket-marker",
            request=marker_request,
        )
        self._remember_resource(
            kind="object_bucket",
            role="object-bucket",
            provider_id=bucket,
            name=bucket,
            ownership={
                "bucket": bucket,
                "marker_key": marker_key,
                "marker_sha256": marker_hash,
            },
            cache_key="object_buckets",
            operation_key="object-bucket",
            request=bucket_request,
        )
        return bucket

    def _run_verified_object_upload(
        self,
        point,
        *,
        bucket: str,
        expected_key: str,
        content: bytes,
    ) -> tuple[dict[str, Any] | None, dict[str, Any], str]:
        """Verify a complete inventory before allowing another adapter PUT."""

        role = "object-key"
        operation = "Object Storage backup upload"
        expected_hash = hashlib.sha256(content).hexdigest()
        request = {
            "resource_type": "object_upload",
            "bucket": bucket,
            "key": expected_key,
            "sha256": expected_hash,
            "size_bytes": len(content),
            "marker_key": f"{self.prefix}/ownership.json",
        }
        entry = self._ledger_role_entry("object_key", role)
        pending = self._pending_intent_witness(role, expected_key, operation, request)
        if entry:
            ownership = entry.get("ownership") or {}
            if (
                ownership.get("run_id") != self.prefix
                or ownership.get("role") != role
                or str(ownership.get("request_fingerprint") or "") != _request_fingerprint(request)
                or str(ownership.get("bucket") or "") != bucket
                or str(ownership.get("key") or "") != expected_key
                or str(ownership.get("sha256") or "") != expected_hash
                or int(ownership.get("size_bytes") or -1) != len(content)
            ):
                raise HarnessError(
                    "Ledgered Vultr Object Storage key failed exact ownership proof."
                )
        elif pending is None:
            self._intent(role, expected_key, operation, request, kind="object_key")
            pending = self.intents.get(role)

        client = getattr(self, "object_client", None)
        if client is None:
            raise HarnessError(
                "Object Storage upload reconciliation requires the authenticated S3 client."
            )
        # The ownership marker is the fence that makes this inventory safe to
        # interpret. Never inspect or mutate a backup key after that marker has
        # disappeared or changed.
        self._verify_object_marker(client, bucket)
        exact = self._find_exact_object_versions(
            client,
            bucket=bucket,
            key=expected_key,
            sha256=expected_hash,
            size_bytes=len(content),
        )
        if len(exact) > 1:
            raise HarnessError(
                "Multiple exact Vultr Object Storage versions match this upload; manual review required."
            )
        if exact:
            identity = exact[0]
            if entry:
                ownership = entry.get("ownership") or {}
                if (
                    str(ownership.get("etag") or "") != str(identity.get("etag") or "")
                    or self._normalise_object_version(ownership.get("version_id"))
                    != self._normalise_object_version(identity.get("version_id"))
                ):
                    raise HarnessError(
                        "Verified Vultr Object Storage metadata differs from the durable ledger."
                    )
            metadata = self._persist_adopted_object_metadata(
                point, key=expected_key, identity=identity
            )
            if entry:
                if pending:
                    self.intents.clear(role)
                return entry, metadata, expected_hash
            adopted = self._remember_resource(
                kind="object_key",
                role=role,
                provider_id=f"{bucket}/{expected_key}",
                name=expected_key,
                ownership={
                    "bucket": bucket,
                    "key": expected_key,
                    "etag": str(identity.get("etag") or ""),
                    "version_id": self._normalise_object_version(identity.get("version_id")),
                    "sha256": expected_hash,
                    "size_bytes": len(content),
                },
                source_witness=bucket,
                cache_key="object_keys",
                operation_key=role,
                request=request,
            )
            return adopted, metadata, expected_hash

        # No exact version and no same-key conflict was found. This is the only
        # branch allowed to invoke the real adapter and therefore the only
        # branch that can issue a PUT.
        try:
            storage_vultr(point)
        except Exception as error:
            raise AmbiguousMutation(
                "Vultr Object Storage backup upload outcome is unknown; "
                "reconcile before retry."
            ) from error
        point.refresh_from_db()
        metadata = (point.metadata or {}).get(VULTR_OBJECT_METADATA_KEY) or {}
        if (
            point.status != point.Status.UPLOAD_COMPLETE
            or str(point.storage_file_id or "") != expected_key
            or str(metadata.get("object_key") or "") != expected_key
            or str(metadata.get("sha256") or "") != expected_hash
            or int(metadata.get("size_bytes") or -1) != len(content)
            or not str(metadata.get("etag") or "")
            or "version_id" not in metadata
            or str(metadata.get("phase") or "") != "committed"
        ):
            raise AmbiguousMutation(
                "Vultr Object Storage adapter did not persist a complete verified identity."
            )
        return entry, metadata, expected_hash

    def create_object_storage_and_test(self) -> None:
        label = f"{self.prefix}-object-storage"
        storage_id, _object_storage = self._ensure_provider_resource(
            kind="object_storage",
            role="object-storage",
            marker=label,
            name=label,
            cache_key="object_storages",
            candidates=lambda: self.collection("/object-storage", "object_storages"),
            readback=lambda resource_id: self._read_detail(
                f"/object-storage/{resource_id}", "object_storage"
            ),
            create=lambda: self.request(
                "POST",
                "/object-storage",
                expected=(201, 202),
                body={
                    "cluster_id": self.object_cluster_id,
                    "tier_id": self.object_tier_id,
                    "label": label,
                },
            ),
            id_from_response=lambda payload: (payload.get("object_storage") or {}).get("id"),
            ownership=self._object_storage_ownership,
            request={
                "resource_type": "object_storage",
                "cluster_id": self.object_cluster_id,
                "tier_id": self.object_tier_id,
                "region": self.region,
                "label": label,
            },
        )
        self.object_storage_id = storage_id
        object_storage = self.wait_for(
            "object storage active",
            lambda: self._poll_detail(
                f"/object-storage/{storage_id}", "object_storage"
            ),
            lambda item: str(item.get("status", "")).lower() in {"active", "running"},
            timeout_seconds=900,
            interval_seconds=15,
            provider=True,
            ownership=lambda item: (
                self._object_storage_ownership(item),
                self._assert_poll_ownership(
                    item,
                    provider_id=storage_id,
                    expected={
                        "region": self.region,
                        "cluster_id": self.object_cluster_id,
                    },
                ),
            ),
        )
        client = self._object_client(object_storage)
        self.object_client = client
        endpoint = self.object_credentials["endpoint"]
        access_key = self.object_credentials["access_key"]
        secret_key = self.object_credentials["secret_key"]
        bucket = f"{self.prefix}-bucket"[:63]
        key = f"{self.prefix}/fixture.zip"
        content = b"BackupSheep Vultr live E2E object fixture\n"
        self._ensure_object_bucket(client, bucket)

        website_node = factories.make_website_node(self.account, self.member)
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="vultr"),
            name=label,
            added_by=self.member,
        )
        CoreStorageVultr.objects.create(
            storage=storage,
            access_key=bs_encrypt(access_key, self.account.get_encryption_key()),
            secret_key=bs_encrypt(secret_key, self.account.get_encryption_key()),
            bucket_name=bucket,
            endpoint=endpoint,
            prefix=self.prefix,
        )
        backup = CoreWebsiteBackup.objects.create(
            website=website_node.website,
            uuid=f"{self.prefix}-file-backup",
            name=f"{self.prefix}-file-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        archive = ROOT / "_storage" / f"{backup.uuid}.zip"
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(content)
        expected_key = f"{self.prefix}/{backup.uuid}.zip"
        object_role = "object-key"
        try:
            object_entry, metadata, expected_hash = self._run_verified_object_upload(
                point,
                bucket=bucket,
                expected_key=expected_key,
                content=content,
            )
            head, body = self._object_identity(client, bucket, expected_key)
            if hashlib.sha256(body).hexdigest() != expected_hash or len(body) != len(content):
                raise AmbiguousMutation(
                    "Vultr Object Storage backup object failed exact content read-back."
                )
            if (
                str(head.get("ETag") or "") != str(metadata.get("etag") or "")
                or self._normalise_object_version(head.get("VersionId"))
                != self._normalise_object_version(metadata.get("version_id"))
            ):
                raise AmbiguousMutation(
                    "Vultr Object Storage provider identity differs from adapter metadata."
                )
            first_identity = (
                metadata.get("etag"),
                self._normalise_object_version(metadata.get("version_id")),
                point.storage_file_id,
            )
            if not object_entry:
                self._remember_resource(
                    kind="object_key",
                    role=object_role,
                    provider_id=f"{bucket}/{expected_key}",
                    name=expected_key,
                    ownership={
                        "bucket": bucket,
                        "key": expected_key,
                        "etag": str(metadata.get("etag") or ""),
                        "version_id": self._normalise_object_version(
                            metadata.get("version_id")
                        ),
                        "sha256": expected_hash,
                        "size_bytes": len(content),
                    },
                    source_witness=bucket,
                    cache_key="object_keys",
                    operation_key=object_role,
                    request={
                        "resource_type": "object_upload",
                        "bucket": bucket,
                        "key": expected_key,
                        "sha256": expected_hash,
                        "size_bytes": len(content),
                        "marker_key": f"{self.prefix}/ownership.json",
                    },
                )
            # Keep the local archive present for the replay. A worker retry has
            # the source archive available; deleting it before this call would
            # test the file-not-found path instead of crash-safe object adoption.
            self._mutation(
                "object-key-replay",
                expected_key,
                "Object Storage backup replay",
                {
                    "resource_type": "object_upload",
                    "bucket": bucket,
                    "key": expected_key,
                    "sha256": expected_hash,
                    "size_bytes": len(content),
                    "marker_key": f"{self.prefix}/ownership.json",
                },
                lambda: storage_vultr(point),
                kind="object_key",
            )
            self.intents.clear("object-key-replay")
            point.refresh_from_db()
            second_metadata = (point.metadata or {}).get(VULTR_OBJECT_METADATA_KEY) or {}
            second_identity = (
                second_metadata.get("etag"),
                self._normalise_object_version(second_metadata.get("version_id")),
                point.storage_file_id,
            )
            self.record_test(
                "VUL-10",
                "PASS" if point.status == point.Status.UPLOAD_COMPLETE and hashlib.sha256(body).hexdigest() == expected_hash and first_identity == second_identity else "FAIL",
                provider={"bucket": bucket, "key": point.storage_file_id, "etag": head.get("ETag"), "version_id": head.get("VersionId")},
                local={
                    "storage_point_id": point.id,
                    "first_metadata": metadata,
                    "second_metadata": second_metadata,
                    "first_identity": first_identity,
                    "second_identity": second_identity,
                    "status": point.status,
                    "status_display": point.get_status_display(),
                    "sha256": expected_hash,
                    "size_bytes": len(content),
                },
            )
        finally:
            archive.unlink(missing_ok=True)

    # ---------- managed database ----------

    def create_managed_database_and_test(self) -> None:
        label = f"{self.prefix}-database"
        database_id, _database = self._ensure_provider_resource(
            kind="database",
            role="source-database",
            marker=label,
            name=label,
            cache_key="databases",
            candidates=lambda: self.collection("/databases", "databases"),
            readback=lambda resource_id: self._read_detail(
                f"/databases/{resource_id}", "database"
            ),
            create=lambda: self.request(
                "POST",
                "/databases",
                expected=(201, 202),
                body={
                    "database_engine": self.database_engine,
                    "database_engine_version": self.database_engine_version,
                    "region": self.region,
                    "plan": self.database_plan,
                    "label": label,
                },
            ),
            id_from_response=lambda payload: (payload.get("database") or {}).get("id"),
            ownership=lambda item: {
                "label": label,
                "region": self.region,
                "plan": self.database_plan,
                "database_engine": self.database_engine,
                "database_engine_version": self.database_engine_version,
            },
            request={
                "resource_type": "managed_database",
                "database_engine": self.database_engine,
                "database_engine_version": self.database_engine_version,
                "region": self.region,
                "plan": self.database_plan,
                "label": label,
            },
        )
        self.wait_for(
            "managed database running",
            lambda: self._poll_detail(f"/databases/{database_id}", "database"),
            lambda item: str(item.get("status", "")).lower() in {"running", "active", "available"},
            timeout_seconds=1800,
            interval_seconds=20,
            provider=True,
            ownership=lambda item: self._assert_poll_ownership(
                item,
                provider_id=database_id,
                expected={
                    "region": self.region,
                    "plan": self.database_plan,
                    "database_engine": self.database_engine,
                    "database_engine_version": self.database_engine_version,
                },
            ),
        )
        node, managed = self.local_node(CoreNode.Type.DATABASE, label, database_id)
        managed.refresh_metadata()
        db_backup = CoreVultrDatabaseBackup.objects.create(
            vultr_database=managed,
            uuid=f"{self.prefix}-db-backup",
            name=f"{self.prefix}-db-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        self.wait_for(
            "managed database provider backup metadata",
            lambda: managed.client.list_backup_records(database_id),
            lambda records: bool(records),
            timeout_seconds=1800,
            interval_seconds=30,
            provider=True,
            ownership=lambda records: self._assert_backup_records_ownership(
                records, database_id
            ),
        )
        managed.create_snapshot(db_backup)
        db_backup.refresh_from_db()
        db_backup.poll_status()
        if not db_backup.provider_backup_id:
            raise HarnessError("Managed database backup metadata did not persist provider marker")
        self.record_test(
            "VUL-11",
            "PASS" if db_backup.status == UtilBackup.Status.COMPLETE else "FAIL",
            provider={"source_database_id": database_id, "provider_backup_id": db_backup.provider_backup_id, "provider_status": db_backup.provider_status},
            local={"backup_id": db_backup.id, "marker": db_backup.provider_marker, "status": db_backup.get_status_display()},
        )

        db_restore = CoreVultrDatabaseRestore.objects.create(
            backup=db_backup,
            name=f"{self.prefix}-database-restore",
            params={"region": self.region, "plan": self.database_plan, "type": "basebackup"},
        )
        db_restore.provider_marker = self._recovery_marker(
            "database", "restore-database", f"bs-restore-{db_restore.uuid.hex[:20]}"
        )
        db_restore.save(update_fields=["provider_marker", "modified"])
        db_restore_role = "restore-database"
        restore_id, _restore_database = self._prepare_adapter_resource(
            kind="database",
            role=db_restore_role,
            marker=db_restore.provider_marker,
            name=db_restore.name,
            candidates=lambda: [
                item
                for item in self.collection("/databases", "databases")
                if item.get("label") == db_restore.provider_marker
            ],
            readback=lambda resource_id: self._read_detail(
                f"/databases/{resource_id}", "database"
            ),
            ownership=lambda item: {
                "label": db_restore.provider_marker,
                "restore_marker": db_restore.provider_marker,
                "region": str((db_restore.params or {}).get("region") or self.region),
                "plan": str((db_restore.params or {}).get("plan") or self.database_plan),
                "database_engine": self.database_engine,
                "database_engine_version": self.database_engine_version,
                "source_id": database_id,
            },
            request={
                "resource_type": "managed_database_restore",
                "restore_marker": db_restore.provider_marker,
                "source_database_id": database_id,
                "provider_backup_id": db_backup.provider_backup_id,
                "database_engine": self.database_engine,
                "database_engine_version": self.database_engine_version,
                "region": str((db_restore.params or {}).get("region") or self.region),
                "plan": str((db_restore.params or {}).get("plan") or self.database_plan),
            },
        )
        if restore_id:
            db_restore.resource_id = restore_id
            db_restore.status = db_restore.Status.IN_PROGRESS
            db_restore.save(update_fields=["resource_id", "status", "modified"])
        else:
            try:
                managed.restore_snapshot(db_backup, db_restore)
            except Exception as error:
                raise AmbiguousMutation(
                    "Vultr managed-database fork outcome is unknown; reconcile before retry."
                ) from error
            db_restore.refresh_from_db()
            restore_id = str(db_restore.resource_id or "")
            self._finish_adapter_resource(
                kind="database",
                role=db_restore_role,
                name=db_restore.name,
                provider_id=restore_id,
                readback=lambda resource_id: self._read_detail(
                    f"/databases/{resource_id}", "database"
                ),
                ownership=lambda item: {
                    "label": db_restore.provider_marker,
                    "restore_marker": db_restore.provider_marker,
                    "region": str((db_restore.params or {}).get("region") or self.region),
                    "plan": str((db_restore.params or {}).get("plan") or self.database_plan),
                    "database_engine": self.database_engine,
                    "database_engine_version": self.database_engine_version,
                    "source_id": database_id,
                },
                cache_key="databases",
                request={
                    "resource_type": "managed_database_restore",
                    "restore_marker": db_restore.provider_marker,
                    "source_database_id": database_id,
                    "provider_backup_id": db_backup.provider_backup_id,
                    "database_engine": self.database_engine,
                    "database_engine_version": self.database_engine_version,
                    "region": str((db_restore.params or {}).get("region") or self.region),
                    "plan": str((db_restore.params or {}).get("plan") or self.database_plan),
                },
                source_witness=database_id,
            )
        if not restore_id:
            raise HarnessError("Managed database fork did not persist target ID")

        def read_fork_status():
            db_restore.refresh_from_db()
            state = managed.check_restore(db_restore)
            if state == CoreVultrDatabaseRestore.Status.FAILED:
                raise HarnessError(
                    "BackupSheep marked managed database fork failed: "
                    f"{db_restore.provider_status or 'provider status failure'}"
                )
            return state

        self.wait_for(
            "managed database fork running",
            read_fork_status,
            lambda state: state == CoreVultrDatabaseRestore.Status.COMPLETE,
            timeout_seconds=1800,
            interval_seconds=30,
        )
        self._mutation(
            "restore-database-replay",
            db_restore.provider_marker,
            "managed database restore replay",
            {
                "resource_type": "managed_database_restore",
                "restore_marker": db_restore.provider_marker,
                "source_database_id": database_id,
                "provider_backup_id": db_backup.provider_backup_id,
                "database_engine": self.database_engine,
                "database_engine_version": self.database_engine_version,
                "region": str((db_restore.params or {}).get("region") or self.region),
                "plan": str((db_restore.params or {}).get("plan") or self.database_plan),
            },
            lambda: managed.restore_snapshot(db_backup, db_restore),
            kind="database",
        )
        self.intents.clear("restore-database-replay")
        databases = self.collection("/databases", "databases")
        targets = [item for item in databases if item.get("label") == db_restore.provider_marker]
        source = next((item for item in databases if item.get("id") == database_id), {})
        self.record_test(
            "VUL-12",
            "PASS" if len(targets) == 1 and source.get("label") == label else "FAIL",
            provider={"source_id": database_id, "restore_id": restore_id, "matching_targets": len(targets), "source_label_unchanged": source.get("label") == label},
            local={"restore_id": db_restore.id, "marker": db_restore.provider_marker, "status": db_restore.get_status_display()},
        )

    # ---------- cleanup ----------

    @staticmethod
    def _s3_not_found(error: Exception) -> bool:
        response = getattr(error, "response", {}) or {}
        error_data = response.get("Error", {}) if isinstance(response, dict) else {}
        code = str(error_data.get("Code") or "").lower()
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode") if isinstance(response, dict) else None
        return code in {"404", "nosuchbucket", "nosuchkey", "notfound"} or status == 404

    def _wait_for_provider_absence(
        self,
        path: str,
        response_key: str,
        entry: dict[str, Any],
        *,
        timeout_seconds: int = 180,
        interval_seconds: int = 5,
    ) -> None:
        """Verify a deleted provider resource is absent before finalizing state."""

        deadline = time.monotonic() + max(0, timeout_seconds)
        while True:
            try:
                resource = self._read_cleanup_resource(entry, path, response_key)
            except ProviderNotFound:
                return
            if resource is None:
                return
            # A visible resource during the grace period is still required to
            # carry the exact original ownership witness. Never keep polling,
            # or issue another delete, against an adopted/recreated resource.
            if not self._resource_matches_entry(resource, entry):
                raise HarnessError(
                    "Provider delete read-back changed ownership; manual review required."
                )
            if time.monotonic() >= deadline:
                raise ProviderTransientFailure(
                    "Provider delete remains visible after the bounded verification window."
                )
            time.sleep(max(0, interval_seconds))

    def _wait_for_object_absence(
        self,
        client,
        bucket: str,
        key: str,
        version_id: str = "",
        *,
        timeout_seconds: int = 180,
        interval_seconds: int = 5,
    ) -> None:
        """Verify one exact object version is absent after deletion."""

        kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
        normalized_version = self._normalise_object_version(version_id)
        if normalized_version:
            kwargs["VersionId"] = normalized_version
        deadline = time.monotonic() + max(0, timeout_seconds)
        while True:
            try:
                client.head_object(**kwargs)
            except Exception as error:
                if self._s3_not_found(error):
                    return
                raise ProviderTransientFailure(
                    "Object Storage delete verification encountered a resumable provider failure."
                ) from error
            if time.monotonic() >= deadline:
                raise ProviderTransientFailure(
                    "Object Storage version remains visible after the bounded verification window."
                )
            time.sleep(max(0, interval_seconds))

    def _wait_for_object_bucket_absence(
        self,
        client,
        bucket: str,
        *,
        timeout_seconds: int = 180,
        interval_seconds: int = 5,
    ) -> None:
        """Verify an Object Storage bucket is absent after deletion."""

        deadline = time.monotonic() + max(0, timeout_seconds)
        while True:
            try:
                client.head_bucket(Bucket=bucket)
            except Exception as error:
                if self._s3_not_found(error):
                    return
                raise ProviderTransientFailure(
                    "Object Storage bucket delete verification encountered a resumable provider failure."
                ) from error
            if time.monotonic() >= deadline:
                raise ProviderTransientFailure(
                    "Object Storage bucket remains visible after the bounded verification window."
                )
            time.sleep(max(0, interval_seconds))

    def _object_client_for_cleanup(self):
        entry = self._ledger_role_entry(
            "object_storage", "object-storage", allow_manual_review=True
        )
        if not entry:
            return None
        resource = self._read_detail(
            f"/object-storage/{entry['resource_id']}", "object_storage"
        )
        if resource is None:
            raise HarnessError("Ledgered Vultr Object Storage subscription is absent.")
        # This check intentionally precedes _object_client(), which is the first
        # place provider-returned S3 credentials are read or handed to an SDK.
        if not self._resource_matches_entry(resource, entry):
            raise HarnessError(
                "Ledgered Vultr Object Storage subscription failed exact ownership read-back."
            )
        client = getattr(self, "object_client", None)
        if client is not None:
            return client
        client = self._object_client(resource)
        self.object_client = client
        return client

    @staticmethod
    def _bounded_object_inventory(
        client,
        bucket: str,
        *,
        max_pages: int = 100,
        max_items: int = 10_000,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        seen_tokens: set[str] = set()
        token = ""
        for _page_number in range(max_pages):
            kwargs: dict[str, Any] = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            response = client.list_objects_v2(**kwargs)
            page = response.get("Contents") or []
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise HarnessError("Object Storage returned a malformed object inventory.")
            for item in page:
                key = str(item.get("Key") or "")
                if not key or key in seen_keys:
                    raise HarnessError(
                        "Object Storage returned a missing or duplicate object key."
                    )
                seen_keys.add(key)
                items.append(item)
                if len(items) > max_items:
                    raise HarnessError(
                        "Object Storage inventory exceeded the bounded cleanup limit."
                    )
            if not bool(response.get("IsTruncated")):
                return items
            next_token = str(response.get("NextContinuationToken") or "")
            if not next_token or next_token in seen_tokens:
                raise HarnessError(
                    "Object Storage returned a repeated or missing continuation token."
                )
            seen_tokens.add(next_token)
            token = next_token
        raise HarnessError("Object Storage inventory exceeded the bounded page limit.")

    @classmethod
    def _bounded_object_version_inventory(
        cls,
        client,
        bucket: str,
        *,
        max_pages: int = 100,
        max_items: int = 10_000,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        versions: list[dict[str, Any]] = []
        delete_markers: list[dict[str, Any]] = []
        seen_identities: set[tuple[str, str, str]] = set()
        seen_tokens: set[tuple[str, str]] = set()
        key_marker = ""
        version_marker = ""
        for _page_number in range(max_pages):
            kwargs: dict[str, Any] = {"Bucket": bucket, "MaxKeys": 1000}
            if key_marker:
                kwargs["KeyMarker"] = key_marker
            if version_marker:
                kwargs["VersionIdMarker"] = version_marker
            response = client.list_object_versions(**kwargs)
            page_versions = response.get("Versions") or []
            page_markers = response.get("DeleteMarkers") or []
            if (
                not isinstance(page_versions, list)
                or not isinstance(page_markers, list)
                or any(not isinstance(item, dict) for item in page_versions + page_markers)
            ):
                raise HarnessError("Object Storage returned a malformed version inventory.")
            for category, page, target in (
                ("version", page_versions, versions),
                ("delete-marker", page_markers, delete_markers),
            ):
                for item in page:
                    key = str(item.get("Key") or "")
                    version_id = cls._normalise_object_version(item.get("VersionId"))
                    identity = (category, key, version_id)
                    if not key or identity in seen_identities:
                        raise HarnessError(
                            "Object Storage returned a missing or duplicate object version."
                        )
                    seen_identities.add(identity)
                    target.append(item)
                    if len(versions) + len(delete_markers) > max_items:
                        raise HarnessError(
                            "Object Storage version inventory exceeded the bounded cleanup limit."
                        )
            if not bool(response.get("IsTruncated")):
                return versions, delete_markers
            next_key = str(response.get("NextKeyMarker") or "")
            next_version = str(response.get("NextVersionIdMarker") or "")
            next_token = (next_key, next_version)
            if not next_key or next_token in seen_tokens:
                raise HarnessError(
                    "Object Storage returned a repeated or missing version cursor."
                )
            seen_tokens.add(next_token)
            key_marker, version_marker = next_token
        raise HarnessError("Object Storage version inventory exceeded the bounded page limit.")

    def _verify_ledgered_object(
        self,
        client,
        bucket: str,
        entry: dict[str, Any],
    ) -> tuple[str, str, bytes]:
        provider_id = str(entry.get("resource_id") or "")
        ownership = entry.get("ownership") or {}
        key = str(ownership.get("key") or "")
        version_id = self._normalise_object_version(ownership.get("version_id"))
        if (
            ownership.get("run_id") != self.prefix
            or str(ownership.get("bucket") or "") != bucket
            or not key
            or provider_id != f"{bucket}/{key}"
            or not str(ownership.get("sha256") or "")
            or "size_bytes" not in ownership
        ):
            raise HarnessError(
                f"object {provider_id} has malformed durable ownership proof"
            )
        kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id:
            kwargs["VersionId"] = version_id
        head = client.head_object(**kwargs)
        response = client.get_object(**kwargs)
        stream = response["Body"]
        try:
            body = stream.read()
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        if len(body) != int(ownership["size_bytes"]):
            raise HarnessError("object byte-count ownership proof failed")
        if hashlib.sha256(body).hexdigest() != str(ownership["sha256"]):
            raise HarnessError("object SHA-256 ownership proof failed")
        if ownership.get("etag") and str(head.get("ETag") or "") != str(ownership["etag"]):
            raise HarnessError("object ETag ownership proof failed")
        if self._normalise_object_version(head.get("VersionId")) != version_id:
            raise HarnessError("object version ownership proof failed")
        return key, version_id, body

    def _delete_ledgered_object(
        self,
        client,
        bucket: str,
        entry: dict[str, Any],
    ) -> None:
        provider_id = str(entry.get("resource_id") or "")
        ownership = entry.get("ownership") or {}
        key = str(ownership.get("key") or "")
        version_id = self._normalise_object_version(ownership.get("version_id"))
        cleanup_key = f"cleanup:object_key:{provider_id}"
        request = self._delete_request_for_entry(entry)
        self._prepare_cleanup_intent(
            cleanup_key,
            provider_id,
            "Object Storage object delete",
            request,
            kind="object_key",
        )
        kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id:
            kwargs["VersionId"] = version_id
        try:
            client.delete_object(**kwargs)
        except Exception as error:
            if not self._s3_not_found(error):
                raise
        # A successful DELETE response is not proof that the version is no
        # longer observable. Keep the intent and ledger authority until an
        # exact HEAD returns 404.
        self._wait_for_object_absence(client, bucket, key, version_id)
        self.intents.clear(cleanup_key)
        self.ledger.mark_cleanup("object_key", provider_id, state="deleted")

    @staticmethod
    def _pending_summary(key: str, intent: dict[str, Any], *, state: str) -> dict[str, Any]:
        return {
            "key": str(key),
            "kind": str(intent.get("kind") or ""),
            "operation": str(intent.get("operation") or ""),
            "marker": str(intent.get("marker") or ""),
            "fingerprint": str(intent.get("fingerprint") or ""),
            "state": state,
        }

    def _pending_provider_spec(
        self,
        key: str,
        intent: dict[str, Any],
    ) -> tuple[str, str, str, str, dict[str, Any]] | None:
        """Map a pending provider/adaptor create to its complete inventory."""

        role = str(key)
        base_role = {
            "instance-snapshot-replay": "instance-snapshot",
            "restore-instance-replay": "restore-instance",
            "restore-block-replay": "restore-block",
            "restore-database-replay": "restore-database",
        }.get(role, role)
        request = intent.get("request")
        if not isinstance(request, dict):
            raise HarnessError("Pending Vultr intent lacks its immutable request parameters.")
        specs = {
            "source-instance": ("instance", "/instances", "instances", "instance"),
            "restore-instance": ("instance", "/instances", "instances", "instance"),
            "source-block": ("block", "/blocks", "blocks", "block"),
            "restore-block": ("block", "/blocks", "blocks", "block"),
            "instance-snapshot": ("snapshot", "/snapshots", "snapshots", "snapshot"),
            "block-snapshot": (
                "block_snapshot",
                "/blocks/snapshots",
                "snapshots",
                "snapshot",
            ),
            "object-storage": (
                "object_storage",
                "/object-storage",
                "object_storages",
                "object_storage",
            ),
            "source-database": ("database", "/databases", "databases", "database"),
            "restore-database": ("database", "/databases", "databases", "database"),
        }
        if base_role not in specs:
            return None
        kind, path, item_key, response_key = specs[base_role]
        return kind, path, item_key, response_key, request

    def _pending_provider_ownership(
        self,
        role: str,
        intent: dict[str, Any],
        item: dict[str, Any],
    ) -> dict[str, Any]:
        request = intent["request"]
        marker = str(intent.get("marker") or "")
        if role == "source-instance":
            return {
                "label": marker,
                "hostname": str(request.get("hostname") or ""),
                "tags": list(request.get("tags") or []),
                "region": str(request.get("region") or ""),
                "plan": str(request.get("plan") or ""),
                "os_id": request.get("os_id"),
            }
        if role == "restore-instance":
            return {
                "tags": [marker],
                "restore_marker": marker,
                "snapshot_id": str(request.get("snapshot_id") or ""),
                "region": str(request.get("region") or ""),
                "plan": str(request.get("plan") or ""),
                "os_id": request.get("os_id"),
            }
        if role == "source-block":
            return {
                "label": marker,
                "region": str(request.get("region") or ""),
                "size_gb": request.get("size_gb"),
            }
        if role == "restore-block":
            return {
                "label": marker,
                "restore_marker": marker,
                "snapshot_id": str(request.get("snapshot_id") or ""),
                "region": str(request.get("region") or ""),
                "size_gb": request.get("size_gb"),
            }
        if role == "instance-snapshot":
            return {
                "description": marker,
                "instance_id": str(request.get("source_instance_id") or ""),
            }
        if role == "block-snapshot":
            return {
                "description": marker,
                "block_id": str(request.get("source_block_id") or ""),
            }
        if role == "object-storage":
            return {
                "label": marker,
                "region": str(request.get("region") or ""),
                "cluster_id": request.get("cluster_id"),
                "tier_id": request.get("tier_id"),
            }
        if role == "source-database":
            return {
                "label": marker,
                "region": str(request.get("region") or ""),
                "plan": str(request.get("plan") or ""),
                "database_engine": str(request.get("database_engine") or ""),
                "database_engine_version": str(request.get("database_engine_version") or ""),
            }
        if role == "restore-database":
            return {
                "label": marker,
                "restore_marker": marker,
                "source_id": str(request.get("source_database_id") or ""),
                "region": str(request.get("region") or ""),
                "plan": str(request.get("plan") or ""),
                "database_engine": str(request.get("database_engine") or ""),
                "database_engine_version": str(request.get("database_engine_version") or ""),
            }
        return {}

    def _reconcile_pending_provider_intent(
        self,
        key: str,
        intent: dict[str, Any],
    ) -> str:
        spec = self._pending_provider_spec(key, intent)
        if spec is None:
            return "unresolved"
        kind, path, item_key, response_key, request = spec
        role = {
            "instance-snapshot-replay": "instance-snapshot",
            "restore-instance-replay": "restore-instance",
            "restore-block-replay": "restore-block",
            "restore-database-replay": "restore-database",
        }.get(key, key)
        if key.endswith("-replay"):
            entry = self._ledger_role_entry(kind, role, allow_manual_review=True)
            if not entry:
                return "unresolved"
            if str((entry.get("ownership") or {}).get("request_fingerprint") or "") != _request_fingerprint(request):
                return "unresolved"
            resource = self._read_detail(
                f"{path}/{entry['resource_id']}", response_key
            )
            if resource is None or not self._resource_matches_entry(resource, entry):
                return "unresolved"
            self.intents.clear(key)
            return "adopted"

        inventory = self.collection(path, item_key)
        candidates = [
            item
            for item in inventory
            if self._has_exact_marker(item, str(intent.get("marker") or ""))
        ]
        if len(candidates) > 1:
            return "unresolved"
        if not candidates:
            # A complete inventory is only a point-in-time observation. Vultr
            # may have accepted the request while the resource is not yet
            # visible. Keep the durable intent and stop cleanup/retry until a
            # later reconciliation can prove the exact resource identity.
            return "unresolved"
        candidate = candidates[0]
        provider_id = self._resource_id(candidate)
        if not provider_id:
            return "unresolved"
        resource = self._read_detail(f"{path}/{provider_id}", response_key)
        if resource is None:
            return "unresolved"
        expected_ownership = self._pending_provider_ownership(role, intent, resource)
        expected = {
            "resource_id": provider_id,
            "ownership": {
                "run_id": self.prefix,
                "role": role,
                "request_fingerprint": _request_fingerprint(request),
                **expected_ownership,
            },
        }
        if not self._resource_matches_entry(resource, expected):
            return "unresolved"
        self._remember_resource(
            kind=kind,
            role=role,
            provider_id=provider_id,
            name=str(intent.get("marker") or provider_id),
            ownership=expected_ownership,
            request=request,
            source_witness=str(
                request.get("source_instance_id")
                or request.get("source_block_id")
                or request.get("source_database_id")
                or request.get("snapshot_id")
                or ""
            ),
            cache_key={
                "instance": "instances",
                "block": "blocks",
                "snapshot": "snapshots",
                "block_snapshot": "block_snapshots",
                "object_storage": "object_storages",
                "database": "databases",
            }[kind],
            operation_key=key,
        )
        return "adopted"

    def _reconcile_pending_object_intent(
        self,
        client,
        key: str,
        intent: dict[str, Any],
    ) -> str:
        request = intent.get("request")
        if not isinstance(request, dict):
            return "unresolved"
        if key in {"object-bucket", "object-bucket-marker"}:
            bucket = str(request.get("bucket") or (intent.get("marker") if key == "object-bucket" else ""))
            if not bucket:
                return "unresolved"
            try:
                names = {
                    str(item.get("Name") or "")
                    for item in (client.list_buckets().get("Buckets") or [])
                    if isinstance(item, dict) and item.get("Name")
                }
            except Exception:
                return "unresolved"
            if bucket not in names:
                # Bucket listing is eventually consistent. Empty visibility is
                # not a definitive pre-acceptance rejection and must never
                # discard either the bucket or marker intent.
                return "unresolved"
            marker_intent = self.intents.get("object-bucket-marker")
            bucket_intent = self.intents.get("object-bucket")
            if not marker_intent or not bucket_intent:
                return "unresolved"
            try:
                self._ensure_object_bucket(client, bucket)
            except Exception:
                return "unresolved"
            return "adopted"
        if key not in {"object-key", "object-key-replay"}:
            return "unresolved"
        bucket = str(request.get("bucket") or "")
        object_key = str(request.get("key") or intent.get("marker") or "")
        if not bucket or not object_key:
            return "unresolved"
        if key == "object-key-replay":
            # This synthetic intent models a crash after a prior exact object
            # was already ledgered but before the replay worker acknowledged
            # completion. Reconcile from the durable version/ETag witness; it
            # must never be left as an unknown intent merely because its key
            # differs from the primary upload role.
            entry = self._ledger_role_entry("object_key", "object-key")
            if not entry:
                return "unresolved"
            ownership = entry.get("ownership") or {}
            if (
                str(ownership.get("request_fingerprint") or "")
                != _request_fingerprint(request)
                or str(ownership.get("bucket") or "") != bucket
                or str(ownership.get("key") or "") != object_key
                or str(ownership.get("sha256") or "")
                != str(request.get("sha256") or "")
                or int(ownership.get("size_bytes") or -1)
                != int(request.get("size_bytes") or -1)
            ):
                return "unresolved"
            try:
                self._verify_object_marker(client, bucket)
                verified_key, verified_version, _body = self._verify_ledgered_object(
                    client, bucket, entry
                )
            except Exception:
                return "unresolved"
            if (
                verified_key != object_key
                or verified_version
                != self._normalise_object_version(ownership.get("version_id"))
            ):
                return "unresolved"
            self.intents.clear(key)
            return "adopted"
        try:
            self._verify_object_marker(client, bucket)
            exact = self._find_exact_object_versions(
                client,
                bucket=bucket,
                key=object_key,
                sha256=str(request.get("sha256") or ""),
                size_bytes=int(request.get("size_bytes") or -1),
            )
        except Exception:
            return "unresolved"
        if len(exact) > 1:
            return "unresolved"
        if not exact:
            # A complete object/version inventory can lag a successful PUT.
            # Preserve the intent and cleanup authority until the exact
            # version can be verified.
            return "unresolved"
        identity = exact[0]
        self._remember_resource(
            kind="object_key",
            role="object-key",
            provider_id=f"{bucket}/{object_key}",
            name=object_key,
            ownership={
                "bucket": bucket,
                "key": object_key,
                "etag": str(identity.get("etag") or ""),
                "version_id": self._normalise_object_version(identity.get("version_id")),
                "sha256": str(request.get("sha256") or ""),
                "size_bytes": int(request.get("size_bytes") or -1),
            },
            source_witness=bucket,
            cache_key="object_keys",
            operation_key=key,
            request=request,
        )
        return "adopted"

    def _delete_request_for_entry(
        self,
        entry: dict[str, Any],
        *,
        path: str = "",
    ) -> dict[str, Any]:
        kind = str(entry.get("kind") or "")
        provider_id = str(entry.get("resource_id") or "")
        ownership = entry.get("ownership") or {}
        if kind == "object_key":
            return {
                "provider": "vultr_object_storage",
                "operation": "delete",
                "kind": kind,
                "bucket": str(ownership.get("bucket") or ""),
                "key": str(ownership.get("key") or ""),
                "version_id": self._normalise_object_version(ownership.get("version_id")),
                "sha256": str(ownership.get("sha256") or ""),
                "size_bytes": int(ownership.get("size_bytes") or -1),
            }
        return {
            "provider": "vultr",
            "operation": "delete",
            "kind": kind,
            "resource_id": provider_id,
            "path": path,
        }

    def _reconcile_pending_delete_intent(
        self,
        client,
        key: str,
        intent: dict[str, Any],
    ) -> str:
        parts = str(key).split(":", 2)
        if len(parts) != 3 or parts[0] != "cleanup":
            return "unresolved"
        kind, provider_id = parts[1], parts[2]
        entry = self.ledger.get(kind, provider_id)
        if not entry:
            return "unresolved"
        if kind == "object_key":
            expected_request = self._delete_request_for_entry(entry)
        else:
            path_template, response_key = {
                "snapshot": ("/snapshots/{resource_id}", "snapshot"),
                "block_snapshot": ("/blocks/snapshots/{resource_id}", "snapshot"),
                "instance": ("/instances/{resource_id}", "instance"),
                "block": ("/blocks/{resource_id}", "block"),
                "database": ("/databases/{resource_id}", "database"),
                "object_storage": ("/object-storage/{resource_id}", "object_storage"),
                "object_bucket": ("", ""),
            }.get(kind, ("", ""))
            expected_request = self._delete_request_for_entry(
                entry,
                path=path_template.format(resource_id=provider_id)
                if path_template
                else "",
            )
        request = intent.get("request")
        if request != expected_request or str(intent.get("fingerprint") or "") != _request_fingerprint(expected_request):
            return "unresolved"

        if kind == "object_key":
            if client is None:
                return "unresolved"
            bucket = expected_request["bucket"]
            try:
                self._verify_ledgered_object(client, bucket, entry)
            except Exception as error:
                if self._s3_not_found(error):
                    self.intents.clear(key)
                    self.ledger.mark_cleanup(kind, provider_id, state="absent")
                    return "cleaned"
                self.ledger.mark_cleanup(
                    kind,
                    provider_id,
                    state="manual_review",
                    error="pending object delete ownership could not be verified",
                )
                return "unresolved"
            kwargs: dict[str, Any] = {
                "Bucket": bucket,
                "Key": expected_request["key"],
            }
            if expected_request["version_id"]:
                kwargs["VersionId"] = expected_request["version_id"]
            try:
                client.delete_object(**kwargs)
            except Exception as error:
                if not self._s3_not_found(error):
                    self.ledger.mark_cleanup(
                        kind,
                        provider_id,
                        state="manual_review",
                        error="pending object delete remains retryable after a provider failure",
                    )
                    return "unresolved"
            try:
                self._wait_for_object_absence(
                    client,
                    bucket,
                    expected_request["key"],
                    expected_request["version_id"],
                )
            except Exception:
                self.ledger.mark_cleanup(
                    kind,
                    provider_id,
                    state="manual_review",
                    error="pending object delete remains visible or retryable",
                )
                return "unresolved"
            self.intents.clear(key)
            self.ledger.mark_cleanup(kind, provider_id, state="deleted")
            return "cleaned"

        if kind == "object_bucket":
            if client is None:
                return "unresolved"
            bucket = provider_id
            try:
                client.head_bucket(Bucket=bucket)
            except Exception as error:
                if self._s3_not_found(error):
                    self.intents.clear(key)
                    self.ledger.mark_cleanup(kind, provider_id, state="absent")
                    return "cleaned"
                self.ledger.mark_cleanup(
                    kind,
                    provider_id,
                    state="manual_review",
                    error="pending bucket delete remains retryable after a provider failure",
                )
                return "unresolved"
            try:
                client.delete_bucket(Bucket=bucket)
            except Exception as error:
                if not self._s3_not_found(error):
                    self.ledger.mark_cleanup(
                        kind,
                        provider_id,
                        state="manual_review",
                        error="pending bucket delete remains retryable after a provider failure",
                    )
                    return "unresolved"
            try:
                self._wait_for_object_bucket_absence(client, bucket)
            except Exception:
                self.ledger.mark_cleanup(
                    kind,
                    provider_id,
                    state="manual_review",
                    error="pending bucket delete remains visible or retryable",
                )
                return "unresolved"
            self.intents.clear(key)
            self.ledger.mark_cleanup(kind, provider_id, state="deleted")
            return "cleaned"

        path_template, response_key = {
            "snapshot": ("/snapshots/{resource_id}", "snapshot"),
            "block_snapshot": ("/blocks/snapshots/{resource_id}", "snapshot"),
            "instance": ("/instances/{resource_id}", "instance"),
            "block": ("/blocks/{resource_id}", "block"),
            "database": ("/databases/{resource_id}", "database"),
            "object_storage": ("/object-storage/{resource_id}", "object_storage"),
        }.get(kind, ("", ""))
        if not path_template:
            return "unresolved"
        path = path_template.format(resource_id=provider_id)
        try:
            resource = self._read_cleanup_resource(entry, path, response_key)
            if resource is None:
                self.intents.clear(key)
                self.ledger.mark_cleanup(kind, provider_id, state="absent")
                return "cleaned"
            if not self._resource_matches_entry(resource, entry):
                self.ledger.mark_cleanup(
                    kind,
                    provider_id,
                    state="manual_review",
                    error="pending provider delete ownership verification failed",
                )
                return "unresolved"
            try:
                self.request("DELETE", path, expected=(204,))
            except ProviderNotFound:
                # The provider may have accepted the delete before returning
                # 404. Verify absence instead of treating the response alone
                # as completion.
                pass
            self._wait_for_provider_absence(path, response_key, entry)
        except Exception:
            self.ledger.mark_cleanup(
                kind,
                provider_id,
                state="manual_review",
                error="pending provider delete remains retryable after a provider failure",
            )
            return "unresolved"
        self.intents.clear(key)
        self.ledger.mark_cleanup(kind, provider_id, state="deleted")
        return "cleaned"

    def _reconcile_pending_intents(self, object_client, errors: list[str]) -> bool:
        """Resolve every intent before any ordinary cleanup delete is allowed."""

        pending = self.intents.pending()
        summaries = [
            self._pending_summary(key, value, state="pending")
            for key, value in sorted(pending.items())
        ]
        self.report["cleanup"]["pending_intents"] = summaries
        unresolved: list[dict[str, Any]] = []
        # Provider resources first: a successfully adopted object-storage
        # subscription can then authorize the S3 bucket/key inventory pass.
        provider_items = [
            (key, value)
            for key, value in sorted(pending.items())
            if not str(value.get("operation") or "").startswith("cleanup")
            and self._pending_provider_spec(key, value) is not None
        ]
        for key, intent in provider_items:
            try:
                state = self._reconcile_pending_provider_intent(key, intent)
            except Exception:
                state = "unresolved"
            if state == "unresolved":
                unresolved.append(self._pending_summary(key, intent, state=state))

        object_pending = [
            (key, value)
            for key, value in sorted(self.intents.pending().items())
            if not str(value.get("operation") or "").startswith("cleanup")
            and key
            in {
                "object-bucket",
                "object-bucket-marker",
                "object-key",
                "object-key-replay",
            }
        ]
        object_client = object_client
        for key, intent in object_pending:
            try:
                if object_client is None:
                    object_client = self._object_client_for_cleanup()
                state = self._reconcile_pending_object_intent(object_client, key, intent)
            except Exception:
                state = "unresolved"
            if state == "unresolved":
                unresolved.append(self._pending_summary(key, intent, state=state))

        for key, intent in sorted(self.intents.pending().items()):
            if str(intent.get("operation") or "").startswith("cleanup"):
                try:
                    if object_client is None and key.startswith("cleanup:object_"):
                        object_client = self._object_client_for_cleanup()
                    state = self._reconcile_pending_delete_intent(
                        object_client, key, intent
                    )
                except Exception:
                    state = "unresolved"
                if state == "unresolved":
                    unresolved.append(self._pending_summary(key, intent, state=state))

        # Any key not understood by the harness is deliberately unresolved. It
        # is never silently discarded during an upgrade.
        for key, intent in self.intents.pending().items():
            if not any(item["key"] == key for item in unresolved):
                unresolved.append(self._pending_summary(key, intent, state="unresolved"))
        self.report["cleanup"]["unresolved_intents"] = unresolved
        if unresolved:
            errors.append("pending Vultr mutation intents require manual review")
            return False
        return True

    def _cleanup_object_bucket(
        self,
        client,
        entry: dict[str, Any],
        errors: list[str],
    ) -> None:
        kind = "object_bucket"
        provider_id = str(entry.get("resource_id") or "")
        ownership = entry.get("ownership") or {}
        bucket = str(ownership.get("bucket") or "")
        marker_key = str(ownership.get("marker_key") or "")
        marker_body = self._object_marker_body(self.prefix)
        marker_hash = hashlib.sha256(marker_body).hexdigest()
        if (
            provider_id != bucket
            or ownership.get("run_id") != self.prefix
            or ownership.get("role") != "object-bucket"
            or not marker_key
            or str(ownership.get("marker_sha256") or "") != marker_hash
        ):
            message = f"refused bucket cleanup for {provider_id}: malformed ownership proof"
            self.ledger.mark_cleanup(kind, provider_id, state="manual_review", error=message)
            errors.append(message)
            return
        try:
            try:
                client.head_bucket(Bucket=bucket)
            except Exception as error:
                if self._s3_not_found(error):
                    self.ledger.mark_cleanup(kind, provider_id, state="absent")
                    for item in self.ledger.entries("object_key"):
                        if (
                            item.get("cleanup_state") in {"eligible", "failed"}
                            and (item.get("ownership") or {}).get("bucket") == bucket
                        ):
                            self.ledger.mark_cleanup(
                                "object_key", str(item.get("resource_id") or ""), state="absent"
                            )
                    return
                raise

            object_entries = [
                item
                for item in self.ledger.entries("object_key")
                if (item.get("ownership") or {}).get("bucket") == bucket
                and item.get("cleanup_state") in {"eligible", "failed"}
            ]
            marker_entries = [
                item
                for item in object_entries
                if (item.get("ownership") or {}).get("role") == "object-bucket-marker"
                and (item.get("ownership") or {}).get("key") == marker_key
            ]
            if len(marker_entries) != 1:
                raise HarnessError("ownership marker has no unique durable ledger entry")
            if len(object_entries) != len(
                {
                    str((item.get("ownership") or {}).get("key") or "")
                    for item in object_entries
                }
            ):
                raise HarnessError("durable object ledger contains duplicate keys")

            expected_versions: set[tuple[str, str]] = set()
            expected_keys: set[str] = set()
            marker_observed = False
            for object_entry in object_entries:
                key, version_id, body = self._verify_ledgered_object(
                    client, bucket, object_entry
                )
                expected_keys.add(key)
                expected_versions.add((key, version_id))
                if object_entry is marker_entries[0]:
                    marker_observed = body == marker_body
            if not marker_observed:
                raise HarnessError("ownership marker is missing or changed")

            listed = self._bounded_object_inventory(client, bucket)
            versions, delete_markers = self._bounded_object_version_inventory(
                client, bucket
            )
            observed_keys = {str(item.get("Key") or "") for item in listed}
            observed_versions = {
                (
                    str(item.get("Key") or ""),
                    self._normalise_object_version(item.get("VersionId")),
                )
                for item in versions
            }
            if (
                observed_keys != expected_keys
                or observed_versions != expected_versions
                or delete_markers
            ):
                raise HarnessError(
                    "unknown resources or versions exist in the bucket; cleanup deleted nothing"
                )

            # All reads and comparisons complete while the exact ownership
            # marker still exists. Delete data first, then the marker last.
            marker_entry = marker_entries[0]
            non_marker_entries = sorted(
                (item for item in object_entries if item is not marker_entry),
                key=lambda item: str((item.get("ownership") or {}).get("key") or ""),
            )
            for object_entry in non_marker_entries:
                self._delete_ledgered_object(client, bucket, object_entry)
            self._delete_ledgered_object(client, bucket, marker_entry)

            remaining_objects = self._bounded_object_inventory(client, bucket)
            remaining_versions, remaining_delete_markers = (
                self._bounded_object_version_inventory(client, bucket)
            )
            if remaining_objects or remaining_versions or remaining_delete_markers:
                raise HarnessError(
                    "Object Storage bucket changed during cleanup; bucket deletion was refused."
                )
            cleanup_key = f"cleanup:object_bucket:{provider_id}"
            self._prepare_cleanup_intent(
                cleanup_key,
                provider_id,
                "Object Storage bucket delete",
                self._delete_request_for_entry(entry),
                kind="object_bucket",
            )
            try:
                client.delete_bucket(Bucket=bucket)
            except Exception as error:
                if not self._s3_not_found(error):
                    raise
            self._wait_for_object_bucket_absence(client, bucket)
            self.intents.clear(cleanup_key)
            self.ledger.mark_cleanup(kind, provider_id, state="deleted")
        except Exception as error:
            message = f"refused bucket cleanup for {provider_id}: {self._safe_error(error)}"
            self.ledger.mark_cleanup(kind, provider_id, state="manual_review", error=message)
            errors.append(message)

    def _cleanup_provider_entry(
        self,
        entry: dict[str, Any],
        *,
        path_template: str,
        response_key: str,
        errors: list[str],
    ) -> None:
        kind = str(entry.get("kind") or "")
        provider_id = str(entry.get("resource_id") or "")
        if not provider_id or not self.ledger.cleanup_eligible(kind, provider_id):
            return
        path = path_template.format(resource_id=provider_id)
        try:
            resource = self._read_cleanup_resource(entry, path, response_key)
            if resource is None:
                self.ledger.mark_cleanup(kind, provider_id, state="absent")
                return
            if not self._resource_matches_entry(resource, entry):
                message = f"refused {kind} cleanup for {provider_id}: exact ownership proof failed"
                self.ledger.mark_cleanup(kind, provider_id, state="manual_review", error=message)
                errors.append(message)
                return
            cleanup_key = f"cleanup:{kind}:{provider_id}"
            self._prepare_cleanup_intent(
                cleanup_key,
                provider_id,
                f"{kind} delete",
                self._delete_request_for_entry(
                    entry,
                    path=path,
                ),
                kind=kind,
            )
            try:
                self.request("DELETE", path, expected=(204,))
            except ProviderNotFound:
                # Verify the exact detail below even when the DELETE response
                # itself is a 404; the request may have been accepted before
                # the provider returned its response.
                pass
            self._wait_for_provider_absence(path, response_key, entry)
            self.intents.clear(cleanup_key)
            self.ledger.mark_cleanup(kind, provider_id, state="deleted")
        except ProviderNotFound:
            self.intents.clear(f"cleanup:{kind}:{provider_id}")
            self.ledger.mark_cleanup(kind, provider_id, state="absent")
        except Exception as error:
            message = f"delete {kind} {provider_id}: {self._safe_error(error)}"
            self.ledger.mark_cleanup(kind, provider_id, state="failed", error=message)
            errors.append(message)

    def cleanup(self) -> None:
        errors: list[str] = []
        self._assert_cleanup_gate()
        if not self.cleanup_requested:
            self.report["cleanup"] = {
                "status": "NOT_REQUESTED",
                "errors": [],
                "provider_resources_considered": [],
            }
            return

        self.report["cleanup"].setdefault("pending_intents", [])
        self.report["cleanup"].setdefault("unresolved_intents", [])
        if not self._reconcile_pending_intents(None, errors):
            remaining = [
                {
                    "kind": entry.get("kind"),
                    "resource_id": entry.get("resource_id"),
                    "cleanup_state": entry.get("cleanup_state"),
                }
                for entry in self.ledger.entries()
                if entry.get("cleanup_state") in {"eligible", "failed", "manual_review"}
            ]
            self.report["cleanup"]["remaining"] = remaining
            self.report["cleanup"]["local_graph_retained"] = bool(
                self.account is not None
            )
            self.report["cleanup"]["errors"] = errors
            self.report["cleanup"]["status"] = "FAIL"
            return

        all_entries = [
            entry
            for entry in self.ledger.entries()
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        object_entries = [entry for entry in all_entries if entry.get("kind") == "object_key"]
        bucket_entries = [entry for entry in all_entries if entry.get("kind") == "object_bucket"]
        object_client = None
        if object_entries or bucket_entries:
            try:
                object_client = self._object_client_for_cleanup()
                if object_client is None:
                    raise HarnessError("No ledgered Vultr Object Storage client is available.")
                if object_entries and not bucket_entries:
                    raise HarnessError(
                        "Ledgered Vultr Object Storage keys have no exact bucket authority."
                    )
                for entry in reversed(bucket_entries):
                    self._cleanup_object_bucket(object_client, entry, errors)
            except Exception as error:
                errors.append(f"Vultr Object Storage cleanup unavailable: {self._safe_error(error)}")

        # Dependencies leave in this order. Every entry comes from the durable
        # ledger; no provider inventory item is ever used as delete authority.
        cleanup_specs = (
            ("snapshot", "/snapshots/{resource_id}", "snapshot"),
            ("block_snapshot", "/blocks/snapshots/{resource_id}", "snapshot"),
            ("instance", "/instances/{resource_id}", "instance"),
            ("block", "/blocks/{resource_id}", "block"),
            ("database", "/databases/{resource_id}", "database"),
            ("object_storage", "/object-storage/{resource_id}", "object_storage"),
        )
        role_order = {
            "restore-database": 0,
            "source-database": 1,
            "restore-block": 0,
            "source-block": 1,
            "restore-instance": 0,
            "source-instance": 1,
            "instance-snapshot": 0,
            "block-snapshot": 0,
            "object-storage": 0,
        }
        for kind, path_template, response_key in cleanup_specs:
            entries = [
                entry
                for entry in self.ledger.entries(kind)
                if entry.get("cleanup_state") in {"eligible", "failed"}
            ]
            entries.sort(key=lambda entry: role_order.get(
                (entry.get("ownership") or {}).get("role"), 99
            ))
            for entry in entries:
                # A bucket must be gone before its subscription; unknown bucket
                # contents deliberately keep the subscription for manual review.
                if kind == "object_storage" and any(
                    bucket.get("cleanup_state") in {"eligible", "failed", "manual_review"}
                    for bucket in self.ledger.entries("object_bucket")
                ):
                    errors.append(
                        f"skipped object storage {entry.get('resource_id')}: "
                        "bucket cleanup is not confirmed"
                    )
                    continue
                self._cleanup_provider_entry(
                    entry,
                    path_template=path_template,
                    response_key=response_key,
                    errors=errors,
                )

        remaining = [
            {
                "kind": entry.get("kind"),
                "resource_id": entry.get("resource_id"),
                "cleanup_state": entry.get("cleanup_state"),
            }
            for entry in self.ledger.entries()
            if entry.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        self.report["cleanup"]["remaining"] = remaining
        if remaining:
            errors.append(f"durable Vultr resources remain for cleanup review: {remaining}")

        if self.account is not None and not errors and not remaining:
            try:
                account_id = self.account.id
                self.account.delete()
                self.member.delete()
                self.user.delete()
                self.report["cleanup"]["local_account_id"] = account_id
            except Exception as error:
                errors.append(f"local BackupSheep records: {self._safe_error(error)}")
        elif self.account is not None:
            self.report["cleanup"]["local_graph_retained"] = True
        self.report["cleanup"]["errors"] = errors
        self.report["cleanup"]["status"] = "PASS" if not errors else "FAIL"

    def render_report(self) -> str:
        self.report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        lines = [
            "# Vultr live E2E test report",
            "",
            f"- Run: `{self.report['run_id']}`",
            f"- Mode: `{self.report['execution_mode']}`",
            f"- Started: `{self.report.get('started_at')}`",
            f"- Finished: `{self.report.get('finished_at')}`",
            f"- API endpoint: `{self.api_base}`",
            "- Credentials: supplied through `VULTR_API_KEY`; not recorded.",
            "",
            "## Safety and baseline",
            "",
            "Only resources created by this run were eligible for cleanup. Provider snapshots and managed-database backup metadata were deleted only after exact ownership checks; provider-managed database backups were never deleted.",
            "",
            "```json",
            json.dumps({"baseline": self.report.get("baseline"), "account": self.report.get("account")}, indent=2, sort_keys=True),
            "```",
            "",
            "## Live acceptance matrix",
            "",
            "| ID | Result | Evidence |",
            "|---|---|---|",
        ]
        for test_id, result in self.report.get("tests", {}).items():
            lines.append(
                f"| {test_id} | **{result.get('status')}** | `{json.dumps(result, sort_keys=True).replace('|', '\\u007c')}` |"
            )
        lines.extend(
            [
                "",
                "## Resource ledger",
                "",
                "| Service | Class | Provider ID | Ownership proof | Cleanup allowed |",
                "|---|---|---|---|---|",
            ]
        )
        for item in self.report.get("ledger", []):
            lines.append(
                f"| {item.get('provider_service')} | {item.get('resource_class')} | `{item.get('provider_id')}` | `{json.dumps(item.get('ownership_proof', {}), sort_keys=True)}` | {item.get('cleanup_allowed')} |"
            )
        lines.extend(
            [
                "",
                "## Cleanup",
                "",
                "```json",
                json.dumps(self.report.get("cleanup"), indent=2, sort_keys=True),
                "```",
                "",
                "## Limitations",
                "",
            ]
        )
        lines.extend(f"- {item}" for item in self.report.get("limitations", []))
        return "\n".join(lines) + "\n"

    def run(self) -> int:
        try:
            if self.cleanup_requested:
                self.report["mode"] = "cleanup_only"
            else:
                self.baseline()
                self.setup_local()
                self.create_sources()
                self.snapshot_and_restore()
                self.create_object_storage_and_test()
                self.create_managed_database_and_test()
            self.report["result"] = "PASS"
        except Exception as error:
            self.report["result"] = "FAIL"
            self.report["error"] = self._safe_error(error)
        finally:
            self.cleanup()
            if (
                self.cleanup_requested
                and self.report["cleanup"].get("status") != "PASS"
            ):
                self.report["result"] = "FAIL"
            report = self.render_report()
            if self.report_path:
                self.report_path.parent.mkdir(parents=True, exist_ok=True)
                self.report_path.write_text(report, encoding="utf-8")
            print(json.dumps(self.report, indent=2, sort_keys=True, default=str))
        return 0 if (
            self.report.get("result") == "PASS"
            and self.report["cleanup"]["status"] in {"PASS", "NOT_REQUESTED"}
        ) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="Write a sanitized Markdown report to this path")
    args = parser.parse_args()
    return LiveVultrHarness(report_path=args.report).run()


if __name__ == "__main__":
    raise SystemExit(main())
