#!/usr/bin/env python3
"""Safety-gated UpCloud live UI E2E support harness.

The default ``plan`` command is deliberately offline. Compute, Block Storage,
and Managed Object Storage creation require ``BACKUPSHEEP_E2E_APPLY=YES``;
cleanup additionally requires ``BACKUPSHEEP_E2E_CLEANUP=YES``. Every provider
mutation is preceded by a durable intent, and cleanup addresses only exact IDs
whose ownership was persisted in the run ledger after provider read-back.

The UpCloud API token is accepted only through ``UPCLOUD_API_TOKEN``. Managed
Object Storage access credentials are written atomically to one ignored mode
0600 runtime file and are never written to the ownership ledger or stdout.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import io
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
import time
import tarfile
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote

import requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


API_BASE = "https://api.upcloud.com/1.3"
REQUEST_TIMEOUT = (10.0, 60.0)
MAX_PAGES = 100
MAX_ITEMS = 10_000
COMPUTE_PAGE_LIMIT = 100
COMPUTE_MAX_WAIT_POLLS = 120
COMPUTE_POLL_SECONDS = 5
SSH_MAX_WAIT_POLLS = 60
SSH_POLL_SECONDS = 5
FIREWALL_RULE_LIMIT = 1000
FIREWALL_MAX_WAIT_POLLS = 24
FIREWALL_POLL_SECONDS = 5
FIREWALL_STABILIZATION_SECONDS = 120
FIREWALL_ALLOWED_PORTS = (22, 80, 5432)
FIREWALL_LEDGER_KIND = "compute_source_firewall_rule"
FIREWALL_RULE_FIELDS = (
    "direction",
    "family",
    "protocol",
    "source_address_start",
    "source_address_end",
    "source_port_start",
    "source_port_end",
    "destination_address_start",
    "destination_address_end",
    "destination_port_start",
    "destination_port_end",
    "icmp_type",
    "action",
    "comment",
)
RUNTIME_DIR = ROOT / "scripts" / ".upcloud-runtime"
RUNTIME_SCHEMA = "backupsheep-upcloud-mos-runtime-v1"
COMPUTE_RUNTIME_SCHEMA = "backupsheep-upcloud-compute-runtime-v1"
RUNTIME_FIELDS = {
    "schema",
    "provider",
    "run_id",
    "account",
    "service_uuid",
    "region",
    "endpoint",
    "bucket_name",
    "prefix",
    "username",
    "policy_name",
    "access_key",
    "secret_key",
}
COMPUTE_RUNTIME_FIELDS = {
    "schema",
    "provider",
    "run_id",
    "account",
    "server_uuid",
    "ssh_user",
    "website_root",
    "database_host",
    "database_port",
    "database_name",
    "database_user",
    "database_password",
}
ACTIVE_LEDGER_STATES = {"eligible", "failed"}
TERMINAL_LEDGER_STATES = {"deleted", "absent"}
SERVICE_TRANSITIONAL_STATES = {
    "pending",
    "setup",
    "setup-service",
    "setup-network",
    "setup-tls",
    "setup-public-endpoint",
    "setup-private-endpoint",
    "setup-dns",
    "setup-iam",
    "setup-checkup",
    "cleanup-deleted-buckets",
    "starting",
    "maintenance",
}
SERVICE_FAILED_STATES = {"error", "failed", "stopped", "terminated"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UPCLOUD_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SAFE_MARKER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
UI_OBJECT_KINDS = {
    "website": "mos_ui_website_object",
    "database": "mos_ui_database_object",
}
UI_OBJECT_MANIFEST_SCHEMA = 1
MANIFEST_MAX_BYTES = 64 * 1024
MANIFEST_TOP_LEVEL_KEYS = {
    "object": frozenset({"schema", "run_id", "objects"}),
    "compute": frozenset({"schema", "run_id", "volume", "server"}),
    "workload": frozenset({"schema", "run_id", "website", "postgresql"}),
}
UPCLOUD_GENERATION_MARKER = ".upcloud-manifest-generation.json"
WORKLOAD_GENERATION_MARKER = ".workload-manifest-ownership.json"
UPCLOUD_GENERATION_FILENAMES = frozenset(
    {
        "upcloud-compute-manifest.json",
        "upcloud-workload-manifest.json",
        "upcloud-object-manifest.json",
        UPCLOUD_GENERATION_MARKER,
    }
)
WORKLOAD_GENERATION_FILENAMES = frozenset(
    {"upcloud-workload-manifest.json", WORKLOAD_GENERATION_MARKER}
)
UPCLOUD_GENERATION_MARKER_KEYS = frozenset(
    {
        "schema",
        "kind",
        "provider",
        "integration_code",
        "run_id",
        "disposition",
        "manifests",
        "storage_id",
        "rows",
        "artifact_bindings",
    }
)
WORKLOAD_GENERATION_MARKER_KEYS = frozenset(
    {
        "schema",
        "kind",
        "run_id",
        "provider_code",
        "integration_code",
        "storage_id",
        "rows",
        "website_restore_correlation_id",
        "database_restore_correlation_id",
        "website_restore_path",
        "database_restore_database",
        "artifact_bindings",
        "manifest",
    }
)
UPCLOUD_GENERATION_ROW_KEYS = frozenset(
    {
        "volume_node_id",
        "volume_backup_id",
        "volume_restore_id",
        "server_node_id",
        "server_backup_id",
        "server_restore_id",
        "website_node_id",
        "website_backup_id",
        "website_restore_id",
        "database_node_id",
        "database_backup_id",
        "database_restore_id",
        "website_storage_point_id",
        "database_storage_point_id",
        "website_artifact_id",
        "database_artifact_id",
    }
)
WORKLOAD_GENERATION_ROW_KEYS = frozenset(
    {
        "website_node_id",
        "website_backup_id",
        "website_restore_id",
        "database_node_id",
        "database_backup_id",
        "database_restore_id",
        "website_storage_point_id",
        "database_storage_point_id",
        "website_artifact_id",
        "database_artifact_id",
    }
)
ARTIFACT_BINDING_KEYS = frozenset(
    {"artifact_id", "byte_count", "sha256", "etag", "version_id", "binding_sha256"}
)
WORKLOAD_STORAGE_CODES = {
    "do_spaces": "digitalocean",
    "upcloud": "upcloud",
    "oracle": "oracle",
}
UI_OBJECT_ROW_KEYS = frozenset(
    {
        "kind",
        "backup_id",
        "backup_uuid",
        "storage_point_id",
        "storage_id",
        "artifact_id",
        "artifact_status",
        "object_key",
        "sha256",
        "byte_count",
        "etag",
        "version_id",
    }
)
COMPUTE_VOLUME_KEYS = frozenset(
    {
        "node_id",
        "backup_id",
        "restore_id",
        "source_resource_id",
        "backup_resource_id",
        "backup_marker",
        "restore_resource_id",
        "restore_marker",
    }
)
COMPUTE_SERVER_KEYS = frozenset(
    {
        "node_id",
        "backup_id",
        "restore_id",
        "source_resource_id",
        "backup_resource_id",
        "backup_marker",
        "restore_storage_id",
        "restore_storage_marker",
        "restore_server_id",
        "restore_server_marker",
        "restore_hostname",
    }
)
WORKLOAD_WEBSITE_KEYS = frozenset(
    {"node_id", "backup_id", "restore_id", "restore_path"}
)
WORKLOAD_DATABASE_KEYS = frozenset(
    {"node_id", "backup_id", "restore_id", "restore_database"}
)
SAFE_BACKUP_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
OBJECT_LEDGER_KINDS = set(UI_OBJECT_KINDS.values()) | {
    "mos_ownership_object",
    "mos_delete_marker",
}
USER_RETAINED_BY_INSTRUCTION = "USER_RETAINED_BY_INSTRUCTION"
MOS_RETENTION_RECEIPT_KIND = "mos_retention_receipt"
MOS_RUNTIME_CREDENTIAL_KIND = "mos_runtime_credential_file"
UPCLOUD_ACCOUNT_TOKEN_KIND = "upcloud_account_api_token"
MOS_RETAINED_PROVIDER_KINDS = frozenset(
    {
        "mos_service",
        "mos_network",
        "mos_user",
        "mos_inline_policy",
        "mos_access_key",
    }
)
MOS_RETAINED_KINDS = MOS_RETAINED_PROVIDER_KINDS | frozenset(
    {MOS_RUNTIME_CREDENTIAL_KIND}
)
MOS_RETENTION_OWNERSHIP_KEYS = frozenset(
    {
        "account",
        "run_id",
        "service_uuid",
        "retained_kind",
        "retained_resource_id",
        "disposition",
    }
)
MOS_DATA_LEDGER_KINDS = frozenset(
    {
        "mos_bucket",
        "mos_bucket_configuration",
        "mos_multipart_upload",
        "mos_ui_object_binding",
        *OBJECT_LEDGER_KINDS,
    }
)


class HarnessError(RuntimeError):
    """Credential-free, bounded harness failure.

    A mutation intent may only be released when the provider has explicitly
    rejected the request.  Keeping that fact as structured metadata avoids
    accidentally treating an SDK parsing error or an unclassified provider
    exception as a safe-to-retry failure.
    """

    def __init__(
        self,
        message,
        *,
        code="",
        definitive_rejection=False,
        mutation_outcome_unknown=False,
    ):
        super().__init__(message)
        self.code = str(code or "")
        self.definitive_rejection = bool(definitive_rejection)
        self.mutation_outcome_unknown = bool(mutation_outcome_unknown)


class AmbiguousMutation(HarnessError):
    """A provider mutation may have succeeded and must be reconciled."""

    def __init__(self, message, *, code="PROVIDER_AMBIGUOUS"):
        super().__init__(
            message,
            code=code,
            mutation_outcome_unknown=True,
        )


class InventoryNotEmpty(HarnessError):
    """Cleanup stopped before touching an unledgered object or upload."""


class SecretUnavailable(HarnessError):
    """A one-time access-key secret cannot be recovered safely."""


class ProviderUnavailable(HarnessError):
    """A read-only provider operation failed transiently."""


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _fingerprint(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _utc_timestamp(value) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise HarnessError("The UpCloud firewall verification timestamp is missing.")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        raise HarnessError("The UpCloud firewall verification timestamp is malformed.") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _normalize_firewall_rule(rule: dict) -> dict:
    """Return only the provider fields that define an UpCloud firewall rule."""
    if not isinstance(rule, dict):
        raise HarnessError("UpCloud returned a malformed firewall rule.")
    normalized = {
        field: str(rule.get(field) or "").strip() for field in FIREWALL_RULE_FIELDS
    }
    for field in ("direction", "family", "protocol", "action"):
        normalized[field] = normalized[field].casefold()
    if len(normalized["comment"]) > 250:
        raise HarnessError("UpCloud returned an overlong firewall rule comment.")
    return normalized


def _etag(value) -> str:
    return str(value or "").strip('"')


def _safe_path(value, *, variable, allow_runtime=False) -> Path:
    if not value:
        raise HarnessError(f"{variable} is required.")
    path = Path(value).expanduser().resolve(strict=False)
    if "_docs" in path.parts:
        raise HarnessError(f"{variable} must not point inside _docs.")
    if allow_runtime:
        try:
            path.relative_to(ROOT)
        except ValueError:
            return path
        try:
            path.relative_to(RUNTIME_DIR.resolve(strict=False))
        except ValueError as error:
            raise HarnessError(
                f"{variable} must be outside the worktree or inside the ignored "
                "scripts/.upcloud-runtime directory."
            ) from error
    return path


def _runtime_path(run_id: str, environment) -> Path:
    configured = str(environment.get("UPCLOUD_E2E_RUNTIME_FILE") or "").strip()
    path = configured or str(RUNTIME_DIR / f"{run_id}.json")
    return _safe_path(
        path, variable="UPCLOUD_E2E_RUNTIME_FILE", allow_runtime=True
    )


def _write_runtime_secret(path: Path, payload: dict) -> None:
    path = _safe_path(
        path, variable="UPCLOUD_E2E_RUNTIME_FILE", allow_runtime=True
    )
    if path.is_symlink():
        raise HarnessError("The UpCloud runtime credential path cannot be a symlink.")
    if set(payload) != RUNTIME_FIELDS or any(
        not isinstance(payload.get(key), str) or not payload.get(key)
        for key in RUNTIME_FIELDS
    ):
        raise HarnessError("The UpCloud runtime credential payload is malformed.")
    if payload["schema"] != RUNTIME_SCHEMA or payload["provider"] != "upcloud":
        raise HarnessError("The UpCloud runtime credential scope is malformed.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(payload, target, sort_keys=True, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_runtime_secret(path: Path) -> dict:
    path = _safe_path(
        path, variable="UPCLOUD_E2E_RUNTIME_FILE", allow_runtime=True
    )
    if path.is_symlink() or not path.is_file():
        raise SecretUnavailable(
            "The protected UpCloud Object Storage runtime credential file is missing."
        )
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise HarnessError(
            "The UpCloud Object Storage runtime credential file must have mode 0600."
        )
    try:
        with open(path, encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, ValueError) as error:
        raise HarnessError(
            "The UpCloud Object Storage runtime credential file is unreadable."
        ) from error
    if (
        not isinstance(payload, dict)
        or set(payload) != RUNTIME_FIELDS
        or any(
            not isinstance(payload.get(key), str) or not payload.get(key)
            for key in RUNTIME_FIELDS
        )
        or payload.get("schema") != RUNTIME_SCHEMA
        or payload.get("provider") != "upcloud"
    ):
        raise HarnessError(
            "The UpCloud Object Storage runtime credential file is malformed."
        )
    return payload


def _remove_compute_runtime_secret(path: Path) -> None:
    path = _safe_path(
        path, variable="UpCloud compute runtime file", allow_runtime=True
    )
    if not path.name.endswith(".upcloud-compute.json"):
        raise HarnessError(
            "Only the separate compute runtime artifact can be removed by cleanup."
        )
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise HarnessError("The UpCloud runtime credential path became unsafe.")
    path.unlink()
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _compute_runtime_path(runtime_path: Path, run_id: str) -> Path:
    path = runtime_path.with_name(f"{run_id}.upcloud-compute.json")
    return _safe_path(
        path, variable="UpCloud compute runtime file", allow_runtime=True
    )


def _write_compute_runtime_secret(path: Path, payload: dict) -> None:
    path = _safe_path(
        path, variable="UpCloud compute runtime file", allow_runtime=True
    )
    if path.is_symlink():
        raise HarnessError("The UpCloud compute runtime path cannot be a symlink.")
    if (
        set(payload) != COMPUTE_RUNTIME_FIELDS
        or payload.get("schema") != COMPUTE_RUNTIME_SCHEMA
        or payload.get("provider") != "upcloud"
        or any(
            not isinstance(payload.get(field), str) or not payload.get(field)
            for field in COMPUTE_RUNTIME_FIELDS
        )
    ):
        raise HarnessError("The UpCloud compute runtime payload is malformed.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(payload, target, sort_keys=True, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_compute_runtime_secret(path: Path) -> dict:
    path = _safe_path(
        path, variable="UpCloud compute runtime file", allow_runtime=True
    )
    if path.is_symlink() or not path.is_file():
        raise SecretUnavailable(
            "The protected UpCloud compute runtime credential file is missing."
        )
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise HarnessError("The UpCloud compute runtime file must have mode 0600.")
    try:
        with open(path, encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, ValueError):
        raise HarnessError("The UpCloud compute runtime file is unreadable.") from None
    if (
        not isinstance(payload, dict)
        or set(payload) != COMPUTE_RUNTIME_FIELDS
        or payload.get("schema") != COMPUTE_RUNTIME_SCHEMA
        or payload.get("provider") != "upcloud"
        or any(
            not isinstance(payload.get(field), str) or not payload.get(field)
            for field in COMPUTE_RUNTIME_FIELDS
        )
    ):
        raise HarnessError("The UpCloud compute runtime file is malformed.")
    return payload


def _safe_name(run_id: str, suffix: str, *, maximum: int = 64) -> str:
    base = re.sub(r"[^a-z0-9-]", "-", run_id.casefold()).strip("-")
    digest = _hash(f"{run_id}:{suffix}")[:10]
    reserved = len("bs--") + len(suffix) + len(digest)
    prefix = base[: max(1, maximum - reserved)].rstrip("-")
    return f"bs-{prefix}-{suffix}-{digest}"[:maximum].rstrip("-")


def _bucket_name(run_id: str) -> str:
    return _safe_name(run_id, "objects", maximum=63)


def _resource_names(run_id: str) -> dict:
    return {
        "service": _safe_name(run_id, "mos"),
        "network": _safe_name(run_id, "public"),
        "bucket": _bucket_name(run_id),
        "username": _safe_name(run_id, "backup", maximum=64),
        "policy": _safe_name(run_id, "least-privilege", maximum=128),
        "prefix": f"backupsheep-e2e/{run_id}/",
        "source_volume": _safe_name(run_id, "volume", maximum=128),
        "source_server": _safe_name(run_id, "server", maximum=128),
        "source_boot": _safe_name(run_id, "boot", maximum=128),
        "hostname": _safe_name(run_id, "server", maximum=54) + ".invalid",
    }


def _labels(run_id: str) -> list[dict]:
    return [
        {"key": "backupsheep-e2e-owned", "value": "true"},
        {"key": "backupsheep-e2e-run", "value": run_id},
    ]


def _label_map(value) -> dict:
    if isinstance(value, dict):
        value = value.get("label")
    if not isinstance(value, list):
        return {}
    result = {}
    for item in value:
        if not isinstance(item, dict):
            return {}
        key = str(item.get("key") or "")
        if not key or key in result:
            return {}
        result[key] = str(item.get("value") or "")
    return result


def _public_endpoint(service: dict) -> str:
    endpoints = service.get("endpoints") if isinstance(service, dict) else None
    matches = []
    for item in endpoints or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "public" or item.get("mode") != "api":
            continue
        hostname = str(item.get("domain_name") or "").casefold().rstrip(".")
        if (
            HOST_RE.fullmatch(hostname)
            and hostname.endswith(".upcloudobjects.com")
            and ":" not in hostname
        ):
            matches.append(hostname)
    if len(matches) != 1:
        raise HarnessError(
            "The run-owned service does not expose one exact public S3 endpoint."
        )
    return matches[0]


def _policy_document(bucket: str, prefix: str) -> dict:
    bucket_arn = f"arn:aws:s3:::{bucket}"
    object_arn = f"{bucket_arn}/{prefix}*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BackupSheepBucketConfiguration",
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                ],
                "Resource": bucket_arn,
            },
            {
                "Sid": "BackupSheepBoundedInventory",
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListBucketVersions",
                ],
                "Resource": bucket_arn,
                "Condition": {
                    "StringLike": {"s3:prefix": [prefix, f"{prefix}*"]}
                },
            },
            {
                "Sid": "BackupSheepObjects",
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:ListMultipartUploadParts",
                    "s3:PutObject",
                ],
                "Resource": object_arn,
            },
        ],
    }


def _normalized_policy(value) -> str:
    text = str(value or "")
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    try:
        payload = json.loads(text)
    except (TypeError, ValueError) as error:
        raise HarnessError("UpCloud returned a malformed inline policy document.") from error
    if not isinstance(payload, dict):
        raise HarnessError("UpCloud returned a malformed inline policy document.")
    return _canonical(payload)


def _contains_sensitive_key(value) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(
                token in normalized
                for token in ("secret", "password", "access_key", "api_token")
            ):
                return True
            if _contains_sensitive_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(child) for child in value)
    return False


def _strict_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError("A manifest contains a duplicate JSON key.")
        result[key] = value
    return result


def _parse_manifest_bytes(payload: bytes, *, kind: str) -> dict:
    if not isinstance(payload, bytes) or len(payload) > MANIFEST_MAX_BYTES:
        raise HarnessError(f"The UpCloud {kind} manifest is missing, unsafe, or too large.")
    try:
        manifest = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_strict_object_pairs
        )
    except HarnessError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError):
        raise HarnessError(f"The UpCloud {kind} manifest is unreadable.") from None
    if not isinstance(manifest, dict):
        raise HarnessError(f"The UpCloud {kind} manifest must be a JSON object.")
    if _contains_sensitive_key(manifest):
        raise HarnessError(f"The UpCloud {kind} manifest must not contain credentials.")
    expected = MANIFEST_TOP_LEVEL_KEYS[kind]
    if set(manifest) != expected:
        raise HarnessError(f"The UpCloud {kind} manifest has unknown or missing fields.")
    if type(manifest.get("schema")) is not int or manifest["schema"] != 1:
        raise HarnessError(f"The UpCloud {kind} manifest schema must be integer 1.")
    return manifest


def _load_strict_manifest(path_value, *, kind: str) -> dict:
    """Reject the retired loose-file interface before any file is trusted."""

    _safe_path(path_value, variable="--manifest")
    raise HarnessError(
        "Loose manifest paths are no longer accepted; pass a complete new "
        "generation directory containing its ownership marker."
    )


def _safe_backup_object_id(value, field="backup_uuid") -> str:
    value = str(value or "").strip()
    if (
        not SAFE_BACKUP_OBJECT_ID_RE.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HarnessError(f"{field} is not a safe BackupSheep object identifier.")
    return value


def _positive_generation_id(value, field: str) -> int:
    if type(value) is not int or value < 1:
        raise HarnessError(f"{field} must be a positive BackupSheep row ID.")
    return value


def _safe_generation_directory(value) -> tuple[Path, dict[str, Path]]:
    """Open one immutable-looking generation envelope without provider I/O."""

    if not value:
        raise HarnessError(
            "A complete generation directory is required; loose manifest paths "
            "are no longer accepted."
        )
    raw = Path(value).expanduser()
    if not raw.is_absolute() or any(part in {".", ".."} for part in raw.parts[1:]):
        raise HarnessError("The generation path must be an absolute, unambiguous directory.")
    try:
        if raw.is_symlink():
            raise HarnessError("The manifest generation directory cannot be a symlink.")
        absolute = raw.absolute()
        real = Path(os.path.realpath(absolute))
        if real != absolute:
            raise HarnessError("The manifest generation path cannot traverse a symlink.")
        directory_stat = os.lstat(real)
    except HarnessError:
        raise
    except OSError:
        raise HarnessError("The manifest generation directory is missing or unreadable.") from None
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise HarnessError(
            "Loose manifest paths are no longer accepted; pass a complete new "
            "generation directory."
        )
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise HarnessError("The manifest generation directory must have mode 0700.")
    files = {}
    try:
        with os.scandir(real) as entries:
            for entry in entries:
                entry_path = real / entry.name
                entry_stat = os.lstat(entry_path)
                if entry.is_symlink() or stat.S_ISLNK(entry_stat.st_mode):
                    raise HarnessError("Manifest generation files cannot be symlinks.")
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise HarnessError("Manifest generation contains a non-regular file.")
                if stat.S_IMODE(entry_stat.st_mode) != 0o600:
                    raise HarnessError("Manifest generation files must have mode 0600.")
                files[entry.name] = entry_path
    except HarnessError:
        raise
    except OSError:
        raise HarnessError("The manifest generation directory is unreadable.") from None
    return real, files


def _read_generation_file(path: Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        payload = os.read(descriptor, MANIFEST_MAX_BYTES + 1)
    except OSError:
        raise HarnessError(f"The {label} is unreadable.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(payload) > MANIFEST_MAX_BYTES:
        raise HarnessError(f"The {label} is too large.")
    return payload


def _artifact_binding_digest(identity: dict) -> str:
    payload = json.dumps(
        identity,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    return hashlib.sha256(payload).hexdigest()


def _validate_artifact_binding(binding, row, *, label: str) -> dict:
    if not isinstance(binding, dict) or set(binding) != ARTIFACT_BINDING_KEYS:
        raise HarnessError(f"The {label} artifact binding is incomplete.")
    artifact_id = _positive_generation_id(binding.get("artifact_id"), f"{label}.artifact_id")
    byte_count = _positive_generation_id(binding.get("byte_count"), f"{label}.byte_count")
    checksum = str(binding.get("sha256") or "").casefold()
    etag = str(binding.get("etag") or "")
    version_id = str(binding.get("version_id") or "")
    binding_digest = str(binding.get("binding_sha256") or "").casefold()
    if (
        not SHA256_RE.fullmatch(checksum)
        or not etag
        or not version_id
        or version_id == "null"
        or not SHA256_RE.fullmatch(binding_digest)
    ):
        raise HarnessError(f"The {label} artifact binding is malformed.")
    identity = {
        "artifact_id": artifact_id,
        "byte_count": byte_count,
        "sha256": checksum,
        "etag": etag,
        "version_id": version_id,
    }
    if _artifact_binding_digest(identity) != binding_digest:
        raise HarnessError(f"The {label} artifact binding digest is invalid.")
    if any(
        (
            not isinstance(row, dict),
            row.get("artifact_id") != artifact_id,
            row.get("byte_count") != byte_count,
            str(row.get("sha256") or "").casefold() != checksum,
            str(row.get("etag") or "") != etag,
            str(row.get("version_id") or "") != version_id,
        )
    ):
        raise HarnessError(f"The {label} artifact binding does not match its manifest row.")
    return identity


def _validate_object_manifest_rows(manifest: dict) -> dict[str, dict]:
    rows = manifest.get("objects") if isinstance(manifest, dict) else None
    if (
        not isinstance(rows, list)
        or len(rows) != len(UI_OBJECT_KINDS)
        or any(not isinstance(row, dict) for row in rows)
        or sorted(str(row.get("kind") or "") for row in rows)
        != sorted(UI_OBJECT_KINDS)
    ):
        raise HarnessError(
            "The UI object manifest must contain exactly one website and one database object."
        )
    result = {}
    for row in rows:
        if set(row) != UI_OBJECT_ROW_KEYS:
            raise HarnessError("The UI object manifest contains a malformed row.")
        kind = str(row.get("kind") or "")
        if kind in result or kind not in UI_OBJECT_KINDS:
            raise HarnessError("The UI object manifest contains duplicate artifact kinds.")
        for field in (
            "backup_id",
            "storage_point_id",
            "storage_id",
            "artifact_id",
        ):
            _positive_generation_id(row.get(field), f"{kind}.{field}")
        backup_uuid = _safe_backup_object_id(row.get("backup_uuid"), f"{kind}.backup_uuid")
        checksum = str(row.get("sha256") or "").casefold()
        if (
            row.get("artifact_status") != "verified"
            or not checksum
            or not SHA256_RE.fullmatch(checksum)
            or type(row.get("byte_count")) is not int
            or row["byte_count"] < 1
            or not str(row.get("etag") or "")
            or not str(row.get("version_id") or "")
            or str(row.get("version_id")) == "null"
            or not str(row.get("object_key") or "")
            or str(row["object_key"]).startswith("/")
            or "\\" in str(row["object_key"])
        ):
            raise HarnessError(f"The {kind} artifact witness is incomplete or unsafe.")
        result[kind] = {
            **row,
            "backup_uuid": backup_uuid,
            "sha256": checksum,
            "etag": str(row["etag"]),
            "version_id": str(row["version_id"]),
        }
    return result


def _validate_marker_rows(rows, expected, *, label: str) -> None:
    if not isinstance(rows, dict) or set(rows) != set(expected):
        raise HarnessError(f"The {label} row binding is incomplete.")
    for field, value in expected.items():
        if _positive_generation_id(rows.get(field), f"{label}.{field}") != value:
            raise HarnessError(f"The {label} row binding does not match its manifests.")


@dataclass(frozen=True)
class HarnessConfig:
    run_id: str
    ledger_path: Path
    account: str
    region: str
    runtime_path: Path
    zone: str = ""
    server_plan: str = ""
    os_template: str = ""
    ssh_user: str = "root"
    volume_size_gb: int = 10
    boot_size_gb: int = 25
    allowed_cidrs: tuple[str, ...] = ()
    apply: bool = False
    cleanup: bool = False

    @classmethod
    def from_environment(cls, environment=None):
        environment = environment or os.environ
        run_id = require_run_id(environment.get("BACKUPSHEEP_E2E_RUN_ID"))
        ledger_path = _safe_path(
            environment.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            variable="BACKUPSHEEP_E2E_LEDGER_PATH",
        )
        account = str(environment.get("UPCLOUD_E2E_ALLOWED_ACCOUNT") or "").strip()
        region = str(
            environment.get("UPCLOUD_E2E_OBJECT_STORAGE_REGION") or ""
        ).strip()
        zone = str(environment.get("UPCLOUD_E2E_ZONE") or "").strip()
        server_plan = str(
            environment.get("UPCLOUD_E2E_SERVER_PLAN") or ""
        ).strip()
        os_template = str(
            environment.get("UPCLOUD_E2E_OS_TEMPLATE") or ""
        ).strip()
        ssh_user = str(
            environment.get("UPCLOUD_E2E_SSH_USER") or "root"
        ).strip()
        raw_cidrs = str(
            environment.get("UPCLOUD_E2E_ALLOWED_CIDRS") or ""
        ).strip()
        if not account:
            raise HarnessError("UPCLOUD_E2E_ALLOWED_ACCOUNT is required.")
        if not re.fullmatch(r"[a-zA-Z0-9_.@+-]{1,128}", account):
            raise HarnessError("UPCLOUD_E2E_ALLOWED_ACCOUNT is malformed.")
        if region and not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", region):
            raise HarnessError(
                "UPCLOUD_E2E_OBJECT_STORAGE_REGION must be an exact region name."
            )
        if zone and not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", zone):
            raise HarnessError("UPCLOUD_E2E_ZONE is malformed.")
        if server_plan and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", server_plan
        ):
            raise HarnessError("UPCLOUD_E2E_SERVER_PLAN is malformed.")
        if os_template and not UPCLOUD_UUID_RE.fullmatch(os_template):
            raise HarnessError("UPCLOUD_E2E_OS_TEMPLATE must be an exact UUID.")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", ssh_user):
            raise HarnessError("UPCLOUD_E2E_SSH_USER is malformed.")
        allowed_cidrs = []
        for raw_cidr in [value.strip() for value in raw_cidrs.split(",") if value.strip()]:
            try:
                network = ipaddress.ip_network(raw_cidr, strict=True)
            except ValueError:
                raise HarnessError("UPCLOUD_E2E_ALLOWED_CIDRS contains an invalid CIDR.") from None
            required_prefix = 32 if network.version == 4 else 128
            if (
                network.prefixlen != required_prefix
                or network.network_address.is_unspecified
                or network.network_address.is_multicast
            ):
                raise HarnessError(
                    "UPCLOUD_E2E_ALLOWED_CIDRS accepts only exact /32 or /128 host CIDRs."
                )
            allowed_cidrs.append(str(network))
        if len(allowed_cidrs) != len(set(allowed_cidrs)):
            raise HarnessError("UPCLOUD_E2E_ALLOWED_CIDRS contains duplicates.")
        try:
            volume_size_gb = int(
                environment.get("UPCLOUD_E2E_VOLUME_SIZE_GB") or 10
            )
            boot_size_gb = int(
                environment.get("UPCLOUD_E2E_BOOT_SIZE_GB") or 25
            )
        except (TypeError, ValueError):
            raise HarnessError("UpCloud storage sizes must be integers.") from None
        if not 10 <= volume_size_gb <= 100 or not 10 <= boot_size_gb <= 100:
            raise HarnessError("UpCloud E2E storage sizes are outside safe bounds.")
        return cls(
            run_id=run_id,
            ledger_path=ledger_path,
            account=account,
            region=region,
            runtime_path=_runtime_path(run_id, environment),
            zone=zone,
            server_plan=server_plan,
            os_template=os_template,
            ssh_user=ssh_user,
            volume_size_gb=volume_size_gb,
            boot_size_gb=boot_size_gb,
            allowed_cidrs=tuple(sorted(allowed_cidrs)),
            apply=str(environment.get("BACKUPSHEEP_E2E_APPLY") or "").upper()
            == "YES",
            cleanup=str(
                environment.get("BACKUPSHEEP_E2E_CLEANUP") or ""
            ).upper()
            == "YES",
        )


class UpCloudControlPlane:
    """Small token-auth API boundary that never exposes provider response text."""

    def __init__(self, token: str, *, session=None, api_base=API_BASE):
        token = str(token or "").strip()
        if not token:
            raise HarnessError("UPCLOUD_API_TOKEN is required for live commands.")
        self._token = token
        self._session = session or requests.Session()
        self._base = str(api_base).rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        accepted=(200,),
        allow_not_found=False,
        mutation=False,
        params=None,
        json_body=None,
    ):
        root_segment = str(path or "").strip("/").split("/", 1)[0]
        request_scope = (
            f"{str(method).upper()} /{root_segment}"
            if re.fullmatch(r"[a-z0-9-]{1,64}", root_segment)
            else str(method).upper()
        )
        try:
            response = self._session.request(
                method,
                self._base + "/" + str(path).lstrip("/"),
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                params=params,
                json=json_body,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            if mutation:
                raise AmbiguousMutation(
                    "The UpCloud mutation response was lost; rerun reconciliation "
                    "without creating a replacement resource."
                ) from None
            raise ProviderUnavailable(
                "The UpCloud control plane is temporarily unavailable."
            ) from None
        try:
            status_code = int(getattr(response, "status_code", 0) or 0)
            if allow_not_found and status_code == 404:
                return None
            if status_code not in set(accepted):
                provider_code = ""
                provider_message = ""
                try:
                    problem = response.json()
                    detail = problem.get("error") if isinstance(problem, dict) else None
                    candidate = (
                        detail.get("error_code") or detail.get("code")
                        if isinstance(detail, dict)
                        else problem.get("error_code") or problem.get("code")
                        if isinstance(problem, dict)
                        else ""
                    )
                    candidate = str(candidate or "").strip().upper().replace("-", "_")
                    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", candidate):
                        provider_code = candidate
                    if isinstance(detail, dict):
                        provider_message = str(
                            detail.get("error_message") or detail.get("message") or ""
                        )
                    elif isinstance(detail, str):
                        provider_message = detail
                    elif isinstance(problem, dict):
                        provider_message = str(
                            problem.get("error_message") or problem.get("message") or ""
                        )
                    if provider_code == "UNKNOWN_ATTRIBUTE" and isinstance(
                        detail, dict
                    ):
                        match = re.search(
                            r"(?i)unknown\s+attribute\s+['\"]?([a-z][a-z0-9_]*)",
                            provider_message,
                        )
                        allowed_fields = {
                            "action", "address", "boot_disk", "core_number",
                            "create_password", "encrypted", "firewall", "hostname",
                            "interfaces", "ip_address", "ip_addresses", "labels",
                            "login_user", "memory_amount", "metadata", "networking",
                            "plan", "size", "ssh_key", "ssh_keys", "storage",
                            "storage_device", "storage_devices", "tier", "timezone",
                            "title", "type", "username", "zone",
                        }
                        field = match.group(1).casefold() if match else ""
                        if field in allowed_fields:
                            provider_code = f"{provider_code}:{field.upper()}"
                except (TypeError, ValueError):
                    pass
                if not provider_code and provider_message:
                    match = re.search(
                        r"(?i)(?:attribute\s+|field\s+)([a-z][a-z0-9_]*)",
                        provider_message,
                    )
                    allowed_diagnostics = {
                        "action", "address", "boot_disk", "create_password",
                        "encrypted", "firewall", "hostname", "labels", "login_user",
                        "metadata", "networking", "plan", "size", "ssh_keys",
                        "storage", "storage_device", "storage_devices", "tier",
                        "timezone", "title", "type", "username", "zone",
                    }
                    field = match.group(1).casefold() if match else ""
                    if field in allowed_diagnostics:
                        provider_code = f"FIELD:{field.upper()}"
                code_suffix = f" ({provider_code or f'HTTP_{status_code}'})"
                if status_code in {401, 403}:
                    raise HarnessError(
                        "UpCloud rejected the token or its required permissions"
                        f" for {request_scope}{code_suffix}.",
                        code="PROVIDER_AUTH_FAILED",
                        definitive_rejection=True,
                    )
                if status_code == 429:
                    if mutation:
                        raise HarnessError(
                            "UpCloud rate-limited the bounded mutation"
                            f" for {request_scope}{code_suffix}; no accepted "
                            "mutation is available to adopt.",
                            code="PROVIDER_RATE_LIMIT",
                            definitive_rejection=True,
                        )
                    raise ProviderUnavailable(
                        "UpCloud rate-limited the bounded harness request"
                        f"{code_suffix}."
                    )
                if status_code == 408:
                    if mutation:
                        raise AmbiguousMutation(
                            "UpCloud timed out a mutation request; exact "
                            "reconciliation is required before retry.",
                            code="PROVIDER_TIMEOUT",
                        )
                    raise ProviderUnavailable(
                        "The UpCloud control plane timed out the bounded request."
                    )
                if status_code >= 500:
                    if mutation:
                        raise AmbiguousMutation(
                            "UpCloud returned a transient mutation response; exact "
                            "reconciliation is required before retry.",
                            code="PROVIDER_TRANSIENT_OUTAGE",
                        )
                    raise ProviderUnavailable(
                        "The UpCloud control plane returned a transient outage."
                    )
                if 400 <= status_code < 500:
                    raise HarnessError(
                        "UpCloud rejected the bounded harness request for "
                        f"{request_scope}{code_suffix}.",
                        code="PROVIDER_DEFINITE_REJECTION",
                        definitive_rejection=True,
                    )
                if mutation:
                    raise AmbiguousMutation(
                        "UpCloud returned an unclassified mutation response; exact "
                        "reconciliation is required before retry.",
                        code="PROVIDER_UNEXPECTED_STATUS",
                    )
                raise HarnessError(
                    "UpCloud rejected the bounded harness request for "
                    f"{request_scope}{code_suffix}."
                )
            if status_code == 204:
                return None
            try:
                return response.json()
            except (TypeError, ValueError):
                if status_code in {200, 201, 202}:
                    return {}
                raise HarnessError("UpCloud returned malformed JSON.") from None
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()


def _s3_client(credentials: dict):
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise HarnessError("boto3 is required for Object Storage commands.") from error
    return boto3.client(
        "s3",
        endpoint_url=f"https://{credentials['endpoint']}",
        region_name=credentials["region"],
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"],
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def _s3_error_code(error) -> str:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return ""
    detail = response.get("Error")
    return str(detail.get("Code") or "") if isinstance(detail, dict) else ""


def _s3_error_status(error):
    """Return an S3 HTTP status without depending on a concrete SDK class."""

    response = getattr(error, "response", None)
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata") or {}
        candidates = (
            metadata.get("HTTPStatusCode"),
            response.get("status_code"),
            response.get("StatusCode"),
        )
        detail = response.get("Error")
        if isinstance(detail, dict):
            candidates += (detail.get("HTTPStatusCode"), detail.get("StatusCode"))
        for candidate in candidates:
            try:
                if candidate is not None:
                    return int(candidate)
            except (TypeError, ValueError):
                continue
    for attribute in ("status_code", "status"):
        try:
            value = getattr(error, attribute, None)
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _s3_error_is_transport(error) -> bool:
    name = error.__class__.__name__.casefold()
    return any(
        marker in name
        for marker in (
            "timeout",
            "connection",
            "endpointconnection",
            "connecttimeout",
            "readtimeout",
        )
    )


def _s3_error_outcome(error):
    """Classify an S3 failure as definite, transient, or genuinely unknown."""

    code = _s3_error_code(error).casefold()
    status = _s3_error_status(error)
    if _s3_error_is_transport(error) or status in {408, 504} or (
        isinstance(status, int) and status >= 500
    ):
        return "unknown"
    if status == 429 or code in {
        "slowdown",
        "throttling",
        "throttlingexception",
        "toomanyrequestsexception",
        "ratelimitexceeded",
    }:
        # The S3 endpoint rejected the request with a rate-limit response;
        # there is no accepted mutation to adopt.
        return "definite"
    if status in {401, 403, 404} or code in {
        "accessdenied",
        "accessdeniedexception",
        "unauthorized",
        "invalidaccesskeyid",
        "invalidtoken",
        "signaturedoesnotmatch",
        "nosuchbucket",
        "nosuchkey",
        "nosuchupload",
        "notfound",
    }:
        return "definite"
    if isinstance(status, int) and 400 <= status < 500:
        # 408 is handled above because the request may have reached the
        # provider before the timeout response was produced.
        return "definite"
    return "unknown"


def _s3_call(callback, *, mutation=False, allow_not_found=False):
    try:
        return callback()
    except Exception as error:
        code = _s3_error_code(error)
        status = _s3_error_status(error)
        if allow_not_found and (
            status == 404
            or code in {
            "404",
            "NoSuchBucket",
            "NoSuchKey",
            "NoSuchUpload",
            "NotFound",
            }
        ):
            return None
        outcome = _s3_error_outcome(error)
        suffix = f" ({code or f'HTTP_{status}' if status else 'UNKNOWN'})"
        if outcome == "definite":
            if mutation:
                raise HarnessError(
                    "The S3-compatible provider definitively rejected the mutation"
                    f"{suffix}.",
                    code="PROVIDER_DEFINITE_REJECTION",
                    definitive_rejection=True,
                ) from None
            raise HarnessError(
                "The bounded UpCloud Object Storage request was definitively rejected"
                f"{suffix}.",
                code="PROVIDER_DEFINITE_REJECTION",
                definitive_rejection=True,
            ) from None
        if not mutation:
            raise ProviderUnavailable(
                "UpCloud Object Storage is temporarily unavailable or the request "
                "outcome is unknown."
            ) from None
        raise AmbiguousMutation(
            "The S3-compatible mutation response was lost or transient; exact "
            "reconciliation is required before retry."
        ) from None


class UpCloudLiveHarness:
    def __init__(
        self,
        config: HarnessConfig,
        *,
        environment=None,
        control=None,
        s3_factory=None,
        sleeper=None,
        clock=None,
    ):
        self.config = config
        self.environment = environment or os.environ
        token = str(self.environment.get("UPCLOUD_API_TOKEN") or "").strip()
        self.control = control or UpCloudControlPlane(token)
        self.s3_factory = s3_factory or _s3_client
        self.sleep = sleeper or time.sleep
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.names = _resource_names(config.run_id)
        self.ledger = DurableResourceLedger(
            config.ledger_path,
            provider="upcloud",
            run_id=config.run_id,
            scope=config.account,
        )
        self.intents = DurableMutationIntentStore(
            config.ledger_path,
            provider="upcloud",
            run_id=config.run_id,
            scope=config.account,
        )
        self.account = ""

    def _require_compute_config(self):
        if not self.config.zone:
            raise HarnessError("UPCLOUD_E2E_ZONE is required for compute commands.")
        if not self.config.server_plan:
            raise HarnessError(
                "UPCLOUD_E2E_SERVER_PLAN is required for compute commands."
            )
        if not UPCLOUD_UUID_RE.fullmatch(self.config.os_template):
            raise HarnessError(
                "UPCLOUD_E2E_OS_TEMPLATE is required for compute commands."
            )
        if not self.config.allowed_cidrs:
            raise HarnessError(
                "UPCLOUD_E2E_ALLOWED_CIDRS must include exact demo/local /32 or /128 hosts."
            )

    def _require_object_storage_config(self):
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{1,63}", self.config.region or ""
        ):
            raise HarnessError(
                "UPCLOUD_E2E_OBJECT_STORAGE_REGION is required for Object Storage commands."
            )

    def _require_apply(self):
        if not self.config.apply:
            raise HarnessError(
                "Provider setup requires BACKUPSHEEP_E2E_APPLY=YES."
            )

    def _require_cleanup(self):
        if not (self.config.apply and self.config.cleanup):
            raise HarnessError(
                "Cleanup requires both BACKUPSHEEP_E2E_APPLY=YES and "
                "BACKUPSHEEP_E2E_CLEANUP=YES."
            )

    def verify_account(self) -> str:
        payload = self.control.request("GET", "/account")
        account = payload.get("account") if isinstance(payload, dict) else None
        username = str(account.get("username") or "") if isinstance(account, dict) else ""
        if not username or username != self.config.account:
            raise HarnessError(
                "The authenticated UpCloud account does not match the exact allowed account."
            )
        self.account = username
        return username

    def _control_mutation(self, intent_key: str, method: str, path: str, **kwargs):
        """Keep only intents whose provider outcome can still be ambiguous."""

        try:
            return self.control.request(
                method, path, mutation=True, **kwargs
            )
        except AmbiguousMutation:
            raise
        except HarnessError as error:
            # Only an explicit provider rejection releases the intent.  An
            # unclassified HarnessError is deliberately retained because it
            # may represent a lost or otherwise unknown mutation outcome.
            if error.definitive_rejection and not error.mutation_outcome_unknown:
                self.intents.clear(intent_key)
            raise

    def _s3_mutation(self, intent_key: str, callback):
        """Run one S3 mutation and release only a definite rejection intent."""

        try:
            return _s3_call(callback, mutation=True)
        except HarnessError as error:
            if error.definitive_rejection and not error.mutation_outcome_unknown:
                self.intents.clear(intent_key)
            raise

    def verify_compute_plan(self) -> dict:
        """Prove the exact plan is compatible before creating any fixture."""

        payload = self.control.request("GET", "/plan")
        container = payload.get("plans") if isinstance(payload, dict) else None
        plans = container.get("plan") if isinstance(container, dict) else None
        if (
            not isinstance(plans, list)
            or len(plans) > MAX_ITEMS
            or any(not isinstance(plan, dict) for plan in plans)
        ):
            raise HarnessError("UpCloud returned a malformed plan inventory.")
        matches = [
            plan
            for plan in plans
            if str(plan.get("name") or "") == self.config.server_plan
        ]
        if len(matches) != 1:
            raise HarnessError("The exact UpCloud server plan is unavailable.")
        plan = matches[0]
        try:
            storage_size = int(plan.get("storage_size"))
            core_number = int(plan.get("core_number"))
            memory_amount = int(plan.get("memory_amount"))
        except (TypeError, ValueError):
            raise HarnessError("The exact UpCloud server plan is malformed.") from None
        storage_tier = str(plan.get("storage_tier") or "").casefold()
        if (
            storage_size != self.config.boot_size_gb
            or storage_tier != "standard"
            or core_number < 1
            or memory_amount < 1024
        ):
            raise HarnessError(
                "The exact UpCloud server plan is incompatible with the bounded fixture."
            )
        return {
            "name": self.config.server_plan,
            "storage_size": storage_size,
            "storage_tier": storage_tier,
            "core_number": core_number,
            "memory_amount": memory_amount,
        }

    def _active_entries(self, kind: str) -> list[dict]:
        return [
            row
            for row in self.ledger.entries(kind)
            if row.get("cleanup_state") in ACTIVE_LEDGER_STATES
        ]

    def _one_active(self, kind: str) -> dict | None:
        rows = self._active_entries(kind)
        if len(rows) > 1:
            raise HarnessError(f"Multiple active {kind} resources are ledgered.")
        return rows[0] if rows else None

    def _offset_list(self, path: str) -> list[dict]:
        result = []
        offset = 0
        seen_pages = set()
        for _ in range(MAX_PAGES):
            payload = self.control.request(
                "GET", path, params={"limit": 100, "offset": offset}
            )
            if not isinstance(payload, list) or any(
                not isinstance(item, dict) for item in payload
            ):
                raise HarnessError("UpCloud returned a malformed bounded inventory.")
            identity = _fingerprint(payload)
            if payload and identity in seen_pages:
                raise HarnessError("UpCloud returned a non-advancing inventory page.")
            seen_pages.add(identity)
            result.extend(payload)
            if len(result) > MAX_ITEMS:
                raise HarnessError("UpCloud inventory exceeded the safety bound.")
            if len(payload) < 100:
                return result
            offset += len(payload)
        raise HarnessError("UpCloud inventory exceeded the page bound.")

    @staticmethod
    def _exact_name(items: list[dict], field: str, name: str) -> dict | None:
        matches = [item for item in items if str(item.get(field) or "") == name]
        if len(matches) > 1:
            raise HarnessError("Multiple provider resources share the exact run name.")
        return matches[0] if matches else None

    def _service_request(self) -> dict:
        return {
            "name": self.names["service"],
            "region": self.config.region,
            "configured_status": "started",
            "termination_protection": False,
            "networks": [
                {
                    "name": self.names["network"],
                    "type": "public",
                    "family": "IPv4",
                }
            ],
            "labels": _labels(self.config.run_id),
        }

    def _service_owned(self, service: dict, *, resource_id=None) -> bool:
        if not isinstance(service, dict):
            return False
        networks = service.get("networks")
        expected_network = {
            "name": self.names["network"],
            "type": "public",
            "family": "IPv4",
        }
        normalized_networks = [
            {key: item.get(key) for key in expected_network}
            for item in networks or []
            if isinstance(item, dict)
        ]
        labels = _label_map(service.get("labels"))
        return all(
            (
                bool(service.get("uuid")),
                resource_id in (None, "")
                or str(service.get("uuid")) == str(resource_id),
                str(service.get("name") or "") == self.names["service"],
                str(service.get("region") or "") == self.config.region,
                str(service.get("configured_status") or "") == "started",
                service.get("termination_protection") is False,
                normalized_networks == [expected_network],
                labels.get("backupsheep-e2e-owned") == "true",
                labels.get("backupsheep-e2e-run") == self.config.run_id,
            )
        )

    def _service_read(self, resource_id: str) -> dict | None:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(resource_id, safe='')}",
            allow_not_found=True,
        )
        return payload if isinstance(payload, dict) else None

    def _record_service(self, service: dict, request: dict) -> dict:
        resource_id = str(service.get("uuid") or "")
        if not self._service_owned(service, resource_id=resource_id):
            raise HarnessError("UpCloud service ownership verification failed.")
        entry = self.ledger.record(
            kind="mos_service",
            resource_id=resource_id,
            name=self.names["service"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "region": self.config.region,
                "request_fingerprint": _fingerprint(request),
            },
            source_witness=f"upcloud-account:{self.account}",
        )
        self.ledger.record(
            kind="mos_network",
            resource_id=f"{resource_id}:{self.names['network']}",
            name=self.names["network"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": resource_id,
                "type": "public",
                "family": "IPv4",
            },
            source_witness=resource_id,
        )
        return entry

    def ensure_service(self) -> dict:
        self._require_apply()
        request = self._service_request()
        fingerprint = _fingerprint(request)
        entry = self._one_active("mos_service")
        if entry:
            service = self._service_read(entry["resource_id"])
            if not self._service_owned(service or {}, resource_id=entry["resource_id"]):
                raise HarnessError("The ledgered UpCloud service ownership changed.")
            return service

        intent_key = "mos_service_create"
        intent = self.intents.get(intent_key)
        services = self._offset_list("/object-storage-2")
        ledger_service_ids = {
            str(row.get("resource_id") or "")
            for row in self._active_entries("mos_service")
        }
        candidate = self._exact_name(services, "name", self.names["service"])
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("request_fingerprint") == fingerprint
            and intent.get("name") == self.names["service"]
            and intent.get("preflight_absent") is True
        )
        if candidate:
            if not intent_matches:
                raise HarnessError(
                    "An unledgered UpCloud service matches the run-owned name."
                )
            service = self._service_read(str(candidate.get("uuid") or ""))
            self._record_service(service or {}, request)
            self.intents.clear(intent_key)
            return service
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior UpCloud service create is not visible; no duplicate was sent."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "mos_service",
                "name": self.names["service"],
                "operation": "create",
                "request_fingerprint": fingerprint,
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        payload = self._control_mutation(
            intent_key,
            "POST",
            "/object-storage-2",
            accepted=(201,),
            json_body=request,
        )
        candidate_id = str(payload.get("uuid") or "") if isinstance(payload, dict) else ""
        if candidate_id:
            candidate = self._service_read(candidate_id)
        else:
            candidate = self._exact_name(
                self._offset_list("/object-storage-2"),
                "name",
                self.names["service"],
            )
            candidate = (
                self._service_read(str(candidate.get("uuid") or ""))
                if candidate
                else None
            )
        if not candidate:
            raise AmbiguousMutation(
                "UpCloud accepted the service create but exact read-back is incomplete."
            )
        self._record_service(candidate, request)
        self.intents.clear(intent_key)
        return candidate

    def wait_service_ready(self, service: dict) -> dict:
        resource_id = str(service.get("uuid") or "")
        for attempt in range(120):
            try:
                current = self._service_read(resource_id)
            except ProviderUnavailable:
                if attempt == 119:
                    break
                self.sleep(10)
                continue
            if not self._service_owned(current or {}, resource_id=resource_id):
                raise HarnessError("The run-owned UpCloud service changed while waiting.")
            state = str(current.get("operational_state") or "").casefold()
            if state == "running":
                _public_endpoint(current)
                return current
            if state in SERVICE_FAILED_STATES:
                raise HarnessError("The UpCloud Object Storage service entered a terminal state.")
            if state not in SERVICE_TRANSITIONAL_STATES:
                raise HarnessError("UpCloud returned an unknown Object Storage service state.")
            if attempt < 119:
                self.sleep(10)
        raise ProviderUnavailable(
            "The UpCloud Object Storage service did not become ready within the bound."
        )

    def _buckets(self, service_id: str) -> list[dict]:
        return self._offset_list(
            f"/object-storage-2/{quote(service_id, safe='')}/buckets"
        )

    def _bucket_request(self) -> dict:
        return {"name": self.names["bucket"]}

    def _record_bucket(self, service_id: str, bucket: dict, request: dict) -> dict:
        name = str(bucket.get("name") or "") if isinstance(bucket, dict) else ""
        if name != self.names["bucket"]:
            raise HarnessError("UpCloud bucket ownership verification failed.")
        return self.ledger.record(
            kind="mos_bucket",
            resource_id=f"{service_id}:{name}",
            name=name,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": service_id,
                "bucket_name": name,
                "prefix": self.names["prefix"],
                "request_fingerprint": _fingerprint(request),
            },
            source_witness=service_id,
        )

    def ensure_bucket(self, service: dict) -> dict:
        service_id = str(service.get("uuid") or "")
        request = self._bucket_request()
        fingerprint = _fingerprint(request)
        entry = self._one_active("mos_bucket")
        candidates = self._buckets(service_id)
        candidate = self._exact_name(candidates, "name", self.names["bucket"])
        if entry:
            ownership = entry.get("ownership") or {}
            if (
                entry["resource_id"] != f"{service_id}:{self.names['bucket']}"
                or ownership.get("service_uuid") != service_id
                or candidate is None
            ):
                raise HarnessError("The ledgered UpCloud bucket ownership changed.")
            return candidate

        intent_key = "mos_bucket_create"
        intent = self.intents.get(intent_key)
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("request_fingerprint") == fingerprint
            and intent.get("service_uuid") == service_id
            and intent.get("preflight_absent") is True
        )
        if candidate:
            if not intent_matches:
                raise HarnessError(
                    "An unledgered bucket matches the exact UpCloud run name."
                )
            self._record_bucket(service_id, candidate, request)
            self.intents.clear(intent_key)
            return candidate
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior UpCloud bucket create is not visible; no duplicate was sent."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "mos_bucket",
                "name": self.names["bucket"],
                "operation": "create",
                "service_uuid": service_id,
                "request_fingerprint": fingerprint,
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "POST",
            f"/object-storage-2/{quote(service_id, safe='')}/buckets",
            accepted=(201,),
            json_body=request,
        )
        candidate = self._exact_name(
            self._buckets(service_id), "name", self.names["bucket"]
        )
        if not candidate:
            raise AmbiguousMutation(
                "UpCloud accepted the bucket create but exact read-back is incomplete."
            )
        self._record_bucket(service_id, candidate, request)
        self.intents.clear(intent_key)
        return candidate

    def _users(self, service_id: str) -> list[dict]:
        payload = self.control.request(
            "GET", f"/object-storage-2/{quote(service_id, safe='')}/users"
        )
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise HarnessError("UpCloud returned a malformed user inventory.")
        if len(payload) > MAX_ITEMS:
            raise HarnessError("UpCloud user inventory exceeded the safety bound.")
        return payload

    def _user_read(self, service_id: str, username: str) -> dict | None:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}",
            allow_not_found=True,
        )
        return payload if isinstance(payload, dict) else None

    def _user_owned(self, user: dict, username: str) -> bool:
        arn = str(user.get("arn") or "") if isinstance(user, dict) else ""
        return bool(
            isinstance(user, dict)
            and str(user.get("username") or "") == username
            and (not arn or arn.endswith(f":user/{username}"))
        )

    def _record_user(self, service_id: str, user: dict, request: dict) -> dict:
        username = self.names["username"]
        if not self._user_owned(user, username):
            raise HarnessError("UpCloud Object Storage user ownership failed.")
        return self.ledger.record(
            kind="mos_user",
            resource_id=f"{service_id}:{username}",
            name=username,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": service_id,
                "username": username,
                "arn": str(user.get("arn") or ""),
                "request_fingerprint": _fingerprint(request),
            },
            source_witness=service_id,
        )

    def ensure_user(self, service: dict) -> dict:
        service_id = str(service.get("uuid") or "")
        username = self.names["username"]
        request = {"username": username}
        fingerprint = _fingerprint(request)
        entry = self._one_active("mos_user")
        candidate = self._exact_name(self._users(service_id), "username", username)
        if entry:
            candidate = self._user_read(service_id, username)
            if not self._user_owned(candidate or {}, username):
                raise HarnessError("The ledgered UpCloud user ownership changed.")
            return candidate
        intent_key = "mos_user_create"
        intent = self.intents.get(intent_key)
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("request_fingerprint") == fingerprint
            and intent.get("service_uuid") == service_id
            and intent.get("preflight_absent") is True
        )
        if candidate:
            if not intent_matches:
                raise HarnessError("An unledgered UpCloud user matches the run name.")
            candidate = self._user_read(service_id, username)
            self._record_user(service_id, candidate or {}, request)
            self.intents.clear(intent_key)
            return candidate
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior UpCloud user create is not visible; no duplicate was sent."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "mos_user",
                "name": username,
                "operation": "create",
                "service_uuid": service_id,
                "request_fingerprint": fingerprint,
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "POST",
            f"/object-storage-2/{quote(service_id, safe='')}/users",
            accepted=(201,),
            json_body=request,
        )
        candidate = self._user_read(service_id, username)
        if not candidate:
            raise AmbiguousMutation(
                "UpCloud accepted the user create but exact read-back is incomplete."
            )
        self._record_user(service_id, candidate, request)
        self.intents.clear(intent_key)
        return candidate

    def _inline_policies(self, service_id: str, username: str) -> list[dict]:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/inline-policies",
        )
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise HarnessError("UpCloud returned a malformed inline-policy inventory.")
        if len(payload) > MAX_ITEMS:
            raise HarnessError("UpCloud inline-policy inventory exceeded the safety bound.")
        return payload

    def _policy_read(
        self, service_id: str, username: str, policy_name: str
    ) -> dict | None:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/inline-policies/"
            f"{quote(policy_name, safe='')}",
            allow_not_found=True,
        )
        return payload if isinstance(payload, dict) else None

    def _policy_request(self) -> dict:
        document = _canonical(
            _policy_document(self.names["bucket"], self.names["prefix"])
        )
        return {
            "name": self.names["policy"],
            # The control-plane JSON request carries the policy as a JSON
            # string. UpCloud may URL-encode the returned representation, so
            # ownership normalization accepts both forms, but encoding the
            # request string itself is rejected by the live API.
            "document": document,
        }

    def _policy_owned(self, policy: dict, request: dict) -> bool:
        if not isinstance(policy, dict):
            return False
        try:
            actual = _normalized_policy(policy.get("document"))
            expected = _normalized_policy(request["document"])
        except HarnessError:
            return False
        return (
            str(policy.get("name") or "") == self.names["policy"]
            and actual == expected
        )

    def _record_policy(
        self, service_id: str, username: str, policy: dict, request: dict
    ) -> dict:
        if not self._policy_owned(policy, request):
            raise HarnessError("UpCloud inline-policy ownership verification failed.")
        return self.ledger.record(
            kind="mos_inline_policy",
            resource_id=f"{service_id}:{username}:{self.names['policy']}",
            name=self.names["policy"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": service_id,
                "username": username,
                "policy_name": self.names["policy"],
                "document_sha256": _hash(_normalized_policy(request["document"])),
                "request_fingerprint": _fingerprint(request),
            },
            source_witness=f"{service_id}:{username}",
        )

    def ensure_policy(self, service: dict, user: dict) -> dict:
        service_id = str(service.get("uuid") or "")
        username = str(user.get("username") or "")
        request = self._policy_request()
        fingerprint = _fingerprint(request)
        entry = self._one_active("mos_inline_policy")
        candidate = self._exact_name(
            self._inline_policies(service_id, username),
            "name",
            self.names["policy"],
        )
        if entry:
            candidate = self._policy_read(
                service_id, username, self.names["policy"]
            )
            if not self._policy_owned(candidate or {}, request):
                raise HarnessError("The ledgered UpCloud inline policy changed.")
            return candidate
        intent_key = "mos_inline_policy_create"
        intent = self.intents.get(intent_key)
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("request_fingerprint") == fingerprint
            and intent.get("service_uuid") == service_id
            and intent.get("username") == username
            and intent.get("preflight_absent") is True
        )
        if candidate:
            if not intent_matches:
                raise HarnessError(
                    "An unledgered inline policy matches the run-owned name."
                )
            candidate = self._policy_read(
                service_id, username, self.names["policy"]
            )
            self._record_policy(service_id, username, candidate or {}, request)
            self.intents.clear(intent_key)
            return candidate
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior inline-policy create is not visible; no duplicate was sent."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "mos_inline_policy",
                "name": self.names["policy"],
                "operation": "create",
                "service_uuid": service_id,
                "username": username,
                "request_fingerprint": fingerprint,
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "POST",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/inline-policies",
            accepted=(201,),
            json_body=request,
        )
        candidate = self._policy_read(service_id, username, self.names["policy"])
        if not candidate:
            raise AmbiguousMutation(
                "UpCloud accepted the inline policy but exact read-back is incomplete."
            )
        self._record_policy(service_id, username, candidate, request)
        self.intents.clear(intent_key)
        return candidate

    def _access_keys(self, service_id: str, username: str) -> list[dict]:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/access-keys",
        )
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise HarnessError("UpCloud returned a malformed access-key inventory.")
        if len(payload) > 2:
            raise HarnessError("The run-owned user has an excessive access-key inventory.")
        return payload

    def _access_key_read(
        self, service_id: str, username: str, access_key: str
    ) -> dict | None:
        payload = self.control.request(
            "GET",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/access-keys/"
            f"{quote(access_key, safe='')}",
            allow_not_found=True,
        )
        return payload if isinstance(payload, dict) else None

    def _runtime_payload(
        self,
        *,
        service: dict,
        access_key: str,
        secret_key: str,
    ) -> dict:
        return {
            "schema": RUNTIME_SCHEMA,
            "provider": "upcloud",
            "run_id": self.config.run_id,
            "account": self.account,
            "service_uuid": str(service.get("uuid") or ""),
            "region": self.config.region,
            "endpoint": _public_endpoint(service),
            "bucket_name": self.names["bucket"],
            "prefix": self.names["prefix"],
            "username": self.names["username"],
            "policy_name": self.names["policy"],
            "access_key": str(access_key),
            "secret_key": str(secret_key),
        }

    def _validate_runtime(self, payload: dict, service: dict) -> dict:
        expected = {
            "schema": RUNTIME_SCHEMA,
            "provider": "upcloud",
            "run_id": self.config.run_id,
            "account": self.account,
            "service_uuid": str(service.get("uuid") or ""),
            "region": self.config.region,
            "endpoint": _public_endpoint(service),
            "bucket_name": self.names["bucket"],
            "prefix": self.names["prefix"],
            "username": self.names["username"],
            "policy_name": self.names["policy"],
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise HarnessError(
                "The protected Object Storage credentials do not match this exact run."
            )
        return payload

    def _record_access_key(
        self,
        service_id: str,
        username: str,
        access_key: dict,
    ) -> dict:
        key_id = str(access_key.get("access_key_id") or "")
        status_value = str(access_key.get("status") or "")
        if not key_id or status_value != "Active":
            raise HarnessError("UpCloud access-key ownership verification failed.")
        key_hash = _hash(key_id)
        return self.ledger.record(
            kind="mos_access_key",
            resource_id=key_hash,
            name="run-owned-access-key",
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": service_id,
                "username": username,
                "access_key_sha256": key_hash,
                "status": "Active",
            },
            source_witness=f"{service_id}:{username}",
        )

    def ensure_access_key(self, service: dict, user: dict) -> dict:
        service_id = str(service.get("uuid") or "")
        username = str(user.get("username") or "")
        entry = self._one_active("mos_access_key")
        keys = self._access_keys(service_id, username)
        if len(keys) > 1:
            raise HarnessError(
                "The run-owned UpCloud user has duplicate access keys."
            )
        candidate = keys[0] if keys else None
        intent_key = "mos_access_key_create"
        intent = self.intents.get(intent_key)
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("service_uuid") == service_id
            and intent.get("username") == username
            and intent.get("preflight_absent") is True
        )
        if candidate:
            key_id = str(candidate.get("access_key_id") or "")
            exact = self._access_key_read(service_id, username, key_id)
            if not exact:
                raise AmbiguousMutation(
                    "The listed UpCloud access key is not exactly readable."
                )
            key_hash = _hash(key_id)
            if entry and entry.get("resource_id") != key_hash:
                raise HarnessError("The ledgered UpCloud access-key identity changed.")
            if not entry and not intent_matches:
                raise HarnessError(
                    "An unledgered access key exists on the run-owned user."
                )
            self._record_access_key(service_id, username, exact)
            try:
                runtime = _read_runtime_secret(self.config.runtime_path)
            except SecretUnavailable:
                raise SecretUnavailable(
                    "The exact run-owned access key exists, but UpCloud exposes its "
                    "secret only once. Run exact cleanup; do not create a duplicate key."
                ) from None
            self._validate_runtime(runtime, service)
            if runtime["access_key"] != key_id:
                raise HarnessError("The runtime access key does not match the ledger.")
            if intent_matches:
                self.intents.clear(intent_key)
            return runtime
        if entry:
            raise HarnessError("The ledgered UpCloud access key is no longer visible.")
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior access-key create is not visible; no duplicate was sent."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "mos_access_key",
                "name": "run-owned-access-key",
                "operation": "create",
                "service_uuid": service_id,
                "username": username,
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        payload = self._control_mutation(
            intent_key,
            "POST",
            f"/object-storage-2/{quote(service_id, safe='')}/users/"
            f"{quote(username, safe='')}/access-keys",
            accepted=(201,),
        )
        created = payload.get("access_key") if isinstance(payload, dict) else None
        if not isinstance(created, dict):
            created = payload if isinstance(payload, dict) else {}
        key_id = str(created.get("access_key_id") or "")
        secret_key = str(created.get("secret_access_key") or "")
        if not key_id or not secret_key:
            raise AmbiguousMutation(
                "UpCloud accepted the access-key create without recoverable credentials."
            )
        runtime = self._runtime_payload(
            service=service, access_key=key_id, secret_key=secret_key
        )
        # The one-time secret becomes durable before any non-secret read-back.
        _write_runtime_secret(self.config.runtime_path, runtime)
        exact = self._access_key_read(service_id, username, key_id)
        if not exact:
            raise AmbiguousMutation(
                "UpCloud accepted the access key but exact read-back is incomplete."
            )
        self._record_access_key(service_id, username, exact)
        self.intents.clear(intent_key)
        return runtime

    def setup_object_storage(self) -> dict:
        self._require_apply()
        self._require_object_storage_config()
        self.verify_account()
        service = self.wait_service_ready(self.ensure_service())
        self.ensure_bucket(service)
        user = self.ensure_user(service)
        self.ensure_policy(service, user)
        self.ensure_access_key(service, user)
        return {
            "status": "ready_for_ui_storage_configuration",
            "service_uuid": str(service.get("uuid") or ""),
            "bucket_name": self.names["bucket"],
            "endpoint": _public_endpoint(service),
            "prefix": self.names["prefix"],
            "credentials_file": str(self.config.runtime_path),
            "versioning": "not_enabled_until_arm_object_storage",
            "ui_no_delete": False,
        }

    def _s3(self, service: dict):
        runtime = self._validate_runtime(
            _read_runtime_secret(self.config.runtime_path), service
        )
        key_entry = self._one_active("mos_access_key")
        if (
            not key_entry
            or key_entry["resource_id"] != _hash(runtime["access_key"])
        ):
            raise HarnessError("The runtime access key lacks an exact ledger witness.")
        return self.s3_factory(runtime), runtime

    @staticmethod
    def _advance_cursor(current, following, label):
        if following in (None, "") or following == current:
            raise HarnessError(f"UpCloud returned a non-advancing {label} cursor.")
        return following

    def _s3_inventory(self, client, bucket: str, prefix: str) -> dict:
        if not isinstance(prefix, str) or prefix != self.names["prefix"]:
            raise HarnessError(
                "S3 inventory requires the exact active BackupSheep run prefix."
            )
        versions = []
        delete_markers = []
        key_marker = None
        version_marker = None
        for _ in range(MAX_PAGES):
            args = {"Bucket": bucket, "Prefix": prefix}
            if key_marker:
                args["KeyMarker"] = key_marker
            if version_marker:
                args["VersionIdMarker"] = version_marker
            page = _s3_call(lambda args=args: client.list_object_versions(**args))
            if not isinstance(page, dict):
                raise HarnessError("UpCloud returned malformed object versions.")
            page_versions = page.get("Versions") or []
            page_markers = page.get("DeleteMarkers") or []
            if any(not isinstance(item, dict) for item in page_versions + page_markers):
                raise HarnessError("UpCloud returned malformed object versions.")
            versions.extend(page_versions)
            delete_markers.extend(page_markers)
            if len(versions) + len(delete_markers) > MAX_ITEMS:
                raise HarnessError("Object version inventory exceeded the safety bound.")
            if not page.get("IsTruncated"):
                break
            next_pair = (
                page.get("NextKeyMarker"),
                page.get("NextVersionIdMarker"),
            )
            if next_pair == (key_marker, version_marker) or not next_pair[0]:
                raise HarnessError("UpCloud returned a non-advancing version cursor.")
            key_marker, version_marker = next_pair
        else:
            raise HarnessError("Object version inventory exceeded the page bound.")

        objects = []
        continuation = None
        for _ in range(MAX_PAGES):
            args = {"Bucket": bucket, "Prefix": prefix}
            if continuation:
                args["ContinuationToken"] = continuation
            page = _s3_call(lambda args=args: client.list_objects_v2(**args))
            if not isinstance(page, dict):
                raise HarnessError("UpCloud returned malformed object inventory.")
            rows = page.get("Contents") or []
            if any(not isinstance(item, dict) for item in rows):
                raise HarnessError("UpCloud returned malformed object inventory.")
            objects.extend(rows)
            if len(objects) > MAX_ITEMS:
                raise HarnessError("Object inventory exceeded the safety bound.")
            if not page.get("IsTruncated"):
                break
            continuation = self._advance_cursor(
                continuation, page.get("NextContinuationToken"), "object"
            )
        else:
            raise HarnessError("Object inventory exceeded the page bound.")

        uploads = []
        key_marker = None
        upload_marker = None
        for _ in range(MAX_PAGES):
            args = {"Bucket": bucket, "Prefix": prefix}
            if key_marker:
                args["KeyMarker"] = key_marker
            if upload_marker:
                args["UploadIdMarker"] = upload_marker
            page = _s3_call(lambda args=args: client.list_multipart_uploads(**args))
            if not isinstance(page, dict):
                raise HarnessError("UpCloud returned malformed multipart inventory.")
            rows = page.get("Uploads") or []
            if any(not isinstance(item, dict) for item in rows):
                raise HarnessError("UpCloud returned malformed multipart inventory.")
            uploads.extend(rows)
            if len(uploads) > MAX_ITEMS:
                raise HarnessError("Multipart inventory exceeded the safety bound.")
            if not page.get("IsTruncated"):
                break
            next_pair = (page.get("NextKeyMarker"), page.get("NextUploadIdMarker"))
            if next_pair == (key_marker, upload_marker) or not all(next_pair):
                raise HarnessError("UpCloud returned a non-advancing multipart cursor.")
            key_marker, upload_marker = next_pair
        else:
            raise HarnessError("Multipart inventory exceeded the page bound.")
        return {
            "versions": versions,
            "delete_markers": delete_markers,
            "objects": objects,
            "multipart_uploads": uploads,
        }

    @staticmethod
    def _inventory_empty(inventory: dict) -> bool:
        return not any(inventory.get(key) for key in inventory)

    @staticmethod
    def _head_object(client, bucket: str, key: str, version_id: str):
        args = {"Bucket": bucket, "Key": key}
        if version_id:
            args["VersionId"] = version_id
        return _s3_call(
            lambda: client.head_object(**args), allow_not_found=True
        )

    @staticmethod
    def _stream_identity(
        client, bucket: str, key: str, version_id: str, maximum_bytes: int
    ) -> tuple[str, int]:
        args = {"Bucket": bucket, "Key": key}
        if version_id:
            args["VersionId"] = version_id
        response = _s3_call(lambda: client.get_object(**args))
        if not isinstance(response, dict) or "Body" not in response:
            raise HarnessError("UpCloud returned a malformed object body.")
        body = response["Body"]
        digest = hashlib.sha256()
        count = 0
        try:
            while True:
                chunk = body.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > maximum_bytes:
                    raise HarnessError(
                        "The object exceeded the explicit verification byte bound."
                    )
                digest.update(chunk)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        return digest.hexdigest(), count

    def _record_object(
        self,
        *,
        kind: str,
        bucket: str,
        key: str,
        version_id: str,
        sha256: str,
        byte_count: int,
        etag: str,
        backup_id: str,
        metadata: dict,
        backup_uuid: str = "",
    ) -> dict:
        if kind not in OBJECT_LEDGER_KINDS:
            raise HarnessError("The UpCloud object ledger kind is invalid.")
        if not version_id or version_id == "null":
            raise HarnessError("A non-null object version ID is required for live acceptance.")
        resource_id = _hash(f"{bucket}\0{key}\0{version_id}")
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=key,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "bucket": bucket,
                "key": key,
                "version_id": version_id,
                "sha256": sha256,
                "byte_count": int(byte_count),
                "etag": _etag(etag),
                "backup_id": backup_id,
                "backup_uuid": backup_uuid,
                "metadata": dict(metadata),
            },
            source_witness=(
                f"{bucket}:{kind}:{backup_uuid or backup_id or self.config.run_id}"
                f":{backup_id}"
            ),
        )

    def _exact_key_versions(self, inventory: dict, key: str) -> list[dict]:
        return [
            item
            for item in inventory.get("versions") or []
            if str(item.get("Key") or "") == key
        ]

    def arm_object_storage(self) -> dict:
        """Enable versioning only after the UI probe leaves the exact run prefix."""
        self._require_apply()
        self._require_object_storage_config()
        self.verify_account()
        service_entry = self._one_active("mos_service")
        if not service_entry:
            raise HarnessError("Run setup-object-storage before arming the bucket.")
        service = self._service_read(service_entry["resource_id"])
        if not self._service_owned(service or {}, resource_id=service_entry["resource_id"]):
            raise HarnessError("The run-owned UpCloud service ownership changed.")
        client, runtime = self._s3(service)
        bucket = runtime["bucket_name"]
        inventory = self._s3_inventory(client, bucket, runtime["prefix"])
        if not self._inventory_empty(inventory):
            raise InventoryNotEmpty(
                "The exact run prefix is not empty. Arming refused so a UI validation "
                "probe or unledgered object cannot become an untracked version."
            )

        versioning_key = "mos_bucket_versioning_enable"
        versioning_request = {"bucket": bucket, "status": "Enabled"}
        current = _s3_call(lambda: client.get_bucket_versioning(Bucket=bucket))
        status_value = str(current.get("Status") or "") if isinstance(current, dict) else ""
        config_entry = self._one_active("mos_bucket_configuration")
        if status_value == "Enabled" and not (
            config_entry
            or (
                self.intents.get(versioning_key)
                and self.intents.get(versioning_key).get("request_boundary_crossed")
            )
        ):
            raise HarnessError(
                "Bucket versioning was enabled without this run's durable intent."
            )
        if status_value != "Enabled":
            self.intents.put(
                versioning_key,
                {
                    "marker": self.config.run_id,
                    "kind": "mos_bucket_configuration",
                    "name": bucket,
                    "operation": "enable-versioning",
                    "request_fingerprint": _fingerprint(versioning_request),
                },
            )
            self.intents.update(versioning_key, request_boundary_crossed=True)
            try:
                self._s3_mutation(
                    versioning_key,
                    lambda: client.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={"Status": "Enabled"},
                    ),
                )
            except AmbiguousMutation:
                observed = _s3_call(
                    lambda: client.get_bucket_versioning(Bucket=bucket)
                )
                if not isinstance(observed, dict) or observed.get("Status") != "Enabled":
                    raise
            current = _s3_call(lambda: client.get_bucket_versioning(Bucket=bucket))
            if not isinstance(current, dict) or current.get("Status") != "Enabled":
                raise AmbiguousMutation(
                    "Bucket versioning did not reach the exact enabled state."
                )
        self.ledger.record(
            kind="mos_bucket_configuration",
            resource_id=f"{service_entry['resource_id']}:{bucket}:versioning",
            name=bucket,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "service_uuid": service_entry["resource_id"],
                "bucket": bucket,
                "versioning": "Enabled",
                "provenance": "intent_applied",
                "request_fingerprint": _fingerprint(versioning_request),
            },
            source_witness=f"{service_entry['resource_id']}:{bucket}",
        )
        if self.intents.get(versioning_key):
            self.intents.clear(versioning_key)

        marker_key = f"{runtime['prefix']}.backupsheep-e2e-ownership.bin"
        marker_body = (
            "BackupSheep UpCloud MOS ownership witness v1\n"
            + _hash(f"{self.account}:{self.config.run_id}:{bucket}")
            + "\n"
        ).encode("ascii")
        marker_sha = hashlib.sha256(marker_body).hexdigest()
        marker_metadata = {
            "backupsheep-run": self.config.run_id,
            "backupsheep-sha256": marker_sha,
            "backupsheep-bytes": str(len(marker_body)),
        }
        marker_intent_key = "mos_ownership_object_create"
        marker_request = {
            "bucket": bucket,
            "key": marker_key,
            "sha256": marker_sha,
            "byte_count": len(marker_body),
            "metadata": marker_metadata,
        }
        inventory = self._s3_inventory(client, bucket, runtime["prefix"])
        candidates = self._exact_key_versions(inventory, marker_key)
        marker_entry = self._one_active("mos_ownership_object")
        if len(candidates) > 1:
            raise HarnessError("Multiple ownership-marker versions were found.")
        if candidates and not (
            marker_entry
            or (
                self.intents.get(marker_intent_key)
                and self.intents.get(marker_intent_key).get("request_boundary_crossed")
                and self.intents.get(marker_intent_key).get("request_fingerprint")
                == _fingerprint(marker_request)
            )
        ):
            raise HarnessError("An unledgered ownership marker already exists.")
        if not candidates:
            if (
                self.intents.get(marker_intent_key)
                and self.intents.get(marker_intent_key).get("request_boundary_crossed")
            ):
                raise AmbiguousMutation(
                    "A prior ownership-marker upload is not visible; no duplicate was sent."
                )
            self.intents.put(
                marker_intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": "mos_ownership_object",
                    "name": marker_key,
                    "operation": "put-object",
                    "request_fingerprint": _fingerprint(marker_request),
                },
            )
            self.intents.update(marker_intent_key, request_boundary_crossed=True)
            try:
                self._s3_mutation(
                    marker_intent_key,
                    lambda: client.put_object(
                        Bucket=bucket,
                        Key=marker_key,
                        Body=marker_body,
                        Metadata=marker_metadata,
                    ),
                )
            except AmbiguousMutation:
                pass
            candidates = self._exact_key_versions(
                self._s3_inventory(client, bucket, runtime["prefix"]), marker_key
            )
            if len(candidates) != 1:
                raise AmbiguousMutation(
                    "Ownership-marker upload lacks one exact provider version."
                )
        candidate = candidates[0]
        version_id = str(candidate.get("VersionId") or "")
        head = self._head_object(client, bucket, marker_key, version_id)
        if not isinstance(head, dict):
            raise AmbiguousMutation("The ownership-marker version is not readable.")
        observed_sha, observed_bytes = self._stream_identity(
            client, bucket, marker_key, version_id, len(marker_body)
        )
        metadata = head.get("Metadata") or {}
        if (
            observed_sha != marker_sha
            or observed_bytes != len(marker_body)
            or int(head.get("ContentLength") or -1) != len(marker_body)
            or any(
                str(metadata.get(key) or "") != value
                for key, value in marker_metadata.items()
            )
        ):
            raise HarnessError("The ownership-marker content or metadata changed.")
        self._record_object(
            kind="mos_ownership_object",
            bucket=bucket,
            key=marker_key,
            version_id=version_id,
            sha256=marker_sha,
            byte_count=len(marker_body),
            etag=head.get("ETag"),
            backup_id="",
            backup_uuid="",
            metadata=marker_metadata,
        )
        if self.intents.get(marker_intent_key):
            self.intents.clear(marker_intent_key)
        return {
            "status": "armed_for_versioned_ui_backups",
            "service_uuid": service_entry["resource_id"],
            "bucket_name": bucket,
            "prefix": runtime["prefix"],
            "versioning": "Enabled",
        }

    def _validate_bucket_configuration(
        self, entry: dict, *, service_entry: dict, bucket: str
    ) -> dict:
        ownership = dict((entry or {}).get("ownership") or {})
        service_id = str(service_entry.get("resource_id") or "")
        expected_id = f"{service_id}:{bucket}:versioning"
        provenance = str(ownership.get("provenance") or "")
        common_valid = all(
            (
                entry.get("resource_id") == expected_id,
                entry.get("name") == bucket,
                entry.get("source_witness") == f"{service_id}:{bucket}",
                ownership.get("account") == self.account,
                ownership.get("run_id") == self.config.run_id,
                ownership.get("service_uuid") == service_id,
                ownership.get("bucket") == bucket,
                ownership.get("versioning") == "Enabled",
                provenance in {"intent_applied", "observed_existing"},
            )
        )
        if not common_valid:
            raise HarnessError("The UpCloud bucket configuration witness is malformed.")
        if provenance == "intent_applied":
            if set(ownership) != {
                "account",
                "run_id",
                "service_uuid",
                "bucket",
                "versioning",
                "provenance",
                "request_fingerprint",
            }:
                raise HarnessError("The UpCloud bucket mutation witness has extra fields.")
            request = {"bucket": bucket, "status": "Enabled"}
            if ownership.get("request_fingerprint") != _fingerprint(request):
                raise HarnessError("The UpCloud bucket mutation witness changed.")
        else:
            if set(ownership) != {
                "account",
                "run_id",
                "service_uuid",
                "bucket",
                "versioning",
                "provenance",
                "request_fingerprint",
                "observation_fingerprint",
                "ownership_marker",
            }:
                raise HarnessError("The UpCloud bucket observation witness has extra fields.")
            if ownership.get("request_fingerprint") not in (None, ""):
                raise HarnessError("Observed bucket evidence must not invent a request fingerprint.")
            observation = {
                "service_uuid": service_id,
                "bucket": bucket,
                "versioning": "Enabled",
                "provenance": "observed_existing",
            }
            if ownership.get("observation_fingerprint") != _fingerprint(observation):
                raise HarnessError("The UpCloud bucket observation witness changed.")
        return ownership

    def _ownership_marker_contract(self, bucket: str, prefix: str) -> dict:
        key = f"{prefix}.backupsheep-e2e-ownership.bin"
        body = (
            "BackupSheep UpCloud MOS ownership witness v1\n"
            + _hash(f"{self.account}:{self.config.run_id}:{bucket}")
            + "\n"
        ).encode("ascii")
        return {
            "key": key,
            "body": body,
            "sha256": hashlib.sha256(body).hexdigest(),
            "byte_count": len(body),
            "metadata": {
                "backupsheep-run": self.config.run_id,
                "backupsheep-sha256": hashlib.sha256(body).hexdigest(),
                "backupsheep-bytes": str(len(body)),
            },
        }

    def reconcile_object_storage_evidence(self) -> dict:
        """Adopt fresh read-only versioning/marker evidence for an exact owned bucket."""

        self._require_object_storage_config()
        self.verify_account()
        service_entry = self._one_active("mos_service")
        bucket_entry = self._one_active("mos_bucket")
        if service_entry is None or bucket_entry is None:
            raise HarnessError("Object evidence reconciliation requires exact service and bucket witnesses.")
        service_id = str(service_entry["resource_id"])
        service = self._service_read(service_id)
        if not self._service_owned(service or {}, resource_id=service_id):
            raise HarnessError("The run-owned UpCloud service ownership changed.")
        bucket_ownership = dict(bucket_entry.get("ownership") or {})
        if any(
            (
                bucket_entry.get("resource_id") != f"{service_id}:{self.names['bucket']}",
                bucket_entry.get("name") != self.names["bucket"],
                bucket_entry.get("source_witness") != service_id,
                bucket_ownership.get("account") != self.account,
                bucket_ownership.get("run_id") != self.config.run_id,
                bucket_ownership.get("service_uuid") != service_id,
                bucket_ownership.get("bucket_name") != self.names["bucket"],
                bucket_ownership.get("prefix") != self.names["prefix"],
                bucket_ownership.get("request_fingerprint")
                != _fingerprint(self._bucket_request()),
            )
        ):
            raise HarnessError("The run-owned UpCloud bucket witness changed.")
        bucket = self._exact_name(self._buckets(service_id), "name", self.names["bucket"])
        if bucket is None:
            raise HarnessError("The exact run-owned UpCloud bucket is not present.")
        client, runtime = self._s3(service)
        if runtime["bucket_name"] != self.names["bucket"] or runtime["prefix"] != self.names["prefix"]:
            raise HarnessError("The protected runtime bucket scope changed.")
        versioning = _s3_call(
            lambda: client.get_bucket_versioning(Bucket=runtime["bucket_name"])
        )
        if not isinstance(versioning, dict) or versioning.get("Status") != "Enabled":
            raise HarnessError("The exact run-owned bucket is not currently versioned.")

        contract = self._ownership_marker_contract(
            runtime["bucket_name"], runtime["prefix"]
        )
        inventory = self._s3_inventory(
            client, runtime["bucket_name"], runtime["prefix"]
        )
        marker_versions = self._exact_key_versions(inventory, contract["key"])
        marker_deletes = [
            item
            for item in inventory.get("delete_markers") or []
            if str(item.get("Key") or "") == contract["key"]
        ]
        if len(marker_versions) + len(marker_deletes) > 1:
            raise HarnessError("Multiple exact UpCloud ownership-marker versions were found.")
        if marker_deletes:
            raise HarnessError("The exact UpCloud ownership marker was replaced by a delete marker.")
        candidates = marker_versions
        marker_entry = self._one_active("mos_ownership_object")
        if marker_entry is not None and not candidates:
            raise HarnessError("The ledgered UpCloud ownership marker disappeared.")
        marker_status = "absent"
        if candidates:
            version_id = str(candidates[0].get("VersionId") or "")
            if not version_id or version_id == "null":
                raise HarnessError("The UpCloud ownership marker lacks a version ID.")
            head = self._head_object(
                client, runtime["bucket_name"], contract["key"], version_id
            )
            if not isinstance(head, dict):
                raise HarnessError("The exact UpCloud ownership marker is unreadable.")
            observed_sha, observed_bytes = self._stream_identity(
                client,
                runtime["bucket_name"],
                contract["key"],
                version_id,
                contract["byte_count"],
            )
            metadata = head.get("Metadata") or {}
            if any(
                (
                    observed_sha != contract["sha256"],
                    observed_bytes != contract["byte_count"],
                    int(head.get("ContentLength") or -1) != contract["byte_count"],
                    any(
                        str(metadata.get(key) or "") != value
                        for key, value in contract["metadata"].items()
                    ),
                )
            ):
                raise HarnessError("The exact UpCloud ownership marker changed.")
            if marker_entry is None:
                self._record_object(
                    kind="mos_ownership_object",
                    bucket=runtime["bucket_name"],
                    key=contract["key"],
                    version_id=version_id,
                    sha256=contract["sha256"],
                    byte_count=contract["byte_count"],
                    etag=head.get("ETag"),
                    backup_id="",
                    metadata=contract["metadata"],
                )
            else:
                self._verify_object_entry(client, marker_entry, contract["byte_count"])
            marker_status = "verified"

        config_entry = self._one_active("mos_bucket_configuration")
        if config_entry is None:
            observation = {
                "service_uuid": service_id,
                "bucket": runtime["bucket_name"],
                "versioning": "Enabled",
                "provenance": "observed_existing",
            }
            config_entry = self.ledger.record(
                kind="mos_bucket_configuration",
                resource_id=f"{service_id}:{runtime['bucket_name']}:versioning",
                name=runtime["bucket_name"],
                ownership={
                    "account": self.account,
                    "run_id": self.config.run_id,
                    **observation,
                    "request_fingerprint": "",
                    "observation_fingerprint": _fingerprint(observation),
                    "ownership_marker": marker_status,
                },
                source_witness=f"{service_id}:{runtime['bucket_name']}",
            )
        self._validate_bucket_configuration(
            config_entry,
            service_entry=service_entry,
            bucket=runtime["bucket_name"],
        )
        config_ownership = config_entry.get("ownership") or {}
        if (
            config_ownership.get("provenance") == "observed_existing"
            and config_ownership.get("ownership_marker") != marker_status
        ):
            raise HarnessError("The observed UpCloud ownership-marker state changed.")
        return {
            "status": "verified",
            "service_uuid": service_id,
            "bucket_name": runtime["bucket_name"],
            "prefix": runtime["prefix"],
            "versioning": "Enabled",
            "configuration_provenance": (config_entry.get("ownership") or {}).get(
                "provenance"
            ),
            "ownership_marker": marker_status,
        }

    def verify_ui_objects(self, manifest_path: str, *, maximum_bytes: int) -> dict:
        if maximum_bytes < 1 or maximum_bytes > 1024**4:
            raise HarnessError("The object verification byte bound is invalid.")
        generation = self._load_generation(manifest_path, kind="object")
        manifest = generation["manifest"]
        if manifest.get("run_id") != self.config.run_id:
            raise HarnessError(
                "The UI object manifest run_id does not match this harness run."
            )
        rows = manifest.get("objects") if isinstance(manifest, dict) else None
        if (
            not isinstance(rows, list)
            or len(rows) != len(UI_OBJECT_KINDS)
            or any(not isinstance(row, dict) for row in rows)
            or sorted(str(row.get("kind") or "") for row in rows)
            != sorted(UI_OBJECT_KINDS)
        ):
            raise HarnessError(
                "The UI object manifest must contain exactly one website and "
                "one database object."
            )

        self._require_object_storage_config()
        self.verify_account()
        service_entry = self._one_active("mos_service")
        config_entry = self._one_active("mos_bucket_configuration")
        if not service_entry or not config_entry:
            raise HarnessError("The exact bucket must be armed before UI verification.")
        service = self._service_read(service_entry["resource_id"])
        if not self._service_owned(service or {}, resource_id=service_entry["resource_id"]):
            raise HarnessError("The run-owned UpCloud service ownership changed.")
        client, runtime = self._s3(service)
        self._validate_bucket_configuration(
            config_entry,
            service_entry=service_entry,
            bucket=runtime["bucket_name"],
        )
        versioning = _s3_call(
            lambda: client.get_bucket_versioning(Bucket=runtime["bucket_name"])
        )
        if not isinstance(versioning, dict) or versioning.get("Status") != "Enabled":
            raise HarnessError("The exact UpCloud bucket is no longer versioned.")
        seen = set()
        seen_keys = set()
        verified = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != UI_OBJECT_ROW_KEYS:
                raise HarnessError("The UI object manifest contains a malformed row.")
            object_kind = str(row.get("kind") or "")
            kind = UI_OBJECT_KINDS.get(object_kind)
            backup_id = self._manifest_backup_row_id(
                row.get("backup_id"), "backup_id"
            )
            backup_uuid = _safe_backup_object_id(row.get("backup_uuid"))
            storage_point_id = self._manifest_backup_row_id(
                row.get("storage_point_id"), "storage_point_id"
            )
            storage_id = self._manifest_backup_row_id(
                row.get("storage_id"), "storage_id"
            )
            artifact_id = self._manifest_backup_row_id(
                row.get("artifact_id"), "artifact_id"
            )
            artifact_status = str(row.get("artifact_status") or "")
            key = str(row.get("object_key") or "")
            sha256 = str(row.get("sha256") or "").casefold()
            version_id = str(row.get("version_id") or "")
            etag = _etag(row.get("etag"))
            byte_count = row.get("byte_count")
            if type(byte_count) is not int:
                raise HarnessError("A UI object byte count is malformed.")
            identity = (object_kind, backup_id, backup_uuid)
            if (
                not kind
                or artifact_status != "verified"
                or identity in seen
                or key in seen_keys
                or key != f"{runtime['prefix']}{backup_uuid}.zip"
                or not SHA256_RE.fullmatch(sha256)
                or byte_count < 1
                or byte_count > maximum_bytes
                or not etag
                or not version_id
                or version_id == "null"
            ):
                raise HarnessError("A UI object witness is incomplete or out of scope.")
            seen.add(identity)
            seen_keys.add(key)
            inventory = self._s3_inventory(
                client, runtime["bucket_name"], runtime["prefix"]
            )
            candidates = self._exact_key_versions(inventory, key)
            if len(candidates) != 1 or str(candidates[0].get("VersionId") or "") != version_id:
                raise HarnessError(
                    "The UI object has a missing or duplicate exact provider version."
                )
            head = self._head_object(
                client, runtime["bucket_name"], key, version_id
            )
            if not isinstance(head, dict):
                raise HarnessError("The exact UI object version is not readable.")
            metadata = head.get("Metadata") or {}
            expected_metadata = {
                "backupsheep-sha256": sha256,
                "backupsheep-bytes": str(byte_count),
                "backupsheep-backup-id": str(backup_id),
            }
            observed_sha, observed_bytes = self._stream_identity(
                client,
                runtime["bucket_name"],
                key,
                version_id,
                maximum_bytes,
            )
            if (
                int(head.get("ContentLength") or -1) != byte_count
                or _etag(head.get("ETag")) != etag
                or str(head.get("VersionId") or "") != version_id
                or observed_sha != sha256
                or observed_bytes != byte_count
                or any(
                    str(metadata.get(name) or "") != value
                    for name, value in expected_metadata.items()
                )
            ):
                raise HarnessError(
                    "The UI object bytes or persisted BackupSheep metadata do not match."
                )
            self._record_object(
                kind=kind,
                bucket=runtime["bucket_name"],
                key=key,
                version_id=version_id,
                sha256=sha256,
                byte_count=byte_count,
                etag=etag,
                backup_id=backup_id,
                backup_uuid=backup_uuid,
                metadata=expected_metadata,
            )
            entry = self.ledger.get(kind, _hash(f"{runtime['bucket_name']}\0{key}\0{version_id}"))
            ownership = dict((entry or {}).get("ownership") or {})
            ownership["durable_binding"] = {
                "storage_point_id": storage_point_id,
                "storage_id": storage_id,
                "artifact_id": artifact_id,
                "artifact_status": artifact_status,
            }
            if entry is not None:
                # DurableResourceLedger intentionally refuses rebinding. Record the
                # complete binding on first adoption by passing it through a dedicated
                # evidence row whose identity is derived from the exact object version.
                self.ledger.record(
                    kind="mos_ui_object_binding",
                    resource_id=_hash(
                        f"{kind}\0{backup_id}\0{backup_uuid}\0{storage_point_id}\0{artifact_id}"
                    ),
                    name=key,
                    ownership={
                        "account": self.account,
                        "run_id": self.config.run_id,
                        "object_kind": kind,
                        "object_resource_id": entry["resource_id"],
                        "backup_id": backup_id,
                        "backup_uuid": backup_uuid,
                        "generation_marker_sha256": generation["marker_digest"],
                        **ownership["durable_binding"],
                    },
                    source_witness=entry["resource_id"],
                )
            verified.append(
                {
                    "kind": object_kind,
                    "backup_id": backup_id,
                    "backup_uuid": backup_uuid,
                    "storage_point_id": storage_point_id,
                    "storage_id": storage_id,
                    "artifact_id": artifact_id,
                    "artifact_status": artifact_status,
                    "object_key": key,
                    "version_id": version_id,
                    "byte_count": byte_count,
                    "sha256": sha256,
                    "etag": etag,
                }
            )
        return {"status": "verified", "objects": verified}

    def _object_entries(self) -> list[dict]:
        rows = []
        for kind in sorted(OBJECT_LEDGER_KINDS):
            rows.extend(self._active_entries(kind))
        return rows

    def _verify_object_entry(self, client, entry: dict, maximum_bytes: int) -> None:
        ownership = entry.get("ownership") or {}
        bucket = str(ownership.get("bucket") or "")
        key = str(ownership.get("key") or "")
        version_id = str(ownership.get("version_id") or "")
        expected_id = _hash(f"{bucket}\0{key}\0{version_id}")
        if (
            ownership.get("account") != self.account
            or ownership.get("run_id") != self.config.run_id
            or entry.get("resource_id") != expected_id
            or not key.startswith(self.names["prefix"])
            or not version_id
        ):
            raise HarnessError("A ledgered object ownership witness is malformed.")
        if entry.get("kind") == "mos_delete_marker":
            return
        head = self._head_object(client, bucket, key, version_id)
        if head is None:
            return
        try:
            byte_count = int(ownership.get("byte_count"))
        except (TypeError, ValueError):
            raise HarnessError("A ledgered object byte witness is malformed.") from None
        sha256, observed = self._stream_identity(
            client, bucket, key, version_id, maximum_bytes
        )
        metadata = head.get("Metadata") or {}
        if (
            observed != byte_count
            or sha256 != ownership.get("sha256")
            or int(head.get("ContentLength") or -1) != byte_count
            or _etag(head.get("ETag")) != ownership.get("etag")
            or str(head.get("VersionId") or "") != version_id
            or any(
                str(metadata.get(key) or "") != str(value)
                for key, value in (ownership.get("metadata") or {}).items()
            )
        ):
            raise HarnessError("A ledgered object changed before cleanup.")

    def _preflight_object_cleanup(
        self, client, bucket: str, prefix: str, *, maximum_bytes: int
    ) -> tuple[dict, list[dict], list[dict]]:
        inventory = self._s3_inventory(client, bucket, prefix)
        object_entries = self._object_entries()
        upload_entries = self._active_entries("mos_multipart_upload")
        actual_all_versions = {
            (str(item.get("Key") or ""), str(item.get("VersionId") or ""))
            for section in ("versions", "delete_markers")
            for item in (inventory.get(section) or [])
        }
        actual_upload_pairs = {
            (str(item.get("Key") or ""), str(item.get("UploadId") or ""))
            for item in (inventory.get("multipart_uploads") or [])
        }
        for entry in object_entries:
            ownership = entry.get("ownership") or {}
            intent_key = f"cleanup:{entry['kind']}:{entry['resource_id']}"
            intent = self.intents.get(intent_key)
            if intent and intent.get("request_boundary_crossed"):
                expected_intent = {
                    "marker": self.config.run_id,
                    "kind": entry["kind"],
                    "name": ownership.get("key"),
                    "operation": "delete-version",
                }
                if any(intent.get(key) != value for key, value in expected_intent.items()):
                    raise HarnessError("A pending object-delete intent changed scope.")
                pair = (
                    str(ownership.get("key") or ""),
                    str(ownership.get("version_id") or ""),
                )
                if pair in actual_all_versions:
                    raise AmbiguousMutation(
                        "A crossed object-delete intent remains present; deletion will not replay."
                    )
                self.ledger.mark_cleanup(entry["kind"], entry["resource_id"], state="deleted")
                self.intents.clear(intent_key)
        for entry in upload_entries:
            ownership = entry.get("ownership") or {}
            intent_key = f"cleanup:mos-upload:{entry['resource_id']}"
            intent = self.intents.get(intent_key)
            if intent and intent.get("request_boundary_crossed"):
                expected_intent = {
                    "marker": self.config.run_id,
                    "kind": "mos_multipart_upload",
                    "name": ownership.get("key"),
                    "operation": "abort",
                }
                if any(intent.get(key) != value for key, value in expected_intent.items()):
                    raise HarnessError("A pending multipart-abort intent changed scope.")
                pair = (
                    str(ownership.get("key") or ""),
                    str(ownership.get("upload_id") or ""),
                )
                if pair in actual_upload_pairs:
                    raise AmbiguousMutation(
                        "A crossed multipart-abort intent remains present; abort will not replay."
                    )
                self.ledger.mark_cleanup("mos_multipart_upload", entry["resource_id"], state="deleted")
                self.intents.clear(intent_key)
        object_entries = self._object_entries()
        upload_entries = self._active_entries("mos_multipart_upload")
        expected_versions = {
            (
                str((entry.get("ownership") or {}).get("key") or ""),
                str((entry.get("ownership") or {}).get("version_id") or ""),
            )
            for entry in object_entries
        }
        actual_versions = {
            (str(item.get("Key") or ""), str(item.get("VersionId") or ""))
            for item in (inventory.get("versions") or [])
        }
        actual_markers = {
            (str(item.get("Key") or ""), str(item.get("VersionId") or ""))
            for item in (inventory.get("delete_markers") or [])
        }
        expected_markers = {
            pair
            for pair, entry in zip(
                [
                    (
                        str((row.get("ownership") or {}).get("key") or ""),
                        str((row.get("ownership") or {}).get("version_id") or ""),
                    )
                    for row in object_entries
                ],
                object_entries,
            )
            if entry.get("kind") == "mos_delete_marker"
        }
        expected_object_versions = expected_versions - expected_markers
        expected_uploads = {
            (
                str((entry.get("ownership") or {}).get("key") or ""),
                str((entry.get("ownership") or {}).get("upload_id") or ""),
            )
            for entry in upload_entries
        }
        actual_uploads = {
            (str(item.get("Key") or ""), str(item.get("UploadId") or ""))
            for item in (inventory.get("multipart_uploads") or [])
        }
        active_keys = {
            str(item.get("Key") or "") for item in (inventory.get("objects") or [])
        }
        if (
            actual_versions != expected_object_versions
            or actual_markers != expected_markers
            or actual_uploads != expected_uploads
            or not active_keys.issubset({key for key, _version in actual_versions})
        ):
            raise InventoryNotEmpty(
                "Cleanup refused because the exact run prefix contains an "
                "unledgered object version, delete marker, current object, or "
                "multipart upload."
            )
        for entry in object_entries:
            self._verify_object_entry(client, entry, maximum_bytes)
        for entry in upload_entries:
            ownership = entry.get("ownership") or {}
            if (
                ownership.get("account") != self.account
                or ownership.get("run_id") != self.config.run_id
                or ownership.get("bucket") != bucket
                or not str(ownership.get("key") or "").startswith(self.names["prefix"])
                or not ownership.get("upload_id")
            ):
                raise HarnessError("A multipart-upload ledger witness is malformed.")
        return inventory, object_entries, upload_entries

    def _delete_bucket_contents(
        self, client, bucket: str, prefix: str, *, maximum_bytes: int
    ) -> None:
        _inventory, objects, uploads = self._preflight_object_cleanup(
            client, bucket, prefix, maximum_bytes=maximum_bytes
        )
        for entry in uploads:
            ownership = entry["ownership"]
            intent_key = f"cleanup:mos-upload:{entry['resource_id']}"
            self.intents.put(
                intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": "mos_multipart_upload",
                    "name": ownership["key"],
                    "operation": "abort",
                },
            )
            self.intents.update(intent_key, request_boundary_crossed=True)
            self._s3_mutation(
                intent_key,
                lambda ownership=ownership: client.abort_multipart_upload(
                    Bucket=bucket,
                    Key=ownership["key"],
                    UploadId=ownership["upload_id"],
                ),
            )
            self.ledger.mark_cleanup(
                "mos_multipart_upload", entry["resource_id"], state="deleted"
            )
            self.intents.clear(intent_key)
        for entry in objects:
            ownership = entry["ownership"]
            intent_key = f"cleanup:{entry['kind']}:{entry['resource_id']}"
            self.intents.put(
                intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": entry["kind"],
                    "name": ownership["key"],
                    "operation": "delete-version",
                },
            )
            self.intents.update(intent_key, request_boundary_crossed=True)
            self._s3_mutation(
                intent_key,
                lambda ownership=ownership: client.delete_object(
                    Bucket=bucket,
                    Key=ownership["key"],
                    VersionId=ownership["version_id"],
                ),
            )
            if self._head_object(
                client, bucket, ownership["key"], ownership["version_id"]
            ) is not None:
                self.ledger.mark_cleanup(
                    entry["kind"],
                    entry["resource_id"],
                    state="failed",
                    error="Exact object version remains visible.",
                )
                raise AmbiguousMutation(
                    "An exact ledgered object version remains visible after deletion."
                )
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="deleted"
            )
            self.intents.clear(intent_key)
        if not self._inventory_empty(self._s3_inventory(client, bucket, prefix)):
            raise InventoryNotEmpty(
                "The exact run prefix still contains objects after ledgered cleanup."
            )

    def _control_delete(
        self,
        *,
        intent_key: str,
        kind: str,
        entry: dict,
        path: str,
        verify_absent,
        params=None,
    ) -> None:
        if kind in MOS_RETAINED_PROVIDER_KINDS:
            raise HarnessError(
                "MOS credential and service scaffolding is retained by user "
                "instruction and cannot enter a provider-delete path."
            )
        expected_intent = {
            "marker": self.config.run_id,
            "kind": kind,
            "name": entry.get("name") or entry["resource_id"],
            "operation": "delete",
        }
        pending = self.intents.get(intent_key)
        if pending and pending.get("request_boundary_crossed"):
            if any(pending.get(key) != value for key, value in expected_intent.items()):
                raise HarnessError("A pending provider-delete intent changed scope.")
            if verify_absent():
                self.ledger.mark_cleanup(kind, entry["resource_id"], state="deleted")
                self.intents.clear(intent_key)
                return
            raise AmbiguousMutation(
                "A crossed provider-delete intent still has an exact resource; deletion will not replay."
            )
        self.intents.put(
            intent_key,
            expected_intent,
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "DELETE",
            path,
            accepted=(204,),
            allow_not_found=True,
            params=params,
        )
        if not verify_absent():
            self.ledger.mark_cleanup(
                kind,
                entry["resource_id"],
                state="failed",
                error="Exact provider resource remains visible after delete.",
            )
            raise AmbiguousMutation(
                "An exact UpCloud resource remains visible after deletion."
            )
        self.ledger.mark_cleanup(kind, entry["resource_id"], state="deleted")
        self.intents.clear(intent_key)

    def _adopt_pending_access_key_for_cleanup(
        self, service_id: str, username: str
    ) -> None:
        if self._one_active("mos_access_key"):
            return
        intent = self.intents.get("mos_access_key_create")
        if not intent or not intent.get("request_boundary_crossed"):
            return
        if (
            intent.get("service_uuid") != service_id
            or intent.get("username") != username
            or intent.get("preflight_absent") is not True
        ):
            raise HarnessError("The pending access-key intent scope is malformed.")
        keys = self._access_keys(service_id, username)
        if len(keys) != 1:
            raise AmbiguousMutation(
                "The pending access-key create does not have one exact cleanup witness."
            )
        key_id = str(keys[0].get("access_key_id") or "")
        exact = self._access_key_read(service_id, username, key_id)
        if not exact:
            raise AmbiguousMutation(
                "The pending access key is not exactly readable for cleanup."
            )
        self._record_access_key(service_id, username, exact)

    def _record_mos_retention_receipt(
        self,
        *,
        service_id: str,
        retained_kind: str,
        retained_resource_id: str,
        source_witness: str,
    ) -> dict:
        if retained_kind not in MOS_RETAINED_KINDS:
            raise HarnessError("An unsupported MOS retention receipt was requested.")
        retained_resource_id = str(retained_resource_id or "")
        if not retained_resource_id or len(retained_resource_id) > 1024:
            raise HarnessError("A MOS retention receipt resource ID is malformed.")
        ownership = {
            "account": self.account,
            "run_id": self.config.run_id,
            "service_uuid": str(service_id or ""),
            "retained_kind": retained_kind,
            "retained_resource_id": retained_resource_id,
            "disposition": USER_RETAINED_BY_INSTRUCTION,
        }
        receipt_id = _hash(_canonical(ownership))
        return self.ledger.record(
            kind=MOS_RETENTION_RECEIPT_KIND,
            resource_id=receipt_id,
            name=f"{retained_kind}-retained",
            ownership=ownership,
            source_witness=str(source_witness or retained_resource_id),
        )

    def _mos_retention_receipts(self) -> dict:
        receipts = {}
        for row in self._active_entries(MOS_RETENTION_RECEIPT_KIND):
            ownership = row.get("ownership")
            if (
                not isinstance(ownership, dict)
                or set(ownership) != MOS_RETENTION_OWNERSHIP_KEYS
                or ownership.get("account") != self.account
                or ownership.get("run_id") != self.config.run_id
                or ownership.get("retained_kind") not in MOS_RETAINED_KINDS
                or ownership.get("disposition")
                != USER_RETAINED_BY_INSTRUCTION
                or not str(ownership.get("service_uuid") or "")
                or not str(ownership.get("retained_resource_id") or "")
                or row.get("resource_id") != _hash(_canonical(ownership))
            ):
                raise HarnessError("A durable MOS retention receipt is malformed.")
            identity = (
                str(ownership["retained_kind"]),
                str(ownership["retained_resource_id"]),
            )
            if identity in receipts:
                raise HarnessError("Duplicate durable MOS retention receipts exist.")
            receipts[identity] = row
        return receipts

    @staticmethod
    def _account_token_retention_summary() -> dict:
        return {
            "kind": UPCLOUD_ACCOUNT_TOKEN_KIND,
            "resource_id": "outside-harness",
            "disposition": USER_RETAINED_BY_INSTRUCTION,
        }

    def _mos_retention_summary(self, receipts: dict | None = None) -> list[dict]:
        receipts = receipts if receipts is not None else self._mos_retention_receipts()
        result = [self._account_token_retention_summary()]
        result.extend(
            {
                "kind": kind,
                "resource_id": resource_id,
                "disposition": USER_RETAINED_BY_INSTRUCTION,
            }
            for kind, resource_id in sorted(receipts)
        )
        return result

    def _runtime_retention_resource_id(self, key_entry: dict) -> str:
        return _hash(
            f"{self.config.runtime_path}\0{key_entry['resource_id']}\0"
            f"{self.config.run_id}"
        )

    def _validate_runtime_for_retention(
        self, service: dict, key_entry: dict
    ) -> str:
        runtime = self._validate_runtime(
            _read_runtime_secret(self.config.runtime_path), service
        )
        if _hash(str(runtime.get("access_key") or "")) != key_entry["resource_id"]:
            raise HarnessError(
                "The protected runtime credential no longer matches its exact "
                "access-key witness."
            )
        return self._runtime_retention_resource_id(key_entry)

    def _validate_and_receipt_retained_mos_scaffolding(
        self, service_entry: dict, service: dict
    ) -> list[dict]:
        service_id = str(service_entry.get("resource_id") or "")
        if not self._service_owned(service, resource_id=service_id):
            raise HarnessError("Retained MOS service ownership verification failed.")

        retained_entries = [("mos_service", service_entry)]
        network_entry = self._one_active("mos_network")
        if not network_entry:
            raise HarnessError("The retained MOS service lacks its network witness.")
        networks = self.control.request(
            "GET", f"/object-storage-2/{quote(service_id, safe='')}/networks"
        )
        if not isinstance(networks, list) or any(
            not isinstance(item, dict) for item in networks
        ):
            raise HarnessError("UpCloud returned malformed retained network inventory.")
        if len(networks) != 1:
            raise HarnessError("Retained MOS network inventory is not exact.")
        network = networks[0]
        network_ownership = network_entry.get("ownership") or {}
        if (
            network_entry.get("resource_id")
            != f"{service_id}:{self.names['network']}"
            or network_ownership.get("account") != self.account
            or network_ownership.get("run_id") != self.config.run_id
            or network_ownership.get("service_uuid") != service_id
            or str(network.get("name") or "") != self.names["network"]
            or str(network.get("type") or "") != "public"
            or str(network.get("family") or "") != "IPv4"
        ):
            raise HarnessError("Retained MOS network ownership verification failed.")
        retained_entries.append(("mos_network", network_entry))

        user_entry = self._one_active("mos_user")
        policy_entry = self._one_active("mos_inline_policy")
        if user_entry:
            self._adopt_pending_access_key_for_cleanup(
                service_id, self.names["username"]
            )
        key_entry = self._one_active("mos_access_key")
        if not user_entry and (policy_entry or key_entry):
            raise HarnessError(
                "Retained MOS policy or key evidence exists without its user."
            )

        users = [
            item
            for item in self._users(service_id)
            if str(item.get("username") or "") != "_upcloud-internal-user"
        ]
        if user_entry:
            if len(users) != 1 or not self._user_owned(
                users[0], self.names["username"]
            ):
                raise HarnessError("Retained MOS user inventory is not exact.")
            exact_user = self._user_read(service_id, self.names["username"])
            user_ownership = user_entry.get("ownership") or {}
            if (
                not self._user_owned(exact_user or {}, self.names["username"])
                or user_entry.get("resource_id")
                != f"{service_id}:{self.names['username']}"
                or user_ownership.get("account") != self.account
                or user_ownership.get("run_id") != self.config.run_id
                or user_ownership.get("service_uuid") != service_id
            ):
                raise HarnessError("Retained MOS user ownership verification failed.")
            retained_entries.append(("mos_user", user_entry))

            policies = self._inline_policies(service_id, self.names["username"])
            if policy_entry:
                if (
                    len(policies) != 1
                    or str(policies[0].get("name") or "") != self.names["policy"]
                ):
                    raise HarnessError("Retained MOS policy inventory is not exact.")
                exact_policy = self._policy_read(
                    service_id, self.names["username"], self.names["policy"]
                )
                policy_ownership = policy_entry.get("ownership") or {}
                request = self._policy_request()
                if (
                    not self._policy_owned(exact_policy or {}, request)
                    or policy_entry.get("resource_id")
                    != f"{service_id}:{self.names['username']}:{self.names['policy']}"
                    or policy_ownership.get("account") != self.account
                    or policy_ownership.get("run_id") != self.config.run_id
                    or policy_ownership.get("service_uuid") != service_id
                    or policy_ownership.get("document_sha256")
                    != _hash(_normalized_policy(request["document"]))
                ):
                    raise HarnessError("Retained MOS policy ownership verification failed.")
                retained_entries.append(("mos_inline_policy", policy_entry))
            elif policies:
                raise HarnessError("An unledgered retained MOS policy exists.")

            keys = self._access_keys(service_id, self.names["username"])
            if key_entry:
                matches = [
                    item
                    for item in keys
                    if _hash(str(item.get("access_key_id") or ""))
                    == key_entry["resource_id"]
                ]
                if len(keys) != 1 or len(matches) != 1:
                    raise HarnessError("Retained MOS access-key inventory is not exact.")
                key_id = str(matches[0].get("access_key_id") or "")
                exact_key = self._access_key_read(
                    service_id, self.names["username"], key_id
                )
                key_ownership = key_entry.get("ownership") or {}
                if (
                    not exact_key
                    or str(exact_key.get("status") or "") != "Active"
                    or _hash(str(exact_key.get("access_key_id") or ""))
                    != key_entry["resource_id"]
                    or key_ownership.get("account") != self.account
                    or key_ownership.get("run_id") != self.config.run_id
                    or key_ownership.get("service_uuid") != service_id
                    or key_ownership.get("username") != self.names["username"]
                ):
                    raise HarnessError(
                        "Retained MOS access-key ownership verification failed."
                    )
                retained_entries.append(("mos_access_key", key_entry))
            elif keys:
                raise HarnessError("An unledgered retained MOS access key exists.")
        elif users:
            raise HarnessError("An unledgered retained MOS user exists.")

        runtime_exists = self.config.runtime_path.exists() or self.config.runtime_path.is_symlink()
        runtime_resource_id = ""
        if key_entry:
            runtime_resource_id = self._validate_runtime_for_retention(
                service, key_entry
            )
        elif runtime_exists:
            raise HarnessError(
                "A protected MOS runtime credential exists without an exact key witness."
            )

        for retained_kind, entry in retained_entries:
            ownership = entry.get("ownership") or {}
            if (
                ownership.get("account") != self.account
                or ownership.get("run_id") != self.config.run_id
                or (
                    retained_kind != "mos_service"
                    and ownership.get("service_uuid") != service_id
                )
            ):
                raise HarnessError("Retained MOS durable ownership evidence changed.")
            self._record_mos_retention_receipt(
                service_id=service_id,
                retained_kind=retained_kind,
                retained_resource_id=str(entry["resource_id"]),
                source_witness=str(entry["resource_id"]),
            )
        if runtime_resource_id:
            self._record_mos_retention_receipt(
                service_id=service_id,
                retained_kind=MOS_RUNTIME_CREDENTIAL_KIND,
                retained_resource_id=runtime_resource_id,
                source_witness=str(key_entry["resource_id"]),
            )
        return self._mos_retention_summary()

    def cleanup_object_storage(
        self,
        *,
        maximum_bytes: int,
        require_evidence: bool = False,
        preserve_credentials: bool = True,
    ) -> dict:
        self._require_cleanup()
        if preserve_credentials is not True:
            raise HarnessError(
                "MOS credential preservation is mandatory; no credential-revoke "
                "cleanup mode exists."
            )
        self._require_object_storage_config()
        self.verify_account()
        if maximum_bytes < 1 or maximum_bytes > 1024**4:
            raise HarnessError("The cleanup verification byte bound is invalid.")
        service_entry = self._one_active("mos_service")
        if not service_entry:
            nested_kinds = (
                *sorted(MOS_RETAINED_PROVIDER_KINDS - {"mos_service"}),
                *sorted(MOS_DATA_LEDGER_KINDS),
                MOS_RETENTION_RECEIPT_KIND,
            )
            if any(self._active_entries(kind) for kind in nested_kinds):
                raise HarnessError(
                    "MOS resources or retention receipts exist without a service witness."
                )
            return {"status": "nothing_to_cleanup"}

        if require_evidence and (
            self._one_active("mos_bucket_configuration") is None
            or self._one_active("mos_ui_website_object") is None
            or self._one_active("mos_ui_database_object") is None
            or len(self._active_entries("mos_ui_object_binding")) != 2
        ):
            raise HarnessError(
                "Evidence-gated object cleanup requires complete website/database "
                "object bindings."
            )

        service_id = str(service_entry["resource_id"])
        service = self._service_read(service_id)
        if service is None:
            raise HarnessError(
                "The user-retained MOS service is absent; cleanup will not mark "
                "credential or service scaffolding terminal."
            )
        if not self._service_owned(service, resource_id=service_id):
            raise HarnessError("Cleanup refused a service ownership mismatch.")

        bucket_entry = self._one_active("mos_bucket")
        if require_evidence:
            config_entry = self._one_active("mos_bucket_configuration")
            website = self._one_active("mos_ui_website_object")
            database = self._one_active("mos_ui_database_object")
            bindings = self._active_entries("mos_ui_object_binding")
            if not config_entry or not website or not database or len(bindings) != 2:
                raise HarnessError(
                    "Evidence-gated object cleanup requires complete website/database "
                    "object bindings."
                )
            self._validate_bucket_configuration(
                config_entry,
                service_entry=service_entry,
                bucket=self.names["bucket"],
            )
            client, runtime = self._s3(service)
            current = _s3_call(
                lambda: client.get_bucket_versioning(Bucket=runtime["bucket_name"])
            )
            if not isinstance(current, dict) or current.get("Status") != "Enabled":
                raise HarnessError(
                    "Evidence-gated object cleanup requires fresh enabled versioning."
                )
            if {
                str((row.get("ownership") or {}).get("object_resource_id") or "")
                for row in bindings
            } != {website["resource_id"], database["resource_id"]}:
                raise HarnessError(
                    "Durable object bindings do not match exact object versions."
                )

        retained = self._validate_and_receipt_retained_mos_scaffolding(
            service_entry, service
        )
        if bucket_entry:
            ownership = bucket_entry.get("ownership") or {}
            if (
                ownership.get("account") != self.account
                or ownership.get("run_id") != self.config.run_id
                or ownership.get("service_uuid") != service_id
                or ownership.get("bucket_name") != self.names["bucket"]
                or ownership.get("prefix") != self.names["prefix"]
                or bucket_entry["resource_id"]
                != f"{service_id}:{self.names['bucket']}"
            ):
                raise HarnessError("Cleanup refused a bucket ownership mismatch.")

        buckets = self._buckets(service_id)
        bucket = self._exact_name(buckets, "name", self.names["bucket"])
        foreign_buckets = [
            row
            for row in buckets
            if str(row.get("name") or "") != self.names["bucket"]
        ]
        if foreign_buckets:
            raise HarnessError(
                "Data cleanup refused an unowned bucket on the retained MOS service."
            )
        if bucket and not bucket_entry:
            raise HarnessError(
                "Data cleanup refused an unledgered bucket on the retained MOS service."
            )

        if bucket_entry and bucket is None:
            for entry in self._object_entries():
                self.ledger.mark_cleanup(
                    entry["kind"], entry["resource_id"], state="absent"
                )
            for entry in self._active_entries("mos_multipart_upload"):
                self.ledger.mark_cleanup(
                    "mos_multipart_upload", entry["resource_id"], state="absent"
                )
            for kind in ("mos_bucket_configuration", "mos_ui_object_binding"):
                for entry in self._active_entries(kind):
                    self.ledger.mark_cleanup(
                        kind, entry["resource_id"], state="absent"
                    )
            self.ledger.mark_cleanup(
                "mos_bucket", bucket_entry["resource_id"], state="absent"
            )
        elif bucket_entry:
            client, runtime = self._s3(service)
            self._delete_bucket_contents(
                client,
                self.names["bucket"],
                runtime["prefix"],
                maximum_bytes=maximum_bytes,
            )
            bucket_path = (
                f"/object-storage-2/{quote(service_id, safe='')}/buckets/"
                f"{quote(self.names['bucket'], safe='')}"
            )
            self._control_delete(
                intent_key="cleanup:mos-bucket",
                kind="mos_bucket",
                entry=bucket_entry,
                path=bucket_path,
                verify_absent=lambda: self._exact_name(
                    self._buckets(service_id), "name", self.names["bucket"]
                )
                is None,
            )
            for kind in ("mos_bucket_configuration", "mos_ui_object_binding"):
                for entry in self._active_entries(kind):
                    self.ledger.mark_cleanup(
                        kind, entry["resource_id"], state="deleted"
                    )

        if self._buckets(service_id):
            raise HarnessError(
                "The retained MOS service still contains a bucket after data cleanup."
            )
        active_data = {
            kind: [row["resource_id"] for row in self._active_entries(kind)]
            for kind in sorted(MOS_DATA_LEDGER_KINDS)
            if self._active_entries(kind)
        }
        if active_data:
            raise HarnessError(
                "Object data cleanup cannot complete while durable data evidence "
                "remains active."
            )
        return {
            "status": "completed",
            "service_uuid": service_id,
            "data_cleanup": "terminal",
            "credential_service_scaffolding": USER_RETAINED_BY_INSTRUCTION,
            "retained_by_instruction": retained,
        }

    # Compute and Block Storage -------------------------------------------------

    def _compute_inventory(self, kind: str) -> list[dict]:
        definitions = {
            # The live API ignores ``type=`` on the generic collection and can
            # return public templates. Use the documented typed collections.
            "storage": ("/storage/normal", "storages", "storage", {}),
            "backup": ("/storage/backup", "storages", "storage", {}),
            "server": ("/server", "servers", "server", {}),
        }
        if kind not in definitions:
            raise HarnessError("Unsupported UpCloud compute inventory kind.")
        path, container_key, item_key, fixed_params = definitions[kind]
        resources = []
        seen_ids = set()
        seen_pages = set()
        offset = 0
        for _page in range(MAX_PAGES):
            params = dict(fixed_params)
            params.update(
                {
                    "limit": COMPUTE_PAGE_LIMIT,
                    "offset": offset,
                    # UpCloud's live API accepts this spelling.  Keep the
                    # sort stable so offset reconciliation cannot move a
                    # resource between pages during a run.
                    "sort_by": "title",
                    "order": "asc",
                }
            )
            payload = self.control.request("GET", path, params=params)
            container = (
                payload.get(container_key) if isinstance(payload, dict) else None
            )
            page = container.get(item_key) if isinstance(container, dict) else None
            if not isinstance(page, list) or any(
                not isinstance(item, dict)
                or not UPCLOUD_UUID_RE.fullmatch(str(item.get("uuid") or ""))
                for item in page
            ):
                raise HarnessError("UpCloud returned malformed compute inventory.")
            identity = tuple(str(item["uuid"]) for item in page)
            if identity and identity in seen_pages:
                raise HarnessError("UpCloud returned a repeated compute inventory page.")
            seen_pages.add(identity)
            for item in page:
                resource_id = str(item["uuid"])
                if resource_id in seen_ids:
                    raise HarnessError("UpCloud compute inventory contains duplicate UUIDs.")
                if kind in {"storage", "backup"} and str(
                    item.get("type") or ""
                ) != ("normal" if kind == "storage" else "backup"):
                    raise HarnessError("UpCloud storage inventory escaped its type filter.")
                seen_ids.add(resource_id)
                resources.append(item)
                if len(resources) > MAX_ITEMS:
                    raise HarnessError("UpCloud compute inventory exceeded its item bound.")
            if len(page) < COMPUTE_PAGE_LIMIT:
                return resources
            next_offset = offset + len(page)
            if next_offset <= offset:
                raise HarnessError("UpCloud compute pagination did not advance.")
            offset = next_offset
        raise HarnessError("UpCloud compute inventory exceeded its page bound.")

    def _ip_inventory(self) -> list[dict]:
        rows = []
        seen = set()
        offset = 0
        for _page in range(MAX_PAGES):
            payload = self.control.request(
                "GET",
                "/ip_address",
                params={"limit": COMPUTE_PAGE_LIMIT, "offset": offset},
            )
            container = payload.get("ip_addresses") if isinstance(payload, dict) else None
            page = container.get("ip_address") if isinstance(container, dict) else None
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise HarnessError("UpCloud returned malformed IP inventory.")
            for row in page:
                address = str(row.get("address") or "")
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    raise HarnessError("UpCloud returned malformed IP inventory.") from None
                identity = (address, str(row.get("server") or ""))
                if identity in seen:
                    raise HarnessError("UpCloud IP inventory contains duplicates.")
                seen.add(identity)
                rows.append(row)
            if len(rows) > MAX_ITEMS:
                raise HarnessError("UpCloud IP inventory exceeded the safety bound.")
            if len(page) < COMPUTE_PAGE_LIMIT:
                return rows
            offset += len(page)
        raise HarnessError("UpCloud IP inventory exceeded the page bound.")

    @staticmethod
    def _exact_title(items: list[dict], title: str) -> dict | None:
        matches = [item for item in items if str(item.get("title") or "") == title]
        if len(matches) > 1:
            raise HarnessError("Multiple UpCloud resources share an exact run marker.")
        return matches[0] if matches else None

    def _storage_read(self, resource_id: str) -> dict | None:
        if not UPCLOUD_UUID_RE.fullmatch(str(resource_id or "")):
            raise HarnessError("UpCloud storage UUID is malformed.")
        payload = self.control.request(
            "GET",
            f"/storage/{quote(str(resource_id), safe='')}",
            allow_not_found=True,
        )
        if payload is None:
            return None
        storage = payload.get("storage") if isinstance(payload, dict) else None
        if not isinstance(storage, dict):
            raise HarnessError("UpCloud returned malformed storage details.")
        return storage

    def _server_read(self, resource_id: str) -> dict | None:
        if not UPCLOUD_UUID_RE.fullmatch(str(resource_id or "")):
            raise HarnessError("UpCloud server UUID is malformed.")
        payload = self.control.request(
            "GET",
            f"/server/{quote(str(resource_id), safe='')}",
            allow_not_found=True,
        )
        if payload is None:
            return None
        server = payload.get("server") if isinstance(payload, dict) else None
        if not isinstance(server, dict):
            raise HarnessError("UpCloud returned malformed server details.")
        return server

    def _provider_firewall_inventory(self, server_id: str) -> list[dict]:
        """Read one bounded, position-validated provider firewall inventory."""
        if not UPCLOUD_UUID_RE.fullmatch(str(server_id or "")):
            raise HarnessError("UpCloud server UUID is malformed.")
        payload = self.control.request(
            "GET",
            f"/server/{quote(str(server_id), safe='')}/firewall_rule",
        )
        container = payload.get("firewall_rules") if isinstance(payload, dict) else None
        rules = container.get("firewall_rule") if isinstance(container, dict) else None
        if not isinstance(rules, list) or not rules or len(rules) > FIREWALL_RULE_LIMIT:
            raise HarnessError(
                "UpCloud returned a malformed or empty firewall inventory."
            )

        positions = []
        fingerprints = set()
        for rule in rules:
            if not isinstance(rule, dict):
                raise HarnessError("UpCloud returned a malformed firewall inventory.")
            try:
                position = int(rule.get("position"))
            except (TypeError, ValueError):
                raise HarnessError("UpCloud returned a malformed firewall position.") from None
            if not 1 <= position <= FIREWALL_RULE_LIMIT:
                raise HarnessError("UpCloud returned an invalid firewall position.")
            normalized = _normalize_firewall_rule(rule)
            fingerprint = _fingerprint(normalized)
            if fingerprint in fingerprints:
                raise HarnessError("UpCloud returned duplicate firewall rules.")
            positions.append(position)
            fingerprints.add(fingerprint)
        if positions != list(range(1, len(positions) + 1)):
            raise HarnessError("UpCloud firewall positions are not successive.")
        return rules

    def _provider_firewall_expected_rules(self) -> list[dict]:
        """Build the exact allowlist plus an explicit inbound default drop."""
        expected = []
        for cidr in self.config.allowed_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                raise HarnessError("The configured UpCloud firewall CIDR is invalid.") from None
            address = str(network.network_address)
            family = "IPv4" if network.version == 4 else "IPv6"
            for port in FIREWALL_ALLOWED_PORTS:
                comment = (
                    f"BackupSheep E2E {self.config.run_id} "
                    f"allow tcp {port} from {address}"
                )
                if len(comment) > 250:
                    raise HarnessError("The UpCloud firewall ownership comment is too long.")
                expected.append(
                    {
                        "direction": "in",
                        "family": family,
                        "protocol": "tcp",
                        "source_address_start": address,
                        "source_address_end": address,
                        "source_port_start": "",
                        "source_port_end": "",
                        "destination_address_start": "",
                        "destination_address_end": "",
                        "destination_port_start": str(port),
                        "destination_port_end": str(port),
                        "icmp_type": "",
                        "action": "accept",
                        "comment": comment,
                    }
                )
        # UpCloud documents the final rule as the default rule.  Keeping an
        # explicit inbound drop makes the first PUT fail-closed even when the
        # provider's initial chain is empty.  No outbound rule is added, so
        # UpCloud's normal outbound allowance remains available for apt and
        # other fixture setup traffic.
        expected.append({"direction": "in", "action": "drop"})
        return expected

    def _provider_firewall_request(self) -> dict:
        return {
            "firewall_rules": {
                "firewall_rule": self._provider_firewall_expected_rules()
            }
        }

    def _provider_firewall_observation(
        self, server_id: str, *, server: dict | None = None
    ) -> dict:
        exact_server = server if isinstance(server, dict) else self._server_read(server_id)
        if exact_server is None:
            raise AmbiguousMutation("The exact UpCloud server is not readable for firewall reconciliation.")
        if str(exact_server.get("firewall") or "").casefold() != "on":
            raise HarnessError("The exact UpCloud server provider firewall is not enabled.")
        rules = self._provider_firewall_inventory(server_id)
        normalized = [_normalize_firewall_rule(rule) for rule in rules]
        return {
            "firewall": "on",
            "rules": normalized,
            "rules_sha256": _fingerprint(normalized),
            "allow_rule_fingerprints": [
                _fingerprint(rule)
                for rule in normalized
                if rule["action"] == "accept"
            ],
        }

    def _provider_firewall_is_exact(self, observation: dict) -> bool:
        return observation.get("rules") == [
            _normalize_firewall_rule(rule)
            for rule in self._provider_firewall_expected_rules()
        ]

    @staticmethod
    def _provider_firewall_is_default_drop(observation: dict) -> bool:
        default_drop = _normalize_firewall_rule({"direction": "in", "action": "drop"})
        return observation.get("rules") == [default_drop]

    def _wait_provider_firewall_exact(self, server_id: str) -> dict:
        for attempt in range(FIREWALL_MAX_WAIT_POLLS):
            observation = self._provider_firewall_observation(server_id)
            if self._provider_firewall_is_exact(observation):
                return observation
            if attempt + 1 < FIREWALL_MAX_WAIT_POLLS:
                self.sleep(FIREWALL_POLL_SECONDS)
        raise AmbiguousMutation(
            "The UpCloud provider firewall did not reach the exact run-owned chain "
            "within the finite reconciliation timeout."
        )

    def _record_provider_firewall_rules(
        self, server_id: str, observation: dict
    ) -> dict:
        if not self._provider_firewall_is_exact(observation):
            raise HarnessError("The UpCloud provider firewall chain is not exact.")
        prior_timestamps = {
            str((row.get("ownership") or {}).get("firewall_verified_at") or "")
            for row in self.ledger.entries(FIREWALL_LEDGER_KIND)
            if str((row.get("ownership") or {}).get("server_id") or "")
            == str(server_id)
            and (row.get("ownership") or {}).get("firewall_verified_at")
        }
        if len(prior_timestamps) > 1:
            raise HarnessError(
                "The UpCloud firewall ledger has inconsistent verification timestamps."
            )
        if prior_timestamps:
            verified_at = _utc_timestamp(prior_timestamps.pop())
        else:
            clock_value = self.clock()
            if isinstance(clock_value, datetime):
                verified_at = clock_value
                if verified_at.tzinfo is None:
                    verified_at = verified_at.replace(tzinfo=timezone.utc)
                verified_at = verified_at.astimezone(timezone.utc)
            else:
                verified_at = _utc_timestamp(clock_value)
        verified_at_text = verified_at.isoformat()
        stabilization_deadline = verified_at + timedelta(
            seconds=FIREWALL_STABILIZATION_SECONDS
        )
        expected = [
            _normalize_firewall_rule(rule)
            for rule in self._provider_firewall_expected_rules()
        ]
        allow_rules = [rule for rule in expected if rule["action"] == "accept"]
        rule_ids = []
        for rule in allow_rules:
            rule_fingerprint = _fingerprint(rule)
            resource_id = f"{server_id}:{rule_fingerprint}"
            self.ledger.record(
                kind=FIREWALL_LEDGER_KIND,
                resource_id=resource_id,
                name=rule["comment"],
                ownership={
                    "account": self.account,
                    "run_id": self.config.run_id,
                    "server_id": server_id,
                    "rule": rule,
                    "rule_fingerprint": rule_fingerprint,
                    "firewall_verified_at": verified_at_text,
                },
                source_witness=server_id,
            )
            rule_ids.append(resource_id)
        return {
            "schema": 1,
            "server_id": server_id,
            "rules_sha256": observation["rules_sha256"],
            "allow_rule_fingerprints": [
                _fingerprint(rule) for rule in allow_rules
            ],
            "allow_rule_count": len(allow_rules),
            "default_incoming": "drop",
            "outbound": "provider-default",
            "firewall_verified_at": verified_at_text,
            "firewall_stabilization_deadline_at": stabilization_deadline.isoformat(),
            "ledger_rule_ids": rule_ids,
        }

    def _ensure_provider_firewall(self, server_id: str) -> dict:
        """Adopt or atomically install the exact provider firewall chain."""
        request = self._provider_firewall_request()
        request_fingerprint = _fingerprint(request)
        intent_key = f"compute_source_firewall:{server_id}"
        intent = self.intents.get(intent_key)
        if intent and any(
            (
                intent.get("request_fingerprint") != request_fingerprint,
                intent.get("server_id") != server_id,
                intent.get("kind") != FIREWALL_LEDGER_KIND,
                intent.get("operation") != "replace-chain",
            )
        ):
            raise HarnessError("The pending UpCloud firewall intent changed scope.")

        observation = self._provider_firewall_observation(server_id)
        if self._provider_firewall_is_exact(observation):
            evidence = self._record_provider_firewall_rules(server_id, observation)
            if intent:
                self.intents.clear(intent_key)
            return evidence

        if intent and intent.get("request_boundary_crossed"):
            # The PUT is idempotent but we never issue a second mutation after
            # a lost response.  A subsequent run either adopts the exact chain
            # above or remains explicitly ambiguous.
            observation = self._wait_provider_firewall_exact(server_id)
            evidence = self._record_provider_firewall_rules(server_id, observation)
            self.intents.clear(intent_key)
            return evidence

        if not self._provider_firewall_is_default_drop(observation):
            raise HarnessError(
                "The new UpCloud server has an unexpected provider firewall rule; "
                "refusing to overwrite a foreign or world-exposing chain."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": FIREWALL_LEDGER_KIND,
                "name": self.names["source_server"],
                "operation": "replace-chain",
                "server_id": server_id,
                "request_fingerprint": request_fingerprint,
                "preflight_default_drop": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "PUT",
            f"/server/{quote(server_id, safe='')}/firewall_rule",
            accepted=(204,),
            json_body=request,
        )
        observation = self._wait_provider_firewall_exact(server_id)
        evidence = self._record_provider_firewall_rules(server_id, observation)
        self.intents.clear(intent_key)
        return evidence

    @staticmethod
    def _storage_server_ids(storage: dict) -> list[str]:
        container = storage.get("servers") if isinstance(storage, dict) else None
        values = container.get("server") if isinstance(container, dict) else None
        if not isinstance(values, list) or any(
            not UPCLOUD_UUID_RE.fullmatch(str(value or "")) for value in values
        ):
            raise HarnessError("UpCloud returned malformed storage attachments.")
        identifiers = [str(value) for value in values]
        if len(identifiers) != len(set(identifiers)):
            raise HarnessError("UpCloud returned duplicate storage attachments.")
        return identifiers

    @staticmethod
    def _server_storage_devices(server: dict) -> list[dict]:
        container = (
            server.get("storage_devices") if isinstance(server, dict) else None
        )
        devices = (
            container.get("storage_device")
            if isinstance(container, dict)
            else None
        )
        if not isinstance(devices, list) or any(
            not isinstance(device, dict)
            or not UPCLOUD_UUID_RE.fullmatch(str(device.get("storage") or ""))
            for device in devices
        ):
            raise HarnessError("UpCloud returned malformed server storage devices.")
        ids = [str(device["storage"]) for device in devices]
        if len(ids) != len(set(ids)):
            raise HarnessError("UpCloud returned duplicate server storage devices.")
        return devices

    @staticmethod
    def _server_public_addresses(server: dict) -> list[str]:
        container = server.get("ip_addresses") if isinstance(server, dict) else None
        values = container.get("ip_address") if isinstance(container, dict) else None
        if values is None and isinstance(server, dict):
            networking = server.get("networking")
            interfaces = networking.get("interfaces") if isinstance(networking, dict) else None
            interfaces = interfaces.get("interface") if isinstance(interfaces, dict) else None
            values = []
            for interface in interfaces or []:
                if not isinstance(interface, dict) or str(interface.get("type") or "").casefold() != "public":
                    continue
                addresses = interface.get("ip_addresses")
                addresses = addresses.get("ip_address") if isinstance(addresses, dict) else None
                for value in addresses or []:
                    if isinstance(value, dict):
                        values.append({**value, "access": "public"})
        if not isinstance(values, list):
            raise HarnessError("UpCloud returned malformed server addresses.")
        addresses = []
        for value in values:
            if not isinstance(value, dict):
                raise HarnessError("UpCloud returned malformed server addresses.")
            if (
                str(value.get("access") or "").casefold() == "public"
                and str(value.get("family") or "") == "IPv4"
            ):
                address = str(value.get("address") or "")
                if not re.fullmatch(
                    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", address
                ):
                    raise HarnessError("UpCloud returned a malformed public IPv4 address.")
                addresses.append(address)
        if len(addresses) != len(set(addresses)):
            raise HarnessError("UpCloud returned duplicate public IPv4 addresses.")
        return addresses

    @staticmethod
    def _server_network_contract(server: dict) -> dict:
        networking = server.get("networking") if isinstance(server, dict) else None
        interfaces = (
            networking.get("interfaces") if isinstance(networking, dict) else None
        )
        values = (
            interfaces.get("interface") if isinstance(interfaces, dict) else None
        )
        if not isinstance(values, list) or not values:
            raise HarnessError("UpCloud returned malformed server networking.")
        normalized = []
        safe = []
        public_families = []
        seen_indexes = set()
        for interface in values:
            if not isinstance(interface, dict):
                raise HarnessError("UpCloud returned malformed server networking.")
            interface_type = str(interface.get("type") or "").casefold()
            if interface_type not in {"public", "utility", "private"}:
                raise HarnessError("The test server escaped its safe network shape.")
            try:
                index = int(interface.get("index"))
            except (TypeError, ValueError):
                raise HarnessError("UpCloud returned malformed network indexes.") from None
            if index < 1 or index in seen_indexes:
                raise HarnessError("UpCloud returned duplicate network indexes.")
            seen_indexes.add(index)
            addresses = interface.get("ip_addresses")
            addresses = (
                addresses.get("ip_address")
                if isinstance(addresses, dict)
                else None
            )
            if not isinstance(addresses, list) or not addresses:
                raise HarnessError("UpCloud returned malformed interface addresses.")
            families = []
            for address in addresses:
                family = str(address.get("family") or "") if isinstance(address, dict) else ""
                if family not in {"IPv4", "IPv6"}:
                    raise HarnessError("UpCloud returned an unknown address family.")
                if interface_type in {"utility", "private"} and family != "IPv4":
                    raise HarnessError(
                        "UpCloud returned an unsupported non-public IPv6 interface."
                    )
                families.append({"family": family})
                if interface_type == "public":
                    public_families.append(family)
            value = {
                "index": index,
                "type": interface_type,
                "ip_addresses": {"ip_address": families},
            }
            if interface_type == "private":
                network = str(interface.get("network") or "")
                if not UPCLOUD_UUID_RE.fullmatch(network):
                    raise HarnessError("UpCloud returned a malformed private network ID.")
                value["network"] = network
            for field in ("source_ip_filtering", "bootable"):
                flag = str(interface.get(field) or "").strip().casefold()
                if flag:
                    if flag not in {"yes", "no"}:
                        raise HarnessError("UpCloud returned a malformed interface flag.")
                    value[field] = flag
            normalized.append(value)
            if interface_type != "public":
                safe.append(value)
        if not safe:
            raise HarnessError("UpCloud server has no reconstructible non-public interface.")
        normalized.sort(key=lambda item: item["index"])
        safe.sort(key=lambda item: item["index"])
        for interface in normalized:
            interface.pop("index")
        return {
            "networking": {"interfaces": {"interface": safe}},
            "full_networking": {"interfaces": {"interface": normalized}},
            "public_ip_families": sorted(
                public_families, key=lambda family: (family != "IPv4", family)
            ),
        }

    @staticmethod
    def _server_network_shape(server: dict) -> dict:
        return UpCloudLiveHarness._server_network_contract(server)["full_networking"]

    def _server_safe_config(self, server: dict, boot_device: dict) -> dict:
        plan = str(server.get("plan") or "")
        firewall = str(server.get("firewall") or "").casefold()
        metadata = str(server.get("metadata") or "no").casefold()
        if (
            str(server.get("zone") or "") != self.config.zone
            or plan != self.config.server_plan
            or firewall != "on"
            or metadata not in {"yes", "no"}
            or server.get("server_group") not in (None, "")
        ):
            raise HarnessError("The UpCloud server safe configuration changed.")
        network_contract = self._server_network_contract(server)
        config = {
            "schema": 1,
            "zone": self.config.zone,
            "plan": plan,
            "firewall": firewall,
            "metadata": metadata,
            "networking": network_contract["networking"],
            "public_ip_families": network_contract["public_ip_families"],
            "boot_address": str(boot_device.get("address") or "virtio")[:64],
        }
        if plan == "custom":
            try:
                config["core_number"] = int(server.get("core_number"))
                config["memory_amount"] = int(server.get("memory_amount"))
            except (TypeError, ValueError):
                raise HarnessError("The custom server sizing is malformed.") from None
        for field in ("timezone", "video_model", "nic_model"):
            value = str(server.get(field) or "").strip()
            if value:
                config[field] = value
        return config

    def _source_storage_owned(
        self,
        storage: dict,
        *,
        resource_id: str,
        title: str,
        expected_servers=None,
    ) -> bool:
        labels = _label_map(storage.get("labels")) if isinstance(storage, dict) else {}
        if not all(
            (
                isinstance(storage, dict),
                str(storage.get("uuid") or "") == str(resource_id),
                str(storage.get("title") or "") == title,
                str(storage.get("type") or "") == "normal",
                str(storage.get("zone") or "") == self.config.zone,
                str(storage.get("tier") or "") == "standard",
                str(storage.get("encrypted") or "").casefold() == "yes",
                labels.get("backupsheep-e2e-owned") == "true",
                labels.get("backupsheep-e2e-run") == self.config.run_id,
            )
        ):
            return False
        if expected_servers is not None:
            return sorted(self._storage_server_ids(storage)) == sorted(
                str(value) for value in expected_servers
            )
        return True

    def _source_volume_request(self) -> dict:
        return {
            "storage": {
                "title": self.names["source_volume"],
                "zone": self.config.zone,
                "size": self.config.volume_size_gb,
                "tier": "standard",
                "encrypted": "yes",
                "labels": _labels(self.config.run_id),
            }
        }

    def _record_source_volume(self, storage: dict) -> dict:
        resource_id = str(storage.get("uuid") or "")
        if not self._source_storage_owned(
            storage,
            resource_id=resource_id,
            title=self.names["source_volume"],
        ):
            raise HarnessError("UpCloud source-volume ownership verification failed.")
        try:
            size = int(storage.get("size"))
        except (TypeError, ValueError):
            raise HarnessError("UpCloud returned a malformed source-volume size.") from None
        if size != self.config.volume_size_gb:
            raise HarnessError("UpCloud source-volume size changed.")
        return self.ledger.record(
            kind="compute_source_volume",
            resource_id=resource_id,
            name=self.names["source_volume"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "zone": self.config.zone,
                "type": "normal",
                "tier": "standard",
                "encrypted": "yes",
                "size": size,
                "request_fingerprint": _fingerprint(self._source_volume_request()),
            },
            source_witness=f"upcloud-account:{self.account}",
        )

    def ensure_source_volume(self) -> dict:
        entry = self._one_active("compute_source_volume")
        if entry:
            storage = self._storage_read(entry["resource_id"])
            if storage is None or not self._source_storage_owned(
                storage,
                resource_id=entry["resource_id"],
                title=self.names["source_volume"],
            ):
                raise HarnessError("The ledgered UpCloud source volume changed.")
            return storage

        intent_key = "compute_source_volume_create"
        intent = self.intents.get(intent_key)
        summary = self._exact_title(
            self._compute_inventory("storage"), self.names["source_volume"]
        )
        if summary is not None:
            if not intent or not intent.get("request_boundary_crossed"):
                raise HarnessError(
                    "An unledgered UpCloud volume has the exact run title."
                )
            storage = self._storage_read(str(summary.get("uuid") or ""))
            if storage is None:
                raise AmbiguousMutation("The pending source volume is not exactly readable.")
            self._record_source_volume(storage)
            self.intents.clear(intent_key)
            return storage
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "The source-volume create crossed the provider boundary but no exact "
                "owned resource is visible; no duplicate was sent."
            )

        request = self._source_volume_request()
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "compute_source_volume",
                "name": self.names["source_volume"],
                "operation": "create",
                "request_fingerprint": _fingerprint(request),
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        payload = self._control_mutation(
            intent_key,
            "POST",
            "/storage",
            accepted=(201,),
            json_body=request,
        )
        returned = payload.get("storage") if isinstance(payload, dict) else None
        resource_id = str(returned.get("uuid") or "") if isinstance(returned, dict) else ""
        if not UPCLOUD_UUID_RE.fullmatch(resource_id):
            summary = self._exact_title(
                self._compute_inventory("storage"), self.names["source_volume"]
            )
            resource_id = str(summary.get("uuid") or "") if summary else ""
        storage = self._storage_read(resource_id) if resource_id else None
        if storage is None:
            raise AmbiguousMutation(
                "UpCloud accepted the source-volume create without exact read-back."
            )
        self._record_source_volume(storage)
        self.intents.clear(intent_key)
        return storage

    def _key_paths(self):
        private_key = self.config.runtime_path.with_name(
            f"{self.config.run_id}.upcloud-ssh-key"
        )
        public_key = private_key.with_name(private_key.name + ".pub")
        known_hosts = private_key.with_name(private_key.name + ".known-hosts")
        return tuple(
            _safe_path(path, variable="UpCloud E2E SSH artifact", allow_runtime=True)
            for path in (private_key, public_key, known_hosts)
        )

    @staticmethod
    def _atomic_key_write(path: Path, payload: bytes, mode: int) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            os.chmod(path, mode)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _ensure_ssh_key(self):
        private_path, public_path, _known_hosts = self._key_paths()
        if private_path.exists() != public_path.exists():
            raise HarnessError("The run-scoped UpCloud SSH key pair is incomplete.")
        if not private_path.exists():
            self._require_apply()
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa

                key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                private_payload = key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
                public_payload = key.public_key().public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH,
                ) + f" backupsheep-e2e-{self.config.run_id}\n".encode("ascii")
                self._atomic_key_write(private_path, private_payload, 0o600)
                self._atomic_key_write(public_path, public_payload, 0o600)
            except HarnessError:
                raise
            except Exception:
                raise HarnessError("Could not create the run-scoped UpCloud SSH key.") from None
        if private_path.is_symlink() or public_path.is_symlink():
            raise HarnessError("The run-scoped UpCloud SSH key path became unsafe.")
        if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
            raise HarnessError("The UpCloud SSH private key must have mode 0600.")
        public = public_path.read_text(encoding="ascii").strip()
        if not public.startswith("ssh-rsa ") or len(public) > 8192:
            raise HarnessError("The run-scoped UpCloud SSH public key is malformed.")
        return private_path, public

    def _source_server_request(self, source_volume_id: str, public_key: str) -> dict:
        return {
            "server": {
                "zone": self.config.zone,
                "title": self.names["source_server"],
                "hostname": self.names["hostname"],
                "plan": self.config.server_plan,
                # Keep the provider firewall enabled from server creation.
                # The first control-plane action after creation replaces the
                # initial default-drop chain with the exact host allowlist
                # plus an explicit inbound drop; SSH is never attempted
                # before that chain is read back.
                "firewall": "on",
                # Cloud-init templates require the metadata service during
                # initialization; the live API rejects an explicit "no".
                "metadata": "yes",
                "timezone": "UTC",
                "labels": {"label": _labels(self.config.run_id)},
                "storage_devices": {
                    "storage_device": [
                        {
                            "action": "clone",
                            "storage": self.config.os_template,
                            "title": self.names["source_boot"],
                            "size": self.config.boot_size_gb,
                            "tier": "standard",
                            "encrypted": "yes",
                            "labels": _labels(self.config.run_id),
                        },
                        {
                            "action": "attach",
                            "storage": source_volume_id,
                            "type": "disk",
                            "address": "scsi",
                        },
                    ]
                },
                # UpCloud starts the server before the separate firewall PUT.
                # Create it with only the utility interface; public families
                # are assigned after the exact chain is read back.
                "networking": {
                    "interfaces": {
                        "interface": [
                            {
                                "type": "utility",
                                "ip_addresses": {
                                    "ip_address": [{"family": "IPv4"}]
                                },
                            }
                        ]
                    }
                },
                "login_user": {
                    "username": self.config.ssh_user,
                    "create_password": "no",
                    "ssh_keys": {"ssh_key": [public_key]},
                },
            }
        }

    @staticmethod
    def _boot_device(server: dict) -> dict:
        devices = UpCloudLiveHarness._server_storage_devices(server)
        boot_order = str(server.get("boot_order") or "").strip().casefold()
        if boot_order != "disk":
            raise HarnessError("The UpCloud server boot order is not disk.")
        boot = [
            device
            for device in devices
            if str(device.get("type") or "disk").casefold() == "disk"
            and str(device.get("boot_disk") or "0").casefold()
            in {"1", "yes", "true"}
        ]
        if len(boot) == 1:
            return boot[0]
        if boot:
            raise HarnessError("The UpCloud server has multiple boot storages.")
        # The live create API rejects ``boot_disk`` as an input attribute and
        # can return "0" for every attached device. The first cloned plan disk
        # is assigned virtio:0, while this harness pins the data volume to the
        # SCSI bus. Infer only that one exact, provider-assigned boot address.
        disk_devices = [
            device
            for device in devices
            if str(device.get("type") or "disk").casefold() == "disk"
        ]
        addresses = [str(device.get("address") or "").casefold() for device in disk_devices]
        if len(addresses) != len(set(addresses)):
            raise HarnessError("The UpCloud server has duplicate storage addresses.")
        inferred = [
            device
            for device in disk_devices
            if str(device.get("address") or "").casefold() == "virtio:0"
            and _label_map(device.get("labels")).get("_os_type")
            and UPCLOUD_UUID_RE.fullmatch(
                _label_map(device.get("labels")).get("_template_uuid", "")
            )
        ]
        if len(inferred) != 1:
            raise HarnessError("The UpCloud server does not have one exact boot storage.")
        return inferred[0]

    def _ensure_provider_public_ip_families(
        self,
        server_id: str,
        expected_families=("IPv4",),
        *,
        firewall_verified_at,
    ) -> dict:
        """Assign public families after the durable firewall settle window."""
        if not UPCLOUD_UUID_RE.fullmatch(str(server_id or "")):
            raise HarnessError("UpCloud server UUID is malformed.")
        expected = [str(family) for family in expected_families]
        if not expected or any(family not in {"IPv4", "IPv6"} for family in expected):
            raise HarnessError("The witnessed UpCloud public IP families are malformed.")
        if expected != sorted(expected, key=lambda family: (family != "IPv4", family)):
            raise HarnessError("The witnessed UpCloud public IP families are unordered.")

        def observe():
            server = self._server_read(server_id)
            if server is None:
                raise AmbiguousMutation(
                    "The exact UpCloud server is not readable for public-IP reconciliation."
                )
            contract = self._server_network_contract(server)
            actual = list(contract["public_ip_families"])
            if len(actual) > len(expected) or actual != expected[: len(actual)]:
                raise HarnessError(
                    "The UpCloud server has an unexpected public network shape."
                )
            return server, actual

        server, actual = observe()
        verified_at = _utc_timestamp(firewall_verified_at)
        stabilization_deadline = verified_at + timedelta(
            seconds=FIREWALL_STABILIZATION_SECONDS
        )
        clock_value = self.clock()
        if isinstance(clock_value, datetime):
            now = clock_value
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            now = now.astimezone(timezone.utc)
        else:
            now = _utc_timestamp(clock_value)
        if now < stabilization_deadline:
            if actual:
                raise HarnessError(
                    "The UpCloud server exposed a public interface before firewall "
                    "stabilization completed."
                )
            raise HarnessError(
                "The UpCloud firewall is read back exactly but remains in its "
                f"120-second stabilization window until {stabilization_deadline.isoformat()}."
            )
        for ordinal in range(len(expected)):
            if len(actual) > ordinal:
                continue
            family = expected[ordinal]
            intent_key = f"compute_source_public_ip:{server_id}:{ordinal}:{family}"
            request = {
                "ip_address": {"family": family, "server": str(server_id)}
            }
            request_fingerprint = _fingerprint(request)
            intent = self.intents.get(intent_key)
            if intent and any(
                (
                    intent.get("request_fingerprint") != request_fingerprint,
                    intent.get("server_id") != str(server_id),
                    intent.get("family") != family,
                    intent.get("ordinal") != ordinal,
                )
            ):
                raise HarnessError("The pending UpCloud public-IP intent changed scope.")
            if intent and intent.get("request_boundary_crossed"):
                server, actual = observe()
                if len(actual) <= ordinal:
                    raise AmbiguousMutation(
                        "The UpCloud public-IP request crossed the provider boundary "
                        "without exact read-back; no duplicate was sent."
                    )
                self.intents.clear(intent_key)
                continue

            self.intents.put(
                intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": "compute_source_public_ip",
                    "name": self.names["source_server"],
                    "operation": "assign",
                    "server_id": str(server_id),
                    "family": family,
                    "ordinal": ordinal,
                    "request_fingerprint": request_fingerprint,
                    "preflight_families": list(actual),
                },
            )
            self.intents.update(intent_key, request_boundary_crossed=True)
            self._control_mutation(
                intent_key,
                "POST",
                "/ip_address",
                accepted=(201, 202),
                json_body=request,
            )
            server, actual = observe()
            if len(actual) <= ordinal:
                raise AmbiguousMutation(
                    "UpCloud accepted a public-IP assignment without exact read-back."
                )
            self.intents.clear(intent_key)
        server, actual = observe()
        if actual != expected:
            raise AmbiguousMutation(
                "The UpCloud server public network did not reach the exact witnessed shape."
            )
        return server

    def _source_server_owned(
        self,
        server: dict,
        *,
        resource_id: str,
        source_volume_id: str,
        expected_config=None,
        expected_firewall=None,
        verify_firewall=True,
    ) -> tuple[bool, dict, str]:
        labels = _label_map(server.get("labels")) if isinstance(server, dict) else {}
        if not all(
            (
                isinstance(server, dict),
                str(server.get("uuid") or "") == str(resource_id),
                str(server.get("title") or "") == self.names["source_server"],
                str(server.get("hostname") or "") == self.names["hostname"],
                str(server.get("zone") or "") == self.config.zone,
                str(server.get("state") or "").casefold()
                in {"maintenance", "started", "stopped"},
                labels.get("backupsheep-e2e-owned") == "true",
                labels.get("backupsheep-e2e-run") == self.config.run_id,
            )
        ):
            return False, {}, ""
        boot = self._boot_device(server)
        boot_id = str(boot.get("storage") or "")
        devices = self._server_storage_devices(server)
        source_matches = [
            device
            for device in devices
            if str(device.get("storage") or "") == source_volume_id
            and str(device.get("boot_disk") or "0").casefold()
            in {"0", "no", "false"}
        ]
        if len(source_matches) != 1 or boot_id == source_volume_id:
            return False, {}, ""
        config = self._server_safe_config(server, boot)
        if expected_config is not None and config != expected_config:
            return False, {}, ""
        if verify_firewall:
            observation = self._provider_firewall_observation(
                resource_id, server=server
            )
            if not self._provider_firewall_is_exact(observation):
                return False, {}, ""
            if expected_firewall is not None and (
                observation.get("rules_sha256")
                != expected_firewall.get("rules_sha256")
                or observation.get("allow_rule_fingerprints")
                != expected_firewall.get("allow_rule_fingerprints")
            ):
                return False, {}, ""
        return True, config, boot_id

    def _record_source_server(self, server: dict, source_volume_id: str) -> dict:
        resource_id = str(server.get("uuid") or "")
        owned, safe_config, boot_id = self._source_server_owned(
            server,
            resource_id=resource_id,
            source_volume_id=source_volume_id,
            verify_firewall=False,
        )
        if not owned:
            raise HarnessError("UpCloud source-server ownership verification failed.")
        server = self._wait_server_started(resource_id)
        firewall_evidence = self._ensure_provider_firewall(resource_id)
        server = self._ensure_provider_public_ip_families(
            resource_id,
            ("IPv4",),
            firewall_verified_at=firewall_evidence["firewall_verified_at"],
        )
        server = self._server_read(resource_id)
        owned, safe_config, boot_id = self._source_server_owned(
            server or {},
            resource_id=resource_id,
            source_volume_id=source_volume_id,
            verify_firewall=True,
        )
        if not owned:
            raise HarnessError("UpCloud source-server firewall ownership verification failed.")
        boot = self._storage_read(boot_id)
        if boot is None or not self._source_storage_owned(
            boot,
            resource_id=boot_id,
            title=self.names["source_boot"],
            expected_servers=[resource_id],
        ):
            raise HarnessError("UpCloud boot-storage ownership verification failed.")
        self.ledger.record(
            kind="compute_source_boot",
            resource_id=boot_id,
            name=self.names["source_boot"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "zone": self.config.zone,
                "type": "normal",
                "tier": "standard",
                "encrypted": "yes",
                "server_id": resource_id,
            },
            source_witness=resource_id,
        )
        self.ledger.record(
            kind="compute_source_attachment",
            resource_id=f"{resource_id}:{source_volume_id}",
            name=self.names["source_volume"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "server_id": resource_id,
                "storage_id": source_volume_id,
                "boot_disk": False,
            },
            source_witness=f"{resource_id}:{source_volume_id}",
        )
        return self.ledger.record(
            kind="compute_source_server",
            resource_id=resource_id,
            name=self.names["source_server"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "zone": self.config.zone,
                "source_volume_id": source_volume_id,
                "boot_storage_id": boot_id,
                "safe_config": safe_config,
                "safe_config_sha256": _fingerprint(safe_config),
                "public_ipv4": self._server_public_addresses(server),
                "public_ip_families": safe_config["public_ip_families"],
                "provider_firewall": firewall_evidence,
            },
            source_witness=source_volume_id,
        )

    def ensure_source_server(self, source_volume: dict) -> dict:
        source_volume_id = str(source_volume.get("uuid") or "")
        entry = self._one_active("compute_source_server")
        if entry:
            server = self._server_read(entry["resource_id"])
            owned, _config, boot_id = self._source_server_owned(
                server or {},
                resource_id=entry["resource_id"],
                source_volume_id=source_volume_id,
                expected_config=(entry.get("ownership") or {}).get("safe_config"),
            )
            if not owned or boot_id != (entry.get("ownership") or {}).get(
                "boot_storage_id"
            ):
                raise HarnessError("The ledgered UpCloud source server changed.")
            return server

        private_key, public_key = self._ensure_ssh_key()
        del private_key
        request = self._source_server_request(source_volume_id, public_key)
        request_fingerprint = _fingerprint(request)
        intent_key = "compute_source_server_create"
        intent = self.intents.get(intent_key)
        summary = self._exact_title(
            self._compute_inventory("server"), self.names["source_server"]
        )
        if summary is not None:
            if (
                not intent
                or not intent.get("request_boundary_crossed")
                or intent.get("request_fingerprint") != request_fingerprint
            ):
                raise HarnessError(
                    "An unledgered UpCloud server has the exact run title."
                )
            server = self._server_read(str(summary.get("uuid") or ""))
            if server is None:
                raise AmbiguousMutation("The pending source server is not exactly readable.")
            self._record_source_server(server, source_volume_id)
            self.intents.clear(intent_key)
            return server
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "The source-server create crossed the provider boundary but no exact "
                "owned resource is visible; no duplicate was sent."
            )

        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "compute_source_server",
                "name": self.names["source_server"],
                "operation": "create",
                "request_fingerprint": request_fingerprint,
                "source_volume_id": source_volume_id,
                "public_key_sha256": _hash(public_key),
                "preflight_absent": True,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        payload = self._control_mutation(
            intent_key,
            "POST",
            "/server",
            accepted=(202,),
            json_body=request,
        )
        returned = payload.get("server") if isinstance(payload, dict) else None
        resource_id = str(returned.get("uuid") or "") if isinstance(returned, dict) else ""
        if not UPCLOUD_UUID_RE.fullmatch(resource_id):
            summary = self._exact_title(
                self._compute_inventory("server"), self.names["source_server"]
            )
            resource_id = str(summary.get("uuid") or "") if summary else ""
        server = self._server_read(resource_id) if resource_id else None
        if server is None:
            raise AmbiguousMutation(
                "UpCloud accepted the source-server create without exact read-back."
            )
        self._record_source_server(server, source_volume_id)
        self.intents.clear(intent_key)
        return server

    def _wait_server_started(self, resource_id: str) -> dict:
        for _attempt in range(COMPUTE_MAX_WAIT_POLLS):
            server = self._server_read(resource_id)
            if server is None:
                raise HarnessError("The exact UpCloud server disappeared while waiting.")
            state = str(server.get("state") or "").casefold()
            if state == "started":
                return server
            if state in {"error", "failed"}:
                raise HarnessError("The exact UpCloud server entered a terminal state.")
            if state not in {"maintenance", "started", "stopped"}:
                raise HarnessError("UpCloud returned an unknown server state.")
            if state == "stopped":
                raise HarnessError("The test server stopped before fixture seeding.")
            self.sleep(COMPUTE_POLL_SECONDS)
        raise HarnessError("The UpCloud server did not start within the bounded waiter.")

    def _fixture_payload(self) -> tuple[bytes, str, int]:
        try:
            byte_count = int(self.environment.get("UPCLOUD_E2E_DATA_BYTES") or 1048576)
        except (TypeError, ValueError):
            raise HarnessError("UPCLOUD_E2E_DATA_BYTES must be an integer.") from None
        if not 4096 <= byte_count <= 64 * 1024 * 1024:
            raise HarnessError("UPCLOUD_E2E_DATA_BYTES is outside safe bounds.")
        chunks = []
        remaining = byte_count
        counter = 0
        while remaining:
            chunk = hashlib.sha256(
                f"{self.config.run_id}:upcloud-e2e:{counter}".encode("utf-8")
            ).digest()
            take = min(len(chunk), remaining)
            chunks.append(chunk[:take])
            remaining -= take
            counter += 1
        payload = b"".join(chunks)
        return payload, hashlib.sha256(payload).hexdigest(), byte_count

    def _ssh_client(self, server: dict, *, host_variable: str):
        try:
            import paramiko
        except Exception:
            raise HarnessError("Paramiko is required for UpCloud data verification.") from None
        private_path, _public_key = self._ensure_ssh_key()
        _private, _public, known_hosts = self._key_paths()
        addresses = set(self._server_public_addresses(server))
        configured = str(self.environment.get(host_variable) or "").strip()
        host = configured or (sorted(addresses)[0] if addresses else "")
        if not host or host not in addresses:
            raise HarnessError("SSH host is not an exact provider-reported address.")
        client = paramiko.SSHClient()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        first_connection = host not in client.get_host_keys()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if first_connection else paramiko.RejectPolicy()
        )
        try:
            key = paramiko.RSAKey.from_private_key_file(str(private_path))
            client.connect(
                hostname=host,
                username=self.config.ssh_user,
                pkey=key,
                allow_agent=False,
                look_for_keys=False,
                timeout=REQUEST_TIMEOUT[0],
                banner_timeout=REQUEST_TIMEOUT[1],
                auth_timeout=REQUEST_TIMEOUT[1],
            )
            if first_connection:
                known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                client.save_host_keys(str(known_hosts))
                os.chmod(known_hosts, 0o600)
            return client
        except Exception:
            client.close()
            raise HarnessError("SSH connection to the exact UpCloud test server failed.") from None

    def _wait_ssh_client(self, server: dict, *, host_variable: str):
        """Wait for cloud-init/sshd after provider state becomes started."""

        for attempt in range(SSH_MAX_WAIT_POLLS):
            try:
                return self._ssh_client(server, host_variable=host_variable)
            except HarnessError:
                if attempt + 1 == SSH_MAX_WAIT_POLLS:
                    break
                self.sleep(SSH_POLL_SECONDS)
        raise HarnessError(
            "SSH on the exact UpCloud test server did not become ready within the bounded waiter."
        )

    @staticmethod
    def _ssh_host_key_fingerprint(client) -> str:
        try:
            raw = client.get_transport().get_remote_server_key().asbytes()
        except Exception:
            raise HarnessError("The UpCloud SSH host key was not readable.") from None
        if not isinstance(raw, bytes) or not raw:
            raise HarnessError("The UpCloud SSH host key was malformed.")
        return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode(
            "ascii"
        ).rstrip("=")

    def _guest_restore_evidence(self, client, server: dict) -> dict:
        """Verify the restored guest network, boot, and bounded egress state."""

        provider_addresses = self._server_public_addresses(server)
        if len(provider_addresses) != 1:
            raise HarnessError("Guest verification requires one exact provider public IPv4.")
        try:
            addresses = json.loads(self._ssh_run(client, "ip -j address show", timeout=30))
            routes = json.loads(self._ssh_run(client, "ip -j route show default", timeout=30))
        except (TypeError, ValueError):
            raise HarnessError("The restored guest returned malformed network evidence.") from None
        if not isinstance(addresses, list) or not isinstance(routes, list):
            raise HarnessError("The restored guest returned malformed network evidence.")
        matches = []
        for interface in addresses:
            if not isinstance(interface, dict):
                raise HarnessError("The restored guest returned malformed interfaces.")
            for address in interface.get("addr_info") or []:
                if (
                    isinstance(address, dict)
                    and address.get("family") == "inet"
                    and address.get("scope") == "global"
                    and str(address.get("local") or "") == provider_addresses[0]
                ):
                    matches.append(interface)
        if len(matches) != 1:
            raise HarnessError("The restored guest public IP does not match the provider.")
        interface = matches[0]
        ifname = str(interface.get("ifname") or "")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", ifname)
            or str(interface.get("operstate") or "").upper() != "UP"
        ):
            raise HarnessError("The restored guest public interface is not UP.")
        defaults = [
            route
            for route in routes
            if isinstance(route, dict)
            and str(route.get("dst") or "default") == "default"
            and str(route.get("dev") or "") == ifname
        ]
        if len(defaults) != 1:
            raise HarnessError("The restored guest default route uses another interface.")
        boot = self._ssh_run(
            client,
            "printf '%s|' \"$(cat /proc/sys/kernel/random/boot_id)\"; "
            "awk '{printf \"%.0f\\n\", $1}' /proc/uptime",
            timeout=30,
        )
        boot_id, separator, uptime_value = boot.partition("|")
        try:
            uptime_seconds = int(uptime_value)
        except (TypeError, ValueError):
            uptime_seconds = -1
        if (
            not separator
            or not UPCLOUD_UUID_RE.fullmatch(boot_id)
            or uptime_seconds < 0
            or uptime_seconds > 31 * 24 * 60 * 60
        ):
            raise HarnessError("The restored guest boot/uptime evidence is malformed.")
        reachability = self._ssh_run(
            client,
            "python3 -c 'import socket; s=socket.create_connection((\"1.1.1.1\",443),5); s.close(); print(\"reachable\")'",
            timeout=15,
        )
        if reachability != "reachable":
            raise HarnessError("The restored guest outbound reachability check failed.")
        return {
            "interface": ifname,
            "interface_state": "UP",
            "public_ip_sha256": _hash(provider_addresses[0]),
            "default_route_interface": ifname,
            "outbound_reachability": "verified",
            "outbound_target": "1.1.1.1:443",
            "boot_id_sha256": _hash(boot_id),
            "uptime_seconds": uptime_seconds,
        }

    @staticmethod
    def _ssh_run(client, command: str, *, timeout: int = 60) -> str:
        try:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
            payload = stdout.read(16384)
            status_code = stdout.channel.recv_exit_status()
        except Exception:
            raise HarnessError("The bounded UpCloud remote command failed.") from None
        if status_code != 0 or len(payload) >= 16384:
            raise HarnessError("The bounded UpCloud remote command was not successful.")
        try:
            return payload.decode("utf-8", "strict").strip()
        except UnicodeDecodeError:
            raise HarnessError("The UpCloud remote command returned malformed output.") from None

    @staticmethod
    def _ssh_run_input(
        client, command: str, payload: str, *, timeout: int = 120
    ) -> str:
        try:
            stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
            stdin.write(payload)
            stdin.flush()
            stdin.channel.shutdown_write()
            output = stdout.read(16384)
            status_code = stdout.channel.recv_exit_status()
        except Exception:
            raise HarnessError("The bounded UpCloud remote input command failed.") from None
        if status_code != 0 or len(output) >= 16384:
            raise HarnessError("The bounded UpCloud remote input command was not successful.")
        try:
            return output.decode("utf-8", "strict").strip()
        except UnicodeDecodeError:
            raise HarnessError("The UpCloud remote input command returned malformed output.") from None

    @staticmethod
    def _upload_payload(client, run_id: str, payload: bytes) -> str:
        remote = f"/tmp/{run_id}-upcloud-e2e.bin"
        try:
            sftp = client.open_sftp()
            with sftp.file(remote, "wb") as target:
                target.write(payload)
                target.flush()
            sftp.close()
        except Exception:
            raise HarnessError("Could not upload deterministic UpCloud test bytes.") from None
        return remote

    @staticmethod
    def _upload_bytes(client, remote: str, payload: bytes) -> str:
        if not re.fullmatch(r"/tmp/[A-Za-z0-9_.-]{1,180}", remote):
            raise HarnessError("The UpCloud temporary upload path is malformed.")
        try:
            sftp = client.open_sftp()
            with sftp.file(remote, "wb") as target:
                target.write(payload)
                target.flush()
            sftp.chmod(remote, 0o600)
            sftp.close()
        except Exception:
            raise HarnessError("Could not upload a bounded UpCloud fixture file.") from None
        return remote

    def _storage_device_path(self, client, storage_id: str) -> str:
        if not UPCLOUD_UUID_RE.fullmatch(storage_id):
            raise HarnessError("The UpCloud storage UUID is malformed.")
        serial = storage_id.replace("-", "")[:20]
        rows = self._ssh_run(client, "sudo -n lsblk -ndo PATH,SERIAL")
        matches = []
        for row in rows.splitlines():
            parts = row.split()
            if len(parts) == 2 and parts[1].casefold() == serial.casefold():
                matches.append(parts[0])
        if len(matches) != 1 or not re.fullmatch(r"/dev/[A-Za-z0-9_.:/-]{1,120}", matches[0]):
            raise HarnessError("The exact UpCloud storage device was not uniquely visible.")
        return matches[0]

    @staticmethod
    def _exact_mount_source(output: str, mount_path: str) -> str:
        """Return SOURCE only when findmnt reports this exact target mount."""

        lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
        if not lines:
            return ""
        if len(lines) != 1:
            raise HarnessError("The UpCloud mount inventory is ambiguous.")
        parts = lines[0].split(None, 1)
        if len(parts) != 2:
            raise HarnessError("The UpCloud mount inventory is malformed.")
        source, target = parts
        if target != mount_path:
            return ""
        if not re.fullmatch(r"/dev/[A-Za-z0-9_.:/-]{1,120}", source):
            raise HarnessError("The UpCloud mount source is malformed.")
        return source

    def _mount_storage(
        self,
        client,
        storage_id: str,
        *,
        mount_path: str,
        read_only: bool,
    ) -> str:
        device = self._storage_device_path(client, storage_id)
        quoted_device = shlex.quote(device)
        quoted_mount = shlex.quote(mount_path)
        filesystem = self._ssh_run(
            client, f"sudo -n blkid -o value -s TYPE {quoted_device} 2>/dev/null || true"
        )
        if read_only:
            if filesystem != "ext4":
                raise HarnessError("The restored UpCloud storage is not the expected ext4 filesystem.")
        elif not filesystem:
            self._ssh_run(client, f"sudo -n mkfs.ext4 -F {quoted_device} >/dev/null")
        elif filesystem != "ext4":
            raise HarnessError("The source UpCloud storage has an unexpected filesystem.")
        self._ssh_run(client, f"sudo -n mkdir -p {quoted_mount}")
        mounted = self._exact_mount_source(
            self._ssh_run(
                client,
                f"findmnt -n -o SOURCE,TARGET --target {quoted_mount} 2>/dev/null || true",
            ),
            mount_path,
        )
        if not mounted:
            option = "-o ro,noload" if read_only else ""
            self._ssh_run(
                client,
                f"sudo -n mount {option} {quoted_device} {quoted_mount}".replace(
                    "mount  ", "mount "
                ),
            )
            mounted = self._exact_mount_source(
                self._ssh_run(
                    client, f"findmnt -n -o SOURCE,TARGET --target {quoted_mount}"
                ),
                mount_path,
            )
        if not mounted:
            raise HarnessError("The exact UpCloud storage mount was not visible.")
        expected_real = self._ssh_run(client, f"readlink -f {quoted_device}")
        actual_real = self._ssh_run(client, f"readlink -f {shlex.quote(mounted)}")
        if expected_real != actual_real:
            raise HarnessError("The mounted filesystem is not the exact UpCloud storage.")
        return device

    def _remote_evidence(self, client, path: str) -> dict:
        quoted = shlex.quote(path)
        digest = self._ssh_run(
            client, f"sudo -n sha256sum {quoted} | cut -d' ' -f1"
        )
        size = self._ssh_run(client, f"sudo -n stat -c %s {quoted}")
        if not SHA256_RE.fullmatch(digest):
            raise HarnessError("Remote UpCloud SHA-256 evidence is malformed.")
        try:
            byte_count = int(size)
        except (TypeError, ValueError):
            raise HarnessError("Remote UpCloud byte-count evidence is malformed.") from None
        return {"sha256": digest, "byte_count": byte_count}

    def _record_compute_fixture(
        self,
        *,
        kind: str,
        resource_id: str,
        server_id: str,
        path: str,
        evidence: dict,
    ) -> dict:
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=path,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "server_id": server_id,
                "path": path,
                "sha256": evidence["sha256"],
                "byte_count": evidence["byte_count"],
                "filesystem_flushed": True,
            },
            source_witness=server_id,
        )

    def seed_compute_fixtures(self, server: dict, source_volume: dict) -> dict:
        server_id = str(server.get("uuid") or "")
        volume_id = str(source_volume.get("uuid") or "")
        payload, expected_sha256, expected_bytes = self._fixture_payload()
        expected = {"sha256": expected_sha256, "byte_count": expected_bytes}
        root_path = f"/var/lib/backupsheep-e2e/{self.config.run_id}/payload.bin"
        mount_path = f"/mnt/backupsheep-e2e-{self.config.run_id}"
        volume_path = f"{mount_path}/payload.bin"
        client = self._wait_ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            existing_root = self._one_active("compute_server_fixture")
            existing_volume = self._one_active("compute_volume_fixture")
            if existing_root and existing_volume:
                root_actual = self._remote_evidence(client, root_path)
                self._mount_storage(
                    client,
                    volume_id,
                    mount_path=mount_path,
                    read_only=False,
                )
                volume_actual = self._remote_evidence(client, volume_path)
                if root_actual != expected or volume_actual != expected:
                    raise HarnessError("The ledgered UpCloud source fixture changed.")
                return {"server": root_actual, "volume": volume_actual}
            if existing_root or existing_volume:
                raise HarnessError("The UpCloud fixture ledger is incomplete.")
            remote = self._upload_payload(client, self.config.run_id, payload)
            self._ssh_run(
                client,
                f"sudo -n mkdir -p {shlex.quote(str(Path(root_path).parent))}",
            )
            self._ssh_run(
                client,
                f"sudo -n install -m 0600 {shlex.quote(remote)} {shlex.quote(root_path)}",
            )
            self._mount_storage(
                client,
                volume_id,
                mount_path=mount_path,
                read_only=False,
            )
            self._ssh_run(
                client,
                f"sudo -n install -m 0600 {shlex.quote(remote)} {shlex.quote(volume_path)}",
            )
            self._ssh_run(client, "sudo -n sync")
            root_actual = self._remote_evidence(client, root_path)
            volume_actual = self._remote_evidence(client, volume_path)
            self._ssh_run(client, f"rm -f {shlex.quote(remote)}")
        finally:
            client.close()
        if root_actual != expected or volume_actual != expected:
            raise HarnessError("UpCloud source fixture byte/hash verification failed.")
        self._record_compute_fixture(
            kind="compute_server_fixture",
            resource_id=server_id,
            server_id=server_id,
            path=root_path,
            evidence=root_actual,
        )
        self._record_compute_fixture(
            kind="compute_volume_fixture",
            resource_id=volume_id,
            server_id=server_id,
            path=volume_path,
            evidence=volume_actual,
        )
        return {"server": root_actual, "volume": volume_actual}

    def _workload_names(self) -> dict:
        digest = _hash(f"{self.config.run_id}:workloads")[:12]
        base = f"/srv/backupsheep-e2e/{self.config.run_id}"
        return {
            "base": base,
            "website_root": f"{base}/website",
            "database": f"bs_e2e_{digest}"[:63],
            "database_user": f"bs_e2e_u_{digest}"[:63],
            "nginx_site": f"backupsheep-e2e-{self.config.run_id}",
        }

    def _website_archive(self) -> tuple[bytes, dict]:
        payload, _sha256, _byte_count = self._fixture_payload()
        catalog = {
            "run_id": self.config.run_id,
            "records": [
                {
                    "id": index,
                    "slug": f"record-{index:03d}",
                    "score": (index * 37) % 101,
                }
                for index in range(1, 81)
            ],
        }
        files = {
            "index.html": (
                "<!doctype html><html><head><meta charset=\"utf-8\">"
                "<title>BackupSheep UpCloud E2E</title>"
                "<link rel=\"stylesheet\" href=\"/assets/site.css\"></head>"
                f"<body><main><h1>{self.config.run_id}</h1>"
                "<p>Deterministic website backup fixture.</p></main></body></html>\n"
            ).encode("utf-8"),
            "assets/site.css": (
                "body{font-family:system-ui;background:#f4f1e8;color:#17202a}"
                "main{max-width:48rem;margin:4rem auto;padding:2rem}\n"
            ).encode("utf-8"),
            "data/catalog.json": (
                json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
            "downloads/deterministic.bin": payload[:65536],
        }
        manifest = {
            name: {
                "sha256": hashlib.sha256(content).hexdigest(),
                "byte_count": len(content),
            }
            for name, content in sorted(files.items())
        }
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as output:
            for name, content in sorted(files.items()):
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                info.mode = 0o640
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                output.addfile(info, io.BytesIO(content))
        return archive.getvalue(), {
            "files": manifest,
            "file_count": len(manifest),
            "byte_count": sum(item["byte_count"] for item in manifest.values()),
            "tree_sha256": _fingerprint(manifest),
        }

    def _database_fixture(self, database: str, database_user: str, password: str) -> dict:
        if not all(
            re.fullmatch(r"[a-z][a-z0-9_]{2,62}", value)
            for value in (database, database_user)
        ) or not re.fullmatch(r"[0-9a-f]{64}", password):
            raise HarnessError("The generated PostgreSQL fixture identity is malformed.")
        customers = [
            (
                index,
                f"customer{index:04d}@example.invalid",
                ("bronze", "silver", "gold")[index % 3],
                f"2026-{((index - 1) % 12) + 1:02d}-{((index - 1) % 28) + 1:02d}",
            )
            for index in range(1, 121)
        ]
        events = [
            (
                index,
                ((index * 17) % len(customers)) + 1,
                ("created", "updated", "verified", "archived")[index % 4],
                f"payload-{self.config.run_id}-{index:04d}",
            )
            for index in range(1, 481)
        ]
        customer_values = ",\n".join(
            "(%d,'%s','%s','%s')" % row for row in customers
        )
        event_values = ",\n".join(
            "(%d,%d,'%s','%s')" % row for row in events
        )
        initialize_sql = f"""
SET password_encryption = 'scram-sha-256';
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname = '{database}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS {database};
DO $bs$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{database_user}') THEN
    CREATE ROLE {database_user} LOGIN PASSWORD '{password}';
  ELSE
    ALTER ROLE {database_user} WITH LOGIN PASSWORD '{password}';
  END IF;
END
$bs$;
CREATE DATABASE {database} OWNER {database_user};
""".strip() + "\n"
        data_sql = f"""
\\connect {database}
CREATE TABLE customers (
  id integer PRIMARY KEY,
  email text NOT NULL UNIQUE,
  tier text NOT NULL,
  created_on date NOT NULL
);
CREATE TABLE events (
  id integer PRIMARY KEY,
  customer_id integer NOT NULL REFERENCES customers(id),
  event_type text NOT NULL,
  payload text NOT NULL
);
INSERT INTO customers (id,email,tier,created_on) VALUES
{customer_values};
INSERT INTO events (id,customer_id,event_type,payload) VALUES
{event_values};
ALTER TABLE customers OWNER TO {database_user};
ALTER TABLE events OWNER TO {database_user};
""".strip() + "\n"
        canonical_lines = sorted(
            [
                f"customers|{row[0]}|{row[1]}|{row[2]}|{row[3]}"
                for row in customers
            ]
            + [
                f"events|{row[0]}|{row[1]}|{row[2]}|{row[3]}"
                for row in events
            ]
        )
        schema_lines = [
            "customers|created_on|date|NO",
            "customers|email|text|NO",
            "customers|id|integer|NO",
            "customers|tier|text|NO",
            "events|customer_id|integer|NO",
            "events|event_type|text|NO",
            "events|id|integer|NO",
            "events|payload|text|NO",
        ]
        return {
            "initialize_sql": initialize_sql,
            "data_sql": data_sql,
            "row_counts": {"customers": len(customers), "events": len(events)},
            "total_rows": len(customers) + len(events),
            "canonical_sha256": hashlib.sha256(
                "\n".join(canonical_lines).encode("utf-8")
            ).hexdigest(),
            "schema_sha256": hashlib.sha256(
                "\n".join(schema_lines).encode("utf-8")
            ).hexdigest(),
        }

    def _ensure_compute_runtime(self, server: dict) -> dict:
        path = _compute_runtime_path(
            self.config.runtime_path, self.config.run_id
        )
        names = self._workload_names()
        addresses = sorted(self._server_public_addresses(server))
        if len(addresses) != 1:
            raise HarnessError(
                "The common workload server must have one exact public IPv4 address."
            )
        if path.exists():
            payload = _read_compute_runtime_secret(path)
            if any(
                (
                    payload.get("run_id") != self.config.run_id,
                    payload.get("account") != self.account,
                    payload.get("server_uuid") != str(server.get("uuid") or ""),
                    payload.get("ssh_user") != self.config.ssh_user,
                    payload.get("website_root") != names["website_root"],
                    payload.get("database_host") != addresses[0],
                    payload.get("database_port") != "5432",
                    payload.get("database_name") != names["database"],
                    payload.get("database_user") != names["database_user"],
                )
            ):
                raise HarnessError("The UpCloud compute runtime scope changed.")
            return payload
        if self._one_active("compute_workload_fixture"):
            raise SecretUnavailable(
                "The workload credential was lost; no replacement was generated."
            )
        payload = {
            "schema": COMPUTE_RUNTIME_SCHEMA,
            "provider": "upcloud",
            "run_id": self.config.run_id,
            "account": self.account,
            "server_uuid": str(server.get("uuid") or ""),
            "ssh_user": self.config.ssh_user,
            "website_root": names["website_root"],
            "database_host": addresses[0],
            "database_port": "5432",
            "database_name": names["database"],
            "database_user": names["database_user"],
            "database_password": secrets.token_hex(32),
        }
        _write_compute_runtime_secret(path, payload)
        return payload

    def _website_evidence(self, client, root: str, expected: dict) -> dict:
        root = self._owned_website_restore_path(root)
        path_probe = (
            "import json,os,stat,sys\n"
            "path=sys.argv[1]\n"
            "current=''\n"
            "links=[]\n"
            "for part in [value for value in path.split('/') if value]:\n"
            "    current += '/' + part\n"
            "    if stat.S_ISLNK(os.lstat(current).st_mode):\n"
            "        links.append(current)\n"
            "print(json.dumps({'realpath':os.path.realpath(path),'symlinks':links},sort_keys=True))\n"
        )
        identity = self._ssh_run(
            client,
            "sudo -n python3 -c "
            + shlex.quote(path_probe)
            + " "
            + shlex.quote(root),
            timeout=30,
        )
        try:
            identity = json.loads(identity)
        except (TypeError, ValueError):
            raise HarnessError("The website restore path identity is malformed.") from None
        if (
            not isinstance(identity, dict)
            or identity.get("realpath") != root
            or identity.get("symlinks") != []
        ):
            raise HarnessError("The website restore path contains symlink ambiguity.")
        quoted_root = shlex.quote(root)
        listing = self._ssh_run(
            client,
            f"sudo -n find {quoted_root} -type f -printf '%P\\n' | LC_ALL=C sort",
        )
        observed_names = listing.splitlines() if listing else []
        expected_files = expected.get("files") if isinstance(expected, dict) else None
        if not isinstance(expected_files, dict) or observed_names != sorted(expected_files):
            raise HarnessError("The website tree contains missing or unexpected files.")
        observed = {}
        for name in observed_names:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name):
                raise HarnessError("The website tree contains an unsafe relative path.")
            path = f"{root}/{name}"
            evidence = self._remote_evidence(client, path)
            if evidence != expected_files[name]:
                raise HarnessError("A website fixture file failed hash/size verification.")
            observed[name] = evidence
        result = {
            "files": observed,
            "file_count": len(observed),
            "byte_count": sum(item["byte_count"] for item in observed.values()),
            "tree_sha256": _fingerprint(observed),
        }
        if any(result.get(key) != expected.get(key) for key in result):
            raise HarnessError("The website tree witness changed.")
        return result

    def _database_evidence(self, client, database: str) -> dict:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,62}", database):
            raise HarnessError("The PostgreSQL evidence database name is malformed.")

        def query_sha256(query: str) -> str:
            psql = (
                "sudo -n -u postgres psql -At --set=ON_ERROR_STOP=1 "
                f"--dbname={shlex.quote(database)} --command={shlex.quote(query)}"
            )
            digest = "python3 -c " + shlex.quote(
                "import hashlib,sys; data=sys.stdin.buffer.read(); "
                "print(hashlib.sha256(data.rstrip(b'\\n')).hexdigest())"
            )
            value = self._ssh_run(
                client,
                "bash -o pipefail -c " + shlex.quote(f"{psql} | {digest}"),
            )
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise HarnessError("PostgreSQL returned a malformed evidence digest.")
            return value

        row_counts = self._ssh_run(
            client,
            "sudo -n -u postgres psql -At --set=ON_ERROR_STOP=1 "
            f"--dbname={shlex.quote(database)} --command="
            + shlex.quote(
                "SELECT (SELECT count(*) FROM customers)::text || '|' || "
                "(SELECT count(*) FROM events)::text;"
            ),
        )
        parts = row_counts.split("|")
        if len(parts) != 2:
            raise HarnessError("PostgreSQL row-count evidence is malformed.")
        try:
            counts = {"customers": int(parts[0]), "events": int(parts[1])}
        except (TypeError, ValueError):
            raise HarnessError("PostgreSQL row-count evidence is malformed.") from None
        canonical_sha256 = query_sha256(
                "SELECT line FROM ("
                "SELECT 'customers|' || id::text || '|' || email || '|' || tier || '|' || created_on::text AS line FROM customers "
                "UNION ALL "
                "SELECT 'events|' || id::text || '|' || customer_id::text || '|' || event_type || '|' || payload AS line FROM events"
                ") AS rows ORDER BY line COLLATE \"C\";"
        )
        schema_sha256 = query_sha256(
                "SELECT table_name || '|' || column_name || '|' || data_type || '|' || is_nullable "
                "FROM information_schema.columns WHERE table_schema='public' "
                "AND table_name IN ('customers','events') ORDER BY table_name,column_name;"
        )
        return {
            "row_counts": counts,
            "total_rows": sum(counts.values()),
            "canonical_sha256": canonical_sha256,
            "schema_sha256": schema_sha256,
        }

    def _firewall_evidence(self, client) -> dict:
        status = self._ssh_run(client, "sudo -n ufw status")
        if not status.startswith("Status: active"):
            raise HarnessError("The UpCloud workload firewall is not active.")
        observed = set()
        for line in status.splitlines()[1:]:
            tokens = line.split()
            if "ALLOW" not in tokens:
                continue
            index = tokens.index("ALLOW")
            source_tokens = tokens[index + 1 :]
            if source_tokens and source_tokens[0] == "IN":
                source_tokens = source_tokens[1:]
            elif source_tokens and source_tokens[0] == "OUT":
                continue
            if not source_tokens:
                raise HarnessError("The UpCloud workload firewall rule is malformed.")
            destination = tokens[0]
            source = " ".join(source_tokens)
            if source.casefold().startswith("anywhere"):
                raise HarnessError("The UpCloud workload firewall exposes a world rule.")
            if len(source_tokens) != 1:
                raise HarnessError("The UpCloud workload firewall rule is malformed.")
            try:
                port = int(destination.split("/", 1)[0])
                address = ipaddress.ip_address(source)
            except (TypeError, ValueError):
                raise HarnessError("The UpCloud workload firewall rule is malformed.") from None
            prefix = 32 if address.version == 4 else 128
            observed.add((str(ipaddress.ip_network(f"{address}/{prefix}")), port))
        expected = {
            (cidr, port)
            for cidr in self.config.allowed_cidrs
            for port in (22, 80, 5432)
        }
        if observed != expected:
            raise HarnessError(
                "The UpCloud workload firewall differs from the exact host-CIDR allowlist."
            )
        return {
            "allowed_cidrs": list(self.config.allowed_cidrs),
            "tcp_ports": [22, 80, 5432],
            "default_incoming": "deny",
            "rules_sha256": _fingerprint(sorted(observed)),
        }

    def _completed_workload_evidence(
        self,
        server: dict,
        runtime: dict,
        names: dict,
        website_expected: dict,
        database_expected: dict,
    ) -> tuple[dict, dict, dict]:
        """Read back an accepted workload setup before replaying any mutation."""

        client = self._ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            website_actual = self._website_evidence(
                client, names["website_root"], website_expected
            )
            database_actual = self._database_evidence(
                client, runtime["database_name"]
            )
            if database_actual != database_expected:
                raise HarnessError("The PostgreSQL source fixture witness changed.")
            credential_check = self._ssh_run(
                client,
                "PGPASSWORD="
                + shlex.quote(runtime["database_password"])
                + " psql -h 127.0.0.1 --no-password -At --set=ON_ERROR_STOP=1"
                + f" -U {shlex.quote(runtime['database_user'])}"
                + f" -d {shlex.quote(runtime['database_name'])}"
                + " --command="
                + shlex.quote("SELECT current_user;"),
            )
            if credential_check != runtime["database_user"]:
                raise HarnessError("The generated PostgreSQL credential was not usable.")
            firewall = self._firewall_evidence(client)
        finally:
            client.close()
        return website_actual, database_actual, firewall

    def _record_workload_fixture(
        self,
        server: dict,
        runtime: dict,
        names: dict,
        website_actual: dict,
        database_actual: dict,
        firewall: dict,
    ) -> dict:
        server_id = str(server.get("uuid") or "")
        self.ledger.record(
            kind="compute_workload_fixture",
            resource_id=server_id,
            name=names["base"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "server_id": server_id,
                "website_root": names["website_root"],
                "website": website_actual,
                "database_name": runtime["database_name"],
                "database": database_actual,
                "firewall": firewall,
                "runtime_path_sha256": _hash(
                    str(_compute_runtime_path(self.config.runtime_path, self.config.run_id))
                ),
            },
            source_witness=server_id,
        )
        return {
            "status": "ready_for_ui_file_database_backups",
            "server_id": server_id,
            "website": website_actual,
            "database": database_actual,
            "network": firewall,
            "credential_runtime_file": str(
                _compute_runtime_path(self.config.runtime_path, self.config.run_id)
            ),
            "ssh_private_key_file": str(self._key_paths()[0]),
            "website_restore_contract": "exact_completed_durable_source_state",
            "database_restore_contract": "exact_completed_durable_target_mapping",
            "compatible_ui_destinations": [
                "UpCloud Managed Object Storage",
                "Oracle Object Storage",
                "DigitalOcean Spaces",
            ],
        }

    def setup_workloads(self, server: dict) -> dict:
        runtime = self._ensure_compute_runtime(server)
        names = self._workload_names()
        website_archive, website_expected = self._website_archive()
        database_expected = self._database_fixture(
            runtime["database_name"],
            runtime["database_user"],
            runtime["database_password"],
        )
        expected_database_evidence = {
            key: database_expected[key]
            for key in (
                "row_counts",
                "total_rows",
                "canonical_sha256",
                "schema_sha256",
            )
        }
        existing = self._one_active("compute_workload_fixture")
        if existing:
            ownership = existing.get("ownership") or {}
            if any(
                (
                    existing.get("resource_id") != str(server.get("uuid") or ""),
                    ownership.get("account") != self.account,
                    ownership.get("run_id") != self.config.run_id,
                    ownership.get("server_id") != str(server.get("uuid") or ""),
                    ownership.get("website_root") != names["website_root"],
                    ownership.get("database_name") != runtime["database_name"],
                )
            ):
                raise HarnessError("The ledgered workload fixture scope changed.")
            client = self._ssh_client(
                server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
            )
            try:
                website_actual = self._website_evidence(
                    client,
                    names["website_root"],
                    ownership.get("website") or {},
                )
                database_actual = self._database_evidence(
                    client, runtime["database_name"]
                )
                firewall = self._firewall_evidence(client)
            finally:
                client.close()
            if (
                database_actual != ownership.get("database")
                or database_actual != expected_database_evidence
                or firewall != ownership.get("firewall")
            ):
                raise HarnessError("The ledgered workload fixture evidence changed.")
            return {
                "status": "ready_for_ui_file_database_backups",
                "server_id": str(server.get("uuid") or ""),
                "website": website_actual,
                "database": database_actual,
                "network": firewall,
                "credential_runtime_file": str(
                    _compute_runtime_path(
                        self.config.runtime_path, self.config.run_id
                    )
                ),
                "ssh_private_key_file": str(self._key_paths()[0]),
                "website_restore_contract": "exact_completed_durable_source_state",
                "database_restore_contract": "exact_completed_durable_target_mapping",
                "compatible_ui_destinations": [
                    "UpCloud Managed Object Storage",
                    "Oracle Object Storage",
                    "DigitalOcean Spaces",
                ],
            }
        try:
            recovered = self._completed_workload_evidence(
                server,
                runtime,
                names,
                website_expected,
                expected_database_evidence,
            )
        except HarnessError:
            recovered = None
        if recovered is not None:
            return self._record_workload_fixture(
                server, runtime, names, *recovered
            )
        client = self._ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            self._ssh_run(
                client,
                "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -q",
                timeout=900,
            )
            self._ssh_run(
                client,
                "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -q nginx postgresql postgresql-client ufw",
                timeout=900,
            )
            archive_path = self._upload_bytes(
                client,
                f"/tmp/{self.config.run_id}-website.tar",
                website_archive,
            )
            website_root = shlex.quote(names["website_root"])
            self._ssh_run(client, f"sudo -n install -d -m 0750 {website_root}")
            self._ssh_run(
                client,
                f"sudo -n find {website_root} -mindepth 1 -delete",
            )
            self._ssh_run(
                client,
                f"sudo -n tar -xf {shlex.quote(archive_path)} -C {website_root} --no-same-owner",
            )
            self._ssh_run(client, f"rm -f {shlex.quote(archive_path)}")
            nginx_config = (
                "server {\n"
                "    listen 80 default_server;\n"
                "    listen [::]:80 default_server;\n"
                "    server_name _;\n"
                f"    root {names['website_root']};\n"
                "    location / { try_files $uri $uri/ =404; }\n"
                "}\n"
            ).encode("utf-8")
            nginx_temp = self._upload_bytes(
                client,
                f"/tmp/{self.config.run_id}-nginx.conf",
                nginx_config,
            )
            site_available = f"/etc/nginx/sites-available/{names['nginx_site']}"
            site_enabled = f"/etc/nginx/sites-enabled/{names['nginx_site']}"
            self._ssh_run(
                client,
                f"sudo -n install -m 0644 {shlex.quote(nginx_temp)} {shlex.quote(site_available)}",
            )
            self._ssh_run(client, f"rm -f {shlex.quote(nginx_temp)}")
            self._ssh_run(client, "sudo -n rm -f /etc/nginx/sites-enabled/default")
            self._ssh_run(
                client,
                f"sudo -n ln -sfn {shlex.quote(site_available)} {shlex.quote(site_enabled)}",
            )
            self._ssh_run(client, "sudo -n nginx -t")
            self._ssh_run(client, "sudo -n systemctl enable --now nginx")
            self._ssh_run_input(
                client,
                "sudo -n -u postgres psql --set=ON_ERROR_STOP=1",
                database_expected["initialize_sql"],
                timeout=300,
            )
            self._ssh_run_input(
                client,
                "sudo -n -u postgres psql --set=ON_ERROR_STOP=1",
                database_expected["data_sql"],
                timeout=300,
            )
            self._ssh_run(
                client,
                "sudo -n -u postgres psql --set=ON_ERROR_STOP=1 --command="
                + shlex.quote("ALTER SYSTEM SET listen_addresses = '*';"),
            )
            hba_path = self._ssh_run(
                client,
                "sudo -n -u postgres psql -At --command="
                + shlex.quote("SHOW hba_file;"),
            )
            if not re.fullmatch(r"/etc/postgresql/[A-Za-z0-9_./-]{1,180}", hba_path):
                raise HarnessError("PostgreSQL returned an unsafe pg_hba path.")
            begin = f"# BEGIN backupsheep-e2e-{self.config.run_id}"
            end = f"# END backupsheep-e2e-{self.config.run_id}"
            hba_lines = [begin] + [
                "host {database} {user} {cidr} scram-sha-256".format(
                    database=runtime["database_name"],
                    user=runtime["database_user"],
                    cidr=cidr,
                )
                for cidr in self.config.allowed_cidrs
            ] + [end]
            hba_program = f"""
from pathlib import Path
path = Path({hba_path!r})
begin = {begin!r}
end = {end!r}
lines = path.read_text(encoding='utf-8').splitlines()
output = []
inside = False
for line in lines:
    if line == begin:
        inside = True
        continue
    if line == end:
        inside = False
        continue
    if not inside:
        output.append(line)
output.extend({hba_lines!r})
path.write_text('\\n'.join(output) + '\\n', encoding='utf-8')
"""
            self._ssh_run_input(
                client,
                "sudo -n python3 -",
                hba_program,
            )
            self._ssh_run(client, "sudo -n systemctl restart postgresql")
            self._ssh_run(client, "sudo -n ufw --force reset")
            self._ssh_run(client, "sudo -n ufw default deny incoming")
            self._ssh_run(client, "sudo -n ufw default allow outgoing")
            for cidr in self.config.allowed_cidrs:
                for port in (22, 80, 5432):
                    self._ssh_run(
                        client,
                        "sudo -n ufw allow proto tcp from "
                        f"{shlex.quote(cidr)} to any port {port}",
                    )
            self._ssh_run(client, "sudo -n ufw --force enable")
            website_actual = self._website_evidence(
                client, names["website_root"], website_expected
            )
            database_actual = self._database_evidence(
                client, runtime["database_name"]
            )
            if database_actual != expected_database_evidence:
                raise HarnessError("The PostgreSQL source fixture witness changed.")
            credential_check = self._ssh_run(
                client,
                "PGPASSWORD="
                + shlex.quote(runtime["database_password"])
                + " psql -h 127.0.0.1 --no-password -At --set=ON_ERROR_STOP=1"
                + f" -U {shlex.quote(runtime['database_user'])}"
                + f" -d {shlex.quote(runtime['database_name'])}"
                + " --command="
                + shlex.quote("SELECT current_user;"),
            )
            if credential_check != runtime["database_user"]:
                raise HarnessError("The generated PostgreSQL credential was not usable.")
            firewall = self._firewall_evidence(client)
        finally:
            client.close()
        return self._record_workload_fixture(
            server,
            runtime,
            names,
            website_actual,
            database_actual,
            firewall,
        )

    def _normalize_workload_manifest(self, manifest: dict) -> dict:
        if (
            manifest.get("run_id") != self.config.run_id
            or not isinstance(manifest.get("website"), dict)
            or set(manifest["website"]) != WORKLOAD_WEBSITE_KEYS
            or not isinstance(manifest.get("postgresql"), dict)
            or set(manifest["postgresql"]) != WORKLOAD_DATABASE_KEYS
        ):
            raise HarnessError("The workload manifest scope is malformed.")
        names = self._workload_names()
        website = manifest["website"]
        database = manifest["postgresql"]
        website_node_id = self._manifest_backup_row_id(
            website.get("node_id"), "website.node_id"
        )
        website_backup_id = self._manifest_backup_row_id(
            website.get("backup_id"), "website.backup_id"
        )
        website_restore_id = self._manifest_backup_row_id(
            website.get("restore_id"), "website.restore_id"
        )
        expected_path = self._owned_website_restore_path(
            website.get("restore_path")
        )
        database_node_id = self._manifest_backup_row_id(
            database.get("node_id"), "postgresql.node_id"
        )
        database_backup_id = self._manifest_backup_row_id(
            database.get("backup_id"), "postgresql.backup_id"
        )
        database_restore_id = self._manifest_backup_row_id(
            database.get("restore_id"), "postgresql.restore_id"
        )
        restore_database = str(database.get("restore_database") or "")
        source_database = names["database"]
        if (
            not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", restore_database)
            or restore_database == source_database
            or f"_{source_database}_" not in f"_{restore_database}_"
        ):
            raise HarnessError(
                "The PostgreSQL restore target is not bound to the owned source database."
            )
        return {
            "website": {
                "node_id": website_node_id,
                "backup_id": website_backup_id,
                "restore_id": website_restore_id,
                "restore_path": expected_path,
            },
            "postgresql": {
                "node_id": database_node_id,
                "backup_id": database_backup_id,
                "restore_id": database_restore_id,
                "restore_database": restore_database,
            },
        }

    def _load_workload_manifest_with_evidence(self, generation_path: str) -> tuple[dict, str]:
        loaded = self._load_generation(generation_path, kind="workload")
        return (
            self._normalize_workload_manifest(loaded["manifest"]),
            loaded["marker_digest"],
        )

    def _load_workload_manifest(self, generation_path: str) -> dict:
        return self._load_workload_manifest_with_evidence(generation_path)[0]

    def _owned_website_restore_path(self, value) -> str:
        value = str(value or "")
        base = self._workload_names()["base"]
        if (
            value != value.strip()
            or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or not (value == base or value.startswith(base + "/"))
        ):
            raise HarnessError("The website restore path escaped its owned run root.")
        parts = value.split("/")
        if parts[0] or any(part in {"", ".", ".."} for part in parts[1:]):
            raise HarnessError("The website restore path is lexically ambiguous.")
        return value

    def _load_generation(self, generation_path: str, *, kind: str) -> dict:
        """Load and bind one complete generation before provider/guest reads."""

        if kind not in MANIFEST_TOP_LEVEL_KEYS:
            raise HarnessError("The requested manifest kind is unsupported.")
        directory, files = _safe_generation_directory(generation_path)
        names = set(files)
        if names == UPCLOUD_GENERATION_FILENAMES:
            marker_filename = UPCLOUD_GENERATION_MARKER
            full_generation = True
        elif kind == "workload" and names == WORKLOAD_GENERATION_FILENAMES:
            marker_filename = WORKLOAD_GENERATION_MARKER
            full_generation = False
        else:
            raise HarnessError(
                "The generation must contain exactly its ownership marker and all "
                "required manifest files; copied or mixed generations are rejected."
            )

        marker_bytes = _read_generation_file(
            files[marker_filename], label="manifest ownership marker"
        )
        try:
            marker = json.loads(
                marker_bytes.decode("utf-8"), object_pairs_hook=_strict_object_pairs
            )
        except HarnessError:
            raise
        except (UnicodeDecodeError, TypeError, ValueError):
            raise HarnessError("The manifest ownership marker is unreadable.") from None
        if not isinstance(marker, dict) or _contains_sensitive_key(marker):
            raise HarnessError("The manifest ownership marker is malformed or contains credentials.")
        if marker.get("run_id") != self.config.run_id:
            raise HarnessError("The manifest ownership marker run_id does not match this harness run.")

        if full_generation:
            if set(marker) != UPCLOUD_GENERATION_MARKER_KEYS or any(
                (
                    marker.get("schema") != 1,
                    marker.get("kind") != "upcloud_manifest_generation_ownership",
                    marker.get("provider") != "upcloud",
                    marker.get("integration_code") != "upcloud",
                    marker.get("disposition") != "EXCLUSIVE_COMPLETE_GENERATION",
                )
            ):
                raise HarnessError("The UpCloud generation ownership marker is malformed.")
            manifest_entries = marker.get("manifests")
            if not isinstance(manifest_entries, dict) or set(manifest_entries) != {
                "compute",
                "workload",
                "object",
            }:
                raise HarnessError("The UpCloud generation manifest set is incomplete.")
            for manifest_kind, entry in manifest_entries.items():
                if not isinstance(entry, dict) or set(entry) != {
                    "filename",
                    "sha256",
                    "byte_count",
                }:
                    raise HarnessError("The UpCloud generation file binding is malformed.")
                expected_filename = {
                    "compute": "upcloud-compute-manifest.json",
                    "workload": "upcloud-workload-manifest.json",
                    "object": "upcloud-object-manifest.json",
                }[manifest_kind]
                if (
                    entry.get("filename") != expected_filename
                    or not SHA256_RE.fullmatch(str(entry.get("sha256") or "").casefold())
                    or type(entry.get("byte_count")) is not int
                    or entry["byte_count"] < 1
                    or entry["byte_count"] > MANIFEST_MAX_BYTES
                ):
                    raise HarnessError("The UpCloud generation file binding is malformed.")
            manifests = {}
            for manifest_kind, entry in manifest_entries.items():
                filename = entry["filename"]
                payload = _read_generation_file(
                    files[filename], label=f"UpCloud {manifest_kind} manifest"
                )
                digest = hashlib.sha256(payload).hexdigest()
                if len(payload) != entry["byte_count"] or digest != entry["sha256"]:
                    raise HarnessError(
                        "The generation contains a tampered or mixed-generation manifest."
                    )
                manifests[manifest_kind] = _parse_manifest_bytes(
                    payload, kind=manifest_kind
                )
            if any(
                manifest.get("run_id") != self.config.run_id
                for manifest in manifests.values()
            ):
                raise HarnessError("A manifest run_id does not match the ownership marker.")
            if (
                not isinstance(manifests["compute"].get("volume"), dict)
                or set(manifests["compute"]["volume"]) != COMPUTE_VOLUME_KEYS
                or not isinstance(manifests["compute"].get("server"), dict)
                or set(manifests["compute"]["server"]) != COMPUTE_SERVER_KEYS
                or not isinstance(manifests["workload"].get("website"), dict)
                or set(manifests["workload"]["website"]) != WORKLOAD_WEBSITE_KEYS
                or not isinstance(manifests["workload"].get("postgresql"), dict)
                or set(manifests["workload"]["postgresql"]) != WORKLOAD_DATABASE_KEYS
            ):
                raise HarnessError("The UpCloud generation manifest fields are malformed.")
            object_rows = _validate_object_manifest_rows(manifests["object"])
            try:
                volume = manifests["compute"]["volume"]
                server = manifests["compute"]["server"]
                website = manifests["workload"]["website"]
                database = manifests["workload"]["postgresql"]
                expected_rows = {
                    "volume_node_id": _positive_generation_id(volume["node_id"], "volume node_id"),
                    "volume_backup_id": _positive_generation_id(volume["backup_id"], "volume backup_id"),
                    "volume_restore_id": _positive_generation_id(volume["restore_id"], "volume restore_id"),
                    "server_node_id": _positive_generation_id(server["node_id"], "server node_id"),
                    "server_backup_id": _positive_generation_id(server["backup_id"], "server backup_id"),
                    "server_restore_id": _positive_generation_id(server["restore_id"], "server restore_id"),
                    "website_node_id": _positive_generation_id(website["node_id"], "website node_id"),
                    "website_backup_id": _positive_generation_id(website["backup_id"], "website backup_id"),
                    "website_restore_id": _positive_generation_id(website["restore_id"], "website restore_id"),
                    "database_node_id": _positive_generation_id(database["node_id"], "database node_id"),
                    "database_backup_id": _positive_generation_id(database["backup_id"], "database backup_id"),
                    "database_restore_id": _positive_generation_id(database["restore_id"], "database restore_id"),
                    "website_storage_point_id": _positive_generation_id(
                        object_rows["website"]["storage_point_id"], "website storage_point_id"
                    ),
                    "database_storage_point_id": _positive_generation_id(
                        object_rows["database"]["storage_point_id"], "database storage_point_id"
                    ),
                    "website_artifact_id": _positive_generation_id(
                        object_rows["website"]["artifact_id"], "website artifact_id"
                    ),
                    "database_artifact_id": _positive_generation_id(
                        object_rows["database"]["artifact_id"], "database artifact_id"
                    ),
                }
            except (KeyError, TypeError):
                raise HarnessError("The UpCloud generation row bindings are incomplete.") from None
            _validate_marker_rows(marker.get("rows"), expected_rows, label="UpCloud generation")
            storage_ids = {
                object_rows["website"]["storage_id"],
                object_rows["database"]["storage_id"],
            }
            if len(storage_ids) != 1 or marker.get("storage_id") != next(iter(storage_ids)):
                raise HarnessError("The UpCloud generation storage binding is inconsistent.")
            bindings = marker.get("artifact_bindings")
            if not isinstance(bindings, dict) or set(bindings) != {"website", "database"}:
                raise HarnessError("The UpCloud generation artifact bindings are incomplete.")
            for label in ("website", "database"):
                _validate_artifact_binding(bindings[label], object_rows[label], label=label)
        else:
            if set(marker) != WORKLOAD_GENERATION_MARKER_KEYS or marker.get("schema") != 1:
                raise HarnessError("The workload generation ownership marker is malformed.")
            provider_code = str(marker.get("provider_code") or "")
            if (
                provider_code not in WORKLOAD_STORAGE_CODES
                or marker.get("integration_code") != WORKLOAD_STORAGE_CODES[provider_code]
                or type(marker.get("storage_id")) is not int
                or marker["storage_id"] < 1
                or not UPCLOUD_UUID_RE.fullmatch(
                    str(marker.get("website_restore_correlation_id") or "")
                )
                or not UPCLOUD_UUID_RE.fullmatch(
                    str(marker.get("database_restore_correlation_id") or "")
                )
                or not isinstance(marker.get("website_restore_path"), str)
                or not isinstance(marker.get("database_restore_database"), str)
            ):
                raise HarnessError("The workload generation ownership marker is malformed.")
            entry = marker.get("manifest")
            if not isinstance(entry, dict) or set(entry) != {
                "filename",
                "sha256",
                "byte_count",
            } or entry.get("filename") != "upcloud-workload-manifest.json":
                raise HarnessError("The workload generation file binding is malformed.")
            if (
                not SHA256_RE.fullmatch(str(entry.get("sha256") or "").casefold())
                or type(entry.get("byte_count")) is not int
                or entry["byte_count"] < 1
                or entry["byte_count"] > MANIFEST_MAX_BYTES
            ):
                raise HarnessError("The workload generation file binding is malformed.")
            payload = _read_generation_file(
                files["upcloud-workload-manifest.json"], label="UpCloud workload manifest"
            )
            if len(payload) != entry["byte_count"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
                raise HarnessError(
                    "The generation contains a tampered or mixed-generation workload manifest."
                )
            manifests = {"workload": _parse_manifest_bytes(payload, kind="workload")}
            workload = manifests["workload"]
            if (
                not isinstance(workload.get("website"), dict)
                or set(workload["website"]) != WORKLOAD_WEBSITE_KEYS
                or not isinstance(workload.get("postgresql"), dict)
                or set(workload["postgresql"]) != WORKLOAD_DATABASE_KEYS
            ):
                raise HarnessError("The workload generation manifest fields are malformed.")
            website = workload.get("website") or {}
            database = workload.get("postgresql") or {}
            expected_rows = {
                "website_node_id": _positive_generation_id(website.get("node_id"), "website node_id"),
                "website_backup_id": _positive_generation_id(website.get("backup_id"), "website backup_id"),
                "website_restore_id": _positive_generation_id(website.get("restore_id"), "website restore_id"),
                "database_node_id": _positive_generation_id(database.get("node_id"), "database node_id"),
                "database_backup_id": _positive_generation_id(database.get("backup_id"), "database backup_id"),
                "database_restore_id": _positive_generation_id(database.get("restore_id"), "database restore_id"),
            }
            rows = marker.get("rows")
            if not isinstance(rows, dict) or set(rows) != WORKLOAD_GENERATION_ROW_KEYS:
                raise HarnessError("The workload generation row binding is incomplete.")
            for field, value in expected_rows.items():
                if rows.get(field) != value:
                    raise HarnessError("The workload generation row binding does not match its manifest.")
            if (
                marker["website_restore_path"] != website.get("restore_path")
                or marker["database_restore_database"] != database.get("restore_database")
            ):
                raise HarnessError("The workload generation restore binding does not match its manifest.")
            bindings = marker.get("artifact_bindings")
            if not isinstance(bindings, dict) or set(bindings) != {"website", "database"}:
                raise HarnessError("The workload generation artifact bindings are incomplete.")
            for label in ("website", "database"):
                binding = bindings[label]
                if not isinstance(binding, dict) or set(binding) != ARTIFACT_BINDING_KEYS:
                    raise HarnessError(f"The {label} artifact binding is incomplete.")
                _validate_artifact_binding(
                    binding,
                    {
                        "artifact_id": rows[f"{label}_artifact_id"],
                        "byte_count": binding.get("byte_count"),
                        "sha256": binding.get("sha256"),
                        "etag": binding.get("etag"),
                        "version_id": binding.get("version_id"),
                    },
                    label=label,
                )

        return {
            "generation_dir": str(directory),
            "marker_digest": hashlib.sha256(marker_bytes).hexdigest(),
            "marker": marker,
            "manifests": manifests,
            "manifest": manifests[kind],
        }

    def verify_workloads(self, manifest_path: str) -> dict:
        manifest, marker_digest = self._load_workload_manifest_with_evidence(manifest_path)
        self._require_apply()
        self._require_compute_config()
        self.verify_account()
        source = self._one_active("compute_workload_fixture")
        server_entry = self._one_active("compute_source_server")
        if source is None or server_entry is None:
            raise HarnessError("Run setup-compute before workload verification.")
        server = self._server_read(server_entry["resource_id"])
        if server is None or not self._server_entry_owned(server_entry, server):
            raise HarnessError("The common workload source server changed.")
        runtime = _read_compute_runtime_secret(
            _compute_runtime_path(self.config.runtime_path, self.config.run_id)
        )
        ownership = source.get("ownership") or {}
        client = self._ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            source_website = self._website_evidence(
                client, runtime["website_root"], ownership.get("website") or {}
            )
            source_database = self._database_evidence(
                client, runtime["database_name"]
            )
            if source_database != ownership.get("database"):
                raise HarnessError("The source PostgreSQL witness changed before restore verification.")
            restored_website = self._website_evidence(
                client,
                manifest["website"]["restore_path"],
                ownership.get("website") or {},
            )
            restored_database = self._database_evidence(
                client, manifest["postgresql"]["restore_database"]
            )
        finally:
            client.close()
        if restored_database != ownership.get("database"):
            raise HarnessError("The PostgreSQL UI restore failed schema/row/hash verification.")
        website_resource_id = _hash(manifest["website"]["restore_path"])
        database_resource_id = manifest["postgresql"]["restore_database"]
        self.ledger.record(
            kind="ui_website_restore",
            resource_id=website_resource_id,
            name=manifest["website"]["restore_path"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                **manifest["website"],
                "evidence": restored_website,
            },
            source_witness=manifest["website"]["backup_id"],
        )
        self.ledger.record(
            kind="ui_postgresql_restore",
            resource_id=database_resource_id,
            name=database_resource_id,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                **manifest["postgresql"],
                "evidence": restored_database,
            },
            source_witness=manifest["postgresql"]["backup_id"],
        )
        verification_id = _hash(
            f"{manifest['website']['restore_id']}:{manifest['postgresql']['restore_id']}"
        )
        self.ledger.record(
            kind="compute_workload_restore_verification",
            resource_id=verification_id,
            name=self.config.run_id,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "website_backup_id": manifest["website"]["backup_id"],
                "database_backup_id": manifest["postgresql"]["backup_id"],
                "website": restored_website,
                "postgresql": restored_database,
                "all_evidence_matches": True,
                "manifest_marker_sha256": marker_digest,
            },
            source_witness=server_entry["resource_id"],
        )
        return {
            "status": "verified",
            "source": {
                "website": source_website,
                "postgresql": source_database,
            },
            "restored": {
                "website": restored_website,
                "postgresql": restored_database,
            },
            "backup_artifact_verification": (
                "Use the selected UpCloud/Oracle/DigitalOcean object-storage "
                "harness to verify checksum, bytes, ETag, and version ID."
            ),
        }

    def setup_compute(self) -> dict:
        self._require_apply()
        self._require_compute_config()
        self.verify_account()
        plan = self.verify_compute_plan()
        source_volume = self.ensure_source_volume()
        source_server = self.ensure_source_server(source_volume)
        source_server = self._wait_server_started(str(source_server["uuid"]))
        fixture = self.seed_compute_fixtures(source_server, source_volume)
        workloads = self.setup_workloads(source_server)
        server_entry = self._one_active("compute_source_server")
        boot_entry = self._one_active("compute_source_boot")
        return {
            "status": "ready_for_ui_attachment",
            "source_server_id": str(source_server["uuid"]),
            "source_volume_id": str(source_volume["uuid"]),
            "source_boot_storage_id": boot_entry["resource_id"],
            "zone": self.config.zone,
            "plan": plan,
            "fixture": fixture,
            "workloads": workloads,
            "ui_resource_types": {
                "source_server_id": "cloud",
                "source_volume_id": "volume",
            },
            "safe_config_sha256": (server_entry.get("ownership") or {}).get(
                "safe_config_sha256"
            ),
        }

    @staticmethod
    def _manifest_uuid(value, field: str) -> str:
        value = str(value or "").strip().casefold()
        if not UPCLOUD_UUID_RE.fullmatch(value):
            raise HarnessError(f"{field} must be an exact UpCloud UUID.")
        return value

    @staticmethod
    def _manifest_backup_row_id(value, field: str) -> int:
        if type(value) is not int or value < 1:
            raise HarnessError(f"{field} must be a positive numeric BackupSheep row ID.")
        return value

    @staticmethod
    def _manifest_marker(value, field: str, *, prefix=None) -> str:
        value = str(value or "").strip()
        if not SAFE_MARKER_RE.fullmatch(value):
            raise HarnessError(f"{field} is malformed.")
        if prefix and not value.startswith(prefix):
            raise HarnessError(f"{field} is not a BackupSheep-owned marker.")
        return value

    def _normalize_compute_manifest(self, manifest: dict) -> dict:
        if (
            manifest.get("run_id") != self.config.run_id
            or not isinstance(manifest.get("volume"), dict)
            or set(manifest["volume"]) != COMPUTE_VOLUME_KEYS
            or not isinstance(manifest.get("server"), dict)
            or set(manifest["server"]) != COMPUTE_SERVER_KEYS
        ):
            raise HarnessError("The UpCloud compute manifest scope is malformed.")
        volume = manifest["volume"]
        server = manifest["server"]
        normalized = {
            "volume": {
                "node_id": self._manifest_backup_row_id(
                    volume.get("node_id"), "volume.node_id"
                ),
                "backup_id": self._manifest_backup_row_id(
                    volume.get("backup_id"), "volume.backup_id"
                ),
                "restore_id": self._manifest_backup_row_id(
                    volume.get("restore_id"), "volume.restore_id"
                ),
                "source_resource_id": self._manifest_uuid(
                    volume.get("source_resource_id"), "volume.source_resource_id"
                ),
                "backup_resource_id": self._manifest_uuid(
                    volume.get("backup_resource_id"),
                    "volume.backup_resource_id",
                ),
                "backup_marker": self._manifest_marker(
                    volume.get("backup_marker"), "volume.backup_marker"
                ),
                "restore_resource_id": self._manifest_uuid(
                    volume.get("restore_resource_id"),
                    "volume.restore_resource_id",
                ),
                "restore_marker": self._manifest_marker(
                    volume.get("restore_marker"),
                    "volume.restore_marker",
                    prefix="backupsheep-upcloud-",
                ),
            },
            "server": {
                "node_id": self._manifest_backup_row_id(
                    server.get("node_id"), "server.node_id"
                ),
                "backup_id": self._manifest_backup_row_id(
                    server.get("backup_id"), "server.backup_id"
                ),
                "restore_id": self._manifest_backup_row_id(
                    server.get("restore_id"), "server.restore_id"
                ),
                "source_resource_id": self._manifest_uuid(
                    server.get("source_resource_id"), "server.source_resource_id"
                ),
                "backup_resource_id": self._manifest_uuid(
                    server.get("backup_resource_id"),
                    "server.backup_resource_id",
                ),
                "backup_marker": self._manifest_marker(
                    server.get("backup_marker"), "server.backup_marker"
                ),
                "restore_storage_id": self._manifest_uuid(
                    server.get("restore_storage_id"),
                    "server.restore_storage_id",
                ),
                "restore_storage_marker": self._manifest_marker(
                    server.get("restore_storage_marker"),
                    "server.restore_storage_marker",
                    prefix="backupsheep-upcloud-storage-",
                ),
                "restore_server_id": self._manifest_uuid(
                    server.get("restore_server_id"),
                    "server.restore_server_id",
                ),
                "restore_server_marker": self._manifest_marker(
                    server.get("restore_server_marker"),
                    "server.restore_server_marker",
                    prefix="backupsheep-upcloud-server-",
                ),
                "restore_hostname": self._manifest_marker(
                    server.get("restore_hostname"),
                    "server.restore_hostname",
                    prefix="bs-upcloud-",
                ),
            },
        }
        ids = [
            normalized["volume"]["backup_resource_id"],
            normalized["volume"]["restore_resource_id"],
            normalized["server"]["backup_resource_id"],
            normalized["server"]["restore_storage_id"],
            normalized["server"]["restore_server_id"],
        ]
        source_ids = {
            row["resource_id"]
            for kind in (
                "compute_source_volume",
                "compute_source_boot",
                "compute_source_server",
            )
            for row in self._active_entries(kind)
        }
        if len(ids) != len(set(ids)) or set(ids).intersection(source_ids):
            raise HarnessError("The UpCloud UI manifest reuses a source or target UUID.")
        source_volume = self._one_active("compute_source_volume")
        source_server = self._one_active("compute_source_server")
        if (
            source_volume is None
            or source_server is None
            or normalized["volume"]["source_resource_id"]
            != source_volume["resource_id"]
            or normalized["server"]["source_resource_id"]
            != source_server["resource_id"]
        ):
            raise HarnessError("The UpCloud UI manifest source IDs do not match the run ledger.")
        return normalized

    def _load_compute_manifest_with_evidence(self, generation_path: str) -> tuple[dict, str]:
        loaded = self._load_generation(generation_path, kind="compute")
        return (
            self._normalize_compute_manifest(loaded["manifest"]),
            loaded["marker_digest"],
        )

    def _load_compute_manifest(self, generation_path: str) -> dict:
        return self._load_compute_manifest_with_evidence(generation_path)[0]

    def _assert_unique_storage_marker(
        self, *, storage_type: str, resource_id: str, marker: str
    ) -> None:
        kind = "backup" if storage_type == "backup" else "storage"
        matches = [
            item
            for item in self._compute_inventory(kind)
            if str(item.get("title") or "") == marker
        ]
        if len(matches) != 1 or str(matches[0].get("uuid") or "") != resource_id:
            raise HarnessError(
                "The UpCloud UI storage marker is missing, duplicated, or points to another UUID."
            )

    def _verify_ui_storage(
        self,
        *,
        kind: str,
        resource_id: str,
        marker: str,
        storage_type: str,
        origin: str,
        expected_servers=(),
        allow_omitted_origin=False,
        expected_size=None,
        expected_tier=None,
        expected_encrypted=None,
    ) -> dict:
        self._assert_unique_storage_marker(
            storage_type=storage_type,
            resource_id=resource_id,
            marker=marker,
        )
        storage = self._storage_read(resource_id)
        actual_origin = str(storage.get("origin") or "") if isinstance(storage, dict) else ""
        origin_matches = actual_origin == origin or (
            allow_omitted_origin and not actual_origin
        )
        try:
            actual_size = int(storage.get("size")) if isinstance(storage, dict) else -1
        except (TypeError, ValueError):
            actual_size = -1
        if not isinstance(storage, dict) or any(
            (
                str(storage.get("uuid") or "") != resource_id,
                str(storage.get("title") or "") != marker,
                str(storage.get("type") or "") != storage_type,
                not origin_matches,
                str(storage.get("zone") or "") != self.config.zone,
                str(storage.get("state") or "").casefold() != "online",
                expected_size is not None and actual_size != int(expected_size),
                expected_tier is not None
                and str(storage.get("tier") or "").casefold()
                != str(expected_tier).casefold(),
                expected_encrypted is not None
                and str(storage.get("encrypted") or "").casefold()
                != str(expected_encrypted).casefold(),
            )
        ):
            raise HarnessError("UpCloud UI storage ownership verification failed.")
        attached_server_ids = self._storage_server_ids(storage)
        if sorted(attached_server_ids) != sorted(
            str(value) for value in expected_servers
        ):
            raise HarnessError("A UI storage has an unexpected server attachment.")
        self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=marker,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "zone": self.config.zone,
                "marker": marker,
                "type": storage_type,
                "origin": origin,
                "provider_origin": actual_origin,
                "origin_may_be_omitted": bool(allow_omitted_origin),
                "size": actual_size,
                "tier": str(storage.get("tier") or "").casefold(),
                "encrypted": str(storage.get("encrypted") or "").casefold(),
                "verified_server_ids": attached_server_ids,
            },
            source_witness=origin,
        )
        return storage

    def _assert_unique_server_marker(self, resource_id: str, marker: str) -> None:
        matches = [
            item
            for item in self._compute_inventory("server")
            if str(item.get("title") or "") == marker
        ]
        if len(matches) != 1 or str(matches[0].get("uuid") or "") != resource_id:
            raise HarnessError(
                "The UpCloud restored-server marker is missing, duplicated, or points to another UUID."
            )

    def _verify_ui_server(
        self,
        *,
        resource_id: str,
        marker: str,
        hostname: str,
        source_server_id: str,
        restore_storage_id: str,
        expected_config: dict,
    ) -> dict:
        self._assert_unique_server_marker(resource_id, marker)
        server = self._server_read(resource_id)
        labels = _label_map(server.get("labels")) if isinstance(server, dict) else {}
        if not isinstance(server, dict) or any(
            (
                str(server.get("uuid") or "") != resource_id,
                str(server.get("title") or "") != marker,
                str(server.get("hostname") or "") != hostname,
                str(server.get("zone") or "") != self.config.zone,
                str(server.get("state") or "").casefold()
                not in {"maintenance", "started", "stopped"},
                labels.get("backupsheep-restore") != marker,
                labels.get("backupsheep-source") != source_server_id,
            )
        ):
            raise HarnessError("UpCloud restored-server ownership verification failed.")
        boot = self._boot_device(server)
        if str(boot.get("storage") or "") != restore_storage_id:
            raise HarnessError("The restored server is not booting from the exact UI storage.")
        config = self._server_safe_config(server, boot)
        if config != expected_config:
            raise HarnessError("The restored server safe configuration differs from its witness.")
        self.ledger.record(
            kind="ui_server_restore_server",
            resource_id=resource_id,
            name=marker,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "zone": self.config.zone,
                "marker": marker,
                "hostname": hostname,
                "source_server_id": source_server_id,
                "boot_storage_id": restore_storage_id,
                "safe_config": expected_config,
                "safe_config_sha256": _fingerprint(expected_config),
            },
            source_witness=f"{source_server_id}:{restore_storage_id}",
        )
        return server

    def _record_attachment(
        self, *, kind: str, server_id: str, storage_id: str
    ) -> dict:
        return self.ledger.record(
            kind=kind,
            resource_id=f"{server_id}:{storage_id}",
            name=storage_id,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "server_id": server_id,
                "storage_id": storage_id,
                "boot_disk": False,
            },
            source_witness=f"{server_id}:{storage_id}",
        )

    def _ensure_restore_attachment(
        self, *, server_id: str, storage_id: str
    ) -> dict:
        server = self._server_read(server_id)
        source_entry = self._one_active("compute_source_server")
        if source_entry is None or server is None:
            raise HarnessError("The exact test-owned source server is unavailable.")
        owned, _config, _boot = self._source_server_owned(
            server,
            resource_id=server_id,
            source_volume_id=(source_entry.get("ownership") or {}).get(
                "source_volume_id"
            ),
            expected_config=(source_entry.get("ownership") or {}).get("safe_config"),
        )
        if not owned:
            raise HarnessError("Restore attachment refused a changed source server.")
        storage = self._storage_read(storage_id)
        restore_entry = self.ledger.get("ui_volume_restore", storage_id)
        if storage is None or restore_entry is None or not self._storage_entry_owned(
            restore_entry, storage
        ):
            raise HarnessError("Restore attachment refused an unowned storage.")
        attached = self._storage_server_ids(storage)
        intent_key = "compute_restore_volume_attach"
        intent = self.intents.get(intent_key)
        if attached == [server_id]:
            entry = self._record_attachment(
                kind="compute_restore_attachment",
                server_id=server_id,
                storage_id=storage_id,
            )
            self.intents.clear(intent_key)
            return entry
        if attached:
            raise HarnessError("Restore attachment refused a foreign server attachment.")
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "The restore attach response was lost and exact attachment is not visible."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": "compute_restore_attachment",
                "name": storage_id,
                "operation": "attach",
                "server_id": server_id,
                "storage_id": storage_id,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "POST",
            f"/storage/{quote(storage_id, safe='')}/attach",
            accepted=(200,),
            json_body={
                "storage_device": {
                    "type": "disk",
                    "address": "scsi",
                    "storage": storage_id,
                    "server": server_id,
                    "boot_disk": "0",
                }
            },
        )
        exact = self._storage_read(storage_id)
        if exact is None or self._storage_server_ids(exact) != [server_id]:
            raise AmbiguousMutation(
                "UpCloud accepted the restore attach without exact read-back."
            )
        entry = self._record_attachment(
            kind="compute_restore_attachment",
            server_id=server_id,
            storage_id=storage_id,
        )
        self.intents.clear(intent_key)
        return entry

    def _detach_attachment(self, entry: dict, *, intent_key: str) -> None:
        ownership = entry.get("ownership") or {}
        server_id = str(ownership.get("server_id") or "")
        storage_id = str(ownership.get("storage_id") or "")
        if (
            ownership.get("account") != self.account
            or ownership.get("run_id") != self.config.run_id
            or not UPCLOUD_UUID_RE.fullmatch(server_id)
            or not UPCLOUD_UUID_RE.fullmatch(storage_id)
        ):
            raise HarnessError("Storage detach refused a malformed ledger witness.")
        storage = self._storage_read(storage_id)
        if storage is None:
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="absent"
            )
            self.intents.clear(intent_key)
            return
        storage_kind = (
            "compute_source_volume"
            if entry.get("kind") == "compute_source_attachment"
            else "ui_volume_restore"
        )
        storage_entry = self.ledger.get(storage_kind, storage_id)
        server_entry = self.ledger.get("compute_source_server", server_id)
        if storage_entry is None or server_entry is None:
            raise HarnessError(
                "Storage detach refused a missing ownership witness."
            )
        server = self._server_read(server_id)
        if (
            not self._storage_entry_owned(storage_entry, storage)
            or server is None
            or not self._server_entry_owned(server_entry, server)
        ):
            raise HarnessError(
                "Storage detach refused a changed server or storage ownership witness."
            )
        attached = self._storage_server_ids(storage)
        if not attached:
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="absent"
            )
            self.intents.clear(intent_key)
            return
        if attached != [server_id]:
            raise HarnessError("Storage detach refused a foreign attachment.")
        intent = self.intents.get(intent_key)
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "The detach response was lost and the exact attachment remains visible."
            )
        self.intents.put(
            intent_key,
            {
                "marker": self.config.run_id,
                "kind": entry["kind"],
                "name": storage_id,
                "operation": "detach",
                "server_id": server_id,
                "storage_id": storage_id,
            },
        )
        self.intents.update(intent_key, request_boundary_crossed=True)
        self._control_mutation(
            intent_key,
            "POST",
            f"/server/{quote(server_id, safe='')}/storage/detach",
            accepted=(200,),
            json_body={"storage_device": {"storage": storage_id}},
        )
        exact = self._storage_read(storage_id)
        if exact is None or self._storage_server_ids(exact):
            raise AmbiguousMutation(
                "UpCloud accepted the detach without exact read-back."
            )
        self.ledger.mark_cleanup(
            entry["kind"], entry["resource_id"], state="absent"
        )
        self.intents.clear(intent_key)

    def _verify_volume_restore_bytes(
        self,
        *,
        source_server: dict,
        source_server_id: str,
        restore_storage_id: str,
    ) -> dict:
        fixture = self._one_active("compute_volume_fixture")
        if fixture is None:
            raise HarnessError("The durable source-volume fixture evidence is missing.")
        expected = {
            "sha256": str((fixture.get("ownership") or {}).get("sha256") or ""),
            "byte_count": int(
                (fixture.get("ownership") or {}).get("byte_count") or -1
            ),
        }
        attachment = self._ensure_restore_attachment(
            server_id=source_server_id,
            storage_id=restore_storage_id,
        )
        mount_path = f"/mnt/backupsheep-e2e-{self.config.run_id}-restored"
        mounted = False
        client = None
        try:
            client = self._ssh_client(
                source_server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
            )
            self._mount_storage(
                client,
                restore_storage_id,
                mount_path=mount_path,
                read_only=True,
            )
            mounted = True
            actual = self._remote_evidence(client, f"{mount_path}/payload.bin")
            if actual != expected:
                raise HarnessError("UpCloud volume restore failed byte/hash verification.")
        finally:
            try:
                if client is not None:
                    try:
                        if mounted:
                            self._ssh_run(
                                client,
                                f"sudo -n umount {shlex.quote(mount_path)}",
                            )
                    finally:
                        client.close()
            finally:
                self._detach_attachment(
                    attachment, intent_key="compute_restore_volume_detach"
                )
        return actual

    def _verify_server_restore_bytes(
        self, server: dict, *, source_host_key_fingerprint: str
    ) -> dict:
        fixture = self._one_active("compute_server_fixture")
        if fixture is None:
            raise HarnessError("The durable source-server fixture evidence is missing.")
        ownership = fixture.get("ownership") or {}
        expected = {
            "sha256": str(ownership.get("sha256") or ""),
            "byte_count": int(ownership.get("byte_count") or -1),
        }
        path = str(ownership.get("path") or "")
        client = self._wait_ssh_client(
            server, host_variable="UPCLOUD_E2E_RESTORE_SSH_HOST"
        )
        try:
            actual = self._remote_evidence(client, path)
            restored_fingerprint = self._ssh_host_key_fingerprint(client)
            guest = self._guest_restore_evidence(client, server)
        finally:
            client.close()
        if actual != expected:
            raise HarnessError("UpCloud server restore failed boot-disk byte/hash verification.")
        if restored_fingerprint != source_host_key_fingerprint:
            raise HarnessError("The restored SSH host key does not match the source snapshot.")
        return {
            "payload": actual,
            "source_host_key_fingerprint": source_host_key_fingerprint,
            "restored_host_key_fingerprint": restored_fingerprint,
            "guest": guest,
        }

    def verify_compute(self, manifest_path: str) -> dict:
        # Verification attaches the UI-created restored volume and is therefore
        # APPLY-gated even though all provider-created backup/restore resources
        # are discovered and verified by exact ID.
        manifest, marker_digest = self._load_compute_manifest_with_evidence(manifest_path)
        self._require_apply()
        self._require_compute_config()
        self.verify_account()
        source_volume_entry = self._one_active("compute_source_volume")
        source_boot_entry = self._one_active("compute_source_boot")
        source_server_entry = self._one_active("compute_source_server")
        if not source_volume_entry or not source_boot_entry or not source_server_entry:
            raise HarnessError("Run setup-compute before UI compute verification.")
        source_server = self._server_read(source_server_entry["resource_id"])
        owned, safe_config, boot_id = self._source_server_owned(
            source_server or {},
            resource_id=source_server_entry["resource_id"],
            source_volume_id=source_volume_entry["resource_id"],
            expected_config=(source_server_entry.get("ownership") or {}).get(
                "safe_config"
            ),
        )
        if not owned or boot_id != source_boot_entry["resource_id"]:
            raise HarnessError("The exact source graph changed before UI verification.")
        volume = manifest["volume"]
        server = manifest["server"]
        volume_backup = self._verify_ui_storage(
            kind="ui_volume_backup",
            resource_id=volume["backup_resource_id"],
            marker=volume["backup_marker"],
            storage_type="backup",
            origin=source_volume_entry["resource_id"],
        )
        volume_restore = self._verify_ui_storage(
            kind="ui_volume_restore",
            resource_id=volume["restore_resource_id"],
            marker=volume["restore_marker"],
            storage_type="normal",
            origin=str(volume_backup["uuid"]),
            allow_omitted_origin=True,
            expected_size=int(volume_backup["size"]),
            expected_tier=(source_volume_entry.get("ownership") or {}).get(
                "tier"
            ),
            expected_encrypted=(
                source_volume_entry.get("ownership") or {}
            ).get("encrypted"),
        )
        server_backup = self._verify_ui_storage(
            kind="ui_server_backup",
            resource_id=server["backup_resource_id"],
            marker=server["backup_marker"],
            storage_type="backup",
            origin=source_boot_entry["resource_id"],
        )
        server_restore_storage = self._verify_ui_storage(
            kind="ui_server_restore_storage",
            resource_id=server["restore_storage_id"],
            marker=server["restore_storage_marker"],
            storage_type="normal",
            origin=str(server_backup["uuid"]),
            expected_servers=[server["restore_server_id"]],
            allow_omitted_origin=True,
            expected_size=int(server_backup["size"]),
            expected_tier=(source_boot_entry.get("ownership") or {}).get(
                "tier"
            ),
            expected_encrypted=(
                source_boot_entry.get("ownership") or {}
            ).get("encrypted"),
        )
        restored_server = self._verify_ui_server(
            resource_id=server["restore_server_id"],
            marker=server["restore_server_marker"],
            hostname=server["restore_hostname"],
            source_server_id=source_server_entry["resource_id"],
            restore_storage_id=str(server_restore_storage["uuid"]),
            expected_config=safe_config,
        )
        restored_server = self._wait_server_started(str(restored_server["uuid"]))
        source_client = self._wait_ssh_client(
            source_server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            source_host_key_fingerprint = self._ssh_host_key_fingerprint(source_client)
        finally:
            source_client.close()
        volume_evidence = self._verify_volume_restore_bytes(
            source_server=source_server,
            source_server_id=source_server_entry["resource_id"],
            restore_storage_id=str(volume_restore["uuid"]),
        )
        server_evidence = self._verify_server_restore_bytes(
            restored_server,
            source_host_key_fingerprint=source_host_key_fingerprint,
        )
        verification_id = _hash(
            ":".join(
                [
                    volume["restore_resource_id"],
                    server["restore_storage_id"],
                    server["restore_server_id"],
                ]
            )
        )
        self.ledger.record(
            kind="compute_restore_verification",
            resource_id=verification_id,
            name=self.config.run_id,
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "volume": volume_evidence,
                "server": server_evidence,
                "all_hashes_match": True,
                "manifest_marker_sha256": marker_digest,
            },
            source_witness=(
                f"{volume['restore_resource_id']}:{server['restore_server_id']}"
            ),
        )
        self.ledger.record(
            kind="compute_guest_restore_verification",
            resource_id=_hash(server["restore_server_id"]),
            name=server["restore_hostname"],
            ownership={
                "account": self.account,
                "run_id": self.config.run_id,
                "source_server_id": source_server_entry["resource_id"],
                "restore_server_id": server["restore_server_id"],
                **server_evidence,
                "manifest_marker_sha256": marker_digest,
            },
            source_witness=(
                f"{source_server_entry['resource_id']}:{server['restore_server_id']}"
            ),
        )
        return {
            "status": "verified",
            "source_server_id": source_server_entry["resource_id"],
            "source_volume_id": source_volume_entry["resource_id"],
            "volume": {
                "backup_resource_id": volume["backup_resource_id"],
                "restore_resource_id": volume["restore_resource_id"],
                "evidence": volume_evidence,
            },
            "server": {
                "backup_resource_id": server["backup_resource_id"],
                "restore_storage_id": server["restore_storage_id"],
                "restore_server_id": server["restore_server_id"],
                "evidence": server_evidence,
            },
        }

    def _storage_entry_owned(self, entry: dict, storage: dict) -> bool:
        ownership = entry.get("ownership") or {}
        kind = str(entry.get("kind") or "")
        if (
            ownership.get("account") != self.account
            or ownership.get("run_id") != self.config.run_id
            or str(storage.get("uuid") or "") != str(entry.get("resource_id") or "")
        ):
            return False
        if kind == "compute_source_volume":
            return self._source_storage_owned(
                storage,
                resource_id=entry["resource_id"],
                title=self.names["source_volume"],
            )
        if kind == "compute_source_boot":
            return self._source_storage_owned(
                storage,
                resource_id=entry["resource_id"],
                title=self.names["source_boot"],
            )
        if kind in {
            "ui_volume_backup",
            "ui_volume_restore",
            "ui_server_backup",
            "ui_server_restore_storage",
        }:
            expected_origin = str(ownership.get("origin") or "")
            actual_origin = str(storage.get("origin") or "")
            origin_matches = actual_origin == expected_origin or (
                ownership.get("origin_may_be_omitted") is True
                and not actual_origin
            )
            try:
                size_matches = int(storage.get("size")) == int(
                    ownership.get("size")
                )
            except (TypeError, ValueError):
                size_matches = False
            return all(
                (
                    str(storage.get("title") or "") == ownership.get("marker"),
                    str(storage.get("type") or "") == ownership.get("type"),
                    origin_matches,
                    str(storage.get("zone") or "") == ownership.get("zone"),
                    size_matches,
                    str(storage.get("tier") or "").casefold()
                    == str(ownership.get("tier") or "").casefold(),
                    str(storage.get("encrypted") or "").casefold()
                    == str(ownership.get("encrypted") or "").casefold(),
                )
            )
        return False

    def _server_entry_owned(self, entry: dict, server: dict) -> bool:
        ownership = entry.get("ownership") or {}
        if (
            ownership.get("account") != self.account
            or ownership.get("run_id") != self.config.run_id
            or str(server.get("uuid") or "") != str(entry.get("resource_id") or "")
        ):
            return False
        if entry.get("kind") == "compute_source_server":
            owned, _config, boot_id = self._source_server_owned(
                server,
                resource_id=entry["resource_id"],
                source_volume_id=ownership.get("source_volume_id"),
                expected_config=ownership.get("safe_config"),
            )
            return owned and boot_id == ownership.get("boot_storage_id")
        if entry.get("kind") == "ui_server_restore_server":
            labels = _label_map(server.get("labels"))
            try:
                boot = self._boot_device(server)
                config = self._server_safe_config(server, boot)
            except HarnessError:
                return False
            return all(
                (
                    str(server.get("title") or "") == ownership.get("marker"),
                    str(server.get("hostname") or "") == ownership.get("hostname"),
                    labels.get("backupsheep-restore") == ownership.get("marker"),
                    labels.get("backupsheep-source")
                    == ownership.get("source_server_id"),
                    str(boot.get("storage") or "")
                    == ownership.get("boot_storage_id"),
                    config == ownership.get("safe_config"),
                )
            )
        return False

    def _provider_firewall_ledger_entries(self, server_id: str) -> list[dict]:
        rows = [
            row
            for row in self.ledger.entries(FIREWALL_LEDGER_KIND)
            if str((row.get("ownership") or {}).get("server_id") or "")
            == str(server_id)
        ]
        expected = {
            _fingerprint(_normalize_firewall_rule(rule))
            for rule in self._provider_firewall_expected_rules()
            if str(rule.get("action") or "").casefold() == "accept"
        }
        observed = set()
        for row in rows:
            ownership = row.get("ownership") or {}
            rule = ownership.get("rule")
            normalized = _normalize_firewall_rule(rule)
            fingerprint = _fingerprint(normalized)
            if any(
                (
                    ownership.get("account") != self.account,
                    ownership.get("run_id") != self.config.run_id,
                    ownership.get("server_id") != server_id,
                    ownership.get("rule_fingerprint") != fingerprint,
                    row.get("resource_id") != f"{server_id}:{fingerprint}",
                    normalized["action"] != "accept",
                    fingerprint not in expected,
                    fingerprint in observed,
                )
            ):
                raise HarnessError("The UpCloud firewall ledger ownership is malformed.")
            observed.add(fingerprint)
        if observed != expected:
            raise HarnessError(
                "The UpCloud firewall ledger does not contain exactly every run-owned allow rule."
            )
        return rows

    def _cleanup_provider_firewall(self, entry: dict, server: dict) -> None:
        """Remove only ledgered allow rules and retain the inbound drop guard."""
        server_id = str(entry.get("resource_id") or "")
        ownership = entry.get("ownership") or {}
        expected_firewall = ownership.get("provider_firewall")
        if not isinstance(expected_firewall, dict):
            raise HarnessError("The source server has no provider firewall witness.")
        if str(server.get("firewall") or "").casefold() != "on":
            raise HarnessError("Cleanup refuses to operate with the provider firewall off.")

        all_rows = self._provider_firewall_ledger_entries(server_id)
        expected_allow = {
            str(value)
            for value in (expected_firewall.get("allow_rule_fingerprints") or [])
        }
        if expected_allow != {
            str((row.get("ownership") or {}).get("rule_fingerprint") or "")
            for row in all_rows
        }:
            raise HarnessError("The source firewall witness and ledger do not match.")
        default_drop = _normalize_firewall_rule({"direction": "in", "action": "drop"})

        def current_rules() -> list[dict]:
            observed = self._provider_firewall_observation(server_id)
            if observed.get("firewall") != "on":
                raise HarnessError("The provider firewall changed state during cleanup.")
            return list(observed["rules"])

        def locate(rules: list[dict], fingerprint: str) -> list[tuple[int, dict]]:
            return [
                (position, rule)
                for position, rule in enumerate(rules, start=1)
                if _fingerprint(rule) == fingerprint
            ]

        # Reconcile a response that may have been lost before comparing the
        # current chain to the expected remaining ledger-owned set.
        for row in all_rows:
            if row.get("cleanup_state") not in ACTIVE_LEDGER_STATES:
                continue
            fingerprint = str((row.get("ownership") or {}).get("rule_fingerprint") or "")
            intent_key = f"cleanup:compute-firewall:{server_id}:{fingerprint}"
            intent = self.intents.get(intent_key)
            if not intent:
                continue
            if intent.get("request_boundary_crossed") is not True:
                raise HarnessError("The pending UpCloud firewall cleanup intent is incomplete.")
            matches = locate(current_rules(), fingerprint)
            if len(matches) > 1:
                raise HarnessError("The exact UpCloud firewall rule is duplicated during cleanup.")
            if matches:
                raise AmbiguousMutation(
                    "The UpCloud firewall delete crossed the provider boundary but the exact rule remains."
                )
            self.ledger.mark_cleanup(
                FIREWALL_LEDGER_KIND, row["resource_id"], state="deleted"
            )
            self.intents.clear(intent_key)

        def expected_remaining() -> list[dict]:
            active_fingerprints = {
                str((row.get("ownership") or {}).get("rule_fingerprint") or "")
                for row in self.ledger.entries(FIREWALL_LEDGER_KIND)
                if str((row.get("ownership") or {}).get("server_id") or "") == server_id
                and row.get("cleanup_state") in ACTIVE_LEDGER_STATES
            }
            rules = [
                _normalize_firewall_rule(rule)
                for rule in self._provider_firewall_expected_rules()
                if str(rule.get("action") or "").casefold() == "accept"
                and _fingerprint(_normalize_firewall_rule(rule)) in active_fingerprints
            ]
            rules.append(default_drop)
            return rules

        if current_rules() != expected_remaining():
            raise HarnessError(
                "Cleanup found a foreign, missing, or changed UpCloud provider firewall rule."
            )

        while True:
            rows = [
                row
                for row in self.ledger.entries(FIREWALL_LEDGER_KIND)
                if str((row.get("ownership") or {}).get("server_id") or "") == server_id
                and row.get("cleanup_state") in ACTIVE_LEDGER_STATES
            ]
            if not rows:
                break
            rules = current_rules()
            # Positions are mutable after every delete; always re-read and
            # delete the highest-position exact rule first.
            matches = []
            for row in rows:
                fingerprint = str((row.get("ownership") or {}).get("rule_fingerprint") or "")
                found = locate(rules, fingerprint)
                if len(found) > 1:
                    raise HarnessError("The exact UpCloud firewall rule is duplicated during cleanup.")
                if not found:
                    self.ledger.mark_cleanup(
                        FIREWALL_LEDGER_KIND, row["resource_id"], state="absent"
                    )
                    continue
                matches.append((found[0][0], row, fingerprint))
            if not matches:
                continue
            position, row, fingerprint = max(matches, key=lambda value: value[0])
            intent_key = f"cleanup:compute-firewall:{server_id}:{fingerprint}"
            if self.intents.get(intent_key):
                raise AmbiguousMutation(
                    "The UpCloud firewall cleanup intent remains unresolved."
                )
            self.intents.put(
                intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": FIREWALL_LEDGER_KIND,
                    "name": row.get("name") or fingerprint,
                    "operation": "delete-rule",
                    "server_id": server_id,
                    "rule_fingerprint": fingerprint,
                    "position": position,
                },
            )
            self.intents.update(intent_key, request_boundary_crossed=True)
            self._control_mutation(
                intent_key,
                "DELETE",
                f"/server/{quote(server_id, safe='')}/firewall_rule/{position}",
                accepted=(204,),
                allow_not_found=True,
            )
            remaining = locate(current_rules(), fingerprint)
            if remaining:
                self.ledger.mark_cleanup(
                    FIREWALL_LEDGER_KIND,
                    row["resource_id"],
                    state="failed",
                    error="Exact provider firewall rule remains visible after delete.",
                )
                raise AmbiguousMutation(
                    "The exact UpCloud provider firewall rule remains after deletion."
                )
            self.ledger.mark_cleanup(
                FIREWALL_LEDGER_KIND, row["resource_id"], state="deleted"
            )
            self.intents.clear(intent_key)

        if current_rules() != [default_drop]:
            raise HarnessError(
                "Cleanup did not leave exactly the provider inbound default drop rule."
            )

    def _stop_server_for_cleanup(self, entry: dict, server: dict) -> dict:
        resource_id = entry["resource_id"]
        state = str(server.get("state") or "").casefold()
        intent_key = f"cleanup:compute-stop:{resource_id}"
        intent = self.intents.get(intent_key)
        expected = {
            "marker": self.config.run_id,
            "kind": entry["kind"],
            "name": entry.get("name") or resource_id,
            "operation": "stop",
            "resource_id": resource_id,
        }
        if intent and intent.get("request_boundary_crossed") and any(
            intent.get(key) != value for key, value in expected.items()
        ):
            raise HarnessError("A pending soft-stop intent changed scope.")
        if state == "stopped":
            self.intents.clear(intent_key)
            return server
        if state not in {"started", "maintenance"}:
            raise HarnessError(
                "Cleanup refused a server outside started/maintenance/stopped state."
            )
        if not (intent and intent.get("request_boundary_crossed")):
            if state == "maintenance":
                raise HarnessError(
                    "A server entered maintenance without this run's soft-stop intent."
                )
            self.intents.put(
                intent_key,
                {
                    "marker": self.config.run_id,
                    "kind": entry["kind"],
                    "name": entry.get("name") or resource_id,
                    "operation": "stop",
                    "resource_id": resource_id,
                },
            )
            self.intents.update(intent_key, request_boundary_crossed=True)
            self._control_mutation(
                intent_key,
                "POST",
                f"/server/{quote(resource_id, safe='')}/stop",
                accepted=(200,),
                json_body={"stop_server": {"stop_type": "soft"}},
            )
        for _attempt in range(COMPUTE_MAX_WAIT_POLLS):
            exact = self._server_read(resource_id)
            if exact is None:
                raise AmbiguousMutation("The exact server disappeared during stop.")
            exact_state = str(exact.get("state") or "").casefold()
            if exact_state == "stopped":
                self.intents.clear(intent_key)
                return exact
            if exact_state not in {"started", "maintenance"}:
                raise HarnessError("The exact server entered an unknown stop state.")
            self.sleep(COMPUTE_POLL_SECONDS)
        raise AmbiguousMutation("The exact UpCloud server did not stop within the bound.")

    def _delete_compute_server(self, entry: dict) -> None:
        server = self._server_read(entry["resource_id"])
        if server is None:
            if entry.get("kind") == "compute_source_server":
                for row in self.ledger.entries(FIREWALL_LEDGER_KIND):
                    if str((row.get("ownership") or {}).get("server_id") or "") == str(
                        entry["resource_id"]
                    ) and row.get("cleanup_state") in ACTIVE_LEDGER_STATES:
                        self.ledger.mark_cleanup(
                            FIREWALL_LEDGER_KIND,
                            row["resource_id"],
                            state="absent",
                        )
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="absent"
            )
            return
        if entry.get("kind") == "compute_source_server":
            ownership = entry.get("ownership") or {}
            owned, _config, boot_id = self._source_server_owned(
                server,
                resource_id=entry["resource_id"],
                source_volume_id=ownership.get("source_volume_id"),
                expected_config=ownership.get("safe_config"),
                verify_firewall=False,
            )
            if not owned or boot_id != ownership.get("boot_storage_id"):
                raise HarnessError("Cleanup refused a changed or unowned UpCloud source server.")
            self._cleanup_provider_firewall(entry, server)
            server = self._server_read(entry["resource_id"])
            if server is None:
                raise AmbiguousMutation("The source server disappeared during firewall cleanup.")
            owned, _config, boot_id = self._source_server_owned(
                server,
                resource_id=entry["resource_id"],
                source_volume_id=ownership.get("source_volume_id"),
                expected_config=ownership.get("safe_config"),
                verify_firewall=False,
            )
            if not owned or boot_id != ownership.get("boot_storage_id"):
                raise HarnessError("Source server ownership changed during firewall cleanup.")
        elif not self._server_entry_owned(entry, server):
            raise HarnessError("Cleanup refused a changed or unowned UpCloud server.")
        server = self._stop_server_for_cleanup(entry, server)
        if entry.get("kind") == "compute_source_server":
            ownership = entry.get("ownership") or {}
            owned, _config, boot_id = self._source_server_owned(
                server,
                resource_id=entry["resource_id"],
                source_volume_id=ownership.get("source_volume_id"),
                expected_config=ownership.get("safe_config"),
                verify_firewall=False,
            )
            if not owned or boot_id != ownership.get("boot_storage_id"):
                raise HarnessError("Source server ownership changed while stopping.")
        elif not self._server_entry_owned(entry, server):
            raise HarnessError("Server ownership changed while stopping for cleanup.")
        self._control_delete(
            intent_key=f"cleanup:compute-server:{entry['resource_id']}",
            kind=entry["kind"],
            entry=entry,
            path=f"/server/{quote(entry['resource_id'], safe='')}",
            params={"storages": "0", "backups": "keep"},
            verify_absent=lambda: self._server_read(entry["resource_id"]) is None,
        )

    def _delete_compute_storage(self, entry: dict) -> None:
        storage = self._storage_read(entry["resource_id"])
        if storage is None:
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="absent"
            )
            return
        if not self._storage_entry_owned(entry, storage):
            raise HarnessError("Cleanup refused a changed or unowned UpCloud storage.")
        if self._storage_server_ids(storage):
            raise HarnessError("Cleanup refused an attached UpCloud storage.")
        self._control_delete(
            intent_key=f"cleanup:compute-storage:{entry['kind']}:{entry['resource_id']}",
            kind=entry["kind"],
            entry=entry,
            path=f"/storage/{quote(entry['resource_id'], safe='')}",
            params={"backups": "keep"},
            verify_absent=lambda: self._storage_read(entry["resource_id"]) is None,
        )

    def _adopt_pending_compute_for_cleanup(self) -> None:
        volume_intent = self.intents.get("compute_source_volume_create")
        if not self._one_active("compute_source_volume") and volume_intent and volume_intent.get(
            "request_boundary_crossed"
        ):
            summary = self._exact_title(
                self._compute_inventory("storage"), self.names["source_volume"]
            )
            if summary is None:
                raise AmbiguousMutation(
                    "Pending source-volume creation has no exact cleanup witness."
                )
            storage = self._storage_read(str(summary.get("uuid") or ""))
            if storage is None:
                raise AmbiguousMutation(
                    "Pending source-volume creation is not exactly readable."
                )
            self._record_source_volume(storage)
        server_intent = self.intents.get("compute_source_server_create")
        if not self._one_active("compute_source_server") and server_intent and server_intent.get(
            "request_boundary_crossed"
        ):
            volume_entry = self._one_active("compute_source_volume")
            if volume_entry is None:
                raise AmbiguousMutation("Pending source server has no source-volume witness.")
            summary = self._exact_title(
                self._compute_inventory("server"), self.names["source_server"]
            )
            if summary is None:
                raise AmbiguousMutation(
                    "Pending source-server creation has no exact cleanup witness."
                )
            server = self._server_read(str(summary.get("uuid") or ""))
            if server is None:
                raise AmbiguousMutation(
                    "Pending source-server creation is not exactly readable."
                )
            self._record_source_server(server, volume_entry["resource_id"])

    def _unmount_source_volume(self, server: dict) -> None:
        fixture = self._one_active("compute_volume_fixture")
        if fixture is None:
            return
        path = str((fixture.get("ownership") or {}).get("path") or "")
        mount_path = str(Path(path).parent)
        if not mount_path.startswith(f"/mnt/backupsheep-e2e-{self.config.run_id}"):
            raise HarnessError("The source-volume mount witness is malformed.")
        client = self._ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            mounted = self._exact_mount_source(
                self._ssh_run(
                    client,
                    f"findmnt -n -o SOURCE,TARGET --target {shlex.quote(mount_path)} 2>/dev/null || true",
                ),
                mount_path,
            )
            if mounted:
                self._ssh_run(
                    client, f"sudo -n umount {shlex.quote(mount_path)}"
                )
        finally:
            client.close()

    def _cleanup_workloads(self, server: dict, *, require_evidence: bool) -> None:
        source = self._one_active("compute_workload_fixture")
        workload_evidence = self._one_active(
            "compute_workload_restore_verification"
        )
        compute_evidence = self._one_active("compute_restore_verification")
        if require_evidence and (workload_evidence is None or compute_evidence is None):
            raise HarnessError(
                "Evidence-gated cleanup requires successful compute, website, and "
                "PostgreSQL UI restore verification."
            )
        if source is None:
            return
        if str(server.get("state") or "").casefold() != "started":
            raise HarnessError("Workload cleanup requires the exact source server to be started.")
        runtime = _read_compute_runtime_secret(
            _compute_runtime_path(self.config.runtime_path, self.config.run_id)
        )
        names = self._workload_names()
        website_entries = self._active_entries("ui_website_restore")
        database_entries = self._active_entries("ui_postgresql_restore")
        if len(website_entries) > 1 or len(database_entries) > 1:
            raise HarnessError("Workload cleanup found duplicate restore evidence rows.")
        client = self._ssh_client(
            server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
        )
        try:
            databases = [entry["resource_id"] for entry in database_entries]
            databases.append(runtime["database_name"])
            if len(databases) != len(set(databases)) or any(
                not re.fullmatch(r"[a-z][a-z0-9_]{2,62}", value)
                for value in databases
            ):
                raise HarnessError("The workload database cleanup witness is malformed.")
            sql = ""
            for database in databases:
                sql += (
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    f"WHERE datname='{database}' AND pid <> pg_backend_pid();\n"
                    f"DROP DATABASE IF EXISTS {database};\n"
                )
            sql += f"DROP ROLE IF EXISTS {runtime['database_user']};\n"
            self._ssh_run_input(
                client,
                "sudo -n -u postgres psql --set=ON_ERROR_STOP=1",
                sql,
                timeout=300,
            )
            for entry in website_entries:
                ownership = entry.get("ownership") or {}
                path = str(ownership.get("restore_path") or "")
                if (
                    ownership.get("account") != self.account
                    or ownership.get("run_id") != self.config.run_id
                ):
                    raise HarnessError("Website cleanup refused a changed restore witness.")
                self._owned_website_restore_path(path)
                quoted = shlex.quote(path)
                self._ssh_run(
                    client,
                    f"if sudo -n test -d {quoted}; then sudo -n find {quoted} -mindepth 1 -delete && sudo -n rmdir {quoted}; fi",
                )
            site_available = f"/etc/nginx/sites-available/{names['nginx_site']}"
            site_enabled = f"/etc/nginx/sites-enabled/{names['nginx_site']}"
            base = shlex.quote(names["base"])
            self._ssh_run(
                client,
                f"sudo -n rm -f {shlex.quote(site_enabled)} {shlex.quote(site_available)}",
            )
            self._ssh_run(
                client,
                f"if sudo -n test -d {base}; then sudo -n find {base} -mindepth 1 -delete && sudo -n rmdir {base}; fi",
            )
            self._ssh_run(client, "sudo -n nginx -t")
            self._ssh_run(client, "sudo -n systemctl reload nginx")
        finally:
            client.close()
        for entry in website_entries:
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="deleted"
            )
        for entry in database_entries:
            self.ledger.mark_cleanup(
                entry["kind"], entry["resource_id"], state="deleted"
            )
        self.ledger.mark_cleanup(
            source["kind"], source["resource_id"], state="deleted"
        )
        if workload_evidence:
            self.ledger.mark_cleanup(
                workload_evidence["kind"],
                workload_evidence["resource_id"],
                state="absent",
            )

    def cleanup_compute(self, *, require_evidence: bool = False) -> dict:
        self._require_cleanup()
        self._require_compute_config()
        self.verify_account()
        self._adopt_pending_compute_for_cleanup()

        if require_evidence and (
            self._one_active("compute_restore_verification") is None
            or self._one_active("compute_guest_restore_verification") is None
            or self._one_active("compute_workload_restore_verification") is None
        ):
            raise HarnessError(
                "Evidence-gated cleanup requires successful compute and workload UI restore verification."
            )

        restore_attachment = self._one_active("compute_restore_attachment")
        if restore_attachment:
            self._detach_attachment(
                restore_attachment,
                intent_key="cleanup:compute-restore-attachment",
            )

        restored_server = self._one_active("ui_server_restore_server")
        if restored_server:
            self._delete_compute_server(restored_server)

        source_server = self._one_active("compute_source_server")
        source_attachment = self._one_active("compute_source_attachment")
        if source_server and source_attachment:
            exact_server = self._server_read(source_server["resource_id"])
            if exact_server is not None:
                if not self._server_entry_owned(source_server, exact_server):
                    raise HarnessError("Cleanup refused a changed source server.")
                if str(exact_server.get("state") or "").casefold() == "started":
                    self._cleanup_workloads(
                        exact_server, require_evidence=require_evidence
                    )
                    self._unmount_source_volume(exact_server)
            self._detach_attachment(
                source_attachment,
                intent_key="cleanup:compute-source-attachment",
            )
        if source_server:
            self._delete_compute_server(source_server)

        storage_order = (
            "ui_volume_restore",
            "ui_server_restore_storage",
            "ui_volume_backup",
            "ui_server_backup",
            "compute_source_volume",
            "compute_source_boot",
        )
        deleted_storage_ids = []
        for kind in storage_order:
            entry = self._one_active(kind)
            if entry:
                self._delete_compute_storage(entry)
                deleted_storage_ids.append(entry["resource_id"])

        if not self._active_entries("compute_source_server") and not any(
            self._active_entries(kind) for kind in storage_order
        ):
            for kind in (
                "compute_server_fixture",
                "compute_volume_fixture",
                "compute_restore_verification",
                "compute_guest_restore_verification",
                "compute_workload_fixture",
                "compute_workload_restore_verification",
                "ui_website_restore",
                "ui_postgresql_restore",
            ):
                for entry in self._active_entries(kind):
                    self.ledger.mark_cleanup(
                        kind, entry["resource_id"], state="absent"
                    )
            for path in self._key_paths():
                if path.exists():
                    if path.is_symlink() or not path.is_file():
                        raise HarnessError("The UpCloud SSH artifact path became unsafe.")
                    path.unlink()
            compute_runtime = _compute_runtime_path(
                self.config.runtime_path, self.config.run_id
            )
            if compute_runtime.exists():
                _remove_compute_runtime_secret(compute_runtime)
            for key in list(self.intents.pending()):
                if key.startswith("compute_") or key.startswith("cleanup:compute"):
                    self.intents.clear(key)
        return {
            "status": "completed",
            "deleted_storage_ids": deleted_storage_ids,
            "source_server_id": source_server["resource_id"] if source_server else None,
            "restored_server_id": (
                restored_server["resource_id"] if restored_server else None
            ),
        }

    def inventory(self, *, phase: str) -> dict:
        """Read-only exact-run inventory; never adopts evidence or mutates state."""

        if phase not in {"before", "after"}:
            raise HarnessError("Inventory phase must be before or after.")
        self.verify_account()
        retention_receipts = self._mos_retention_receipts()
        ledger_service_ids = {
            str(row.get("resource_id") or "")
            for row in self._active_entries("mos_service")
        }
        ledger_compute_ids = {
            str(row.get("resource_id") or "")
            for kind in (
                "compute_source_server",
                "compute_source_volume",
                "compute_source_boot",
                "ui_volume_backup",
                "ui_volume_restore",
                "ui_server_backup",
                "ui_server_restore_storage",
                "ui_server_restore_server",
            )
            for row in self._active_entries(kind)
        }
        expected_titles = {
            self.names["source_server"],
            self.names["source_volume"],
            self.names["source_boot"],
        }
        matches = {"servers": [], "storages": [], "backups": []}
        collisions = []
        for kind, output_key in (
            ("server", "servers"),
            ("storage", "storages"),
            ("backup", "backups"),
        ):
            for summary in self._compute_inventory(kind):
                resource_id = str(summary.get("uuid") or "")
                title = str(summary.get("title") or "")
                labels = _label_map(summary.get("labels"))
                run_marked = (
                    labels.get("backupsheep-e2e-owned") == "true"
                    and labels.get("backupsheep-e2e-run") == self.config.run_id
                )
                if run_marked or resource_id in ledger_compute_ids:
                    matches[output_key].append(resource_id)
                elif title in expected_titles:
                    collisions.append({"kind": kind, "resource_id": resource_id})
        attachments = []
        public_ips = []
        for server_id in matches["servers"]:
            exact = self._server_read(server_id)
            if exact is None:
                raise HarnessError("An inventoried exact-run server disappeared.")
            attachments.extend(
                {
                    "server_id": server_id,
                    "storage_id": str(device.get("storage") or ""),
                }
                for device in self._server_storage_devices(exact)
            )
            public_ips.extend(
                {
                    "server_id": server_id,
                    "address_sha256": _hash(address),
                }
                for address in self._server_public_addresses(exact)
            )
        for storage_id in matches["storages"] + matches["backups"]:
            exact = self._storage_read(storage_id)
            if exact is None:
                raise HarnessError("An inventoried exact-run storage disappeared.")
            attachments.extend(
                {"server_id": server_id, "storage_id": storage_id}
                for server_id in self._storage_server_ids(exact)
            )
        attachments = [
            {"server_id": server_id, "storage_id": storage_id}
            for server_id, storage_id in sorted(
                {(row["server_id"], row["storage_id"]) for row in attachments}
            )
        ]
        for row in self._ip_inventory():
            server_id = str(row.get("server") or "")
            if server_id in ledger_compute_ids or server_id in matches["servers"]:
                public_ips.append(
                    {
                        "server_id": server_id,
                        "address_sha256": _hash(str(row.get("address") or "")),
                    }
                )
        public_ips = [
            {"server_id": server_id, "address_sha256": digest}
            for server_id, digest in sorted(
                {(row["server_id"], row["address_sha256"]) for row in public_ips}
            )
        ]
        services = self._offset_list("/object-storage-2")
        service_matches = []
        service_collisions = []
        mos_graph = []
        for summary in services:
            name = str(summary.get("name") or "")
            labels = _label_map(summary.get("labels"))
            marked = (
                labels.get("backupsheep-e2e-owned") == "true"
                and labels.get("backupsheep-e2e-run") == self.config.run_id
            )
            service_id = str(summary.get("uuid") or "")
            if marked or service_id in ledger_service_ids:
                exact = self._service_read(service_id)
                if not self._service_owned(exact or {}, resource_id=service_id):
                    raise HarnessError("An exact-run MOS service changed ownership.")
                service_matches.append(service_id)
                networks = self.control.request(
                    "GET", f"/object-storage-2/{quote(service_id, safe='')}/networks"
                )
                if not isinstance(networks, list) or any(
                    not isinstance(row, dict) for row in networks
                ):
                    raise HarnessError("UpCloud returned malformed MOS network inventory.")
                buckets = sorted(
                    str(row.get("name") or "") for row in self._buckets(service_id)
                )
                users = sorted(
                    str(row.get("username") or "")
                    for row in self._users(service_id)
                    if str(row.get("username") or "")
                    != "_upcloud-internal-user"
                )
                network_names = sorted(
                    str(row.get("name") or "") for row in networks
                )
                policy_names = []
                key_fingerprints = []
                if users == [self.names["username"]]:
                    policy_names = sorted(
                        str(row.get("name") or "")
                        for row in self._inline_policies(
                            service_id, self.names["username"]
                        )
                    )
                    key_fingerprints = sorted(
                        _hash(str(row.get("access_key_id") or ""))
                        for row in self._access_keys(
                            service_id, self.names["username"]
                        )
                    )

                service_entries = [
                    row
                    for row in self._active_entries("mos_service")
                    if str(row.get("resource_id") or "") == service_id
                ]
                network_entries = [
                    row
                    for row in self._active_entries("mos_network")
                    if (row.get("ownership") or {}).get("service_uuid")
                    == service_id
                ]
                user_entries = [
                    row
                    for row in self._active_entries("mos_user")
                    if (row.get("ownership") or {}).get("service_uuid")
                    == service_id
                ]
                policy_entries = [
                    row
                    for row in self._active_entries("mos_inline_policy")
                    if (row.get("ownership") or {}).get("service_uuid")
                    == service_id
                ]
                key_entries = [
                    row
                    for row in self._active_entries("mos_access_key")
                    if (row.get("ownership") or {}).get("service_uuid")
                    == service_id
                ]
                provider_entries = (
                    [("mos_service", row) for row in service_entries]
                    + [("mos_network", row) for row in network_entries]
                    + [("mos_user", row) for row in user_entries]
                    + [("mos_inline_policy", row) for row in policy_entries]
                    + [("mos_access_key", row) for row in key_entries]
                )
                unreceipted = [
                    {
                        "kind": kind,
                        "resource_id": str(row.get("resource_id") or ""),
                    }
                    for kind, row in provider_entries
                    if (kind, str(row.get("resource_id") or ""))
                    not in retention_receipts
                ]
                runtime_verified = False
                runtime_receipt_id = ""
                if len(key_entries) == 1:
                    runtime_receipt_id = self._runtime_retention_resource_id(
                        key_entries[0]
                    )
                    if (
                        MOS_RUNTIME_CREDENTIAL_KIND,
                        runtime_receipt_id,
                    ) in retention_receipts:
                        self._validate_runtime_for_retention(exact, key_entries[0])
                        runtime_verified = True
                expected_receipt_identities = {
                    (kind, str(row.get("resource_id") or ""))
                    for kind, row in provider_entries
                }
                if runtime_receipt_id:
                    expected_receipt_identities.add(
                        (MOS_RUNTIME_CREDENTIAL_KIND, runtime_receipt_id)
                    )
                service_receipt_identities = {
                    identity
                    for identity, receipt in retention_receipts.items()
                    if (receipt.get("ownership") or {}).get("service_uuid")
                    == service_id
                }
                unexpected_receipts = sorted(
                    service_receipt_identities - expected_receipt_identities
                )
                expected_networks = (
                    [self.names["network"]] if len(network_entries) == 1 else []
                )
                expected_users = (
                    [self.names["username"]] if len(user_entries) == 1 else []
                )
                expected_policies = (
                    [self.names["policy"]] if len(policy_entries) == 1 else []
                )
                expected_key_fingerprints = sorted(
                    str(row.get("resource_id") or "") for row in key_entries
                )
                retention_verified = all(
                    (
                        len(service_entries) == 1,
                        len(network_entries) == 1,
                        len(user_entries) == 1,
                        len(policy_entries) == 1,
                        len(key_entries) == 1,
                        not buckets,
                        network_names == expected_networks,
                        users == expected_users,
                        policy_names == expected_policies,
                        key_fingerprints == expected_key_fingerprints,
                        not unreceipted,
                        runtime_verified,
                        not unexpected_receipts,
                    )
                )
                scaffold_receipts = [
                    {
                        "kind": kind,
                        "resource_id": resource_id,
                        "disposition": USER_RETAINED_BY_INSTRUCTION,
                    }
                    for (kind, resource_id), receipt in sorted(
                        retention_receipts.items()
                    )
                    if (receipt.get("ownership") or {}).get("service_uuid")
                    == service_id
                ]
                mos_graph.append(
                    {
                        "service_uuid": service_id,
                        "buckets": buckets,
                        "users": users,
                        "networks": network_names,
                        "inline_policies": policy_names,
                        "key_fingerprints": key_fingerprints,
                        "protected_runtime_file_verified": runtime_verified,
                        "disposition": (
                            USER_RETAINED_BY_INSTRUCTION
                            if (
                                "mos_service",
                                service_id,
                            ) in retention_receipts
                            else ""
                        ),
                        "retention_verified": retention_verified,
                        "unreceipted_scaffolding": unreceipted,
                        "unexpected_retention_receipts": [
                            {"kind": kind, "resource_id": resource_id}
                            for kind, resource_id in unexpected_receipts
                        ],
                        "retained_scaffolding": scaffold_receipts,
                    }
                )
            elif name == self.names["service"]:
                service_collisions.append(str(summary.get("uuid") or ""))
        result = {
            "status": "verified",
            "phase": phase,
            "exact_run": {
                **{key: sorted(value) for key, value in matches.items()},
                "attachments": sorted(attachments, key=lambda row: (row["server_id"], row["storage_id"])),
                "public_ips": sorted(public_ips, key=lambda row: (row["server_id"], row["address_sha256"])),
                "mos_services": sorted(service_matches),
                "mos_graph": mos_graph,
            },
            "name_only_collisions": collisions,
            "mos_name_only_collisions": service_collisions,
            "retained_by_instruction": self._mos_retention_summary(
                retention_receipts
            ),
        }
        missing_ledger_services = sorted(
            ledger_service_ids - set(service_matches)
        )
        orphaned_receipt_services = sorted(
            {
                str((row.get("ownership") or {}).get("service_uuid") or "")
                for row in retention_receipts.values()
            }
            - set(service_matches)
        )
        unverified_retained_graph = [
            row["service_uuid"]
            for row in mos_graph
            if not row["retention_verified"]
        ]
        if phase == "after" and any(
            (
                matches["servers"],
                matches["storages"],
                matches["backups"],
                attachments,
                public_ips,
                collisions,
                service_collisions,
                missing_ledger_services,
                orphaned_receipt_services,
                unverified_retained_graph,
            )
        ):
            raise HarnessError("Final exact-run inventory found provider orphans.")
        return result


def _plan() -> dict:
    return {
        "status": "plan_only",
        "network_calls": False,
        "credentials_read": False,
        "commands": [
            "setup-compute",
            "verify-compute",
            "verify-workloads",
            "cleanup-compute",
            "setup-object-storage",
            "arm-object-storage",
            "verify-object-storage",
            "cleanup-object-storage",
            "reconcile-object-storage-evidence",
            "export-manifests",
            "inventory",
        ],
        "gates": {
            "setup": "BACKUPSHEEP_E2E_APPLY=YES",
            "cleanup": (
                "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
            ),
            "network_allowlist": (
                "UPCLOUD_E2E_ALLOWED_CIDRS containing only exact /32 or /128 hosts"
            ),
            "acceptance_cleanup": "cleanup-compute --require-evidence",
            "object_storage_credentials": (
                "preserve-credentials is mandatory and default-on; this harness "
                "has no credential revoke mode"
            ),
        },
        "workflow": [
            "Run setup-compute to create the exact server, boot storage, normal volume, website tree, and PostgreSQL fixture.",
            "Attach the printed source server and source volume IDs through the BackupSheep UI.",
            "Run UI Cloud Server and Volume backups/restores, then verify-compute with exact provider IDs and markers.",
            "Run UI website/PostgreSQL backups/restores and verify-workloads against hashes, schema, and row counts.",
            "Run setup-object-storage.",
            "Configure the UI storage with no_delete=false using the protected runtime file.",
            "Run arm-object-storage only after UI validation has removed its probe.",
            "Run UI website/database backups and restores.",
            "Export a non-secret artifact manifest and run verify-object-storage.",
            "Use cleanup-compute --require-evidence for acceptance cleanup.",
            "Run cleanup-object-storage under the separate cleanup gate.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safety-gated UpCloud live UI E2E support harness."
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("plan")
    subparsers.add_parser("setup-compute")
    verify_compute = subparsers.add_parser("verify-compute")
    verify_compute.add_argument("--manifest", required=True)
    verify_workloads = subparsers.add_parser("verify-workloads")
    verify_workloads.add_argument("--manifest", required=True)
    cleanup_compute = subparsers.add_parser("cleanup-compute")
    cleanup_compute.add_argument("--require-evidence", action="store_true")
    subparsers.add_parser("setup-object-storage")
    subparsers.add_parser("arm-object-storage")
    verify = subparsers.add_parser("verify-object-storage")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--maximum-bytes", type=int, default=10 * 1024**3)
    cleanup = subparsers.add_parser("cleanup-object-storage")
    cleanup.add_argument("--maximum-bytes", type=int, default=10 * 1024**3)
    cleanup.add_argument("--require-evidence", action="store_true")
    cleanup.add_argument(
        "--preserve-credentials",
        action="store_true",
        default=True,
        help=(
            "Mandatory default-on gate retaining the MOS key, user, service, "
            "policy, network, and protected runtime file."
        ),
    )
    subparsers.add_parser("reconcile-object-storage-evidence")
    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("--phase", choices=("before", "after"), required=True)
    exporter = subparsers.add_parser("export-manifests")
    for option in (
        "account-id",
        "storage-id",
        "website-backup-id",
        "website-restore-id",
        "database-backup-id",
        "database-restore-id",
        "volume-restore-id",
        "server-restore-id",
    ):
        exporter.add_argument(f"--{option}", type=int, required=True)
    exporter.add_argument("--run-id", required=True)
    exporter.add_argument("--output-dir", required=True)
    return parser


def main(argv=None, *, environment=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "plan"
    if command == "plan":
        print(json.dumps(_plan(), indent=2, sort_keys=True))
        return 0
    environment = environment or os.environ
    try:
        if command == "export-manifests":
            os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")
            import django

            django.setup()
            from scripts.upcloud_manifest_export import (
                UpCloudManifestExportError,
                export_upcloud_manifests,
            )

            try:
                result = export_upcloud_manifests(
                    output_dir=args.output_dir,
                    run_id=args.run_id,
                    account_id=args.account_id,
                    storage_id=args.storage_id,
                    website_backup_id=args.website_backup_id,
                    website_restore_id=args.website_restore_id,
                    database_backup_id=args.database_backup_id,
                    database_restore_id=args.database_restore_id,
                    volume_restore_id=args.volume_restore_id,
                    server_restore_id=args.server_restore_id,
                )
            except UpCloudManifestExportError as error:
                raise HarnessError(str(error)) from None
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        config = HarnessConfig.from_environment(environment)
        harness = UpCloudLiveHarness(config, environment=environment)
        if command == "setup-compute":
            result = harness.setup_compute()
        elif command == "verify-compute":
            result = harness.verify_compute(args.manifest)
        elif command == "verify-workloads":
            result = harness.verify_workloads(args.manifest)
        elif command == "cleanup-compute":
            result = harness.cleanup_compute(
                require_evidence=args.require_evidence
            )
        elif command == "setup-object-storage":
            result = harness.setup_object_storage()
        elif command == "arm-object-storage":
            result = harness.arm_object_storage()
        elif command == "verify-object-storage":
            result = harness.verify_ui_objects(
                args.manifest, maximum_bytes=args.maximum_bytes
            )
        elif command == "cleanup-object-storage":
            result = harness.cleanup_object_storage(
                maximum_bytes=args.maximum_bytes,
                require_evidence=args.require_evidence,
                preserve_credentials=args.preserve_credentials,
            )
        elif command == "reconcile-object-storage-evidence":
            result = harness.reconcile_object_storage_evidence()
        elif command == "inventory":
            result = harness.inventory(phase=args.phase)
        else:
            raise HarnessError("Unknown UpCloud harness command.")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HarnessError, LedgerError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("ERROR: The UpCloud harness stopped safely.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
