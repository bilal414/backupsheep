"""Safety-gated DigitalOcean snapshot/restore acceptance harness.

The default execution is read-only.  Source provisioning is enabled only when
``BACKUPSHEEP_E2E_APPLY=YES`` and an exact expected Personal-team UUID/name are
provided.  Cleanup additionally requires ``BACKUPSHEEP_E2E_CLEANUP=YES`` and
deletes only exact IDs that this run read back and fsynced to its durable ledger.

The token is read exclusively from ``DIGITALOCEAN_TOKEN``.  It is never accepted
on the command line, persisted, or printed.
"""

from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

import boto3
import django
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    ConnectionClosedError,
    EndpointConnectionError,
    ReadTimeoutError,
)


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")
django.setup()

from apps.api.v1.connection.digitalocean.client import (  # noqa: E402
    DigitalOceanAPIError,
    digitalocean_api_url,
    find_exact_snapshot,
    get_json,
    iter_collection,
)
from apps.api.v1.utils.http import request_timeout, requests  # noqa: E402
from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


class HarnessError(RuntimeError):
    """A fail-closed, secret-free harness failure."""


class AmbiguousMutation(HarnessError):
    """A provider request may have been accepted but cannot yet be adopted."""


class ScopedProviderRejection(HarnessError):
    """The PAT or Spaces key lacks one named capability."""

    def __init__(self, required_scope: str):
        self.required_scope = str(required_scope)
        super().__init__(
            f"DigitalOcean rejected the required {self.required_scope} capability."
        )


class InventoryNotEmpty(HarnessError):
    """Cleanup found objects or uploads it is not authorized to remove."""


PAYLOAD_PORT = 8080
PAYLOAD_MAX_BYTES = 64 * 1024
HEALTH_MAX_BYTES = 4 * 1024
SPACES_MAX_PAGES = 10_000
SPACES_MAX_ITEMS = 2_000_000
SPACES_SECRET_FIELDS = {
    "endpoint_url",
    "region",
    "bucket",
    "access_key",
    "secret_key",
}
SPACES_OBJECT_KINDS = {
    "spaces_ownership_object",
    "spaces_ui_website_object",
    "spaces_ui_database_object",
}
UI_OBJECT_MANIFEST_SCHEMA = 1
UI_OBJECT_KINDS = {"website", "database"}
UI_OBJECT_MANIFEST_KEYS = {"schema", "run_id", "prefix", "objects"}
UI_OBJECT_MANIFEST_ROW_KEYS = {
    "kind",
    "key",
    "version_id",
    "sha256",
    "etag",
    "backup_id",
    "byte_count",
    "metadata",
}
SPACES_UI_METADATA_KEYS = {
    "backupsheep-backup-id",
    "backupsheep-bytes",
    "backupsheep-sha256",
}
MUTATION_INTENT_SCHEMA = 1
MUTATION_INTENT_MAX_AGE_SECONDS = 24 * 60 * 60
MUTATION_RECONCILE_TIMEOUT_SECONDS = 300
MUTATION_RECONCILE_INTERVAL_SECONDS = 5
FIREWALL_SELECTOR_FIELDS = {
    "addresses",
    "droplet_ids",
    "load_balancer_uids",
    "kubernetes_ids",
    "tags",
}
NATIVE_VOLUME_VERIFIER_SCHEMA = 1
NATIVE_VOLUME_VERIFIER_APPLY_ENV = "BACKUPSHEEP_E2E_VOLUME_VERIFY_APPLY"
NATIVE_VOLUME_SEED_APPLY_ENV = "BACKUPSHEEP_E2E_VOLUME_SEED_APPLY"
NATIVE_VOLUME_VERIFIER_CLEANUP_ENV = "BACKUPSHEEP_E2E_VOLUME_VERIFY_CLEANUP"
NATIVE_VOLUME_DEFAULT_OFFSET_BYTES = 16 * 1024 * 1024
NATIVE_VOLUME_DEFAULT_BYTE_COUNT = 4 * 1024 * 1024
NATIVE_VOLUME_MIN_OFFSET_BYTES = 8 * 1024 * 1024
NATIVE_VOLUME_MAX_OFFSET_BYTES = 1024 * 1024 * 1024
NATIVE_VOLUME_MAX_BYTE_COUNT = 16 * 1024 * 1024
NATIVE_VOLUME_BLOCK_ALIGNMENT = 4096
NATIVE_VOLUME_KEY_FILES = {
    "client_key",
    "client_key.pub",
    "host_key",
    "host_key.pub",
    "known_hosts",
    "manifest.json",
}
NATIVE_VOLUME_KEY_MANIFEST_KEYS = {
    "schema",
    "run_id",
    "team_uuid",
    "client_public_key",
    "client_fingerprint",
    "host_public_key",
    "host_fingerprint",
    "created_at",
}


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError("A local JSON artifact contains duplicate object keys.")
        result[key] = value
    return result


def _strict_json_loads(raw: str | bytes, *, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_strict_json_object)
    except HarnessError:
        raise
    except (TypeError, UnicodeError, ValueError) as error:
        raise HarnessError(f"The local {label} JSON is malformed.") from error


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _native_volume_range(offset_bytes: Any, byte_count: Any) -> tuple[int, int]:
    if type(offset_bytes) is not int or type(byte_count) is not int:
        raise HarnessError("The native-volume byte range must use exact integers.")
    if (
        offset_bytes < NATIVE_VOLUME_MIN_OFFSET_BYTES
        or offset_bytes > NATIVE_VOLUME_MAX_OFFSET_BYTES
        or byte_count < NATIVE_VOLUME_BLOCK_ALIGNMENT
        or byte_count > NATIVE_VOLUME_MAX_BYTE_COUNT
        or offset_bytes % NATIVE_VOLUME_BLOCK_ALIGNMENT
        or byte_count % NATIVE_VOLUME_BLOCK_ALIGNMENT
    ):
        raise HarnessError(
            "The native-volume byte range is outside the aligned safety bounds."
        )
    return offset_bytes, byte_count


def _native_volume_fixture(
    *,
    run_id: str,
    team_uuid: str,
    source_volume_id: str,
    offset_bytes: int,
    byte_count: int,
) -> dict[str, Any]:
    """Return deterministic bytes that cannot be caller-asserted as provider proof."""

    offset_bytes, byte_count = _native_volume_range(offset_bytes, byte_count)
    identity = {
        "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
        "purpose": "backupsheep-digitalocean-native-volume-live-e2e",
        "run_id": require_run_id(run_id),
        "team_uuid": str(team_uuid),
        "source_volume_id": str(source_volume_id),
        "offset_bytes": offset_bytes,
        "byte_count": byte_count,
    }
    if not identity["team_uuid"] or not identity["source_volume_id"]:
        raise HarnessError("The native-volume fixture identity is incomplete.")
    header = b"BACKUPSHEEP-DO-NATIVE-VOLUME-E2E\n" + _canonical(identity).encode(
        "ascii"
    ) + b"\n"
    if len(header) >= byte_count:
        raise HarnessError("The native-volume fixture header exceeds its byte range.")
    seed = hashlib.sha256(header).digest()
    payload = header + hashlib.shake_256(seed).digest(byte_count - len(header))
    if len(payload) != byte_count:
        raise HarnessError("The native-volume fixture length is inconsistent.")
    return {
        **identity,
        "payload": payload,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "fixture_fingerprint": _fingerprint(identity),
    }


def _native_volume_device_path(volume_name: Any) -> str:
    name = str(volume_name or "")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
        raise HarnessError("The native-volume provider name is unsafe for a device path.")
    return f"/dev/disk/by-id/scsi-0DO_Volume_{name}"


def _ssh_public_key(value: Any, *, label: str) -> str:
    text_value = str(value or "").strip()
    parts = text_value.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise HarnessError(f"The {label} is not one exact Ed25519 public key.")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as error:
        raise HarnessError(f"The {label} is malformed.") from error
    if not decoded or len(decoded) > 4096:
        raise HarnessError(f"The {label} is malformed.")
    return f"ssh-ed25519 {parts[1]}"


def _ssh_public_fingerprint(public_key: str) -> str:
    normalized = _ssh_public_key(public_key, label="SSH public key")
    blob = base64.b64decode(normalized.split()[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _secret_safe_subprocess(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout_seconds: int = 30,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            arguments,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=timeout_seconds,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HarnessError("A protected native-volume verifier command failed.") from error


def _spaces_prefix(value: Any) -> str:
    """Return one unambiguous, durable S3 object prefix.

    S3 keys are opaque strings, but operators and providers routinely render
    them through URL/path tooling.  Refusing path separators, encoded path
    separators, dot segments, and absolute prefixes keeps the ownership proof
    stable across those representations.
    """

    prefix = str(value or "")
    if (
        not prefix
        or prefix != prefix.strip()
        or not prefix.endswith("/")
        or prefix.startswith(("/", "\\"))
        or "\x00" in prefix
        or "\\" in prefix
        or "%" in prefix
        or "//" in prefix
    ):
        raise HarnessError("The active Spaces object prefix is ambiguous.")
    if any(part in {".", ".."} for part in prefix.split("/")[:-1]):
        raise HarnessError("The active Spaces object prefix contains traversal.")
    return prefix


def _spaces_object_key(key: Any, prefix: str) -> str:
    """Validate that *key* is exactly below the already-pinned *prefix*."""

    prefix = _spaces_prefix(prefix)
    value = str(key or "")
    if (
        not value
        or value != value.strip()
        or not value.startswith(prefix)
        or value == prefix
        or value.startswith(("/", "\\"))
        or "\x00" in value
        or "\\" in value
        or "%" in value
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise HarnessError("The Spaces object key is outside the exact run prefix.")
    return value


def _backup_witness(value: Any) -> str:
    """Validate the positive BackupSheep row ID persisted in object metadata."""

    if isinstance(value, bool) or value is None:
        raise HarnessError("The Spaces object has no exact BackupSheep backup witness.")
    if isinstance(value, int):
        witness = str(value)
    elif isinstance(value, str):
        witness = value.strip()
    else:
        raise HarnessError("The Spaces object has no exact BackupSheep backup witness.")
    if not re.fullmatch(r"[1-9][0-9]*", witness):
        raise HarnessError("The Spaces object has no exact BackupSheep backup witness.")
    return witness


def _positive_integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value.strip()):
        return int(value.strip())
    return None


def _spaces_ui_metadata(
    metadata: Any, *, backup_id: str, sha256: str, byte_count: int
) -> dict[str, str]:
    """Require the complete, exact metadata contract before object reads."""

    if not isinstance(metadata, dict):
        raise HarnessError("The Spaces object metadata witness is malformed.")
    normalized = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise HarnessError("The Spaces object metadata witness is malformed.")
        normalized_key = key.casefold()
        if normalized_key in normalized:
            raise HarnessError("The Spaces object metadata witness has duplicate keys.")
        normalized[normalized_key] = value
    try:
        normalized_bytes = int(byte_count)
    except (TypeError, ValueError):
        raise HarnessError("The Spaces object byte witness is malformed.") from None
    checksum = str(sha256).casefold()
    if normalized_bytes < 0 or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise HarnessError("The Spaces object checksum or byte witness is malformed.")
    expected = {
        "backupsheep-backup-id": _backup_witness(backup_id),
        "backupsheep-bytes": str(normalized_bytes),
        "backupsheep-sha256": checksum,
    }
    if set(normalized) != SPACES_UI_METADATA_KEYS or normalized != expected:
        raise HarnessError(
            "The Spaces object metadata is not the exact BackupSheep witness."
        )
    return expected


def _manifest_has_sensitive_keys(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(
                token in normalized
                for token in ("secret", "password", "access_key", "token")
            ):
                return True
            if _manifest_has_sensitive_keys(child):
                return True
    elif isinstance(value, list):
        return any(_manifest_has_sensitive_keys(child) for child in value)
    return False


def _load_ui_object_manifest(
    manifest_path: str,
    *,
    run_id: str,
    prefix: str,
    maximum_bytes: int,
) -> list[dict[str, Any]]:
    """Read and fully validate a secret-free UI object manifest locally."""

    try:
        path = Path(manifest_path).expanduser()
        if path.is_symlink() or not path.is_file():
            raise OSError("manifest is not a regular file")
        manifest = _strict_json_loads(
            path.read_bytes(), label="UI upload manifest"
        )
    except HarnessError:
        raise
    except OSError as error:
        raise HarnessError("The UI upload manifest could not be read.") from error
    if not isinstance(manifest, dict):
        raise HarnessError("The UI upload manifest must be a JSON object.")
    if _manifest_has_sensitive_keys(manifest):
        raise HarnessError("The UI upload manifest must not contain credentials.")
    if set(manifest) != UI_OBJECT_MANIFEST_KEYS:
        raise HarnessError("The UI upload manifest contains unknown or missing fields.")
    if (
        type(manifest.get("schema")) is not int
        or manifest.get("schema") != UI_OBJECT_MANIFEST_SCHEMA
        or manifest.get("run_id") != run_id
        or manifest.get("prefix") != prefix
    ):
        raise HarnessError(
            "The UI upload manifest schema, run_id, or prefix is outside this run."
        )
    objects = manifest.get("objects")
    if not isinstance(objects, list) or not objects or len(objects) > 100:
        raise HarnessError("The UI upload manifest must contain 1-100 objects.")

    normalized_objects = []
    seen = set()
    seen_keys = set()
    for item in objects:
        if not isinstance(item, dict):
            raise HarnessError("The UI upload manifest contains a malformed row.")
        if set(item) != UI_OBJECT_MANIFEST_ROW_KEYS:
            raise HarnessError("The UI upload manifest row contains unknown or missing fields.")
        metadata = item.get("metadata")
        if isinstance(metadata, dict) and "backupsheep-size" in {
            str(key).casefold() for key in metadata
        }:
            raise HarnessError("The legacy backupsheep-size metadata field is forbidden.")
        object_kind = str(item.get("kind") or "")
        key = _spaces_object_key(item.get("key"), prefix)
        version_id = str(item.get("version_id") or "")
        sha256 = str(item.get("sha256") or "").casefold()
        etag = str(item.get("etag") or "").strip('"')
        backup_id = _backup_witness(item.get("backup_id"))
        if type(item.get("byte_count")) is not int:
            raise HarnessError("The UI upload byte count is malformed.")
        byte_count = item["byte_count"]
        metadata = _spaces_ui_metadata(
            metadata,
            backup_id=backup_id,
            sha256=sha256,
            byte_count=byte_count,
        )
        identity = (key, version_id)
        if (
            object_kind not in UI_OBJECT_KINDS
            or not version_id
            or version_id == "null"
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or not etag
            or byte_count < 0
            or byte_count > maximum_bytes
            or identity in seen
            or key in seen_keys
        ):
            raise HarnessError("The UI upload witness is incomplete or unsafe.")
        seen.add(identity)
        seen_keys.add(key)
        normalized_objects.append(
            {
                "kind": object_kind,
                "key": key,
                "version_id": version_id,
                "sha256": sha256,
                "etag": etag,
                "backup_id": backup_id,
                "byte_count": byte_count,
                "metadata": metadata,
            }
        )
    if {item["kind"] for item in normalized_objects} != UI_OBJECT_KINDS:
        raise HarnessError("The manifest must prove one website and one database upload.")
    return normalized_objects


def _canonical(value: dict[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise HarnessError("Mutation parameters are not canonicalizable.") from error


def _fingerprint(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _resource_name(run_id: str, suffix: str) -> str:
    """Return a DigitalOcean-volume-safe, deterministic name (max 64 chars)."""

    raw = f"{run_id}-{suffix}"
    if not raw[0].isalpha():
        raw = f"bs-{raw}"
    if len(raw) <= 64:
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    tail = f"-{digest}-{suffix}"
    return f"{raw[: 64 - len(tail)].rstrip('-')}{tail}"


def _spaces_bucket_name(run_id: str, team_uuid: str, region: str) -> str:
    """Return a deterministic, high-entropy, DNS-safe Spaces bucket name."""

    digest = hashlib.sha256(
        f"digitalocean-spaces:{team_uuid}:{run_id}:{region}".encode("utf-8")
    ).hexdigest()[:20]
    stem = re.sub(r"[^a-z0-9-]+", "-", run_id.lower()).strip("-")[:30]
    name = f"bs-e2e-{stem}-{digest}"
    if not 3 <= len(name) <= 63 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name
    ):
        raise HarnessError("The generated Spaces bucket name is invalid.")
    return name


def _payload_expectation(run_id: str) -> dict[str, Any]:
    """Build a bounded deterministic payload; only its expectation is persisted."""

    seed = hashlib.sha256(f"backupsheep-do-payload:{run_id}".encode()).hexdigest()
    lines = [
        "BackupSheep DigitalOcean live E2E payload v1",
        f"run={run_id}",
    ]
    lines.extend(f"block-{index:03d}={seed}" for index in range(64))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if not payload or len(payload) > PAYLOAD_MAX_BYTES:
        raise HarnessError("The deterministic source payload exceeded its bound.")
    return {
        "payload": payload,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "byte_count": len(payload),
        "run_marker": run_id,
    }


def _cloud_init(run_id: str, expectation: dict[str, Any]) -> str:
    """Serve only two bounded unauthenticated endpoints behind a run firewall."""

    payload = expectation.get("payload")
    if not isinstance(payload, bytes):
        raise HarnessError("The source payload is unavailable for cloud-init.")
    marker = json.dumps(run_id)
    expected_hash = json.dumps(str(expectation["sha256"]))
    expected_bytes = int(expectation["byte_count"])
    server = f'''#!/usr/bin/env python3
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOAD = Path("/opt/backupsheep-e2e/payload.bin")
EXPECTED_SHA256 = {expected_hash}
EXPECTED_BYTES = {expected_bytes}
RUN_MARKER = {marker}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        body = PAYLOAD.read_bytes()
        valid = len(body) == EXPECTED_BYTES and hashlib.sha256(body).hexdigest() == EXPECTED_SHA256
        if self.path == "/healthz":
            response = json.dumps({{"ready": valid, "sha256": EXPECTED_SHA256, "byte_count": EXPECTED_BYTES, "run_marker": RUN_MARKER}}, separators=(",", ":")).encode()
            self.send_response(200 if valid else 503)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/payload" and valid:
            response = body
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
        else:
            response = b"not found\\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

ThreadingHTTPServer(("0.0.0.0", {PAYLOAD_PORT}), Handler).serve_forever()
'''
    unit = f'''[Unit]
Description=BackupSheep deterministic DigitalOcean E2E payload
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 /opt/backupsheep-e2e/server.py
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/opt/backupsheep-e2e

[Install]
WantedBy=multi-user.target
'''
    cloud_config = {
        "write_files": [
            {
                "path": "/opt/backupsheep-e2e/payload.bin",
                "permissions": "0644",
                "encoding": "b64",
                "content": base64.b64encode(payload).decode("ascii"),
            },
            {
                "path": "/opt/backupsheep-e2e/server.py",
                "permissions": "0555",
                "content": server,
            },
            {
                "path": "/etc/systemd/system/backupsheep-e2e.service",
                "permissions": "0644",
                "content": unit,
            },
        ],
        "runcmd": [
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", "backupsheep-e2e.service"],
        ],
    }
    # JSON is valid YAML 1.2 and avoids ad-hoc shell escaping in user data.
    return "#cloud-config\n" + json.dumps(cloud_config, separators=(",", ":"))


def _probe_cidrs(values: list[str]) -> list[str]:
    """Accept only explicit single-host CIDRs; never expose the probe port globally."""

    result = []
    for raw in values:
        for item in str(raw or "").split(","):
            item = item.strip()
            if not item:
                continue
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError as error:
                raise HarnessError("Every probe source must be an exact host CIDR.") from error
            if network.prefixlen != network.max_prefixlen:
                raise HarnessError("Probe exposure is limited to /32 or /128 hosts.")
            address = network.network_address
            if address.is_unspecified or address.is_multicast:
                raise HarnessError("The probe source CIDR is unsafe.")
            result.append(str(network))
    result = list(dict.fromkeys(result))
    if not result:
        raise HarnessError("At least one explicit /32 or /128 probe CIDR is required.")
    if not any(ipaddress.ip_network(value).version == 4 for value in result):
        raise HarnessError("At least one IPv4 /32 is required for the public payload probe.")
    return sorted(
        result,
        key=lambda value: (
            ipaddress.ip_network(value).version,
            int(ipaddress.ip_network(value).network_address),
        ),
    )


def _public_ipv4(resource: dict) -> str:
    networks = resource.get("networks") if isinstance(resource, dict) else None
    v4 = networks.get("v4") if isinstance(networks, dict) else None
    matches = []
    for item in v4 or []:
        if not isinstance(item, dict) or item.get("type") != "public":
            continue
        try:
            address = ipaddress.ip_address(str(item.get("ip_address") or ""))
        except ValueError:
            continue
        if address.version == 4:
            matches.append(str(address))
    if len(matches) != 1:
        raise HarnessError("The Droplet does not expose one exact public IPv4 address.")
    return matches[0]


def _digitalocean_source_tag(source_id: str) -> str:
    digest = hashlib.sha256(str(source_id).encode("utf-8")).hexdigest()[:32]
    return f"backupsheep-source-{digest}"


def _restore_source_values(resource: dict, target_kind: str) -> list[str]:
    keys = (
        ("image", "image_id", "snapshot_id")
        if target_kind == "droplet"
        else ("snapshot_id", "snapshot")
    )
    values = []
    for key in keys:
        if key not in resource:
            continue
        value = resource.get(key)
        if isinstance(value, dict):
            value = value.get("id")
        if value not in (None, ""):
            values.append(str(value))
    return values


def _restore_target_owned(resource: dict, witness: dict) -> bool:
    if not isinstance(resource, dict):
        return False
    if str(resource.get("id") or "") != str(witness.get("provider_id") or ""):
        return False
    if str(resource.get("name") or "") != str(witness.get("name") or ""):
        return False
    tags = resource.get("tags")
    if not isinstance(tags, list):
        return False
    normalized = {str(tag) for tag in tags if isinstance(tag, str)}
    required = {
        str(witness.get("marker") or ""),
        f"backupsheep-restore-{witness.get('target_kind')}",
    }
    if "" in required or not required.issubset(normalized):
        return False
    source_id = str(witness.get("snapshot_id") or "")
    if not source_id:
        return False
    if str(witness.get("target_kind") or "") == "volume":
        expected_region = str(witness.get("expected_region") or "")
        expected_size = _positive_integer(witness.get("expected_size_gigabytes"))
        actual_size = _positive_integer(resource.get("size_gigabytes"))
        if expected_size is None or actual_size is None:
            return False
        if (
            not expected_region
            or expected_size <= 0
            or _resource_region(resource) != expected_region
            or actual_size != expected_size
            or not isinstance(resource.get("droplet_ids"), list)
            or resource.get("droplet_ids") != []
        ):
            return False
    values = _restore_source_values(resource, str(witness.get("target_kind")))
    if values:
        return set(values) == {source_id}
    return _digitalocean_source_tag(source_id) in normalized


def _resource_region(resource: dict) -> str:
    region = resource.get("region") if isinstance(resource, dict) else None
    if isinstance(region, dict):
        return str(region.get("slug") or region.get("name") or "")
    return str(region or "")


def _resource_image(resource: dict) -> str:
    image = resource.get("image") if isinstance(resource, dict) else None
    if isinstance(image, dict):
        return str(image.get("slug") or image.get("id") or "")
    return str(image or "")


def _creation_witness(kind: str, resource: dict, request: dict | None = None) -> dict:
    """Capture immutable provider fields needed for later destructive cleanup."""

    request = request if isinstance(request, dict) else {}
    tags = resource.get("tags") if isinstance(resource, dict) else None
    request_tags = request.get("tags")
    expected_tags = request_tags if isinstance(request_tags, list) else tags
    witness = {
        "name": str(request.get("name") or resource.get("name") or ""),
        "region": str(request.get("region") or _resource_region(resource)),
        "tags": sorted(
            {str(tag) for tag in (expected_tags or []) if isinstance(tag, str)}
        ),
    }
    if kind.endswith("droplet") or kind == "payload_firewall":
        if kind == "payload_firewall":
            return witness
        witness.update(
            {
                "size": str(
                    request.get("size")
                    or resource.get("size_slug")
                    or resource.get("size")
                    or ""
                ),
                "image": str(request.get("image") or _resource_image(resource)),
            }
        )
    elif kind.endswith("volume"):
        size = request.get("size_gigabytes")
        if size is None:
            size = resource.get("size_gigabytes")
        try:
            witness["size_gigabytes"] = int(size)
        except (TypeError, ValueError):
            witness["size_gigabytes"] = -1
    return witness


def _creation_witness_matches(kind: str, resource: dict, witness: dict) -> bool:
    if not isinstance(resource, dict) or not isinstance(witness, dict):
        return False
    expected = _creation_witness(kind, resource, witness)
    # _creation_witness() uses the request-shaped values when present; compare
    # provider fields explicitly so a changed resource cannot be deleted merely
    # because its name and run tag still happen to match.
    if str(resource.get("name") or "") != str(witness.get("name") or ""):
        return False
    actual_tags = resource.get("tags")
    if sorted(
        {str(tag) for tag in (actual_tags or []) if isinstance(tag, str)}
    ) != sorted(str(tag) for tag in (witness.get("tags") or [])):
        return False
    if witness.get("region") and _resource_region(resource) != str(witness["region"]):
        return False
    if "size" in witness and str(
        resource.get("size_slug") or resource.get("size") or ""
    ) != str(witness.get("size") or ""):
        return False
    if "image" in witness and _resource_image(resource) != str(witness.get("image") or ""):
        return False
    if "size_gigabytes" in witness:
        try:
            actual_size = int(resource.get("size_gigabytes"))
        except (TypeError, ValueError):
            return False
        if actual_size != int(witness.get("size_gigabytes") or -1):
            return False
    return _fingerprint(expected) == str(witness.get("immutable_fingerprint") or "")


def _request_creation_matches(kind: str, resource: dict, request: dict) -> bool:
    expected = _creation_witness(kind, resource, request)
    expected["immutable_fingerprint"] = _fingerprint(expected)
    return _creation_witness_matches(kind, resource, expected)


def _stored_snapshot_marker(ownership: dict) -> str:
    """Read a snapshot marker without conflating it with a restore marker.

    ``marker`` is the field used by older ledgers. It is accepted only when
    it is the sole witness or agrees exactly with the new explicit field.
    """

    if not isinstance(ownership, dict):
        return ""
    explicit = str(ownership.get("snapshot_marker") or "").strip()
    legacy = str(ownership.get("marker") or "").strip()
    if explicit and legacy and explicit != legacy:
        raise HarnessError("The snapshot ledger contains conflicting marker witnesses.")
    return explicit or legacy


def _stored_restore_marker(ownership: dict) -> str:
    """Read a restore marker while safely supporting pre-split ledgers."""

    if not isinstance(ownership, dict):
        return ""
    explicit = str(ownership.get("restore_marker") or "").strip()
    legacy = str(ownership.get("marker") or "").strip()
    if explicit and legacy and explicit != legacy:
        raise HarnessError("The restore ledger contains conflicting marker witnesses.")
    return explicit or legacy


def _resolve_legacy_marker(
    *,
    snapshot_marker: str | None,
    restore_marker: str | None,
    legacy_marker: str | None,
) -> tuple[str, str]:
    """Resolve old one-marker callers only when both roles are unambiguous."""

    snapshot = str(snapshot_marker or "").strip()
    restore = str(restore_marker or "").strip()
    legacy = str(legacy_marker or "").strip()
    if legacy and snapshot and legacy != snapshot:
        raise HarnessError("The legacy marker conflicts with the snapshot marker.")
    if legacy and restore and legacy != restore:
        raise HarnessError("The legacy marker conflicts with the restore marker.")
    if legacy:
        snapshot = snapshot or legacy
        restore = restore or legacy
    return snapshot, restore


def select_ui_restore_witness(candidates: list[dict], witness: dict) -> dict:
    """Select one exact UI restore and fail on missing, duplicate, or foreign rows."""

    if not isinstance(candidates, list) or any(
        not isinstance(item, dict) for item in candidates
    ):
        raise HarnessError("DigitalOcean returned malformed UI restore witnesses.")
    exact = [item for item in candidates if _restore_target_owned(item, witness)]
    if len(exact) > 1:
        raise HarnessError("Multiple exact UI restore witnesses were found.")
    if len(candidates) > 1:
        raise HarnessError("Duplicate or foreign resources share the UI restore marker.")
    if not exact:
        if candidates:
            raise HarnessError("The UI restore witness is foreign or incomplete.")
        raise HarnessError("The UI restore witness is missing.")
    return exact[0]


def _default_spaces_secret_path(run_id: str) -> Path:
    git_metadata = ROOT / ".git"
    if git_metadata.is_dir():
        return git_metadata / "backupsheep-e2e-secrets" / f"{run_id}-spaces.json"
    return (
        Path(tempfile.gettempdir())
        / "backupsheep-e2e-secrets"
        / f"{run_id}-spaces.json"
    )


def _validate_secret_path(path: Path) -> Path:
    path = path.expanduser().resolve(strict=False)
    try:
        path.relative_to(ROOT)
    except ValueError:
        return path
    git_metadata = (ROOT / ".git").resolve(strict=False)
    try:
        path.relative_to(git_metadata)
    except ValueError as error:
        raise HarnessError(
            "The Spaces credential file must be outside the worktree or inside .git."
        ) from error
    return path


def _write_runtime_secret(path: Path, payload: dict[str, str]) -> None:
    path = _validate_secret_path(path)
    if set(payload) != SPACES_SECRET_FIELDS or any(
        not isinstance(value, str) or not value for value in payload.values()
    ):
        raise HarnessError("The Spaces runtime credential payload is malformed.")
    if path.is_symlink():
        raise HarnessError("The Spaces runtime credential path cannot be a symlink.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_runtime_secret(path: Path) -> dict[str, str]:
    path = _validate_secret_path(path)
    if path.is_symlink() or not path.is_file():
        raise HarnessError("The protected Spaces runtime credential file is missing.")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise HarnessError("The Spaces runtime credential file must have mode 0600.")
    try:
        payload = _strict_json_loads(
            path.read_bytes(), label="Spaces runtime credential"
        )
    except HarnessError:
        raise
    except OSError as error:
        raise HarnessError("The Spaces runtime credential file is unreadable.") from error
    if not isinstance(payload, dict) or set(payload) != SPACES_SECRET_FIELDS or any(
        not isinstance(value, str) or not value for value in payload.values()
    ):
        raise HarnessError("The Spaces runtime credential file is malformed.")
    return payload


def _native_volume_key_dir(
    *, ledger_path: Any, requested_path: Any, run_id: str, team_uuid: str
) -> Path:
    ledger = Path(str(ledger_path or "")).expanduser().resolve(strict=False)
    if not str(ledger_path or ""):
        raise HarnessError("The native-volume verifier requires a durable ledger path.")
    digest = hashlib.sha256(
        f"digitalocean-native-volume:{team_uuid}:{run_id}".encode("utf-8")
    ).hexdigest()[:24]
    expected_leaf = f".backupsheep-do-volume-verifier-{digest}"
    candidate = (
        Path(str(requested_path)).expanduser()
        if requested_path
        else ledger.parent / expected_leaf
    ).resolve(strict=False)
    if candidate.parent != ledger.parent or candidate.name != expected_leaf:
        raise HarnessError(
            "The native-volume verifier key directory must use its exact ledger-adjacent path."
        )
    if candidate == _default_spaces_secret_path(run_id).resolve(strict=False):
        raise HarnessError("The native-volume key path conflicts with Spaces credentials.")
    return candidate


def _read_native_volume_key_material(
    path: Path, *, run_id: str, team_uuid: str
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir():
        raise HarnessError("The native-volume verifier key directory is missing or unsafe.")
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise HarnessError("The native-volume verifier key directory must have mode 0700.")
    children = {child.name for child in path.iterdir()}
    if children != NATIVE_VOLUME_KEY_FILES or any(child.is_symlink() for child in path.iterdir()):
        raise HarnessError("The native-volume verifier key directory contains unexpected files.")
    client_private = path / "client_key"
    client_public_path = path / "client_key.pub"
    host_private = path / "host_key"
    host_public_path = path / "host_key.pub"
    known_hosts_path = path / "known_hosts"
    manifest_path = path / "manifest.json"
    for private in (client_private, host_private, known_hosts_path, manifest_path):
        if not private.is_file() or stat.S_IMODE(private.stat().st_mode) != 0o600:
            raise HarnessError("A native-volume verifier protected key file has unsafe mode.")
    for public in (client_public_path, host_public_path):
        if not public.is_file() or stat.S_IMODE(public.stat().st_mode) != 0o644:
            raise HarnessError("A native-volume verifier public key file has unsafe mode.")
    try:
        manifest = _strict_json_loads(
            manifest_path.read_bytes(), label="native-volume key manifest"
        )
        client_public = _ssh_public_key(
            client_public_path.read_text(encoding="utf-8"),
            label="native-volume client public key",
        )
        host_public = _ssh_public_key(
            host_public_path.read_text(encoding="utf-8"),
            label="native-volume host public key",
        )
        known_hosts = known_hosts_path.read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError("The native-volume verifier key material is unreadable.") from error
    if not isinstance(manifest, dict) or set(manifest) != NATIVE_VOLUME_KEY_MANIFEST_KEYS:
        raise HarnessError("The native-volume verifier key manifest schema is invalid.")
    expected = {
        "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
        "run_id": run_id,
        "team_uuid": team_uuid,
        "client_public_key": client_public,
        "client_fingerprint": _ssh_public_fingerprint(client_public),
        "host_public_key": host_public,
        "host_fingerprint": _ssh_public_fingerprint(host_public),
        "created_at": manifest.get("created_at"),
    }
    if (
        not isinstance(expected["created_at"], str)
        or not expected["created_at"]
        or manifest != expected
    ):
        raise HarnessError("The native-volume verifier key manifest witness changed.")
    derived_client = _ssh_public_key(
        _secret_safe_subprocess(
            ["ssh-keygen", "-y", "-f", str(client_private)]
        ).stdout.decode("ascii", errors="strict"),
        label="derived native-volume client public key",
    )
    derived_host = _ssh_public_key(
        _secret_safe_subprocess(
            ["ssh-keygen", "-y", "-f", str(host_private)]
        ).stdout.decode("ascii", errors="strict"),
        label="derived native-volume host public key",
    )
    if derived_client != client_public or derived_host != host_public:
        raise HarnessError("A native-volume verifier private/public key pair mismatched.")
    if known_hosts != f"* {host_public}\n":
        raise HarnessError("The native-volume verifier host-key pin changed.")
    return {
        **manifest,
        "directory": path,
        "client_private_path": client_private,
        "host_private_path": host_private,
        "known_hosts_path": known_hosts_path,
    }


def _ensure_native_volume_key_material(
    path: Path, *, run_id: str, team_uuid: str
) -> dict[str, Any]:
    if path.exists() or path.is_symlink():
        return _read_native_volume_key_material(
            path, run_id=run_id, team_uuid=team_uuid
        )
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise HarnessError("The native-volume verifier ledger directory is unavailable.")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{path.name}.create.", dir=path.parent)
    )
    try:
        os.chmod(temporary, 0o700)
        for filename, comment in (
            ("client_key", f"backupsheep:{run_id}:client"),
            ("host_key", f"backupsheep:{run_id}:host"),
        ):
            _secret_safe_subprocess(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    comment,
                    "-f",
                    str(temporary / filename),
                ]
            )
            os.chmod(temporary / filename, 0o600)
            os.chmod(temporary / f"{filename}.pub", 0o644)
        client_public = _ssh_public_key(
            (temporary / "client_key.pub").read_text(encoding="utf-8"),
            label="native-volume client public key",
        )
        host_public = _ssh_public_key(
            (temporary / "host_key.pub").read_text(encoding="utf-8"),
            label="native-volume host public key",
        )
        known_hosts_path = temporary / "known_hosts"
        known_hosts_descriptor = os.open(
            known_hosts_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(known_hosts_descriptor, "w", encoding="ascii") as output:
            output.write(f"* {host_public}\n")
            output.flush()
            os.fsync(output.fileno())
        manifest = {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "run_id": run_id,
            "team_uuid": team_uuid,
            "client_public_key": client_public,
            "client_fingerprint": _ssh_public_fingerprint(client_public),
            "host_public_key": host_public,
            "host_fingerprint": _ssh_public_fingerprint(host_public),
            "created_at": _utc_now(),
        }
        manifest_path = temporary / "manifest.json"
        descriptor = os.open(
            manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        directory_fd = os.open(temporary, os.O_RDONLY)
        try:
            for filename in NATIVE_VOLUME_KEY_FILES:
                file_fd = os.open(temporary / filename, os.O_RDONLY)
                try:
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if temporary.exists():
            for filename in NATIVE_VOLUME_KEY_FILES:
                candidate = temporary / filename
                if candidate.is_file() and not candidate.is_symlink():
                    candidate.unlink()
            try:
                temporary.rmdir()
            except OSError:
                pass
    return _read_native_volume_key_material(path, run_id=run_id, team_uuid=team_uuid)


def _native_volume_verifier_cloud_init(
    *, run_id: str, team_uuid: str, key_material: dict[str, Any]
) -> str:
    try:
        host_private = Path(key_material["host_private_path"]).read_bytes()
    except (KeyError, OSError) as error:
        raise HarnessError("The native-volume host key could not be read safely.") from error
    client_public = _ssh_public_key(
        key_material.get("client_public_key"),
        label="native-volume client public key",
    )
    host_public = _ssh_public_key(
        key_material.get("host_public_key"),
        label="native-volume host public key",
    )
    ready = _canonical(
        {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "run_id": run_id,
            "team_uuid": team_uuid,
            "client_fingerprint": key_material.get("client_fingerprint"),
            "host_fingerprint": key_material.get("host_fingerprint"),
        }
    ) + "\n"
    cloud_config = {
        "disable_root": False,
        "ssh_pwauth": False,
        "users": [
            {
                "name": "root",
                "ssh_authorized_keys": [client_public],
            }
        ],
        "write_files": [
            {
                "path": "/etc/ssh/ssh_host_ed25519_key",
                "owner": "root:root",
                "permissions": "0600",
                "encoding": "b64",
                "content": base64.b64encode(host_private).decode("ascii"),
            },
            {
                "path": "/etc/ssh/ssh_host_ed25519_key.pub",
                "owner": "root:root",
                "permissions": "0644",
                "content": host_public + "\n",
            },
            {
                "path": "/etc/ssh/sshd_config.d/91-backupsheep-volume-verifier.conf",
                "owner": "root:root",
                "permissions": "0644",
                "content": (
                    "PasswordAuthentication no\n"
                    "KbdInteractiveAuthentication no\n"
                    "PermitRootLogin prohibit-password\n"
                    "AllowUsers root\n"
                    "AllowTcpForwarding no\n"
                    "X11Forwarding no\n"
                    "PermitTunnel no\n"
                ),
            },
            {
                "path": "/var/lib/backupsheep-volume-verifier/ready.json",
                "owner": "root:root",
                "permissions": "0400",
                "content": ready,
            },
        ],
        "runcmd": [
            ["systemctl", "restart", "ssh.service"],
        ],
    }
    return "#cloud-config\n" + json.dumps(cloud_config, separators=(",", ":"))


NATIVE_VOLUME_GUEST_PROGRAM = r'''
import base64
import datetime
import glob
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.request

def fail(message):
    raise SystemExit(message)

def exact_read(descriptor, offset, count):
    chunks = []
    remaining = count
    cursor = offset
    while remaining:
        chunk = os.pread(descriptor, remaining, cursor)
        if not chunk:
            fail("short block-device read")
        chunks.append(chunk)
        cursor += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def metadata(path):
    request = urllib.request.Request(
        "http://169.254.169.254/metadata/v1/" + path,
        headers={"User-Agent": "backupsheep-native-volume-verifier/1"},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        value = response.read(256)
        if response.read(1):
            fail("metadata response exceeded its bound")
    return value.decode("ascii", errors="strict").strip()

try:
    request = json.loads(base64.b64decode(sys.argv[1], validate=True))
except Exception:
    fail("invalid verifier request")
if not isinstance(request, dict) or set(request) != {
    "schema", "operation", "run_id", "team_uuid", "droplet_id", "region",
    "ready_sha256", "volume_id", "volume_name", "offset_bytes", "byte_count",
    "expected_sha256", "expected_preimage_sha256",
}:
    fail("invalid verifier request schema")
if request.get("schema") != 1 or request.get("operation") not in {
    "identity", "inspect", "seed", "read"
}:
    fail("invalid verifier operation")
for key in ("run_id", "team_uuid", "droplet_id", "region", "ready_sha256"):
    if not isinstance(request.get(key), str) or not request[key]:
        fail("incomplete verifier identity")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,62}", request["run_id"]):
    fail("invalid run identity")
ready_path = "/var/lib/backupsheep-volume-verifier/ready.json"
with open(ready_path, "rb") as source:
    ready_bytes = source.read(8193)
if len(ready_bytes) > 8192 or hashlib.sha256(ready_bytes).hexdigest() != request["ready_sha256"]:
    fail("verifier readiness witness mismatch")
observed_droplet = metadata("id")
observed_region = metadata("region")
if observed_droplet != request["droplet_id"] or observed_region != request["region"]:
    fail("verifier metadata identity mismatch")
base = {
    "schema": 1,
    "run_id": request["run_id"],
    "team_uuid": request["team_uuid"],
    "verifier_droplet_id": observed_droplet,
    "observed_region": observed_region,
    "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
if request["operation"] == "identity":
    print(json.dumps({**base, "operation": "identity"}, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)

volume_id = request.get("volume_id")
volume_name = request.get("volume_name")
offset = request.get("offset_bytes")
count = request.get("byte_count")
if (
    not isinstance(volume_id, str) or not volume_id
    or not isinstance(volume_name, str)
    or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", volume_name)
    or type(offset) is not int or type(count) is not int
    or offset < 8 * 1024 * 1024 or offset > 1024 * 1024 * 1024
    or count < 4096 or count > 16 * 1024 * 1024
    or offset % 4096 or count % 4096
):
    fail("invalid volume byte range")
stable = "/dev/disk/by-id/scsi-0DO_Volume_" + volume_name
if not os.path.islink(stable) or sorted(glob.glob(stable + "*")) != [stable]:
    fail("stable volume device is missing or ambiguous")
resolved = os.path.realpath(stable)
device_stat = os.stat(resolved, follow_symlinks=True)
if not stat.S_ISBLK(device_stat.st_mode):
    fail("stable volume path is not a block device")
device_type = subprocess.run(
    ["lsblk", "-dn", "-o", "TYPE", resolved],
    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
).stdout.strip()
if device_type != "disk":
    fail("stable volume path is not a whole disk")
tree = json.loads(subprocess.run(
    ["lsblk", "-J", "-p", "-o", "NAME,TYPE,MOUNTPOINTS", resolved],
    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
).stdout)
nodes = tree.get("blockdevices") if isinstance(tree, dict) else None
if not isinstance(nodes, list) or len(nodes) != 1:
    fail("block topology is ambiguous")
def mounted(node):
    points = node.get("mountpoints")
    if points is None and "mountpoint" in node:
        points = [node.get("mountpoint")]
    if not isinstance(points, list) or any(point not in (None, "") for point in points):
        return True
    children = node.get("children") or []
    return not isinstance(children, list) or any(mounted(child) for child in children)
if mounted(nodes[0]):
    fail("volume or child device is mounted")
signatures = subprocess.run(
    ["wipefs", "--noheadings", "--output", "OFFSET,TYPE", "--no-act", resolved],
    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
).stdout.strip()
if signatures:
    fail("volume contains a filesystem or partition signature")
device_size = int(subprocess.run(
    ["blockdev", "--getsize64", resolved],
    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
).stdout.strip())
if offset + count > device_size:
    fail("volume byte range exceeds the block device")
read_descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
try:
    before = exact_read(read_descriptor, offset, count)
finally:
    os.close(read_descriptor)
before_sha256 = hashlib.sha256(before).hexdigest()
operation = request["operation"]
write_performed = False
status_value = "observed"
if operation == "seed":
    expected = request.get("expected_sha256")
    expected_preimage = request.get("expected_preimage_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("invalid expected fixture hash")
    if not isinstance(expected_preimage, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_preimage):
        fail("invalid expected preimage hash")
    payload = sys.stdin.buffer.read(count + 1)
    if len(payload) != count or hashlib.sha256(payload).hexdigest() != expected:
        fail("fixture input mismatch")
    if before_sha256 == expected:
        status_value = "already-seeded"
    else:
        if before_sha256 != expected_preimage:
            fail("source preimage changed before seed")
        descriptor = os.open(resolved, os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
        try:
            cursor = 0
            while cursor < len(payload):
                written = os.pwrite(descriptor, payload[cursor:], offset + cursor)
                if written <= 0:
                    fail("short block-device write")
                cursor += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        write_performed = True
        status_value = "seeded"
elif operation == "read":
    if request.get("expected_preimage_sha256") not in (None, ""):
        fail("read-only restore request contains a write precondition")
elif operation != "inspect":
    fail("unsupported block operation")
read_descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
try:
    observed = exact_read(read_descriptor, offset, count)
finally:
    os.close(read_descriptor)
observed_sha256 = hashlib.sha256(observed).hexdigest()
if operation in {"seed", "read"} and observed_sha256 != request.get("expected_sha256"):
    fail("live volume content hash mismatch")
result = {
    **base,
    "operation": operation,
    "status": status_value,
    "volume_id": volume_id,
    "volume_name": volume_name,
    "stable_device": stable,
    "resolved_device": resolved,
    "device_size_bytes": device_size,
    "offset_bytes": offset,
    "byte_count": count,
    "sha256": observed_sha256,
    "preimage_sha256": before_sha256,
    "mounted": False,
    "signatures": [],
    "open_mode": "read-only" if operation in {"identity", "inspect", "read"} else "read-write",
    "write_performed": write_performed,
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''.strip()


def _native_volume_ready_bytes(
    *, run_id: str, team_uuid: str, key_material: dict[str, Any]
) -> bytes:
    return (
        _canonical(
            {
                "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
                "run_id": run_id,
                "team_uuid": team_uuid,
                "client_fingerprint": key_material.get("client_fingerprint"),
                "host_fingerprint": key_material.get("host_fingerprint"),
            }
        )
        + "\n"
    ).encode("ascii")


def _validate_native_volume_guest_proof(
    proof: Any,
    *,
    operation: str,
    run_id: str,
    team_uuid: str,
    verifier_droplet_id: str,
    region: str,
    volume_id: str | None = None,
    volume_name: str | None = None,
    offset_bytes: int | None = None,
    byte_count: int | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    identity_keys = {
        "schema",
        "operation",
        "run_id",
        "team_uuid",
        "verifier_droplet_id",
        "observed_region",
        "observed_at",
    }
    volume_keys = {
        "status",
        "volume_id",
        "volume_name",
        "stable_device",
        "resolved_device",
        "device_size_bytes",
        "offset_bytes",
        "byte_count",
        "sha256",
        "preimage_sha256",
        "mounted",
        "signatures",
        "open_mode",
        "write_performed",
    }
    expected_keys = identity_keys if operation == "identity" else identity_keys | volume_keys
    if not isinstance(proof, dict) or set(proof) != expected_keys:
        raise HarnessError("The native-volume guest proof schema is invalid.")
    if (
        proof.get("schema") != NATIVE_VOLUME_VERIFIER_SCHEMA
        or proof.get("operation") != operation
        or proof.get("run_id") != run_id
        or proof.get("team_uuid") != team_uuid
        or str(proof.get("verifier_droplet_id") or "")
        != str(verifier_droplet_id)
        or proof.get("observed_region") != region
    ):
        raise HarnessError("The native-volume guest identity witness mismatched.")
    try:
        observed_at = datetime.fromisoformat(str(proof.get("observed_at") or ""))
    except ValueError as error:
        raise HarnessError("The native-volume guest timestamp is malformed.") from error
    if observed_at.tzinfo is None:
        raise HarnessError("The native-volume guest timestamp has no timezone.")
    if operation == "identity":
        return dict(proof)
    expected_offset, expected_count = _native_volume_range(
        offset_bytes, byte_count
    )
    expected_device = _native_volume_device_path(volume_name)
    checksum = str(proof.get("sha256") or "")
    preimage = str(proof.get("preimage_sha256") or "")
    if (
        proof.get("volume_id") != str(volume_id)
        or proof.get("volume_name") != str(volume_name)
        or proof.get("stable_device") != expected_device
        or not re.fullmatch(r"/dev/[A-Za-z0-9._:+-]+", str(proof.get("resolved_device") or ""))
        or type(proof.get("device_size_bytes")) is not int
        or proof["device_size_bytes"] < expected_offset + expected_count
        or proof.get("offset_bytes") != expected_offset
        or proof.get("byte_count") != expected_count
        or not re.fullmatch(r"[0-9a-f]{64}", checksum)
        or not re.fullmatch(r"[0-9a-f]{64}", preimage)
        or proof.get("mounted") is not False
        or proof.get("signatures") != []
        or type(proof.get("write_performed")) is not bool
    ):
        raise HarnessError("The native-volume block-device witness mismatched.")
    if expected_sha256 is not None and checksum != str(expected_sha256):
        raise HarnessError("The native-volume live byte hash mismatched.")
    if operation in {"inspect", "read"} and (
        proof.get("open_mode") != "read-only"
        or proof.get("write_performed") is not False
        or proof.get("status") != "observed"
    ):
        raise HarnessError("The restored-volume proof was not strictly read-only.")
    if operation == "seed" and (
        proof.get("open_mode") != "read-write"
        or proof.get("status") not in {"seeded", "already-seeded"}
        or (proof.get("status") == "seeded")
        != (proof.get("write_performed") is True)
    ):
        raise HarnessError("The source-volume seed proof is inconsistent.")
    return dict(proof)


def _safe_account(payload: dict) -> dict:
    account = payload.get("account") if isinstance(payload, dict) else None
    team = account.get("team") if isinstance(account, dict) else None
    if not isinstance(account, dict) or not isinstance(team, dict):
        raise HarnessError("DigitalOcean did not return an explicit team context.")
    team_uuid = str(team.get("uuid") or "")
    team_name = str(team.get("name") or "")
    account_uuid = str(account.get("uuid") or "")
    if not team_uuid or not team_name or not account_uuid:
        raise HarnessError("DigitalOcean returned an incomplete account/team identity.")
    if account.get("status") != "active":
        raise HarnessError("The DigitalOcean account is not active.")
    return {
        "account_uuid": account_uuid,
        "team_uuid": team_uuid,
        "team_name": team_name,
        "status": "active",
    }


def require_personal_team(
    account: dict,
    *,
    expected_uuid: str | None,
    expected_name: str,
    mutation: bool,
) -> None:
    if account["team_name"] != expected_name:
        raise HarnessError("The active DigitalOcean team is not the expected Personal team.")
    if mutation and not expected_uuid:
        raise HarnessError("DIGITALOCEAN_E2E_TEAM_UUID is required for provider mutation.")
    if expected_uuid and account["team_uuid"] != expected_uuid:
        raise HarnessError("The active DigitalOcean team UUID does not match the allowlist.")


def _mutation_response(
    method: str,
    path: str,
    *,
    headers: dict,
    body=None,
    required_scope: str | None = None,
):
    try:
        response = requests.request(
            method,
            digitalocean_api_url(path),
            headers=headers,
            json=body,
            verify=True,
            timeout=request_timeout(),
        )
    except requests.exceptions.Timeout as error:
        raise AmbiguousMutation("DigitalOcean mutation timed out; reconcile before retrying.") from error
    except requests.exceptions.RequestException as error:
        raise AmbiguousMutation(
            "DigitalOcean mutation lost its response; reconcile before retrying."
        ) from error
    try:
        status_code = int(response.status_code)
        if not 200 <= status_code < 300:
            if status_code in {401, 403}:
                if required_scope:
                    raise ScopedProviderRejection(required_scope)
                raise HarnessError("DigitalOcean rejected the mutation credentials or permissions.")
            if status_code == 429:
                raise HarnessError("DigitalOcean rate-limited the mutation.")
            if status_code >= 500:
                raise AmbiguousMutation(
                    "DigitalOcean returned a transient mutation response; reconcile before retrying."
                )
            raise HarnessError("DigitalOcean rejected the mutation.")
        if status_code == 204:
            return {}
        payload = response.json()
        if not isinstance(payload, dict):
            raise AmbiguousMutation(
                "DigitalOcean accepted a mutation without a usable resource response."
            )
        return payload
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _iter_provider_collection(
    path: str,
    collection_key: str,
    identity_key: str,
    *,
    headers: dict,
    params: dict | None = None,
) -> list[dict]:
    """Bounded provider-link pagination for collections without an ``id`` field."""

    request_params = dict(params or {})
    request_params.setdefault("per_page", 200)
    next_path = path
    seen_pages: set[str] = set()
    seen_items: set[str] = set()
    expected_total = None
    items: list[dict] = []
    for _page in range(SPACES_MAX_PAGES):
        page_key = f"{next_path}|{sorted(request_params.items())!r}"
        if page_key in seen_pages:
            raise HarnessError("DigitalOcean returned repeated collection pagination.")
        seen_pages.add(page_key)
        payload = get_json(next_path, headers=headers, params=request_params or None)
        request_params = {}
        page_items = payload.get(collection_key)
        if not isinstance(page_items, list) or any(
            not isinstance(item, dict) for item in page_items
        ):
            raise HarnessError("DigitalOcean returned a malformed collection.")
        meta = payload.get("meta") or {}
        links = payload.get("links") or {}
        if not isinstance(meta, dict) or not isinstance(links, dict):
            raise HarnessError("DigitalOcean returned malformed pagination metadata.")
        try:
            total = int(meta["total"]) if "total" in meta else None
        except (TypeError, ValueError):
            raise HarnessError("DigitalOcean returned malformed pagination totals.") from None
        if total is not None and total < 0:
            raise HarnessError("DigitalOcean returned malformed pagination totals.")
        if expected_total is None:
            expected_total = total
        elif total is not None and total != expected_total:
            raise HarnessError("The DigitalOcean collection changed during pagination.")
        for item in page_items:
            identity = str(item.get(identity_key) or "")
            if not identity or identity in seen_items:
                raise HarnessError("DigitalOcean returned duplicate collection identities.")
            seen_items.add(identity)
            items.append(item)
            if len(items) > SPACES_MAX_ITEMS:
                raise HarnessError("The DigitalOcean collection exceeded its safety bound.")
        pages = links.get("pages") or {}
        if not isinstance(pages, dict):
            raise HarnessError("DigitalOcean returned malformed pagination links.")
        provider_next = pages.get("next")
        if provider_next:
            next_path = str(provider_next)
            continue
        if expected_total is not None and len(items) != expected_total:
            raise HarnessError("DigitalOcean returned an incomplete collection.")
        return items
    raise HarnessError("DigitalOcean collection pagination exceeded its page bound.")


def _response_bytes(response, maximum: int) -> bytes:
    chunks = []
    size = 0
    iterator = getattr(response, "iter_content", None)
    if callable(iterator):
        for chunk in iterator(chunk_size=4096):
            if not chunk:
                continue
            size += len(chunk)
            if size > maximum:
                raise HarnessError("The payload probe response exceeded its safety bound.")
            chunks.append(chunk)
        return b"".join(chunks)
    content = getattr(response, "content", b"")
    if not isinstance(content, bytes) or len(content) > maximum:
        raise HarnessError("The payload probe response exceeded its safety bound.")
    return content


def _probe_payload_endpoint(ip_address: str, expectation: dict[str, Any]) -> None:
    base = f"http://{ip_address}:{PAYLOAD_PORT}"
    responses = []
    try:
        for path, maximum in (("/healthz", HEALTH_MAX_BYTES), ("/payload", PAYLOAD_MAX_BYTES)):
            response = requests.get(
                f"{base}{path}",
                timeout=(5, 15),
                allow_redirects=False,
                stream=True,
            )
            responses.append(response)
            if int(response.status_code) != 200:
                raise HarnessError("The deterministic payload endpoint is not ready.")
            body = _response_bytes(response, maximum)
            if path == "/healthz":
                try:
                    health = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    raise HarnessError("The payload health response is malformed.") from None
                if (
                    not isinstance(health, dict)
                    or health.get("ready") is not True
                    or str(health.get("sha256") or "") != expectation["sha256"]
                    or int(health.get("byte_count") or -1)
                    != expectation["byte_count"]
                    or str(health.get("run_marker") or "")
                    != expectation["run_marker"]
                ):
                    raise HarnessError("The payload health witness does not match.")
            elif (
                len(body) != expectation["byte_count"]
                or hashlib.sha256(body).hexdigest() != expectation["sha256"]
            ):
                raise HarnessError("The restored payload hash or byte count does not match.")
    finally:
        for response in responses:
            close = getattr(response, "close", None)
            if callable(close):
                close()


def _spaces_client(credentials: dict[str, str]):
    return boto3.client(
        "s3",
        endpoint_url=credentials["endpoint_url"],
        region_name=credentials["region"],
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"],
        config=Config(
            connect_timeout=5,
            read_timeout=30,
            retries={"max_attempts": 3, "mode": "standard"},
            signature_version="s3v4",
            s3={"addressing_style": "virtual"},
        ),
    )


def _spaces_error_code(error: Exception) -> str:
    if isinstance(
        error,
        (
            ConnectTimeoutError,
            ReadTimeoutError,
            EndpointConnectionError,
            ConnectionClosedError,
        ),
    ):
        return "PROVIDER_TIMEOUT"
    if isinstance(error, ClientError):
        response = error.response if isinstance(error.response, dict) else {}
        details = response.get("Error") if isinstance(response.get("Error"), dict) else {}
        code = str(details.get("Code") or "").casefold()
        metadata = (
            response.get("ResponseMetadata")
            if isinstance(response.get("ResponseMetadata"), dict)
            else {}
        )
        try:
            status = int(metadata.get("HTTPStatusCode") or 0)
        except (TypeError, ValueError):
            status = 0
        if status == 404 or code in {"nosuchbucket", "nosuchkey", "notfound", "404"}:
            return "PROVIDER_NOT_FOUND"
        if status in {401, 403} or code in {
            "accessdenied",
            "invalidaccesskeyid",
            "signaturedoesnotmatch",
            "unauthorized",
        }:
            return "PROVIDER_AUTH_FAILED"
        if status == 429 or code in {"slowdown", "throttling", "toomanyrequests"}:
            return "PROVIDER_RATE_LIMIT"
        if status >= 500:
            return "PROVIDER_TRANSIENT_OUTAGE"
        if code in {"bucketalreadyexists", "bucketalreadyownedbyyou"}:
            return "PROVIDER_OWNERSHIP_MISMATCH"
    return "PROVIDER_REQUEST_FAILED"


def _spaces_call(operation, *, mutation=False, required_scope=None):
    try:
        return operation()
    except Exception as error:
        code = _spaces_error_code(error)
        if code == "PROVIDER_AUTH_FAILED" and required_scope:
            raise ScopedProviderRejection(required_scope) from None
        if code in {
            "PROVIDER_TIMEOUT",
            "PROVIDER_TRANSIENT_OUTAGE",
        } and mutation:
            raise AmbiguousMutation(
                "The Spaces mutation outcome is unknown; reconcile before retrying."
            ) from None
        safe = {
            "PROVIDER_NOT_FOUND": "The exact Spaces resource was not found.",
            "PROVIDER_RATE_LIMIT": "DigitalOcean Spaces rate-limited the request.",
            "PROVIDER_OWNERSHIP_MISMATCH": "The Spaces resource ownership is ambiguous.",
            "PROVIDER_TIMEOUT": "The Spaces request timed out.",
            "PROVIDER_TRANSIENT_OUTAGE": "DigitalOcean Spaces is temporarily unavailable.",
        }.get(code, "DigitalOcean Spaces rejected the request.")
        raise HarnessError(safe) from None


class DigitalOceanHarness:
    def __init__(self, args):
        self.apply = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
        self.cleanup_enabled = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
        self.attach_ui_droplet_firewall = bool(args.attach_ui_droplet_firewall)
        self.volume_verifier_action = str(args.native_volume_verifier_action or "")
        self.expected_team_uuid = str(args.team_uuid or "")
        if self.attach_ui_droplet_firewall:
            if not args.verify_ui_droplet_restore:
                raise HarnessError(
                    "Firewall attachment requires --verify-ui-droplet-restore."
                )
            if os.environ.get("BACKUPSHEEP_E2E_APPLY") != "YES":
                raise HarnessError(
                    "Firewall attachment requires BACKUPSHEEP_E2E_APPLY=YES."
                )
            if os.environ.get("BACKUPSHEEP_E2E_FIREWALL_APPLY") != "YES":
                raise HarnessError(
                    "Firewall attachment requires BACKUPSHEEP_E2E_FIREWALL_APPLY=YES."
                )
            if args.team_name != "Personal":
                raise HarnessError(
                    "Firewall attachment is restricted to the exact Personal team."
                )
            if not self.expected_team_uuid:
                raise HarnessError(
                    "Firewall attachment requires the exact Personal-team UUID allowlist."
                )
        volume_mutation = self.volume_verifier_action in {
            "prepare-source",
            "verify-restored",
            "cleanup",
        }
        if volume_mutation:
            if not self.apply:
                raise HarnessError(
                    "Native-volume verification requires BACKUPSHEEP_E2E_APPLY=YES."
                )
            if os.environ.get(NATIVE_VOLUME_VERIFIER_APPLY_ENV) != "YES":
                raise HarnessError(
                    f"Native-volume verification requires {NATIVE_VOLUME_VERIFIER_APPLY_ENV}=YES."
                )
            if args.team_name != "Personal" or not self.expected_team_uuid:
                raise HarnessError(
                    "Native-volume verification requires the exact Personal-team UUID allowlist."
                )
        if self.volume_verifier_action == "prepare-source" and os.environ.get(
            NATIVE_VOLUME_SEED_APPLY_ENV
        ) != "YES":
            raise HarnessError(
                f"Source-volume seeding requires {NATIVE_VOLUME_SEED_APPLY_ENV}=YES."
            )
        if self.volume_verifier_action == "cleanup" and (
            not self.cleanup_enabled
            or os.environ.get(NATIVE_VOLUME_VERIFIER_CLEANUP_ENV) != "YES"
        ):
            raise HarnessError(
                "Native-volume verifier cleanup requires the exact cleanup confirmation gates."
            )
        token = os.environ.get("DIGITALOCEAN_TOKEN")
        if not token:
            raise HarnessError("DIGITALOCEAN_TOKEN is required in the environment.")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.run_id = require_run_id(args.run_id)
        self.run_tag = self.run_id
        self.spaces_apply = (
            self.apply
            and os.environ.get("BACKUPSHEEP_E2E_SPACES_APPLY") == "YES"
        )
        self.spaces_cleanup_enabled = (
            self.cleanup_enabled
            and os.environ.get("BACKUPSHEEP_E2E_SPACES_CLEANUP") == "YES"
        )
        self.region = str(args.region)
        self.native_volume_offset_bytes, self.native_volume_byte_count = (
            _native_volume_range(
                args.native_volume_offset_bytes,
                args.native_volume_byte_count,
            )
        )
        self.native_volume_verifier_key_dir = _native_volume_key_dir(
            ledger_path=args.ledger,
            requested_path=args.native_volume_verifier_key_dir,
            run_id=self.run_id,
            team_uuid=self.expected_team_uuid,
        )
        self.native_volume_verifier_size = str(
            args.native_volume_verifier_droplet_size
        )
        self.native_volume_verifier_image = str(
            args.native_volume_verifier_droplet_image
        )
        self.source_volume_size_gib = int(args.volume_size_gib)
        self.payload_expectation = _payload_expectation(self.run_id)
        raw_probe_cidrs = list(args.probe_cidr or [])
        env_probe_cidrs = os.environ.get("DIGITALOCEAN_E2E_PROBE_CIDRS")
        if env_probe_cidrs:
            raw_probe_cidrs.append(env_probe_cidrs)
        self.probe_cidrs = (
            _probe_cidrs(raw_probe_cidrs)
            if args.provision_sources
            or args.verify_ui_droplet_restore
            or self.volume_verifier_action in {"prepare-source", "verify-restored"}
            else []
        )
        self.spaces_secret_path = _validate_secret_path(
            Path(
                args.spaces_secret_file
                or _default_spaces_secret_path(self.run_id)
            )
        )
        self.spaces_prefix = _spaces_prefix(
            getattr(args, "spaces_prefix", None)
            or os.environ.get("DIGITALOCEAN_E2E_SPACES_PREFIX")
            or f"ui/{self.run_id}/"
        )
        self.mutation_reconcile_timeout_seconds = MUTATION_RECONCILE_TIMEOUT_SECONDS
        self.mutation_reconcile_interval_seconds = MUTATION_RECONCILE_INTERVAL_SECONDS
        self.account = _safe_account(get_json("/v2/account", headers=self.headers))
        require_personal_team(
            self.account,
            expected_uuid=args.team_uuid,
            expected_name=args.team_name,
            mutation=(
                self.apply
                or self.cleanup_enabled
                or self.spaces_apply
                or self.spaces_cleanup_enabled
                or self.attach_ui_droplet_firewall
                or volume_mutation
            ),
        )
        self.ledger = DurableResourceLedger(
            args.ledger,
            provider="digitalocean",
            run_id=self.run_id,
            scope=self.account["team_uuid"],
        )
        self.intents = DurableMutationIntentStore(
            args.ledger,
            provider="digitalocean",
            run_id=self.run_id,
            scope=self.account["team_uuid"],
        )
        if args.cleanup and not self.probe_cidrs:
            firewalls = self.ledger.entries("payload_firewall")
            if len(firewalls) == 1:
                ledger_cidrs = (firewalls[0].get("ownership") or {}).get(
                    "probe_cidrs"
                )
                if isinstance(ledger_cidrs, list):
                    self.probe_cidrs = _probe_cidrs(ledger_cidrs)
        if self.volume_verifier_action == "cleanup" and not self.probe_cidrs:
            firewalls = self.ledger.entries("native_volume_verifier_firewall")
            if len(firewalls) == 1:
                ledger_cidrs = (firewalls[0].get("ownership") or {}).get(
                    "probe_cidrs"
                )
                if isinstance(ledger_cidrs, list):
                    self.probe_cidrs = _probe_cidrs(ledger_cidrs)

    def summary(self):
        return {
            "provider": "digitalocean",
            "run_id": self.run_id,
            "team": {
                "name": self.account["team_name"],
                "uuid": self.account["team_uuid"],
            },
            "mode": "apply" if self.apply else "read-only",
            "cleanup_enabled": self.cleanup_enabled,
            "spaces_apply_enabled": self.spaces_apply,
            "spaces_cleanup_enabled": self.spaces_cleanup_enabled,
            "firewall_attachment_enabled": self.attach_ui_droplet_firewall,
            "native_volume_verifier_action": self.volume_verifier_action or None,
            "ledger_entries": len(self.ledger.entries()),
        }

    def _resources(self, kind: str) -> list[dict]:
        mapping = {
            "source_droplet": ("/v2/droplets", "droplets"),
            "source_volume": ("/v2/volumes", "volumes"),
            "ui_restore_droplet": ("/v2/droplets", "droplets"),
            "ui_restore_volume": ("/v2/volumes", "volumes"),
            "payload_firewall": ("/v2/firewalls", "firewalls"),
            "native_volume_verifier_droplet": ("/v2/droplets", "droplets"),
            "native_volume_verifier_firewall": ("/v2/firewalls", "firewalls"),
        }
        path, key = mapping[kind]
        return iter_collection(path, key, headers=self.headers)

    def _owned_candidates(self, kind: str, name: str) -> list[dict]:
        return [
            resource
            for resource in self._resources(kind)
            if str(resource.get("name") or "") == name
            and self.run_tag in (resource.get("tags") or [])
        ]

    def _read_resource(self, kind: str, resource_id: str) -> dict | None:
        mapping = {
            "source_droplet": ("droplets", "droplet"),
            "ui_restore_droplet": ("droplets", "droplet"),
            "source_volume": ("volumes", "volume"),
            "ui_restore_volume": ("volumes", "volume"),
            "payload_firewall": ("firewalls", "firewall"),
            "native_volume_verifier_droplet": ("droplets", "droplet"),
            "native_volume_verifier_firewall": ("firewalls", "firewall"),
        }
        if kind not in mapping:
            raise HarnessError("The DigitalOcean resource kind is unsupported.")
        singular, key = mapping[kind]
        try:
            payload = get_json(
                f"/v2/{singular}/{resource_id}", headers=self.headers
            )
        except DigitalOceanAPIError as error:
            if error.code == "PROVIDER_NOT_FOUND":
                return None
            raise
        resource = payload.get(key)
        if not isinstance(resource, dict):
            raise HarnessError("DigitalOcean returned a malformed resource read-back.")
        return resource

    def _verify_owned(self, kind: str, resource: dict, name: str) -> dict:
        resource_id = str(resource.get("id") or "")
        if (
            not resource_id
            or str(resource.get("name") or "") != name
            or self.run_tag not in (resource.get("tags") or [])
        ):
            raise HarnessError("DigitalOcean resource ownership verification failed.")
        return resource

    def _verify_creation_fingerprint(
        self, kind: str, resource: dict, ownership: dict
    ) -> None:
        witness = ownership.get("creation_witness") if isinstance(ownership, dict) else None
        if not isinstance(witness, dict) or not witness.get("immutable_fingerprint"):
            raise HarnessError(
                "The durable DigitalOcean creation fingerprint is missing."
            )
        if not _creation_witness_matches(kind, resource, witness):
            raise HarnessError(
                "The DigitalOcean resource changed after creation; cleanup stopped."
            )

    def _record(self, kind: str, resource: dict, request: dict):
        name = str(resource["name"])
        creation = _creation_witness(kind, resource, request)
        creation["immutable_fingerprint"] = _fingerprint(creation)
        ownership = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "request_fingerprint": _fingerprint(request),
            "creation_witness": creation,
        }
        if kind == "source_droplet":
            ownership.update(
                {
                    "payload_sha256": self.payload_expectation["sha256"],
                    "payload_byte_count": self.payload_expectation["byte_count"],
                }
            )
        elif kind == "native_volume_verifier_droplet":
            key_material = getattr(self, "_native_volume_key_material_cache", None)
            if not isinstance(key_material, dict):
                raise HarnessError(
                    "The native-volume verifier key witness is unavailable."
                )
            ownership.update(
                {
                    "client_fingerprint": key_material["client_fingerprint"],
                    "host_fingerprint": key_material["host_fingerprint"],
                    "key_witness_id": key_material["key_witness_id"],
                    "ready_sha256": hashlib.sha256(
                        _native_volume_ready_bytes(
                            run_id=self.run_id,
                            team_uuid=self.account["team_uuid"],
                            key_material=key_material,
                        )
                    ).hexdigest(),
                }
            )
            provider_created_at = str(resource.get("created_at") or "")
            if not provider_created_at:
                raise HarnessError(
                    "The native-volume verifier Droplet has no provider creation timestamp."
                )
            verifier_creation = {
                "resource_id": str(resource.get("id") or ""),
                "name": name,
                "created_at": provider_created_at,
                "region": _resource_region(resource),
                "size": str(resource.get("size_slug") or resource.get("size") or ""),
                "image": _resource_image(resource),
                "tags": sorted(str(tag) for tag in resource.get("tags") or []),
                "key_witness_id": key_material["key_witness_id"],
                "ready_sha256": ownership["ready_sha256"],
            }
            verifier_creation["immutable_fingerprint"] = _fingerprint(
                verifier_creation
            )
            ownership["verifier_creation_witness"] = verifier_creation
        return self.ledger.record(
            kind=kind,
            resource_id=str(resource["id"]),
            name=name,
            ownership=ownership,
            source_witness=f"{kind}:{name}",
        )

    def _read_run_tag(self) -> dict | None:
        try:
            payload = get_json(
                f"/v2/tags/{quote(self.run_tag, safe='')}", headers=self.headers
            )
        except DigitalOceanAPIError as error:
            if error.code == "PROVIDER_NOT_FOUND":
                return None
            raise
        tag = payload.get("tag")
        if not isinstance(tag, dict) or str(tag.get("name") or "") != self.run_tag:
            raise HarnessError("DigitalOcean returned a malformed run-tag read-back.")
        return tag

    def _record_run_tag(self):
        tag = self._read_run_tag()
        if tag is None:
            raise HarnessError("DigitalOcean did not persist the run ownership tag.")
        self.ledger.record(
            kind="run_tag",
            resource_id=self.run_tag,
            name=self.run_tag,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "request_fingerprint": _fingerprint(
                    {"team_uuid": self.account["team_uuid"], "tag": self.run_tag}
                ),
            },
            source_witness=f"run-tag:{self.run_tag}",
        )

    def ensure_source(self, kind: str, request: dict) -> dict:
        name = str(request["name"])
        fingerprint = _fingerprint(request)
        intent = self.intents.get(kind)
        candidates = self._owned_candidates(kind, name)
        if len(candidates) > 1:
            raise HarnessError("Multiple exact run-owned DigitalOcean sources were found.")
        if candidates:
            resource = self._read_resource(kind, str(candidates[0]["id"]))
            self._verify_owned(kind, resource or {}, name)
            if not _request_creation_matches(kind, resource or {}, request):
                raise HarnessError(
                    "The exact DigitalOcean resource creation fingerprint changed."
                )
            ledger_entry = self.ledger.get(kind, str(resource["id"]))
            intent_matches = bool(
                intent
                and intent.get("request_boundary_crossed")
                and intent.get("name") == name
                and intent.get("request_fingerprint") == fingerprint
            )
            if ledger_entry is None and not intent_matches:
                raise HarnessError(
                    "An exact name/tag match exists without this run's durable create intent."
                )
            if ledger_entry is not None:
                stored_ownership = ledger_entry.get("ownership") or {}
                if stored_ownership.get("request_fingerprint") != fingerprint or not _creation_witness_matches(
                    kind,
                    resource,
                    stored_ownership.get("creation_witness") or {},
                ):
                    raise HarnessError(
                        "The durable DigitalOcean creation fingerprint no longer matches."
                    )
            self._record(kind, resource, request)
            self._record_run_tag()
            if intent_matches:
                self.intents.clear(kind)
            return resource

        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior source-create request has no exact match yet; do not retry it."
            )
        if not self.apply:
            raise HarnessError("Source resources are absent and apply mode is disabled.")

        self.intents.put(
            kind,
            {
                "marker": self.run_tag,
                "kind": kind,
                "name": name,
                "operation": "create",
                "request_fingerprint": fingerprint,
            },
        )
        # Persist before crossing the provider mutation boundary. A crash in the
        # tiny interval before the request is conservatively treated as unknown.
        self.intents.update(kind, request_boundary_crossed=True)
        path, response_key = (
            ("/v2/droplets", "droplet")
            if kind.endswith("droplet")
            else ("/v2/volumes", "volume")
        )
        try:
            payload = _mutation_response(
                "POST", path, headers=self.headers, body=request
            )
        except AmbiguousMutation:
            # Preserve the intent across lost/unknown responses so a replay
            # may only adopt the one exact name-and-tag match.
            raise
        except HarnessError:
            # Definite provider rejection means no create was accepted.  Do
            # not strand the run behind an unresolvable mutation intent.
            self.intents.clear(kind)
            raise
        created = payload.get(response_key)
        resource_id = str(created.get("id") or "") if isinstance(created, dict) else ""
        if not resource_id:
            raise AmbiguousMutation("DigitalOcean did not return the created resource ID.")
        resource = self._read_resource(kind, resource_id)
        self._verify_owned(kind, resource or {}, name)
        self._record(kind, resource, request)
        self._record_run_tag()
        self.intents.clear(kind)
        return resource

    def wait_droplet_active(
        self, resource_id: str, *, kind="source_droplet", timeout_seconds=900
    ):
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            droplet = self._read_resource(kind, resource_id)
            if droplet is None:
                raise HarnessError("The run-owned Droplet disappeared.")
            status = str(droplet.get("status") or "")
            if status == "active":
                return droplet
            if status not in {"new", "off", "active"}:
                raise HarnessError("The run-owned Droplet entered an unexpected state.")
            time.sleep(10)
        raise HarnessError("The run-owned Droplet did not become active before timeout.")

    def wait_absent(self, kind: str, resource_id: str, timeout_seconds=300):
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._read_resource(kind, resource_id) is None:
                return
            time.sleep(5)
        raise AmbiguousMutation(
            "DigitalOcean accepted cleanup but the resource is still visible."
        )

    def wait_tag_absent(self, timeout_seconds=300):
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._read_run_tag() is None:
                return
            time.sleep(5)
        raise AmbiguousMutation(
            "DigitalOcean accepted tag cleanup but the tag is still visible."
        )

    def _require_native_volume_gate(self, *, source_write: bool = False) -> None:
        if (
            not getattr(self, "apply", False)
            or os.environ.get(NATIVE_VOLUME_VERIFIER_APPLY_ENV) != "YES"
            or not getattr(self, "expected_team_uuid", "")
            or str((getattr(self, "account", {}) or {}).get("team_uuid") or "")
            != self.expected_team_uuid
            or str((getattr(self, "account", {}) or {}).get("team_name") or "")
            != "Personal"
        ):
            raise HarnessError(
                "Native-volume verification is outside the exact apply and Personal-team gates."
            )
        if source_write and os.environ.get(NATIVE_VOLUME_SEED_APPLY_ENV) != "YES":
            raise HarnessError(
                "Native-volume source seeding lacks its dedicated destructive confirmation."
            )

    def _ensure_native_volume_key_witness(self) -> dict[str, Any]:
        self._require_native_volume_gate()
        key_material = _ensure_native_volume_key_material(
            self.native_volume_verifier_key_dir,
            run_id=self.run_id,
            team_uuid=self.account["team_uuid"],
        )
        key_witness = {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "client_public_key_sha256": hashlib.sha256(
                key_material["client_public_key"].encode("ascii")
            ).hexdigest(),
            "client_fingerprint": key_material["client_fingerprint"],
            "host_public_key_sha256": hashlib.sha256(
                key_material["host_public_key"].encode("ascii")
            ).hexdigest(),
            "host_fingerprint": key_material["host_fingerprint"],
            "key_directory_name": self.native_volume_verifier_key_dir.name,
        }
        key_witness_id = _fingerprint(key_witness)
        key_material["key_witness_id"] = key_witness_id
        key_witness["immutable_fingerprint"] = key_witness_id
        self.ledger.record(
            kind="native_volume_verifier_key_witness",
            resource_id=key_witness_id,
            name=self.native_volume_verifier_key_dir.name,
            ownership=key_witness,
            source_witness=f"native-volume-verifier-keys:{key_witness_id}",
        )
        self._native_volume_key_material_cache = key_material
        return key_material

    def ensure_native_volume_verifier_droplet(self) -> tuple[dict, dict[str, Any]]:
        self._require_native_volume_gate()
        if not self.probe_cidrs:
            raise HarnessError("Native-volume verifier SSH requires exact probe CIDRs.")
        verifier_name = _resource_name(self.run_id, "volume-verifier")
        named = [
            resource
            for resource in self._resources("native_volume_verifier_droplet")
            if str(resource.get("name") or "") == verifier_name
        ]
        if len(named) > 1:
            raise HarnessError("Multiple native-volume verifier Droplets share the exact name.")
        if named and self.run_tag not in (named[0].get("tags") or []):
            raise HarnessError(
                "The native-volume verifier name is occupied without this run marker."
            )
        key_material = self._ensure_native_volume_key_witness()
        request = {
            "name": verifier_name,
            "region": self.region,
            "size": self.native_volume_verifier_size,
            "image": self.native_volume_verifier_image,
            "tags": [self.run_tag, "backupsheep-native-volume-verifier"],
            "backups": False,
            "ipv6": False,
            "monitoring": False,
            "user_data": _native_volume_verifier_cloud_init(
                run_id=self.run_id,
                team_uuid=self.account["team_uuid"],
                key_material=key_material,
            ),
        }
        droplet = self.ensure_source("native_volume_verifier_droplet", request)
        droplet = self.wait_droplet_active(
            str(droplet["id"]), kind="native_volume_verifier_droplet"
        )
        entry = self.ledger.get(
            "native_volume_verifier_droplet", str(droplet["id"])
        )
        ownership = entry.get("ownership") if isinstance(entry, dict) else None
        if (
            not isinstance(ownership, dict)
            or ownership.get("team_uuid") != self.account["team_uuid"]
            or ownership.get("run_tag") != self.run_tag
            or ownership.get("client_fingerprint")
            != key_material["client_fingerprint"]
            or ownership.get("host_fingerprint") != key_material["host_fingerprint"]
            or ownership.get("key_witness_id") != key_material["key_witness_id"]
        ):
            raise HarnessError("The native-volume verifier Droplet key witness changed.")
        verifier_creation = ownership.get("verifier_creation_witness")
        expected_creation = {
            "resource_id": str(droplet.get("id") or ""),
            "name": verifier_name,
            "created_at": str(droplet.get("created_at") or ""),
            "region": _resource_region(droplet),
            "size": str(droplet.get("size_slug") or droplet.get("size") or ""),
            "image": _resource_image(droplet),
            "tags": sorted(str(tag) for tag in droplet.get("tags") or []),
            "key_witness_id": key_material["key_witness_id"],
            "ready_sha256": ownership.get("ready_sha256"),
        }
        expected_creation["immutable_fingerprint"] = _fingerprint(expected_creation)
        if verifier_creation != expected_creation:
            raise HarnessError(
                "The native-volume verifier provider creation witness changed."
            )
        self._verify_creation_fingerprint(
            "native_volume_verifier_droplet", droplet, ownership
        )
        _public_ipv4(droplet)
        return droplet, key_material

    @staticmethod
    def _native_volume_verifier_droplet_view(resource: dict) -> dict[str, Any]:
        """Return the immutable/current fields used for a mutation preflight.

        The collection response and the direct resource response are separate
        ownership witnesses.  Keeping this view deliberately small avoids
        comparing provider fields that are allowed to change asynchronously,
        while still binding every field that can redirect a verifier action.
        """

        if not isinstance(resource, dict):
            raise HarnessError("DigitalOcean returned a malformed verifier Droplet.")
        tags = resource.get("tags")
        if not isinstance(tags, list) or any(
            not isinstance(tag, str) or not tag for tag in tags
        ):
            raise HarnessError("The verifier Droplet tags are malformed.")
        created_at = str(resource.get("created_at") or "")
        status = str(resource.get("status") or "")
        if not created_at or not status:
            raise HarnessError("The verifier Droplet lifecycle witness is incomplete.")
        return {
            "id": str(resource.get("id") or ""),
            "name": str(resource.get("name") or ""),
            "tags": sorted(tags),
            "region": _resource_region(resource),
            "size": str(resource.get("size_slug") or resource.get("size") or ""),
            "image": _resource_image(resource),
            "created_at": created_at,
            "status": status,
        }

    def _fresh_owned_verifier_droplet_for_mutation(
        self, droplet_id: str, *, expected_region: str | None = None
    ) -> tuple[dict, str]:
        """Freshly fence the exact verifier Droplet before a provider POST.

        This helper is intentionally shared by the firewall and volume-action
        paths.  A caller-supplied numeric ID is never sufficient: the complete
        inventory, direct-ID read, durable ledger row, Personal-team scope,
        run tags, creation witness, key witness, region, and active lifecycle
        state must all agree in the same preflight.
        """

        self._require_native_volume_gate()
        verifier_id = str(droplet_id or "")
        if not re.fullmatch(r"[1-9][0-9]*", verifier_id):
            raise HarnessError("The verifier Droplet ID must be one exact positive integer.")
        account = getattr(self, "account", {}) or {}
        if (
            str(account.get("team_name") or "") != "Personal"
            or str(account.get("team_uuid") or "") != str(self.expected_team_uuid or "")
            or not self.expected_team_uuid
        ):
            raise HarnessError("The verifier Droplet is outside the Personal-team scope.")

        inventory = self._resources("native_volume_verifier_droplet")
        exact_inventory = [
            row for row in inventory if str(row.get("id") or "") == verifier_id
        ]
        if len(exact_inventory) != 1:
            raise HarnessError(
                "The verifier Droplet inventory has zero or duplicate exact matches."
            )
        inventory_view = self._native_volume_verifier_droplet_view(exact_inventory[0])
        verifier_name = inventory_view["name"]
        if not verifier_name:
            raise HarnessError("The verifier Droplet has no exact durable name.")
        named_inventory = [
            row for row in inventory if str(row.get("name") or "") == verifier_name
        ]
        if len(named_inventory) != 1:
            raise HarnessError(
                "The verifier Droplet inventory has zero or duplicate name matches."
            )

        direct = self._read_resource(
            "native_volume_verifier_droplet", verifier_id
        )
        if direct is None:
            raise HarnessError("The exact verifier Droplet direct read is missing.")
        direct_view = self._native_volume_verifier_droplet_view(direct)
        if inventory_view != direct_view:
            raise HarnessError(
                "The verifier Droplet inventory and direct read disagree."
            )
        if direct_view["status"] != "active":
            raise HarnessError("The verifier Droplet is not active for a provider action.")
        if direct_view["region"] != str(self.region):
            raise HarnessError("The verifier Droplet region mismatched the run scope.")
        if expected_region is not None and direct_view["region"] != str(expected_region):
            raise HarnessError("The verifier Droplet region mismatched the volume action.")
        required_tags = {self.run_tag, "backupsheep-native-volume-verifier"}
        if not required_tags.issubset(set(direct_view["tags"])):
            raise HarnessError("The verifier Droplet run ownership tags are incomplete.")

        entry = self.ledger.get("native_volume_verifier_droplet", verifier_id)
        if not isinstance(entry, dict) or str(entry.get("resource_id") or "") != verifier_id:
            raise HarnessError("The verifier Droplet has no exact durable ledger row.")
        if entry.get("cleanup_state") not in {"eligible", "failed"}:
            raise HarnessError("The verifier Droplet ledger row is not active evidence.")
        ownership = entry.get("ownership")
        if (
            not isinstance(ownership, dict)
            or ownership.get("team_uuid") != self.account["team_uuid"]
            or ownership.get("run_tag") != self.run_tag
            or ownership.get("key_witness_id") in (None, "")
        ):
            raise HarnessError("The verifier Droplet durable ownership witness mismatched.")
        self._verify_owned("native_volume_verifier_droplet", direct, verifier_name)
        self._verify_creation_fingerprint(
            "native_volume_verifier_droplet", direct, ownership
        )

        key_witness_id = str(ownership.get("key_witness_id") or "")
        key_entry = self.ledger.get("native_volume_verifier_key_witness", key_witness_id)
        key_ownership = key_entry.get("ownership") if isinstance(key_entry, dict) else None
        if (
            not isinstance(key_entry, dict)
            or str(key_entry.get("resource_id") or "") != key_witness_id
            or key_entry.get("cleanup_state") not in {"eligible", "failed"}
            or not isinstance(key_ownership, dict)
            or key_ownership.get("team_uuid") != self.account["team_uuid"]
            or key_ownership.get("run_tag") != self.run_tag
            or key_ownership.get("immutable_fingerprint") != key_witness_id
            or ownership.get("client_fingerprint")
            != key_ownership.get("client_fingerprint")
            or ownership.get("host_fingerprint")
            != key_ownership.get("host_fingerprint")
        ):
            raise HarnessError("The verifier Droplet key witness mismatched.")

        verifier_creation = ownership.get("verifier_creation_witness")
        expected_creation = {
            "resource_id": verifier_id,
            "name": verifier_name,
            "created_at": direct_view["created_at"],
            "region": direct_view["region"],
            "size": direct_view["size"],
            "image": direct_view["image"],
            "tags": direct_view["tags"],
            "key_witness_id": key_witness_id,
            "ready_sha256": ownership.get("ready_sha256"),
        }
        expected_creation["immutable_fingerprint"] = _fingerprint(expected_creation)
        if verifier_creation != expected_creation:
            raise HarnessError("The verifier Droplet creation witness mismatched.")

        mutation_witness = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "droplet": direct_view,
            "creation_fingerprint": (
                (ownership.get("creation_witness") or {}).get("immutable_fingerprint")
            ),
            "verifier_creation_fingerprint": verifier_creation.get(
                "immutable_fingerprint"
            ),
            "key_witness_id": key_witness_id,
            "key_fingerprint": key_ownership.get("immutable_fingerprint"),
        }
        return direct, _fingerprint(mutation_witness)

    def _native_volume_guest_request(
        self,
        *,
        operation: str,
        droplet: dict,
        key_material: dict[str, Any],
        volume: dict | None = None,
        expected_sha256: str | None = None,
        expected_preimage_sha256: str | None = None,
    ) -> dict[str, Any]:
        request = {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "operation": operation,
            "run_id": self.run_id,
            "team_uuid": self.account["team_uuid"],
            "droplet_id": str(droplet.get("id") or ""),
            "region": self.region,
            "ready_sha256": hashlib.sha256(
                _native_volume_ready_bytes(
                    run_id=self.run_id,
                    team_uuid=self.account["team_uuid"],
                    key_material=key_material,
                )
            ).hexdigest(),
            "volume_id": "",
            "volume_name": "",
            "offset_bytes": 0,
            "byte_count": 0,
            "expected_sha256": expected_sha256 or "",
            "expected_preimage_sha256": expected_preimage_sha256 or "",
        }
        if operation != "identity":
            if not isinstance(volume, dict):
                raise HarnessError("The native-volume guest request has no exact volume.")
            request.update(
                {
                    "volume_id": str(volume.get("id") or ""),
                    "volume_name": str(volume.get("name") or ""),
                    "offset_bytes": self.native_volume_offset_bytes,
                    "byte_count": self.native_volume_byte_count,
                }
            )
            _native_volume_device_path(request["volume_name"])
        return request

    def _run_native_volume_guest(
        self,
        *,
        operation: str,
        droplet: dict,
        key_material: dict[str, Any],
        volume: dict | None = None,
        expected_sha256: str | None = None,
        expected_preimage_sha256: str | None = None,
        fixture_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        self._require_native_volume_gate(source_write=operation == "seed")
        ip_address = _public_ipv4(droplet)
        request = self._native_volume_guest_request(
            operation=operation,
            droplet=droplet,
            key_material=key_material,
            volume=volume,
            expected_sha256=expected_sha256,
            expected_preimage_sha256=expected_preimage_sha256,
        )
        program = base64.b64encode(
            NATIVE_VOLUME_GUEST_PROGRAM.encode("utf-8")
        ).decode("ascii")
        request_payload = base64.b64encode(
            json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
                "ascii"
            )
        ).decode("ascii")
        bootstrap = (
            "import base64;exec(compile(base64.b64decode('"
            + program
            + "'),'<backupsheep-native-volume>','exec'))"
        )
        remote_command = (
            "python3 -c "
            + shlex.quote(bootstrap)
            + " "
            + shlex.quote(request_payload)
        )
        result = _secret_safe_subprocess(
            [
                "ssh",
                "-T",
                "-i",
                str(key_material["client_private_path"]),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={key_material['known_hosts_path']}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "HostKeyAlgorithms=ssh-ed25519",
                "-o",
                "PubkeyAcceptedAlgorithms=ssh-ed25519",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "LogLevel=ERROR",
                f"root@{ip_address}",
                remote_command,
            ],
            input_bytes=fixture_bytes,
            timeout_seconds=180,
        )
        if len(result.stdout) > 64 * 1024:
            raise HarnessError("The native-volume guest proof exceeded its bound.")
        proof = _strict_json_loads(
            result.stdout, label="native-volume guest proof"
        )
        return _validate_native_volume_guest_proof(
            proof,
            operation=operation,
            run_id=self.run_id,
            team_uuid=self.account["team_uuid"],
            verifier_droplet_id=str(droplet.get("id") or ""),
            region=self.region,
            volume_id=(str(volume.get("id") or "") if volume else None),
            volume_name=(str(volume.get("name") or "") if volume else None),
            offset_bytes=(self.native_volume_offset_bytes if volume else None),
            byte_count=(self.native_volume_byte_count if volume else None),
            expected_sha256=expected_sha256,
        )

    def wait_native_volume_verifier_ready(
        self,
        droplet: dict,
        key_material: dict[str, Any],
        *,
        timeout_seconds: int = 600,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_error = None
        while time.monotonic() < deadline:
            try:
                return self._run_native_volume_guest(
                    operation="identity",
                    droplet=droplet,
                    key_material=key_material,
                )
            except HarnessError as error:
                last_error = error
                time.sleep(5)
        raise HarnessError(
            "The native-volume verifier did not present its pinned identity in time."
        ) from last_error

    @staticmethod
    def _normalize_native_volume_firewall(resource: dict) -> dict:
        normalized = dict(resource or {})
        normalized["outbound_rules"] = [
            {**rule, "sources": rule.get("destinations")}
            for rule in normalized.get("outbound_rules") or []
            if isinstance(rule, dict)
        ]
        return normalized

    def _native_volume_firewall_owned(
        self,
        resource: dict,
        *,
        droplet_id: str,
        firewall_id: str | None = None,
        require_ready: bool = False,
    ) -> bool:
        if not isinstance(resource, dict):
            return False
        if firewall_id is not None and str(resource.get("id") or "") != str(
            firewall_id
        ):
            return False
        if str(resource.get("name") or "") != _resource_name(
            self.run_id, "volume-verifier-firewall"
        ):
            return False
        if [str(value) for value in (resource.get("droplet_ids") or [])] != [
            str(droplet_id)
        ]:
            return False
        pending = resource.get("pending_changes") or []
        if not isinstance(pending, list) or any(
            not isinstance(change, dict)
            or str(change.get("droplet_id") or "") != str(droplet_id)
            or change.get("removing") is not False
            or str(change.get("status") or "") not in {"waiting", "succeeded"}
            for change in pending
        ):
            return False
        if require_ready and (
            str(resource.get("status") or "") != "succeeded" or pending
        ):
            return False
        normalized = self._normalize_native_volume_firewall(resource)
        expected = {
            "name": _resource_name(self.run_id, "volume-verifier-firewall"),
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "22",
                    "sources": {"addresses": list(self.probe_cidrs)},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "80",
                    "destinations": {"addresses": ["169.254.169.254/32"]},
                }
            ],
            "droplet_ids": [int(droplet_id)],
        }
        return self._firewall_immutable_fingerprint(
            normalized
        ) == self._firewall_immutable_fingerprint(expected)

    def _record_native_volume_verifier_firewall(
        self, resource: dict, request: dict, *, droplet_id: str
    ) -> dict:
        resource_id = str(resource.get("id") or "")
        created_at = str(resource.get("created_at") or "")
        immutable_fingerprint = self._firewall_immutable_fingerprint(request)
        if not resource_id or not created_at:
            raise HarnessError(
                "The native-volume verifier firewall creation witness is incomplete."
            )
        creation = {
            "name": request["name"],
            "created_at": created_at,
            "rules_fingerprint": immutable_fingerprint,
            "verifier_droplet_id": str(droplet_id),
        }
        creation["immutable_fingerprint"] = _fingerprint(creation)
        return self.ledger.record(
            kind="native_volume_verifier_firewall",
            resource_id=resource_id,
            name=request["name"],
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "verifier_droplet_id": str(droplet_id),
                "probe_cidrs": list(self.probe_cidrs),
                "request_fingerprint": _fingerprint(request),
                "immutable_fingerprint": immutable_fingerprint,
                "creation_witness": creation,
            },
            source_witness=f"native-volume-verifier-firewall:{resource_id}",
        )

    def ensure_native_volume_verifier_firewall(self, droplet_id: str) -> dict:
        self._require_native_volume_gate()
        if not self.probe_cidrs:
            raise HarnessError("Native-volume verifier SSH requires exact probe CIDRs.")
        if not re.fullmatch(r"[1-9][0-9]*", str(droplet_id or "")):
            raise HarnessError("The verifier Droplet ID must be one exact positive integer.")
        request = {
            "name": _resource_name(self.run_id, "volume-verifier-firewall"),
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "22",
                    "sources": {"addresses": list(self.probe_cidrs)},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "80",
                    "destinations": {"addresses": ["169.254.169.254/32"]},
                }
            ],
            "droplet_ids": [int(droplet_id)],
        }
        kind = "native_volume_verifier_firewall"
        fingerprint = _fingerprint(request)
        immutable_fingerprint = self._firewall_immutable_fingerprint(request)
        intent = self.intents.get(kind)
        candidates = [
            resource
            for resource in self._resources(kind)
            if str(resource.get("name") or "") == request["name"]
        ]
        if len(candidates) > 1:
            raise HarnessError("Multiple native-volume verifier firewalls were found.")
        if candidates:
            resource_id = str(candidates[0].get("id") or "")
            resource = self._read_resource(kind, resource_id)
            if not self._native_volume_firewall_owned(
                resource or {}, droplet_id=droplet_id, firewall_id=resource_id
            ):
                raise HarnessError(
                    "The native-volume verifier firewall ownership mismatched."
                )
            entry = self.ledger.get(kind, resource_id)
            intent_matches = bool(
                intent
                and intent.get("request_boundary_crossed") is True
                and intent.get("name") == request["name"]
                and intent.get("request_fingerprint") == fingerprint
                and self._firewall_intent_is_bounded(
                    intent, fingerprint=immutable_fingerprint
                )
            )
            if entry is None and not intent_matches:
                raise HarnessError(
                    "An unledgered firewall matches the native-volume verifier name."
                )
            if entry is not None:
                ownership = entry.get("ownership") or {}
                creation = ownership.get("creation_witness")
                if (
                    ownership.get("team_uuid") != self.account["team_uuid"]
                    or ownership.get("run_tag") != self.run_tag
                    or ownership.get("verifier_droplet_id") != str(droplet_id)
                    or ownership.get("request_fingerprint") != fingerprint
                    or ownership.get("immutable_fingerprint")
                    != immutable_fingerprint
                    or not isinstance(creation, dict)
                    or creation.get("created_at")
                    != str(resource.get("created_at") or "")
                    or creation.get("rules_fingerprint")
                    != immutable_fingerprint
                    or creation.get("immutable_fingerprint")
                    != _fingerprint(
                        {
                            "name": request["name"],
                            "created_at": str(resource.get("created_at") or ""),
                            "rules_fingerprint": immutable_fingerprint,
                            "verifier_droplet_id": str(droplet_id),
                        }
                    )
                ):
                    raise HarnessError(
                        "The native-volume firewall durable witness changed."
                    )
            self._record_native_volume_verifier_firewall(
                resource, request, droplet_id=droplet_id
            )
            if intent_matches:
                self.intents.clear(kind)
        else:
            intent_state = self._intent_mutation_state(intent) if intent else ""
            if intent and (
                intent.get("intent_schema") != MUTATION_INTENT_SCHEMA
                or intent.get("marker") != self.run_tag
                or intent.get("kind") != kind
                or intent.get("name") != request["name"]
                or intent.get("operation") != "create"
                or intent.get("request_fingerprint") != fingerprint
                or intent.get("immutable_fingerprint") != immutable_fingerprint
            ):
                raise HarnessError("The native-volume firewall intent drifted.")
            if intent and intent_state in {"submitted", "accepted"}:
                raise AmbiguousMutation(
                    "A prior native-volume firewall create has no exact match; no replay was issued."
                )
            if intent and intent_state not in {"planned", "preflight", ""}:
                raise HarnessError("The native-volume firewall intent is not retryable.")
            _verifier, verifier_fingerprint = (
                self._fresh_owned_verifier_droplet_for_mutation(droplet_id)
            )
            if intent and intent.get("verifier_droplet_fingerprint") not in (
                None,
                verifier_fingerprint,
            ):
                raise HarnessError("The native-volume firewall verifier witness changed.")
            self.intents.put(
                kind,
                {
                    "marker": self.run_tag,
                    "kind": kind,
                    "name": request["name"],
                    "operation": "create",
                    "request_fingerprint": fingerprint,
                    "immutable_fingerprint": immutable_fingerprint,
                    "intent_schema": MUTATION_INTENT_SCHEMA,
                    "created_at": time.time(),
                    "preflight_absent": True,
                    "preflight_candidate_count": 0,
                    "state": "planned",
                    "mutation_state": "planned",
                    "preflight_state": "planned",
                    "request_boundary_crossed": False,
                    "outcome_unknown": False,
                    "verifier_droplet_fingerprint": verifier_fingerprint,
                },
            )
            # The verifier ownership read above is the final preflight.  Do
            # not cross the request boundary until the provider call is next.
            self._mark_intent_submitted(
                kind,
                verifier_droplet_fingerprint=verifier_fingerprint,
            )
            try:
                payload = _mutation_response(
                    "POST", "/v2/firewalls", headers=self.headers, body=request
                )
            except AmbiguousMutation:
                raise
            except HarnessError:
                self.intents.clear(kind)
                raise
            created = payload.get("firewall") if isinstance(payload, dict) else None
            resource_id = (
                str(created.get("id") or "") if isinstance(created, dict) else ""
            )
            if not resource_id:
                raise AmbiguousMutation(
                    "DigitalOcean did not return the native-volume firewall ID."
                )
            resource = self._read_resource(kind, resource_id)
            if not self._native_volume_firewall_owned(
                resource or {}, droplet_id=droplet_id, firewall_id=resource_id
            ):
                raise HarnessError(
                    "The native-volume verifier firewall read-back mismatched."
                )
            self._record_native_volume_verifier_firewall(
                resource, request, droplet_id=droplet_id
            )
            self.intents.clear(kind)
        resource_id = str(resource.get("id") or "")
        if not self._poll_mutation_state(
            read_back=lambda: self._read_resource(kind, resource_id),
            verify_present=lambda current: (
                None
                if self._native_volume_firewall_owned(
                    current,
                    droplet_id=droplet_id,
                    firewall_id=resource_id,
                )
                else (_ for _ in ()).throw(
                    HarnessError(
                        "The native-volume verifier firewall changed while applying."
                    )
                )
            ),
            complete=lambda current: self._native_volume_firewall_owned(
                current or {},
                droplet_id=droplet_id,
                firewall_id=resource_id,
                require_ready=True,
            ),
            label=f"native-volume-firewall:{resource_id}",
        ):
            raise AmbiguousMutation(
                "The native-volume verifier firewall did not become ready in time."
            )
        return self._read_resource(kind, resource_id) or {}

    @staticmethod
    def _native_volume_attachment_ids(resource: dict) -> list[str]:
        values = resource.get("droplet_ids") if isinstance(resource, dict) else None
        if not isinstance(values, list):
            raise HarnessError("DigitalOcean returned malformed volume attachments.")
        normalized = []
        for value in values:
            if isinstance(value, bool) or value in (None, ""):
                raise HarnessError("DigitalOcean returned malformed volume attachments.")
            normalized.append(str(value))
        if len(normalized) != len(set(normalized)) or len(normalized) > 1:
            raise HarnessError("DigitalOcean returned ambiguous volume attachments.")
        return normalized

    @staticmethod
    def _native_volume_provider_view(resource: dict) -> dict[str, Any]:
        if not isinstance(resource, dict):
            raise HarnessError("DigitalOcean returned a malformed volume witness.")
        return {
            "id": str(resource.get("id") or ""),
            "name": str(resource.get("name") or ""),
            "tags": sorted(
                str(tag)
                for tag in (resource.get("tags") or [])
                if isinstance(tag, str)
            ),
            "region": _resource_region(resource),
            "size_gigabytes": _positive_integer(resource.get("size_gigabytes")),
            "droplet_ids": DigitalOceanHarness._native_volume_attachment_ids(
                resource
            ),
            "snapshot_sources": sorted(_restore_source_values(resource, "volume")),
        }

    def _read_exact_native_volume(
        self,
        *,
        kind: str,
        volume_id: str,
        name: str,
        region: str,
        size_gigabytes: int,
        allowed_attachment_ids: set[str],
        restore_witness: dict | None = None,
    ) -> dict:
        inventory = self._resources(kind)
        normalized_allowed_ids = {str(value) for value in allowed_attachment_ids}
        if len(normalized_allowed_ids) > 1 or any(
            not re.fullmatch(r"[1-9][0-9]*", value)
            for value in normalized_allowed_ids
        ):
            raise HarnessError("The verifier attachment allowlist is malformed.")
        id_matches = [
            resource
            for resource in inventory
            if str(resource.get("id") or "") == str(volume_id)
        ]
        name_matches = [
            resource
            for resource in inventory
            if str(resource.get("name") or "") == str(name)
        ]
        for resource in inventory:
            resource_id = str(resource.get("id") or "")
            attachment_ids = self._native_volume_attachment_ids(resource)
            if resource_id != str(volume_id) and normalized_allowed_ids.intersection(
                attachment_ids
            ):
                raise HarnessError(
                    "The verifier Droplet has a foreign volume attachment."
                )
        if (
            len(id_matches) != 1
            or len(name_matches) != 1
            or str(name_matches[0].get("id") or "") != str(volume_id)
        ):
            raise HarnessError(
                "The complete volume inventory has zero or duplicate exact matches."
            )
        direct = self._read_resource(kind, str(volume_id))
        if direct is None:
            raise HarnessError("The exact native-volume verifier target is missing.")
        inventory_view = self._native_volume_provider_view(id_matches[0])
        direct_view = self._native_volume_provider_view(direct)
        if inventory_view != direct_view:
            raise HarnessError("The volume inventory and exact-ID read-back disagree.")
        expected_size = _positive_integer(size_gigabytes)
        if (
            direct_view["id"] != str(volume_id)
            or direct_view["name"] != str(name)
            or direct_view["region"] != str(region)
            or expected_size is None
            or direct_view["size_gigabytes"] != expected_size
            or not set(direct_view["droplet_ids"]).issubset(normalized_allowed_ids)
        ):
            raise HarnessError(
                "The exact volume identity, size, region, or attachment witness mismatched."
            )
        if kind == "source_volume":
            entry = self.ledger.get(kind, str(volume_id))
            ownership = entry.get("ownership") if isinstance(entry, dict) else None
            if (
                not isinstance(entry, dict)
                or entry.get("cleanup_state") not in {"eligible", "failed"}
                or not isinstance(ownership, dict)
                or ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
            ):
                raise HarnessError("The source volume is not exact active owned evidence.")
            self._verify_owned(kind, direct, str(name))
            self._verify_creation_fingerprint(kind, direct, ownership)
        elif kind == "ui_restore_volume":
            if not isinstance(restore_witness, dict):
                raise HarnessError("The restored volume has no exact UI witness.")
            detached_view = dict(direct)
            detached_view["droplet_ids"] = []
            if not _restore_target_owned(detached_view, restore_witness):
                raise HarnessError("The restored volume ownership witness mismatched.")
        else:
            raise HarnessError("The native-volume verifier target kind is invalid.")
        return direct

    def _transition_native_volume_attachment(
        self,
        *,
        kind: str,
        volume_id: str,
        volume_name: str,
        verifier_droplet_id: str,
        region: str,
        size_gigabytes: int,
        attach: bool,
        restore_witness: dict | None = None,
    ) -> dict[str, Any]:
        self._require_native_volume_gate()
        if not re.fullmatch(r"[1-9][0-9]*", str(verifier_droplet_id or "")):
            raise HarnessError("The verifier Droplet ID must be one exact positive integer.")
        desired_ids = [str(verifier_droplet_id)] if attach else []

        def read_back():
            return self._read_exact_native_volume(
                kind=kind,
                volume_id=volume_id,
                name=volume_name,
                region=region,
                size_gigabytes=size_gigabytes,
                allowed_attachment_ids={str(verifier_droplet_id)},
                restore_witness=restore_witness,
            )

        operation = "attach" if attach else "detach"
        request = {
            "type": operation,
            "droplet_id": int(verifier_droplet_id),
            "region": str(region),
            "volume_id": str(volume_id),
        }
        intent_key = (
            f"native-volume:{operation}:{volume_id}:{verifier_droplet_id}"
        )
        fingerprint = _fingerprint(request)
        intent, _ = self._prepare_mutation_intent(
            intent_key,
            kind="native_volume_attachment",
            name=f"{volume_id}:{verifier_droplet_id}",
            operation=operation,
            request=request,
        )
        current = read_back()
        current_ids = self._native_volume_attachment_ids(current)
        if current_ids == desired_ids:
            if intent:
                self.intents.clear(intent_key)
            return {
                "operation": operation,
                "volume_id": str(volume_id),
                "verifier_droplet_id": str(verifier_droplet_id),
                "droplet_ids": desired_ids,
                "region": str(region),
                "observed_at": _utc_now(),
                "action_id": str((intent or {}).get("action_id") or ""),
                "reconciled": bool(intent),
            }
        state = self._intent_mutation_state(intent) if intent is not None else ""
        if intent is not None and state in {"submitted", "accepted"}:
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=lambda resource: self._native_volume_attachment_ids(
                    resource
                ),
                complete=lambda resource: self._native_volume_attachment_ids(
                    resource
                )
                == desired_ids,
                label=f"native-volume-{operation}:{volume_id}",
            ):
                self.intents.clear(intent_key)
                return {
                    "operation": operation,
                    "volume_id": str(volume_id),
                    "verifier_droplet_id": str(verifier_droplet_id),
                    "droplet_ids": desired_ids,
                    "region": str(region),
                    "observed_at": _utc_now(),
                    "action_id": str(intent.get("action_id") or ""),
                    "reconciled": True,
                }
            raise AmbiguousMutation(
                f"The exact volume {operation} remains uncertain; no action replay was issued."
            )
        if intent is not None and state not in {"planned", "preflight", ""}:
            raise HarnessError("The native-volume attachment intent is not retryable.")
        # This is the last exact volume read before the action.  The verifier
        # Droplet is independently re-read and its immutable/key witness is
        # bound into the intent before the request boundary is crossed.
        _verifier, verifier_fingerprint = self._fresh_owned_verifier_droplet_for_mutation(
            verifier_droplet_id, expected_region=region
        )
        self._bind_mutation_intent_witness(
            intent_key,
            field="verifier_droplet_fingerprint",
            value=verifier_fingerprint,
        )
        self._mark_intent_submitted(
            intent_key,
            preflight_droplet_ids=list(current_ids),
            verifier_droplet_fingerprint=verifier_fingerprint,
        )
        try:
            payload = _mutation_response(
                "POST",
                f"/v2/volumes/{quote(str(volume_id), safe='')}/actions",
                headers=self.headers,
                body={
                    "type": operation,
                    "droplet_id": int(verifier_droplet_id),
                    "region": str(region),
                },
                required_scope="block_storage_action:create",
            )
        except AmbiguousMutation:
            self.intents.update(intent_key, outcome_unknown=True)
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=lambda resource: self._native_volume_attachment_ids(
                    resource
                ),
                complete=lambda resource: self._native_volume_attachment_ids(
                    resource
                )
                == desired_ids,
                label=f"native-volume-{operation}:{volume_id}",
            ):
                self.intents.clear(intent_key)
                return {
                    "operation": operation,
                    "volume_id": str(volume_id),
                    "verifier_droplet_id": str(verifier_droplet_id),
                    "droplet_ids": desired_ids,
                    "region": str(region),
                    "observed_at": _utc_now(),
                    "action_id": "",
                    "reconciled": True,
                }
            raise
        except HarnessError:
            self.intents.clear(intent_key)
            raise
        action = payload.get("action") if isinstance(payload, dict) else None
        action_id = str(action.get("id") or "") if isinstance(action, dict) else ""
        action_type = str(action.get("type") or "") if isinstance(action, dict) else ""
        action_resource = (
            str(action.get("resource_id") or "") if isinstance(action, dict) else ""
        )
        if (
            not action_id
            or action_type != operation
            or (action_resource and action_resource != str(volume_id))
        ):
            self.intents.update(intent_key, outcome_unknown=True)
            raise AmbiguousMutation(
                "DigitalOcean accepted the volume action without an exact action witness."
            )
        self._set_intent_mutation_state(
            intent_key,
            "accepted",
            accepted_at=time.time(),
            action_id=action_id,
            outcome_unknown=False,
        )
        if not self._poll_mutation_state(
            read_back=read_back,
            verify_present=lambda resource: self._native_volume_attachment_ids(
                resource
            ),
            complete=lambda resource: self._native_volume_attachment_ids(resource)
            == desired_ids,
            label=f"native-volume-{operation}:{volume_id}",
        ):
            raise AmbiguousMutation(
                f"DigitalOcean accepted the volume {operation}, but exact read-back is pending."
            )
        self.intents.clear(intent_key)
        return {
            "operation": operation,
            "volume_id": str(volume_id),
            "verifier_droplet_id": str(verifier_droplet_id),
            "droplet_ids": desired_ids,
            "region": str(region),
            "observed_at": _utc_now(),
            "action_id": action_id,
            "reconciled": False,
        }

    @staticmethod
    def _native_volume_evidence_fingerprint(ownership: dict) -> str:
        payload = copy.deepcopy(ownership)
        payload.pop("evidence_fingerprint", None)
        return _fingerprint(payload)

    def _validate_native_volume_evidence(
        self,
        entry: Any,
        *,
        kind: str,
        volume_id: str,
        proof: str,
    ) -> dict[str, Any]:
        ownership = entry.get("ownership") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("kind") != kind
            or str(entry.get("resource_id") or "") != str(volume_id)
            or entry.get("cleanup_state") not in {"eligible", "failed"}
            or not isinstance(ownership, dict)
            or ownership.get("schema") != NATIVE_VOLUME_VERIFIER_SCHEMA
            or ownership.get("team_uuid") != self.account["team_uuid"]
            or ownership.get("run_tag") != self.run_tag
            or ownership.get("proof") != proof
            or str(ownership.get("volume_id") or "") != str(volume_id)
            or ownership.get("provider_detached") is not True
            or ownership.get("detached_readback", {}).get("droplet_ids") != []
            or ownership.get("evidence_fingerprint")
            != self._native_volume_evidence_fingerprint(ownership)
        ):
            raise HarnessError("The durable native-volume byte evidence is malformed.")
        for timestamp_key in ("guest_observed_at", "provider_detached_at"):
            try:
                value = datetime.fromisoformat(str(ownership.get(timestamp_key) or ""))
            except ValueError as error:
                raise HarnessError(
                    "The durable native-volume timestamp is malformed."
                ) from error
            if value.tzinfo is None:
                raise HarnessError(
                    "The durable native-volume timestamp has no timezone."
                )
        if (
            not re.fullmatch(r"[0-9a-f]{64}", str(ownership.get("sha256") or ""))
            or _positive_integer(ownership.get("byte_count")) is None
            or type(ownership.get("offset_bytes")) is not int
        ):
            raise HarnessError("The durable native-volume byte range is malformed.")
        _native_volume_range(
            ownership["offset_bytes"], ownership["byte_count"]
        )
        return ownership

    def _record_native_volume_source_evidence(
        self,
        *,
        source_volume: dict,
        verifier_droplet: dict,
        key_material: dict[str, Any],
        fixture: dict[str, Any],
        guest_proof: dict[str, Any],
        attach_witness: dict[str, Any],
        detach_witness: dict[str, Any],
    ) -> dict:
        source_id = str(source_volume.get("id") or "")
        ownership = {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "proof": "LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
            "volume_id": source_id,
            "volume_name": str(source_volume.get("name") or ""),
            "verifier_droplet_id": str(verifier_droplet.get("id") or ""),
            "observed_region": guest_proof["observed_region"],
            "size_gigabytes": int(source_volume["size_gigabytes"]),
            "stable_device": guest_proof["stable_device"],
            "resolved_device": guest_proof["resolved_device"],
            "device_size_bytes": guest_proof["device_size_bytes"],
            "offset_bytes": fixture["offset_bytes"],
            "byte_count": fixture["byte_count"],
            "sha256": fixture["sha256"],
            "fixture_fingerprint": fixture["fixture_fingerprint"],
            "guest_observed_at": guest_proof["observed_at"],
            "guest_operation": guest_proof["operation"],
            "guest_write_performed": guest_proof["write_performed"],
            "client_fingerprint": key_material["client_fingerprint"],
            "host_fingerprint": key_material["host_fingerprint"],
            "attach_readback": copy.deepcopy(attach_witness),
            "detached_readback": copy.deepcopy(detach_witness),
            "provider_detached": detach_witness.get("droplet_ids") == [],
            "provider_detached_at": detach_witness["observed_at"],
        }
        ownership["evidence_fingerprint"] = self._native_volume_evidence_fingerprint(
            ownership
        )
        return self.ledger.record(
            kind="native_volume_source_content_witness",
            resource_id=source_id,
            name=str(source_volume.get("name") or ""),
            ownership=ownership,
            source_witness=f"native-volume-source-bytes:{source_id}",
        )

    def _record_native_volume_restore_evidence(
        self,
        *,
        source_evidence: dict[str, Any],
        restore_volume: dict,
        verifier_droplet: dict,
        key_material: dict[str, Any],
        guest_proof: dict[str, Any],
        attach_witness: dict[str, Any],
        detach_witness: dict[str, Any],
    ) -> dict:
        restore_id = str(restore_volume.get("id") or "")
        ownership = {
            "schema": NATIVE_VOLUME_VERIFIER_SCHEMA,
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "proof": "LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
            "volume_id": restore_id,
            "volume_name": str(restore_volume.get("name") or ""),
            "source_volume_id": str(source_evidence["volume_id"]),
            "source_evidence_fingerprint": source_evidence[
                "evidence_fingerprint"
            ],
            "verifier_droplet_id": str(verifier_droplet.get("id") or ""),
            "observed_region": guest_proof["observed_region"],
            "size_gigabytes": int(restore_volume["size_gigabytes"]),
            "stable_device": guest_proof["stable_device"],
            "resolved_device": guest_proof["resolved_device"],
            "device_size_bytes": guest_proof["device_size_bytes"],
            "offset_bytes": source_evidence["offset_bytes"],
            "byte_count": source_evidence["byte_count"],
            "sha256": source_evidence["sha256"],
            "guest_observed_at": guest_proof["observed_at"],
            "guest_operation": "read",
            "read_only": True,
            "guest_write_performed": False,
            "client_fingerprint": key_material["client_fingerprint"],
            "host_fingerprint": key_material["host_fingerprint"],
            "attach_readback": copy.deepcopy(attach_witness),
            "detached_readback": copy.deepcopy(detach_witness),
            "provider_detached": detach_witness.get("droplet_ids") == [],
            "provider_detached_at": detach_witness["observed_at"],
        }
        ownership["evidence_fingerprint"] = self._native_volume_evidence_fingerprint(
            ownership
        )
        return self.ledger.record(
            kind="native_volume_restore_content_witness",
            resource_id=restore_id,
            name=str(restore_volume.get("name") or ""),
            ownership=ownership,
            source_witness=(
                f"native-volume-restore-bytes:{source_evidence['volume_id']}:{restore_id}"
            ),
        )

    def _source_volume_contract(self, source_volume_id: str) -> tuple[dict, dict]:
        entry = self.ledger.get("source_volume", str(source_volume_id))
        ownership = entry.get("ownership") if isinstance(entry, dict) else None
        creation = ownership.get("creation_witness") if isinstance(ownership, dict) else None
        expected_size = (
            _positive_integer(creation.get("size_gigabytes"))
            if isinstance(creation, dict)
            else None
        )
        if (
            not isinstance(entry, dict)
            or entry.get("cleanup_state") not in {"eligible", "failed"}
            or not isinstance(ownership, dict)
            or ownership.get("team_uuid") != self.account["team_uuid"]
            or ownership.get("run_tag") != self.run_tag
            or not isinstance(creation, dict)
            or creation.get("region") != self.region
            or expected_size is None
            or expected_size != self.source_volume_size_gib
            or str(entry.get("name") or "") != str(creation.get("name") or "")
        ):
            raise HarnessError("The source volume durable ownership contract mismatched.")
        return entry, ownership

    def prepare_native_volume_source(self, source_volume_id: str) -> dict[str, Any]:
        """Seed and prove one exact source volume before a fresh UI backup."""

        self._require_native_volume_gate(source_write=True)
        source_volume_id = str(source_volume_id or "")
        entry, _source_ownership = self._source_volume_contract(source_volume_id)
        verifier_entries = [
            row
            for row in self.ledger.entries("native_volume_verifier_droplet")
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(verifier_entries) > 1:
            raise HarnessError("Multiple active native-volume verifier Droplets are ledgered.")
        existing_verifier_id = (
            str(verifier_entries[0].get("resource_id") or "")
            if verifier_entries
            else ""
        )
        source_volume = self._read_exact_native_volume(
            kind="source_volume",
            volume_id=source_volume_id,
            name=str(entry.get("name") or ""),
            region=self.region,
            size_gigabytes=self.source_volume_size_gib,
            allowed_attachment_ids=(
                {existing_verifier_id} if existing_verifier_id else set()
            ),
        )
        existing_evidence = self.ledger.get(
            "native_volume_source_content_witness", source_volume_id
        )
        if existing_evidence:
            evidence = self._validate_native_volume_evidence(
                existing_evidence,
                kind="native_volume_source_content_witness",
                volume_id=source_volume_id,
                proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
            )
            if self._native_volume_attachment_ids(source_volume) != []:
                raise HarnessError(
                    "The proven source volume is not currently detached."
                )
            return {
                "status": "SOURCE_ALREADY_PREPARED",
                "source_volume_id": source_volume_id,
                "sha256": evidence["sha256"],
                "byte_count": evidence["byte_count"],
                "offset_bytes": evidence["offset_bytes"],
                "provider_detached": True,
            }
        droplet, key_material = self.ensure_native_volume_verifier_droplet()
        verifier_id = str(droplet.get("id") or "")
        if existing_verifier_id and verifier_id != existing_verifier_id:
            raise HarnessError("The active native-volume verifier Droplet ID changed.")
        if self._native_volume_attachment_ids(source_volume) not in ([], [verifier_id]):
            raise HarnessError("The source volume is attached to a foreign Droplet.")
        self.ensure_native_volume_verifier_firewall(verifier_id)
        identity = self.wait_native_volume_verifier_ready(droplet, key_material)
        fixture = _native_volume_fixture(
            run_id=self.run_id,
            team_uuid=self.account["team_uuid"],
            source_volume_id=source_volume_id,
            offset_bytes=self.native_volume_offset_bytes,
            byte_count=self.native_volume_byte_count,
        )
        workflow_key = f"native-volume:prepare-source:{source_volume_id}"
        workflow_request = {
            "source_volume_id": source_volume_id,
            "source_volume_name": str(source_volume.get("name") or ""),
            "verifier_droplet_id": verifier_id,
            "region": self.region,
            "size_gigabytes": self.source_volume_size_gib,
            "offset_bytes": fixture["offset_bytes"],
            "byte_count": fixture["byte_count"],
            "sha256": fixture["sha256"],
            "fixture_fingerprint": fixture["fixture_fingerprint"],
        }
        workflow_fingerprint = _fingerprint(workflow_request)
        workflow = self.intents.get(workflow_key)
        if workflow:
            if (
                workflow.get("marker") != self.run_tag
                or workflow.get("kind") != "native_volume_source_workflow"
                or workflow.get("name") != source_volume_id
                or workflow.get("operation") != "prepare-source"
                or workflow.get("request_fingerprint") != workflow_fingerprint
            ):
                raise HarnessError("The native-volume source workflow intent drifted.")
        else:
            self.intents.put(
                workflow_key,
                {
                    "marker": self.run_tag,
                    "kind": "native_volume_source_workflow",
                    "name": source_volume_id,
                    "operation": "prepare-source",
                    "request_fingerprint": workflow_fingerprint,
                    "state": "planned",
                },
            )
        attach_witness = self._transition_native_volume_attachment(
            kind="source_volume",
            volume_id=source_volume_id,
            volume_name=str(source_volume.get("name") or ""),
            verifier_droplet_id=verifier_id,
            region=self.region,
            size_gigabytes=self.source_volume_size_gib,
            attach=True,
        )
        self.intents.update(
            workflow_key,
            state="attached",
            attachment_witness=attach_witness,
            guest_identity_fingerprint=_fingerprint(identity),
        )
        detach_witness = None
        seed_intent_key = f"native-volume:seed-bytes:{source_volume_id}"
        try:
            inspect_proof = self._run_native_volume_guest(
                operation="inspect",
                droplet=droplet,
                key_material=key_material,
                volume=source_volume,
            )
            seed_intent = self.intents.get(seed_intent_key)
            if seed_intent:
                expected_preimage = str(
                    seed_intent.get("expected_preimage_sha256") or ""
                )
                expected_seed_request = {
                    **workflow_request,
                    "expected_preimage_sha256": expected_preimage,
                    "operation": "seed",
                }
                if (
                    seed_intent.get("marker") != self.run_tag
                    or seed_intent.get("kind") != "native_volume_seed"
                    or seed_intent.get("name") != source_volume_id
                    or seed_intent.get("operation") != "seed"
                    or seed_intent.get("request_boundary_crossed") is not True
                    or self._intent_mutation_state(seed_intent)
                    not in {"submitted", "accepted"}
                    or not re.fullmatch(r"[0-9a-f]{64}", expected_preimage)
                    or seed_intent.get("request_fingerprint")
                    != _fingerprint(expected_seed_request)
                ):
                    raise HarnessError("The native-volume seed intent drifted.")
            else:
                if inspect_proof["sha256"] == fixture["sha256"]:
                    raise HarnessError(
                        "Source bytes match the fixture without a durable seed intent."
                    )
                expected_preimage = inspect_proof["sha256"]
                seed_request = {
                    **workflow_request,
                    "expected_preimage_sha256": expected_preimage,
                    "operation": "seed",
                }
                self.intents.put(
                    seed_intent_key,
                    {
                        "intent_schema": MUTATION_INTENT_SCHEMA,
                        "marker": self.run_tag,
                        "kind": "native_volume_seed",
                        "name": source_volume_id,
                        "operation": "seed",
                        "request_fingerprint": _fingerprint(seed_request),
                        "request_boundary_crossed": True,
                        "state": "submitted",
                        "mutation_state": "submitted",
                        "submitted_at": time.time(),
                        "expected_preimage_sha256": expected_preimage,
                    },
                )
            if inspect_proof["sha256"] == fixture["sha256"]:
                guest_proof = self._run_native_volume_guest(
                    operation="read",
                    droplet=droplet,
                    key_material=key_material,
                    volume=source_volume,
                    expected_sha256=fixture["sha256"],
                )
            elif inspect_proof["sha256"] == expected_preimage:
                guest_proof = self._run_native_volume_guest(
                    operation="seed",
                    droplet=droplet,
                    key_material=key_material,
                    volume=source_volume,
                    expected_sha256=fixture["sha256"],
                    expected_preimage_sha256=expected_preimage,
                    fixture_bytes=fixture["payload"],
                )
            else:
                raise HarnessError(
                    "The source byte range changed after an uncertain seed attempt."
                )
            self._set_intent_mutation_state(
                seed_intent_key,
                "accepted",
                accepted_at=time.time(),
                guest_proof_fingerprint=_fingerprint(guest_proof),
                outcome_unknown=False,
            )
            self.intents.update(
                workflow_key,
                state="source-bytes-verified",
                guest_proof=guest_proof,
            )
            detach_witness = self._transition_native_volume_attachment(
                kind="source_volume",
                volume_id=source_volume_id,
                volume_name=str(source_volume.get("name") or ""),
                verifier_droplet_id=verifier_id,
                region=self.region,
                size_gigabytes=self.source_volume_size_gib,
                attach=False,
            )
        except Exception as error:
            self.intents.update(
                workflow_key,
                state="manual-review",
                failure_code=type(error).__name__,
            )
            try:
                current = self._read_exact_native_volume(
                    kind="source_volume",
                    volume_id=source_volume_id,
                    name=str(source_volume.get("name") or ""),
                    region=self.region,
                    size_gigabytes=self.source_volume_size_gib,
                    allowed_attachment_ids={verifier_id},
                )
                if self._native_volume_attachment_ids(current) == [verifier_id]:
                    self._transition_native_volume_attachment(
                        kind="source_volume",
                        volume_id=source_volume_id,
                        volume_name=str(source_volume.get("name") or ""),
                        verifier_droplet_id=verifier_id,
                        region=self.region,
                        size_gigabytes=self.source_volume_size_gib,
                        attach=False,
                    )
            except Exception as detach_error:
                raise AmbiguousMutation(
                    "Source verification failed and exact detachment is uncertain."
                ) from detach_error
            raise
        final_source = self._read_exact_native_volume(
            kind="source_volume",
            volume_id=source_volume_id,
            name=str(source_volume.get("name") or ""),
            region=self.region,
            size_gigabytes=self.source_volume_size_gib,
            allowed_attachment_ids=set(),
        )
        if self._native_volume_attachment_ids(final_source) != []:
            raise AmbiguousMutation(
                "The source volume was not exactly detached after byte verification."
            )
        evidence = self._record_native_volume_source_evidence(
            source_volume=final_source,
            verifier_droplet=droplet,
            key_material=key_material,
            fixture=fixture,
            guest_proof=guest_proof,
            attach_witness=attach_witness,
            detach_witness=detach_witness or {},
        )
        self.intents.clear(seed_intent_key)
        self.intents.clear(workflow_key)
        ownership = evidence["ownership"]
        return {
            "status": "SOURCE_PREPARED",
            "source_volume_id": source_volume_id,
            "verifier_droplet_id": verifier_id,
            "sha256": ownership["sha256"],
            "byte_count": ownership["byte_count"],
            "offset_bytes": ownership["offset_bytes"],
            "provider_detached": True,
        }

    def verify_native_volume_restore(
        self,
        *,
        provider_id: str,
        name: str,
        snapshot_id: str,
        snapshot_marker: str,
        restore_marker: str,
        run_tag: str,
        expected_region: str,
        expected_size_gigabytes: int,
    ) -> dict[str, Any]:
        """Read, never write, an exact UI-restored native volume."""

        self._require_native_volume_gate()
        provider_id = str(provider_id or "")
        expected_size = _positive_integer(expected_size_gigabytes)
        if not provider_id or not expected_region or expected_size is None:
            raise HarnessError("The restored native-volume contract is incomplete.")
        snapshot_entry = self.ledger.get("ui_snapshot_volume", str(snapshot_id))
        snapshot_ownership = (
            snapshot_entry.get("ownership")
            if isinstance(snapshot_entry, dict)
            else None
        )
        source_volume_id = (
            str(snapshot_ownership.get("source_id") or "")
            if isinstance(snapshot_ownership, dict)
            else ""
        )
        if (
            not isinstance(snapshot_entry, dict)
            or snapshot_entry.get("cleanup_state") not in {"eligible", "failed"}
            or not isinstance(snapshot_ownership, dict)
            or snapshot_ownership.get("team_uuid") != self.account["team_uuid"]
            or snapshot_ownership.get("run_tag") != self.run_tag
            or _stored_snapshot_marker(snapshot_ownership) != snapshot_marker
            or snapshot_ownership.get("resource_type") != "volume"
            or str(run_tag) != self.run_tag
            or not source_volume_id
        ):
            raise HarnessError(
                "The restored native-volume snapshot ownership witness mismatched."
            )
        source_entry = self.ledger.get(
            "native_volume_source_content_witness", source_volume_id
        )
        source_evidence = self._validate_native_volume_evidence(
            source_entry,
            kind="native_volume_source_content_witness",
            volume_id=source_volume_id,
            proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
        )
        if (
            source_evidence.get("observed_region") != expected_region
            or source_evidence.get("offset_bytes")
            != self.native_volume_offset_bytes
            or source_evidence.get("byte_count") != self.native_volume_byte_count
        ):
            raise HarnessError(
                "The source live-byte witness and restored verification range disagree."
            )
        source_contract, _source_ownership = self._source_volume_contract(
            source_volume_id
        )
        source_current = self._read_exact_native_volume(
            kind="source_volume",
            volume_id=source_volume_id,
            name=str(source_contract.get("name") or ""),
            region=expected_region,
            size_gigabytes=int(source_evidence["size_gigabytes"]),
            allowed_attachment_ids=set(),
        )
        if self._native_volume_attachment_ids(source_current) != []:
            raise HarnessError("The source volume is not detached before restore proof.")
        restore_witness = {
            "target_kind": "volume",
            "provider_id": provider_id,
            "name": str(name),
            "marker": str(restore_marker),
            "run_tag": str(run_tag),
            "snapshot_id": str(snapshot_id),
            "expected_region": str(expected_region),
            "expected_size_gigabytes": expected_size,
        }
        verifier_entries = [
            row
            for row in self.ledger.entries("native_volume_verifier_droplet")
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(verifier_entries) != 1:
            raise HarnessError(
                "Restored byte verification requires one exact active verifier Droplet."
            )
        verifier_id = str(verifier_entries[0].get("resource_id") or "")
        if verifier_id != str(source_evidence.get("verifier_droplet_id") or ""):
            raise HarnessError("The source and restored verifier Droplet IDs disagree.")
        restore_volume = self._read_exact_native_volume(
            kind="ui_restore_volume",
            volume_id=provider_id,
            name=name,
            region=expected_region,
            size_gigabytes=expected_size,
            allowed_attachment_ids={verifier_id},
            restore_witness=restore_witness,
        )
        if self._native_volume_attachment_ids(restore_volume) == []:
            control = self.verify_ui_restore(
                target_kind="volume",
                provider_id=provider_id,
                name=name,
                snapshot_id=snapshot_id,
                run_tag=run_tag,
                snapshot_marker=snapshot_marker,
                restore_marker=restore_marker,
                expected_region=expected_region,
                expected_size_gigabytes=expected_size,
            )
            if control.get("verification_level") == "FULL_E2E":
                return {
                    "status": "RESTORE_ALREADY_VERIFIED",
                    "ui_restore": control,
                }
        existing_restore = self.ledger.get(
            "native_volume_restore_content_witness", provider_id
        )
        if existing_restore:
            restore_evidence = self._validate_native_volume_evidence(
                existing_restore,
                kind="native_volume_restore_content_witness",
                volume_id=provider_id,
                proof="LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
            )
            if (
                restore_evidence.get("read_only") is not True
                or restore_evidence.get("guest_write_performed") is not False
                or restore_evidence.get("source_volume_id") != source_volume_id
                or restore_evidence.get("source_evidence_fingerprint")
                != source_evidence["evidence_fingerprint"]
                or restore_evidence.get("sha256") != source_evidence["sha256"]
                or self._native_volume_attachment_ids(restore_volume) != []
            ):
                raise HarnessError("The existing restored live-byte witness mismatched.")
            full = self.verify_ui_restore(
                target_kind="volume",
                provider_id=provider_id,
                name=name,
                snapshot_id=snapshot_id,
                run_tag=run_tag,
                snapshot_marker=snapshot_marker,
                restore_marker=restore_marker,
                expected_region=expected_region,
                expected_size_gigabytes=expected_size,
            )
            return {"status": "RESTORE_ALREADY_VERIFIED", "ui_restore": full}
        droplet, key_material = self.ensure_native_volume_verifier_droplet()
        if str(droplet.get("id") or "") != verifier_id:
            raise HarnessError("The exact verifier Droplet changed before restored read.")
        self.ensure_native_volume_verifier_firewall(verifier_id)
        identity = self.wait_native_volume_verifier_ready(droplet, key_material)
        workflow_key = f"native-volume:verify-restored:{provider_id}"
        workflow_request = {
            "source_volume_id": source_volume_id,
            "source_evidence_fingerprint": source_evidence[
                "evidence_fingerprint"
            ],
            "restore_volume_id": provider_id,
            "restore_volume_name": str(name),
            "snapshot_id": str(snapshot_id),
            "restore_marker": str(restore_marker),
            "verifier_droplet_id": verifier_id,
            "region": expected_region,
            "size_gigabytes": expected_size,
            "offset_bytes": source_evidence["offset_bytes"],
            "byte_count": source_evidence["byte_count"],
            "sha256": source_evidence["sha256"],
            "operation": "read-only",
        }
        workflow_fingerprint = _fingerprint(workflow_request)
        workflow = self.intents.get(workflow_key)
        if workflow:
            if (
                workflow.get("marker") != self.run_tag
                or workflow.get("kind") != "native_volume_restore_workflow"
                or workflow.get("name") != provider_id
                or workflow.get("operation") != "verify-restored"
                or workflow.get("request_fingerprint") != workflow_fingerprint
            ):
                raise HarnessError("The restored native-volume workflow intent drifted.")
        else:
            self.intents.put(
                workflow_key,
                {
                    "marker": self.run_tag,
                    "kind": "native_volume_restore_workflow",
                    "name": provider_id,
                    "operation": "verify-restored",
                    "request_fingerprint": workflow_fingerprint,
                    "state": "planned",
                },
            )
        attach_witness = self._transition_native_volume_attachment(
            kind="ui_restore_volume",
            volume_id=provider_id,
            volume_name=name,
            verifier_droplet_id=verifier_id,
            region=expected_region,
            size_gigabytes=expected_size,
            attach=True,
            restore_witness=restore_witness,
        )
        self.intents.update(
            workflow_key,
            state="attached",
            attachment_witness=attach_witness,
            guest_identity_fingerprint=_fingerprint(identity),
        )
        detach_witness = None
        try:
            guest_proof = self._run_native_volume_guest(
                operation="read",
                droplet=droplet,
                key_material=key_material,
                volume=restore_volume,
                expected_sha256=source_evidence["sha256"],
            )
            if (
                guest_proof.get("open_mode") != "read-only"
                or guest_proof.get("write_performed") is not False
                or guest_proof.get("sha256") != source_evidence["sha256"]
                or guest_proof.get("byte_count") != source_evidence["byte_count"]
                or guest_proof.get("offset_bytes") != source_evidence["offset_bytes"]
            ):
                raise HarnessError(
                    "The restored volume live read did not match the source witness."
                )
            self.intents.update(
                workflow_key,
                state="restore-bytes-verified",
                guest_proof=guest_proof,
            )
            detach_witness = self._transition_native_volume_attachment(
                kind="ui_restore_volume",
                volume_id=provider_id,
                volume_name=name,
                verifier_droplet_id=verifier_id,
                region=expected_region,
                size_gigabytes=expected_size,
                attach=False,
                restore_witness=restore_witness,
            )
        except Exception as error:
            self.intents.update(
                workflow_key,
                state="manual-review",
                failure_code=type(error).__name__,
            )
            try:
                current = self._read_exact_native_volume(
                    kind="ui_restore_volume",
                    volume_id=provider_id,
                    name=name,
                    region=expected_region,
                    size_gigabytes=expected_size,
                    allowed_attachment_ids={verifier_id},
                    restore_witness=restore_witness,
                )
                if self._native_volume_attachment_ids(current) == [verifier_id]:
                    self._transition_native_volume_attachment(
                        kind="ui_restore_volume",
                        volume_id=provider_id,
                        volume_name=name,
                        verifier_droplet_id=verifier_id,
                        region=expected_region,
                        size_gigabytes=expected_size,
                        attach=False,
                        restore_witness=restore_witness,
                    )
            except Exception as detach_error:
                raise AmbiguousMutation(
                    "Restored verification failed and exact detachment is uncertain."
                ) from detach_error
            raise
        final_restore = self._read_exact_native_volume(
            kind="ui_restore_volume",
            volume_id=provider_id,
            name=name,
            region=expected_region,
            size_gigabytes=expected_size,
            allowed_attachment_ids=set(),
            restore_witness=restore_witness,
        )
        if self._native_volume_attachment_ids(final_restore) != []:
            raise AmbiguousMutation(
                "The restored volume was not exactly detached after its live read."
            )
        self._record_native_volume_restore_evidence(
            source_evidence=source_evidence,
            restore_volume=final_restore,
            verifier_droplet=droplet,
            key_material=key_material,
            guest_proof=guest_proof,
            attach_witness=attach_witness,
            detach_witness=detach_witness or {},
        )
        self.intents.clear(workflow_key)
        full = self.verify_ui_restore(
            target_kind="volume",
            provider_id=provider_id,
            name=name,
            snapshot_id=snapshot_id,
            run_tag=run_tag,
            snapshot_marker=snapshot_marker,
            restore_marker=restore_marker,
            expected_region=expected_region,
            expected_size_gigabytes=expected_size,
        )
        if full.get("verification_level") != "FULL_E2E":
            raise HarnessError(
                "The restored byte proof was persisted but FULL_E2E adoption failed."
            )
        return {
            "status": "RESTORE_VERIFIED_FULL_E2E",
            "source_volume_id": source_volume_id,
            "restore_volume_id": provider_id,
            "verifier_droplet_id": verifier_id,
            "ui_restore": full,
        }

    def _live_native_volume_content_proof(
        self,
        *,
        source_volume_id: str,
        restore_volume_id: str,
        restore_resource: dict,
    ) -> dict[str, Any] | None:
        source_entry = self.ledger.get(
            "native_volume_source_content_witness", str(source_volume_id)
        )
        restore_entry = self.ledger.get(
            "native_volume_restore_content_witness", str(restore_volume_id)
        )
        source_is_evidence = (
            isinstance(source_entry, dict)
            and source_entry.get("kind")
            == "native_volume_source_content_witness"
        )
        restore_is_evidence = (
            isinstance(restore_entry, dict)
            and restore_entry.get("kind")
            == "native_volume_restore_content_witness"
        )
        if not source_is_evidence and not restore_is_evidence:
            return None
        source = self._validate_native_volume_evidence(
            source_entry,
            kind="native_volume_source_content_witness",
            volume_id=str(source_volume_id),
            proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
        )
        restore = self._validate_native_volume_evidence(
            restore_entry,
            kind="native_volume_restore_content_witness",
            volume_id=str(restore_volume_id),
            proof="LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
        )
        if (
            not re.fullmatch(
                r"[0-9a-f]{64}", str(source.get("fixture_fingerprint") or "")
            )
            or restore.get("source_volume_id") != str(source_volume_id)
            or restore.get("source_evidence_fingerprint")
            != source["evidence_fingerprint"]
            or restore.get("verifier_droplet_id")
            != source.get("verifier_droplet_id")
            or restore.get("observed_region") != source.get("observed_region")
            or restore.get("offset_bytes") != source.get("offset_bytes")
            or restore.get("byte_count") != source.get("byte_count")
            or restore.get("sha256") != source.get("sha256")
            or restore.get("read_only") is not True
            or restore.get("guest_operation") != "read"
            or restore.get("guest_write_performed") is not False
            or self._native_volume_attachment_ids(restore_resource) != []
        ):
            raise HarnessError(
                "The source and restored native-volume byte witnesses disagree."
            )
        source_contract, _source_ownership = self._source_volume_contract(
            str(source_volume_id)
        )
        source_resource = self._read_exact_native_volume(
            kind="source_volume",
            volume_id=str(source_volume_id),
            name=str(source_contract.get("name") or ""),
            region=str(source["observed_region"]),
            size_gigabytes=int(source["size_gigabytes"]),
            allowed_attachment_ids=set(),
        )
        if self._native_volume_attachment_ids(source_resource) != []:
            raise HarnessError("The source volume is no longer detached.")
        content = {
            "proof": "LIVE_NATIVE_VOLUME_BYTE_PROOF",
            "source_volume_id": str(source_volume_id),
            "restore_volume_id": str(restore_volume_id),
            "verifier_droplet_id": str(source["verifier_droplet_id"]),
            "region": str(source["observed_region"]),
            "offset_bytes": int(source["offset_bytes"]),
            "byte_count": int(source["byte_count"]),
            "sha256": str(source["sha256"]),
            "source_evidence_fingerprint": source["evidence_fingerprint"],
            "restore_evidence_fingerprint": restore["evidence_fingerprint"],
            "source_guest_observed_at": source["guest_observed_at"],
            "restore_guest_observed_at": restore["guest_observed_at"],
            "source_provider_detached_at": source["provider_detached_at"],
            "restore_provider_detached_at": restore["provider_detached_at"],
            "read_only_restore": True,
        }
        content["evidence_fingerprint"] = _fingerprint(content)
        return content

    def _prepare_mutation_intent(
        self,
        intent_key: str,
        *,
        kind: str,
        name: str,
        operation: str,
        request: dict,
        **extra,
    ) -> tuple[dict | None, str]:
        """Persist a retryable preflight intent without crossing the POST boundary.

        A planned/preflight intent is deliberately safe to revisit after a
        worker crash or a failed provider read.  ``request_boundary_crossed``
        is set only by ``_mark_intent_submitted`` immediately before the
        provider mutation, which is the point at which replay must become
        reconciliation-only.
        """

        fingerprint = _fingerprint(request)
        expected = {
            "intent_schema": MUTATION_INTENT_SCHEMA,
            "marker": self.run_tag,
            "kind": kind,
            "name": str(name),
            "operation": operation,
            "request_fingerprint": fingerprint,
            **extra,
        }
        current = self.intents.get(intent_key)
        if current:
            if any(current.get(key) != value for key, value in expected.items()):
                raise HarnessError("The durable DigitalOcean mutation intent drifted.")
            state = self._intent_mutation_state(current)
            crossed = current.get("request_boundary_crossed") is True
            if crossed and state == "":
                # Older ledgers recorded only the boundary bit.  Adopt that
                # conservative witness as submitted/unknown so a restart can
                # reconcile it, never replay it.
                current = self.intents.update(
                    intent_key,
                    state="submitted",
                    mutation_state="submitted",
                    preflight_state="complete",
                    outcome_unknown=True,
                )
            elif crossed and state not in {"submitted", "accepted"}:
                raise HarnessError("The DigitalOcean mutation intent boundary is invalid.")
            if not crossed and state not in {"planned", "preflight", ""}:
                raise HarnessError("The DigitalOcean mutation preflight state is invalid.")
        else:
            self.intents.put(
                intent_key,
                {
                    **expected,
                    "state": "planned",
                    "mutation_state": "planned",
                    "preflight_state": "planned",
                    "request_boundary_crossed": False,
                    "outcome_unknown": False,
                },
            )
        return current, fingerprint

    def _bind_mutation_intent_witness(
        self, intent_key: str, *, field: str, value: str
    ) -> dict:
        """Bind a fresh preflight witness without crossing the mutation boundary."""

        normalized = str(value or "")
        if not normalized:
            raise HarnessError("The mutation preflight witness is empty.")
        current = self.intents.get(intent_key)
        if isinstance(current, dict) and current.get(field) not in (None, normalized):
            raise HarnessError("The mutation preflight witness changed.")
        self.intents.update(intent_key, **{field: normalized, "preflight_state": "complete"})
        updated = self.intents.get(intent_key)
        if isinstance(updated, dict):
            return updated
        return {field: normalized}

    def _mark_intent_submitted(self, intent_key: str, **updates) -> dict:
        """Cross the durable request boundary immediately before a provider call."""

        current = self.intents.get(intent_key)
        if not isinstance(current, dict):
            raise HarnessError("The mutation intent disappeared before the provider call.")
        state = self._intent_mutation_state(current)
        if current.get("request_boundary_crossed") is True:
            if state in {"submitted", "accepted"}:
                raise HarnessError("The mutation intent is already beyond its request boundary.")
            raise HarnessError("The mutation intent has an invalid request boundary.")
        if state not in {"planned", "preflight", ""}:
            raise HarnessError("The mutation intent is not in a retryable preflight state.")
        payload = {
            "state": "submitted",
            "mutation_state": "submitted",
            "preflight_state": "complete",
            "request_boundary_crossed": True,
            "submitted_at": time.time(),
            "outcome_unknown": False,
            **updates,
        }
        self.intents.update(intent_key, **payload)
        updated = self.intents.get(intent_key)
        if not isinstance(updated, dict):
            raise HarnessError("The submitted mutation intent could not be re-read.")
        return updated

    def _poll_mutation_state(
        self,
        *,
        read_back,
        verify_present,
        complete,
        label: str,
    ) -> bool:
        """Poll one exact provider identity without issuing another mutation."""

        try:
            timeout_seconds = max(
                0.0,
                float(
                    getattr(
                        self,
                        "mutation_reconcile_timeout_seconds",
                        MUTATION_RECONCILE_TIMEOUT_SECONDS,
                    )
                ),
            )
            interval_seconds = max(
                0.01,
                float(
                    getattr(
                        self,
                        "mutation_reconcile_interval_seconds",
                        MUTATION_RECONCILE_INTERVAL_SECONDS,
                    )
                ),
            )
        except (TypeError, ValueError):
            raise HarnessError("The mutation reconciliation bounds are malformed.") from None
        deadline = time.monotonic() + timeout_seconds
        while True:
            current = read_back()
            if complete(current):
                return True
            if current is not None:
                verify_present(current)
            now = time.monotonic()
            if now >= deadline:
                return False
            time.sleep(min(interval_seconds, max(0.0, deadline - now)))

    @staticmethod
    def _intent_mutation_state(intent: dict) -> str:
        if not isinstance(intent, dict):
            return ""
        state = intent.get("state") or intent.get("mutation_state")
        return str(state or "")

    def _set_intent_mutation_state(self, intent_key: str, state: str, **updates):
        if state not in {"submitted", "accepted"}:
            raise HarnessError("The DigitalOcean mutation state is invalid.")
        return self.intents.update(
            intent_key,
            state=state,
            mutation_state=state,
            **updates,
        )

    def _delete_provider_with_intent(
        self,
        *,
        intent_key: str,
        kind: str,
        resource_id: str,
        name: str,
        request: dict,
        read_back,
        verify_present,
        delete_call,
    ) -> str:
        """Reconcile an exact provider ID before and after a destructive call."""

        intent, _fingerprint_value = self._prepare_mutation_intent(
            intent_key,
            kind=kind,
            name=name,
            operation="delete",
            request=request,
            provider_id=str(resource_id),
        )
        current = read_back()
        if current is None:
            self.intents.clear(intent_key)
            return "absent"
        verify_present(current)
        state = self._intent_mutation_state(intent) if intent is not None else ""
        if intent is not None and state in {"submitted", "accepted"}:
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=verify_present,
                complete=lambda resource: resource is None,
                label=f"{kind}:{resource_id}",
            ):
                self.intents.clear(intent_key)
                return "deleted"
            raise AmbiguousMutation(
                f"DigitalOcean {kind} cleanup is still visible; "
                "no DELETE replay was issued."
            )
        if intent is not None and state not in {"planned", "preflight", ""}:
            raise HarnessError("The cleanup intent is not in a retryable preflight state.")
        # The exact ID, current provider state, and immutable ownership witness
        # were just observed.  Only now, immediately before DELETE, cross the
        # durable request boundary.
        self._mark_intent_submitted(
            intent_key,
            outcome_unknown=False,
            reconciled_provider_id=str(resource_id),
            reconciled_state=str(
                current.get("status") or current.get("state") or "present"
            ),
        )
        try:
            delete_call()
        except AmbiguousMutation:
            self._set_intent_mutation_state(
                intent_key, "submitted", outcome_unknown=True
            )
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=verify_present,
                complete=lambda resource: resource is None,
                label=f"{kind}:{resource_id}",
            ):
                self.intents.clear(intent_key)
                return "deleted"
            raise
        except HarnessError:
            self.intents.clear(intent_key)
            raise
        self._set_intent_mutation_state(
            intent_key,
            "accepted",
            accepted_at=time.time(),
            outcome_unknown=False,
        )
        if not self._poll_mutation_state(
            read_back=read_back,
            verify_present=verify_present,
            complete=lambda resource: resource is None,
            label=f"{kind}:{resource_id}",
        ):
            raise AmbiguousMutation(
                "DigitalOcean accepted cleanup but the exact resource remains visible; "
                "the accepted intent will be reconciled without replay."
            )
        self.intents.clear(intent_key)
        return "deleted"

    def _delete_spaces_with_intent(
        self,
        *,
        intent_key: str,
        kind: str,
        name: str,
        request: dict,
        read_back,
        verify_present,
        delete_call,
    ) -> str:
        """S3-compatible equivalent of _delete_provider_with_intent."""

        intent, _fingerprint_value = self._prepare_mutation_intent(
            intent_key,
            kind=kind,
            name=name,
            operation="delete",
            request=request,
        )
        current = read_back()
        if current is None:
            self.intents.clear(intent_key)
            return "absent"
        verify_present(current)
        state = self._intent_mutation_state(intent) if intent is not None else ""
        if intent is not None and state in {"submitted", "accepted"}:
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=verify_present,
                complete=lambda resource: resource is None,
                label=f"{kind}:{name}",
            ):
                self.intents.clear(intent_key)
                return "deleted"
            raise AmbiguousMutation(
                "DigitalOcean Spaces cleanup is still visible; no delete replay was issued."
            )
        if intent is not None and state not in {"planned", "preflight", ""}:
            raise HarnessError("The Spaces cleanup intent is not in a retryable preflight state.")
        self._mark_intent_submitted(
            intent_key,
            outcome_unknown=False,
            reconciled_state="present",
        )
        try:
            delete_call()
        except AmbiguousMutation:
            self._set_intent_mutation_state(
                intent_key, "submitted", outcome_unknown=True
            )
            if self._poll_mutation_state(
                read_back=read_back,
                verify_present=verify_present,
                complete=lambda resource: resource is None,
                label=f"{kind}:{name}",
            ):
                self.intents.clear(intent_key)
                return "deleted"
            raise
        except HarnessError:
            self.intents.clear(intent_key)
            raise
        self._set_intent_mutation_state(
            intent_key,
            "accepted",
            accepted_at=time.time(),
            outcome_unknown=False,
        )
        if not self._poll_mutation_state(
            read_back=read_back,
            verify_present=verify_present,
            complete=lambda resource: resource is None,
            label=f"{kind}:{name}",
        ):
            raise AmbiguousMutation(
                "DigitalOcean Spaces accepted cleanup but the exact object remains visible; "
                "the accepted intent will be reconciled without replay."
            )
        self.intents.clear(intent_key)
        return "deleted"

    @staticmethod
    def _normalize_firewall_selector(selector: Any) -> dict[str, list[str]]:
        """Normalize a DO selector while rejecting broadened selectors.

        DigitalOcean can echo optional selector arrays alongside ``addresses``.
        Empty optional arrays are harmless and are normalized away; any
        non-empty selector would broaden the firewall's reach and therefore
        cannot be adopted or deleted by this harness.
        """

        if not isinstance(selector, dict):
            raise HarnessError("The DigitalOcean firewall selector is malformed.")
        if not set(selector).issubset(FIREWALL_SELECTOR_FIELDS):
            raise HarnessError("The DigitalOcean firewall selector has unknown fields.")
        addresses = selector.get("addresses")
        if not isinstance(addresses, list) or any(
            not isinstance(value, str) or not value for value in addresses
        ):
            raise HarnessError("The DigitalOcean firewall addresses are malformed.")
        if len(addresses) != len(set(addresses)):
            raise HarnessError("The DigitalOcean firewall addresses are duplicated.")
        for field in FIREWALL_SELECTOR_FIELDS - {"addresses"}:
            if field in selector:
                values = selector[field]
                if not isinstance(values, list) or values:
                    raise HarnessError(
                        "The DigitalOcean firewall has a non-address selector."
                    )
        return {"addresses": sorted(addresses)}

    @classmethod
    def _firewall_rule_selector(
        cls, rule: dict, *, outbound: bool = False
    ) -> dict[str, list[str]]:
        if not isinstance(rule, dict):
            raise HarnessError("The DigitalOcean firewall rule is malformed.")
        field = "destinations" if outbound else "sources"
        selector = rule.get(field)
        if selector is None and outbound:
            # Read-back normalizers pass outbound destinations as ``sources``.
            selector = rule.get("sources")
        return cls._normalize_firewall_selector(selector)

    @classmethod
    def _firewall_rule_addresses(cls, rule: dict) -> set[str]:
        try:
            return set(cls._firewall_rule_selector(rule).get("addresses") or [])
        except HarnessError:
            return set()

    @classmethod
    def _firewall_immutable_fingerprint(cls, firewall: dict) -> str:
        """Fingerprint the complete name/rule contract, excluding attachments."""

        if not isinstance(firewall, dict):
            raise HarnessError("The DigitalOcean firewall witness is malformed.")

        def normalize(rule: dict, *, outbound: bool) -> dict:
            selector = cls._firewall_rule_selector(rule, outbound=outbound)
            return {
                "protocol": str(rule.get("protocol") or ""),
                "ports": str(rule.get("ports") or ""),
                "selector": selector,
            }

        inbound = firewall.get("inbound_rules")
        outbound = firewall.get("outbound_rules")
        if not isinstance(inbound, list) or not isinstance(outbound, list):
            raise HarnessError("The DigitalOcean firewall rule lists are malformed.")
        return _fingerprint(
            {
                "name": str(firewall.get("name") or ""),
                "inbound_rules": sorted(
                    (normalize(rule, outbound=False) for rule in inbound),
                    key=_canonical,
                ),
                "outbound_rules": sorted(
                    (normalize(rule, outbound=True) for rule in outbound),
                    key=_canonical,
                ),
            }
        )

    @staticmethod
    def _firewall_intent_is_bounded(intent: dict, *, fingerprint: str) -> bool:
        if not isinstance(intent, dict):
            return False
        if (
            intent.get("intent_schema") != MUTATION_INTENT_SCHEMA
            or intent.get("preflight_absent") is not True
            or intent.get("preflight_candidate_count") != 0
            or intent.get("immutable_fingerprint") != fingerprint
        ):
            return False
        try:
            created_at = float(intent.get("created_at"))
        except (TypeError, ValueError):
            return False
        return 0 <= time.time() - created_at <= MUTATION_INTENT_MAX_AGE_SECONDS

    def _firewall_owned(
        self,
        firewall: dict,
        *,
        firewall_id=None,
        allowed_droplet_ids=None,
        required_droplet_id=None,
        require_empty_droplet_ids=False,
    ) -> bool:
        if not isinstance(firewall, dict):
            return False
        expected_name = _resource_name(self.run_id, "payload-firewall")
        if firewall_id is not None and str(firewall.get("id") or "") != str(
            firewall_id
        ):
            return False
        if str(firewall.get("name") or "") != expected_name:
            return False
        inbound = firewall.get("inbound_rules")
        outbound = firewall.get("outbound_rules")
        if not isinstance(inbound, list) or not isinstance(outbound, list):
            return False
        expected_inbound = [
            rule
            for rule in inbound
            if isinstance(rule, dict)
            and str(rule.get("protocol") or "") == "tcp"
            and str(rule.get("ports") or "") == str(PAYLOAD_PORT)
            and self._firewall_rule_addresses(rule) == set(self.probe_cidrs)
        ]
        if len(inbound) != 1 or len(expected_inbound) != 1:
            return False
        outbound_protocols = {
            str(rule.get("protocol") or "")
            for rule in outbound
            if isinstance(rule, dict)
            and str(rule.get("ports") or "") == "0"
            and self._firewall_rule_addresses(rule) == {"0.0.0.0/0", "::/0"}
        }
        if outbound_protocols != {"tcp", "udp", "icmp"} or len(outbound) != 3:
            return False
        droplet_ids = firewall.get("droplet_ids")
        if not isinstance(droplet_ids, list):
            return False
        actual = {str(value) for value in droplet_ids}
        allowed = {str(value) for value in (allowed_droplet_ids or [])}
        if not actual.issubset(allowed):
            return False
        if required_droplet_id is not None and str(required_droplet_id) not in actual:
            return False
        if require_empty_droplet_ids and actual:
            return False
        return True

    def _firewall_allowed_droplet_ids(self) -> set[str]:
        allowed = {
            str(entry["resource_id"])
            for kind in ("source_droplet", "ui_restore_droplet")
            for entry in self.ledger.entries(kind)
        }
        return allowed

    def ensure_payload_firewall(self, source_droplet_id: str) -> dict:
        if not self.probe_cidrs:
            raise HarnessError("Payload probing requires explicit host CIDRs.")
        kind = "payload_firewall"
        name = _resource_name(self.run_id, "payload-firewall")
        request = {
            "name": name,
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": str(PAYLOAD_PORT),
                    "sources": {"addresses": self.probe_cidrs},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": protocol,
                    # DigitalOcean's current firewall schema requires the
                    # string "0" for all ports (and always returns "0" for
                    # ICMP).  "all" is rejected with HTTP 422.
                    "ports": "0",
                    "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                }
                for protocol in ("tcp", "udp", "icmp")
            ],
            "droplet_ids": [int(source_droplet_id)],
        }
        # Firewall responses use ``destinations`` for outbound rules; normalize
        # those addresses into the same exact verifier used for inbound sources.
        def verify(resource, resource_id=None):
            normalized = dict(resource or {})
            normalized["outbound_rules"] = [
                {
                    **rule,
                    "sources": rule.get("destinations"),
                }
                for rule in normalized.get("outbound_rules") or []
                if isinstance(rule, dict)
            ]
            return self._firewall_owned(
                normalized,
                firewall_id=resource_id,
                allowed_droplet_ids=self._firewall_allowed_droplet_ids()
                | {str(source_droplet_id)},
                required_droplet_id=source_droplet_id,
            )

        fingerprint = _fingerprint(request)
        immutable_fingerprint = self._firewall_immutable_fingerprint(request)
        intent = self.intents.get(kind)
        candidates = [
            item
            for item in self._resources(kind)
            if str(item.get("name") or "") == name
        ]
        if len(candidates) > 1:
            raise HarnessError("Multiple exact run-owned payload firewalls were found.")
        if candidates:
            resource = self._read_resource(kind, str(candidates[0].get("id") or ""))
            if not resource or not verify(resource, resource.get("id")):
                raise HarnessError("Payload firewall ownership verification failed.")
            ledger_entry = self.ledger.get(kind, str(resource["id"]))
            intent_matches = bool(
                intent
                and intent.get("request_boundary_crossed")
                and intent.get("name") == name
                and intent.get("request_fingerprint") == fingerprint
                and self._firewall_intent_is_bounded(
                    intent, fingerprint=immutable_fingerprint
                )
            )
            if ledger_entry is None and not intent_matches:
                raise HarnessError("An unledgered firewall matches the run name.")
            if ledger_entry is not None:
                stored = ledger_entry.get("ownership") or {}
                creation = stored.get("creation_witness")
                if (
                    stored.get("team_uuid") != self.account["team_uuid"]
                    or stored.get("run_tag") != self.run_tag
                    or stored.get("source_droplet_id") != str(source_droplet_id)
                    or stored.get("request_fingerprint") != fingerprint
                    or stored.get("immutable_fingerprint") != immutable_fingerprint
                    or not isinstance(creation, dict)
                    or creation.get("name") != name
                    or creation.get("rules_fingerprint") != immutable_fingerprint
                    or creation.get("immutable_fingerprint") != immutable_fingerprint
                    or creation.get("source_droplet_id") != str(source_droplet_id)
                ):
                    raise HarnessError(
                        "The durable payload firewall creation fingerprint changed."
                    )
            self.ledger.record(
                kind=kind,
                resource_id=str(resource["id"]),
                name=name,
                ownership={
                    "team_uuid": self.account["team_uuid"],
                    "run_tag": self.run_tag,
                    "source_droplet_id": str(source_droplet_id),
                    "probe_cidrs": list(self.probe_cidrs),
                    "request_fingerprint": fingerprint,
                    "immutable_fingerprint": immutable_fingerprint,
                    "creation_witness": {
                        "name": name,
                        "rules_fingerprint": immutable_fingerprint,
                        "source_droplet_id": str(source_droplet_id),
                        "immutable_fingerprint": immutable_fingerprint,
                    },
                },
                source_witness=f"payload-firewall:{name}",
            )
            if intent_matches:
                self.intents.clear(kind)
            return resource
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior firewall create has no exact match yet; do not retry it."
            )
        if not self.apply:
            raise HarnessError("The payload firewall is absent and apply mode is disabled.")
        self.intents.put(
            kind,
            {
                "marker": self.run_tag,
                "kind": kind,
                "name": name,
                "operation": "create",
                "request_fingerprint": fingerprint,
                "immutable_fingerprint": immutable_fingerprint,
                "intent_schema": MUTATION_INTENT_SCHEMA,
                "created_at": time.time(),
                "preflight_absent": True,
                "preflight_candidate_count": 0,
                "state": "planned",
                "mutation_state": "planned",
                "preflight_state": "planned",
                "request_boundary_crossed": False,
                "outcome_unknown": False,
            },
        )
        self.intents.update(
            kind,
            state="submitted",
            mutation_state="submitted",
            preflight_state="complete",
            request_boundary_crossed=True,
            submitted_at=time.time(),
            outcome_unknown=False,
        )
        try:
            payload = _mutation_response(
                "POST", "/v2/firewalls", headers=self.headers, body=request
            )
        except AmbiguousMutation:
            # The provider may have accepted the request.  Keep the durable
            # intent so a replay can only reconcile the exact name and rules.
            raise
        except HarnessError:
            # A definite 4xx/provider rejection did not accept the mutation;
            # clear this exact intent so a corrected request can be attempted.
            self.intents.clear(kind)
            raise
        created = payload.get("firewall") if isinstance(payload, dict) else None
        resource_id = str(created.get("id") or "") if isinstance(created, dict) else ""
        if not resource_id:
            raise AmbiguousMutation("DigitalOcean did not return the firewall ID.")
        resource = self._read_resource(kind, resource_id)
        if not resource or not verify(resource, resource_id):
            raise HarnessError("Payload firewall ownership verification failed.")
        self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "source_droplet_id": str(source_droplet_id),
                "probe_cidrs": list(self.probe_cidrs),
                "request_fingerprint": fingerprint,
                "immutable_fingerprint": immutable_fingerprint,
                "creation_witness": {
                    "name": name,
                    "rules_fingerprint": immutable_fingerprint,
                    "source_droplet_id": str(source_droplet_id),
                    "immutable_fingerprint": immutable_fingerprint,
                },
            },
            source_witness=f"payload-firewall:{name}",
        )
        self.intents.clear(kind)
        return resource

    def _require_payload_firewall_attachment_gate(self) -> None:
        if (
            not getattr(self, "apply", False)
            or not getattr(self, "attach_ui_droplet_firewall", False)
            or os.environ.get("BACKUPSHEEP_E2E_FIREWALL_APPLY") != "YES"
            or not getattr(self, "expected_team_uuid", "")
            or str((getattr(self, "account", {}) or {}).get("team_uuid") or "")
            != self.expected_team_uuid
            or str((getattr(self, "account", {}) or {}).get("team_name") or "")
            != "Personal"
        ):
            raise HarnessError(
                "Payload firewall attachment is outside the exact apply and Personal-team gates."
            )

    def _attach_payload_firewall(self, droplet_id: str) -> None:
        self._require_payload_firewall_attachment_gate()
        entries = [
            entry
            for entry in self.ledger.entries("payload_firewall")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(entries) != 1:
            raise HarnessError("One exact ledgered payload firewall is required.")
        entry = entries[0]
        firewall_id = str(entry["resource_id"])
        firewall_ownership = entry.get("ownership") or {}
        firewall = self._read_resource("payload_firewall", firewall_id)
        if firewall is None:
            raise HarnessError("The ledgered payload firewall is missing.")
        allowed = self._firewall_allowed_droplet_ids()
        initial_normalized = dict(firewall)
        initial_normalized["outbound_rules"] = [
            {**rule, "sources": rule.get("destinations")}
            for rule in firewall.get("outbound_rules") or []
            if isinstance(rule, dict)
        ]
        immutable_fingerprint = self._firewall_immutable_fingerprint(initial_normalized)
        creation = firewall_ownership.get("creation_witness")
        if (
            firewall_ownership.get("immutable_fingerprint") != immutable_fingerprint
            or not isinstance(creation, dict)
            or creation.get("rules_fingerprint") != immutable_fingerprint
            or creation.get("immutable_fingerprint") != immutable_fingerprint
            or creation.get("source_droplet_id")
            != str(firewall_ownership.get("source_droplet_id") or "")
        ):
            raise HarnessError("The payload firewall creation fingerprint changed.")

        def verify_firewall(resource):
            if not isinstance(resource, dict):
                raise HarnessError("The payload firewall read-back is malformed.")
            normalized = dict(resource)
            normalized["outbound_rules"] = [
                {**rule, "sources": rule.get("destinations")}
                for rule in resource.get("outbound_rules") or []
                if isinstance(rule, dict)
            ]
            if not self._firewall_owned(
                normalized,
                firewall_id=firewall_id,
                allowed_droplet_ids=allowed,
                required_droplet_id=firewall_ownership.get("source_droplet_id"),
            ):
                raise HarnessError(
                    "The payload firewall has foreign assignments or rules."
                )
            if self._firewall_immutable_fingerprint(normalized) != immutable_fingerprint:
                raise HarnessError("The payload firewall rule fingerprint changed.")
            return resource

        verify_firewall(firewall)
        request = {
            "firewall_id": str(firewall_id),
            "droplet_id": str(droplet_id),
            "operation": "attach",
        }
        intent_key = f"attach:payload-firewall:{firewall_id}:{droplet_id}"
        if str(droplet_id) in {str(value) for value in firewall.get("droplet_ids") or []}:
            pending = self.intents.get(intent_key)
            if pending:
                pending, _ = self._prepare_mutation_intent(
                    intent_key,
                    kind="payload_firewall_attachment",
                    name=f"{firewall_id}:{droplet_id}",
                    operation="attach",
                    request=request,
                    firewall_id=str(firewall_id),
                    droplet_id=str(droplet_id),
                )
                if self._intent_mutation_state(pending) not in {
                    "planned",
                    "preflight",
                    "submitted",
                    "accepted",
                }:
                    raise HarnessError(
                        "The firewall attachment intent has an invalid preflight state."
                    )
                self.intents.clear(intent_key)
            return
        if str(droplet_id) not in allowed:
            raise HarnessError("The restored Droplet is not in the durable ledger.")
        intent, _fingerprint_value = self._prepare_mutation_intent(
            intent_key,
            kind="payload_firewall_attachment",
            name=f"{firewall_id}:{droplet_id}",
            operation="attach",
            request=request,
            firewall_id=str(firewall_id),
            droplet_id=str(droplet_id),
        )
        if intent is not None:
            state = self._intent_mutation_state(intent)
            if state not in {"planned", "preflight", "submitted", "accepted"}:
                raise HarnessError(
                    "The firewall attachment intent has an invalid preflight state."
                )
            if state in {"submitted", "accepted"} and self._poll_mutation_state(
                read_back=lambda: self._read_resource("payload_firewall", firewall_id),
                verify_present=verify_firewall,
                complete=lambda resource: isinstance(resource, dict)
                and str(droplet_id)
                in {str(value) for value in resource.get("droplet_ids") or []},
                label=f"payload-firewall:{firewall_id}:{droplet_id}",
            ):
                self.intents.clear(intent_key)
                return
            if state in {"submitted", "accepted"}:
                raise AmbiguousMutation(
                    "The firewall attachment is still unconfirmed; no attachment replay was issued."
                )
        # If a worker restarted after acceptance, adoption is based on the
        # exact firewall ID and the current assignment state.  A foreign or
        # changed firewall never receives a replay.
        observed = self._read_resource("payload_firewall", firewall_id)
        if observed is None:
            raise AmbiguousMutation("The exact payload firewall disappeared during attachment.")
        verify_firewall(observed)
        if str(droplet_id) in {str(value) for value in observed.get("droplet_ids") or []}:
            self.intents.clear(intent_key)
            return
        self._mark_intent_submitted(
            intent_key,
            outcome_unknown=False,
            reconciled_provider_id=str(firewall_id),
            reconciled_state="present_unattached",
        )
        try:
            _mutation_response(
                "POST",
                f"/v2/firewalls/{quote(firewall_id, safe='')}/droplets",
                headers=self.headers,
                body={"droplet_ids": [int(droplet_id)]},
            )
        except AmbiguousMutation:
            self._set_intent_mutation_state(
                intent_key, "submitted", outcome_unknown=True
            )
            if self._poll_mutation_state(
                read_back=lambda: self._read_resource("payload_firewall", firewall_id),
                verify_present=verify_firewall,
                complete=lambda resource: isinstance(resource, dict)
                and str(droplet_id)
                in {str(value) for value in resource.get("droplet_ids") or []},
                label=f"payload-firewall:{firewall_id}:{droplet_id}",
            ):
                self.intents.clear(intent_key)
                return
            raise
        except HarnessError:
            self.intents.clear(intent_key)
            raise
        self._set_intent_mutation_state(
            intent_key, "accepted", accepted_at=time.time(), outcome_unknown=False
        )
        if not self._poll_mutation_state(
            read_back=lambda: self._read_resource("payload_firewall", firewall_id),
            verify_present=verify_firewall,
            complete=lambda resource: isinstance(resource, dict)
            and str(droplet_id)
            in {str(value) for value in resource.get("droplet_ids") or []},
            label=f"payload-firewall:{firewall_id}:{droplet_id}",
        ):
            raise AmbiguousMutation(
                "The firewall attachment was accepted but is not yet visible."
            )
        self.intents.clear(intent_key)

    def wait_payload_ready(
        self, droplet: dict, *, timeout_seconds=600
    ) -> dict[str, Any]:
        ip_address = _public_ipv4(droplet)
        deadline = time.monotonic() + timeout_seconds
        last_error = None
        while time.monotonic() < deadline:
            try:
                _probe_payload_endpoint(ip_address, self.payload_expectation)
                return {
                    "sha256": self.payload_expectation["sha256"],
                    "byte_count": self.payload_expectation["byte_count"],
                }
            except (HarnessError, requests.exceptions.RequestException) as error:
                last_error = error
                time.sleep(5)
        raise HarnessError(
            "The deterministic payload was not ready before timeout."
        ) from last_error

    def record_payload_verification(self, *, kind: str, droplet: dict) -> dict:
        if kind not in {"source", "ui_restore"}:
            raise HarnessError("The payload witness kind is invalid.")
        resource_id = str(droplet.get("id") or "") if isinstance(droplet, dict) else ""
        name = str(droplet.get("name") or "") if isinstance(droplet, dict) else ""
        if not resource_id or not name:
            raise HarnessError("The payload witness has no exact Droplet identity.")
        return self.ledger.record(
            kind=f"{kind}_payload_witness",
            resource_id=resource_id,
            name=name,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "droplet_id": resource_id,
                "sha256": self.payload_expectation["sha256"],
                "byte_count": self.payload_expectation["byte_count"],
            },
            source_witness=f"payload:{kind}:{resource_id}",
        )

    def verify_snapshot(
        self,
        *,
        kind: str,
        source_id: str,
        snapshot_marker: str | None = None,
        marker: str | None = None,
    ):
        snapshot_marker, _restore_marker = _resolve_legacy_marker(
            snapshot_marker=snapshot_marker,
            restore_marker=None,
            legacy_marker=marker,
        )
        if not snapshot_marker:
            raise HarnessError("The snapshot backup marker is required.")
        resource_type = "droplet" if kind == "droplet" else "volume"
        source_kind = f"source_{resource_type}"
        source_entry = self.ledger.get(source_kind, str(source_id))
        if not source_entry or source_entry.get("cleanup_state") not in {
            "eligible",
            "failed",
        }:
            raise HarnessError("The snapshot source is not an active ledgered resource.")
        if resource_type == "droplet":
            payload_entry = self.ledger.get(
                "source_payload_witness", str(source_id)
            )
            if not payload_entry:
                raise HarnessError(
                    "The source Droplet payload was not durably proven ready before backup."
                )
        snapshot = find_exact_snapshot(
            headers=self.headers,
            marker=snapshot_marker,
            source_id=source_id,
            resource_type=resource_type,
        )
        if snapshot is None:
            raise HarnessError("The exact BackupSheep snapshot is not visible yet.")
        snapshot_id = str(snapshot["id"])
        snapshot_creation = {
            "name": str(snapshot.get("name") or ""),
            "resource_id": str(snapshot.get("resource_id") or ""),
            "resource_type": str(snapshot.get("resource_type") or ""),
        }
        snapshot_creation["immutable_fingerprint"] = _fingerprint(snapshot_creation)
        self.ledger.record(
            kind=f"ui_snapshot_{resource_type}",
            resource_id=snapshot_id,
            name=str(snapshot.get("name") or ""),
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                # Keep the legacy alias for old cleanup tooling. It is
                # deliberately identical to the explicit snapshot witness.
                "snapshot_marker": snapshot_marker,
                "marker": snapshot_marker,
                "source_id": str(source_id),
                "resource_type": resource_type,
                "creation_witness": snapshot_creation,
            },
            source_witness=(
                f"snapshot:{resource_type}:{source_id}:{snapshot_marker}"
            ),
        )
        return {
            "id": snapshot_id,
            "name": str(snapshot.get("name") or ""),
            "resource_id": str(snapshot.get("resource_id") or ""),
            "resource_type": str(snapshot.get("resource_type") or ""),
        }

    def verify_ui_restore(
        self,
        *,
        target_kind: str,
        provider_id: str,
        name: str,
        snapshot_id: str,
        run_tag: str,
        snapshot_marker: str | None = None,
        restore_marker: str | None = None,
        marker: str | None = None,
        expected_region: str | None = None,
        expected_size_gigabytes: int | None = None,
        attach_payload_firewall: bool = False,
        source_content_sha256: str | None = None,
        source_content_byte_count: int | None = None,
        restore_content_sha256: str | None = None,
        restore_content_byte_count: int | None = None,
    ) -> dict:
        if target_kind not in {"droplet", "volume"}:
            raise HarnessError("The UI restore target kind is invalid.")
        if target_kind == "droplet" and attach_payload_firewall:
            self._require_payload_firewall_attachment_gate()
        if target_kind == "volume":
            expected_region = str(expected_region or "").strip()
            expected_size_gigabytes = _positive_integer(expected_size_gigabytes)
            if expected_size_gigabytes is None:
                raise HarnessError(
                    "The expected UI volume restore size must be a positive integer."
                )
            if not expected_region:
                raise HarnessError(
                    "The expected UI volume restore region and positive size are required."
                )
            content_witness = None
            if any(
                value not in (None, "")
                for value in (
                    source_content_sha256,
                    source_content_byte_count,
                    restore_content_sha256,
                    restore_content_byte_count,
                )
            ):
                raise HarnessError(
                    "Caller-asserted volume hashes cannot establish FULL_E2E; use the native-volume live verifier."
                )
        elif expected_region is not None or expected_size_gigabytes is not None:
            raise HarnessError("Volume expectations cannot be used for a Droplet restore.")
        elif any(
            value not in (None, "")
            for value in (
                source_content_sha256,
                source_content_byte_count,
                restore_content_sha256,
                restore_content_byte_count,
            )
        ):
            raise HarnessError("Volume content witnesses cannot be used for a Droplet restore.")
        snapshot_marker, restore_marker = _resolve_legacy_marker(
            snapshot_marker=snapshot_marker,
            restore_marker=restore_marker,
            legacy_marker=marker,
        )
        snapshot_entry = self.ledger.get(
            f"ui_snapshot_{target_kind}", str(snapshot_id)
        )
        if not snapshot_entry or snapshot_entry.get("cleanup_state") not in {
            "eligible",
            "failed",
        }:
            raise HarnessError("The UI restore snapshot is not in the active ledger.")
        if run_tag != self.run_tag:
            raise HarnessError("The UI restore run tag does not match this harness run.")
        snapshot_ownership = snapshot_entry.get("ownership")
        stored_snapshot_marker = _stored_snapshot_marker(snapshot_ownership)
        if not snapshot_marker:
            # A legacy caller may omit the snapshot marker only when the exact
            # ledgered snapshot supplies one unambiguous witness. This does
            # not infer a restore marker from the snapshot marker.
            snapshot_marker = stored_snapshot_marker
        if not restore_marker:
            raise HarnessError("The UI restore marker is required.")
        if (
            not isinstance(snapshot_ownership, dict)
            or str(snapshot_ownership.get("team_uuid") or "")
            != str(self.account["team_uuid"])
            or str(snapshot_ownership.get("run_tag") or "") != self.run_tag
            or not snapshot_marker
            or stored_snapshot_marker != snapshot_marker
            or str(snapshot_ownership.get("source_id") or "") == ""
            or str(snapshot_ownership.get("resource_type") or "")
            != target_kind
        ):
            raise HarnessError(
                "The UI restore snapshot is not owned by this exact harness run."
            )
        witness = {
            "target_kind": target_kind,
            "provider_id": str(provider_id),
            "name": str(name),
            "marker": restore_marker,
            "run_tag": str(run_tag),
            "snapshot_id": str(snapshot_id),
        }
        if target_kind == "volume":
            witness.update(
                {
                    "expected_region": expected_region,
                    "expected_size_gigabytes": expected_size_gigabytes,
                }
            )
        plural = "droplets" if target_kind == "droplet" else "volumes"
        candidates = iter_collection(
            f"/v2/{plural}",
            plural,
            headers=self.headers,
            params={"tag_name": restore_marker},
        )
        selected = select_ui_restore_witness(candidates, witness)
        resource = self._read_resource(
            f"ui_restore_{target_kind}", str(provider_id)
        )
        if resource is None or not _restore_target_owned(resource, witness):
            raise HarnessError("The exact UI restore target failed direct read-back.")
        if str(selected.get("id")) != str(resource.get("id")):
            raise HarnessError("The UI restore inventory and direct ID disagree.")
        if target_kind == "volume":
            content_witness = self._live_native_volume_content_proof(
                source_volume_id=str(snapshot_ownership.get("source_id") or ""),
                restore_volume_id=str(provider_id),
                restore_resource=resource,
            )
        creation = _creation_witness(
            f"ui_restore_{target_kind}",
            resource,
            {
                "name": str(name),
                "region": _resource_region(resource),
                "tags": list(resource.get("tags") or []),
                "size": resource.get("size_slug") or resource.get("size"),
                "image": _resource_image(resource),
                "size_gigabytes": resource.get("size_gigabytes"),
            },
        )
        creation["immutable_fingerprint"] = _fingerprint(creation)
        ownership = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "snapshot_marker": snapshot_marker,
            "restore_marker": restore_marker,
            "snapshot_id": str(snapshot_id),
            "target_kind": target_kind,
            "source_tag": _digitalocean_source_tag(snapshot_id),
            "creation_witness": creation,
        }
        if target_kind == "volume":
            ownership.update(
                {
                    "expected_region": expected_region,
                    "expected_size_gigabytes": expected_size_gigabytes,
                    "expected_droplet_ids": [],
                }
            )
        verification_level = "CONTROL_PLANE_ONLY"
        guest_payload_witness = None
        if target_kind == "droplet" and attach_payload_firewall:
            self._attach_payload_firewall(str(provider_id))
            resource = self.wait_droplet_active(
                str(provider_id), kind="ui_restore_droplet"
            )
            self.wait_payload_ready(resource)
            guest_payload_witness = {
                "sha256": self.payload_expectation["sha256"],
                "byte_count": self.payload_expectation["byte_count"],
                "proof": "LIVE_GUEST_HTTP_READ",
            }
            # The byte-level guest proof becomes durable before cleanup
            # authority. A worker crash cannot leave an unverified target row.
            self.record_payload_verification(kind="ui_restore", droplet=resource)
            verification_level = "FULL_E2E"
        elif target_kind == "volume" and content_witness is not None:
            verification_level = "FULL_E2E"

        if verification_level != "FULL_E2E":
            return {
                "status": "CONTROL_PLANE_ONLY",
                "verification_level": "CONTROL_PLANE_ONLY",
                "cleanup_evidence_recorded": False,
                "provider_id": str(provider_id),
                "target_kind": target_kind,
                "snapshot_id": str(snapshot_id),
                "snapshot_marker": snapshot_marker,
                "restore_marker": restore_marker,
            }

        ownership.update(
            {
                "verification_level": "FULL_E2E",
                "cleanup_authorized": True,
            }
        )
        if target_kind == "droplet":
            ownership.update(
                {
                    "payload_sha256": self.payload_expectation["sha256"],
                    "payload_byte_count": self.payload_expectation["byte_count"],
                    "guest_payload_witness": guest_payload_witness,
                }
            )
        else:
            ownership["content_witness"] = content_witness
        self.ledger.record(
            kind=f"ui_restore_{target_kind}",
            resource_id=str(provider_id),
            name=str(name),
            ownership=ownership,
            source_witness=(
                f"ui-restore:{target_kind}:{snapshot_id}:{restore_marker}"
            ),
        )
        result = {
            "status": "FULL_E2E",
            "verification_level": "FULL_E2E",
            "cleanup_evidence_recorded": True,
            "provider_id": str(provider_id),
            "target_kind": target_kind,
            "snapshot_id": str(snapshot_id),
            "snapshot_marker": snapshot_marker,
            "restore_marker": restore_marker,
            "firewall_attached": target_kind == "droplet" and attach_payload_firewall,
        }
        if target_kind == "droplet":
            result["payload_verified"] = True
        else:
            result["content_verified"] = True
        return result

    @staticmethod
    def _spaces_key_hash(access_key: str) -> str:
        return hashlib.sha256(str(access_key).encode("utf-8")).hexdigest()

    @staticmethod
    def _spaces_key_owned(key: dict, *, name: str, access_key=None) -> bool:
        if not isinstance(key, dict):
            return False
        candidate = str(key.get("access_key") or "")
        if not candidate or str(key.get("name") or "") != str(name):
            return False
        if access_key is not None and candidate != str(access_key):
            return False
        grants = key.get("grants")
        if not isinstance(grants, list) or len(grants) != 1:
            return False
        grant = grants[0]
        return (
            isinstance(grant, dict)
            and str(grant.get("bucket") or "") == ""
            and str(grant.get("permission") or "") == "fullaccess"
        )

    def _spaces_keys(self, *, name: str) -> list[dict]:
        try:
            keys = _iter_provider_collection(
                "/v2/spaces/keys",
                "keys",
                "access_key",
                headers=self.headers,
                # The live API currently returns 404 instead of an empty list
                # when an unmatched ``name`` filter is supplied. Fetch the
                # bounded provider-linked inventory and match the exact name
                # locally so absence is not misclassified as resource 404.
                params={"sort": "created_at", "sort_direction": "asc"},
            )
        except DigitalOceanAPIError as error:
            if error.code == "PROVIDER_AUTH_FAILED":
                raise ScopedProviderRejection("spaces_key:read") from None
            raise
        exact = [item for item in keys if str(item.get("name") or "") == name]
        if len(exact) > 1:
            raise HarnessError("Multiple Spaces keys share the exact run-owned name.")
        return exact

    def _read_spaces_key(self, access_key: str) -> dict | None:
        try:
            payload = get_json(
                f"/v2/spaces/keys/{quote(str(access_key), safe='')}",
                headers=self.headers,
            )
        except DigitalOceanAPIError as error:
            if error.code == "PROVIDER_NOT_FOUND":
                return None
            if error.code == "PROVIDER_AUTH_FAILED":
                raise ScopedProviderRejection("spaces_key:read") from None
            raise
        key = payload.get("key") if isinstance(payload, dict) else None
        if key is None and isinstance(payload, dict):
            keys = payload.get("keys")
            if isinstance(keys, list) and len(keys) == 1:
                key = keys[0]
        if not isinstance(key, dict):
            raise HarnessError("DigitalOcean returned a malformed Spaces key read-back.")
        return key

    def _record_spaces_key(self, key: dict, request: dict) -> dict:
        access_key = str(key.get("access_key") or "")
        key_hash = self._spaces_key_hash(access_key)
        creation = {
            "name": str(request.get("name") or ""),
            "grants": request.get("grants") or [],
        }
        creation["immutable_fingerprint"] = _fingerprint(creation)
        return self.ledger.record(
            kind="spaces_key",
            resource_id=key_hash,
            name=str(key.get("name") or ""),
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "access_key_sha256": key_hash,
                "permission": "fullaccess",
                "request_fingerprint": _fingerprint(request),
                "creation_witness": creation,
            },
            source_witness=f"spaces-key:{key.get('name')}",
        )

    def ensure_spaces_key(self, bucket_name: str) -> tuple[dict, dict[str, str]]:
        if not self.spaces_apply:
            raise HarnessError(
                "Spaces setup requires BACKUPSHEEP_E2E_APPLY=YES and "
                "BACKUPSHEEP_E2E_SPACES_APPLY=YES."
            )
        kind = "spaces_key_create"
        name = _resource_name(self.run_id, "spaces-key")
        request = {
            "name": name,
            "grants": [{"bucket": "", "permission": "fullaccess"}],
        }
        fingerprint = _fingerprint(request)
        intent = self.intents.get(kind)
        candidates = self._spaces_keys(name=name)
        if candidates:
            candidate = candidates[0]
            access_key = str(candidate.get("access_key") or "")
            read_back = self._read_spaces_key(access_key)
            if not self._spaces_key_owned(read_back or {}, name=name, access_key=access_key):
                raise HarnessError("Spaces key ownership verification failed.")
            key_hash = self._spaces_key_hash(access_key)
            entry = self.ledger.get("spaces_key", key_hash)
            intent_matches = bool(
                intent
                and intent.get("request_boundary_crossed")
                and intent.get("name") == name
                and intent.get("request_fingerprint") == fingerprint
            )
            if entry is None and not intent_matches:
                raise HarnessError("An unledgered Spaces key matches the run name.")
            self._record_spaces_key(read_back, request)
            try:
                credentials = _read_runtime_secret(self.spaces_secret_path)
            except HarnessError:
                raise AmbiguousMutation(
                    "The run-owned Spaces key exists but its one-time secret is unavailable; "
                    "run exact Spaces cleanup before using a new run ID."
                ) from None
            if (
                credentials["access_key"] != access_key
                or credentials["bucket"] != bucket_name
                or credentials["region"] != self.region
                or credentials["endpoint_url"]
                != f"https://{self.region}.digitaloceanspaces.com"
            ):
                raise HarnessError("The protected Spaces credentials do not match the ledger.")
            if intent_matches:
                self.intents.clear(kind)
            return read_back, credentials
        if intent and intent.get("request_boundary_crossed"):
            raise AmbiguousMutation(
                "A prior Spaces key create is not visible yet; do not create another key."
            )
        self.intents.put(
            kind,
            {
                "marker": self.run_tag,
                "kind": "spaces_key",
                "name": name,
                "operation": "create",
                "request_fingerprint": fingerprint,
            },
        )
        self.intents.update(kind, request_boundary_crossed=True)
        payload = _mutation_response(
            "POST",
            "/v2/spaces/keys",
            headers=self.headers,
            body=request,
            required_scope="spaces_key:create_credentials",
        )
        created = payload.get("key") if isinstance(payload, dict) else None
        if not isinstance(created, dict):
            raise AmbiguousMutation(
                "DigitalOcean accepted the Spaces key create without a usable response."
            )
        access_key = str(created.get("access_key") or "")
        secret_key = str(created.get("secret_key") or "")
        if (
            not access_key
            or not secret_key
            or not self._spaces_key_owned(created, name=name, access_key=access_key)
        ):
            raise AmbiguousMutation(
                "DigitalOcean accepted the Spaces key create without complete credentials."
            )
        credentials = {
            "endpoint_url": f"https://{self.region}.digitaloceanspaces.com",
            "region": self.region,
            "bucket": bucket_name,
            "access_key": access_key,
            "secret_key": secret_key,
        }
        # The one-time secret is made durable before the non-secret API read-back.
        # Neither the access key nor secret is written to the resource ledger.
        _write_runtime_secret(self.spaces_secret_path, credentials)
        read_back = self._read_spaces_key(access_key)
        if not self._spaces_key_owned(read_back or {}, name=name, access_key=access_key):
            raise HarnessError("Spaces key ownership verification failed.")
        self._record_spaces_key(read_back, request)
        self.intents.clear(kind)
        return read_back, credentials

    @staticmethod
    def _spaces_ownership_payload(run_id: str, team_uuid: str) -> bytes:
        seed = hashlib.sha256(
            f"backupsheep-spaces-ownership:{team_uuid}:{run_id}".encode("utf-8")
        ).hexdigest()
        return f"BackupSheep Spaces ownership witness v1\n{seed}\n".encode("ascii")

    @staticmethod
    def _spaces_object_id(bucket: str, key: str, version_id: str) -> str:
        return hashlib.sha256(
            f"{bucket}\0{key}\0{version_id}".encode("utf-8")
        ).hexdigest()

    def _durable_spaces_prefix(self, bucket: str) -> str:
        entry = self.ledger.get("spaces_bucket", str(bucket))
        ownership = entry.get("ownership") if isinstance(entry, dict) else None
        prefix = ownership.get("prefix") if isinstance(ownership, dict) else None
        if not isinstance(prefix, str) or prefix != self.spaces_prefix:
            raise HarnessError(
                "The exact active BackupSheep Spaces prefix is not durably pinned."
            )
        return _spaces_prefix(prefix)

    def _record_spaces_object(
        self,
        *,
        kind: str,
        bucket: str,
        key: str,
        version_id: str,
        sha256: str,
        byte_count: int,
        etag: str,
        metadata: dict | None = None,
    ) -> dict:
        if kind not in SPACES_OBJECT_KINDS:
            raise HarnessError("The Spaces object kind is invalid.")
        if kind in {"spaces_ui_website_object", "spaces_ui_database_object"}:
            prefix = self._durable_spaces_prefix(bucket)
            _spaces_object_key(key, prefix)
            metadata = _spaces_ui_metadata(
                metadata,
                backup_id=(metadata or {}).get("backupsheep-backup-id")
                if isinstance(metadata, dict)
                else "",
                sha256=sha256,
                byte_count=byte_count,
            )
        object_id = self._spaces_object_id(bucket, key, version_id)
        return self.ledger.record(
            kind=kind,
            resource_id=object_id,
            name=key,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "bucket": bucket,
                "key": key,
                "version_id": version_id,
                "sha256": sha256,
                "byte_count": int(byte_count),
                "etag": str(etag).strip('"'),
                "metadata": dict(metadata or {}),
                "prefix": (
                    self.spaces_prefix
                    if kind in {"spaces_ui_website_object", "spaces_ui_database_object"}
                    else ""
                ),
            },
            source_witness=f"spaces-object:{bucket}:{kind}:{object_id}",
        )

    @staticmethod
    def _spaces_bucket_created_at(value: Any) -> str:
        if value is None:
            raise HarnessError("Spaces returned a bucket without a creation witness.")
        isoformat = getattr(value, "isoformat", None)
        created_at = isoformat() if callable(isoformat) else str(value).strip()
        if not created_at:
            raise HarnessError("Spaces returned a bucket without a creation witness.")
        return created_at

    def _spaces_buckets(self, client) -> list[dict[str, str]]:
        payload = _spaces_call(
            lambda: client.list_buckets(), required_scope="Spaces full access"
        )
        buckets = payload.get("Buckets") if isinstance(payload, dict) else None
        if not isinstance(buckets, list) or any(
            not isinstance(item, dict)
            or not item.get("Name")
            or item.get("CreationDate") is None
            for item in buckets
        ):
            raise HarnessError("Spaces returned a malformed bucket inventory.")
        normalized = [
            {
                "name": str(item["Name"]),
                "created_at": self._spaces_bucket_created_at(item["CreationDate"]),
            }
            for item in buckets
        ]
        names = [item["name"] for item in normalized]
        if len(names) != len(set(names)) or len(names) > SPACES_MAX_ITEMS:
            raise HarnessError("Spaces returned duplicate or excessive buckets.")
        return normalized

    def _spaces_bucket_names(self, client) -> list[str]:
        return [item["name"] for item in self._spaces_buckets(client)]

    def _verify_spaces_bucket_state(
        self, client, *, bucket: str, ownership: dict
    ) -> dict[str, str]:
        """Freshly prove exact bucket identity before reading any UI object."""

        if not isinstance(ownership, dict):
            raise HarnessError("The Spaces bucket ownership witness is malformed.")
        matches = [item for item in self._spaces_buckets(client) if item["name"] == bucket]
        if len(matches) != 1:
            raise HarnessError("The exact Spaces bucket is missing or ambiguous.")
        _spaces_call(
            lambda: client.head_bucket(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        location = _spaces_call(
            lambda: client.get_bucket_location(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        actual_region = (
            str(location.get("LocationConstraint") or "")
            if isinstance(location, dict)
            else ""
        )
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        status = (
            str(versioning.get("Status") or "")
            if isinstance(versioning, dict)
            else ""
        )
        expected_creation = {
            "bucket": bucket,
            "region": str(ownership.get("region") or ""),
            "prefix": str(ownership.get("prefix") or ""),
            "acl": "private",
            "versioning": "Enabled",
            "created_at": matches[0]["created_at"],
        }
        durable_creation = ownership.get("creation_witness")
        if (
            actual_region != expected_creation["region"]
            or status != "Enabled"
            or str(ownership.get("versioning") or "") != "Enabled"
            or not isinstance(durable_creation, dict)
            or durable_creation != {
                **expected_creation,
                "immutable_fingerprint": _fingerprint(expected_creation),
            }
        ):
            raise HarnessError("The current Spaces bucket state changed from its owned witness.")
        return {"region": actual_region, "versioning": status, **matches[0]}

    def _head_spaces_object(
        self, client, *, bucket: str, key: str, version_id: str
    ) -> dict | None:
        try:
            return client.head_object(
                Bucket=bucket, Key=key, VersionId=version_id
            )
        except Exception as error:
            if _spaces_error_code(error) == "PROVIDER_NOT_FOUND":
                return None
            return _spaces_call(lambda: (_ for _ in ()).throw(error))

    @staticmethod
    def _verify_spaces_head(head: dict, ownership: dict) -> None:
        if not isinstance(head, dict):
            raise HarnessError("Spaces returned malformed object metadata.")
        try:
            byte_count = int(head.get("ContentLength"))
        except (TypeError, ValueError):
            raise HarnessError("Spaces returned malformed object byte metadata.") from None
        if (
            byte_count != int(ownership["byte_count"])
            or str(head.get("ETag") or "").strip('"') != str(ownership["etag"])
            or str(head.get("VersionId") or "") != str(ownership["version_id"])
        ):
            raise HarnessError("Spaces object metadata does not match the durable witness.")
        expected_metadata = ownership.get("metadata") or {}
        actual_metadata = head.get("Metadata") or {}
        if not isinstance(expected_metadata, dict) or not isinstance(actual_metadata, dict):
            raise HarnessError("Spaces custom object metadata does not match.")
        def normalize(metadata):
            normalized = {}
            for key, value in metadata.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise HarnessError("Spaces custom object metadata does not match.")
                normalized_key = key.casefold()
                if normalized_key in normalized:
                    raise HarnessError("Spaces custom object metadata has duplicate keys.")
                normalized[normalized_key] = value
            return normalized

        expected_normalized = normalize(expected_metadata)
        actual_normalized = normalize(actual_metadata)
        if actual_normalized != expected_normalized:
            raise HarnessError("Spaces custom object metadata does not match.")

    def _verify_spaces_ownership_version(
        self, client, *, bucket: str, candidate: dict
    ) -> dict:
        """Prove the exact run marker version, metadata, hash, and bytes."""

        payload = self._spaces_ownership_payload(
            self.run_id, self.account["team_uuid"]
        )
        sha256 = hashlib.sha256(payload).hexdigest()
        key = ".backupsheep-e2e/ownership.bin"
        version_id = str(candidate.get("VersionId") or "")
        etag = str(candidate.get("ETag") or "").strip('"')
        metadata = {
            "backupsheep-run": self.run_id,
            "sha256": sha256,
            "byte-count": str(len(payload)),
        }
        ownership = {
            "version_id": version_id,
            "byte_count": len(payload),
            "etag": etag,
            "metadata": metadata,
        }
        if (
            str(candidate.get("Key") or "") != key
            or not version_id
            or version_id == "null"
            or not etag
        ):
            raise HarnessError("The Spaces ownership marker version is incomplete.")
        head = self._head_spaces_object(
            client, bucket=bucket, key=key, version_id=version_id
        )
        if head is None:
            raise HarnessError("The Spaces ownership marker version is missing.")
        self._verify_spaces_head(head, ownership)
        response = _spaces_call(
            lambda: client.get_object(
                Bucket=bucket, Key=key, VersionId=version_id
            ),
            required_scope="Spaces object read",
        )
        body = response.get("Body") if isinstance(response, dict) else None
        if body is None or not callable(getattr(body, "read", None)):
            raise HarnessError("Spaces returned a malformed ownership marker body.")
        try:
            observed = body.read(len(payload) + 1)
            if not isinstance(observed, bytes):
                raise HarnessError("Spaces returned a malformed ownership marker body.")
            trailing = body.read(1)
            if trailing:
                observed += trailing
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if (
            observed != payload
            or len(observed) != len(payload)
            or hashlib.sha256(observed).hexdigest() != sha256
        ):
            raise HarnessError("The Spaces ownership marker bytes or hash mismatched.")
        return {
            "key": key,
            "sha256": sha256,
            **ownership,
        }

    def _adopt_exact_spaces_ownership_marker(self, client, *, bucket: str) -> dict:
        """Adopt an ambiguous upload only from one exact durable marker version."""

        marker_rows = self.ledger.entries("spaces_ownership_object")
        active_rows = [
            row
            for row in marker_rows
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(marker_rows) > 1 or (marker_rows and len(active_rows) != 1):
            raise HarnessError("Spaces ownership marker ledger evidence is ambiguous.")
        payload = self._spaces_ownership_payload(
            self.run_id, self.account["team_uuid"]
        )
        sha256 = hashlib.sha256(payload).hexdigest()
        key = ".backupsheep-e2e/ownership.bin"
        metadata = {
            "backupsheep-run": self.run_id,
            "sha256": sha256,
            "byte-count": str(len(payload)),
        }
        request = {
            "bucket": bucket,
            "key": key,
            "sha256": sha256,
            "byte_count": len(payload),
            "metadata": metadata,
        }
        intent = self.intents.get("spaces_ownership_upload")
        intent_matches = bool(
            isinstance(intent, dict)
            and intent.get("request_boundary_crossed") is True
            and intent.get("name") == key
            and intent.get("request_fingerprint") == _fingerprint(request)
        )
        if intent is not None and not intent_matches:
            raise HarnessError("The Spaces ownership upload intent drifted.")
        if not active_rows and not intent_matches:
            raise HarnessError(
                "Ambiguous Spaces bucket recovery lacks the exact ownership upload intent."
            )
        inventory = self._spaces_inventory(client, bucket)
        candidates = [
            row
            for row in inventory["versions"]
            if str(row.get("Key") or "") == key
        ]
        marker_deletes = [
            row
            for row in inventory["delete_markers"]
            if str(row.get("Key") or "") == key
        ]
        if len(candidates) != 1 or marker_deletes:
            raise HarnessError(
                "Ambiguous Spaces bucket recovery requires one exact live ownership marker."
            )
        proof = self._verify_spaces_ownership_version(
            client, bucket=bucket, candidate=candidates[0]
        )
        if active_rows:
            ownership = active_rows[0].get("ownership") or {}
            if (
                ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or ownership.get("bucket") != bucket
                or ownership.get("key") != proof["key"]
                or ownership.get("version_id") != proof["version_id"]
                or ownership.get("sha256") != proof["sha256"]
                or ownership.get("byte_count") != proof["byte_count"]
                or ownership.get("etag") != proof["etag"]
                or ownership.get("metadata") != proof["metadata"]
            ):
                raise HarnessError(
                    "The durable Spaces ownership marker disagrees with fresh proof."
                )
        else:
            self._record_spaces_object(
                kind="spaces_ownership_object",
                bucket=bucket,
                key=proof["key"],
                version_id=proof["version_id"],
                sha256=proof["sha256"],
                byte_count=proof["byte_count"],
                etag=proof["etag"],
                metadata=proof["metadata"],
            )
        if intent_matches:
            self.intents.clear("spaces_ownership_upload")
        return proof

    def _verify_spaces_object_entry(
        self, kind: str, ownership: dict, *, bucket: str
    ) -> tuple[str, str]:
        if not isinstance(ownership, dict):
            raise HarnessError("The Spaces object ownership witness is malformed.")
        if (
            ownership.get("team_uuid") != self.account["team_uuid"]
            or ownership.get("run_tag") != self.run_tag
            or ownership.get("bucket") != bucket
        ):
            raise HarnessError("Spaces object cleanup ownership failed.")
        key = str(ownership.get("key") or "")
        version_id = str(ownership.get("version_id") or "")
        if not version_id or version_id == "null":
            raise HarnessError("The Spaces object version witness is missing.")
        if kind in {"spaces_ui_website_object", "spaces_ui_database_object"}:
            prefix = self._durable_spaces_prefix(bucket)
            if ownership.get("prefix") != prefix:
                raise HarnessError("The Spaces object prefix witness changed.")
            _spaces_object_key(key, prefix)
            metadata = ownership.get("metadata")
            _spaces_ui_metadata(
                metadata,
                backup_id=(metadata or {}).get("backupsheep-backup-id")
                if isinstance(metadata, dict)
                else "",
                sha256=str(ownership.get("sha256") or ""),
                byte_count=ownership.get("byte_count"),
            )
        elif kind == "spaces_ownership_object":
            if key != ".backupsheep-e2e/ownership.bin":
                raise HarnessError("The Spaces ownership object key changed.")
        else:
            raise HarnessError("The Spaces object kind is invalid.")
        if str(ownership.get("etag") or "") == "":
            raise HarnessError("The Spaces object ETag witness is missing.")
        try:
            if int(ownership.get("byte_count")) < 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HarnessError("The Spaces object byte witness is malformed.") from None
        return key, version_id

    def ensure_spaces_bucket(self) -> dict:
        if not self.spaces_apply:
            raise HarnessError(
                "Spaces setup requires BACKUPSHEEP_E2E_APPLY=YES and "
                "BACKUPSHEEP_E2E_SPACES_APPLY=YES."
            )
        bucket = _spaces_bucket_name(
            self.run_id, self.account["team_uuid"], self.region
        )
        _key, credentials = self.ensure_spaces_key(bucket)
        client = _spaces_client(credentials)
        kind = "spaces_bucket_create"
        request = {
            "bucket": bucket,
            "region": self.region,
            "acl": "private",
            "versioning": "Enabled",
            "prefix": self.spaces_prefix,
        }
        fingerprint = _fingerprint(request)
        intent = self.intents.get(kind)
        initial_buckets = self._spaces_buckets(client)
        present_matches = [item for item in initial_buckets if item["name"] == bucket]
        if len(present_matches) > 1:
            raise HarnessError("Multiple Spaces buckets share the exact run-owned name.")
        present = len(present_matches) == 1
        bucket_entry = self.ledger.get("spaces_bucket", bucket)
        intent_matches = bool(
            intent
            and intent.get("request_boundary_crossed")
            and intent.get("name") == bucket
            and intent.get("request_fingerprint") == fingerprint
            and intent.get("preflight_absent") is True
        )
        if present and bucket_entry is None and not intent_matches:
            raise HarnessError("An unledgered Spaces bucket matches the run name.")
        if not present and bucket_entry is not None:
            raise HarnessError("The ledgered Spaces bucket is missing; setup will not recreate it.")
        created_now = False
        recovered_marker = False
        if present and bucket_entry is not None:
            ownership = bucket_entry.get("ownership") or {}
            expected_creation = {
                "bucket": bucket,
                "region": self.region,
                "prefix": self.spaces_prefix,
                "acl": "private",
                "versioning": "Enabled",
                "created_at": present_matches[0]["created_at"],
            }
            if (
                bucket_entry.get("cleanup_state") not in {"eligible", "failed"}
                or ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or ownership.get("region") != self.region
                or ownership.get("prefix") != self.spaces_prefix
                or ownership.get("endpoint_sha256")
                != hashlib.sha256(credentials["endpoint_url"].encode("utf-8")).hexdigest()
                or ownership.get("access_key_sha256")
                != self._spaces_key_hash(credentials["access_key"])
                or ownership.get("request_fingerprint") != fingerprint
                or ownership.get("versioning") != "Enabled"
                or ownership.get("creation_witness")
                != {
                    **expected_creation,
                    "immutable_fingerprint": _fingerprint(expected_creation),
                }
            ):
                raise HarnessError(
                    "The present Spaces bucket durable ownership witness mismatched."
                )
            # This complete read-only check happens before any possible
            # versioning call. Drift is never repaired by mutating a same-name
            # bucket.
            self._verify_spaces_bucket_state(
                client, bucket=bucket, ownership=ownership
            )
        elif present and intent_matches:
            # A prior create response is not ownership. Recovery requires the
            # independently versioned run marker, including exact bytes/hash.
            self._adopt_exact_spaces_ownership_marker(client, bucket=bucket)
            recovered_marker = True
        if not present:
            if intent and intent.get("request_boundary_crossed"):
                raise AmbiguousMutation(
                    "A prior Spaces bucket create is not visible yet; do not retry it."
                )
            self.intents.put(
                kind,
                {
                    "marker": self.run_tag,
                    "kind": "spaces_bucket",
                    "name": bucket,
                    "operation": "create",
                    "request_fingerprint": fingerprint,
                    "preflight_absent": True,
                },
            )
            self.intents.update(kind, request_boundary_crossed=True)
            _spaces_call(
                lambda: client.create_bucket(Bucket=bucket, ACL="private"),
                mutation=True,
                required_scope="Spaces full access",
            )
            created_now = True
            current_after_create = [
                item for item in self._spaces_buckets(client) if item["name"] == bucket
            ]
            if len(current_after_create) != 1:
                raise AmbiguousMutation(
                    "Spaces accepted the bucket create but exact read-back is incomplete."
                )
        _spaces_call(
            lambda: client.head_bucket(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        location = _spaces_call(
            lambda: client.get_bucket_location(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        if (
            not isinstance(location, dict)
            or str(location.get("LocationConstraint") or "") != self.region
        ):
            raise HarnessError("Spaces bucket location does not match the requested region.")
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        versioning_status = (
            str(versioning.get("Status") or "")
            if isinstance(versioning, dict)
            else ""
        )
        if bucket_entry is None and (created_now or recovered_marker):
            if versioning_status != "Enabled":
                _spaces_call(
                    lambda: client.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={"Status": "Enabled"},
                    ),
                    mutation=True,
                    required_scope="Spaces full access",
                )
                versioning = _spaces_call(
                    lambda: client.get_bucket_versioning(Bucket=bucket),
                    required_scope="Spaces bucket read",
                )
                versioning_status = (
                    str(versioning.get("Status") or "")
                    if isinstance(versioning, dict)
                    else ""
                )
        if versioning_status != "Enabled":
            raise HarnessError("Spaces bucket versioning is not enabled.")
        current_buckets = [
            item for item in self._spaces_buckets(client) if item["name"] == bucket
        ]
        if len(current_buckets) != 1:
            raise HarnessError("The exact Spaces bucket creation witness is missing.")
        bucket_creation = {
            "bucket": bucket,
            "region": self.region,
            "prefix": self.spaces_prefix,
            "acl": "private",
            "versioning": "Enabled",
            "created_at": current_buckets[0]["created_at"],
        }
        ownership_key = ".backupsheep-e2e/ownership.bin"
        ownership_payload = self._spaces_ownership_payload(
            self.run_id, self.account["team_uuid"]
        )
        ownership_hash = hashlib.sha256(ownership_payload).hexdigest()
        existing_objects = self.ledger.entries("spaces_ownership_object")
        active_objects = [
            entry
            for entry in existing_objects
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(active_objects) > 1:
            raise HarnessError("Multiple active Spaces ownership objects are ledgered.")
        if active_objects:
            object_entry = active_objects[0]
            ownership = object_entry.get("ownership") or {}
            if (
                ownership.get("bucket") != bucket
                or ownership.get("key") != ownership_key
                or ownership.get("sha256") != ownership_hash
                or int(ownership.get("byte_count") or -1) != len(ownership_payload)
            ):
                raise HarnessError("The Spaces ownership object ledger has drifted.")
            proof = self._verify_spaces_ownership_version(
                client,
                bucket=bucket,
                candidate={
                    "Key": ownership_key,
                    "VersionId": ownership.get("version_id"),
                    "ETag": ownership.get("etag"),
                },
            )
            if proof["sha256"] != ownership_hash:
                raise HarnessError("The ledgered Spaces ownership marker hash changed.")
        else:
            object_metadata = {
                "backupsheep-run": self.run_id,
                "sha256": ownership_hash,
                "byte-count": str(len(ownership_payload)),
            }
            ownership_request = {
                "bucket": bucket,
                "key": ownership_key,
                "sha256": ownership_hash,
                "byte_count": len(ownership_payload),
                "metadata": object_metadata,
            }
            ownership_intent_key = "spaces_ownership_upload"
            ownership_intent = self.intents.get(ownership_intent_key)
            ownership_fingerprint = _fingerprint(ownership_request)
            inventory = self._spaces_inventory(client, bucket)
            candidate_versions = [
                row
                for row in inventory["versions"]
                if str(row.get("Key") or "") == ownership_key
            ]
            if len(candidate_versions) > 1:
                raise HarnessError(
                    "Multiple ownership-object versions exist; cleanup requires review."
                )
            ownership_intent_matches = bool(
                ownership_intent
                and ownership_intent.get("request_boundary_crossed")
                and ownership_intent.get("name") == ownership_key
                and ownership_intent.get("request_fingerprint")
                == ownership_fingerprint
            )
            if candidate_versions:
                if not ownership_intent_matches:
                    raise HarnessError(
                        "An unledgered Spaces object matches the ownership key."
                    )
                self._adopt_exact_spaces_ownership_marker(client, bucket=bucket)
            elif ownership_intent and ownership_intent.get(
                "request_boundary_crossed"
            ):
                raise AmbiguousMutation(
                    "A prior ownership-object upload is not visible; do not upload another version."
                )
            else:
                self.intents.put(
                    ownership_intent_key,
                    {
                        "marker": self.run_tag,
                        "kind": "spaces_ownership_object",
                        "name": ownership_key,
                        "operation": "put",
                        "request_fingerprint": ownership_fingerprint,
                    },
                )
                self.intents.update(
                    ownership_intent_key, request_boundary_crossed=True
                )
                put = _spaces_call(
                    lambda: client.put_object(
                        Bucket=bucket,
                        Key=ownership_key,
                        Body=ownership_payload,
                        ContentType="application/octet-stream",
                        Metadata=object_metadata,
                    ),
                    mutation=True,
                    required_scope="Spaces object write",
                )
                version_id = (
                    str(put.get("VersionId") or "")
                    if isinstance(put, dict)
                    else ""
                )
                etag = (
                    str(put.get("ETag") or "").strip('"')
                    if isinstance(put, dict)
                    else ""
                )
                if not version_id or not etag:
                    raise AmbiguousMutation(
                        "Spaces accepted the ownership upload without version metadata."
                    )
                proof = self._verify_spaces_ownership_version(
                    client,
                    bucket=bucket,
                    candidate={
                        "Key": ownership_key,
                        "VersionId": version_id,
                        "ETag": etag,
                    },
                )
                self._record_spaces_object(
                    kind="spaces_ownership_object",
                    bucket=bucket,
                    key=ownership_key,
                    version_id=version_id,
                    sha256=proof["sha256"],
                    byte_count=proof["byte_count"],
                    etag=proof["etag"],
                    metadata=proof["metadata"],
                )
                self.intents.clear(ownership_intent_key)
        key_entries = [
            entry
            for entry in self.ledger.entries("spaces_key")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(key_entries) != 1:
            raise HarnessError("One exact active Spaces key witness is required.")
        self.ledger.record(
            kind="spaces_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "region": self.region,
                "prefix": self.spaces_prefix,
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode("utf-8")
                ).hexdigest(),
                "access_key_sha256": key_entries[0]["resource_id"],
                "request_fingerprint": fingerprint,
                "versioning": "Enabled",
                "creation_witness": {
                    **bucket_creation,
                    "immutable_fingerprint": _fingerprint(bucket_creation),
                },
            },
            source_witness=f"spaces-bucket:{bucket}:{self.region}",
        )
        if self.intents.get(kind):
            self.intents.clear(kind)
        return {
            "status": "ready",
            "credentials_file": str(self.spaces_secret_path),
            "versioning": "enabled",
        }

    @staticmethod
    def _manifest_has_sensitive_keys(value: Any) -> bool:
        return _manifest_has_sensitive_keys(value)

    def verify_spaces_ui_uploads(self, manifest_path: str, *, maximum_bytes: int) -> dict:
        credentials = _read_runtime_secret(self.spaces_secret_path)
        bucket = credentials["bucket"]
        bucket_entry = self.ledger.get("spaces_bucket", bucket)
        if not bucket_entry or bucket_entry.get("cleanup_state") not in {
            "eligible",
            "failed",
        }:
            raise HarnessError("The Spaces bucket is not in the active ledger.")
        bucket_ownership = bucket_entry.get("ownership")
        if (
            not isinstance(bucket_ownership, dict)
            or str(bucket_ownership.get("team_uuid") or "")
            != str(self.account["team_uuid"])
            or str(bucket_ownership.get("run_tag") or "") != self.run_tag
            or str(bucket_ownership.get("region") or "") != credentials["region"]
            or str(bucket_ownership.get("access_key_sha256") or "")
            != self._spaces_key_hash(credentials["access_key"])
            or str(bucket_ownership.get("endpoint_sha256") or "")
            != hashlib.sha256(credentials["endpoint_url"].encode("utf-8")).hexdigest()
            or str(bucket_ownership.get("versioning") or "") != "Enabled"
            or bucket_ownership.get("prefix") != self.spaces_prefix
        ):
            raise HarnessError(
                "The Spaces bucket credentials do not match the durable run witness."
            )
        prefix = self._durable_spaces_prefix(bucket)
        normalized_objects = _load_ui_object_manifest(
            manifest_path,
            run_id=self.run_id,
            prefix=prefix,
            maximum_bytes=maximum_bytes,
        )
        client = _spaces_client(credentials)
        self._verify_spaces_bucket_state(
            client, bucket=bucket, ownership=bucket_ownership
        )
        inventory = self._spaces_inventory(client, bucket, prefix)
        verified = {"website": 0, "database": 0}
        for item in normalized_objects:
            object_kind = item["kind"]
            key = item["key"]
            version_id = item["version_id"]
            sha256 = item["sha256"]
            etag = item["etag"]
            byte_count = item["byte_count"]
            metadata = item["metadata"]
            versions = [
                row
                for row in inventory["versions"]
                if str(row.get("Key") or "") == key
            ]
            delete_markers = [
                row
                for row in inventory["delete_markers"]
                if str(row.get("Key") or "") == key
            ]
            if (
                len(versions) != 1
                or str(versions[0].get("VersionId") or "") != version_id
                or delete_markers
            ):
                raise HarnessError(
                    "The exact UI object has a missing, duplicate, or deleted provider version."
                )
            head = self._head_spaces_object(
                client, bucket=bucket, key=key, version_id=version_id
            )
            ownership = {
                "version_id": version_id,
                "byte_count": byte_count,
                "etag": etag,
                "metadata": metadata,
                "prefix": prefix,
            }
            if head is None:
                raise HarnessError("The exact UI upload version is missing.")
            self._verify_spaces_head(head, ownership)
            response = _spaces_call(
                lambda: client.get_object(
                    Bucket=bucket, Key=key, VersionId=version_id
                ),
                required_scope="Spaces object read",
            )
            body = response.get("Body") if isinstance(response, dict) else None
            if body is None or not callable(getattr(body, "read", None)):
                raise HarnessError("Spaces returned a malformed object body.")
            digest = hashlib.sha256()
            observed = 0
            try:
                while True:
                    chunk = body.read(min(1024 * 1024, maximum_bytes + 1 - observed))
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > maximum_bytes or observed > byte_count:
                        raise HarnessError("The UI upload exceeded its expected byte bound.")
                    digest.update(chunk)
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
            if observed != byte_count or digest.hexdigest() != sha256:
                raise HarnessError("The UI upload checksum or byte count does not match.")
            self._record_spaces_object(
                kind=f"spaces_ui_{object_kind}_object",
                bucket=bucket,
                key=key,
                version_id=version_id,
                sha256=sha256,
                byte_count=byte_count,
                etag=etag,
                metadata=metadata,
            )
            verified[object_kind] += 1
        if any(count == 0 for count in verified.values()):
            raise HarnessError("The manifest must prove one website and one database upload.")
        return {"status": "verified", "object_counts": verified}

    @staticmethod
    def _spaces_inventory(
        client, bucket: str, prefix: str | None = None
    ) -> dict[str, list[dict]]:
        if prefix is not None:
            prefix = _spaces_prefix(prefix)
        versions = []
        delete_markers = []
        seen = set()
        key_marker = version_marker = None
        for _page in range(SPACES_MAX_PAGES):
            request = {"Bucket": bucket, "MaxKeys": 1000}
            if prefix is not None:
                request["Prefix"] = prefix
            if key_marker:
                request["KeyMarker"] = key_marker
            if version_marker:
                request["VersionIdMarker"] = version_marker
            payload = _spaces_call(
                lambda request=request: client.list_object_versions(**request),
                required_scope="Spaces object version inventory",
            )
            page_versions = payload.get("Versions") or []
            page_markers = payload.get("DeleteMarkers") or []
            if not isinstance(page_versions, list) or not isinstance(page_markers, list):
                raise HarnessError("Spaces returned malformed version inventory.")
            for kind, rows, destination in (
                ("version", page_versions, versions),
                ("delete-marker", page_markers, delete_markers),
            ):
                for row in rows:
                    if not isinstance(row, dict):
                        raise HarnessError("Spaces returned malformed version inventory.")
                    identity = (kind, str(row.get("Key") or ""), str(row.get("VersionId") or ""))
                    if not identity[1] or not identity[2] or identity in seen:
                        raise HarnessError("Spaces returned duplicate version inventory.")
                    seen.add(identity)
                    destination.append(row)
                    if len(seen) > SPACES_MAX_ITEMS:
                        raise HarnessError("Spaces version inventory exceeded its bound.")
            if not payload.get("IsTruncated"):
                break
            next_key = str(payload.get("NextKeyMarker") or "")
            next_version = str(payload.get("NextVersionIdMarker") or "")
            if not next_key or (next_key, next_version) == (key_marker, version_marker):
                raise HarnessError("Spaces returned malformed version pagination.")
            key_marker, version_marker = next_key, next_version or None
        else:
            raise HarnessError("Spaces version inventory exceeded its page bound.")

        objects = []
        continuation = None
        for _page in range(SPACES_MAX_PAGES):
            request = {"Bucket": bucket, "MaxKeys": 1000}
            if prefix is not None:
                request["Prefix"] = prefix
            if continuation:
                request["ContinuationToken"] = continuation
            payload = _spaces_call(
                lambda request=request: client.list_objects_v2(**request),
                required_scope="Spaces object inventory",
            )
            rows = payload.get("Contents") or []
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise HarnessError("Spaces returned malformed object inventory.")
            objects.extend(rows)
            if len(objects) > SPACES_MAX_ITEMS:
                raise HarnessError("Spaces object inventory exceeded its bound.")
            if not payload.get("IsTruncated"):
                break
            next_token = str(payload.get("NextContinuationToken") or "")
            if not next_token or next_token == continuation:
                raise HarnessError("Spaces returned malformed object pagination.")
            continuation = next_token
        else:
            raise HarnessError("Spaces object inventory exceeded its page bound.")

        uploads = []
        key_marker = upload_marker = None
        for _page in range(SPACES_MAX_PAGES):
            request = {"Bucket": bucket, "MaxUploads": 1000}
            if prefix is not None:
                request["Prefix"] = prefix
            if key_marker:
                request["KeyMarker"] = key_marker
            if upload_marker:
                request["UploadIdMarker"] = upload_marker
            payload = _spaces_call(
                lambda request=request: client.list_multipart_uploads(**request),
                required_scope="Spaces multipart inventory",
            )
            rows = payload.get("Uploads") or []
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise HarnessError("Spaces returned malformed multipart inventory.")
            uploads.extend(rows)
            if len(uploads) > SPACES_MAX_ITEMS:
                raise HarnessError("Spaces multipart inventory exceeded its bound.")
            if not payload.get("IsTruncated"):
                break
            next_key = str(payload.get("NextKeyMarker") or "")
            next_upload = str(payload.get("NextUploadIdMarker") or "")
            if not next_key or not next_upload or (next_key, next_upload) == (
                key_marker,
                upload_marker,
            ):
                raise HarnessError("Spaces returned malformed multipart pagination.")
            key_marker, upload_marker = next_key, next_upload
        else:
            raise HarnessError("Spaces multipart inventory exceeded its page bound.")
        return {
            "versions": versions,
            "delete_markers": delete_markers,
            "objects": objects,
            "multipart_uploads": uploads,
        }

    def _adopt_pending_spaces_key_for_cleanup(self) -> None:
        if self.ledger.entries("spaces_key"):
            return
        intent = self.intents.get("spaces_key_create")
        if not intent or not intent.get("request_boundary_crossed"):
            return
        name = str(intent.get("name") or "")
        if not name:
            raise HarnessError("The pending Spaces key intent is malformed.")
        candidates = self._spaces_keys(name=name)
        if not candidates:
            raise AmbiguousMutation(
                "The pending Spaces key create has no exact witness; cleanup will not guess."
            )
        candidate = candidates[0]
        access_key = str(candidate.get("access_key") or "")
        read_back = self._read_spaces_key(access_key)
        if not self._spaces_key_owned(
            read_back or {}, name=name, access_key=access_key
        ):
            raise HarnessError("The pending Spaces key failed exact read-back.")
        request = {
            "name": name,
            "grants": [{"bucket": "", "permission": "fullaccess"}],
        }
        if intent.get("request_fingerprint") != _fingerprint(request):
            raise HarnessError("The pending Spaces key request fingerprint drifted.")
        self._record_spaces_key(read_back, request)

    def _adopt_pending_spaces_bucket_for_cleanup(self) -> None:
        if self.ledger.entries("spaces_bucket"):
            return
        intent = self.intents.get("spaces_bucket_create")
        if not intent or not intent.get("request_boundary_crossed"):
            return
        if intent.get("preflight_absent") is not True:
            raise HarnessError("The pending Spaces bucket lacks absence proof.")
        credentials = _read_runtime_secret(self.spaces_secret_path)
        bucket = str(intent.get("name") or "")
        if not bucket or credentials["bucket"] != bucket:
            raise HarnessError("The pending Spaces bucket and credentials disagree.")
        key_entries = [
            entry
            for entry in self.ledger.entries("spaces_key")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if (
            len(key_entries) != 1
            or self._spaces_key_hash(credentials["access_key"])
            != key_entries[0]["resource_id"]
        ):
            raise HarnessError("The pending Spaces bucket has no exact key witness.")
        client = _spaces_client(credentials)
        buckets = [item for item in self._spaces_buckets(client) if item["name"] == bucket]
        if len(buckets) != 1:
            raise AmbiguousMutation(
                "The pending Spaces bucket create is not visible; cleanup will not revoke its key."
            )
        _spaces_call(
            lambda: client.head_bucket(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        location = _spaces_call(
            lambda: client.get_bucket_location(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        if (
            not isinstance(location, dict)
            or str(location.get("LocationConstraint") or "") != credentials["region"]
        ):
            raise HarnessError("The pending Spaces bucket location witness changed.")
        request = {
            "bucket": bucket,
            "region": credentials["region"],
            "acl": "private",
            "versioning": "Enabled",
            "prefix": self.spaces_prefix,
        }
        request_fingerprint = _fingerprint(request)
        if intent.get("request_fingerprint") != request_fingerprint:
            raise HarnessError("The pending Spaces bucket request fingerprint drifted.")
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        status = str(versioning.get("Status") or "") if isinstance(versioning, dict) else ""
        if status != "Enabled":
            raise HarnessError("The pending Spaces bucket versioning witness changed.")
        bucket_creation = {
            "bucket": bucket,
            "region": credentials["region"],
            "prefix": self.spaces_prefix,
            "acl": "private",
            "versioning": "Enabled",
            "created_at": buckets[0]["created_at"],
        }

        # A create intent plus a same-name bucket is never enough cleanup
        # authority. Zero/duplicate marker versions, wrong metadata, or wrong
        # bytes leave the bucket unledgered and therefore undeletable.
        self._adopt_exact_spaces_ownership_marker(client, bucket=bucket)

        self.ledger.record(
            kind="spaces_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "region": credentials["region"],
                "prefix": self.spaces_prefix,
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode("utf-8")
                ).hexdigest(),
                "access_key_sha256": key_entries[0]["resource_id"],
                "request_fingerprint": request_fingerprint,
                "versioning": status,
                "creation_witness": {
                    **bucket_creation,
                    "immutable_fingerprint": _fingerprint(bucket_creation),
                },
            },
            source_witness=f"spaces-bucket:{bucket}:{credentials['region']}",
        )

    def cleanup_spaces(self) -> dict:
        if not (
            self.apply
            and self.cleanup_enabled
            and self.spaces_cleanup_enabled
        ):
            raise HarnessError(
                "Spaces cleanup requires BACKUPSHEEP_E2E_APPLY=YES, "
                "BACKUPSHEEP_E2E_CLEANUP=YES, and "
                "BACKUPSHEEP_E2E_SPACES_CLEANUP=YES."
            )
        retained_secret_before = None
        if self.spaces_secret_path.exists():
            if self.spaces_secret_path.is_symlink() or not self.spaces_secret_path.is_file():
                raise HarnessError("The Spaces credential path is not a regular file.")
            retained_secret_before = self.spaces_secret_path.read_bytes()
        self._adopt_pending_spaces_key_for_cleanup()
        self._adopt_pending_spaces_bucket_for_cleanup()
        bucket_entries = [
            entry
            for entry in self.ledger.entries("spaces_bucket")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        key_entries = [
            entry
            for entry in self.ledger.entries("spaces_key")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(bucket_entries) > 1 or len(key_entries) > 1:
            raise HarnessError("Spaces cleanup has ambiguous ledger resources.")
        bucket_entry = bucket_entries[0] if bucket_entries else None
        credentials = None
        if bucket_entry:
            credentials = _read_runtime_secret(self.spaces_secret_path)
            bucket = str(bucket_entry["resource_id"])
            ownership = bucket_entry.get("ownership") or {}
            if (
                credentials["bucket"] != bucket
                or credentials["region"] != ownership.get("region")
                or hashlib.sha256(credentials["endpoint_url"].encode()).hexdigest()
                != ownership.get("endpoint_sha256")
                or self._spaces_key_hash(credentials["access_key"])
                != ownership.get("access_key_sha256")
                or ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or ownership.get("prefix") != self.spaces_prefix
            ):
                self.ledger.mark_cleanup(
                    "spaces_bucket", bucket, state="manual_review"
                )
                raise HarnessError("Spaces bucket cleanup ownership verification failed.")
            bucket_creation = ownership.get("creation_witness")
            expected_bucket_creation = {
                "bucket": bucket,
                "region": ownership.get("region"),
                "prefix": self.spaces_prefix,
                "acl": "private",
                "versioning": "Enabled",
                "created_at": (
                    bucket_creation.get("created_at")
                    if isinstance(bucket_creation, dict)
                    else None
                ),
            }
            if (
                not isinstance(bucket_creation, dict)
                or not expected_bucket_creation["created_at"]
                or any(
                    bucket_creation.get(key) != value
                    for key, value in expected_bucket_creation.items()
                )
                or bucket_creation.get("immutable_fingerprint")
                != _fingerprint(expected_bucket_creation)
            ):
                self.ledger.mark_cleanup(
                    "spaces_bucket", bucket, state="manual_review"
                )
                raise HarnessError("Spaces bucket creation fingerprint changed.")
            client = _spaces_client(credentials)
            names = self._spaces_bucket_names(client)
            if bucket not in names:
                for kind in sorted(SPACES_OBJECT_KINDS):
                    for entry in self.ledger.entries(kind):
                        if entry.get("cleanup_state") in {"eligible", "failed"}:
                            object_id = str(entry.get("resource_id") or "")
                            ownership = entry.get("ownership") or {}
                            try:
                                key, version_id = self._verify_spaces_object_entry(
                                    kind, ownership, bucket=bucket
                                )
                            except HarnessError:
                                self.ledger.mark_cleanup(
                                    kind,
                                    object_id,
                                    state="manual_review",
                                )
                                raise HarnessError("Spaces object cleanup ownership failed.")
                            if self._spaces_object_id(bucket, key, version_id) != object_id:
                                self.ledger.mark_cleanup(
                                    kind, object_id, state="manual_review"
                                )
                                raise HarnessError("Spaces object identity ownership failed.")
                            self.ledger.mark_cleanup(kind, object_id, state="absent")
                self.ledger.mark_cleanup("spaces_bucket", bucket, state="absent")
            else:
                self._verify_spaces_bucket_state(
                    client, bucket=bucket, ownership=ownership
                )
                for kind in sorted(SPACES_OBJECT_KINDS):
                    for entry in self.ledger.entries(kind):
                        if entry.get("cleanup_state") not in {"eligible", "failed"}:
                            continue
                        object_id = str(entry.get("resource_id") or "")
                        object_ownership = entry.get("ownership") or {}
                        try:
                            key, version_id = self._verify_spaces_object_entry(
                                kind, object_ownership, bucket=bucket
                            )
                        except HarnessError:
                            self.ledger.mark_cleanup(
                                kind, object_id, state="manual_review"
                            )
                            raise HarnessError("Spaces object cleanup ownership failed.")
                        if self._spaces_object_id(bucket, key, version_id) != object_id:
                            self.ledger.mark_cleanup(
                                kind, object_id, state="manual_review"
                            )
                            raise HarnessError("Spaces object identity ownership failed.")
                        request = {
                            "bucket": bucket,
                            "key": key,
                            "version_id": version_id,
                            "etag": object_ownership.get("etag"),
                            "byte_count": object_ownership.get("byte_count"),
                            "metadata": object_ownership.get("metadata") or {},
                            "prefix": object_ownership.get("prefix") or "",
                        }
                        status = self._delete_spaces_with_intent(
                            intent_key=f"cleanup:spaces-object:{object_id}",
                            kind=kind,
                            name=key,
                            request=request,
                            read_back=lambda: self._head_spaces_object(
                                client,
                                bucket=bucket,
                                key=key,
                                version_id=version_id,
                            ),
                            verify_present=lambda head, ownership=object_ownership: self._verify_spaces_head(
                                head, ownership
                            ),
                            delete_call=lambda bucket=bucket, key=key, version_id=version_id: _spaces_call(
                                lambda: client.delete_object(
                                    Bucket=bucket, Key=key, VersionId=version_id
                                ),
                                mutation=True,
                                required_scope="Spaces object delete",
                            ),
                        )
                        self.ledger.mark_cleanup(
                            kind,
                            object_id,
                            state="absent" if status == "absent" else "deleted",
                        )
                inventory = self._spaces_inventory(client, bucket)
                if any(inventory.values()):
                    self.ledger.mark_cleanup(
                        "spaces_bucket",
                        bucket,
                        state="failed",
                        error=(
                            "Bucket contains unledgered versions, delete markers, "
                            "objects, or multipart uploads."
                        ),
                    )
                    raise InventoryNotEmpty(
                        "Spaces cleanup refused a non-empty or version-bearing bucket; "
                        "no unledgered item was deleted."
                    )
                bucket_request = {
                    "bucket": bucket,
                    "region": ownership.get("region"),
                    "prefix": ownership.get("prefix"),
                    "operation": "delete",
                }

                def read_bucket():
                    if bucket not in self._spaces_bucket_names(client):
                        return None
                    return {"name": bucket}

                def verify_bucket(_resource):
                    if any(self._spaces_inventory(client, bucket).values()):
                        raise InventoryNotEmpty(
                            "The Spaces bucket became non-empty during cleanup."
                        )

                status = self._delete_spaces_with_intent(
                    intent_key=f"cleanup:spaces-bucket:{bucket}",
                    kind="spaces_bucket",
                    name=bucket,
                    request=bucket_request,
                    read_back=read_bucket,
                    verify_present=verify_bucket,
                    delete_call=lambda: _spaces_call(
                        lambda: client.delete_bucket(Bucket=bucket),
                        mutation=True,
                        required_scope="Spaces full access",
                    ),
                )
                self.ledger.mark_cleanup(
                    "spaces_bucket",
                    bucket,
                    state="absent" if status == "absent" else "deleted",
                )

        retained_key = None
        if key_entries:
            key_entry = key_entries[0]
            name = str(key_entry.get("name") or "")
            ownership = key_entry.get("ownership") or {}
            if (
                ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or ownership.get("permission") != "fullaccess"
                or ownership.get("access_key_sha256")
                != key_entry.get("resource_id")
            ):
                self.ledger.mark_cleanup(
                    "spaces_key",
                    str(key_entry["resource_id"]),
                    state="manual_review",
                )
                raise HarnessError("Spaces key cleanup ownership verification failed.")
            key_creation = ownership.get("creation_witness")
            expected_key_creation = {
                "name": name,
                "grants": [{"bucket": "", "permission": "fullaccess"}],
            }
            if (
                not isinstance(key_creation, dict)
                or key_creation.get("name") != expected_key_creation["name"]
                or key_creation.get("grants") != expected_key_creation["grants"]
                or key_creation.get("immutable_fingerprint")
                != _fingerprint(expected_key_creation)
            ):
                self.ledger.mark_cleanup(
                    "spaces_key",
                    str(key_entry["resource_id"]),
                    state="manual_review",
                )
                raise HarnessError("Spaces key creation fingerprint changed.")
            candidates = self._spaces_keys(name=name)
            if candidates:
                candidate = candidates[0]
                access_key = str(candidate.get("access_key") or "")
                if self._spaces_key_hash(access_key) != key_entry["resource_id"]:
                    self.ledger.mark_cleanup(
                        "spaces_key",
                        str(key_entry["resource_id"]),
                        state="manual_review",
                    )
                    raise HarnessError("The exact Spaces key hash no longer matches.")
                read_back = self._read_spaces_key(access_key)
                def verify_key(current):
                    if not self._spaces_key_owned(
                        current or {}, name=name, access_key=access_key
                    ):
                        raise HarnessError("The exact Spaces key failed read-back.")
                    current_creation = {
                        "name": str(current.get("name") or ""),
                        "grants": current.get("grants") or [],
                    }
                    if (
                        current_creation != expected_key_creation
                        or _fingerprint(current_creation)
                        != key_creation.get("immutable_fingerprint")
                    ):
                        raise HarnessError(
                            "The Spaces key creation fingerprint changed."
                        )

                verify_key(read_back)
            # A user-retained key is intentionally not passed to any DELETE
            # helper. ``manual_review`` is the ledger's non-destructive terminal
            # state; the exact reason remains durable in cleanup_error.
            self.ledger.mark_cleanup(
                "spaces_key",
                str(key_entry["resource_id"]),
                state="manual_review",
                error=USER_RETAINED_BY_INSTRUCTION,
            )
            retained_key = str(key_entry["resource_id"])

        all_key_entries = self.ledger.entries("spaces_key")
        retained_entries = [
            entry
            for entry in all_key_entries
            if entry.get("cleanup_state") == "manual_review"
            and entry.get("cleanup_error") == USER_RETAINED_BY_INSTRUCTION
        ]
        if len(all_key_entries) > 1 or (
            all_key_entries and len(retained_entries) != 1
        ):
            raise HarnessError("The retained Spaces key evidence is ambiguous.")
        if retained_entries:
            retained_key = str(retained_entries[0].get("resource_id") or "")
            self.ledger.record(
                kind="spaces_key_retention_witness",
                resource_id=retained_key,
                name=str(retained_entries[0].get("name") or ""),
                ownership={
                    "team_uuid": self.account["team_uuid"],
                    "run_tag": self.run_tag,
                    "access_key_sha256": retained_key,
                    "status": USER_RETAINED_BY_INSTRUCTION,
                },
                source_witness=f"spaces-key-retained:{retained_key}",
            )

        if self.spaces_secret_path.is_symlink():
            raise HarnessError("The Spaces credential path became a symlink.")
        if all_key_entries and not self.spaces_secret_path.is_file():
            raise HarnessError(
                "The protected Spaces credential file must remain available by instruction."
            )
        retained_secret = (
            self.spaces_secret_path.read_bytes()
            if self.spaces_secret_path.is_file()
            else None
        )
        if all_key_entries and not retained_secret:
            raise HarnessError("The protected Spaces credential file is empty.")
        if retained_secret_before is not None and retained_secret != retained_secret_before:
            raise HarnessError("The protected Spaces credential file changed during cleanup.")

        # Bucket/object create intents can be retired after exact cleanup. A key
        # create intent is also complete once its retained read-back is ledgered;
        # no key-delete intent is created or cleared here.
        for intent_key in (
            "spaces_ownership_upload",
            "spaces_bucket_create",
            "spaces_key_create",
        ):
            if self.intents.get(intent_key):
                self.intents.clear(intent_key)
        return {
            "status": "completed",
            "spaces_key": {
                "status": USER_RETAINED_BY_INSTRUCTION,
                "resource_id": retained_key,
            },
            "credential_file": {"status": USER_RETAINED_BY_INSTRUCTION},
        }

    def native_volume_verifier_report(self) -> dict[str, Any]:
        """Provider-read-only inventory for the exact verifier workflow."""

        inventories = {
            "droplets": self._resources("native_volume_verifier_droplet"),
            "firewalls": self._resources("native_volume_verifier_firewall"),
            "volumes": self._resources("source_volume"),
        }
        droplet_name = _resource_name(self.run_id, "volume-verifier")
        firewall_name = _resource_name(self.run_id, "volume-verifier-firewall")
        droplets = [
            row
            for row in inventories["droplets"]
            if str(row.get("name") or "") == droplet_name
        ]
        firewalls = [
            row
            for row in inventories["firewalls"]
            if str(row.get("name") or "") == firewall_name
        ]
        if len(droplets) > 1 or len(firewalls) > 1:
            raise HarnessError("The native-volume verifier inventory is ambiguous.")
        source_evidence = self.ledger.entries(
            "native_volume_source_content_witness"
        )
        restore_evidence = self.ledger.entries(
            "native_volume_restore_content_witness"
        )
        full_restores = [
            row
            for row in self.ledger.entries("ui_restore_volume")
            if (row.get("ownership") or {}).get("verification_level") == "FULL_E2E"
            and (row.get("ownership") or {}).get("content_witness", {}).get(
                "proof"
            )
            == "LIVE_NATIVE_VOLUME_BYTE_PROOF"
        ]
        pending = self.intents.pending()
        return {
            "provider": "digitalocean",
            "mode": "provider-read-only-native-volume-verifier-report",
            "provider_mutation_count": 0,
            "run_id": self.run_id,
            "team": {
                "name": self.account["team_name"],
                "uuid": self.account["team_uuid"],
            },
            "complete_inventory": {
                key: len(value) for key, value in inventories.items()
            },
            "verifier_droplet": (
                {
                    "id": str(droplets[0].get("id") or ""),
                    "status": str(droplets[0].get("status") or ""),
                    "region": _resource_region(droplets[0]),
                }
                if droplets
                else None
            ),
            "verifier_firewall": (
                {
                    "id": str(firewalls[0].get("id") or ""),
                    "status": str(firewalls[0].get("status") or ""),
                    "droplet_ids": [
                        str(value) for value in firewalls[0].get("droplet_ids") or []
                    ],
                }
                if firewalls
                else None
            ),
            "source_live_witness_count": len(source_evidence),
            "restore_live_witness_count": len(restore_evidence),
            "full_e2e_restore_count": len(full_restores),
            "native_volume_pending_intents": sorted(
                key for key in pending if key.startswith("native-volume:")
            ),
            "key_material_present": self.native_volume_verifier_key_dir.is_dir()
            and not self.native_volume_verifier_key_dir.is_symlink(),
        }

    def _delete_native_volume_key_material(self, key_ownership: dict) -> None:
        path = self.native_volume_verifier_key_dir
        tombstone = path.with_name(path.name + ".cleanup")
        if path.exists() and tombstone.exists():
            raise HarnessError("Native-volume key cleanup has duplicate local artifacts.")
        active = tombstone if tombstone.exists() else path
        if not active.exists():
            return
        material = _read_native_volume_key_material(
            active, run_id=self.run_id, team_uuid=self.account["team_uuid"]
        )
        if (
            key_ownership.get("client_fingerprint")
            != material["client_fingerprint"]
            or key_ownership.get("host_fingerprint")
            != material["host_fingerprint"]
            or key_ownership.get("immutable_fingerprint")
            != _fingerprint(
                {
                    key: value
                    for key, value in key_ownership.items()
                    if key != "immutable_fingerprint"
                }
            )
        ):
            raise HarnessError("Native-volume local key cleanup ownership mismatched.")
        if active == path:
            os.replace(path, tombstone)
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            active = tombstone
        for filename in sorted(NATIVE_VOLUME_KEY_FILES):
            candidate = active / filename
            if candidate.is_symlink() or not candidate.is_file():
                raise HarnessError("Native-volume key cleanup encountered an unsafe file.")
            candidate.unlink()
        active.rmdir()
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    def cleanup_native_volume_verifier(self) -> dict[str, Any]:
        self._require_native_volume_gate()
        if (
            not self.cleanup_enabled
            or os.environ.get(NATIVE_VOLUME_VERIFIER_CLEANUP_ENV) != "YES"
        ):
            raise HarnessError(
                "Native-volume verifier cleanup lacks its exact cleanup gates."
            )
        already_cleaned = {}
        for kind in (
            "native_volume_verifier_droplet",
            "native_volume_verifier_firewall",
            "native_volume_verifier_key_witness",
        ):
            rows = self.ledger.entries(kind)
            if len(rows) != 1 or rows[0].get("cleanup_state") not in {
                "absent",
                "deleted",
            }:
                already_cleaned = {}
                break
            already_cleaned[kind] = rows[0]
        if already_cleaned:
            pending = self.intents.pending()
            native_pending = sorted(
                key
                for key in pending
                if key.startswith("native-volume:")
            )
            if (
                not native_pending
                and not self.native_volume_verifier_key_dir.exists()
                and not self.native_volume_verifier_key_dir.is_symlink()
            ):
                return {
                    "status": "VERIFIER_ALREADY_CLEANED",
                    "verifier_droplet_id": str(
                        already_cleaned[
                            "native_volume_verifier_droplet"
                        ].get("resource_id")
                        or ""
                    ),
                    "firewall_id": str(
                        already_cleaned["native_volume_verifier_firewall"].get(
                            "resource_id"
                        )
                        or ""
                    ),
                    "tokens_revoked": 0,
                    "spaces_credentials_changed": False,
                }
        full_rows = [
            row
            for row in self.ledger.entries("ui_restore_volume")
            if row.get("cleanup_state") in {"eligible", "failed"}
            and (row.get("ownership") or {}).get("verification_level") == "FULL_E2E"
            and (row.get("ownership") or {}).get("cleanup_authorized") is True
            and (row.get("ownership") or {}).get("content_witness", {}).get(
                "proof"
            )
            == "LIVE_NATIVE_VOLUME_BYTE_PROOF"
        ]
        if len(full_rows) != 1:
            raise HarnessError(
                "Verifier cleanup is forbidden before one exact live FULL_E2E volume proof."
            )
        full_ownership = full_rows[0].get("ownership") or {}
        content = full_ownership.get("content_witness") or {}
        restore_id = str(full_rows[0].get("resource_id") or "")
        source_id = str(content.get("source_volume_id") or "")
        source_live = self._validate_native_volume_evidence(
            self.ledger.get("native_volume_source_content_witness", source_id),
            kind="native_volume_source_content_witness",
            volume_id=source_id,
            proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
        )
        restore_live = self._validate_native_volume_evidence(
            self.ledger.get("native_volume_restore_content_witness", restore_id),
            kind="native_volume_restore_content_witness",
            volume_id=restore_id,
            proof="LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
        )
        if (
            content.get("source_evidence_fingerprint")
            != source_live["evidence_fingerprint"]
            or content.get("restore_evidence_fingerprint")
            != restore_live["evidence_fingerprint"]
            or restore_live.get("source_volume_id") != source_id
            or restore_live.get("verifier_droplet_id")
            != source_live.get("verifier_droplet_id")
        ):
            raise HarnessError("Verifier cleanup live byte evidence changed.")
        pending = self.intents.pending()
        unsafe_pending = sorted(
            key
            for key in pending
            if key.startswith("native-volume:")
            and not key.startswith("native-volume:cleanup:")
        )
        if unsafe_pending:
            raise HarnessError(
                "Verifier cleanup is forbidden while native-volume operations are uncertain."
            )
        droplet_entries = [
            row
            for row in self.ledger.entries("native_volume_verifier_droplet")
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        firewall_entries = [
            row
            for row in self.ledger.entries("native_volume_verifier_firewall")
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        key_entries = [
            row
            for row in self.ledger.entries("native_volume_verifier_key_witness")
            if row.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(droplet_entries) != 1 or len(firewall_entries) != 1 or len(key_entries) != 1:
            raise HarnessError("Verifier cleanup requires one exact resource of each kind.")
        droplet_entry = droplet_entries[0]
        firewall_entry = firewall_entries[0]
        key_entry = key_entries[0]
        verifier_id = str(droplet_entry.get("resource_id") or "")
        if verifier_id != str(source_live.get("verifier_droplet_id") or ""):
            raise HarnessError("Verifier cleanup Droplet ID changed from live proof.")
        volumes = self._resources("source_volume")
        if any(
            verifier_id in self._native_volume_attachment_ids(volume)
            for volume in volumes
        ):
            raise HarnessError("Verifier cleanup refused while any volume remains attached.")
        firewall_inventory = self._resources("native_volume_verifier_firewall")
        firewall_name = str(firewall_entry.get("name") or "")
        named_firewalls = [
            row
            for row in firewall_inventory
            if str(row.get("name") or "") == firewall_name
        ]
        if (
            len(named_firewalls) != 1
            or str(named_firewalls[0].get("id") or "")
            != str(firewall_entry.get("resource_id") or "")
        ):
            raise HarnessError(
                "Verifier cleanup found a missing, duplicate, or foreign named firewall."
            )
        assigned_firewalls = [
            row
            for row in firewall_inventory
            if verifier_id
            in {str(value) for value in row.get("droplet_ids") or []}
        ]
        if (
            len(assigned_firewalls) != 1
            or str(assigned_firewalls[0].get("id") or "")
            != str(firewall_entry.get("resource_id") or "")
        ):
            raise HarnessError(
                "Verifier cleanup found a missing, duplicate, or foreign firewall assignment."
            )
        firewall_id = str(firewall_entry.get("resource_id") or "")
        firewall_ownership = firewall_entry.get("ownership") or {}

        def read_firewall():
            return self._read_resource("native_volume_verifier_firewall", firewall_id)

        def verify_firewall(resource):
            creation = firewall_ownership.get("creation_witness")
            if (
                not self._native_volume_firewall_owned(
                    resource,
                    droplet_id=verifier_id,
                    firewall_id=firewall_id,
                )
                or firewall_ownership.get("team_uuid") != self.account["team_uuid"]
                or firewall_ownership.get("run_tag") != self.run_tag
                or firewall_ownership.get("probe_cidrs") != self.probe_cidrs
                or not isinstance(creation, dict)
                or creation.get("created_at")
                != str(resource.get("created_at") or "")
                or creation.get("immutable_fingerprint")
                != _fingerprint(
                    {
                        "name": str(resource.get("name") or ""),
                        "created_at": str(resource.get("created_at") or ""),
                        "rules_fingerprint": firewall_ownership.get(
                            "immutable_fingerprint"
                        ),
                        "verifier_droplet_id": verifier_id,
                    }
                )
            ):
                raise HarnessError("Verifier firewall cleanup ownership mismatched.")

        firewall = read_firewall()
        if firewall is None:
            self.ledger.mark_cleanup(
                "native_volume_verifier_firewall", firewall_id, state="absent"
            )
        else:
            verify_firewall(firewall)
            status = self._delete_provider_with_intent(
                intent_key=f"native-volume:cleanup:firewall:{firewall_id}",
                kind="native_volume_verifier_firewall",
                resource_id=firewall_id,
                name=str(firewall_entry.get("name") or ""),
                request={
                    "provider_id": firewall_id,
                    "verifier_droplet_id": verifier_id,
                    "immutable_fingerprint": firewall_ownership.get(
                        "immutable_fingerprint"
                    ),
                },
                read_back=read_firewall,
                verify_present=verify_firewall,
                delete_call=lambda: _mutation_response(
                    "DELETE",
                    f"/v2/firewalls/{quote(firewall_id, safe='')}",
                    headers=self.headers,
                    required_scope="firewall:delete",
                ),
            )
            self.ledger.mark_cleanup(
                "native_volume_verifier_firewall",
                firewall_id,
                state="absent" if status == "absent" else "deleted",
            )
        droplet_inventory = self._resources("native_volume_verifier_droplet")
        droplet_name = str(droplet_entry.get("name") or "")
        named_droplets = [
            row
            for row in droplet_inventory
            if str(row.get("name") or "") == droplet_name
        ]
        exact_droplets = [
            row
            for row in droplet_inventory
            if str(row.get("id") or "") == verifier_id
            and str(row.get("name") or "") == str(droplet_entry.get("name") or "")
        ]
        if (
            len(named_droplets) != 1
            or str(named_droplets[0].get("id") or "") != verifier_id
            or len(exact_droplets) != 1
        ):
            raise HarnessError(
                "Verifier cleanup found a missing, duplicate, or foreign named Droplet."
            )
        droplet_ownership = droplet_entry.get("ownership") or {}

        def read_droplet():
            return self._read_resource("native_volume_verifier_droplet", verifier_id)

        def verify_droplet(resource):
            self._verify_owned(
                "native_volume_verifier_droplet",
                resource,
                str(droplet_entry.get("name") or ""),
            )
            self._verify_creation_fingerprint(
                "native_volume_verifier_droplet", resource, droplet_ownership
            )
            if (
                droplet_ownership.get("team_uuid") != self.account["team_uuid"]
                or droplet_ownership.get("run_tag") != self.run_tag
                or droplet_ownership.get("key_witness_id")
                != key_entry.get("resource_id")
                or droplet_ownership.get("client_fingerprint")
                != (key_entry.get("ownership") or {}).get("client_fingerprint")
                or droplet_ownership.get("host_fingerprint")
                != (key_entry.get("ownership") or {}).get("host_fingerprint")
            ):
                raise HarnessError("Verifier Droplet cleanup ownership mismatched.")
            verifier_creation = droplet_ownership.get(
                "verifier_creation_witness"
            )
            expected_creation = {
                "resource_id": verifier_id,
                "name": str(resource.get("name") or ""),
                "created_at": str(resource.get("created_at") or ""),
                "region": _resource_region(resource),
                "size": str(
                    resource.get("size_slug") or resource.get("size") or ""
                ),
                "image": _resource_image(resource),
                "tags": sorted(str(tag) for tag in resource.get("tags") or []),
                "key_witness_id": key_entry.get("resource_id"),
                "ready_sha256": droplet_ownership.get("ready_sha256"),
            }
            expected_creation["immutable_fingerprint"] = _fingerprint(
                expected_creation
            )
            if verifier_creation != expected_creation:
                raise HarnessError(
                    "Verifier Droplet cleanup provider creation witness mismatched."
                )

        droplet = read_droplet()
        if droplet is None:
            self.ledger.mark_cleanup(
                "native_volume_verifier_droplet", verifier_id, state="absent"
            )
        else:
            if len(exact_droplets) != 1:
                raise HarnessError("Verifier Droplet is absent from complete inventory.")
            verify_droplet(droplet)
            status = self._delete_provider_with_intent(
                intent_key=f"native-volume:cleanup:droplet:{verifier_id}",
                kind="native_volume_verifier_droplet",
                resource_id=verifier_id,
                name=str(droplet_entry.get("name") or ""),
                request={
                    "provider_id": verifier_id,
                    "name": str(droplet_entry.get("name") or ""),
                    "creation_fingerprint": (
                        droplet_ownership.get("creation_witness") or {}
                    ).get("immutable_fingerprint"),
                },
                read_back=read_droplet,
                verify_present=verify_droplet,
                delete_call=lambda: _mutation_response(
                    "DELETE",
                    f"/v2/droplets/{quote(verifier_id, safe='')}",
                    headers=self.headers,
                    required_scope="droplet:delete",
                ),
            )
            self.ledger.mark_cleanup(
                "native_volume_verifier_droplet",
                verifier_id,
                state="absent" if status == "absent" else "deleted",
            )
        key_ownership = key_entry.get("ownership") or {}
        self._delete_native_volume_key_material(key_ownership)
        self.ledger.mark_cleanup(
            "native_volume_verifier_key_witness",
            str(key_entry.get("resource_id") or ""),
            state="deleted",
        )
        return {
            "status": "VERIFIER_CLEANED",
            "verifier_droplet_id": verifier_id,
            "firewall_id": firewall_id,
            "source_volume_id": source_id,
            "restore_volume_id": restore_id,
            "tokens_revoked": 0,
            "spaces_credentials_changed": False,
        }

    def _verify_ui_restore_cleanup_resource(
        self, kind: str, resource: dict, witness: dict, ownership: dict
    ) -> None:
        if not _restore_target_owned(resource, witness):
            raise HarnessError("UI restore cleanup ownership verification failed.")
        self._verify_creation_fingerprint(kind, resource, ownership)

    def cleanup(self):
        if not (self.apply and self.cleanup_enabled):
            raise HarnessError(
                "Cleanup requires BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES."
            )
        # UI restore targets are deleted only by their exact ledgered provider
        # IDs. No inventory result is ever promoted into cleanup authority.
        for kind in ("ui_restore_droplet", "ui_restore_volume"):
            target_kind = "droplet" if kind.endswith("droplet") else "volume"
            plural = "droplets" if target_kind == "droplet" else "volumes"
            for entry in reversed(self.ledger.entries(kind)):
                resource_id = str(entry.get("resource_id") or "")
                if not self.ledger.cleanup_eligible(kind, resource_id):
                    continue
                ownership = entry.get("ownership") or {}
                restore_marker = _stored_restore_marker(ownership)
                witness = {
                    "target_kind": target_kind,
                    "provider_id": resource_id,
                    "name": str(entry.get("name") or ""),
                    "marker": restore_marker,
                    "run_tag": str(ownership.get("run_tag") or ""),
                    "snapshot_id": str(ownership.get("snapshot_id") or ""),
                }
                if target_kind == "volume":
                    witness.update(
                        {
                            "expected_region": str(
                                ownership.get("expected_region") or ""
                            ),
                            "expected_size_gigabytes": ownership.get(
                                "expected_size_gigabytes"
                            ),
                        }
                    )
                if (
                    ownership.get("team_uuid") != self.account["team_uuid"]
                    or ownership.get("run_tag") != self.run_tag
                    or ownership.get("verification_level") != "FULL_E2E"
                    or ownership.get("cleanup_authorized") is not True
                ):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError(
                        "UI restore cleanup requires exact FULL_E2E ownership evidence."
                    )
                if target_kind == "droplet":
                    guest = ownership.get("guest_payload_witness")
                    if (
                        not isinstance(guest, dict)
                        or guest.get("sha256") != self.payload_expectation["sha256"]
                        or guest.get("byte_count")
                        != self.payload_expectation["byte_count"]
                        or guest.get("proof")
                        not in {"LIVE_GUEST_HTTP_READ", "EXACT_CLI_GUEST_WITNESS"}
                    ):
                        self.ledger.mark_cleanup(
                            kind, resource_id, state="manual_review"
                        )
                        raise HarnessError(
                            "UI Droplet cleanup lacks exact guest payload evidence."
                        )
                else:
                    content = ownership.get("content_witness")
                    snapshot_entry = self.ledger.get(
                        "ui_snapshot_volume", witness["snapshot_id"]
                    )
                    snapshot_source = (
                        (snapshot_entry.get("ownership") or {}).get("source_id")
                        if isinstance(snapshot_entry, dict)
                        else None
                    )
                    content_fingerprint_payload = copy.deepcopy(content)
                    if isinstance(content_fingerprint_payload, dict):
                        content_fingerprint = content_fingerprint_payload.pop(
                            "evidence_fingerprint", None
                        )
                    else:
                        content_fingerprint = None
                    source_live_entry = self.ledger.get(
                        "native_volume_source_content_witness",
                        str(snapshot_source or ""),
                    )
                    restore_live_entry = self.ledger.get(
                        "native_volume_restore_content_witness", resource_id
                    )
                    try:
                        source_live = self._validate_native_volume_evidence(
                            source_live_entry,
                            kind="native_volume_source_content_witness",
                            volume_id=str(snapshot_source or ""),
                            proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
                        )
                        restore_live = self._validate_native_volume_evidence(
                            restore_live_entry,
                            kind="native_volume_restore_content_witness",
                            volume_id=resource_id,
                            proof="LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
                        )
                    except HarnessError:
                        source_live = restore_live = None
                    if (
                        not isinstance(content, dict)
                        or content.get("proof") != "LIVE_NATIVE_VOLUME_BYTE_PROOF"
                        or content_fingerprint != _fingerprint(
                            content_fingerprint_payload
                        )
                        or str(content.get("source_volume_id") or "")
                        != str(snapshot_source or "")
                        or str(content.get("restore_volume_id") or "")
                        != resource_id
                        or not isinstance(source_live, dict)
                        or not isinstance(restore_live, dict)
                        or content.get("source_evidence_fingerprint")
                        != source_live.get("evidence_fingerprint")
                        or content.get("restore_evidence_fingerprint")
                        != restore_live.get("evidence_fingerprint")
                        or content.get("sha256") != source_live.get("sha256")
                        or restore_live.get("sha256") != source_live.get("sha256")
                        or content.get("read_only_restore") is not True
                    ):
                        self.ledger.mark_cleanup(
                            kind, resource_id, state="manual_review"
                        )
                        raise HarnessError(
                            "UI volume cleanup lacks exact live byte-content evidence."
                        )
                resource = self._read_resource(kind, resource_id)
                if resource is None:
                    self.ledger.mark_cleanup(kind, resource_id, state="absent")
                    continue
                if not _restore_target_owned(resource, witness):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError("UI restore cleanup ownership verification failed.")
                if target_kind == "volume":
                    fresh_content = self._live_native_volume_content_proof(
                        source_volume_id=str(snapshot_source or ""),
                        restore_volume_id=resource_id,
                        restore_resource=resource,
                    )
                    if fresh_content != content:
                        self.ledger.mark_cleanup(
                            kind, resource_id, state="manual_review"
                        )
                        raise HarnessError(
                            "UI volume cleanup live byte evidence changed."
                        )
                try:
                    self._verify_creation_fingerprint(kind, resource, ownership)
                except HarnessError:
                    self.ledger.mark_cleanup(kind, resource_id, state="manual_review")
                    raise
                status = self._delete_provider_with_intent(
                    intent_key=f"cleanup:{kind}:{resource_id}",
                    kind=kind,
                    resource_id=resource_id,
                    name=str(entry.get("name") or ""),
                    request={
                        "provider_id": resource_id,
                        "target_kind": target_kind,
                        "name": str(entry.get("name") or ""),
                        "snapshot_id": witness["snapshot_id"],
                        "restore_marker": restore_marker,
                    },
                    read_back=lambda: self._read_resource(kind, resource_id),
                    verify_present=lambda current: (
                        self._verify_ui_restore_cleanup_resource(
                            kind, current, witness, ownership
                        )
                    ),
                    delete_call=lambda: _mutation_response(
                        "DELETE",
                        f"/v2/{plural}/{quote(resource_id, safe='')}",
                        headers=self.headers,
                    ),
                )
                self.ledger.mark_cleanup(
                    kind,
                    resource_id,
                    state="absent" if status == "absent" else "deleted",
                )
                if kind == "ui_restore_droplet":
                    payload_entry = self.ledger.get(
                        "ui_restore_payload_witness", resource_id
                    )
                    if payload_entry and payload_entry.get("cleanup_state") in {
                        "eligible",
                        "failed",
                    }:
                        self.ledger.mark_cleanup(
                            "ui_restore_payload_witness",
                            resource_id,
                            state="deleted",
                        )

        # Snapshot cleanup is likewise ID-only and linked back to an exact
        # ledgered source. Snapshot inventory is never used for deletion.
        for kind in ("ui_snapshot_droplet", "ui_snapshot_volume"):
            for entry in reversed(self.ledger.entries(kind)):
                resource_id = str(entry.get("resource_id") or "")
                if not self.ledger.cleanup_eligible(kind, resource_id):
                    continue
                ownership = entry.get("ownership") or {}
                snapshot_marker = _stored_snapshot_marker(ownership)
                if (
                    ownership.get("team_uuid") != self.account["team_uuid"]
                    or ownership.get("run_tag") != self.run_tag
                    or ownership.get("resource_type")
                    != kind.removeprefix("ui_snapshot_")
                ):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError("Snapshot cleanup ledger ownership failed.")
                def read_snapshot():
                    try:
                        payload = get_json(
                            f"/v2/snapshots/{quote(resource_id, safe='')}",
                            headers=self.headers,
                        )
                    except DigitalOceanAPIError as error:
                        if error.code == "PROVIDER_NOT_FOUND":
                            return None
                        raise
                    snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
                    if not isinstance(snapshot, dict):
                        raise HarnessError("DigitalOcean returned a malformed snapshot.")
                    return snapshot

                def verify_snapshot(snapshot):
                    if (
                        str(snapshot.get("id") or "") != resource_id
                        or str(snapshot.get("name") or "") != snapshot_marker
                        or str(snapshot.get("resource_id") or "")
                        != str(ownership.get("source_id") or "")
                        or str(snapshot.get("resource_type") or "")
                        != str(ownership.get("resource_type") or "")
                    ):
                        raise HarnessError("Snapshot cleanup ownership verification failed.")
                    creation = ownership.get("creation_witness")
                    expected = {
                        "name": snapshot_marker,
                        "resource_id": str(ownership.get("source_id") or ""),
                        "resource_type": str(ownership.get("resource_type") or ""),
                    }
                    if (
                        not isinstance(creation, dict)
                        or any(creation.get(key) != value for key, value in expected.items())
                        or creation.get("immutable_fingerprint") != _fingerprint(expected)
                    ):
                        raise HarnessError("Snapshot creation fingerprint changed.")

                snapshot = read_snapshot()
                if snapshot is None:
                    self.ledger.mark_cleanup(kind, resource_id, state="absent")
                    continue
                try:
                    verify_snapshot(snapshot)
                except HarnessError:
                    self.ledger.mark_cleanup(kind, resource_id, state="manual_review")
                    raise
                status = self._delete_provider_with_intent(
                    intent_key=f"cleanup:{kind}:{resource_id}",
                    kind=kind,
                    resource_id=resource_id,
                    name=snapshot_marker,
                    request={
                        "provider_id": resource_id,
                        "snapshot_marker": snapshot_marker,
                        "source_id": str(ownership.get("source_id") or ""),
                        "resource_type": str(ownership.get("resource_type") or ""),
                    },
                    read_back=read_snapshot,
                    verify_present=verify_snapshot,
                    delete_call=lambda: _mutation_response(
                        "DELETE",
                        f"/v2/snapshots/{quote(resource_id, safe='')}",
                        headers=self.headers,
                    ),
                )
                self.ledger.mark_cleanup(
                    kind,
                    resource_id,
                    state="absent" if status == "absent" else "deleted",
                )

        for kind in ("source_volume", "source_droplet"):
            for entry in reversed(self.ledger.entries(kind)):
                resource_id = str(entry.get("resource_id") or "")
                if not self.ledger.cleanup_eligible(kind, resource_id):
                    continue
                ownership = entry.get("ownership") or {}
                if (
                    ownership.get("team_uuid") != self.account["team_uuid"]
                    or ownership.get("run_tag") != self.run_tag
                ):
                    self.ledger.mark_cleanup(kind, resource_id, state="manual_review")
                    raise HarnessError("Ledger ownership no longer matches the active team/run.")
                resource = self._read_resource(kind, resource_id)
                if resource is None:
                    self.ledger.mark_cleanup(kind, resource_id, state="absent")
                    continue
                self._verify_owned(kind, resource, str(entry.get("name") or ""))
                try:
                    self._verify_creation_fingerprint(kind, resource, ownership)
                except HarnessError:
                    self.ledger.mark_cleanup(kind, resource_id, state="manual_review")
                    raise
                plural = "droplets" if kind == "source_droplet" else "volumes"

                def verify_source(current):
                    self._verify_owned(kind, current, str(entry.get("name") or ""))
                    self._verify_creation_fingerprint(kind, current, ownership)

                status = self._delete_provider_with_intent(
                    intent_key=f"cleanup:{kind}:{resource_id}",
                    kind=kind,
                    resource_id=resource_id,
                    name=str(entry.get("name") or ""),
                    request={
                        "provider_id": resource_id,
                        "kind": kind,
                        "name": str(entry.get("name") or ""),
                    },
                    read_back=lambda: self._read_resource(kind, resource_id),
                    verify_present=verify_source,
                    delete_call=lambda: _mutation_response(
                        "DELETE",
                        f"/v2/{plural}/{quote(resource_id, safe='')}",
                        headers=self.headers,
                    ),
                )
                self.ledger.mark_cleanup(
                    kind,
                    resource_id,
                    state="absent" if status == "absent" else "deleted",
                )
                if kind == "source_droplet":
                    payload_entry = self.ledger.get(
                        "source_payload_witness", resource_id
                    )
                    if payload_entry and payload_entry.get("cleanup_state") in {
                        "eligible",
                        "failed",
                    }:
                        self.ledger.mark_cleanup(
                            "source_payload_witness",
                            resource_id,
                            state="deleted",
                        )

        for entry in self.ledger.entries("payload_firewall"):
            resource_id = str(entry.get("resource_id") or "")
            if not self.ledger.cleanup_eligible("payload_firewall", resource_id):
                continue
            ownership = entry.get("ownership") or {}
            if (
                ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or ownership.get("probe_cidrs") != self.probe_cidrs
            ):
                self.ledger.mark_cleanup(
                    "payload_firewall", resource_id, state="manual_review"
                )
                raise HarnessError("Payload firewall cleanup ledger ownership failed.")
            firewall = self._read_resource("payload_firewall", resource_id)
            if firewall is None:
                self.ledger.mark_cleanup(
                    "payload_firewall", resource_id, state="absent"
                )
                continue
            normalized = dict(firewall)
            normalized["outbound_rules"] = [
                {**rule, "sources": rule.get("destinations")}
                for rule in firewall.get("outbound_rules") or []
                if isinstance(rule, dict)
            ]
            if not self._firewall_owned(
                normalized,
                firewall_id=resource_id,
                allowed_droplet_ids=self._firewall_allowed_droplet_ids(),
                require_empty_droplet_ids=True,
            ):
                self.ledger.mark_cleanup(
                    "payload_firewall", resource_id, state="manual_review"
                )
                raise HarnessError("Payload firewall has foreign rules or assignments.")
            immutable_fingerprint = self._firewall_immutable_fingerprint(normalized)
            creation = ownership.get("creation_witness")
            if (
                ownership.get("immutable_fingerprint") != immutable_fingerprint
                or not isinstance(creation, dict)
                or creation.get("name") != str(firewall.get("name") or "")
                or creation.get("rules_fingerprint") != immutable_fingerprint
                or creation.get("immutable_fingerprint") != immutable_fingerprint
                or creation.get("source_droplet_id")
                != str(ownership.get("source_droplet_id") or "")
            ):
                self.ledger.mark_cleanup(
                    "payload_firewall", resource_id, state="manual_review"
                )
                raise HarnessError("Payload firewall creation fingerprint changed.")

            def read_firewall():
                return self._read_resource("payload_firewall", resource_id)

            def verify_firewall(current):
                current_normalized = dict(current or {})
                current_normalized["outbound_rules"] = [
                    {**rule, "sources": rule.get("destinations")}
                    for rule in current.get("outbound_rules") or []
                    if isinstance(rule, dict)
                ]
                if not self._firewall_owned(
                    current_normalized,
                    firewall_id=resource_id,
                    allowed_droplet_ids=self._firewall_allowed_droplet_ids(),
                    require_empty_droplet_ids=True,
                ) or self._firewall_immutable_fingerprint(current_normalized) != immutable_fingerprint:
                    raise HarnessError("Payload firewall ownership changed during cleanup.")

            status = self._delete_provider_with_intent(
                intent_key=f"cleanup:payload-firewall:{resource_id}",
                kind="payload_firewall",
                resource_id=resource_id,
                name=str(firewall.get("name") or ""),
                request={
                    "provider_id": resource_id,
                    "name": str(firewall.get("name") or ""),
                    "immutable_fingerprint": immutable_fingerprint,
                },
                read_back=read_firewall,
                verify_present=verify_firewall,
                delete_call=lambda: _mutation_response(
                    "DELETE",
                    f"/v2/firewalls/{quote(resource_id, safe='')}",
                    headers=self.headers,
                ),
            )
            self.ledger.mark_cleanup(
                "payload_firewall",
                resource_id,
                state="absent" if status == "absent" else "deleted",
            )

        tag_entry = self.ledger.get("run_tag", self.run_tag)
        if tag_entry and self.ledger.cleanup_eligible("run_tag", self.run_tag):
            ownership = tag_entry.get("ownership") or {}
            if (
                ownership.get("team_uuid") != self.account["team_uuid"]
                or ownership.get("run_tag") != self.run_tag
                or tag_entry.get("name") != self.run_tag
            ):
                self.ledger.mark_cleanup(
                    "run_tag", self.run_tag, state="manual_review"
                )
                raise HarnessError("Run-tag ledger ownership verification failed.")
            tag = self._read_run_tag()
            if tag is None:
                self.ledger.mark_cleanup("run_tag", self.run_tag, state="absent")
                return
            resources = tag.get("resources") or {}
            if not isinstance(resources, dict):
                raise HarnessError("DigitalOcean returned malformed run-tag resources.")
            counts = []
            for value in resources.values():
                if isinstance(value, dict) and value.get("count") is not None:
                    try:
                        counts.append(int(value["count"]))
                    except (TypeError, ValueError) as error:
                        raise HarnessError(
                            "DigitalOcean returned malformed run-tag counts."
                        ) from error
            if any(count != 0 for count in counts):
                self.ledger.mark_cleanup(
                    "run_tag",
                    self.run_tag,
                    state="failed",
                    error="Run-owned resources are still tagged.",
                )
                raise HarnessError(
                    "The run tag still owns resources; delete exact snapshots/targets first."
                )
            def read_cleanup_tag():
                return self._read_run_tag()

            def verify_cleanup_tag(current):
                if str(current.get("name") or "") != self.run_tag:
                    raise HarnessError("Run-tag cleanup ownership changed.")
                current_resources = current.get("resources") or {}
                if not isinstance(current_resources, dict):
                    raise HarnessError("DigitalOcean returned malformed run-tag resources.")
                for value in current_resources.values():
                    if isinstance(value, dict) and value.get("count") is not None:
                        try:
                            if int(value["count"]) != 0:
                                raise HarnessError(
                                    "The run tag still owns resources; cleanup stopped."
                                )
                        except (TypeError, ValueError) as error:
                            raise HarnessError(
                                "DigitalOcean returned malformed run-tag counts."
                            ) from error

            status = self._delete_provider_with_intent(
                intent_key=f"cleanup:run-tag:{self.run_tag}",
                kind="run_tag",
                resource_id=self.run_tag,
                name=self.run_tag,
                request={"tag": self.run_tag, "operation": "delete"},
                read_back=read_cleanup_tag,
                verify_present=verify_cleanup_tag,
                delete_call=lambda: _mutation_response(
                    "DELETE",
                    f"/v2/tags/{quote(self.run_tag, safe='')}",
                    headers=self.headers,
                ),
            )
            self.ledger.mark_cleanup(
                "run_tag",
                self.run_tag,
                state="absent" if status == "absent" else "deleted",
            )


LEGACY_NORMALIZATION_APPLY_ENV = "BACKUPSHEEP_E2E_LEDGER_NORMALIZE"
USER_RETAINED_BY_INSTRUCTION = "USER_RETAINED_BY_INSTRUCTION"
LEGACY_NORMALIZATION_KINDS = {
    "source_droplet",
    "source_volume",
    "payload_firewall",
    "spaces_bucket",
    "spaces_key",
    "ui_snapshot_droplet",
    "ui_snapshot_volume",
}


def _read_local_json_artifact_bytes(
    path: Path, *, label: str, require_mode_0600: bool = False
) -> tuple[dict, bytes, str]:
    """Read one existing regular JSON file without creating local artifacts."""

    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("artifact is not a regular file")
        if require_mode_0600 and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError("artifact mode is not 0600")
        raw = path.read_bytes()
        payload = _strict_json_loads(raw, label=label)
    except HarnessError:
        raise
    except OSError as error:
        raise HarnessError(f"The local {label} artifact could not be read safely.") from error
    if not isinstance(payload, dict):
        raise HarnessError(f"The local {label} artifact is malformed.")
    return payload, raw, hashlib.sha256(raw).hexdigest()


def _read_local_json_artifact(path: Path, *, label: str) -> tuple[dict, str]:
    """Read one existing regular JSON file without creating locks or sidecars."""

    payload, _raw, sha256 = _read_local_json_artifact_bytes(path, label=label)
    return payload, sha256


def _normalization_string_list(
    values: Any, *, label: str, allow_empty: bool = False
) -> list[str]:
    if not isinstance(values, list):
        raise HarnessError(f"The {label} witness must be an explicit list.")
    normalized = []
    for value in values:
        if isinstance(value, bool) or value in (None, ""):
            raise HarnessError(f"The {label} witness contains an invalid value.")
        item = str(value)
        if item != item.strip() or not item:
            raise HarnessError(f"The {label} witness contains an invalid value.")
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        raise HarnessError(f"The {label} witness contains duplicates.")
    if not normalized and not allow_empty:
        raise HarnessError(f"The {label} witness cannot be empty.")
    return sorted(normalized)


def _normalization_tags(resource: dict, *, label: str) -> list[str]:
    tags = resource.get("tags") if isinstance(resource, dict) else None
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise HarnessError(f"The {label} provider tag witness is malformed.")
    return _normalization_string_list(tags, label=f"{label} provider tags", allow_empty=True)


def _normalization_created_at(resource: dict, *, label: str) -> str:
    value = resource.get("created_at") if isinstance(resource, dict) else None
    created_at = str(value or "")
    if not created_at or created_at != created_at.strip():
        raise HarnessError(f"The {label} provider creation timestamp is missing.")
    return created_at


def _normalization_json_bytes(payload: dict) -> bytes:
    try:
        return (
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise HarnessError("The normalized ledger is not canonicalizable.") from error


def _open_existing_normalization_lock(path: Path):
    handle = None
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("lock is not a regular file")
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError("lock mode is not 0600")
        descriptor = os.open(path, os.O_RDONLY)
        handle = os.fdopen(descriptor, "rb", closefd=True)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return handle
    except (OSError, BlockingIOError) as error:
        if handle is not None:
            handle.close()
        raise HarnessError(
            "Legacy normalization requires the existing idle mode-0600 harness locks."
        ) from error


@contextmanager
def _normalization_artifact_locks(ledger_path: Path):
    """Hold existing harness locks without creating or writing any artifact."""

    ledger_lock = ledger_path.with_name(ledger_path.name + ".lock")
    handles = []
    try:
        handles.append(_open_existing_normalization_lock(ledger_lock))
        intent_path = ledger_path.with_name(
            ledger_path.name + ".mutation-intents.json"
        )
        if intent_path.exists():
            intent_lock = intent_path.with_name(intent_path.name + ".lock")
            handles.append(_open_existing_normalization_lock(intent_lock))
        yield intent_path
    finally:
        for handle in reversed(handles):
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


def _normalization_intent_report(
    intent_path: Path, *, run_id: str, scope: str
) -> dict[str, Any]:
    if not intent_path.exists():
        return {"exists": False, "pending_count": 0, "sha256": None}
    intents, _raw, intent_sha256 = _read_local_json_artifact_bytes(
        intent_path,
        label="DigitalOcean mutation intent",
        require_mode_0600=True,
    )
    if (
        intents.get("schema") != 1
        or intents.get("provider") != "digitalocean"
        or intents.get("run_id") != run_id
        or intents.get("scope") != scope
        or not isinstance(intents.get("pending"), dict)
        or any(
            not isinstance(key, str) or not isinstance(value, dict)
            for key, value in intents.get("pending", {}).items()
        )
    ):
        raise HarnessError("The local DigitalOcean mutation intent is malformed.")
    if intents["pending"]:
        raise HarnessError(
            "Legacy normalization is forbidden while provider mutation intents are pending."
        )
    return {"exists": True, "pending_count": 0, "sha256": intent_sha256}


def _atomic_replace_normalized_ledger(
    path: Path, *, expected_sha256: str, original_raw: bytes, replacement: bytes
) -> None:
    """Replace only the ledger, atomically, after a final exact byte check."""

    if hashlib.sha256(original_raw).hexdigest() != expected_sha256:
        raise HarnessError("The original ledger SHA-256 witness is malformed.")
    try:
        current = path.read_bytes()
    except OSError as error:
        raise HarnessError("The DigitalOcean ledger changed before normalization.") from error
    if current != original_raw or hashlib.sha256(current).hexdigest() != expected_sha256:
        raise HarnessError("The DigitalOcean ledger changed before normalization.")

    descriptor = None
    temporary = None
    directory_fd = None
    replaced = False
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.normalize.", dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(replacement)
            output.flush()
            os.fsync(output.fileno())
        if path.is_symlink() or not path.is_file():
            raise HarnessError("The DigitalOcean ledger changed before normalization.")
        if path.read_bytes() != original_raw:
            raise HarnessError("The DigitalOcean ledger changed before normalization.")
        os.replace(temporary, path)
        temporary = None
        replaced = True
        try:
            os.fsync(directory_fd)
        except OSError as error:
            # Best-effort atomic rollback preserves the caller-visible bytes if
            # the directory durability barrier itself fails.
            rollback_fd, rollback = tempfile.mkstemp(
                prefix=f".{path.name}.rollback.", dir=path.parent
            )
            try:
                os.fchmod(rollback_fd, 0o600)
                with os.fdopen(rollback_fd, "wb") as output:
                    output.write(original_raw)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(rollback, path)
                rollback = None
                os.fsync(directory_fd)
                replaced = False
            finally:
                if rollback and os.path.exists(rollback):
                    os.unlink(rollback)
            raise HarnessError(
                "The normalized ledger durability barrier failed; original bytes were restored."
            ) from error
    except HarnessError:
        raise
    except OSError as error:
        if replaced:
            raise HarnessError(
                "The normalized ledger replacement encountered an unrecoverable local failure."
            ) from error
        raise HarnessError(
            "The normalized ledger could not be atomically persisted."
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_legacy_normalization_cli(args) -> str:
    prohibited = {
        "native_volume_verifier": bool(args.native_volume_verifier_action),
        "local_report": args.report,
        "provision_sources": args.provision_sources,
        "cleanup": args.cleanup,
        "ui_droplet_restore_verification": args.verify_ui_droplet_restore,
        "ui_volume_restore_verification": args.verify_ui_volume_restore,
        "ui_droplet_firewall_attachment": args.attach_ui_droplet_firewall,
        "spaces_setup": args.spaces_setup,
        "spaces_cleanup": args.spaces_cleanup,
        "spaces_object_verification": bool(args.spaces_ui_upload_manifest),
    }
    enabled = sorted(name for name, value in prohibited.items() if value)
    if enabled:
        raise HarnessError(
            "Legacy normalization cannot be combined with operational flags: "
            + ", ".join(enabled)
        )
    run_id = require_run_id(args.run_id)
    if not args.ledger:
        raise HarnessError("Legacy normalization requires an existing --ledger.")
    if args.team_name != "Personal" or not str(args.team_uuid or ""):
        raise HarnessError(
            "Legacy normalization requires the exact Personal team name and UUID."
        )
    if not args.spaces_secret_file:
        raise HarnessError(
            "Legacy normalization requires the exact protected --spaces-secret-file."
        )
    if args.normalize_legacy_ledger == "report":
        if args.normalization_report_sha256:
            raise HarnessError(
                "The dry normalization report cannot accept an apply report SHA-256."
            )
    elif args.normalize_legacy_ledger == "apply":
        if os.environ.get(LEGACY_NORMALIZATION_APPLY_ENV) != "YES":
            raise HarnessError(
                f"Legacy normalization apply requires {LEGACY_NORMALIZATION_APPLY_ENV}=YES."
            )
        report_sha256 = str(args.normalization_report_sha256 or "").casefold()
        if not re.fullmatch(r"[0-9a-f]{64}", report_sha256):
            raise HarnessError(
                "Legacy normalization apply requires the exact dry-report SHA-256."
            )
    else:
        raise HarnessError("The legacy normalization mode is invalid.")

    required = {
        "droplet snapshot marker": args.droplet_snapshot_marker,
        "droplet source ID": args.droplet_source_id,
        "volume snapshot marker": args.volume_snapshot_marker,
        "volume source ID": args.volume_source_id,
        "firewall source Droplet ID": args.normalize_firewall_source_droplet_id,
        "UI Droplet restore ID": args.ui_droplet_restore_id,
        "UI Droplet restore name": args.ui_droplet_restore_name,
        "UI Droplet snapshot marker": args.ui_droplet_snapshot_marker,
        "UI Droplet restore marker": args.ui_droplet_restore_marker,
        "UI Droplet restore snapshot ID": args.ui_droplet_restore_snapshot_id,
        "UI Droplet restore run tag": args.ui_droplet_restore_run_tag,
        "UI Droplet expected region": args.ui_droplet_expected_region,
        "UI Droplet expected size": args.ui_droplet_expected_size,
        "UI Droplet payload SHA-256": args.ui_droplet_payload_sha256,
        "UI Droplet payload byte count": args.ui_droplet_payload_byte_count,
        "UI volume restore ID": args.ui_volume_restore_id,
        "UI volume restore name": args.ui_volume_restore_name,
        "UI volume snapshot marker": args.ui_volume_snapshot_marker,
        "UI volume restore marker": args.ui_volume_restore_marker,
        "UI volume restore snapshot ID": args.ui_volume_restore_snapshot_id,
        "UI volume restore run tag": args.ui_volume_restore_run_tag,
        "UI volume expected region": args.ui_volume_expected_region,
        "UI volume expected size": args.ui_volume_expected_size_gib,
        "source volume content SHA-256": args.ui_volume_source_content_sha256,
        "source volume content byte count": args.ui_volume_source_content_byte_count,
        "restored volume content SHA-256": args.ui_volume_restore_content_sha256,
        "restored volume content byte count": args.ui_volume_restore_content_byte_count,
    }
    missing = sorted(label for label, value in required.items() if value in (None, ""))
    if missing:
        raise HarnessError(
            "Legacy normalization requires exact CLI witnesses: " + ", ".join(missing)
        )
    if not args.normalize_ui_droplet_restore or not args.normalize_ui_volume_restore:
        raise HarnessError(
            "Both exact UI restore normalization confirmations are required."
        )
    if (
        not args.normalize_ui_droplet_guest_proof
        or not args.normalize_ui_volume_content_proof
    ):
        raise HarnessError(
            "Explicit Droplet guest and volume byte-content proof confirmations are required."
        )
    if args.ui_droplet_restore_run_tag != run_id or args.ui_volume_restore_run_tag != run_id:
        raise HarnessError("The UI restore run-tag witnesses must equal the exact run ID.")
    if args.normalize_firewall_source_droplet_id != str(args.droplet_source_id):
        raise HarnessError("The firewall source witness must equal the source Droplet ID.")
    if args.ui_droplet_snapshot_marker != args.droplet_snapshot_marker:
        raise HarnessError("The UI Droplet snapshot markers do not agree.")
    if args.ui_volume_snapshot_marker != args.volume_snapshot_marker:
        raise HarnessError("The UI volume snapshot markers do not agree.")
    if _positive_integer(args.volume_size_gib) is None:
        raise HarnessError("The source volume size must be a positive exact integer.")
    if _positive_integer(args.ui_volume_expected_size_gib) is None:
        raise HarnessError("The UI volume restore size must be a positive exact integer.")
    expected_payload = _payload_expectation(run_id)
    if (
        str(args.ui_droplet_payload_sha256 or "").casefold()
        != expected_payload["sha256"]
        or _positive_integer(args.ui_droplet_payload_byte_count)
        != expected_payload["byte_count"]
    ):
        raise HarnessError("The exact UI Droplet guest payload witness mismatched.")
    source_content_sha256 = str(
        args.ui_volume_source_content_sha256 or ""
    ).casefold()
    restore_content_sha256 = str(
        args.ui_volume_restore_content_sha256 or ""
    ).casefold()
    source_content_bytes = _positive_integer(
        args.ui_volume_source_content_byte_count
    )
    restore_content_bytes = _positive_integer(
        args.ui_volume_restore_content_byte_count
    )
    if (
        not re.fullmatch(r"[0-9a-f]{64}", source_content_sha256)
        or source_content_sha256 != restore_content_sha256
        or source_content_bytes is None
        or source_content_bytes != restore_content_bytes
    ):
        raise HarnessError("The source/restore volume byte-content witnesses mismatched.")

    volume_attachment_ids = _normalization_string_list(
        list(args.normalize_source_volume_droplet_id or []),
        label="source volume attachment",
        allow_empty=True,
    )
    if bool(args.normalize_source_volume_unattached) == bool(volume_attachment_ids):
        raise HarnessError(
            "Choose exactly one source-volume attachment witness: explicit unattached or IDs."
        )
    firewall_ids = _normalization_string_list(
        list(args.normalize_firewall_droplet_id or []),
        label="firewall attachment",
    )
    if str(args.droplet_source_id) not in firewall_ids:
        raise HarnessError("The exact firewall assignments must include the source Droplet.")
    allowed_firewall_ids = {
        str(args.droplet_source_id),
        str(args.ui_droplet_restore_id),
    }
    if not set(firewall_ids).issubset(allowed_firewall_ids):
        raise HarnessError("The firewall attachment witness includes a foreign Droplet.")
    if not set(volume_attachment_ids).issubset(allowed_firewall_ids):
        raise HarnessError("The source volume attachment witness includes a foreign Droplet.")
    droplet_tags = _normalization_string_list(
        list(args.normalize_ui_droplet_tag or []),
        label="UI Droplet restore tags",
    )
    volume_tags = _normalization_string_list(
        list(args.normalize_ui_volume_tag or []),
        label="UI volume restore tags",
    )
    for target_kind, snapshot_id, marker, tags in (
        (
            "droplet",
            args.ui_droplet_restore_snapshot_id,
            args.ui_droplet_restore_marker,
            droplet_tags,
        ),
        (
            "volume",
            args.ui_volume_restore_snapshot_id,
            args.ui_volume_restore_marker,
            volume_tags,
        ),
    ):
        required_tags = {
            run_id,
            str(marker),
            f"backupsheep-restore-{target_kind}",
            _digitalocean_source_tag(str(snapshot_id)),
        }
        if not required_tags.issubset(set(tags)):
            raise HarnessError(
                f"The exact UI {target_kind} tags omit a required ownership witness."
            )
    return run_id


class _LegacyLedgerNormalizer:
    """Build a complete legacy-ledger replacement from provider GET evidence."""

    def __init__(self, args, *, headers: dict, account: dict):
        self.args = args
        self.headers = headers
        self.account = account
        self.run_id = require_run_id(args.run_id)
        self.run_tag = self.run_id
        self.region = str(args.region)
        self.spaces_prefix = _spaces_prefix(args.spaces_prefix or f"ui/{self.run_id}/")
        self.spaces_secret_path = _validate_secret_path(Path(args.spaces_secret_file))
        self.payload_expectation = _payload_expectation(self.run_id)
        self.probe_cidrs = _probe_cidrs(list(args.probe_cidr or []))
        self.source_volume_droplet_ids = (
            []
            if args.normalize_source_volume_unattached
            else _normalization_string_list(
                list(args.normalize_source_volume_droplet_id or []),
                label="source volume attachment",
            )
        )
        self.firewall_droplet_ids = _normalization_string_list(
            list(args.normalize_firewall_droplet_id or []),
            label="firewall attachment",
        )
        self.ui_tags = {
            "droplet": _normalization_string_list(
                list(args.normalize_ui_droplet_tag or []),
                label="UI Droplet restore tags",
            ),
            "volume": _normalization_string_list(
                list(args.normalize_ui_volume_tag or []),
                label="UI volume restore tags",
            ),
        }
        self.reader = object.__new__(DigitalOceanHarness)
        self.reader.headers = headers
        self.reader.account = account
        self.reader.run_id = self.run_id
        self.reader.run_tag = self.run_tag
        self.reader.probe_cidrs = list(self.probe_cidrs)
        self.changes = []

    @staticmethod
    def _exact_inventory_id(inventory: list[dict], resource_id: str, *, label: str) -> dict:
        matches = [
            row
            for row in inventory
            if str(row.get("id") or "") == str(resource_id)
        ]
        if len(matches) != 1:
            raise HarnessError(f"The complete {label} inventory has zero or duplicate ID matches.")
        return matches[0]

    @staticmethod
    def _exact_named(inventory: list[dict], name: str, *, label: str) -> dict:
        matches = [row for row in inventory if str(row.get("name") or "") == name]
        if len(matches) != 1:
            raise HarnessError(f"The complete {label} inventory has zero or duplicate name matches.")
        return matches[0]

    @staticmethod
    def _require_identity(resource: dict, *, resource_id: str, name: str, label: str) -> None:
        if (
            not isinstance(resource, dict)
            or str(resource.get("id") or "") != str(resource_id)
            or str(resource.get("name") or "") != str(name)
        ):
            raise HarnessError(f"The exact {label} identity witness mismatched.")

    @staticmethod
    def _row_map(payload: dict) -> dict[str, list[dict]]:
        resources = payload.get("resources")
        if not isinstance(resources, list) or any(not isinstance(row, dict) for row in resources):
            raise HarnessError("The legacy DigitalOcean resource rows are malformed.")
        seen = set()
        mapping: dict[str, list[dict]] = {}
        for row in resources:
            kind = row.get("kind")
            resource_id = str(row.get("resource_id") or "")
            if not isinstance(kind, str) or not kind or not resource_id:
                raise HarnessError("The legacy DigitalOcean resource identity is malformed.")
            identity = (kind, resource_id)
            if identity in seen:
                raise HarnessError("The legacy DigitalOcean ledger has duplicate provider IDs.")
            seen.add(identity)
            mapping.setdefault(kind, []).append(row)
        return mapping

    @staticmethod
    def _active_legacy_row(rows: dict[str, list[dict]], kind: str) -> dict:
        matches = rows.get(kind) or []
        if len(matches) != 1:
            raise HarnessError(f"Legacy normalization requires one exact {kind} ledger row.")
        row = matches[0]
        if row.get("cleanup_state") not in {"eligible", "failed"}:
            raise HarnessError(f"The legacy {kind} row is not cleanup-active.")
        if not isinstance(row.get("ownership"), dict):
            raise HarnessError(f"The legacy {kind} ownership is malformed.")
        return row

    @staticmethod
    def _restore_row(rows: dict[str, list[dict]], kind: str, resource_id: str) -> dict | None:
        matches = rows.get(kind) or []
        if len(matches) > 1:
            raise HarnessError(f"The legacy {kind} rows are duplicated.")
        if not matches:
            return None
        row = matches[0]
        if str(row.get("resource_id") or "") != str(resource_id):
            raise HarnessError(f"The legacy {kind} row has a mismatched provider ID.")
        if row.get("cleanup_state") not in {"eligible", "failed"}:
            raise HarnessError(f"The legacy {kind} row is not cleanup-active.")
        if not isinstance(row.get("ownership"), dict):
            raise HarnessError(f"The legacy {kind} ownership is malformed.")
        return row

    def _merge_row(
        self,
        row: dict,
        *,
        kind: str,
        resource_id: str,
        name: str,
        ownership_proof: dict,
    ) -> dict:
        if (
            row.get("kind") != kind
            or str(row.get("resource_id") or "") != str(resource_id)
            or str(row.get("name") or "") != str(name)
        ):
            raise HarnessError(f"The legacy {kind} ledger identity mismatched.")
        normalized = copy.deepcopy(row)
        ownership = normalized.get("ownership")
        if not isinstance(ownership, dict):
            raise HarnessError(f"The legacy {kind} ownership is malformed.")
        for key, value in ownership_proof.items():
            current = ownership.get(key)
            missing = key not in ownership or current in (None, "")
            if key in {"creation_witness", "attachment_witness"} and current == {}:
                missing = True
            if not missing and current != value:
                raise HarnessError(f"The legacy {kind} {key} witness mismatched.")
            ownership[key] = copy.deepcopy(value)
        normalized["ownership"] = ownership
        self.changes.append(
            {
                "kind": kind,
                "resource_id": str(resource_id),
                "action": "normalized" if normalized != row else "verified",
                "creation_fingerprint": str(
                    ownership_proof.get("creation_witness", {}).get(
                        "immutable_fingerprint", ""
                    )
                ),
            }
        )
        return normalized

    def _new_restore_row(
        self,
        *,
        kind: str,
        resource: dict,
        ownership: dict,
        source_witness: str,
    ) -> dict:
        resource_id = str(resource.get("id") or "")
        name = str(resource.get("name") or "")
        row = {
            "kind": kind,
            "resource_id": resource_id,
            "name": name,
            "ownership": copy.deepcopy(ownership),
            "source_witness": source_witness,
            "created_at": _normalization_created_at(resource, label=kind),
            "cleanup_state": "eligible",
            "cleanup_error": "",
        }
        self.changes.append(
            {
                "kind": kind,
                "resource_id": resource_id,
                "action": "added",
                "creation_fingerprint": ownership["creation_witness"][
                    "immutable_fingerprint"
                ],
            }
        )
        return row

    @staticmethod
    def _replace_row(payload: dict, original: dict, replacement: dict) -> None:
        matches = [index for index, row in enumerate(payload["resources"]) if row is original]
        if len(matches) != 1:
            raise HarnessError("The in-memory legacy ledger row identity changed.")
        payload["resources"][matches[0]] = replacement

    def _source_droplet(
        self, payload: dict, rows: dict[str, list[dict]], inventory: list[dict]
    ) -> dict:
        kind = "source_droplet"
        row = self._active_legacy_row(rows, kind)
        resource_id = str(self.args.droplet_source_id)
        name = _resource_name(self.run_id, "droplet")
        if str(row.get("resource_id") or "") != resource_id:
            raise HarnessError("The source Droplet ledger ID mismatched its exact CLI witness.")
        inventory_row = self._exact_inventory_id(
            inventory, resource_id, label="Droplet"
        )
        named = [
            item
            for item in inventory
            if str(item.get("name") or "") == name
            and self.run_tag in (item.get("tags") or [])
        ]
        if len(named) != 1 or str(named[0].get("id") or "") != resource_id:
            raise HarnessError("The complete Droplet inventory has an ambiguous run-owned source.")
        direct = self.reader._read_resource(kind, resource_id)

        def proof(resource):
            self._require_identity(
                resource,
                resource_id=resource_id,
                name=name,
                label="source Droplet",
            )
            tags = _normalization_tags(resource, label="source Droplet")
            result = {
                "id": resource_id,
                "name": name,
                "tags": tags,
                "region": _resource_region(resource),
                "size": str(resource.get("size_slug") or ""),
                "image": _resource_image(resource),
            }
            expected = {
                "id": resource_id,
                "name": name,
                "tags": [self.run_tag],
                "region": self.region,
                "size": str(self.args.droplet_size),
                "image": str(self.args.droplet_image),
            }
            if result != expected:
                raise HarnessError("The source Droplet immutable provider witness mismatched.")
            return result

        if proof(inventory_row) != proof(direct or {}):
            raise HarnessError("The source Droplet inventory and direct read disagree.")
        request = {
            "name": name,
            "region": self.region,
            "size": str(self.args.droplet_size),
            "image": str(self.args.droplet_image),
            "tags": [self.run_tag],
            "user_data": _cloud_init(self.run_id, self.payload_expectation),
        }
        creation = _creation_witness(kind, direct or {}, request)
        creation["immutable_fingerprint"] = _fingerprint(creation)
        if not _creation_witness_matches(kind, direct or {}, creation):
            raise HarnessError("The source Droplet creation fingerprint could not be proven.")
        replacement = self._merge_row(
            row,
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "request_fingerprint": _fingerprint(request),
                "payload_sha256": self.payload_expectation["sha256"],
                "payload_byte_count": self.payload_expectation["byte_count"],
                "creation_witness": creation,
            },
        )
        self._replace_row(payload, row, replacement)
        return direct or {}

    def _source_volume(
        self, payload: dict, rows: dict[str, list[dict]], inventory: list[dict]
    ) -> dict:
        kind = "source_volume"
        row = self._active_legacy_row(rows, kind)
        resource_id = str(self.args.volume_source_id)
        name = _resource_name(self.run_id, "volume")
        if str(row.get("resource_id") or "") != resource_id:
            raise HarnessError("The source volume ledger ID mismatched its exact CLI witness.")
        inventory_row = self._exact_inventory_id(inventory, resource_id, label="volume")
        named = [
            item
            for item in inventory
            if str(item.get("name") or "") == name
            and self.run_tag in (item.get("tags") or [])
        ]
        if len(named) != 1 or str(named[0].get("id") or "") != resource_id:
            raise HarnessError("The complete volume inventory has an ambiguous run-owned source.")
        direct = self.reader._read_resource(kind, resource_id)

        def proof(resource):
            self._require_identity(
                resource,
                resource_id=resource_id,
                name=name,
                label="source volume",
            )
            size = _positive_integer(resource.get("size_gigabytes"))
            result = {
                "id": resource_id,
                "name": name,
                "tags": _normalization_tags(resource, label="source volume"),
                "region": _resource_region(resource),
                "size_gigabytes": size,
                "droplet_ids": _normalization_string_list(
                    resource.get("droplet_ids"),
                    label="source volume provider attachment",
                    allow_empty=True,
                ),
            }
            expected = {
                "id": resource_id,
                "name": name,
                "tags": [self.run_tag],
                "region": self.region,
                "size_gigabytes": int(self.args.volume_size_gib),
                "droplet_ids": self.source_volume_droplet_ids,
            }
            if result != expected:
                raise HarnessError("The source volume provider witness mismatched.")
            return result

        if proof(inventory_row) != proof(direct or {}):
            raise HarnessError("The source volume inventory and direct read disagree.")
        request = {
            "name": name,
            "region": self.region,
            "size_gigabytes": int(self.args.volume_size_gib),
            "tags": [self.run_tag],
        }
        creation = _creation_witness(kind, direct or {}, request)
        creation["immutable_fingerprint"] = _fingerprint(creation)
        if not _creation_witness_matches(kind, direct or {}, creation):
            raise HarnessError("The source volume creation fingerprint could not be proven.")
        attachment = {"droplet_ids": list(self.source_volume_droplet_ids)}
        attachment["fingerprint"] = _fingerprint(attachment)
        replacement = self._merge_row(
            row,
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "request_fingerprint": _fingerprint(request),
                "attachment_witness": attachment,
                "creation_witness": creation,
            },
        )
        self._replace_row(payload, row, replacement)
        return direct or {}

    def _snapshot(
        self,
        payload: dict,
        rows: dict[str, list[dict]],
        inventory: list[dict],
        *,
        target_kind: str,
    ) -> dict:
        kind = f"ui_snapshot_{target_kind}"
        row = self._active_legacy_row(rows, kind)
        marker = str(
            self.args.droplet_snapshot_marker
            if target_kind == "droplet"
            else self.args.volume_snapshot_marker
        )
        source_id = str(
            self.args.droplet_source_id
            if target_kind == "droplet"
            else self.args.volume_source_id
        )
        snapshot_id = str(row.get("resource_id") or "")
        restore_snapshot_id = str(
            self.args.ui_droplet_restore_snapshot_id
            if target_kind == "droplet"
            else self.args.ui_volume_restore_snapshot_id
        )
        if snapshot_id != restore_snapshot_id:
            raise HarnessError(f"The {target_kind} snapshot ledger and restore IDs disagree.")
        inventory_row = self._exact_inventory_id(
            inventory, snapshot_id, label="snapshot"
        )
        named = [item for item in inventory if str(item.get("name") or "") == marker]
        if len(named) != 1 or str(named[0].get("id") or "") != snapshot_id:
            raise HarnessError("The complete snapshot inventory has zero or duplicate marker matches.")
        direct_payload = get_json(
            f"/v2/snapshots/{quote(snapshot_id, safe='')}", headers=self.headers
        )
        direct = direct_payload.get("snapshot") if isinstance(direct_payload, dict) else None

        def proof(resource):
            expected = {
                "id": snapshot_id,
                "name": marker,
                "resource_id": source_id,
                "resource_type": target_kind,
            }
            actual = {
                "id": str(resource.get("id") or "") if isinstance(resource, dict) else "",
                "name": str(resource.get("name") or "") if isinstance(resource, dict) else "",
                "resource_id": str(resource.get("resource_id") or "") if isinstance(resource, dict) else "",
                "resource_type": str(resource.get("resource_type") or "") if isinstance(resource, dict) else "",
            }
            if actual != expected:
                raise HarnessError(f"The exact {target_kind} snapshot witness mismatched.")
            return actual

        if proof(inventory_row) != proof(direct or {}):
            raise HarnessError("The snapshot inventory and direct read disagree.")
        creation = {
            "name": marker,
            "resource_id": source_id,
            "resource_type": target_kind,
        }
        creation["immutable_fingerprint"] = _fingerprint(creation)
        replacement = self._merge_row(
            row,
            kind=kind,
            resource_id=snapshot_id,
            name=marker,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "snapshot_marker": marker,
                "marker": marker,
                "source_id": source_id,
                "resource_type": target_kind,
                "creation_witness": creation,
            },
        )
        self._replace_row(payload, row, replacement)
        return direct or {}

    def _restore(
        self,
        payload: dict,
        rows: dict[str, list[dict]],
        inventory: list[dict],
        *,
        target_kind: str,
    ) -> dict:
        kind = f"ui_restore_{target_kind}"
        prefix = "ui_droplet" if target_kind == "droplet" else "ui_volume"
        provider_id = str(getattr(self.args, f"{prefix}_restore_id"))
        name = str(getattr(self.args, f"{prefix}_restore_name"))
        snapshot_id = str(getattr(self.args, f"{prefix}_restore_snapshot_id"))
        snapshot_marker = str(getattr(self.args, f"{prefix}_snapshot_marker"))
        restore_marker = str(getattr(self.args, f"{prefix}_restore_marker"))
        expected_region = str(getattr(self.args, f"{prefix}_expected_region"))
        expected_size = (
            str(self.args.ui_droplet_expected_size)
            if target_kind == "droplet"
            else int(self.args.ui_volume_expected_size_gib)
        )
        source_id = str(
            self.args.droplet_source_id
            if target_kind == "droplet"
            else self.args.volume_source_id
        )
        if provider_id == source_id:
            raise HarnessError(f"The UI {target_kind} restore reuses its source provider ID.")
        row = self._restore_row(rows, kind, provider_id)
        witness = {
            "target_kind": target_kind,
            "provider_id": provider_id,
            "name": name,
            "marker": restore_marker,
            "run_tag": self.run_tag,
            "snapshot_id": snapshot_id,
        }
        if target_kind == "volume":
            witness.update(
                {
                    "expected_region": expected_region,
                    "expected_size_gigabytes": expected_size,
                }
            )
        marker_candidates = [
            item
            for item in inventory
            if restore_marker in (item.get("tags") or [])
        ]
        inventory_row = select_ui_restore_witness(marker_candidates, witness)
        direct = self.reader._read_resource(kind, provider_id)
        if direct is None or not _restore_target_owned(direct, witness):
            raise HarnessError(f"The exact UI {target_kind} restore direct read mismatched.")

        def proof(resource):
            self._require_identity(
                resource,
                resource_id=provider_id,
                name=name,
                label=f"UI {target_kind} restore",
            )
            result = {
                "id": provider_id,
                "name": name,
                "tags": _normalization_tags(resource, label=f"UI {target_kind} restore"),
                "region": _resource_region(resource),
                "created_at": _normalization_created_at(
                    resource, label=f"UI {target_kind} restore"
                ),
            }
            if target_kind == "droplet":
                result.update(
                    {
                        "size": str(resource.get("size_slug") or ""),
                        "image": _resource_image(resource),
                    }
                )
                expected = {
                    "id": provider_id,
                    "name": name,
                    "tags": self.ui_tags[target_kind],
                    "region": expected_region,
                    "created_at": result["created_at"],
                    "size": expected_size,
                    "image": snapshot_id,
                }
            else:
                result.update(
                    {
                        "size_gigabytes": _positive_integer(
                            resource.get("size_gigabytes")
                        ),
                        "droplet_ids": _normalization_string_list(
                            resource.get("droplet_ids"),
                            label="UI volume provider attachment",
                            allow_empty=True,
                        ),
                    }
                )
                expected = {
                    "id": provider_id,
                    "name": name,
                    "tags": self.ui_tags[target_kind],
                    "region": expected_region,
                    "created_at": result["created_at"],
                    "size_gigabytes": expected_size,
                    "droplet_ids": [],
                }
            if result != expected:
                raise HarnessError(f"The UI {target_kind} restore provider witness mismatched.")
            return result

        if proof(inventory_row) != proof(direct):
            raise HarnessError(f"The UI {target_kind} restore inventory and direct read disagree.")
        creation_request = {
            "name": name,
            "region": expected_region,
            "tags": list(self.ui_tags[target_kind]),
            "size": expected_size if target_kind == "droplet" else None,
            "image": snapshot_id if target_kind == "droplet" else None,
            "size_gigabytes": expected_size if target_kind == "volume" else None,
        }
        creation = _creation_witness(kind, direct, creation_request)
        creation["immutable_fingerprint"] = _fingerprint(creation)
        if not _creation_witness_matches(kind, direct, creation):
            raise HarnessError(f"The UI {target_kind} restore fingerprint could not be proven.")
        ownership = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "snapshot_marker": snapshot_marker,
            "restore_marker": restore_marker,
            "snapshot_id": snapshot_id,
            "target_kind": target_kind,
            "source_tag": _digitalocean_source_tag(snapshot_id),
            "expected_region": expected_region,
            "verification_level": "FULL_E2E",
            "cleanup_authorized": True,
            "creation_witness": creation,
        }
        if target_kind == "droplet":
            guest_witness = {
                "sha256": str(self.args.ui_droplet_payload_sha256).casefold(),
                "byte_count": int(self.args.ui_droplet_payload_byte_count),
                "proof": "EXACT_CLI_GUEST_WITNESS",
            }
            ownership.update(
                {
                    "expected_size": expected_size,
                    "payload_sha256": self.payload_expectation["sha256"],
                    "payload_byte_count": self.payload_expectation["byte_count"],
                    "guest_payload_witness": guest_witness,
                }
            )
        else:
            source_live_row = self._active_legacy_row(
                rows, "native_volume_source_content_witness"
            )
            restore_live_row = self._active_legacy_row(
                rows, "native_volume_restore_content_witness"
            )
            source_live = self.reader._validate_native_volume_evidence(
                source_live_row,
                kind="native_volume_source_content_witness",
                volume_id=source_id,
                proof="LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
            )
            restore_live = self.reader._validate_native_volume_evidence(
                restore_live_row,
                kind="native_volume_restore_content_witness",
                volume_id=provider_id,
                proof="LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
            )
            if (
                restore_live.get("source_volume_id") != source_id
                or restore_live.get("source_evidence_fingerprint")
                != source_live.get("evidence_fingerprint")
                or restore_live.get("verifier_droplet_id")
                != source_live.get("verifier_droplet_id")
                or restore_live.get("observed_region") != expected_region
                or source_live.get("observed_region") != expected_region
                or restore_live.get("offset_bytes")
                != source_live.get("offset_bytes")
                or restore_live.get("byte_count") != source_live.get("byte_count")
                or restore_live.get("sha256") != source_live.get("sha256")
                or restore_live.get("read_only") is not True
                or restore_live.get("guest_operation") != "read"
                or restore_live.get("guest_write_performed") is not False
                or str(self.args.ui_volume_source_content_sha256).casefold()
                != source_live.get("sha256")
                or str(self.args.ui_volume_restore_content_sha256).casefold()
                != restore_live.get("sha256")
                or int(self.args.ui_volume_source_content_byte_count)
                != source_live.get("byte_count")
                or int(self.args.ui_volume_restore_content_byte_count)
                != restore_live.get("byte_count")
            ):
                raise HarnessError(
                    "Legacy normalization lacks matching harness-generated live volume evidence."
                )
            content_witness = {
                "proof": "LIVE_NATIVE_VOLUME_BYTE_PROOF",
                "source_volume_id": source_id,
                "restore_volume_id": provider_id,
                "verifier_droplet_id": source_live["verifier_droplet_id"],
                "region": expected_region,
                "offset_bytes": source_live["offset_bytes"],
                "byte_count": source_live["byte_count"],
                "sha256": source_live["sha256"],
                "source_evidence_fingerprint": source_live[
                    "evidence_fingerprint"
                ],
                "restore_evidence_fingerprint": restore_live[
                    "evidence_fingerprint"
                ],
                "source_guest_observed_at": source_live["guest_observed_at"],
                "restore_guest_observed_at": restore_live["guest_observed_at"],
                "source_provider_detached_at": source_live[
                    "provider_detached_at"
                ],
                "restore_provider_detached_at": restore_live[
                    "provider_detached_at"
                ],
                "read_only_restore": True,
            }
            content_witness["evidence_fingerprint"] = _fingerprint(
                content_witness
            )
            ownership.update(
                {
                    "expected_size_gigabytes": expected_size,
                    "expected_droplet_ids": [],
                    "content_witness": content_witness,
                }
            )
        if row is None:
            replacement = self._new_restore_row(
                kind=kind,
                resource=direct,
                ownership=ownership,
                source_witness=(
                    f"ui-restore:{target_kind}:{snapshot_id}:{restore_marker}"
                ),
            )
            payload["resources"].append(replacement)
        else:
            replacement = self._merge_row(
                row,
                kind=kind,
                resource_id=provider_id,
                name=name,
                ownership_proof=ownership,
            )
            self._replace_row(payload, row, replacement)
        return direct

    def _firewall(
        self, payload: dict, rows: dict[str, list[dict]], inventory: list[dict]
    ) -> dict:
        kind = "payload_firewall"
        row = self._active_legacy_row(rows, kind)
        resource_id = str(row.get("resource_id") or "")
        source_id = str(self.args.normalize_firewall_source_droplet_id)
        name = _resource_name(self.run_id, "payload-firewall")
        inventory_row = self._exact_inventory_id(inventory, resource_id, label="firewall")
        named = self._exact_named(inventory, name, label="firewall")
        if str(named.get("id") or "") != resource_id:
            raise HarnessError("The exact firewall name and ID witnesses disagree.")
        direct = self.reader._read_resource(kind, resource_id)

        def proof(resource):
            self._require_identity(
                resource,
                resource_id=resource_id,
                name=name,
                label="payload firewall",
            )
            normalized = dict(resource)
            normalized["outbound_rules"] = [
                {**rule, "sources": rule.get("destinations")}
                for rule in resource.get("outbound_rules") or []
                if isinstance(rule, dict)
            ]
            droplet_ids = _normalization_string_list(
                resource.get("droplet_ids"),
                label="firewall provider attachment",
            )
            if droplet_ids != self.firewall_droplet_ids:
                raise HarnessError("The exact firewall attachment witness mismatched.")
            if not self.reader._firewall_owned(
                normalized,
                firewall_id=resource_id,
                allowed_droplet_ids=self.firewall_droplet_ids,
                required_droplet_id=source_id,
            ):
                raise HarnessError("The payload firewall rules or assignments mismatched.")
            return {
                "id": resource_id,
                "name": name,
                "droplet_ids": droplet_ids,
                "rules_fingerprint": self.reader._firewall_immutable_fingerprint(
                    normalized
                ),
            }

        inventory_proof = proof(inventory_row)
        direct_proof = proof(direct or {})
        if inventory_proof != direct_proof:
            raise HarnessError("The payload firewall inventory and direct read disagree.")
        try:
            source_provider_id = int(source_id)
        except (TypeError, ValueError):
            raise HarnessError("The firewall source Droplet ID must be an exact integer.") from None
        request = {
            "name": name,
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": str(PAYLOAD_PORT),
                    "sources": {"addresses": list(self.probe_cidrs)},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": protocol,
                    "ports": "0",
                    "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                }
                for protocol in ("tcp", "udp", "icmp")
            ],
            "droplet_ids": [source_provider_id],
        }
        immutable_fingerprint = self.reader._firewall_immutable_fingerprint(request)
        if direct_proof["rules_fingerprint"] != immutable_fingerprint:
            raise HarnessError("The payload firewall immutable rule fingerprint mismatched.")
        attachment = {
            "droplet_ids": list(self.firewall_droplet_ids),
            "source_droplet_id": source_id,
        }
        attachment["fingerprint"] = _fingerprint(attachment)
        creation = {
            "name": name,
            "rules_fingerprint": immutable_fingerprint,
            "source_droplet_id": source_id,
            "immutable_fingerprint": immutable_fingerprint,
        }
        replacement = self._merge_row(
            row,
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "source_droplet_id": source_id,
                "probe_cidrs": list(self.probe_cidrs),
                "request_fingerprint": _fingerprint(request),
                "immutable_fingerprint": immutable_fingerprint,
                "attachment_witness": attachment,
                "creation_witness": creation,
            },
        )
        self._replace_row(payload, row, replacement)
        return direct or {}

    def _spaces(
        self,
        payload: dict,
        rows: dict[str, list[dict]],
        key_inventory: list[dict],
    ) -> dict[str, int]:
        key_row = self._active_legacy_row(rows, "spaces_key")
        bucket_row = self._active_legacy_row(rows, "spaces_bucket")
        credentials = _read_runtime_secret(self.spaces_secret_path)
        bucket = _spaces_bucket_name(self.run_id, self.account["team_uuid"], self.region)
        endpoint = f"https://{self.region}.digitaloceanspaces.com"
        if (
            credentials["bucket"] != bucket
            or credentials["region"] != self.region
            or credentials["endpoint_url"] != endpoint
        ):
            raise HarnessError("The protected Spaces credentials mismatched the exact run.")
        access_key = credentials["access_key"]
        key_hash = self.reader._spaces_key_hash(access_key)
        key_name = _resource_name(self.run_id, "spaces-key")
        if (
            str(key_row.get("resource_id") or "") != key_hash
            or str(key_row.get("name") or "") != key_name
        ):
            raise HarnessError("The Spaces key ledger hash or name mismatched.")
        named_keys = [
            item for item in key_inventory if str(item.get("name") or "") == key_name
        ]
        if len(named_keys) != 1:
            raise HarnessError("The complete Spaces key inventory has zero or duplicate names.")
        inventory_key = named_keys[0]
        direct_key = self.reader._read_spaces_key(access_key)
        for candidate in (inventory_key, direct_key or {}):
            if not self.reader._spaces_key_owned(
                candidate, name=key_name, access_key=access_key
            ):
                raise HarnessError("The exact Spaces key grant witness mismatched.")
        key_proof = {
            "name": key_name,
            "access_key_sha256": key_hash,
            "grants": [{"bucket": "", "permission": "fullaccess"}],
        }
        if {
            "name": str(inventory_key.get("name") or ""),
            "access_key_sha256": self.reader._spaces_key_hash(
                str(inventory_key.get("access_key") or "")
            ),
            "grants": inventory_key.get("grants"),
        } != key_proof or {
            "name": str((direct_key or {}).get("name") or ""),
            "access_key_sha256": self.reader._spaces_key_hash(
                str((direct_key or {}).get("access_key") or "")
            ),
            "grants": (direct_key or {}).get("grants"),
        } != key_proof:
            raise HarnessError("The Spaces key inventory and direct read disagree.")
        key_request = {
            "name": key_name,
            "grants": [{"bucket": "", "permission": "fullaccess"}],
        }
        key_creation = copy.deepcopy(key_request)
        key_creation["immutable_fingerprint"] = _fingerprint(key_request)
        key_replacement = self._merge_row(
            key_row,
            kind="spaces_key",
            resource_id=key_hash,
            name=key_name,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "access_key_sha256": key_hash,
                "permission": "fullaccess",
                "request_fingerprint": _fingerprint(key_request),
                "creation_witness": key_creation,
            },
        )
        self._replace_row(payload, key_row, key_replacement)

        if (
            str(bucket_row.get("resource_id") or "") != bucket
            or str(bucket_row.get("name") or "") != bucket
        ):
            raise HarnessError("The Spaces bucket ledger identity mismatched.")
        client = _spaces_client(credentials)
        buckets = self.reader._spaces_buckets(client)
        matches = [item for item in buckets if item["name"] == bucket]
        if len(matches) != 1:
            raise HarnessError("The complete Spaces bucket inventory has zero or duplicate matches.")
        _spaces_call(
            lambda: client.head_bucket(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        location = _spaces_call(
            lambda: client.get_bucket_location(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        if (
            not isinstance(location, dict)
            or str(location.get("LocationConstraint") or "") != self.region
            or not isinstance(versioning, dict)
            or str(versioning.get("Status") or "") != "Enabled"
        ):
            raise HarnessError("The exact Spaces bucket region or versioning mismatched.")
        bucket_request = {
            "bucket": bucket,
            "region": self.region,
            "acl": "private",
            "versioning": "Enabled",
            "prefix": self.spaces_prefix,
        }
        bucket_creation = {
            **bucket_request,
            "created_at": matches[0]["created_at"],
        }
        bucket_creation["immutable_fingerprint"] = _fingerprint(bucket_creation)
        bucket_replacement = self._merge_row(
            bucket_row,
            kind="spaces_bucket",
            resource_id=bucket,
            name=bucket,
            ownership_proof={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "region": self.region,
                "prefix": self.spaces_prefix,
                "endpoint_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
                "access_key_sha256": key_hash,
                "request_fingerprint": _fingerprint(bucket_request),
                "versioning": "Enabled",
                "creation_witness": bucket_creation,
            },
        )
        self._replace_row(payload, bucket_row, bucket_replacement)
        return {"keys": len(key_inventory), "buckets": len(buckets)}

    def reconcile(self, legacy: dict) -> tuple[dict, dict]:
        if (
            legacy.get("schema") != 1
            or legacy.get("provider") != "digitalocean"
            or legacy.get("run_id") != self.run_id
            or legacy.get("scope") != self.account["team_uuid"]
            or not isinstance(legacy.get("created_at"), str)
            or not legacy.get("created_at")
        ):
            raise HarnessError("The legacy DigitalOcean ledger scope or schema mismatched.")
        proposed = copy.deepcopy(legacy)
        rows = self._row_map(proposed)
        for kind in LEGACY_NORMALIZATION_KINDS:
            self._active_legacy_row(rows, kind)

        inventories = {
            "droplets": iter_collection(
                "/v2/droplets", "droplets", headers=self.headers
            ),
            "volumes": iter_collection(
                "/v2/volumes", "volumes", headers=self.headers
            ),
            "firewalls": iter_collection(
                "/v2/firewalls", "firewalls", headers=self.headers
            ),
            "snapshots": iter_collection(
                "/v2/snapshots", "snapshots", headers=self.headers
            ),
        }
        key_inventory = _iter_provider_collection(
            "/v2/spaces/keys",
            "keys",
            "access_key",
            headers=self.headers,
            params={"sort": "created_at", "sort_direction": "asc"},
        )

        self._source_droplet(proposed, rows, inventories["droplets"])
        self._source_volume(proposed, rows, inventories["volumes"])
        self._snapshot(
            proposed, rows, inventories["snapshots"], target_kind="droplet"
        )
        self._snapshot(
            proposed, rows, inventories["snapshots"], target_kind="volume"
        )
        self._restore(
            proposed, rows, inventories["droplets"], target_kind="droplet"
        )
        self._restore(
            proposed, rows, inventories["volumes"], target_kind="volume"
        )
        self._firewall(proposed, rows, inventories["firewalls"])
        spaces_counts = self._spaces(proposed, rows, key_inventory)
        provider_counts = {
            key: len(value) for key, value in inventories.items()
        }
        provider_counts.update({f"spaces_{key}": value for key, value in spaces_counts.items()})
        return proposed, {
            "complete_inventory": provider_counts,
            "witnesses": sorted(
                self.changes, key=lambda item: (item["kind"], item["resource_id"])
            ),
        }


def _provider_read_only_legacy_normalization(args) -> dict:
    run_id = _validate_legacy_normalization_cli(args)
    ledger_path = Path(args.ledger).expanduser().resolve(strict=False)
    with _normalization_artifact_locks(ledger_path) as intent_path:
        legacy, original_raw, ledger_sha256 = _read_local_json_artifact_bytes(
            ledger_path,
            label="DigitalOcean ledger",
            require_mode_0600=True,
        )
        if legacy.get("scope") != str(args.team_uuid):
            raise HarnessError("The local DigitalOcean ledger team UUID mismatched.")
        intent_report = _normalization_intent_report(
            intent_path, run_id=run_id, scope=str(args.team_uuid)
        )
        token = os.environ.get("DIGITALOCEAN_TOKEN")
        if not token:
            raise HarnessError("DIGITALOCEAN_TOKEN is required in the environment.")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        account = _safe_account(get_json("/v2/account", headers=headers))
        require_personal_team(
            account,
            expected_uuid=str(args.team_uuid),
            expected_name="Personal",
            # This safety class requires an exact UUID even though every
            # provider operation below is GET/HEAD/LIST-only.
            mutation=True,
        )
        normalizer = _LegacyLedgerNormalizer(args, headers=headers, account=account)
        proposed, evidence = normalizer.reconcile(legacy)
        changed = proposed != legacy
        replacement = _normalization_json_bytes(proposed) if changed else original_raw
        proposed_sha256 = hashlib.sha256(replacement).hexdigest()
        plan = {
            "provider": "digitalocean",
            "mode": "provider-read-only-legacy-ledger-normalization",
            "provider_mutation_count": 0,
            "run_id": run_id,
            "team": {"name": account["team_name"], "uuid": account["team_uuid"]},
            "ledger": {
                "current_sha256": ledger_sha256,
                "proposed_sha256": proposed_sha256,
                "current_resource_count": len(legacy["resources"]),
                "proposed_resource_count": len(proposed["resources"]),
                "would_change": changed,
            },
            "mutation_intents": intent_report,
            **evidence,
        }
        report_sha256 = _fingerprint(plan)
        if args.normalize_legacy_ledger == "apply":
            if str(args.normalization_report_sha256 or "").casefold() != report_sha256:
                raise HarnessError(
                    "The normalization dry-report SHA-256 is stale or mismatched."
                )
            if changed:
                _atomic_replace_normalized_ledger(
                    ledger_path,
                    expected_sha256=ledger_sha256,
                    original_raw=original_raw,
                    replacement=replacement,
                )
        return {
            **plan,
            "report_sha256": report_sha256,
            "requested_mode": args.normalize_legacy_ledger,
            "ledger_updated": bool(
                args.normalize_legacy_ledger == "apply" and changed
            ),
        }

def _local_read_only_report(args) -> dict:
    """Inspect only local evidence; never construct provider or ledger clients."""

    prohibited = {
        "native_volume_verifier": bool(args.native_volume_verifier_action),
        "provision_sources": args.provision_sources,
        "cleanup": args.cleanup,
        "droplet_snapshot_verification": bool(
            args.droplet_snapshot_marker or args.droplet_source_id
        ),
        "volume_snapshot_verification": bool(
            args.volume_snapshot_marker or args.volume_source_id
        ),
        "ui_droplet_restore_verification": args.verify_ui_droplet_restore,
        "ui_volume_restore_verification": args.verify_ui_volume_restore,
        "ui_droplet_firewall_attachment": args.attach_ui_droplet_firewall,
        "spaces_setup": args.spaces_setup,
        "spaces_cleanup": args.spaces_cleanup,
    }
    enabled = sorted(name for name, value in prohibited.items() if value)
    if enabled:
        raise HarnessError(
            "--report cannot be combined with operational flags: " + ", ".join(enabled)
        )
    run_id = require_run_id(args.run_id)
    if not args.ledger:
        raise HarnessError("--report requires an existing --ledger artifact.")
    ledger_path = Path(args.ledger).expanduser()
    ledger, ledger_sha256 = _read_local_json_artifact(
        ledger_path, label="DigitalOcean ledger"
    )
    if (
        ledger.get("schema") != 1
        or ledger.get("provider") != "digitalocean"
        or ledger.get("run_id") != run_id
        or not isinstance(ledger.get("scope"), str)
        or not ledger.get("scope")
        or not isinstance(ledger.get("resources"), list)
        or any(not isinstance(row, dict) for row in ledger["resources"])
    ):
        raise HarnessError("The local DigitalOcean ledger scope or schema is malformed.")
    if args.team_uuid and ledger.get("scope") != args.team_uuid:
        raise HarnessError("The local DigitalOcean ledger team UUID does not match.")

    resources = ledger["resources"]
    fingerprint_kinds = {
        "source_droplet",
        "source_volume",
        "ui_restore_droplet",
        "ui_restore_volume",
        "spaces_bucket",
    }
    missing_creation_fingerprints = 0
    for row in resources:
        if row.get("kind") not in fingerprint_kinds:
            continue
        ownership = row.get("ownership")
        creation = ownership.get("creation_witness") if isinstance(ownership, dict) else None
        if not isinstance(creation, dict) or not creation.get("immutable_fingerprint"):
            missing_creation_fingerprints += 1

    intent_path = ledger_path.with_name(
        ledger_path.name + ".mutation-intents.json"
    )
    intent_report = {"exists": False, "pending_count": 0, "sha256": None}
    if intent_path.exists():
        intents, intent_sha256 = _read_local_json_artifact(
            intent_path, label="DigitalOcean mutation intent"
        )
        if (
            intents.get("schema") != 1
            or intents.get("provider") != "digitalocean"
            or intents.get("run_id") != run_id
            or intents.get("scope") != ledger.get("scope")
            or not isinstance(intents.get("pending"), dict)
            or any(
                not isinstance(key, str) or not isinstance(value, dict)
                for key, value in intents.get("pending", {}).items()
            )
        ):
            raise HarnessError("The local DigitalOcean mutation intent is malformed.")
        intent_report = {
            "exists": True,
            "pending_count": len(intents["pending"]),
            "sha256": intent_sha256,
        }

    report = {
        "provider": "digitalocean",
        "mode": "local-read-only",
        "run_id": run_id,
        "ledger": {
            "sha256": ledger_sha256,
            "scope": ledger["scope"],
            "resource_count": len(resources),
            "restore_target_count": sum(
                row.get("kind") in {"ui_restore_droplet", "ui_restore_volume"}
                for row in resources
            ),
            "missing_creation_fingerprint_count": missing_creation_fingerprints,
        },
        "mutation_intents": intent_report,
        "storage_manifest": None,
    }
    if args.spaces_ui_upload_manifest:
        prefix = _spaces_prefix(
            args.spaces_prefix or f"ui/{run_id}/"
        )
        objects = _load_ui_object_manifest(
            args.spaces_ui_upload_manifest,
            run_id=run_id,
            prefix=prefix,
            maximum_bytes=args.spaces_max_verify_bytes,
        )
        report["storage_manifest"] = {
            "schema": UI_OBJECT_MANIFEST_SCHEMA,
            "prefix": prefix,
            "object_count": len(objects),
            "object_counts": {
                kind: sum(item["kind"] == kind for item in objects)
                for kind in sorted(UI_OBJECT_KINDS)
            },
        }
    return report


def _validate_native_volume_verifier_cli(args) -> None:
    action = str(args.native_volume_verifier_action or "")
    if not action:
        return
    prohibited = {
        "local_report": args.report,
        "legacy_normalization": bool(args.normalize_legacy_ledger),
        "source_provisioning": args.provision_sources,
        "general_cleanup": args.cleanup,
        "droplet_restore_verification": args.verify_ui_droplet_restore,
        "volume_restore_verification": args.verify_ui_volume_restore,
        "payload_firewall_attachment": args.attach_ui_droplet_firewall,
        "spaces_setup": args.spaces_setup,
        "spaces_cleanup": args.spaces_cleanup,
        "spaces_object_verification": bool(args.spaces_ui_upload_manifest),
    }
    enabled = sorted(name for name, value in prohibited.items() if value)
    if enabled:
        raise HarnessError(
            "Native-volume verifier actions cannot be combined with operational flags: "
            + ", ".join(enabled)
        )
    run_id = require_run_id(args.run_id)
    if not args.ledger:
        raise HarnessError("Native-volume verification requires a durable --ledger.")
    if args.team_name != "Personal" or not str(args.team_uuid or ""):
        raise HarnessError(
            "Native-volume verification requires the exact Personal team UUID."
        )
    _native_volume_range(
        args.native_volume_offset_bytes, args.native_volume_byte_count
    )
    if _positive_integer(args.volume_size_gib) is None:
        raise HarnessError("The source volume size must be a positive exact integer.")
    if not args.native_volume_verifier_droplet_size or not args.native_volume_verifier_droplet_image:
        raise HarnessError("The verifier Droplet size and image are required.")
    if any(
        value not in (None, "")
        for value in (
            args.ui_volume_source_content_sha256,
            args.ui_volume_source_content_byte_count,
            args.ui_volume_restore_content_sha256,
            args.ui_volume_restore_content_byte_count,
        )
    ):
        raise HarnessError(
            "Native-volume verification does not accept caller-asserted content hashes."
        )
    if action == "prepare-source" and not args.volume_source_id:
        raise HarnessError("Source preparation requires the exact --volume-source-id.")
    if action == "verify-restored":
        required = {
            "restore ID": args.ui_volume_restore_id,
            "restore name": args.ui_volume_restore_name,
            "snapshot ID": args.ui_volume_restore_snapshot_id,
            "snapshot marker": args.ui_volume_snapshot_marker,
            "restore marker": args.ui_volume_restore_marker,
            "run tag": args.ui_volume_restore_run_tag,
            "expected region": args.ui_volume_expected_region,
            "expected size": args.ui_volume_expected_size_gib,
        }
        missing = sorted(label for label, value in required.items() if value in (None, ""))
        if missing:
            raise HarnessError(
                "Restored native-volume verification requires exact witnesses: "
                + ", ".join(missing)
            )
        if args.ui_volume_restore_run_tag != run_id:
            raise HarnessError("The restored native-volume run tag must equal the run ID.")
        if _positive_integer(args.ui_volume_expected_size_gib) is None:
            raise HarnessError("The restored native-volume size must be positive.")
    if action == "report":
        ledger = Path(args.ledger).expanduser()
        intent_path = ledger.with_name(ledger.name + ".mutation-intents.json")
        if (
            ledger.is_symlink()
            or not ledger.is_file()
            or intent_path.is_symlink()
            or not intent_path.is_file()
        ):
            raise HarnessError(
                "The verifier report requires existing ledger and intent artifacts."
            )


def _parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true")
    parser.add_argument(
        "--native-volume-verifier-action",
        choices=("report", "prepare-source", "verify-restored", "cleanup"),
        help=(
            "Run exactly one crash-safe native-volume verifier phase. The report "
            "phase is provider-read-only."
        ),
    )
    parser.add_argument(
        "--normalize-legacy-ledger",
        choices=("report", "apply"),
        help=(
            "Provider-read-only legacy evidence reconciliation. 'apply' may only "
            "atomically replace the local ledger after dry-report confirmation."
        ),
    )
    parser.add_argument("--normalization-report-sha256")
    parser.add_argument(
        "--run-id", default=os.environ.get("BACKUPSHEEP_E2E_RUN_ID")
    )
    parser.add_argument(
        "--ledger",
        default=os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
    )
    parser.add_argument(
        "--team-uuid", default=os.environ.get("DIGITALOCEAN_E2E_TEAM_UUID")
    )
    parser.add_argument(
        "--team-name",
        default=os.environ.get("DIGITALOCEAN_E2E_TEAM_NAME", "Personal"),
    )
    parser.add_argument("--region", default="nyc3")
    parser.add_argument("--droplet-size", default="s-1vcpu-1gb")
    parser.add_argument("--droplet-image", default="ubuntu-24-04-x64")
    parser.add_argument("--volume-size-gib", type=int, default=1)
    parser.add_argument(
        "--native-volume-offset-bytes",
        type=int,
        default=NATIVE_VOLUME_DEFAULT_OFFSET_BYTES,
    )
    parser.add_argument(
        "--native-volume-byte-count",
        type=int,
        default=NATIVE_VOLUME_DEFAULT_BYTE_COUNT,
    )
    parser.add_argument(
        "--native-volume-verifier-droplet-size", default="s-1vcpu-1gb"
    )
    parser.add_argument(
        "--native-volume-verifier-droplet-image", default="ubuntu-24-04-x64"
    )
    parser.add_argument("--native-volume-verifier-key-dir")
    parser.add_argument(
        "--probe-cidr",
        action="append",
        default=[],
        help="Exact runner source /32 or /128 allowed to reach the payload endpoint.",
    )
    parser.add_argument("--provision-sources", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument(
        "--droplet-snapshot-marker",
        "--droplet-backup-marker",
        dest="droplet_snapshot_marker",
    )
    parser.add_argument("--droplet-source-id")
    parser.add_argument(
        "--volume-snapshot-marker",
        "--volume-backup-marker",
        dest="volume_snapshot_marker",
    )
    parser.add_argument("--volume-source-id")
    parser.add_argument("--normalize-source-volume-unattached", action="store_true")
    parser.add_argument("--normalize-source-volume-droplet-id", action="append", default=[])
    parser.add_argument("--normalize-firewall-source-droplet-id")
    parser.add_argument("--normalize-firewall-droplet-id", action="append", default=[])
    parser.add_argument("--verify-ui-droplet-restore", action="store_true")
    parser.add_argument("--attach-ui-droplet-firewall", action="store_true")
    parser.add_argument("--normalize-ui-droplet-restore", action="store_true")
    parser.add_argument("--normalize-ui-droplet-tag", action="append", default=[])
    parser.add_argument("--normalize-ui-droplet-guest-proof", action="store_true")
    parser.add_argument("--ui-droplet-restore-id")
    parser.add_argument("--ui-droplet-restore-name")
    parser.add_argument(
        "--ui-droplet-snapshot-marker",
        "--ui-droplet-backup-marker",
        "--ui-droplet-restore-snapshot-marker",
        dest="ui_droplet_snapshot_marker",
    )
    parser.add_argument("--ui-droplet-restore-marker")
    parser.add_argument("--ui-droplet-restore-snapshot-id")
    parser.add_argument("--ui-droplet-restore-run-tag")
    parser.add_argument("--ui-droplet-expected-region")
    parser.add_argument("--ui-droplet-expected-size")
    parser.add_argument("--ui-droplet-payload-sha256")
    parser.add_argument("--ui-droplet-payload-byte-count", type=int)
    parser.add_argument("--verify-ui-volume-restore", action="store_true")
    parser.add_argument("--normalize-ui-volume-restore", action="store_true")
    parser.add_argument("--normalize-ui-volume-tag", action="append", default=[])
    parser.add_argument("--normalize-ui-volume-content-proof", action="store_true")
    parser.add_argument("--ui-volume-restore-id")
    parser.add_argument("--ui-volume-restore-name")
    parser.add_argument(
        "--ui-volume-snapshot-marker",
        "--ui-volume-backup-marker",
        "--ui-volume-restore-snapshot-marker",
        dest="ui_volume_snapshot_marker",
    )
    parser.add_argument("--ui-volume-restore-marker")
    parser.add_argument("--ui-volume-restore-snapshot-id")
    parser.add_argument("--ui-volume-restore-run-tag")
    parser.add_argument("--ui-volume-expected-region")
    parser.add_argument("--ui-volume-expected-size-gib", type=int)
    parser.add_argument("--ui-volume-source-content-sha256")
    parser.add_argument("--ui-volume-source-content-byte-count", type=int)
    parser.add_argument("--ui-volume-restore-content-sha256")
    parser.add_argument("--ui-volume-restore-content-byte-count", type=int)
    parser.add_argument("--spaces-setup", action="store_true")
    parser.add_argument("--spaces-cleanup", action="store_true")
    parser.add_argument("--spaces-ui-upload-manifest")
    parser.add_argument(
        "--spaces-prefix",
        default=os.environ.get("DIGITALOCEAN_E2E_SPACES_PREFIX"),
        help="Exact durable BackupSheep object prefix, including its trailing slash.",
    )
    parser.add_argument(
        "--spaces-secret-file",
        default=os.environ.get("DIGITALOCEAN_E2E_SPACES_SECRET_FILE"),
    )
    parser.add_argument(
        "--spaces-max-verify-bytes",
        type=int,
        default=1024 * 1024 * 1024,
    )
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if not 1 <= args.spaces_max_verify_bytes <= 10 * 1024 * 1024 * 1024:
        raise HarnessError("The Spaces verification byte bound is invalid.")
    if args.normalize_legacy_ledger:
        print(
            json.dumps(
                _provider_read_only_legacy_normalization(args),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.report:
        print(json.dumps(_local_read_only_report(args), indent=2, sort_keys=True))
        return 0
    _validate_native_volume_verifier_cli(args)
    harness = DigitalOceanHarness(args)
    if args.native_volume_verifier_action:
        if args.native_volume_verifier_action == "report":
            result = harness.native_volume_verifier_report()
        elif args.native_volume_verifier_action == "prepare-source":
            result = harness.prepare_native_volume_source(args.volume_source_id)
        elif args.native_volume_verifier_action == "verify-restored":
            result = harness.verify_native_volume_restore(
                provider_id=args.ui_volume_restore_id,
                name=args.ui_volume_restore_name,
                snapshot_id=args.ui_volume_restore_snapshot_id,
                snapshot_marker=args.ui_volume_snapshot_marker,
                restore_marker=args.ui_volume_restore_marker,
                run_tag=args.ui_volume_restore_run_tag,
                expected_region=args.ui_volume_expected_region,
                expected_size_gigabytes=args.ui_volume_expected_size_gib,
            )
        else:
            result = harness.cleanup_native_volume_verifier()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    result = harness.summary()
    scoped_rejection = None
    if args.provision_sources:
        expectation = harness.payload_expectation
        droplet_request = {
            "name": _resource_name(harness.run_id, "droplet"),
            "region": args.region,
            "size": args.droplet_size,
            "image": args.droplet_image,
            "tags": [harness.run_tag],
            "user_data": _cloud_init(harness.run_id, expectation),
        }
        volume_request = {
            "name": _resource_name(harness.run_id, "volume"),
            "region": args.region,
            "size_gigabytes": args.volume_size_gib,
            "tags": [harness.run_tag],
        }
        droplet = harness.ensure_source("source_droplet", droplet_request)
        droplet = harness.wait_droplet_active(str(droplet["id"]))
        harness.ensure_payload_firewall(str(droplet["id"]))
        payload_result = harness.wait_payload_ready(droplet)
        harness.record_payload_verification(kind="source", droplet=droplet)
        volume = harness.ensure_source("source_volume", volume_request)
        result["sources"] = {
            "droplet_id": str(droplet["id"]),
            "volume_id": str(volume["id"]),
            "payload": payload_result,
        }
    if args.droplet_snapshot_marker or args.droplet_source_id:
        if not args.droplet_snapshot_marker or not args.droplet_source_id:
            raise HarnessError("Droplet snapshot marker and source ID are required together.")
        result["droplet_snapshot"] = harness.verify_snapshot(
            kind="droplet",
            snapshot_marker=args.droplet_snapshot_marker,
            source_id=args.droplet_source_id,
        )
    if args.volume_snapshot_marker or args.volume_source_id:
        if not args.volume_snapshot_marker or not args.volume_source_id:
            raise HarnessError("Volume snapshot marker and source ID are required together.")
        result["volume_snapshot"] = harness.verify_snapshot(
            kind="volume",
            snapshot_marker=args.volume_snapshot_marker,
            source_id=args.volume_source_id,
        )
    if args.verify_ui_droplet_restore:
        values = {
            "provider_id": args.ui_droplet_restore_id,
            "name": args.ui_droplet_restore_name,
            "snapshot_id": args.ui_droplet_restore_snapshot_id,
            "snapshot_marker": args.ui_droplet_snapshot_marker,
            "restore_marker": args.ui_droplet_restore_marker,
        }
        if any(
            not values[key]
            for key in ("provider_id", "name", "snapshot_id", "restore_marker")
        ):
            raise HarnessError("All exact UI Droplet restore witnesses are required.")
        legacy_marker = (
            args.ui_droplet_restore_marker
            if not args.ui_droplet_snapshot_marker
            else None
        )
        result["ui_droplet_restore"] = harness.verify_ui_restore(
            target_kind="droplet",
            run_tag=args.ui_droplet_restore_run_tag or harness.run_tag,
            marker=legacy_marker,
            attach_payload_firewall=args.attach_ui_droplet_firewall,
            **values,
        )
    if args.verify_ui_volume_restore:
        values = {
            "provider_id": args.ui_volume_restore_id,
            "name": args.ui_volume_restore_name,
            "snapshot_id": args.ui_volume_restore_snapshot_id,
            "snapshot_marker": args.ui_volume_snapshot_marker,
            "restore_marker": args.ui_volume_restore_marker,
            "expected_region": args.ui_volume_expected_region,
            "expected_size_gigabytes": args.ui_volume_expected_size_gib,
            "source_content_sha256": args.ui_volume_source_content_sha256,
            "source_content_byte_count": args.ui_volume_source_content_byte_count,
            "restore_content_sha256": args.ui_volume_restore_content_sha256,
            "restore_content_byte_count": args.ui_volume_restore_content_byte_count,
        }
        if any(
            not values[key]
            for key in (
                "provider_id",
                "name",
                "snapshot_id",
                "restore_marker",
                "expected_region",
                "expected_size_gigabytes",
            )
        ):
            raise HarnessError(
                "All exact UI volume restore and expected ownership witnesses are required."
            )
        legacy_marker = (
            args.ui_volume_restore_marker
            if not args.ui_volume_snapshot_marker
            else None
        )
        result["ui_volume_restore"] = harness.verify_ui_restore(
            target_kind="volume",
            run_tag=args.ui_volume_restore_run_tag or harness.run_tag,
            marker=legacy_marker,
            **values,
        )
    if args.spaces_setup:
        try:
            result["spaces_setup"] = harness.ensure_spaces_bucket()
        except ScopedProviderRejection as error:
            scoped_rejection = error
            result["spaces_setup"] = {
                "status": "scope_rejected",
                "required_scope": error.required_scope,
            }
    if args.spaces_ui_upload_manifest:
        try:
            result["spaces_ui_uploads"] = harness.verify_spaces_ui_uploads(
                args.spaces_ui_upload_manifest,
                maximum_bytes=args.spaces_max_verify_bytes,
            )
        except ScopedProviderRejection as error:
            scoped_rejection = error
            result["spaces_ui_uploads"] = {
                "status": "scope_rejected",
                "required_scope": error.required_scope,
            }
    if args.spaces_cleanup:
        try:
            result["spaces_cleanup"] = harness.cleanup_spaces()
        except ScopedProviderRejection as error:
            scoped_rejection = error
            result["spaces_cleanup"] = {
                "status": "scope_rejected",
                "required_scope": error.required_scope,
            }
    if args.cleanup:
        harness.cleanup()
        result["cleanup"] = "completed"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if scoped_rejection else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarnessError, LedgerError, DigitalOceanAPIError) as error:
        print(f"DigitalOcean E2E failed safely: {error}", file=sys.stderr)
        raise SystemExit(1)
