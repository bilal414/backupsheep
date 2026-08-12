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
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import time
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
    values = _restore_source_values(resource, str(witness.get("target_kind")))
    if values:
        return set(values) == {source_id}
    return _digitalocean_source_tag(source_id) in normalized


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
        with open(path, encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, ValueError) as error:
        raise HarnessError("The Spaces runtime credential file is unreadable.") from error
    if not isinstance(payload, dict) or set(payload) != SPACES_SECRET_FIELDS or any(
        not isinstance(value, str) or not value for value in payload.values()
    ):
        raise HarnessError("The Spaces runtime credential file is malformed.")
    return payload


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
        token = os.environ.get("DIGITALOCEAN_TOKEN")
        if not token:
            raise HarnessError("DIGITALOCEAN_TOKEN is required in the environment.")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.run_id = require_run_id(args.run_id)
        self.run_tag = self.run_id
        self.apply = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
        self.cleanup_enabled = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
        self.spaces_apply = (
            self.apply
            and os.environ.get("BACKUPSHEEP_E2E_SPACES_APPLY") == "YES"
        )
        self.spaces_cleanup_enabled = (
            self.cleanup_enabled
            and os.environ.get("BACKUPSHEEP_E2E_SPACES_CLEANUP") == "YES"
        )
        self.region = str(args.region)
        self.payload_expectation = _payload_expectation(self.run_id)
        raw_probe_cidrs = list(args.probe_cidr or [])
        env_probe_cidrs = os.environ.get("DIGITALOCEAN_E2E_PROBE_CIDRS")
        if env_probe_cidrs:
            raw_probe_cidrs.append(env_probe_cidrs)
        self.probe_cidrs = (
            _probe_cidrs(raw_probe_cidrs)
            if args.provision_sources or args.verify_ui_droplet_restore
            else []
        )
        self.spaces_secret_path = _validate_secret_path(
            Path(
                args.spaces_secret_file
                or _default_spaces_secret_path(self.run_id)
            )
        )
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
            "ledger_entries": len(self.ledger.entries()),
        }

    def _resources(self, kind: str) -> list[dict]:
        mapping = {
            "source_droplet": ("/v2/droplets", "droplets"),
            "source_volume": ("/v2/volumes", "volumes"),
            "ui_restore_droplet": ("/v2/droplets", "droplets"),
            "ui_restore_volume": ("/v2/volumes", "volumes"),
            "payload_firewall": ("/v2/firewalls", "firewalls"),
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

    def _record(self, kind: str, resource: dict, request: dict):
        name = str(resource["name"])
        ownership = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "request_fingerprint": _fingerprint(request),
        }
        if kind == "source_droplet":
            ownership.update(
                {
                    "payload_sha256": self.payload_expectation["sha256"],
                    "payload_byte_count": self.payload_expectation["byte_count"],
                }
            )
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
            if kind == "source_droplet"
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

    @staticmethod
    def _firewall_rule_addresses(rule: dict) -> set[str]:
        sources = rule.get("sources") if isinstance(rule, dict) else None
        addresses = sources.get("addresses") if isinstance(sources, dict) else None
        if not isinstance(addresses, list):
            return set()
        return {str(value) for value in addresses if isinstance(value, str)}

    def _firewall_owned(
        self, firewall: dict, *, firewall_id=None, allowed_droplet_ids=None
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
        return actual.issubset(allowed)

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
            )

        fingerprint = _fingerprint(request)
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
            )
            if ledger_entry is None and not intent_matches:
                raise HarnessError("An unledgered firewall matches the run name.")
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
            },
        )
        self.intents.update(kind, request_boundary_crossed=True)
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
            },
            source_witness=f"payload-firewall:{name}",
        )
        self.intents.clear(kind)
        return resource

    def _attach_payload_firewall(self, droplet_id: str) -> None:
        entries = [
            entry
            for entry in self.ledger.entries("payload_firewall")
            if entry.get("cleanup_state") in {"eligible", "failed"}
        ]
        if len(entries) != 1:
            raise HarnessError("One exact ledgered payload firewall is required.")
        entry = entries[0]
        firewall_id = str(entry["resource_id"])
        firewall = self._read_resource("payload_firewall", firewall_id)
        if firewall is None:
            raise HarnessError("The ledgered payload firewall is missing.")
        normalized = dict(firewall)
        normalized["outbound_rules"] = [
            {**rule, "sources": rule.get("destinations")}
            for rule in firewall.get("outbound_rules") or []
            if isinstance(rule, dict)
        ]
        allowed = self._firewall_allowed_droplet_ids()
        if not self._firewall_owned(
            normalized,
            firewall_id=firewall_id,
            allowed_droplet_ids=allowed,
        ):
            raise HarnessError("The payload firewall has foreign assignments or rules.")
        if str(droplet_id) in {str(value) for value in firewall.get("droplet_ids") or []}:
            return
        if str(droplet_id) not in allowed:
            raise HarnessError("The restored Droplet is not in the durable ledger.")
        _mutation_response(
            "POST",
            f"/v2/firewalls/{quote(firewall_id, safe='')}/droplets",
            headers=self.headers,
            body={"droplet_ids": [int(droplet_id)]},
        )
        observed = self._read_resource("payload_firewall", firewall_id)
        if observed is None or str(droplet_id) not in {
            str(value) for value in observed.get("droplet_ids") or []
        }:
            raise AmbiguousMutation(
                "The firewall attachment was accepted but is not yet visible."
            )

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

    def verify_snapshot(self, *, kind: str, marker: str, source_id: str):
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
            marker=marker,
            source_id=source_id,
            resource_type=resource_type,
        )
        if snapshot is None:
            raise HarnessError("The exact BackupSheep snapshot is not visible yet.")
        snapshot_id = str(snapshot["id"])
        self.ledger.record(
            kind=f"ui_snapshot_{resource_type}",
            resource_id=snapshot_id,
            name=str(snapshot.get("name") or ""),
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "marker": str(marker),
                "source_id": str(source_id),
                "resource_type": resource_type,
            },
            source_witness=f"snapshot:{resource_type}:{source_id}:{marker}",
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
        marker: str,
        snapshot_id: str,
        run_tag: str,
    ) -> dict:
        if target_kind not in {"droplet", "volume"}:
            raise HarnessError("The UI restore target kind is invalid.")
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
        if (
            not isinstance(snapshot_ownership, dict)
            or str(snapshot_ownership.get("team_uuid") or "")
            != str(self.account["team_uuid"])
            or str(snapshot_ownership.get("run_tag") or "") != self.run_tag
            or str(snapshot_ownership.get("marker") or "") != str(marker)
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
            "marker": str(marker),
            "run_tag": str(run_tag),
            "snapshot_id": str(snapshot_id),
        }
        plural = "droplets" if target_kind == "droplet" else "volumes"
        candidates = iter_collection(
            f"/v2/{plural}",
            plural,
            headers=self.headers,
            params={"tag_name": marker},
        )
        selected = select_ui_restore_witness(candidates, witness)
        resource = self._read_resource(
            f"ui_restore_{target_kind}", str(provider_id)
        )
        if resource is None or not _restore_target_owned(resource, witness):
            raise HarnessError("The exact UI restore target failed direct read-back.")
        if str(selected.get("id")) != str(resource.get("id")):
            raise HarnessError("The UI restore inventory and direct ID disagree.")
        ownership = {
            "team_uuid": self.account["team_uuid"],
            "run_tag": self.run_tag,
            "marker": str(marker),
            "snapshot_id": str(snapshot_id),
            "target_kind": target_kind,
            "source_tag": _digitalocean_source_tag(snapshot_id),
        }
        if target_kind == "droplet":
            ownership.update(
                {
                    "payload_sha256": self.payload_expectation["sha256"],
                    "payload_byte_count": self.payload_expectation["byte_count"],
                }
            )
        self.ledger.record(
            kind=f"ui_restore_{target_kind}",
            resource_id=str(provider_id),
            name=str(name),
            ownership=ownership,
            source_witness=f"ui-restore:{target_kind}:{snapshot_id}:{marker}",
        )
        if target_kind == "droplet":
            self._attach_payload_firewall(str(provider_id))
            resource = self.wait_droplet_active(
                str(provider_id), kind="ui_restore_droplet"
            )
            self.wait_payload_ready(resource)
            self.record_payload_verification(kind="ui_restore", droplet=resource)
        return {
            "provider_id": str(provider_id),
            "target_kind": target_kind,
            "snapshot_id": str(snapshot_id),
            "payload_verified": target_kind == "droplet",
        }

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
            },
            source_witness=f"spaces-object:{bucket}:{kind}:{object_id}",
        )

    def _spaces_bucket_names(self, client) -> list[str]:
        payload = _spaces_call(
            lambda: client.list_buckets(), required_scope="Spaces full access"
        )
        buckets = payload.get("Buckets") if isinstance(payload, dict) else None
        if not isinstance(buckets, list) or any(
            not isinstance(item, dict) or not item.get("Name") for item in buckets
        ):
            raise HarnessError("Spaces returned a malformed bucket inventory.")
        names = [str(item["Name"]) for item in buckets]
        if len(names) != len(set(names)) or len(names) > SPACES_MAX_ITEMS:
            raise HarnessError("Spaces returned duplicate or excessive buckets.")
        return names

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
        if not isinstance(actual_metadata, dict) or any(
            str(actual_metadata.get(key) or "") != str(value)
            for key, value in expected_metadata.items()
        ):
            raise HarnessError("Spaces custom object metadata does not match.")

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
        }
        fingerprint = _fingerprint(request)
        intent = self.intents.get(kind)
        names = self._spaces_bucket_names(client)
        present = bucket in names
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
            names = self._spaces_bucket_names(client)
            if names.count(bucket) != 1:
                raise AmbiguousMutation(
                    "Spaces accepted the bucket create but exact read-back is incomplete."
                )
        _spaces_call(
            lambda: client.head_bucket(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        _spaces_call(
            lambda: client.put_bucket_versioning(
                Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
            ),
            mutation=True,
            required_scope="Spaces full access",
        )
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        if not isinstance(versioning, dict) or versioning.get("Status") != "Enabled":
            raise HarnessError("Spaces bucket versioning is not enabled.")
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
            head = self._head_spaces_object(
                client,
                bucket=bucket,
                key=ownership_key,
                version_id=str(ownership.get("version_id") or ""),
            )
            if head is None:
                raise HarnessError("The ledgered Spaces ownership object is missing.")
            self._verify_spaces_head(head, ownership)
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
            intent_matches = bool(
                ownership_intent
                and ownership_intent.get("request_boundary_crossed")
                and ownership_intent.get("name") == ownership_key
                and ownership_intent.get("request_fingerprint")
                == ownership_fingerprint
            )
            if candidate_versions:
                if not intent_matches:
                    raise HarnessError(
                        "An unledgered Spaces object matches the ownership key."
                    )
                candidate = candidate_versions[0]
                version_id = str(candidate.get("VersionId") or "")
                etag = str(candidate.get("ETag") or "").strip('"')
                ownership = {
                    "version_id": version_id,
                    "byte_count": len(ownership_payload),
                    "etag": etag,
                    "metadata": object_metadata,
                }
                head = self._head_spaces_object(
                    client,
                    bucket=bucket,
                    key=ownership_key,
                    version_id=version_id,
                )
                if not version_id or not etag or head is None:
                    raise HarnessError("The ownership-object recovery witness is incomplete.")
                self._verify_spaces_head(head, ownership)
                self._record_spaces_object(
                    kind="spaces_ownership_object",
                    bucket=bucket,
                    key=ownership_key,
                    version_id=version_id,
                    sha256=ownership_hash,
                    byte_count=len(ownership_payload),
                    etag=etag,
                    metadata=object_metadata,
                )
                self.intents.clear(ownership_intent_key)
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
                head = self._head_spaces_object(
                    client,
                    bucket=bucket,
                    key=ownership_key,
                    version_id=version_id,
                )
                ownership = {
                    "version_id": version_id,
                    "byte_count": len(ownership_payload),
                    "etag": etag,
                    "metadata": object_metadata,
                }
                if head is None:
                    raise AmbiguousMutation(
                        "The Spaces ownership upload is not visible."
                    )
                self._verify_spaces_head(head, ownership)
                self._record_spaces_object(
                    kind="spaces_ownership_object",
                    bucket=bucket,
                    key=ownership_key,
                    version_id=version_id,
                    sha256=ownership_hash,
                    byte_count=len(ownership_payload),
                    etag=etag,
                    metadata=object_metadata,
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
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode("utf-8")
                ).hexdigest(),
                "access_key_sha256": key_entries[0]["resource_id"],
                "request_fingerprint": fingerprint,
                "versioning": "Enabled",
            },
            source_witness=f"spaces-bucket:{bucket}:{self.region}",
        )
        if intent_matches or self.intents.get(kind):
            self.intents.clear(kind)
        return {
            "status": "ready",
            "credentials_file": str(self.spaces_secret_path),
            "versioning": "enabled",
        }

    @staticmethod
    def _manifest_has_sensitive_keys(value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).casefold().replace("-", "_")
                if any(
                    token in normalized
                    for token in ("secret", "password", "access_key", "token")
                ):
                    return True
                if DigitalOceanHarness._manifest_has_sensitive_keys(child):
                    return True
        elif isinstance(value, list):
            return any(
                DigitalOceanHarness._manifest_has_sensitive_keys(child)
                for child in value
            )
        return False

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
        ):
            raise HarnessError(
                "The Spaces bucket credentials do not match the durable run witness."
            )
        try:
            with open(Path(manifest_path).expanduser(), encoding="utf-8") as source:
                manifest = json.load(source)
        except (OSError, ValueError) as error:
            raise HarnessError("The UI upload manifest could not be read.") from error
        if self._manifest_has_sensitive_keys(manifest):
            raise HarnessError("The UI upload manifest must not contain credentials.")
        objects = manifest.get("objects") if isinstance(manifest, dict) else None
        if not isinstance(objects, list) or not objects:
            raise HarnessError("The UI upload manifest has no object witnesses.")
        client = _spaces_client(credentials)
        verified = {"website": 0, "database": 0}
        seen = set()
        for item in objects:
            if not isinstance(item, dict):
                raise HarnessError("The UI upload manifest is malformed.")
            object_kind = str(item.get("kind") or "")
            key = str(item.get("key") or "")
            version_id = str(item.get("version_id") or "")
            sha256 = str(item.get("sha256") or "").lower()
            etag = str(item.get("etag") or "").strip('"')
            metadata = item.get("metadata") or {}
            try:
                byte_count = int(item.get("byte_count"))
            except (TypeError, ValueError):
                raise HarnessError("The UI upload byte count is malformed.") from None
            identity = (key, version_id)
            if (
                object_kind not in verified
                or not key
                or not version_id
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or not etag
                or byte_count < 0
                or byte_count > maximum_bytes
                or not isinstance(metadata, dict)
                or identity in seen
            ):
                raise HarnessError("The UI upload witness is incomplete or unsafe.")
            seen.add(identity)
            head = self._head_spaces_object(
                client, bucket=bucket, key=key, version_id=version_id
            )
            ownership = {
                "version_id": version_id,
                "byte_count": byte_count,
                "etag": etag,
                "metadata": metadata,
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
    def _spaces_inventory(client, bucket: str) -> dict[str, list[dict]]:
        versions = []
        delete_markers = []
        seen = set()
        key_marker = version_marker = None
        for _page in range(SPACES_MAX_PAGES):
            request = {"Bucket": bucket, "MaxKeys": 1000}
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
        names = self._spaces_bucket_names(client)
        if bucket not in names:
            raise AmbiguousMutation(
                "The pending Spaces bucket create is not visible; cleanup will not revoke its key."
            )
        request = {
            "bucket": bucket,
            "region": credentials["region"],
            "acl": "private",
            "versioning": "Enabled",
        }
        request_fingerprint = _fingerprint(request)
        if intent.get("request_fingerprint") != request_fingerprint:
            raise HarnessError("The pending Spaces bucket request fingerprint drifted.")
        versioning = _spaces_call(
            lambda: client.get_bucket_versioning(Bucket=bucket),
            required_scope="Spaces bucket read",
        )
        status = str(versioning.get("Status") or "") if isinstance(versioning, dict) else ""

        object_intent = self.intents.get("spaces_ownership_upload")
        if object_intent and object_intent.get("request_boundary_crossed"):
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
            object_request = {
                "bucket": bucket,
                "key": key,
                "sha256": sha256,
                "byte_count": len(payload),
                "metadata": metadata,
            }
            if (
                object_intent.get("name") != key
                or object_intent.get("request_fingerprint")
                != _fingerprint(object_request)
            ):
                raise HarnessError("The pending ownership upload intent drifted.")
            inventory = self._spaces_inventory(client, bucket)
            candidates = [
                row
                for row in inventory["versions"]
                if str(row.get("Key") or "") == key
            ]
            if len(candidates) > 1:
                raise HarnessError("The pending ownership upload has duplicate versions.")
            if candidates:
                candidate = candidates[0]
                version_id = str(candidate.get("VersionId") or "")
                etag = str(candidate.get("ETag") or "").strip('"')
                ownership = {
                    "version_id": version_id,
                    "byte_count": len(payload),
                    "etag": etag,
                    "metadata": metadata,
                }
                head = self._head_spaces_object(
                    client,
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                )
                if not version_id or not etag or head is None:
                    raise HarnessError("The pending ownership upload is incomplete.")
                self._verify_spaces_head(head, ownership)
                self._record_spaces_object(
                    kind="spaces_ownership_object",
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                    sha256=sha256,
                    byte_count=len(payload),
                    etag=etag,
                    metadata=metadata,
                )
                self.intents.clear("spaces_ownership_upload")

        self.ledger.record(
            kind="spaces_bucket",
            resource_id=bucket,
            name=bucket,
            ownership={
                "team_uuid": self.account["team_uuid"],
                "run_tag": self.run_tag,
                "region": credentials["region"],
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode("utf-8")
                ).hexdigest(),
                "access_key_sha256": key_entries[0]["resource_id"],
                "request_fingerprint": request_fingerprint,
                "versioning": status or "not_enabled",
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
            ):
                self.ledger.mark_cleanup(
                    "spaces_bucket", bucket, state="manual_review"
                )
                raise HarnessError("Spaces bucket cleanup ownership verification failed.")
            client = _spaces_client(credentials)
            names = self._spaces_bucket_names(client)
            if bucket not in names:
                for kind in sorted(SPACES_OBJECT_KINDS):
                    for entry in self.ledger.entries(kind):
                        if entry.get("cleanup_state") in {"eligible", "failed"}:
                            ownership = entry.get("ownership") or {}
                            if ownership.get("bucket") != bucket:
                                self.ledger.mark_cleanup(
                                    kind,
                                    str(entry.get("resource_id") or ""),
                                    state="manual_review",
                                )
                                raise HarnessError(
                                    "A Spaces object ledger entry targets another bucket."
                                )
                            self.ledger.mark_cleanup(
                                kind,
                                str(entry.get("resource_id") or ""),
                                state="absent",
                            )
                self.ledger.mark_cleanup("spaces_bucket", bucket, state="absent")
            else:
                for kind in sorted(SPACES_OBJECT_KINDS):
                    for entry in self.ledger.entries(kind):
                        if entry.get("cleanup_state") not in {"eligible", "failed"}:
                            continue
                        object_id = str(entry.get("resource_id") or "")
                        object_ownership = entry.get("ownership") or {}
                        key = str(object_ownership.get("key") or "")
                        version_id = str(object_ownership.get("version_id") or "")
                        if (
                            object_ownership.get("team_uuid")
                            != self.account["team_uuid"]
                            or object_ownership.get("run_tag") != self.run_tag
                            or object_ownership.get("bucket") != bucket
                            or self._spaces_object_id(bucket, key, version_id)
                            != object_id
                        ):
                            self.ledger.mark_cleanup(
                                kind, object_id, state="manual_review"
                            )
                            raise HarnessError("Spaces object cleanup ownership failed.")
                        head = self._head_spaces_object(
                            client,
                            bucket=bucket,
                            key=key,
                            version_id=version_id,
                        )
                        if head is None:
                            self.ledger.mark_cleanup(
                                kind, object_id, state="absent"
                            )
                            continue
                        self._verify_spaces_head(head, object_ownership)
                        _spaces_call(
                            lambda bucket=bucket, key=key, version_id=version_id: client.delete_object(
                                Bucket=bucket, Key=key, VersionId=version_id
                            ),
                            mutation=True,
                            required_scope="Spaces object delete",
                        )
                        if self._head_spaces_object(
                            client,
                            bucket=bucket,
                            key=key,
                            version_id=version_id,
                        ) is not None:
                            self.ledger.mark_cleanup(
                                kind,
                                object_id,
                                state="failed",
                                error="Exact object version remains visible.",
                            )
                            raise AmbiguousMutation(
                                "The exact Spaces object version remains visible."
                            )
                        self.ledger.mark_cleanup(kind, object_id, state="deleted")
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
                _spaces_call(
                    lambda: client.delete_bucket(Bucket=bucket),
                    mutation=True,
                    required_scope="Spaces full access",
                )
                if bucket in self._spaces_bucket_names(client):
                    self.ledger.mark_cleanup(
                        "spaces_bucket",
                        bucket,
                        state="failed",
                        error="Bucket remains visible after exact delete.",
                    )
                    raise AmbiguousMutation(
                        "The exact Spaces bucket remains visible after deletion."
                    )
                self.ledger.mark_cleanup("spaces_bucket", bucket, state="deleted")

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
            candidates = self._spaces_keys(name=name)
            if not candidates:
                self.ledger.mark_cleanup(
                    "spaces_key", str(key_entry["resource_id"]), state="absent"
                )
            else:
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
                if not self._spaces_key_owned(
                    read_back or {}, name=name, access_key=access_key
                ):
                    raise HarnessError("The exact Spaces key failed read-back.")
                _mutation_response(
                    "DELETE",
                    f"/v2/spaces/keys/{quote(access_key, safe='')}",
                    headers=self.headers,
                    required_scope="spaces_key:delete",
                )
                if self._read_spaces_key(access_key) is not None:
                    self.ledger.mark_cleanup(
                        "spaces_key",
                        str(key_entry["resource_id"]),
                        state="failed",
                        error="Spaces key remains visible after exact delete.",
                    )
                    raise AmbiguousMutation(
                        "The exact Spaces key remains visible after deletion."
                    )
                self.ledger.mark_cleanup(
                    "spaces_key", str(key_entry["resource_id"]), state="deleted"
                )
        all_key_entries = self.ledger.entries("spaces_key")
        key_cleanup_proven = bool(all_key_entries) and all(
            entry.get("cleanup_state") in {"deleted", "absent"}
            for entry in all_key_entries
        )
        if self.spaces_secret_path.exists() and not key_cleanup_proven:
            raise HarnessError(
                "The protected Spaces credentials remain because exact key cleanup is unproven."
            )
        if self.spaces_secret_path.exists():
            if self.spaces_secret_path.is_symlink():
                raise HarnessError("The Spaces credential path became a symlink.")
            self.spaces_secret_path.unlink()
            directory_fd = os.open(self.spaces_secret_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        if key_cleanup_proven:
            for intent_key in (
                "spaces_ownership_upload",
                "spaces_bucket_create",
                "spaces_key_create",
            ):
                if self.intents.get(intent_key):
                    self.intents.clear(intent_key)
        return {"status": "completed"}

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
                witness = {
                    "target_kind": target_kind,
                    "provider_id": resource_id,
                    "name": str(entry.get("name") or ""),
                    "marker": str(ownership.get("marker") or ""),
                    "run_tag": str(ownership.get("run_tag") or ""),
                    "snapshot_id": str(ownership.get("snapshot_id") or ""),
                }
                if (
                    ownership.get("team_uuid") != self.account["team_uuid"]
                    or ownership.get("run_tag") != self.run_tag
                ):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError("UI restore ledger ownership no longer matches.")
                resource = self._read_resource(kind, resource_id)
                if resource is None:
                    self.ledger.mark_cleanup(kind, resource_id, state="absent")
                    continue
                if not _restore_target_owned(resource, witness):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError("UI restore cleanup ownership verification failed.")
                _mutation_response(
                    "DELETE",
                    f"/v2/{plural}/{quote(resource_id, safe='')}",
                    headers=self.headers,
                )
                self.wait_absent(kind, resource_id)
                self.ledger.mark_cleanup(kind, resource_id, state="deleted")
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
                try:
                    payload = get_json(
                        f"/v2/snapshots/{quote(resource_id, safe='')}",
                        headers=self.headers,
                    )
                except DigitalOceanAPIError as error:
                    if error.code == "PROVIDER_NOT_FOUND":
                        self.ledger.mark_cleanup(
                            kind, resource_id, state="absent"
                        )
                        continue
                    raise
                snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
                if not (
                    isinstance(snapshot, dict)
                    and str(snapshot.get("id") or "") == resource_id
                    and str(snapshot.get("name") or "")
                    == str(ownership.get("marker") or "")
                    and str(snapshot.get("resource_id") or "")
                    == str(ownership.get("source_id") or "")
                    and str(snapshot.get("resource_type") or "")
                    == str(ownership.get("resource_type") or "")
                ):
                    self.ledger.mark_cleanup(
                        kind, resource_id, state="manual_review"
                    )
                    raise HarnessError("Snapshot cleanup ownership verification failed.")
                _mutation_response(
                    "DELETE",
                    f"/v2/snapshots/{quote(resource_id, safe='')}",
                    headers=self.headers,
                )
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    try:
                        get_json(
                            f"/v2/snapshots/{quote(resource_id, safe='')}",
                            headers=self.headers,
                        )
                    except DigitalOceanAPIError as error:
                        if error.code == "PROVIDER_NOT_FOUND":
                            self.ledger.mark_cleanup(
                                kind, resource_id, state="deleted"
                            )
                            break
                        raise
                    time.sleep(5)
                else:
                    raise AmbiguousMutation(
                        "The exact snapshot remains visible after cleanup."
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
                plural = "droplets" if kind == "source_droplet" else "volumes"
                _mutation_response(
                    "DELETE",
                    f"/v2/{plural}/{quote(resource_id, safe='')}",
                    headers=self.headers,
                )
                self.wait_absent(kind, resource_id)
                self.ledger.mark_cleanup(kind, resource_id, state="deleted")
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
            ):
                self.ledger.mark_cleanup(
                    "payload_firewall", resource_id, state="manual_review"
                )
                raise HarnessError("Payload firewall has foreign rules or assignments.")
            _mutation_response(
                "DELETE",
                f"/v2/firewalls/{quote(resource_id, safe='')}",
                headers=self.headers,
            )
            self.wait_absent("payload_firewall", resource_id)
            self.ledger.mark_cleanup(
                "payload_firewall", resource_id, state="deleted"
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
            _mutation_response(
                "DELETE",
                f"/v2/tags/{quote(self.run_tag, safe='')}",
                headers=self.headers,
            )
            self.wait_tag_absent()
            self.ledger.mark_cleanup("run_tag", self.run_tag, state="deleted")


def _parser():
    parser = argparse.ArgumentParser()
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
        "--probe-cidr",
        action="append",
        default=[],
        help="Exact runner source /32 or /128 allowed to reach the payload endpoint.",
    )
    parser.add_argument("--provision-sources", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--droplet-snapshot-marker")
    parser.add_argument("--droplet-source-id")
    parser.add_argument("--volume-snapshot-marker")
    parser.add_argument("--volume-source-id")
    parser.add_argument("--verify-ui-droplet-restore", action="store_true")
    parser.add_argument("--ui-droplet-restore-id")
    parser.add_argument("--ui-droplet-restore-name")
    parser.add_argument("--ui-droplet-restore-marker")
    parser.add_argument("--ui-droplet-restore-snapshot-id")
    parser.add_argument("--ui-droplet-restore-run-tag")
    parser.add_argument("--verify-ui-volume-restore", action="store_true")
    parser.add_argument("--ui-volume-restore-id")
    parser.add_argument("--ui-volume-restore-name")
    parser.add_argument("--ui-volume-restore-marker")
    parser.add_argument("--ui-volume-restore-snapshot-id")
    parser.add_argument("--ui-volume-restore-run-tag")
    parser.add_argument("--spaces-setup", action="store_true")
    parser.add_argument("--spaces-cleanup", action="store_true")
    parser.add_argument("--spaces-ui-upload-manifest")
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
    harness = DigitalOceanHarness(args)
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
            marker=args.droplet_snapshot_marker,
            source_id=args.droplet_source_id,
        )
    if args.volume_snapshot_marker or args.volume_source_id:
        if not args.volume_snapshot_marker or not args.volume_source_id:
            raise HarnessError("Volume snapshot marker and source ID are required together.")
        result["volume_snapshot"] = harness.verify_snapshot(
            kind="volume",
            marker=args.volume_snapshot_marker,
            source_id=args.volume_source_id,
        )
    if args.verify_ui_droplet_restore:
        values = {
            "provider_id": args.ui_droplet_restore_id,
            "name": args.ui_droplet_restore_name,
            "marker": args.ui_droplet_restore_marker,
            "snapshot_id": args.ui_droplet_restore_snapshot_id,
        }
        if any(not value for value in values.values()):
            raise HarnessError("All exact UI Droplet restore witnesses are required.")
        result["ui_droplet_restore"] = harness.verify_ui_restore(
            target_kind="droplet",
            run_tag=args.ui_droplet_restore_run_tag or harness.run_tag,
            **values,
        )
    if args.verify_ui_volume_restore:
        values = {
            "provider_id": args.ui_volume_restore_id,
            "name": args.ui_volume_restore_name,
            "marker": args.ui_volume_restore_marker,
            "snapshot_id": args.ui_volume_restore_snapshot_id,
        }
        if any(not value for value in values.values()):
            raise HarnessError("All exact UI volume restore witnesses are required.")
        result["ui_volume_restore"] = harness.verify_ui_restore(
            target_kind="volume",
            run_tag=args.ui_volume_restore_run_tag or harness.run_tag,
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
