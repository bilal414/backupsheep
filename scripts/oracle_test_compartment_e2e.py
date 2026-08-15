#!/usr/bin/env python3
"""Safety-gated Oracle fixture compartment and network harness.

This module is intentionally usable offline.  Importing it, constructing a
configuration, and running ``--phase plan`` do not read an OCI profile, create
ledger files, or make provider/network calls.  Provider access is loaded only
after the explicit ``BACKUPSHEEP_E2E_APPLY=YES`` gate is passed.

The harness creates one child compartment in the explicitly allowed tenancy,
then one dedicated IPv4 VCN, internet gateway, route table, security list, and
public subnet in ``us-ashburn-1``.  The security list permits ingress only from
caller-provided /32 or /128 host CIDRs for SSH and the configured database
ports.  Egress is limited to TCP 80/443, TCP/UDP 53, and UDP 123 through the
dedicated internet gateway route.  All ownership and dependency facts are
stored in a separate fsynced ledger and mutation-intent file outside the
repository and ``_docs``.

The JSON returned by ``provision`` includes only non-secret environment facts
needed by :mod:`scripts.oracle_live_ui_e2e`.  It deliberately does not print
OCI profile paths, key material, or provider client configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

# Keep this module's path checks lexical and side-effect free.  In particular,
# do not call Path.resolve() during plan/config construction: resolve() can
# consult the filesystem for symlink components.
REPO_ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.live_e2e_ledger import (
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


OCI_OCID_RE = re.compile(r"^ocid1\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]*\..+$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
DNS_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{0,14}[a-z0-9]$|^[a-z]$")

REGION = "us-ashburn-1"
MAX_PAGES = 100
MAX_ITEMS = 10_000
REQUEST_TIMEOUT = (10.0, 60.0)
DEFAULT_VCN_CIDR = "10.248.0.0/16"
DEFAULT_SUBNET_CIDR = "10.248.1.0/24"
DEFAULT_DATABASE_PORTS = (1521, 3306, 5432)

# The route table is intentionally broad at the routing layer because an OCI
# internet gateway requires a default route.  The security list is the actual
# egress allow-list and restricts traffic to these exact destination ports.
EGRESS_TCP_PORTS = (53, 80, 443)
EGRESS_UDP_PORTS = (53, 123)

TAG_RUN = "BACKUPSHEEP_E2E_RUN"
TAG_OWNED = "BACKUPSHEEP_E2E_OWNED"
TAG_KIND = "BACKUPSHEEP_E2E_KIND"

KIND_COMPARTMENT = "test_compartment"
KIND_VCN = "test_vcn"
KIND_INTERNET_GATEWAY = "test_internet_gateway"
KIND_ROUTE_TABLE = "test_route_table"
KIND_SECURITY_LIST = "test_security_list"
KIND_SUBNET = "test_subnet"
KIND_DEFAULT_ROUTE_TABLE = "provider_default_route_table"
KIND_DEFAULT_SECURITY_LIST = "provider_default_security_list"
KIND_DEFAULT_DHCP_OPTIONS = "provider_default_dhcp_options"
KINDS = (
    KIND_COMPARTMENT,
    KIND_VCN,
    KIND_INTERNET_GATEWAY,
    KIND_ROUTE_TABLE,
    KIND_SECURITY_LIST,
    KIND_SUBNET,
    KIND_DEFAULT_ROUTE_TABLE,
    KIND_DEFAULT_SECURITY_LIST,
    KIND_DEFAULT_DHCP_OPTIONS,
)
PROVIDER_DEFAULT_KINDS = frozenset(
    {
        KIND_DEFAULT_ROUTE_TABLE,
        KIND_DEFAULT_SECURITY_LIST,
        KIND_DEFAULT_DHCP_OPTIONS,
    }
)
RUNTIME_SCOPE_SCHEMA = 1
CLEANUP_RECEIPT_SCHEMA = 1
RUNTIME_SCOPE_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "profile",
        "tenancy_id",
        "compartment_id",
        "subnet_id",
        "availability_domain",
        "region",
        "ui_ledger_path",
        "network_ledger_path",
    }
)
CLEANUP_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "tenancy_id",
        "compartment_id",
        "runtime_scope_digest",
        "ui_ledger_path",
        "ui_ledger_digest",
        "terminal_resources",
    }
)
UI_USER_RETAINED_KINDS = frozenset(
    {
        "customer_secret_key",
        "iam_membership",
        "iam_policy",
        "iam_group",
        "iam_user",
    }
)


class HarnessError(RuntimeError):
    """A bounded, secret-free safety or provider error."""


class ProviderCallError(HarnessError):
    """Provider failure classified without retaining the provider body."""

    def __init__(self, code: str, *, status: int | None = None, ambiguous=False):
        self.code = str(code)
        self.status = status
        self.ambiguous_outcome = bool(ambiguous)
        suffix = " The mutation outcome is unknown." if ambiguous else ""
        super().__init__(f"OCI request failed: {self.code}.{suffix}")


def _value(resource: Any, name: str, default: Any = None) -> Any:
    if isinstance(resource, dict):
        return resource.get(name, default)
    return getattr(resource, name, default)


def _data(response: Any) -> Any:
    return response.get("data") if isinstance(response, dict) else getattr(response, "data", None)


def _status(response: Any) -> int | None:
    value = response.get("status") if isinstance(response, dict) else getattr(response, "status", None)
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _headers(response: Any) -> dict[str, Any]:
    value = response.get("headers") if isinstance(response, dict) else getattr(response, "headers", None)
    return value if isinstance(value, dict) else {}


def _header(headers: dict[str, Any], name: str) -> Any:
    expected = str(name).casefold()
    for key, value in headers.items():
        if str(key).casefold() == expected:
            return value
    return None


def _next_page(response: Any) -> str:
    value = response.get("opc_next_page") if isinstance(response, dict) else getattr(response, "opc_next_page", None)
    if value in (None, ""):
        value = _header(_headers(response), "opc-next-page")
    return str(value).strip() if value not in (None, "") else ""


def _tags(resource: Any) -> dict[str, str]:
    value = _value(resource, "freeform_tags", {})
    return {str(key): str(item) for key, item in value.items()} if isinstance(value, dict) else {}


def _name(resource: Any) -> str:
    return str(_value(resource, "display_name") or _value(resource, "name") or "")


def _resource_id(resource: Any, *, label: str, resource_type: str | None = None) -> str:
    value = str(_value(resource, "id") or "").strip()
    if not OCI_OCID_RE.fullmatch(value):
        raise HarnessError(f"{label} was not a valid OCI OCID.")
    if resource_type and not value.startswith(f"ocid1.{resource_type}."):
        raise HarnessError(f"{label} was not an OCI {resource_type} OCID.")
    return value


def _require_ocid(value: Any, *, label: str, resource_type: str | None = None) -> str:
    value = str(value or "").strip()
    if not OCI_OCID_RE.fullmatch(value):
        raise HarnessError(f"{label} must be an OCI OCID.")
    if resource_type and not value.startswith(f"ocid1.{resource_type}."):
        raise HarnessError(f"{label} must be an OCI {resource_type} OCID.")
    return value


def _lifecycle(resource: Any) -> str:
    return str(_value(resource, "lifecycle_state") or "").upper()


def _normal_protocol(value: Any) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized in {"6", "tcp"}:
        return "6"
    if normalized in {"17", "udp"}:
        return "17"
    return normalized


def _port_pair(options: Any) -> tuple[int, int] | None:
    if options is None:
        return None
    port_range = _value(options, "destination_port_range")
    if port_range is None:
        nested = _value(options, "tcp_options") or _value(options, "udp_options")
        port_range = _value(nested, "destination_port_range") if nested is not None else None
    if port_range is None:
        return None
    try:
        return (int(_value(port_range, "min")), int(_value(port_range, "max")))
    except (TypeError, ValueError):
        return None


def _safe_error(error: BaseException) -> str:
    """Return a bounded diagnostic without provider response/credential text."""

    text = str(error or "")
    text = re.sub(
        r"(?i)(authorization|api[_-]?key|access[_-]?key|secret[_-]?key|token|password|private[_-]?key)\s*([:=])\s*[^\s,;]+",
        r"\1\2<redacted>",
        text,
    )
    return text[:500]


def _provider_error(error: BaseException, *, mutation: bool = False) -> ProviderCallError:
    status = getattr(error, "status", None) or getattr(error, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    code = str(getattr(error, "code", "") or "").casefold()
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        status = status or response.get("status") or response.get("status_code")
        code = code or str(response.get("code") or "").casefold()
    if status in {401, 403} or code in {"notauthenticated", "notauthorized"}:
        return ProviderCallError("PROVIDER_AUTH_FAILED", status=status)
    if code == "notauthorizedornotfound":
        return ProviderCallError(
            "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED", status=status, ambiguous=True
        )
    if status == 404 or code == "notfound":
        return ProviderCallError("PROVIDER_NOT_FOUND", status=status)
    if status == 429 or code in {"toomanyrequests", "throttled", "throttling"}:
        return ProviderCallError(
            "PROVIDER_RATE_LIMIT", status=status, ambiguous=mutation
        )
    error_name = type(error).__name__.casefold()
    if status in {408, 504} or "timeout" in error_name:
        return ProviderCallError("PROVIDER_TIMEOUT", status=status, ambiguous=mutation)
    if (isinstance(status, int) and status >= 500) or any(
        token in error_name for token in ("connection", "requestexception", "endpoint")
    ):
        return ProviderCallError(
            "PROVIDER_TRANSIENT_OUTAGE", status=status, ambiguous=mutation
        )
    return ProviderCallError("PROVIDER_REQUEST_FAILED", status=status)


def _checked(response: Any, accepted: Iterable[int]) -> Any:
    status = _status(response)
    if status not in set(accepted):
        raise HarnessError("OCI returned an unexpected response status.")
    return response


def iter_oci_pages(method: Callable[..., Any], *, max_pages=MAX_PAGES, max_items=MAX_ITEMS, **kwargs):
    """Yield every OCI cursor page with repeated-cursor and bound protection."""

    cursor = ""
    seen: set[str] = set()
    count = 0
    for _ in range(max_pages):
        request = dict(kwargs)
        request["limit"] = min(100, max_items - count)
        if cursor:
            request["page"] = cursor
        try:
            response = method(**request)
        except Exception as error:  # pragma: no cover - exercised via harness calls
            raise _provider_error(error) from error
        _checked(response, {200})
        items = _data(response)
        if not isinstance(items, (list, tuple)):
            raise HarnessError("OCI returned a malformed inventory page.")
        for item in items:
            count += 1
            if count > max_items:
                raise HarnessError("OCI inventory exceeded the safety limit.")
            yield item
        cursor = _next_page(response)
        if not cursor:
            return
        if cursor in seen:
            raise HarnessError("OCI returned a repeated inventory cursor.")
        seen.add(cursor)
    raise HarnessError("OCI inventory exceeded the page safety limit.")


def _lexical_path(value: Any, *, variable: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise HarnessError(f"{variable} is required.")
    expanded = os.path.expanduser(raw)
    path = Path(os.path.abspath(expanded))
    if "_docs" in path.parts:
        raise HarnessError(f"{variable} must not point inside _docs.")
    try:
        path.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise HarnessError(f"{variable} must be outside the repository.")
    return path


def _reject_symlink_components(path: Path, *, variable: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                raise HarnessError(f"{variable} must not use symlinked path components.")
        except OSError as error:
            raise HarnessError(f"{variable} could not be inspected safely.") from error


def _read_json_artifact(
    path_value: Any,
    *,
    variable: str,
    exact_keys: frozenset[str] | None = None,
    require_0600: bool = True,
) -> tuple[Path, dict[str, Any]]:
    path = _lexical_path(path_value, variable=variable)
    _reject_symlink_components(path, variable=variable)
    try:
        before = path.lstat()
    except OSError as error:
        raise HarnessError(f"{variable} is missing or unreadable.") from error
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_size > 256 * 1024
        or (require_0600 and mode != 0o600)
        or (not require_0600 and mode & 0o022)
    ):
        raise HarnessError(f"{variable} has unsafe type, mode, or size.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            raise HarnessError(f"{variable} changed while being opened.")
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = None
            payload = json.load(source)
    except HarnessError:
        raise
    except (OSError, ValueError) as error:
        raise HarnessError(f"{variable} is malformed.") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(payload, dict) or (
        exact_keys is not None and set(payload) != set(exact_keys)
    ):
        raise HarnessError(f"{variable} has an unsupported schema.")
    return path, payload


def _publish_private_bytes(path: Path, payload: bytes, *, variable: str) -> Path:
    """Create one file through a pinned parent fd without replacement races."""

    path = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_components(path.parent, variable=variable)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = None
    try:
        directory_fd = os.open(path.parent.anchor, flags)
        for component in path.parent.parts[1:]:
            created = False
            try:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    created = True
                except FileExistsError:
                    pass
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child_fd)
                raise HarnessError(f"{variable} parent path is not a directory.")
            if created:
                os.fchmod(child_fd, 0o700)
                os.fsync(child_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    except HarnessError:
        if directory_fd is not None:
            os.close(directory_fd)
        raise
    except OSError as error:
        if directory_fd is not None:
            os.close(directory_fd)
        raise HarnessError(f"{variable} parent directory could not be pinned.") from error
    temporary_name = f".{path.name}.{os.urandom(12).hex()}.tmp"
    target_created = False
    published = False
    cleanup_error = None
    try:
        pinned = os.fstat(directory_fd)
        try:
            visible = os.stat(path.parent, follow_symlinks=False)
        except OSError as error:
            raise HarnessError(f"{variable} parent directory changed.") from error
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_dev != visible.st_dev
            or pinned.st_ino != visible.st_ino
            or stat.S_IMODE(pinned.st_mode) & 0o022
        ):
            raise HarnessError(f"{variable} parent directory is unsafe or changed.")
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name, create_flags, 0o600, dir_fd=directory_fd
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            target_created = True
        except FileExistsError as error:
            raise HarnessError(
                f"{variable} appeared during write; refusing replacement."
            ) from error
        except OSError as error:
            raise HarnessError(f"{variable} could not be published safely.") from error
        try:
            current = os.stat(path.parent, follow_symlinks=False)
        except OSError as error:
            raise HarnessError(
                f"{variable} parent directory changed during publication."
            ) from error
        if current.st_dev != pinned.st_dev or current.st_ino != pinned.st_ino:
            raise HarnessError(f"{variable} parent directory changed during publication.")
        os.fsync(directory_fd)
        published = True
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as error:
            cleanup_error = error
        if target_created and (not published or cleanup_error is not None):
            try:
                os.unlink(path.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                target_created = False
                published = False
            except FileNotFoundError:
                target_created = False
            except OSError as error:
                cleanup_error = cleanup_error or error
        os.close(directory_fd)
        if cleanup_error is not None:
            raise HarnessError(
                f"{variable} publication rollback could not be completed safely."
            ) from cleanup_error
    return path


def _write_private_json(path_value: Any, payload: dict[str, Any], *, variable: str) -> Path:
    path = _lexical_path(path_value, variable=variable)
    _reject_symlink_components(path, variable=variable)
    if path.exists():
        raise HarnessError(f"{variable} already exists; refusing overwrite.")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return _publish_private_bytes(path, encoded, variable=variable)


def _digest_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _file_digest(path: Path, *, variable: str) -> str:
    path = Path(path)
    _reject_symlink_components(path, variable=variable)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HarnessError(f"{variable} is missing.") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HarnessError(f"{variable} must be a regular file.")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise HarnessError(f"{variable} changed while being opened.")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _parse_host_cidrs(value: Any) -> tuple[str, ...]:
    raw_values = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if not raw_values:
        raise HarnessError("ORACLE_E2E_CALLER_CIDRS must contain at least one host CIDR.")
    normalized: list[str] = []
    for raw in raw_values:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as error:
            raise HarnessError("Caller CIDRs must be valid /32 or /128 host networks.") from error
        expected_prefix = 32 if network.version == 4 else 128
        if network.prefixlen != expected_prefix:
            raise HarnessError("Caller CIDRs must be exact /32 or /128 hosts; broad CIDRs are refused.")
        canonical = str(network)
        if canonical not in normalized:
            normalized.append(canonical)
    if len(normalized) > 16:
        raise HarnessError("At most 16 caller host CIDRs are allowed.")
    return tuple(normalized)


def _parse_ports(value: Any) -> tuple[int, ...]:
    raw_values = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if not raw_values:
        return DEFAULT_DATABASE_PORTS
    ports: list[int] = []
    for raw in raw_values:
        try:
            port = int(raw)
        except (TypeError, ValueError) as error:
            raise HarnessError("ORACLE_E2E_DATABASE_PORTS must be comma-separated integers.") from error
        if not 1 <= port <= 65535 or port == 22:
            raise HarnessError("Database ports must be 1-65535 and must not include SSH port 22.")
        if port not in ports:
            ports.append(port)
    if len(ports) > 16:
        raise HarnessError("At most 16 database ports are allowed.")
    return tuple(ports)


def _parse_cidr(value: Any, *, label: str, minimum_prefix: int, maximum_prefix: int) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value), strict=True)
    except ValueError as error:
        raise HarnessError(f"{label} must be a valid IPv4 CIDR.") from error
    if network.version != 4 or not minimum_prefix <= network.prefixlen <= maximum_prefix:
        raise HarnessError(f"{label} must be an IPv4 network between /{minimum_prefix} and /{maximum_prefix}.")
    if not network.is_private:
        raise HarnessError(f"{label} must use a private RFC1918 network.")
    return network


def _subnet_in_vcn(vcn: ipaddress.IPv4Network, subnet: ipaddress.IPv4Network) -> bool:
    return subnet.subnet_of(vcn) and subnet != vcn


@dataclass(frozen=True)
class HarnessConfig:
    run_id: str
    allowed_tenancy_ocid: str
    profile: str
    config_file: Path
    ledger_path: Path
    ui_ledger_path: Path
    runtime_scope_path: Path
    ui_cleanup_receipt_path: Path
    availability_domain: str
    caller_cidrs: tuple[str, ...]
    database_ports: tuple[int, ...]
    vcn_cidr: str
    subnet_cidr: str
    apply: bool
    cleanup: bool
    poll_seconds: int
    timeout_seconds: int
    region: str = REGION

    @classmethod
    def from_environment(cls, environment: dict[str, Any] | None = None) -> "HarnessConfig":
        environment = dict(os.environ if environment is None else environment)
        run_id = require_run_id(str(environment.get("BACKUPSHEEP_E2E_RUN_ID") or "").strip())
        tenancy = _require_ocid(
            environment.get("ORACLE_E2E_ALLOWED_TENANCY_OCID"),
            label="ORACLE_E2E_ALLOWED_TENANCY_OCID",
            resource_type="tenancy",
        )
        profile = str(environment.get("OCI_CLI_PROFILE") or "").strip()
        if not profile or not PROFILE_RE.fullmatch(profile):
            raise HarnessError("OCI_CLI_PROFILE is required and contains unsupported characters.")
        config_file = _lexical_path(
            environment.get("OCI_CLI_CONFIG_FILE", "~/.oci/config"),
            variable="OCI_CLI_CONFIG_FILE",
        )
        ledger_path = _lexical_path(
            environment.get("BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH"),
            variable="BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH",
        )
        ui_ledger_path = _lexical_path(
            environment.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            variable="BACKUPSHEEP_E2E_LEDGER_PATH",
        )
        if ui_ledger_path == ledger_path:
            raise HarnessError("Oracle UI and network ledgers must use separate paths.")
        runtime_scope_path = _lexical_path(
            environment.get("ORACLE_E2E_RUNTIME_SCOPE_FILE"),
            variable="ORACLE_E2E_RUNTIME_SCOPE_FILE",
        )
        ui_cleanup_receipt_path = _lexical_path(
            environment.get("ORACLE_E2E_UI_CLEANUP_RECEIPT"),
            variable="ORACLE_E2E_UI_CLEANUP_RECEIPT",
        )
        protected_artifacts = {
            ledger_path,
            ui_ledger_path,
            runtime_scope_path,
            ui_cleanup_receipt_path,
        }
        if len(protected_artifacts) != 4:
            raise HarnessError(
                "Oracle network/UI ledgers, runtime scope, and cleanup receipt "
                "must use four distinct paths."
            )
        for path in protected_artifacts:
            _reject_symlink_components(path, variable="Oracle protected artifact")
        region = str(environment.get("ORACLE_E2E_REGION", REGION) or "").strip()
        if region != REGION:
            raise HarnessError(f"The Oracle fixture region must be exactly {REGION}.")
        availability_domain = str(environment.get("ORACLE_E2E_AVAILABILITY_DOMAIN") or "").strip()
        if not availability_domain or len(availability_domain) > 128:
            raise HarnessError("ORACLE_E2E_AVAILABILITY_DOMAIN is required.")
        caller_cidrs = _parse_host_cidrs(environment.get("ORACLE_E2E_CALLER_CIDRS"))
        database_ports = _parse_ports(
            environment.get("ORACLE_E2E_DATABASE_PORTS", ",".join(map(str, DEFAULT_DATABASE_PORTS)))
        )
        vcn = _parse_cidr(
            environment.get("ORACLE_E2E_VCN_CIDR", DEFAULT_VCN_CIDR),
            label="ORACLE_E2E_VCN_CIDR",
            minimum_prefix=16,
            maximum_prefix=20,
        )
        subnet = _parse_cidr(
            environment.get("ORACLE_E2E_SUBNET_CIDR", DEFAULT_SUBNET_CIDR),
            label="ORACLE_E2E_SUBNET_CIDR",
            minimum_prefix=24,
            maximum_prefix=28,
        )
        if not _subnet_in_vcn(vcn, subnet):
            raise HarnessError("ORACLE_E2E_SUBNET_CIDR must be a strict subnet of the VCN CIDR.")
        try:
            poll_seconds = max(int(environment.get("ORACLE_E2E_POLL_SECONDS", "10")), 2)
            timeout_seconds = max(int(environment.get("ORACLE_E2E_TIMEOUT_SECONDS", "1800")), 60)
        except (TypeError, ValueError) as error:
            raise HarnessError("Oracle fixture wait settings must be integers.") from error
        return cls(
            run_id=run_id,
            allowed_tenancy_ocid=tenancy,
            profile=profile,
            config_file=config_file,
            ledger_path=ledger_path,
            ui_ledger_path=ui_ledger_path,
            runtime_scope_path=runtime_scope_path,
            ui_cleanup_receipt_path=ui_cleanup_receipt_path,
            availability_domain=availability_domain,
            caller_cidrs=caller_cidrs,
            database_ports=database_ports,
            vcn_cidr=str(vcn),
            subnet_cidr=str(subnet),
            apply=str(environment.get("BACKUPSHEEP_E2E_APPLY") or "") == "YES",
            cleanup=str(environment.get("BACKUPSHEEP_E2E_CLEANUP") or "") == "YES",
            poll_seconds=poll_seconds,
            timeout_seconds=min(timeout_seconds, 7200),
            region=region,
        )


@dataclass(frozen=True)
class _Spec:
    kind: str
    name: str
    resource_type: str
    list_method: Callable[..., Any]
    list_kwargs: dict[str, Any]
    get_method: Callable[..., Any]
    get_kwarg: str
    create: Callable[[], Any]
    proof: dict[str, Any]
    ready_states: frozenset[str]
    failed_states: frozenset[str]
    find_extra: Callable[[Any], bool] | None = None


class OracleTestCompartmentHarness:
    """Provision and clean the exact network graph represented by one ledger."""

    def __init__(self, config: HarnessConfig, *, clients: dict[str, Any] | None = None, sleep=time.sleep):
        self.config = config
        self._clients = dict(clients or {})
        self._sleep = sleep
        self._stores: tuple[DurableResourceLedger, DurableMutationIntentStore] | None = None
        prefix = f"bs-e2e-{config.run_id}"
        self.names = {
            KIND_COMPARTMENT: f"{prefix}-compartment",
            KIND_VCN: f"{prefix}-vcn",
            KIND_INTERNET_GATEWAY: f"{prefix}-igw",
            KIND_ROUTE_TABLE: f"{prefix}-routes",
            KIND_SECURITY_LIST: f"{prefix}-security",
            KIND_SUBNET: f"{prefix}-subnet",
            KIND_DEFAULT_ROUTE_TABLE: f"Default Route Table for {prefix}-vcn",
            KIND_DEFAULT_SECURITY_LIST: f"Default Security List for {prefix}-vcn",
            KIND_DEFAULT_DHCP_OPTIONS: f"Default DHCP Options for {prefix}-vcn",
        }
        self.scope = f"oci:{config.allowed_tenancy_ocid}:{config.region}:{config.run_id}"

    def _tags_for(self, kind: str) -> dict[str, str]:
        if kind not in KINDS:
            raise HarnessError("Unsupported Oracle fixture resource kind.")
        if kind in PROVIDER_DEFAULT_KINDS:
            return {}
        return {TAG_RUN: self.config.run_id, TAG_OWNED: "true", TAG_KIND: kind}

    def plan(self) -> dict[str, Any]:
        """Return an inert plan; this method intentionally has no I/O."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "profile_loaded": False,
            "ledger_initialized": False,
            "region": self.config.region,
            "availability_domain": self.config.availability_domain,
            "caller_cidrs": list(self.config.caller_cidrs),
            "database_ports": list(self.config.database_ports),
            "egress": {
                "tcp_ports": list(EGRESS_TCP_PORTS),
                "udp_ports": list(EGRESS_UDP_PORTS),
                "destination": "0.0.0.0/0",
            },
            "resource_count": len(KINDS),
            "apply_enabled": self.config.apply,
            "cleanup_enabled": self.config.cleanup,
        }

    @staticmethod
    def inert_plan() -> dict[str, Any]:
        """Return the CLI plan without constructing config, stores, or clients."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "profile_loaded": False,
            "ledger_initialized": False,
            "config_loaded": False,
            "sdk_constructed": False,
        }

    def _require_apply(self) -> None:
        if not self.config.apply:
            raise HarnessError("Provider mutations require BACKUPSHEEP_E2E_APPLY=YES.")

    def _require_cleanup(self) -> None:
        self._require_apply()
        if not self.config.cleanup:
            raise HarnessError("Provider cleanup requires BACKUPSHEEP_E2E_CLEANUP=YES.")

    def _stores_for_mutation(self) -> tuple[DurableResourceLedger, DurableMutationIntentStore]:
        self._require_apply()
        if self._stores is None:
            # DurableResourceLedger and DurableMutationIntentStore create their
            # parent directory and fsynced files.  They are never constructed by
            # plan/config paths.
            ledger = DurableResourceLedger(
                self.config.ledger_path,
                provider="oracle_test_compartment",
                run_id=self.config.run_id,
                scope=self.scope,
            )
            intents = DurableMutationIntentStore(
                self.config.ledger_path,
                provider="oracle_test_compartment",
                run_id=self.config.run_id,
                scope=self.scope,
                suffix=".network-intents.json",
            )
            self._stores = (ledger, intents)
        return self._stores

    @property
    def ledger(self) -> DurableResourceLedger:
        return self._stores_for_mutation()[0]

    @property
    def intents(self) -> DurableMutationIntentStore:
        return self._stores_for_mutation()[1]

    def _models(self) -> Any:
        provided = self._clients.get("_models")
        if provided is not None:
            return provided
        try:
            from oci.core import models as core_models
            from oci.identity import models as identity_models
        except Exception as error:  # pragma: no cover - dependency is in app image
            raise HarnessError("The OCI Python SDK is required for provider mutations.") from error
        return type("Models", (), {**vars(core_models), **vars(identity_models)})

    def _load_clients(self) -> dict[str, Any]:
        required = {
            "identity",
            "network",
            "compute",
            "block",
            "object",
            "database",
            "mysql",
            "postgresql",
            "load_balancer",
            "network_load_balancer",
            "file_storage",
            "container_engine",
            "container_instances",
            "functions",
            "nosql",
        }
        if self._clients and not required.issubset(self._clients):
            raise HarnessError("Injected OCI clients are incomplete for survivor sweeps.")
        if self._clients and required.issubset(self._clients):
            return self._clients
        try:
            import oci

            loaded = oci.config.from_file(
                file_location=str(self.config.config_file),
                profile_name=self.config.profile,
            )
            oci.config.validate_config(loaded)
            kwargs = {"timeout": REQUEST_TIMEOUT, "retry_strategy": oci.retry.NoneRetryStrategy()}
            self._clients = {
                "_config": dict(loaded),
                "identity": oci.identity.IdentityClient(loaded, **kwargs),
                "network": oci.core.VirtualNetworkClient(loaded, **kwargs),
                "compute": oci.core.ComputeClient(loaded, **kwargs),
                "block": oci.core.BlockstorageClient(loaded, **kwargs),
                "object": oci.object_storage.ObjectStorageClient(loaded, **kwargs),
                "database": oci.database.DatabaseClient(loaded, **kwargs),
                "mysql": oci.mysql.DbSystemClient(loaded, **kwargs),
                "postgresql": oci.psql.PostgresqlClient(loaded, **kwargs),
                "load_balancer": oci.load_balancer.LoadBalancerClient(loaded, **kwargs),
                "network_load_balancer": oci.network_load_balancer.NetworkLoadBalancerClient(
                    loaded, **kwargs
                ),
                "file_storage": oci.file_storage.FileStorageClient(loaded, **kwargs),
                "container_engine": oci.container_engine.ContainerEngineClient(
                    loaded, **kwargs
                ),
                "container_instances": oci.container_instances.ContainerInstanceClient(
                    loaded, **kwargs
                ),
                "functions": oci.functions.FunctionsManagementClient(loaded, **kwargs),
                "nosql": oci.nosql.NosqlClient(loaded, **kwargs),
            }
        except HarnessError:
            raise
        except Exception as error:
            raise HarnessError(f"OCI profile loading failed: {_provider_error(error).code}.") from error
        return self._clients

    def _call(self, method: Callable[..., Any], *args, accepted=(200,), mutation=False, **kwargs) -> Any:
        try:
            response = method(*args, **kwargs)
            return _checked(response, accepted)
        except HarnessError:
            raise
        except Exception as error:
            raise _provider_error(error, mutation=mutation) from error

    def _validate_scope(self) -> None:
        clients = self._load_clients()
        configured = clients.get("_config") or {}
        tenancy = str(configured.get("tenancy") or "")
        region = str(configured.get("region") or "")
        if tenancy != self.config.allowed_tenancy_ocid:
            raise HarnessError("The configured OCI profile tenancy does not match the exact allowed tenancy.")
        if region != self.config.region:
            raise HarnessError("The configured OCI profile region is not us-ashburn-1.")
        identity = clients["identity"]
        get_tenancy = getattr(identity, "get_tenancy", None)
        if get_tenancy is None:
            raise HarnessError("The OCI identity client does not support exact tenancy verification.")
        tenancy_resource = _data(
            self._call(get_tenancy, tenancy_id=self.config.allowed_tenancy_ocid)
        )
        if str(_value(tenancy_resource, "id") or "") != self.config.allowed_tenancy_ocid:
            raise HarnessError("OCI tenancy read-back did not match the explicitly allowed tenancy.")
        availability = _data(
            self._call(
                identity.list_availability_domains,
                compartment_id=self.config.allowed_tenancy_ocid,
            )
        )
        if not isinstance(availability, (list, tuple)) or len(availability) > MAX_ITEMS:
            raise HarnessError("OCI availability-domain inventory was malformed.")
        exact_ad = [
            row
            for row in availability
            if str(_value(row, "name") or "") == self.config.availability_domain
        ]
        if len(exact_ad) != 1:
            raise HarnessError("The configured availability domain was not an exact active fact.")

    def _runtime_scope_payload(self, *, compartment_id: str, subnet_id: str) -> dict[str, Any]:
        return {
            "schema": RUNTIME_SCOPE_SCHEMA,
            "run_id": self.config.run_id,
            "profile": self.config.profile,
            "tenancy_id": self.config.allowed_tenancy_ocid,
            "compartment_id": _require_ocid(
                compartment_id, label="runtime compartment", resource_type="compartment"
            ),
            "subnet_id": _require_ocid(
                subnet_id, label="runtime subnet", resource_type="subnet"
            ),
            "availability_domain": self.config.availability_domain,
            "region": self.config.region,
            "ui_ledger_path": str(self.config.ui_ledger_path),
            "network_ledger_path": str(self.config.ledger_path),
        }

    def _validate_runtime_scope(self, payload: dict[str, Any], *, facts=None) -> dict[str, Any]:
        if set(payload) != set(RUNTIME_SCOPE_KEYS) or payload.get("schema") != RUNTIME_SCOPE_SCHEMA:
            raise HarnessError("Oracle runtime scope has an unsupported schema.")
        ui_ledger_path = _lexical_path(
            payload.get("ui_ledger_path"), variable="runtime ui ledger"
        )
        network_ledger_path = _lexical_path(
            payload.get("network_ledger_path"), variable="runtime network ledger"
        )
        _reject_symlink_components(ui_ledger_path, variable="runtime ui ledger")
        _reject_symlink_components(
            network_ledger_path, variable="runtime network ledger"
        )
        if (
            payload.get("run_id") != self.config.run_id
            or payload.get("profile") != self.config.profile
            or payload.get("tenancy_id") != self.config.allowed_tenancy_ocid
            or payload.get("availability_domain") != self.config.availability_domain
            or payload.get("region") != self.config.region
            or ui_ledger_path != self.config.ui_ledger_path
            or network_ledger_path != self.config.ledger_path
        ):
            raise HarnessError("Oracle runtime scope drifted from the exact configured run.")
        compartment_id = _require_ocid(
            payload.get("compartment_id"), label="runtime compartment", resource_type="compartment"
        )
        subnet_id = _require_ocid(
            payload.get("subnet_id"), label="runtime subnet", resource_type="subnet"
        )
        if facts and (
            compartment_id != facts["compartment_id"] or subnet_id != facts["subnet_id"]
        ):
            raise HarnessError("Oracle runtime scope does not match the exact network graph.")
        return dict(payload)

    def _ensure_runtime_scope(self, facts: dict[str, Any]) -> dict[str, Any]:
        expected = self._runtime_scope_payload(**facts)
        path = self.config.runtime_scope_path
        if path.exists():
            _path, current = _read_json_artifact(
                path,
                variable="ORACLE_E2E_RUNTIME_SCOPE_FILE",
                exact_keys=RUNTIME_SCOPE_KEYS,
            )
            self._validate_runtime_scope(current, facts=facts)
            if current != expected:
                raise HarnessError("Existing Oracle runtime scope differs from exact network facts.")
            return current
        _write_private_json(
            path, expected, variable="ORACLE_E2E_RUNTIME_SCOPE_FILE"
        )
        return expected

    def _preflight_runtime_scope_for_provision(self) -> None:
        """Reject unsafe or drifted resume artifacts before provider access."""

        intent_path = self.config.ledger_path.with_name(
            self.config.ledger_path.name + ".network-intents.json"
        )
        for variable, path in (
            ("BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH", self.config.ledger_path),
            ("Oracle network mutation intents", intent_path),
            ("ORACLE_E2E_RUNTIME_SCOPE_FILE", self.config.runtime_scope_path),
        ):
            _reject_symlink_components(path, variable=variable)
        if self.config.runtime_scope_path.exists():
            rows = self._read_network_rows_read_only()
            self._load_runtime_scope_for_graph(rows)

    def normalize_runtime_scope(self, network_output_path: str) -> dict[str, Any]:
        """Import old non-secret network output without reading the OCI profile."""

        _path, source = _read_json_artifact(
            network_output_path,
            variable="--network-output",
            require_0600=False,
        )
        if set(source) != {"phase", "run_id", "oracle_harness_environment"}:
            raise HarnessError("Legacy Oracle network output has an unsupported schema.")
        facts = source.get("oracle_harness_environment")
        expected_fact_keys = {
            "ORACLE_E2E_ALLOWED_TENANCY_OCID",
            "ORACLE_E2E_COMPARTMENT_OCID",
            "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID",
            "ORACLE_E2E_SUBNET_OCID",
            "ORACLE_E2E_AVAILABILITY_DOMAIN",
        }
        if (
            source.get("phase") != "PROVISIONED"
            or source.get("run_id") != self.config.run_id
            or not isinstance(facts, dict)
            or set(facts) != expected_fact_keys
            or facts["ORACLE_E2E_ALLOWED_TENANCY_OCID"]
            != self.config.allowed_tenancy_ocid
            or facts["ORACLE_E2E_COMPARTMENT_OCID"]
            != facts["ORACLE_E2E_ALLOWED_COMPARTMENT_OCID"]
            or facts["ORACLE_E2E_AVAILABILITY_DOMAIN"]
            != self.config.availability_domain
        ):
            raise HarnessError("Legacy Oracle network output does not match this exact run.")
        payload = self._runtime_scope_payload(
            compartment_id=facts["ORACLE_E2E_COMPARTMENT_OCID"],
            subnet_id=facts["ORACLE_E2E_SUBNET_OCID"],
        )
        if self.config.runtime_scope_path.exists():
            raise HarnessError("Runtime scope already exists; refusing normalization overwrite.")
        written = _write_private_json(
            self.config.runtime_scope_path,
            payload,
            variable="ORACLE_E2E_RUNTIME_SCOPE_FILE",
        )
        return {
            "phase": "RUNTIME_SCOPE_NORMALIZED",
            "run_id": self.config.run_id,
            "runtime_scope_file": str(written),
            "source_overwritten": False,
        }

    def _find_exact(self, spec: _Spec) -> Any | None:
        rows = list(iter_oci_pages(spec.list_method, **spec.list_kwargs))
        named = [row for row in rows if _name(row) == spec.name]
        exact = [row for row in named if self._matches(row, spec.proof) and (spec.find_extra is None or spec.find_extra(row))]
        if len(exact) > 1:
            raise HarnessError(f"Multiple exact {spec.kind} resources matched the run witness.")
        if any(row not in exact for row in named):
            raise HarnessError(f"A foreign Oracle resource uses the reserved {spec.kind} name.")
        return exact[0] if exact else None

    def _matches(self, resource: Any, proof: dict[str, Any]) -> bool:
        if str(_value(resource, "id") or "") == "":
            return False
        expected_name = str(proof.get("name") or "")
        if expected_name and _name(resource) != expected_name:
            return False
        expected_compartment = str(proof.get("compartment_id") or "")
        if expected_compartment and str(_value(resource, "compartment_id") or "") != expected_compartment:
            return False
        expected_tags = proof.get("tags") or {}
        actual_tags = _tags(resource)
        if any(actual_tags.get(key) != str(value) for key, value in expected_tags.items()):
            return False
        # ``parent_id`` is a durable witness field used by this harness; OCI
        # compartments expose the parent as ``compartment_id`` instead.
        for field in ("vcn_id", "route_table_id"):
            expected = str(proof.get(field) or "")
            if expected and str(_value(resource, field) or "") != expected:
                return False
        expected_cidr = str(proof.get("cidr_block") or "")
        if expected_cidr and str(_value(resource, "cidr_block") or "") != expected_cidr:
            cidrs = _value(resource, "cidr_blocks") or _value(resource, "ipv4_cidr_blocks") or []
            if expected_cidr not in {str(item) for item in cidrs}:
                return False
        return True

    def _entry(self, kind: str) -> dict[str, Any] | None:
        rows = self.ledger.entries(kind)
        if len(rows) > 1:
            raise HarnessError(f"The durable ledger contains duplicate {kind} entries.")
        row = rows[0] if rows else None
        if row and row.get("cleanup_state") not in {"eligible", "failed", "manual_review"}:
            raise HarnessError(f"Ledgered {kind} is already cleaned and cannot be replaced.")
        return row

    def _proof(
        self,
        kind: str,
        *,
        name: str,
        compartment_id: str,
        parent_id: str = "",
        vcn_id: str = "",
        route_table_id: str = "",
        cidr_block: str = "",
    ) -> dict[str, Any]:
        result = {
            "kind": kind,
            "name": name,
            "display_name": name,
            "compartment_id": compartment_id,
            "parent_id": parent_id,
            "vcn_id": vcn_id,
            "route_table_id": route_table_id,
            "cidr_block": cidr_block,
            "tags": self._tags_for(kind),
        }
        return result

    def _put_intent(self, spec: _Spec, operation="create", *, source_witness="") -> None:
        current = self.intents.get(spec.kind)
        if current:
            expected = current.get("proof")
            if expected is not None and expected != spec.proof:
                raise HarnessError(f"The pending {spec.kind} intent has a different ownership witness.")
            if current.get("name") != spec.name or current.get("operation") != operation:
                raise HarnessError(f"The pending {spec.kind} intent has a different mutation witness.")
            if current.get("source_witness") not in {None, "", str(source_witness or "")}:
                raise HarnessError(f"The pending {spec.kind} intent has a different source witness.")
            return
        self.intents.put(
            spec.kind,
            {
                "marker": self.config.run_id,
                "kind": spec.kind,
                "name": spec.name,
                "operation": operation,
                "proof": spec.proof,
                "source_witness": str(source_witness or ""),
                "mutation_started_at": time.time(),
            },
        )

    def _get_exact(self, spec: _Spec, resource_id: str) -> tuple[Any | None, bool]:
        try:
            response = self._call(spec.get_method, **{spec.get_kwarg: resource_id})
        except ProviderCallError as error:
            if error.code == "PROVIDER_NOT_FOUND":
                return None, True
            raise
        resource = _data(response)
        if resource is None:
            raise HarnessError(f"OCI returned no data for exact {spec.kind} resource.")
        return resource, False

    def _wait_and_verify(self, spec: _Spec, resource_id: str) -> Any:
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            resource, absent = self._get_exact(spec, resource_id)
            if absent:
                raise HarnessError(f"Exact ledgered {spec.kind} disappeared; no replacement will be created.")
            state = _lifecycle(resource)
            if state in spec.ready_states or not spec.ready_states:
                if not self._matches(resource, spec.proof) or (spec.find_extra and not spec.find_extra(resource)):
                    raise HarnessError(f"Exact {spec.kind} read-back failed ownership/dependency verification.")
                return resource
            if state in spec.failed_states or not state:
                raise HarnessError(f"Exact {spec.kind} entered a failed lifecycle state.")
            if time.monotonic() >= deadline:
                raise HarnessError(f"Exact {spec.kind} waiter reached its bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _record_and_clear(self, spec: _Spec, resource: Any, *, source_witness: str) -> Any:
        resource_id = _resource_id(resource, label=f"{spec.kind} resource", resource_type=spec.resource_type)
        self.ledger.record(
            kind=spec.kind,
            resource_id=resource_id,
            name=spec.name,
            ownership=spec.proof,
            source_witness=source_witness,
        )
        self.intents.clear(spec.kind)
        return resource

    def _adopt_pending(self, spec: _Spec, intent: dict[str, Any]) -> Any:
        provider_id = str(intent.get("provider_resource_id") or "")
        if provider_id:
            resource, absent = self._get_exact(spec, provider_id)
            if not absent:
                resource = self._wait_and_verify(spec, provider_id)
                return self._record_and_clear(
                    spec,
                    resource,
                    source_witness=str(intent.get("source_witness") or spec.proof.get("parent_id", "")),
                )
        candidate = self._find_exact(spec)
        if candidate is None:
            raise HarnessError(
                f"The {spec.kind} mutation intent is unresolved; no replacement create is permitted."
            )
        resource_id = _resource_id(candidate, label=f"adopted {spec.kind}", resource_type=spec.resource_type)
        self.intents.update(spec.kind, provider_resource_id=resource_id, adopted=True)
        resource = self._wait_and_verify(spec, resource_id)
        return self._record_and_clear(
            spec,
            resource,
            source_witness=str(intent.get("source_witness") or spec.proof.get("parent_id", "")),
        )

    def _ensure(self, spec: _Spec, *, source_witness: str) -> Any:
        row = self._entry(spec.kind)
        if row:
            resource, absent = self._get_exact(spec, str(row["resource_id"]))
            if absent:
                raise HarnessError(f"Ledgered {spec.kind} is absent; no replacement create is permitted.")
            return self._wait_and_verify(spec, str(row["resource_id"]))
        pending = self.intents.get(spec.kind)
        if pending:
            return self._adopt_pending(spec, pending)
        orphan = self._find_exact(spec)
        if orphan is not None:
            raise HarnessError(f"An exact {spec.kind} resource exists without a durable mutation intent.")
        self._put_intent(spec, source_witness=source_witness)
        try:
            response = self._call(spec.create, accepted=(200, 201, 202), mutation=True)
        except ProviderCallError as error:
            # A timeout/rate-limit/connection failure can mean the provider
            # accepted the request.  Scan and adopt one exact marker match;
            # never issue a second create for an unresolved intent.
            candidate = self._find_exact(spec)
            if candidate is None:
                raise error
            resource_id = _resource_id(candidate, label=f"adopted {spec.kind}", resource_type=spec.resource_type)
            self.intents.update(spec.kind, provider_resource_id=resource_id, adopted=True, provider_error=error.code)
            resource = self._wait_and_verify(spec, resource_id)
            return self._record_and_clear(spec, resource, source_witness=source_witness)
        candidate = _data(response)
        if candidate is None or not _value(candidate, "id"):
            candidate = self._find_exact(spec)
            if candidate is None:
                raise HarnessError(f"OCI create returned no exact {spec.kind} resource ID.")
        resource_id = _resource_id(candidate, label=f"created {spec.kind}", resource_type=spec.resource_type)
        self.intents.update(spec.kind, provider_resource_id=resource_id)
        resource = self._wait_and_verify(spec, resource_id)
        return self._record_and_clear(spec, resource, source_witness=source_witness)

    def _make_spec(
        self,
        *,
        kind: str,
        resource_type: str,
        list_method: Callable[..., Any],
        list_kwargs: dict[str, Any],
        get_method: Callable[..., Any],
        get_kwarg: str,
        create: Callable[[], Any],
        proof: dict[str, Any],
        ready_states=("AVAILABLE",),
        failed_states=("FAILED", "FAULTY", "TERMINATED", "TERMINATING"),
        find_extra=None,
    ) -> _Spec:
        return _Spec(
            kind=kind,
            name=str(proof["name"]),
            resource_type=resource_type,
            list_method=list_method,
            list_kwargs=dict(list_kwargs),
            get_method=get_method,
            get_kwarg=get_kwarg,
            create=create,
            proof=proof,
            ready_states=frozenset(ready_states),
            failed_states=frozenset(failed_states),
            find_extra=find_extra,
        )

    def _compartment_spec(self, identity) -> _Spec:
        kind = KIND_COMPARTMENT
        parent = self.config.allowed_tenancy_ocid
        proof = self._proof(kind, name=self.names[kind], compartment_id=parent, parent_id=parent)
        models = self._models()
        details = models.CreateCompartmentDetails(
            compartment_id=parent,
            name=self.names[kind],
            description=f"BackupSheep isolated Oracle E2E fixture {self.config.run_id}",
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="compartment",
            list_method=identity.list_compartments,
            list_kwargs={"compartment_id": parent},
            get_method=identity.get_compartment,
            get_kwarg="compartment_id",
            create=lambda: identity.create_compartment(
                create_compartment_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
            ready_states=("ACTIVE",),
            failed_states=("DELETED", "INACTIVE"),
            find_extra=lambda resource: str(_value(resource, "compartment_id") or "") == parent,
        )

    def _vcn_spec(self, network, compartment_id: str) -> _Spec:
        kind = KIND_VCN
        proof = self._proof(
            kind,
            name=self.names[kind],
            compartment_id=compartment_id,
            cidr_block=self.config.vcn_cidr,
        )
        models = self._models()
        details = models.CreateVcnDetails(
            compartment_id=compartment_id,
            display_name=self.names[kind],
            cidr_blocks=[self.config.vcn_cidr],
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="vcn",
            list_method=network.list_vcns,
            list_kwargs={"compartment_id": compartment_id},
            get_method=network.get_vcn,
            get_kwarg="vcn_id",
            create=lambda: network.create_vcn(
                create_vcn_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
        )

    def _provider_default_spec(
        self,
        network,
        *,
        kind: str,
        name: str,
        resource_type: str,
        list_method: Callable[..., Any],
        get_method: Callable[..., Any],
        get_kwarg: str,
        compartment_id: str,
        vcn_id: str,
        find_extra: Callable[[Any], bool] | None = None,
    ) -> _Spec:
        proof = self._proof(
            kind,
            name=name,
            compartment_id=compartment_id,
            vcn_id=vcn_id,
        )
        return self._make_spec(
            kind=kind,
            resource_type=resource_type,
            list_method=list_method,
            list_kwargs={"compartment_id": compartment_id, "vcn_id": vcn_id},
            get_method=get_method,
            get_kwarg=get_kwarg,
            # Provider-created defaults are never created by this harness.  A
            # callable is retained in the spec so accidental use fails closed.
            create=lambda: (_ for _ in ()).throw(
                HarnessError("Provider defaults may only be adopted by exact read-back.")
            ),
            proof=proof,
            find_extra=find_extra,
        )

    def _provider_default_specs(self, network, compartment_id: str, vcn_id: str) -> tuple[_Spec, ...]:
        return (
            self._provider_default_spec(
                network,
                kind=KIND_DEFAULT_ROUTE_TABLE,
                name=self.names[KIND_DEFAULT_ROUTE_TABLE],
                resource_type="routetable",
                list_method=network.list_route_tables,
                get_method=network.get_route_table,
                get_kwarg="rt_id",
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                find_extra=lambda resource: not (_value(resource, "route_rules") or []),
            ),
            self._provider_default_spec(
                network,
                kind=KIND_DEFAULT_SECURITY_LIST,
                name=self.names[KIND_DEFAULT_SECURITY_LIST],
                resource_type="securitylist",
                list_method=network.list_security_lists,
                get_method=network.get_security_list,
                get_kwarg="security_list_id",
                compartment_id=compartment_id,
                vcn_id=vcn_id,
            ),
            self._provider_default_spec(
                network,
                kind=KIND_DEFAULT_DHCP_OPTIONS,
                name=self.names[KIND_DEFAULT_DHCP_OPTIONS],
                resource_type="dhcpoptions",
                list_method=network.list_dhcp_options,
                get_method=network.get_dhcp_options,
                get_kwarg="dhcp_id",
                compartment_id=compartment_id,
                vcn_id=vcn_id,
            ),
        )

    def _adopt_provider_default(self, spec: _Spec, *, source_witness: str) -> Any:
        row = self._entry(spec.kind)
        if row:
            resource, absent = self._get_exact(spec, str(row["resource_id"]))
            if absent:
                raise HarnessError(
                    f"Ledgered provider default {spec.kind} is absent; no replacement is permitted."
                )
            return self._wait_and_verify(spec, str(row["resource_id"]))
        candidate = self._find_exact(spec)
        if candidate is None:
            raise HarnessError(
                f"OCI did not expose the exact provider-created {spec.kind} dependency."
            )
        resource = self._wait_and_verify(
            spec,
            _resource_id(candidate, label=f"provider-created {spec.kind}", resource_type=spec.resource_type),
        )
        return self._record_and_clear(spec, resource, source_witness=source_witness)

    def _igw_spec(self, network, compartment_id: str, vcn_id: str) -> _Spec:
        kind = KIND_INTERNET_GATEWAY
        proof = self._proof(kind, name=self.names[kind], compartment_id=compartment_id, vcn_id=vcn_id)
        models = self._models()
        details = models.CreateInternetGatewayDetails(
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            display_name=self.names[kind],
            is_enabled=True,
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="internetgateway",
            list_method=network.list_internet_gateways,
            list_kwargs={"compartment_id": compartment_id, "vcn_id": vcn_id},
            get_method=network.get_internet_gateway,
            get_kwarg="ig_id",
            create=lambda: network.create_internet_gateway(
                create_internet_gateway_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
            find_extra=lambda resource: str(_value(resource, "vcn_id") or "") == vcn_id,
        )

    def _route_spec(self, network, compartment_id: str, vcn_id: str, igw_id: str) -> _Spec:
        kind = KIND_ROUTE_TABLE
        proof = self._proof(kind, name=self.names[kind], compartment_id=compartment_id, vcn_id=vcn_id)
        models = self._models()
        rule = models.RouteRule(
            destination="0.0.0.0/0",
            destination_type="CIDR_BLOCK",
            network_entity_id=igw_id,
        )
        details = models.CreateRouteTableDetails(
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            display_name=self.names[kind],
            route_rules=[rule],
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="routetable",
            list_method=network.list_route_tables,
            list_kwargs={"compartment_id": compartment_id, "vcn_id": vcn_id},
            get_method=network.get_route_table,
            get_kwarg="rt_id",
            create=lambda: network.create_route_table(
                create_route_table_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
            find_extra=lambda resource: self._route_rules_exact(resource, igw_id),
        )

    def _security_spec(self, network, compartment_id: str, vcn_id: str) -> _Spec:
        kind = KIND_SECURITY_LIST
        proof = self._proof(kind, name=self.names[kind], compartment_id=compartment_id, vcn_id=vcn_id)
        models = self._models()
        ingress = [
            models.IngressSecurityRule(
                protocol="6",
                source=cidr,
                source_type="CIDR_BLOCK",
                tcp_options=models.TcpOptions(
                    destination_port_range=models.PortRange(min=port, max=port)
                ),
            )
            for cidr in self.config.caller_cidrs
            for port in (22, *self.config.database_ports)
        ]
        egress = [
            models.EgressSecurityRule(
                protocol="6",
                destination="0.0.0.0/0",
                destination_type="CIDR_BLOCK",
                tcp_options=models.TcpOptions(
                    destination_port_range=models.PortRange(min=port, max=port)
                ),
            )
            for port in EGRESS_TCP_PORTS
        ] + [
            models.EgressSecurityRule(
                protocol="17",
                destination="0.0.0.0/0",
                destination_type="CIDR_BLOCK",
                udp_options=models.UdpOptions(
                    destination_port_range=models.PortRange(min=port, max=port)
                ),
            )
            for port in EGRESS_UDP_PORTS
        ]
        details = models.CreateSecurityListDetails(
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            display_name=self.names[kind],
            ingress_security_rules=ingress,
            egress_security_rules=egress,
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="securitylist",
            list_method=network.list_security_lists,
            list_kwargs={"compartment_id": compartment_id, "vcn_id": vcn_id},
            get_method=network.get_security_list,
            get_kwarg="security_list_id",
            create=lambda: network.create_security_list(
                create_security_list_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
            find_extra=self._security_rules_exact,
        )

    def _subnet_spec(
        self,
        network,
        compartment_id: str,
        vcn_id: str,
        route_table_id: str,
        security_list_id: str,
    ) -> _Spec:
        kind = KIND_SUBNET
        proof = self._proof(
            kind,
            name=self.names[kind],
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            route_table_id=route_table_id,
            cidr_block=self.config.subnet_cidr,
        )
        models = self._models()
        details = models.CreateSubnetDetails(
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            display_name=self.names[kind],
            cidr_block=self.config.subnet_cidr,
            route_table_id=route_table_id,
            security_list_ids=[security_list_id],
            prohibit_public_ip_on_vnic=False,
            prohibit_internet_ingress=False,
            freeform_tags=self._tags_for(kind),
        )
        return self._make_spec(
            kind=kind,
            resource_type="subnet",
            list_method=network.list_subnets,
            list_kwargs={"compartment_id": compartment_id, "vcn_id": vcn_id},
            get_method=network.get_subnet,
            get_kwarg="subnet_id",
            create=lambda: network.create_subnet(
                create_subnet_details=details,
                opc_retry_token=self._retry_token(kind),
            ),
            proof=proof,
            find_extra=lambda resource: (
                str(_value(resource, "route_table_id") or "") == route_table_id
                and set(str(item) for item in (_value(resource, "security_list_ids") or [])) == {security_list_id}
                and _value(resource, "prohibit_public_ip_on_vnic") is False
            ),
        )

    def _retry_token(self, kind: str) -> str:
        return "bs-" + hashlib.sha256(f"{self.scope}:{kind}".encode()).hexdigest()[:61]

    def _route_rules_exact(self, resource: Any, igw_id: str) -> bool:
        rules = _value(resource, "route_rules") or []
        if len(rules) != 1:
            return False
        rule = rules[0]
        return (
            str(_value(rule, "destination") or _value(rule, "cidr_block") or "") == "0.0.0.0/0"
            and str(_value(rule, "network_entity_id") or "") == igw_id
        )

    def _security_rules_exact(self, resource: Any) -> bool:
        expected_ingress = {
            ("6", cidr, port)
            for cidr in self.config.caller_cidrs
            for port in (22, *self.config.database_ports)
        }
        actual_ingress = set()
        for rule in _value(resource, "ingress_security_rules") or []:
            pair = _port_pair(rule)
            actual_ingress.add((_normal_protocol(_value(rule, "protocol")), str(_value(rule, "source") or ""), pair[0] if pair and pair[0] == pair[1] else -1))
        if actual_ingress != expected_ingress:
            return False
        expected_tcp = {("6", "0.0.0.0/0", port) for port in EGRESS_TCP_PORTS}
        expected_udp = {("17", "0.0.0.0/0", port) for port in EGRESS_UDP_PORTS}
        actual_egress = set()
        for rule in _value(resource, "egress_security_rules") or []:
            pair = _port_pair(rule)
            actual_egress.add((_normal_protocol(_value(rule, "protocol")), str(_value(rule, "destination") or ""), pair[0] if pair and pair[0] == pair[1] else -1))
        return actual_egress == expected_tcp | expected_udp

    def _provision_graph(self) -> dict[str, Any]:
        clients = self._load_clients()
        self._validate_scope()
        identity = clients["identity"]
        network = clients["network"]
        compartment_spec = self._compartment_spec(identity)
        compartment = self._ensure(compartment_spec, source_witness=self.config.allowed_tenancy_ocid)
        compartment_id = _resource_id(compartment, label="test compartment", resource_type="compartment")
        vcn_spec = self._vcn_spec(network, compartment_id)
        vcn = self._ensure(vcn_spec, source_witness=compartment_id)
        vcn_id = _resource_id(vcn, label="test VCN", resource_type="vcn")
        for default_spec in self._provider_default_specs(network, compartment_id, vcn_id):
            self._adopt_provider_default(default_spec, source_witness=vcn_id)
        igw_spec = self._igw_spec(network, compartment_id, vcn_id)
        igw = self._ensure(igw_spec, source_witness=vcn_id)
        igw_id = _resource_id(igw, label="test internet gateway", resource_type="internetgateway")
        route_spec = self._route_spec(network, compartment_id, vcn_id, igw_id)
        route = self._ensure(route_spec, source_witness=igw_id)
        route_id = _resource_id(route, label="test route table", resource_type="routetable")
        security_spec = self._security_spec(network, compartment_id, vcn_id)
        security = self._ensure(security_spec, source_witness=vcn_id)
        security_id = _resource_id(security, label="test security list", resource_type="securitylist")
        subnet_spec = self._subnet_spec(network, compartment_id, vcn_id, route_id, security_id)
        subnet = self._ensure(subnet_spec, source_witness=f"{route_id}:{security_id}")
        subnet_id = _resource_id(subnet, label="test subnet", resource_type="subnet")
        return {
            "compartment_id": compartment_id,
            "subnet_id": subnet_id,
        }

    def provision(self) -> dict[str, Any]:
        self._require_apply()
        self._preflight_runtime_scope_for_provision()
        facts = self._provision_graph()
        self._ensure_runtime_scope(facts)
        # Only these non-secret values are intended to be copied into the
        # environment used by oracle_live_ui_e2e.py.
        return {
            "phase": "PROVISIONED",
            "run_id": self.config.run_id,
            "oracle_harness_environment": {
                "ORACLE_E2E_ALLOWED_TENANCY_OCID": self.config.allowed_tenancy_ocid,
                "ORACLE_E2E_COMPARTMENT_OCID": facts["compartment_id"],
                "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID": facts["compartment_id"],
                "ORACLE_E2E_SUBNET_OCID": facts["subnet_id"],
                "ORACLE_E2E_AVAILABILITY_DOMAIN": self.config.availability_domain,
            },
        }

    def _ledger_specs(self) -> dict[str, dict[str, Any]]:
        entries = self.ledger.entries()
        kinds = [str(row.get("kind") or "") for row in entries]
        if set(kinds) - set(KINDS) or len(kinds) != len(set(kinds)):
            raise HarnessError("The network ledger contains unsupported or duplicate resource kinds.")
        rows = {row["kind"]: row for row in entries}
        return rows

    def _resource_from_row(self, kind: str, row: dict[str, Any]) -> Any | None:
        clients = self._clients
        identity = clients["identity"]
        network = clients["network"]
        methods = {
            KIND_COMPARTMENT: (identity.get_compartment, "compartment_id"),
            KIND_VCN: (network.get_vcn, "vcn_id"),
            KIND_INTERNET_GATEWAY: (network.get_internet_gateway, "ig_id"),
            KIND_ROUTE_TABLE: (network.get_route_table, "rt_id"),
            KIND_SECURITY_LIST: (network.get_security_list, "security_list_id"),
            KIND_SUBNET: (network.get_subnet, "subnet_id"),
            KIND_DEFAULT_ROUTE_TABLE: (network.get_route_table, "rt_id"),
            KIND_DEFAULT_SECURITY_LIST: (network.get_security_list, "security_list_id"),
            KIND_DEFAULT_DHCP_OPTIONS: (network.get_dhcp_options, "dhcp_id"),
        }
        method, argument = methods[kind]
        try:
            return _data(self._call(method, **{argument: str(row["resource_id"])}))
        except ProviderCallError as error:
            if error.code == "PROVIDER_NOT_FOUND":
                return None
            raise

    def _verify_cleanup_graph(self, rows: dict[str, dict[str, Any]]) -> None:
        if set(rows) != set(KINDS):
            raise HarnessError("Cleanup requires a complete compartment/network ledger graph.")
        root = self.config.allowed_tenancy_ocid
        compartment = rows[KIND_COMPARTMENT]
        vcn = rows[KIND_VCN]
        igw = rows[KIND_INTERNET_GATEWAY]
        route = rows[KIND_ROUTE_TABLE]
        security = rows[KIND_SECURITY_LIST]
        subnet = rows[KIND_SUBNET]
        expected_ids = {
            kind: str(row["resource_id"])
            for kind, row in rows.items()
            if row.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        }
        resources = {
            kind: self._resource_from_row(kind, row)
            for kind, row in rows.items()
        }
        if resources[KIND_COMPARTMENT] is None:
            if any(resource is not None for resource in resources.values()):
                raise HarnessError("Cleanup found a network resource after its parent compartment disappeared.")
            return
        for kind, row in rows.items():
            resource = resources[kind]
            if resource is None:
                continue
            if not self._row_matches_resource(row, resource):
                raise HarnessError(f"Cleanup ownership verification failed for {kind}.")
            if str(row.get("source_witness") or "") != str(
                {
                    KIND_COMPARTMENT: root,
                    KIND_VCN: str(compartment["resource_id"]),
                    KIND_INTERNET_GATEWAY: str(vcn["resource_id"]),
                    KIND_ROUTE_TABLE: str(igw["resource_id"]),
                    KIND_SECURITY_LIST: str(vcn["resource_id"]),
                    KIND_SUBNET: f"{route['resource_id']}:{security['resource_id']}",
                    KIND_DEFAULT_ROUTE_TABLE: str(vcn["resource_id"]),
                    KIND_DEFAULT_SECURITY_LIST: str(vcn["resource_id"]),
                    KIND_DEFAULT_DHCP_OPTIONS: str(vcn["resource_id"]),
                }[kind]
            ):
                raise HarnessError(f"Cleanup source witness failed for {kind}.")
        # A dedicated child compartment must contain no unledgered dependency.
        network = self._clients["network"]
        child_id = str(compartment["resource_id"])
        inventories = {
            KIND_VCN: list(iter_oci_pages(network.list_vcns, compartment_id=child_id)),
            KIND_INTERNET_GATEWAY: list(iter_oci_pages(network.list_internet_gateways, compartment_id=child_id)),
            KIND_ROUTE_TABLE: list(iter_oci_pages(network.list_route_tables, compartment_id=child_id)),
            KIND_SECURITY_LIST: list(iter_oci_pages(network.list_security_lists, compartment_id=child_id)),
            KIND_SUBNET: list(iter_oci_pages(network.list_subnets, compartment_id=child_id)),
            KIND_DEFAULT_DHCP_OPTIONS: list(
                iter_oci_pages(network.list_dhcp_options, compartment_id=child_id)
            ),
        }
        for kind, items in inventories.items():
            related_kinds = {
                KIND_VCN: (KIND_VCN,),
                KIND_INTERNET_GATEWAY: (KIND_INTERNET_GATEWAY,),
                KIND_ROUTE_TABLE: (KIND_ROUTE_TABLE, KIND_DEFAULT_ROUTE_TABLE),
                KIND_SECURITY_LIST: (KIND_SECURITY_LIST, KIND_DEFAULT_SECURITY_LIST),
                KIND_SUBNET: (KIND_SUBNET,),
                KIND_DEFAULT_DHCP_OPTIONS: (KIND_DEFAULT_DHCP_OPTIONS,),
            }[kind]
            allowed = {
                expected_ids.get(related_kind)
                for related_kind in related_kinds
            } - {None}
            actual = {str(_value(item, "id") or "") for item in items}
            if actual - allowed:
                raise HarnessError(f"Cleanup found an unledgered or foreign {kind} dependency.")
            missing_expected = allowed - actual
            if missing_expected:
                # The exact resource may already have been deleted; the ledger
                # state is reconciled by exact get below, never by name.
                for expected_id in missing_expected:
                    lookup_kind = next(
                        related_kind
                        for related_kind in related_kinds
                        if expected_ids.get(related_kind) == expected_id
                    )
                    _exact, absent = self._get_by_kind(lookup_kind, expected_id)
                    if not absent:
                        raise HarnessError(
                            f"Cleanup inventory omitted the exact ledgered {lookup_kind}."
                        )
        children = list(
            iter_oci_pages(
                self._clients["identity"].list_compartments,
                compartment_id=child_id,
            )
        )
        if children:
            raise HarnessError("Cleanup is blocked by a child compartment dependency.")
        # Verify the exact topology again immediately before any delete.
        route_resource = self._resource_from_row(KIND_ROUTE_TABLE, route)
        if route_resource is not None and not self._route_rules_exact(
            route_resource, str(igw["resource_id"])
        ):
            raise HarnessError("Cleanup route-table source graph changed.")
        security_resource = self._resource_from_row(KIND_SECURITY_LIST, security)
        if security_resource is not None and not self._security_rules_exact(security_resource):
            raise HarnessError("Cleanup security-list ingress/egress graph changed.")
        igw_resource = resources[KIND_INTERNET_GATEWAY]
        if igw_resource is not None and (
            str(_value(igw_resource, "vcn_id") or "") != str(vcn["resource_id"])
            or _value(igw_resource, "is_enabled") is not True
        ):
            raise HarnessError("Cleanup internet-gateway dependency graph changed.")
        subnet_resource = resources[KIND_SUBNET]
        if subnet_resource is not None and (
            str(_value(subnet_resource, "vcn_id") or "") != str(vcn["resource_id"])
            or str(_value(subnet_resource, "route_table_id") or "") != str(route["resource_id"])
            or set(str(item) for item in (_value(subnet_resource, "security_list_ids") or []))
            != {str(security["resource_id"])}
            or _value(subnet_resource, "prohibit_public_ip_on_vnic") is not False
        ):
            raise HarnessError("Cleanup subnet dependency graph changed.")

    def _get_by_kind(self, kind: str, resource_id: str) -> tuple[Any | None, bool]:
        rows = {kind: {"resource_id": resource_id}}
        resource = self._resource_from_row(kind, rows[kind])
        return resource, resource is None

    def _row_matches_resource(self, row: dict[str, Any], resource: Any) -> bool:
        return (
            str(_value(resource, "id") or "") == str(row.get("resource_id") or "")
            and self._matches(resource, row.get("ownership") or {})
        )

    def _delete_kind(self, kind: str, row: dict[str, Any]) -> str:
        if kind in PROVIDER_DEFAULT_KINDS:
            raise HarnessError(
                "OCI VCN default resources are provider-managed and must never be deleted directly."
            )
        if row.get("cleanup_state") in {"deleted", "absent"}:
            return "ALREADY_ABSENT"
        resource = self._resource_from_row(kind, row)
        if resource is None:
            self.ledger.mark_cleanup(kind, row["resource_id"], state="absent")
            return "ABSENT"
        # Recheck exact proof immediately before the mutation, including all
        # dependency fields retained in ownership.
        if not self._row_matches_resource(row, resource):
            self.ledger.mark_cleanup(kind, row["resource_id"], state="manual_review", error="ownership drift")
            raise HarnessError(f"Cleanup ownership changed for {kind}; deletion stopped.")
        clients = self._clients
        methods = {
            KIND_COMPARTMENT: (clients["identity"].delete_compartment, "compartment_id"),
            KIND_VCN: (clients["network"].delete_vcn, "vcn_id"),
            KIND_INTERNET_GATEWAY: (clients["network"].delete_internet_gateway, "ig_id"),
            KIND_ROUTE_TABLE: (clients["network"].delete_route_table, "rt_id"),
            KIND_SECURITY_LIST: (clients["network"].delete_security_list, "security_list_id"),
            KIND_SUBNET: (clients["network"].delete_subnet, "subnet_id"),
        }
        method, argument = methods[kind]
        try:
            self._call(method, **{argument: str(row["resource_id"])}, accepted=(200, 202, 204), mutation=True)
        except ProviderCallError as error:
            # An unknown delete result is not a license to retry.  Prove exact
            # absence first; otherwise keep the durable row for manual review.
            after = self._resource_from_row(kind, row)
            if after is None:
                self.ledger.mark_cleanup(kind, row["resource_id"], state="deleted")
                return "DELETED"
            self.ledger.mark_cleanup(kind, row["resource_id"], state="manual_review", error=error.code)
            raise
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            after = self._resource_from_row(kind, row)
            if after is None:
                self.ledger.mark_cleanup(kind, row["resource_id"], state="deleted")
                return "DELETED"
            if time.monotonic() >= deadline:
                self.ledger.mark_cleanup(kind, row["resource_id"], state="manual_review", error="absence timeout")
                raise HarnessError(f"OCI did not prove {kind} absence within the bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _reconcile_provider_defaults_after_vcn_absence(
        self,
        rows: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        """Mark VCN defaults absent only after provider-confirmed VCN cascade.

        OCI prohibits direct deletion of a VCN's default route table, default
        security list, and default DHCP options.  Their exact OCIDs remain
        durable ownership/dependency witnesses until the exact VCN read returns
        a definitive not-found and each default OCID independently does the
        same.  Ambiguous authorization/not-found responses are not absence.
        """

        vcn_row = rows[KIND_VCN]
        if self._resource_from_row(KIND_VCN, vcn_row) is not None:
            raise HarnessError(
                "Provider-default reconciliation requires proven exact VCN absence."
            )
        vcn_id = str(vcn_row.get("resource_id") or "")
        max_attempts = max(
            1,
            min(
                1000,
                (self.config.timeout_seconds + self.config.poll_seconds - 1)
                // self.config.poll_seconds,
            ),
        )
        results: dict[str, str] = {}
        for kind in (
            KIND_DEFAULT_ROUTE_TABLE,
            KIND_DEFAULT_SECURITY_LIST,
            KIND_DEFAULT_DHCP_OPTIONS,
        ):
            row = rows[kind]
            if str(row.get("source_witness") or "") != vcn_id:
                if row.get("cleanup_state") not in {"deleted", "absent"}:
                    self.ledger.mark_cleanup(
                        kind,
                        row["resource_id"],
                        state="manual_review",
                        error="VCN source witness drift",
                    )
                raise HarnessError(
                    f"Provider-default {kind} no longer has the exact VCN source witness."
                )
            if row.get("cleanup_state") == "deleted":
                raise HarnessError(
                    f"Provider-default {kind} was incorrectly recorded as directly deleted."
                )
            if row.get("cleanup_state") == "absent":
                results[kind] = "ALREADY_ABSENT_AFTER_VCN_CASCADE"
                continue
            for attempt in range(max_attempts):
                resource = self._resource_from_row(kind, row)
                if resource is None:
                    self.ledger.mark_cleanup(
                        kind,
                        row["resource_id"],
                        state="absent",
                    )
                    results[kind] = "ABSENT_AFTER_VCN_CASCADE"
                    break
                if not self._row_matches_resource(row, resource):
                    self.ledger.mark_cleanup(
                        kind,
                        row["resource_id"],
                        state="manual_review",
                        error="ownership drift after VCN deletion",
                    )
                    raise HarnessError(
                        f"Provider-default {kind} ownership changed during VCN cascade."
                    )
                if attempt + 1 == max_attempts:
                    self.ledger.mark_cleanup(
                        kind,
                        row["resource_id"],
                        state="manual_review",
                        error="VCN cascade absence timeout",
                    )
                    raise HarnessError(
                        f"OCI did not prove provider-default {kind} absence after VCN deletion."
                    )
                self._sleep(self.config.poll_seconds)
        return results

    def _read_network_rows_read_only(self) -> dict[str, dict[str, Any]]:
        _path, payload = _read_json_artifact(
            self.config.ledger_path,
            variable="BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH",
            require_0600=True,
        )
        if (
            payload.get("schema") != 1
            or payload.get("provider") != "oracle_test_compartment"
            or payload.get("run_id") != self.config.run_id
            or payload.get("scope") != self.scope
            or not isinstance(payload.get("resources"), list)
        ):
            raise HarnessError("Oracle network ledger does not match this exact run.")
        rows = payload["resources"]
        kinds = [str(row.get("kind") or "") for row in rows if isinstance(row, dict)]
        if len(rows) != len(kinds) or set(kinds) != set(KINDS) or len(kinds) != len(set(kinds)):
            raise HarnessError("Oracle network ledger graph is incomplete or duplicated.")
        return {row["kind"]: dict(row) for row in rows}

    def _load_runtime_scope_for_graph(self, rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
        _path, payload = _read_json_artifact(
            self.config.runtime_scope_path,
            variable="ORACLE_E2E_RUNTIME_SCOPE_FILE",
            exact_keys=RUNTIME_SCOPE_KEYS,
        )
        facts = {
            "compartment_id": str(rows[KIND_COMPARTMENT]["resource_id"]),
            "subnet_id": str(rows[KIND_SUBNET]["resource_id"]),
        }
        return self._validate_runtime_scope(payload, facts=facts)

    def _validate_ui_cleanup_receipt(
        self, runtime_scope: dict[str, Any]
    ) -> dict[str, Any]:
        _path, receipt = _read_json_artifact(
            self.config.ui_cleanup_receipt_path,
            variable="ORACLE_E2E_UI_CLEANUP_RECEIPT",
            exact_keys=CLEANUP_RECEIPT_KEYS,
        )
        receipt_ui_ledger_path = _lexical_path(
            receipt.get("ui_ledger_path"), variable="receipt UI ledger"
        )
        _reject_symlink_components(
            receipt_ui_ledger_path, variable="receipt UI ledger"
        )
        if (
            receipt.get("schema") != CLEANUP_RECEIPT_SCHEMA
            or receipt.get("run_id") != self.config.run_id
            or receipt.get("tenancy_id") != self.config.allowed_tenancy_ocid
            or receipt.get("compartment_id") != runtime_scope["compartment_id"]
            or receipt.get("runtime_scope_digest") != _digest_payload(runtime_scope)
            or receipt_ui_ledger_path != self.config.ui_ledger_path
            or receipt.get("ui_ledger_digest")
            != _file_digest(self.config.ui_ledger_path, variable="Oracle UI ledger")
        ):
            raise HarnessError("Oracle UI cleanup receipt does not match the exact runtime scope.")
        _ledger_path, ui_ledger = _read_json_artifact(
            self.config.ui_ledger_path,
            variable="BACKUPSHEEP_E2E_LEDGER_PATH",
            require_0600=True,
        )
        expected_scope = (
            f"oci:{self.config.profile}:{runtime_scope['compartment_id']}:"
            f"{self.config.availability_domain}"
        )
        if (
            ui_ledger.get("schema") != 1
            or ui_ledger.get("provider") != "oracle_cloud"
            or ui_ledger.get("run_id") != self.config.run_id
            or ui_ledger.get("scope") != expected_scope
            or not isinstance(ui_ledger.get("resources"), list)
        ):
            raise HarnessError("Oracle UI ledger does not match the cleanup receipt scope.")
        expected_terminal = []
        for row in ui_ledger["resources"]:
            if not isinstance(row, dict):
                raise HarnessError("Oracle network cleanup requires valid UI ledger rows.")
            kind = str(row.get("kind") or "")
            state = str(row.get("cleanup_state") or "")
            if kind in UI_USER_RETAINED_KINDS:
                if state not in {"eligible", "failed", "manual_review"}:
                    raise HarnessError(
                        "Oracle network cleanup cannot prove a terminal credential row is user-retained."
                    )
                state = "user_retained"
            elif state not in {"deleted", "absent"}:
                raise HarnessError("Oracle network cleanup requires every UI resource terminal.")
            expected_terminal.append(
                {
                    "kind": kind,
                    "resource_id": str(row.get("resource_id") or ""),
                    "state": state,
                }
            )
        terminal = receipt.get("terminal_resources")
        if not isinstance(terminal, list) or any(
            not isinstance(row, dict) or set(row) != {"kind", "resource_id", "state"}
            for row in terminal
        ):
            raise HarnessError("Oracle UI cleanup receipt terminal list is malformed.")
        sort_key = lambda row: (row["kind"], row["resource_id"])
        if sorted(terminal, key=sort_key) != sorted(expected_terminal, key=sort_key):
            raise HarnessError("Oracle UI cleanup receipt does not match terminal ledger IDs.")
        retained = [row for row in terminal if row["state"] == "user_retained"]
        retained_kinds = {row["kind"] for row in retained}
        if retained and retained_kinds != set(UI_USER_RETAINED_KINDS):
            raise HarnessError(
                "Oracle UI cleanup receipt has an incomplete retained credential graph."
            )
        if len({(row["kind"], row["resource_id"]) for row in terminal}) != len(
            terminal
        ):
            raise HarnessError("Oracle UI cleanup receipt repeats a terminal ID.")
        return receipt

    @staticmethod
    def _retained_receipt_ids(receipt: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (str(row["kind"]), str(row["resource_id"]))
            for row in receipt["terminal_resources"]
            if row["state"] == "user_retained"
        }

    def _dependent_survivors(
        self,
        compartment_id: str,
        *,
        retained_ids: set[tuple[str, str]] | None = None,
    ) -> list[dict[str, str]]:
        """Sweep supported compartment families and fail closed on any unknown child."""

        retained_ids = set(retained_ids or set())
        if any(kind not in UI_USER_RETAINED_KINDS or not resource_id for kind, resource_id in retained_ids):
            raise HarnessError("Oracle retained-resource receipt IDs are unsupported.")
        survivors: set[tuple[str, str]] = set()
        observed_retained: set[tuple[str, str]] = set()
        seen_inventory: set[tuple[str, str]] = set()
        terminal = {"DELETED", "TERMINATED", "DETACHED", "CANCELED", "CANCELLED"}

        def pages(method, **kwargs):
            if not callable(method):
                raise HarnessError("OCI survivor sweep client lacks a required list method.")
            cursor = ""
            seen = set()
            count = 0
            for _ in range(MAX_PAGES):
                if count >= MAX_ITEMS:
                    raise HarnessError("OCI survivor inventory exceeded the safety limit.")
                request = dict(kwargs)
                request["limit"] = min(100, MAX_ITEMS - count)
                if cursor:
                    request["page"] = cursor
                response = self._call(method, **request)
                data = _data(response)
                rows = data if isinstance(data, (list, tuple)) else _value(data, "items")
                if not isinstance(rows, (list, tuple)):
                    raise HarnessError("OCI survivor inventory returned a malformed page.")
                for item in rows:
                    count += 1
                    if count > MAX_ITEMS:
                        raise HarnessError("OCI survivor inventory exceeded the safety limit.")
                    yield item
                cursor = _next_page(response)
                if not cursor:
                    return
                if cursor in seen:
                    raise HarnessError("OCI survivor inventory repeated a cursor.")
                seen.add(cursor)
            raise HarnessError("OCI survivor inventory exceeded the page limit.")

        def remember(kind: str, resource: Any, *, include=True):
            if not include:
                return
            resource_id = str(_value(resource, "id") or "")
            if not resource_id:
                raise HarnessError("OCI survivor inventory omitted a resource ID.")
            identity = (kind, resource_id)
            if identity in seen_inventory:
                raise HarnessError("OCI survivor inventory repeated a resource ID.")
            seen_inventory.add(identity)
            state = str(
                _value(resource, "lifecycle_state")
                or _value(resource, "state")
                or ""
            ).upper()
            if state in terminal:
                return
            if identity in retained_ids:
                observed_retained.add(identity)
                return
            survivors.add(identity)

        def collect(kind: str, client_name: str, method_name: str, **kwargs):
            client = self._clients.get(client_name)
            if client is None:
                raise HarnessError("OCI survivor sweep client family is unavailable.")
            for resource in pages(getattr(client, method_name, None), **kwargs):
                remember(kind, resource)

        common = {"compartment_id": compartment_id}
        for kind, client_name, method_name, kwargs in (
            ("instance", "compute", "list_instances", common),
            ("image", "compute", "list_images", common),
            ("vnic_attachment", "compute", "list_vnic_attachments", common),
            ("volume_attachment", "compute", "list_volume_attachments", common),
            (
                "boot_volume_attachment",
                "compute",
                "list_boot_volume_attachments",
                {**common, "availability_domain": self.config.availability_domain},
            ),
            ("volume", "block", "list_volumes", {**common, "availability_domain": self.config.availability_domain}),
            ("boot_volume", "block", "list_boot_volumes", {**common, "availability_domain": self.config.availability_domain}),
            ("volume_backup", "block", "list_volume_backups", common),
            ("boot_volume_backup", "block", "list_boot_volume_backups", common),
            ("nat_gateway", "network", "list_nat_gateways", common),
            ("service_gateway", "network", "list_service_gateways", common),
            ("local_peering_gateway", "network", "list_local_peering_gateways", common),
            ("network_security_group", "network", "list_network_security_groups", common),
            ("drg", "network", "list_drgs", common),
            ("drg_attachment", "network", "list_drg_attachments", common),
            ("ipsec_connection", "network", "list_ip_sec_connections", common),
            ("virtual_circuit", "network", "list_virtual_circuits", common),
            ("public_ip", "network", "list_public_ips", {**common, "scope": "REGION"}),
            ("database_system", "database", "list_db_systems", common),
            ("autonomous_database", "database", "list_autonomous_databases", common),
            ("mysql_db_system", "mysql", "list_db_systems", common),
            ("postgresql_db_system", "postgresql", "list_db_systems", common),
            ("load_balancer", "load_balancer", "list_load_balancers", common),
            ("network_load_balancer", "network_load_balancer", "list_network_load_balancers", common),
            ("file_system", "file_storage", "list_file_systems", {**common, "availability_domain": self.config.availability_domain}),
            ("mount_target", "file_storage", "list_mount_targets", {**common, "availability_domain": self.config.availability_domain}),
            ("oke_cluster", "container_engine", "list_clusters", common),
            ("oke_node_pool", "container_engine", "list_node_pools", common),
            ("container_instance", "container_instances", "list_container_instances", common),
            ("function_application", "functions", "list_applications", common),
            ("nosql_table", "nosql", "list_tables", common),
        ):
            collect(kind, client_name, method_name, **kwargs)

        identity = self._clients["identity"]
        for resource in pages(identity.list_policies, compartment_id=compartment_id):
            remember("iam_policy", resource)
        for kind, method_name in (("iam_user", "list_users"), ("iam_group", "list_groups")):
            for resource in pages(
                getattr(identity, method_name, None),
                compartment_id=self.config.allowed_tenancy_ocid,
            ):
                resource_id = str(_value(resource, "id") or "")
                remember(
                    kind,
                    resource,
                    include=(
                        _tags(resource).get(TAG_RUN) == self.config.run_id
                        or (kind, resource_id) in retained_ids
                    ),
                )
        retained_users = {
            resource_id for kind, resource_id in retained_ids if kind == "iam_user"
        }
        retained_groups = {
            resource_id for kind, resource_id in retained_ids if kind == "iam_group"
        }
        for resource in pages(
            getattr(identity, "list_user_group_memberships", None),
            compartment_id=self.config.allowed_tenancy_ocid,
        ):
            remember(
                "iam_membership",
                resource,
                include=(
                    str(_value(resource, "user_id") or "") in retained_users
                    or str(_value(resource, "group_id") or "") in retained_groups
                    or (
                        "iam_membership",
                        str(_value(resource, "id") or ""),
                    )
                    in retained_ids
                ),
            )
        list_keys = getattr(identity, "list_customer_secret_keys", None)
        if not callable(list_keys):
            raise HarnessError("OCI survivor sweep cannot inventory customer secret keys.")
        for user_id in retained_users:
            response = self._call(list_keys, user_id=user_id)
            rows = _data(response)
            if not isinstance(rows, (list, tuple)):
                raise HarnessError("OCI customer-secret inventory is malformed.")
            for resource in rows:
                remember("customer_secret_key", resource)

        object_client = self._clients["object"]
        namespace = str(
            _data(
                self._call(
                    object_client.get_namespace,
                    compartment_id=self.config.allowed_tenancy_ocid,
                )
            )
            or ""
        )
        if not namespace:
            raise HarnessError("Oracle Object Storage namespace readback is malformed.")
        for resource in pages(
            getattr(object_client, "list_buckets", None),
            namespace_name=namespace,
            compartment_id=compartment_id,
        ):
            remember("bucket", resource)

        missing_retained = retained_ids - observed_retained
        if missing_retained:
            raise HarnessError("Oracle retained credential inventory no longer matches its receipt.")
        return [
            {"kind": kind, "resource_id": resource_id}
            for kind, resource_id in sorted(survivors)
        ]

    def cleanup_plan(self) -> dict[str, Any]:
        """Read-only cleanup preflight; does not initialize mutable stores."""

        rows = self._read_network_rows_read_only()
        runtime = self._load_runtime_scope_for_graph(rows)
        receipt = self._validate_ui_cleanup_receipt(runtime)
        retained_ids = self._retained_receipt_ids(receipt)
        self._load_clients()
        self._validate_scope()
        self._verify_cleanup_graph(rows)
        survivors = self._dependent_survivors(
            runtime["compartment_id"], retained_ids=retained_ids
        )
        return {
            "phase": "CLEANUP_PLAN",
            "run_id": self.config.run_id,
            "provider_mutations": False,
            "local_writes": False,
            "survivors": survivors,
            "user_retained_resources": [
                {"kind": kind, "resource_id": resource_id}
                for kind, resource_id in sorted(retained_ids)
            ],
            "compartment_delete_allowed": not retained_ids,
            "cleanup_allowed": not survivors,
        }

    def cleanup(self) -> dict[str, Any]:
        self._require_cleanup()
        # Validate both protected ledgers and the receipt before constructing
        # mutable stores. A receipt mismatch must not create an intent file or
        # alter the network ledger.
        rows = self._read_network_rows_read_only()
        runtime = self._load_runtime_scope_for_graph(rows)
        receipt = self._validate_ui_cleanup_receipt(runtime)
        retained_ids = self._retained_receipt_ids(receipt)
        if not retained_ids and all(
            str(row.get("cleanup_state") or "") in {"deleted", "absent"}
            for row in rows.values()
        ):
            return {
                "phase": "ALREADY_CLEANED",
                "run_id": self.config.run_id,
                "provider_mutations": False,
                "results": {
                    kind: "ALREADY_ABSENT" for kind in sorted(rows)
                },
                "user_retained_resources": [],
            }
        self._load_clients()
        self._validate_scope()
        if self.intents.pending():
            raise HarnessError("Cleanup is blocked by unresolved network mutation intents.")
        self._verify_cleanup_graph(rows)
        survivors = self._dependent_survivors(
            runtime["compartment_id"], retained_ids=retained_ids
        )
        if survivors:
            raise HarnessError("Cleanup is blocked by surviving or unledgered child resources.")
        mutable_rows = self._ledger_specs()
        if mutable_rows != rows:
            raise HarnessError("Oracle network ledger changed after cleanup preflight.")
        rows = mutable_rows
        if self.intents.pending():
            raise HarnessError("Cleanup is blocked by unresolved network mutation intents.")
        direct_order = (
            KIND_SUBNET,
            KIND_SECURITY_LIST,
            KIND_ROUTE_TABLE,
            KIND_INTERNET_GATEWAY,
            KIND_VCN,
        )
        results = {
            kind: self._delete_kind(kind, rows[kind]) for kind in direct_order
        }
        results.update(self._reconcile_provider_defaults_after_vcn_absence(rows))
        if retained_ids:
            results[KIND_COMPARTMENT] = "USER_RETAINED_CREDENTIAL_SCOPE"
        else:
            results[KIND_COMPARTMENT] = self._delete_kind(
                KIND_COMPARTMENT,
                rows[KIND_COMPARTMENT],
            )
        if self.intents.pending():
            raise HarnessError("Network mutation intents remained after cleanup.")
        return {
            "phase": (
                "CLEANED_WITH_USER_RETAINED_CREDENTIALS"
                if retained_ids
                else "CLEANED"
            ),
            "run_id": self.config.run_id,
            "results": results,
            "user_retained_resources": [
                {"kind": kind, "resource_id": resource_id}
                for kind, resource_id in sorted(retained_ids)
            ],
        }


def _write_output(
    path_value: str,
    payload: dict[str, Any],
    *,
    protected_paths: Iterable[Path] = (),
) -> None:
    path = _lexical_path(path_value, variable="--output")
    protected = {Path(item) for item in protected_paths}
    if path in protected:
        raise HarnessError("--output must not overwrite a protected/source artifact.")
    _write_private_json(path, payload, variable="--output")


def _environment_protected_paths(
    environment: dict[str, Any], *, network_output: str | None = None
) -> set[Path]:
    paths = set()
    for name in (
        "BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH",
        "BACKUPSHEEP_E2E_LEDGER_PATH",
        "ORACLE_E2E_RUNTIME_SCOPE_FILE",
        "ORACLE_E2E_UI_CLEANUP_RECEIPT",
        "OCI_CLI_CONFIG_FILE",
    ):
        value = str(environment.get(name) or "").strip()
        if value:
            paths.add(Path(os.path.abspath(os.path.expanduser(value))))
    if network_output:
        paths.add(Path(os.path.abspath(os.path.expanduser(network_output))))
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline-safe Oracle test compartment/network harness.")
    parser.add_argument(
        "--phase",
        choices=("plan", "normalize-runtime", "provision", "cleanup-plan", "cleanup"),
        default="plan",
    )
    parser.add_argument("--output", help="Optional non-secret JSON output path outside the repository.")
    parser.add_argument("--network-output", help="Existing non-secret provision output to normalize.")
    return parser


def main(argv=None, *, environment=None, clients=None) -> int:
    args = build_parser().parse_args(argv)
    environment = dict(os.environ if environment is None else environment)
    try:
        # This branch must remain before HarnessConfig.from_environment and
        # OracleTestCompartmentHarness construction.  Empty-environment plan is
        # an explicit acceptance requirement and must not even validate a
        # profile, resolve a ledger path, initialize stores, or construct SDK
        # clients.  An explicit --output is the only intentional file write.
        if args.phase == "plan":
            result = OracleTestCompartmentHarness.inert_plan()
            if args.output:
                _write_output(
                    args.output,
                    result,
                    protected_paths=_environment_protected_paths(
                        environment, network_output=args.network_output
                    ),
                )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        config = HarnessConfig.from_environment(environment)
        protected_outputs = {
            config.config_file,
            config.ledger_path,
            config.ui_ledger_path,
            config.runtime_scope_path,
            config.ui_cleanup_receipt_path,
            *_environment_protected_paths(
                environment, network_output=args.network_output
            ),
        }
        if args.output:
            output_path = _lexical_path(args.output, variable="--output")
            _reject_symlink_components(output_path, variable="--output")
            if output_path in protected_outputs:
                raise HarnessError(
                    "--output must not overwrite a protected/source artifact."
                )
            if output_path.exists():
                raise HarnessError("--output already exists; refusing overwrite.")
        harness = OracleTestCompartmentHarness(config, clients=clients)
        if args.phase == "normalize-runtime":
            if not args.network_output:
                raise HarnessError("--network-output is required for normalize-runtime.")
            result = harness.normalize_runtime_scope(args.network_output)
        elif args.phase == "provision":
            result = harness.provision()
        elif args.phase == "cleanup-plan":
            result = harness.cleanup_plan()
        else:
            result = harness.cleanup()
        if args.output:
            _write_output(
                args.output,
                result,
                protected_paths=protected_outputs,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HarnessError, LedgerError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "error": _safe_error(error)}))
        return 2
    except Exception as error:  # never print SDK/provider exception bodies
        print(json.dumps({"status": "FAILED_SAFE", "error": "Oracle fixture failed safely."}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
