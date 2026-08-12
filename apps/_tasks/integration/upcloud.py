"""Crash-safe UpCloud block-storage backup orchestration.

UpCloud's current storage inventory API uses bounded ``limit``/``offset``
pagination.  Backup adoption must exhaust that inventory before a create is
allowed, because UpCloud does not offer an idempotency key for on-demand
storage backups.  The durable BackupSheep UUID is therefore used as the exact
provider title and is persisted before crossing the mutation boundary.
"""

from __future__ import annotations

import hashlib
import json
import re

from celery import current_app
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded
from django.conf import settings
from django.db.models import Q

from apps._tasks.exceptions import (
    ConnectionValidationFailedError,
)
from apps.api.v1.utils.http import request_timeout, requests
from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection
from apps.console.node.models import (
    CoreNode,
    CoreSchedule,
    _BackupProviderError,
    _backup_adopt_provider_resource,
    _backup_execution_metadata,
    _backup_mark_create_started,
    _backup_provider_exception,
    _backup_provider_witness,
    _backup_raise_node_error,
    _backup_record_create_failure,
    _backup_record_provider_witness,
)
from apps.console.utils.models import UtilBackup


UPCLOUD_STORAGE_PAGE_LIMIT = 100
UPCLOUD_STORAGE_MAX_PAGES = 100
UPCLOUD_STORAGE_MAX_ITEMS = 100_000
UPCLOUD_SERVER_PAGE_LIMIT = 100
UPCLOUD_SERVER_MAX_PAGES = 100
UPCLOUD_SERVER_MAX_ITEMS = 10_000
UPCLOUD_ZERO_MATCH_RECONCILIATION_LIMIT = 3
_UPCLOUD_STORAGE_TYPES = frozenset({"backup", "normal"})
_SAFE_MACHINE_CODE = re.compile(r"^[A-Z0-9_.:-]{1,96}$")
_TRANSITIONAL_STORAGE_STATES = frozenset(
    {"backuping", "cloning", "maintenance", "offline", "syncing"}
)


def _upcloud_machine_code(response):
    """Return only a bounded machine code; provider messages stay private."""
    try:
        payload = response.json()
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if not isinstance(error, dict):
        return ""
    value = error.get("error_code") or error.get("code")
    value = str(value or "").strip().upper()
    return value if _SAFE_MACHINE_CODE.fullmatch(value) else ""


def classify_upcloud_response(response, *, mutation=False):
    """Map UpCloud HTTP responses to stable, secret-free execution codes."""
    if response is None or not hasattr(response, "status_code"):
        return _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE",
            unknown_outcome=mutation,
            manual_review=True,
        )
    status = int(getattr(response, "status_code", 0) or 0)
    if 200 <= status < 300:
        return None

    machine_code = _upcloud_machine_code(response)
    if (
        status in {402, 507}
        or (status == 403 and machine_code.endswith("_LIMIT_REACHED"))
        or any(
            token in machine_code
            for token in ("CREDIT", "QUOTA", "RESOURCE_LIMIT", "STORAGE_LIMIT")
        )
    ):
        return _BackupProviderError("QUOTA_EXCEEDED")
    if status in {401, 403} or machine_code in {
        "AUTHENTICATION_FAILED",
        "AUTHORIZATION_FAILED",
        "ACCESS_DENIED",
        "PERMISSION_DENIED",
    }:
        return _BackupProviderError("PROVIDER_AUTH_FAILED")
    if status == 404 or machine_code.endswith("_NOT_FOUND"):
        return _BackupProviderError("PROVIDER_NOT_FOUND")
    if status == 429 or machine_code in {
        "RATE_LIMIT_EXCEEDED",
        "TOO_MANY_REQUESTS",
    }:
        return _BackupProviderError("PROVIDER_RATE_LIMIT", retryable=True)
    if status == 409 or machine_code in {
        "RESOURCE_LOCKED",
        "STORAGE_OPERATION_IN_PROGRESS",
    }:
        # A conflict response is a definitive rejection of this request, but
        # retryable once the provider-side operation holding the lock finishes.
        return _BackupProviderError("PROVIDER_CONFLICT", retryable=True)
    if status in {408, 504}:
        return _BackupProviderError(
            "PROVIDER_TIMEOUT", retryable=True, unknown_outcome=mutation
        )
    if status in {425, 500, 502, 503} or status >= 500 or machine_code in {
        "MAINTENANCE",
        "SERVICE_UNAVAILABLE",
    }:
        return _BackupProviderError(
            "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
        )
    return _BackupProviderError("PROVIDER_REQUEST_FAILED")


def _upcloud_json(response, *, mutation=False):
    problem = classify_upcloud_response(response, mutation=mutation)
    if problem is not None:
        raise problem
    try:
        payload = response.json()
    except Exception:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE",
            unknown_outcome=mutation,
            manual_review=True,
        ) from None
    if not isinstance(payload, dict):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE",
            unknown_outcome=mutation,
            manual_review=True,
        )
    return payload


def _upcloud_total_count(response):
    headers = getattr(response, "headers", None) or {}
    value = next(
        (
            candidate
            for name, candidate in headers.items()
            if str(name).casefold() == "upcloud-total-count"
        ),
        None,
    )
    if value in (None, ""):
        return None
    try:
        total = int(value)
    except (TypeError, ValueError):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        ) from None
    if total < 0 or total > UPCLOUD_STORAGE_MAX_ITEMS:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    return total


def _upcloud_storage_page(response):
    payload = _upcloud_json(response)
    container = payload.get("storages")
    items = container.get("storage") if isinstance(container, dict) else None
    if not isinstance(items, list):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    for item in items:
        if not isinstance(item, dict) or not item.get("uuid"):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
    return items


def list_upcloud_storages(
    auth,
    *,
    storage_type,
    stats=None,
    page_limit=UPCLOUD_STORAGE_PAGE_LIMIT,
    max_pages=UPCLOUD_STORAGE_MAX_PAGES,
    max_items=UPCLOUD_STORAGE_MAX_ITEMS,
):
    """Return one complete, bounded UpCloud storage inventory.

    The official API exposes ``limit`` and ``offset`` rather than a cursor.
    Requests are sorted, duplicate UUIDs/repeated pages fail closed, and a full
    final page is followed by one empty page unless the provider supplies its
    total-count header.
    """
    if storage_type not in _UPCLOUD_STORAGE_TYPES:
        raise ValueError("Unsupported UpCloud storage type.")
    try:
        page_limit = int(page_limit)
        max_pages = int(max_pages)
        max_items = int(max_items)
    except (TypeError, ValueError):
        raise ValueError("UpCloud pagination bounds must be integers.") from None
    if not 1 <= page_limit <= UPCLOUD_STORAGE_PAGE_LIMIT:
        raise ValueError("UpCloud page limit is outside the supported range.")
    if max_pages < 1 or max_items < 1:
        raise ValueError("UpCloud pagination bounds must be positive.")
    max_pages = min(max_pages, UPCLOUD_STORAGE_MAX_PAGES)
    max_items = min(max_items, UPCLOUD_STORAGE_MAX_ITEMS)

    offset = 0
    resources = []
    seen_ids = set()
    seen_pages = set()
    total_count = None
    for page_number in range(1, max_pages + 1):
        response = requests.get(
            f"{settings.UPCLOUD_API}/storage/{storage_type}",
            auth=auth,
            verify=True,
            timeout=request_timeout(),
            headers={"accept": "application/json"},
            params={
                "limit": page_limit,
                "offset": offset,
                "sort_by": "created",
                "order": "asc",
            },
        )
        page = _upcloud_storage_page(response)
        header_total = _upcloud_total_count(response)
        if header_total is not None:
            if total_count is not None and header_total != total_count:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            total_count = header_total

        page_identity = tuple(str(item["uuid"]) for item in page)
        if page_identity and page_identity in seen_pages:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        seen_pages.add(page_identity)
        for item in page:
            resource_id = str(item["uuid"])
            if resource_id in seen_ids:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            if str(item.get("type") or "") != storage_type:
                raise _BackupProviderError(
                    "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
                )
            seen_ids.add(resource_id)
            resources.append(item)
            if len(resources) > max_items:
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )

        if isinstance(stats, dict):
            stats.update(
                {
                    "page_count": page_number,
                    "item_count": len(resources),
                    "last_offset": offset,
                    "scan_complete": False,
                }
            )
        if total_count is not None:
            if len(resources) > total_count:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            if len(resources) == total_count:
                if isinstance(stats, dict):
                    stats["scan_complete"] = True
                return resources
            if not page:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
        elif len(page) < page_limit:
            if isinstance(stats, dict):
                stats["scan_complete"] = True
            return resources

        next_offset = offset + len(page)
        if not page or next_offset <= offset:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        offset = next_offset

    raise _BackupProviderError(
        "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
    )


def _upcloud_server_page(response):
    payload = _upcloud_json(response)
    container = payload.get("servers")
    items = container.get("server") if isinstance(container, dict) else None
    if not isinstance(items, list):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    for item in items:
        if not isinstance(item, dict) or not item.get("uuid"):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
    return items


def list_upcloud_servers(
    auth,
    *,
    stats=None,
    page_limit=UPCLOUD_SERVER_PAGE_LIMIT,
    max_pages=UPCLOUD_SERVER_MAX_PAGES,
    max_items=UPCLOUD_SERVER_MAX_ITEMS,
):
    """Return a complete, stable, bounded UpCloud Cloud Server inventory."""
    try:
        page_limit = int(page_limit)
        max_pages = int(max_pages)
        max_items = int(max_items)
    except (TypeError, ValueError):
        raise ValueError("UpCloud pagination bounds must be integers.") from None
    if not 1 <= page_limit <= UPCLOUD_SERVER_PAGE_LIMIT:
        raise ValueError("UpCloud server page limit is outside the supported range.")
    if max_pages < 1 or max_items < 1:
        raise ValueError("UpCloud pagination bounds must be positive.")
    max_pages = min(max_pages, UPCLOUD_SERVER_MAX_PAGES)
    max_items = min(max_items, UPCLOUD_SERVER_MAX_ITEMS)

    offset = 0
    resources = []
    seen_ids = set()
    seen_pages = set()
    total_count = None
    for page_number in range(1, max_pages + 1):
        response = requests.get(
            f"{settings.UPCLOUD_API}/server",
            auth=auth,
            verify=True,
            timeout=request_timeout(),
            headers={"accept": "application/json"},
            params={
                "limit": page_limit,
                "offset": offset,
                "sort_by": "title",
                "order": "asc",
            },
        )
        page = _upcloud_server_page(response)
        header_total = _upcloud_total_count(response)
        if header_total is not None:
            if header_total > max_items:
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )
            if total_count is not None and total_count != header_total:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            total_count = header_total

        page_identity = tuple(str(item["uuid"]) for item in page)
        if page_identity and page_identity in seen_pages:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        seen_pages.add(page_identity)
        for item in page:
            resource_id = str(item["uuid"])
            if resource_id in seen_ids:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            seen_ids.add(resource_id)
            resources.append(item)
            if len(resources) > max_items:
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )

        if isinstance(stats, dict):
            stats.update(
                {
                    "page_count": page_number,
                    "item_count": len(resources),
                    "last_offset": offset,
                    "scan_complete": False,
                }
            )
        if total_count is not None:
            if len(resources) > total_count or (not page and len(resources) < total_count):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            if len(resources) == total_count:
                if isinstance(stats, dict):
                    stats["scan_complete"] = True
                return resources
        elif len(page) < page_limit:
            if isinstance(stats, dict):
                stats["scan_complete"] = True
            return resources

        next_offset = offset + len(page)
        if not page or next_offset <= offset:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        offset = next_offset

    raise _BackupProviderError(
        "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
    )


def _upcloud_nested_list(payload, container_key, item_key):
    container = payload.get(container_key) if isinstance(payload, dict) else None
    items = container.get(item_key) if isinstance(container, dict) else None
    if not isinstance(items, list):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if any(not isinstance(item, dict) for item in items):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return items


def _upcloud_safe_server_networking(server):
    networking = server.get("networking") if isinstance(server, dict) else None
    interfaces = _upcloud_nested_list(
        networking or {}, "interfaces", "interface"
    )
    safe_interfaces = []
    seen_indexes = set()
    for interface in interfaces:
        interface_type = str(interface.get("type") or "").casefold()
        if interface_type not in {"public", "utility", "private"}:
            raise _BackupProviderError(
                "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
            )
        try:
            index = int(interface.get("index"))
        except (TypeError, ValueError):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            ) from None
        if index < 1 or index in seen_indexes:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        seen_indexes.add(index)
        addresses = _upcloud_nested_list(
            interface, "ip_addresses", "ip_address"
        )
        families = []
        for address in addresses:
            family = str(address.get("family") or "")
            if family not in {"IPv4", "IPv6"}:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            families.append({"family": family})
        if not families:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        safe_interface = {
            "index": index,
            "type": interface_type,
            "ip_addresses": {"ip_address": families},
        }
        if interface_type == "private":
            network = str(interface.get("network") or "")
            if not network:
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )
            safe_interface["network"] = network[:255]
        safe_interfaces.append(safe_interface)
    if not safe_interfaces:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    safe_interfaces.sort(key=lambda item: item["index"])
    for item in safe_interfaces:
        item.pop("index", None)
    return {"interfaces": {"interface": safe_interfaces}}


def _upcloud_safe_server_config(server, boot_device):
    if not isinstance(server, dict) or not isinstance(boot_device, dict):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if server.get("server_group") not in (None, ""):
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    devices = server.get("devices")
    if isinstance(devices, dict) and devices.get("device"):
        # GPU/passthrough device recreation is outside the safe restore contract.
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )

    zone = str(server.get("zone") or "")
    plan = str(server.get("plan") or "")
    firewall = str(server.get("firewall") or "off").casefold()
    metadata_enabled = str(server.get("metadata") or "no").casefold()
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", zone)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", plan)
        or firewall not in {"on", "off"}
        or metadata_enabled not in {"yes", "no"}
    ):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    # Firewall rules are a separate server resource. Enabling an empty firewall
    # would silently change reachability, so stop instead of creating a server
    # whose network security does not match the source.
    if firewall == "on":
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )

    config = {
        "schema": 1,
        "zone": zone,
        "plan": plan,
        "firewall": firewall,
        "metadata": metadata_enabled,
        "networking": _upcloud_safe_server_networking(server),
        "source_hostname": str(server.get("hostname") or "")[:255],
        "source_title": str(server.get("title") or "")[:255],
        "boot_address": str(boot_device.get("address") or "virtio")[:64],
    }
    if plan == "custom":
        for field in ("core_number", "memory_amount"):
            try:
                value = int(server.get(field))
            except (TypeError, ValueError):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                ) from None
            if value < 1:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            config[field] = value
    for field in ("timezone", "video_model", "nic_model"):
        value = str(server.get(field) or "").strip()
        if value:
            if len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_./+-]+", value):
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            config[field] = value
    return config


def _upcloud_server_source_witness(integration, backup, auth):
    response = requests.get(
        f"{settings.UPCLOUD_API}/server/{integration.unique_id}",
        auth=auth,
        verify=True,
        timeout=request_timeout(),
        headers={"accept": "application/json"},
    )
    payload = _upcloud_json(response)
    server = payload.get("server")
    if not isinstance(server, dict):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    server_id = str(server.get("uuid") or "")
    zone = str(server.get("zone") or "")
    state = str(server.get("state") or "").casefold()
    if server_id != str(integration.unique_id) or not zone:
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )
    if state == "maintenance":
        raise _BackupProviderError("PROVIDER_CONFLICT", retryable=True)
    if state == "error":
        raise _BackupProviderError("PROVIDER_TRANSIENT_OUTAGE", retryable=True)
    if state not in {"started", "stopped"}:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )

    storage_devices = _upcloud_nested_list(
        server, "storage_devices", "storage_device"
    )
    disks = [
        device
        for device in storage_devices
        if str(device.get("type") or "disk").casefold() == "disk"
        and device.get("storage")
    ]
    explicit_boot = [
        device
        for device in disks
        if str(device.get("boot_disk") or "0").casefold() in {"1", "yes", "true"}
    ]
    if len(explicit_boot) == 1:
        boot_device = explicit_boot[0]
    elif not explicit_boot and len(disks) == 1:
        boot_device = disks[0]
    else:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    boot_storage_id = str(boot_device.get("storage") or "")

    storage_response = requests.get(
        f"{settings.UPCLOUD_API}/storage/{boot_storage_id}",
        auth=auth,
        verify=True,
        timeout=request_timeout(),
        headers={"accept": "application/json"},
    )
    storage_payload = _upcloud_json(storage_response)
    source_storage = storage_payload.get("storage")
    if not isinstance(source_storage, dict):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    attached_container = source_storage.get("servers")
    attached_servers = (
        attached_container.get("server")
        if isinstance(attached_container, dict)
        else None
    )
    if not isinstance(attached_servers, list):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    attached_ids = {
        str(item.get("uuid") or item.get("id") or item.get("server") or "")
        if isinstance(item, dict)
        else str(item)
        for item in attached_servers
    }
    if (
        str(source_storage.get("uuid") or "") != boot_storage_id
        or str(source_storage.get("type") or "") != "normal"
        or str(source_storage.get("zone") or "") != zone
        or str(source_storage.get("state") or "").casefold() != "online"
        or server_id not in attached_ids
    ):
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )

    safe_config = _upcloud_safe_server_config(server, boot_device)
    encoded = json.dumps(
        safe_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    config_fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    witness = _backup_provider_witness(
        backup,
        provider="upcloud",
        source_id=boot_storage_id,
        resource_type="server_boot_storage",
        scope={
            "zone": zone,
            "server_id": server_id,
            "server_config_fingerprint": config_fingerprint,
            "account_id": integration.node.connection.account_id,
            "connection_id": integration.node.connection_id,
        },
        source=source_storage,
    )
    witness.update(
        {
            "upcloud_server_config": safe_config,
            "upcloud_server_config_fingerprint": config_fingerprint,
            "upcloud_server_id": server_id,
            "upcloud_source_storage_id": boot_storage_id,
            "upcloud_source_storage_tier": str(source_storage.get("tier") or "")[:32],
            "upcloud_source_storage_encrypted": str(source_storage.get("encrypted") or "")[:8],
        }
    )
    return witness


def _owned_upcloud_candidate(
    resources,
    *,
    marker,
    source_id,
    zone,
    storage_type,
):
    marker_matches = [
        item for item in resources if str(item.get("title") or "") == str(marker)
    ]
    if len(marker_matches) > 1:
        raise _BackupProviderError(
            "PROVIDER_DUPLICATE_MATCH", manual_review=True
        )
    if not marker_matches:
        return None
    item = marker_matches[0]
    identity_matches = all(
        (
            str(item.get("origin") or "") == str(source_id),
            str(item.get("zone") or "") == str(zone),
            str(item.get("type") or "") == str(storage_type),
            str(item.get("uuid") or "") != str(source_id),
        )
    )
    if not identity_matches:
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )
    return item


def _upcloud_source_witness(integration, backup, auth):
    response = requests.get(
        f"{settings.UPCLOUD_API}/storage/{integration.unique_id}",
        auth=auth,
        verify=True,
        timeout=request_timeout(),
        headers={"accept": "application/json"},
    )
    payload = _upcloud_json(response)
    source = payload.get("storage")
    if not isinstance(source, dict):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if (
        str(source.get("uuid") or "") != str(integration.unique_id)
        or str(source.get("type") or "") != "normal"
        or not source.get("zone")
    ):
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )
    state = str(source.get("state") or "").casefold()
    if state != "online":
        if state in _TRANSITIONAL_STORAGE_STATES:
            raise _BackupProviderError("PROVIDER_CONFLICT", retryable=True)
        if state == "error":
            raise _BackupProviderError("PROVIDER_FAILED")
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    witness = _backup_provider_witness(
        backup,
        provider="upcloud",
        source_id=integration.unique_id,
        resource_type="storage",
        scope={
            "zone": source["zone"],
            "account_id": integration.node.connection.account_id,
            "connection_id": integration.node.connection_id,
        },
        source=source,
    )
    return witness


def _record_definitive_create_rejection(backup, witness, error):
    """Clear the mutation-unknown bit after a definitive non-2xx response."""
    if getattr(error, "unknown_outcome", False):
        return
    _backup_record_provider_witness(
        backup,
        witness,
        provider_status=error.code,
        metadata={
            "create_attempted": False,
            "outcome_unknown": False,
            "last_error_code": error.code,
        },
    )


def create_upcloud_snapshot(backup):
    """Create or exactly adopt one UpCloud backup storage resource."""
    integration = backup.upcloud
    node = integration.node
    if node.type not in {CoreNode.Type.VOLUME, CoreNode.Type.CLOUD}:
        classified = _BackupProviderError("PROVIDER_FAILED")
        witness = _backup_provider_witness(
            backup,
            provider="upcloud",
            source_id=integration.unique_id,
            resource_type="unsupported",
            scope={},
        )
        _backup_record_create_failure(backup, witness, classified)
        _backup_raise_node_error(node, backup, classified)

    witness = None
    try:
        try:
            auth = node.connection.auth_upcloud.get_verified_client()
        except Exception:
            raise _BackupProviderError("PROVIDER_AUTH_FAILED") from None
        witness = (
            _upcloud_server_source_witness(integration, backup, auth)
            if node.type == CoreNode.Type.CLOUD
            else _upcloud_source_witness(integration, backup, auth)
        )
        _backup_record_provider_witness(
            backup, witness, provider_status="reconciling"
        )
        scan = {}
        try:
            resources = list_upcloud_storages(
                auth, storage_type="backup", stats=scan
            )
        except Exception:
            _backup_record_provider_witness(
                backup,
                witness,
                provider_status="reconciliation_failed",
                metadata={
                    "scan_page_count": scan.get("page_count", 0),
                    "scan_item_count": scan.get("item_count", 0),
                    "scan_last_offset": scan.get("last_offset", 0),
                    "scan_complete": False,
                },
            )
            raise
        candidate = _owned_upcloud_candidate(
            resources,
            marker=witness["marker"],
            source_id=witness["source_id"],
            zone=witness["scope"]["zone"],
            storage_type="backup",
        )
        _backup_record_provider_witness(
            backup,
            witness,
            provider_status="reconciled",
            metadata={
                "scan_page_count": scan.get("page_count", 0),
                "scan_item_count": scan.get("item_count", len(resources)),
                "scan_match_count": 1 if candidate else 0,
                "scan_complete": bool(scan.get("scan_complete")),
            },
        )
        if candidate is not None:
            _backup_adopt_provider_resource(
                backup,
                candidate,
                witness=witness,
                provider="upcloud",
                id_keys=("uuid",),
            )
            return backup.unique_id

        _state, provider_metadata = _backup_execution_metadata(backup)
        if provider_metadata.get("create_attempted") or provider_metadata.get(
            "outcome_unknown"
        ):
            try:
                zero_match_count = int(
                    provider_metadata.get("zero_match_reconciliation_count", 0)
                ) + 1
            except (TypeError, ValueError):
                zero_match_count = UPCLOUD_ZERO_MATCH_RECONCILIATION_LIMIT
            _backup_record_provider_witness(
                backup,
                witness,
                provider_status="reconciling",
                metadata={
                    "create_attempted": True,
                    "outcome_unknown": True,
                    "zero_match_reconciliation_count": zero_match_count,
                    "scan_page_count": scan.get("page_count", 0),
                    "scan_item_count": scan.get("item_count", len(resources)),
                    "scan_match_count": 0,
                    "scan_complete": bool(scan.get("scan_complete")),
                },
            )
            if zero_match_count < UPCLOUD_ZERO_MATCH_RECONCILIATION_LIMIT:
                raise _BackupProviderError(
                    "PROVIDER_CREATE_OUTCOME_UNKNOWN",
                    retryable=True,
                    unknown_outcome=True,
                )
            raise _BackupProviderError(
                "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
            )

        _backup_mark_create_started(backup, witness)
        try:
            response = requests.post(
                f"{settings.UPCLOUD_API}/storage/{witness['source_id']}/backup",
                json={"storage": {"title": witness["marker"]}},
                auth=auth,
                verify=True,
                timeout=request_timeout(),
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                },
            )
        except Exception as error:
            raise _backup_provider_exception(error, mutation=True) from None
        problem = classify_upcloud_response(response, mutation=True)
        if problem is not None:
            _record_definitive_create_rejection(backup, witness, problem)
            raise problem
        payload = _upcloud_json(response, mutation=True)
        storage = payload.get("storage")
        if not isinstance(storage, dict):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE",
                unknown_outcome=True,
                manual_review=True,
            )
        try:
            created = _owned_upcloud_candidate(
                [storage],
                marker=witness["marker"],
                source_id=witness["source_id"],
                zone=witness["scope"]["zone"],
                storage_type="backup",
            )
        except _BackupProviderError as error:
            raise _BackupProviderError(
                error.code, unknown_outcome=True, manual_review=True
            ) from None
        if created is None:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE",
                unknown_outcome=True,
                manual_review=True,
            )
        _backup_adopt_provider_resource(
            backup,
            created,
            witness=witness,
            provider="upcloud",
            id_keys=("uuid",),
        )
        return backup.unique_id
    except Exception as error:
        _state, provider_metadata = _backup_execution_metadata(backup)
        classified = _backup_provider_exception(
            error,
            mutation=bool(
                getattr(error, "unknown_outcome", False)
                or provider_metadata.get("outcome_unknown")
            ),
        )
        if witness is None:
            witness = _backup_provider_witness(
                backup,
                provider="upcloud",
                source_id=integration.unique_id,
                resource_type=(
                    "server_boot_storage"
                    if node.type == CoreNode.Type.CLOUD
                    else "storage"
                ),
                scope={
                    "server_id": integration.unique_id
                } if node.type == CoreNode.Type.CLOUD else {},
            )
        _backup_record_create_failure(
            backup, witness, classified, scan_metadata={"phase": "create"}
        )
        _backup_raise_node_error(node, backup, classified)


@current_app.task(
    name="backup_upcloud",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    soft_time_limit=(24 * 3600),
)
def backup_upcloud(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
    resume=False,
):
    attempt_no = self.request.retries + 1

    schedule_check = None
    if schedule_id:
        backup_type = UtilBackup.Type.SCHEDULED
        if resume or CoreSchedule.objects.filter(
            id=schedule_id, status=CoreSchedule.Status.ACTIVE
        ).exists():
            schedule_check = True
    else:
        backup_type = UtilBackup.Type.ON_DEMAND
        schedule_check = True

    query = Q(id=node_id)
    query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
    query &= ~Q(status=CoreNode.Status.PAUSED)
    query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
    query &= ~Q(connection__status=CoreConnection.Status.PAUSED)
    query &= ~Q(connection__account__status=CoreAccount.Status.DELETE_REQUESTED)

    if CoreNode.objects.filter(query).exists() and schedule_check:
        node = CoreNode.objects.get(id=node_id)
        try:
            # Validation is advisory: the exact source/readiness witness below is
            # authoritative and is persisted before a provider mutation.
            try:
                node.connection.validate()
                node.validate()
            except Exception:
                pass

            backup = node.backup_initiate(
                self.request.id,
                backup_type,
                attempt_no,
                schedule_id,
                storage_ids,
                notes,
            )
            if backup is None:
                return

            if not backup.unique_id:
                from apps._tasks.helper.tasks import run_provider_create

                if (
                    run_provider_create(
                        backup,
                        self.request.id,
                        create_upcloud_snapshot,
                    )
                    is None
                ):
                    return

            from apps._tasks.helper.tasks import poll_cloud_backup

            poll_cloud_backup.apply_async(args=[node.id, backup.id], countdown=60)
        except ConnectionValidationFailedError as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_retrying_reset(self.request.id)
            raise self.retry()
        except SoftTimeLimitExceeded as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_timeout_reset(self.request.id)
        except Exception as error:
            try:
                node.notify_backup_fail(error, backup_type)
                node.backup_retrying_reset(self.request.id)
                raise self.retry()
            except MaxRetriesExceededError:
                node.backup_max_retries_reached(self.request.id)
