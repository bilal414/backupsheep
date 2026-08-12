"""Crash-safe UpCloud block-storage backup orchestration.

UpCloud's current storage inventory API uses bounded ``limit``/``offset``
pagination.  Backup adoption must exhaust that inventory before a create is
allowed, because UpCloud does not offer an idempotency key for on-demand
storage backups.  The durable BackupSheep UUID is therefore used as the exact
provider title and is persisted before crossing the mutation boundary.
"""

from __future__ import annotations

import hashlib
import ipaddress
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
UPCLOUD_FIREWALL_MAX_RULES = 1000
_UPCLOUD_STORAGE_TYPES = frozenset({"backup", "normal"})
_UPCLOUD_STORAGE_TIERS = frozenset({"hdd", "standard", "maxiops"})
_SAFE_MACHINE_CODE = re.compile(r"^[A-Z0-9_.:-]{1,96}$")
_UPCLOUD_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_UPCLOUD_DEVICE_ADDRESS = re.compile(
    r"^(?:virtio|scsi|ide)(?::[0-9]+){0,2}$", re.IGNORECASE
)
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


def _upcloud_storage_device_labels(device):
    """Return strict provider labels used for boot-device selection.

    UpCloud returns storage-device system labels as a list of ``key``/``value``
    objects.  A malformed label block is not silently treated as a data disk;
    doing so could select the wrong boot volume on a multi-disk server.
    """
    raw = device.get("labels") if isinstance(device, dict) else None
    if raw in (None, "", []):
        return {}
    if isinstance(raw, dict):
        raw = raw.get("label")
    if not isinstance(raw, list):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    labels = {}
    for label in raw:
        if not isinstance(label, dict):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        key = str(label.get("key") or "").strip()
        value = label.get("value")
        if not key or isinstance(value, (dict, list, tuple, set)):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        if key in labels:
            raise _BackupProviderError(
                "PROVIDER_DUPLICATE_MATCH", manual_review=True
            )
        labels[key] = str(value or "")
    return labels


def _upcloud_storage_configuration(integration, storage):
    """Return provider-authoritative normal-storage clone attributes.

    UpCloud backup-storage responses can omit ``tier`` while the original
    normal storage response and the durable node metadata still identify the
    source tier.  The source response wins when present; metadata is accepted
    only as the previously discovered provider record.  Missing or conflicting
    values are never replaced with a provider default.
    """
    if not isinstance(storage, dict):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
    metadata = integration.metadata if isinstance(integration.metadata, dict) else {}

    def normalized(raw, allowed):
        if raw in (None, ""):
            return ""
        value = str(raw).strip().casefold()
        if value not in allowed:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        return value

    provider_tier = normalized(storage.get("tier"), _UPCLOUD_STORAGE_TIERS)
    metadata_tier = normalized(metadata.get("tier"), _UPCLOUD_STORAGE_TIERS)
    provider_encrypted = normalized(storage.get("encrypted"), {"yes", "no"})
    metadata_encrypted = normalized(metadata.get("encrypted"), {"yes", "no"})
    if provider_tier and metadata_tier and provider_tier != metadata_tier:
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    if (
        provider_encrypted
        and metadata_encrypted
        and provider_encrypted != metadata_encrypted
    ):
        raise _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH", manual_review=True)
    tier = provider_tier or metadata_tier
    encrypted = provider_encrypted or metadata_encrypted
    if not tier or not encrypted:
        # A normal volume without these two fields cannot be reconstructed
        # safely because UpCloud may select a different storage tier.
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    return {"tier": tier, "encrypted": encrypted}


def select_upcloud_boot_device(server):
    """Select one provider-authoritative boot disk or fail closed.

    The API can report multiple disks with ``boot_disk=0`` while
    ``boot_order=disk``.  In that documented/live shape the uniquely created
    system disk is identified by the provider-assigned ``virtio:0`` address and
    system/template labels.  We never guess from list order or from a title.
    """
    if not isinstance(server, dict):
        raise _BackupProviderError("PROVIDER_MALFORMED_RESPONSE", manual_review=True)
    devices = _upcloud_nested_list(server, "storage_devices", "storage_device")
    disks = []
    seen_storage = set()
    seen_addresses = set()
    for device in devices:
        if str(device.get("type") or "disk").casefold() != "disk":
            continue
        storage_id = str(device.get("storage") or "").strip()
        address = str(device.get("address") or "").strip().casefold()
        if not storage_id or not _UPCLOUD_UUID.fullmatch(storage_id):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        if not _UPCLOUD_DEVICE_ADDRESS.fullmatch(address):
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        if storage_id in seen_storage or address in seen_addresses:
            raise _BackupProviderError(
                "PROVIDER_DUPLICATE_MATCH", manual_review=True
            )
        seen_storage.add(storage_id)
        seen_addresses.add(address)
        disks.append((device, _upcloud_storage_device_labels(device)))
    if not disks:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )

    explicit = [
        item
        for item in disks
        if str(item[0].get("boot_disk") or "0").casefold()
        in {"1", "yes", "true"}
    ]
    if len(explicit) > 1:
        raise _BackupProviderError("PROVIDER_DUPLICATE_MATCH", manual_review=True)
    boot_order = str(server.get("boot_order") or "").strip().casefold()
    if boot_order != "disk":
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    if len(explicit) == 1:
        return explicit[0][0]
    if len(disks) == 1:
        return disks[0][0]

    system_candidates = []
    for device, labels in disks:
        address = str(device.get("address") or "").strip().casefold()
        template_uuid = str(labels.get("_template_uuid") or "").strip()
        os_type = str(labels.get("_os_type") or "").strip()
        if (
            address == "virtio:0"
            and os_type
            and _UPCLOUD_UUID.fullmatch(template_uuid)
        ):
            system_candidates.append(device)
    if len(system_candidates) != 1:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    return system_candidates[0]


def _upcloud_server_network_contract(server):
    """Return reconstructible non-public networking and public IP families."""
    networking = server.get("networking") if isinstance(server, dict) else None
    interfaces = _upcloud_nested_list(networking or {}, "interfaces", "interface")
    all_interfaces = []
    safe_interfaces = []
    public_families = []
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
        addresses = _upcloud_nested_list(interface, "ip_addresses", "ip_address")
        if not addresses:
            raise _BackupProviderError(
                "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        families = []
        for address in addresses:
            family = str(address.get("family") or "")
            if family not in {"IPv4", "IPv6"}:
                raise _BackupProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                )
            if interface_type in {"utility", "private"} and family != "IPv4":
                # UpCloud documents IPv6 as public-interface-only.
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )
            families.append({"family": family})
            if interface_type == "public":
                public_families.append(family)
        normalized = {
            "type": interface_type,
            "ip_addresses": {"ip_address": families},
        }
        if interface_type == "private":
            network = str(interface.get("network") or "").strip()
            if not _UPCLOUD_UUID.fullmatch(network):
                raise _BackupProviderError(
                    "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
                )
            normalized["network"] = network
        for field in ("source_ip_filtering", "bootable"):
            value = str(interface.get(field) or "").strip().casefold()
            if value:
                if value not in {"yes", "no"}:
                    raise _BackupProviderError(
                        "PROVIDER_MALFORMED_RESPONSE", manual_review=True
                    )
                normalized[field] = value
        all_interfaces.append((index, normalized))
        if interface_type != "public":
            safe_interfaces.append((index, normalized))
    if not safe_interfaces:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    all_interfaces.sort(key=lambda item: item[0])
    safe_interfaces.sort(key=lambda item: item[0])
    return {
        "networking": {
            "interfaces": {
                "interface": [item for _index, item in safe_interfaces]
            }
        },
        "full_networking": {
            "interfaces": {
                "interface": [item for _index, item in all_interfaces]
            }
        },
        "public_ip_families": sorted(
            public_families, key=lambda family: (family != "IPv4", family)
        ),
    }


_UPCLOUD_FIREWALL_RULE_FIELDS = frozenset(
    {
        "action",
        "comment",
        "destination_address_end",
        "destination_address_start",
        "destination_port_end",
        "destination_port_start",
        "direction",
        "family",
        "icmp_type",
        "position",
        "protocol",
        "source_address_end",
        "source_address_start",
        "source_port_end",
        "source_port_start",
    }
)
_UPCLOUD_FIREWALL_OPTIONAL_FIELDS = (
    "comment",
    "destination_address_end",
    "destination_address_start",
    "destination_port_end",
    "destination_port_start",
    "family",
    "icmp_type",
    "protocol",
    "source_address_end",
    "source_address_start",
    "source_port_end",
    "source_port_start",
)


def _upcloud_rule_text(rule, key):
    value = rule.get(key, "")
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return str(value)


def _upcloud_rule_number(rule, key, *, minimum, maximum):
    value = _upcloud_rule_text(rule, key).strip()
    if not re.fullmatch(r"[0-9]+", value):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    number = int(value)
    if not minimum <= number <= maximum:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return number


def _upcloud_rule_ip_range(rule, prefix, family):
    start_key = f"{prefix}_address_start"
    end_key = f"{prefix}_address_end"
    start = _upcloud_rule_text(rule, start_key).strip()
    end = _upcloud_rule_text(rule, end_key).strip()
    if bool(start) != bool(end):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if not start:
        return {}
    try:
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
    except ValueError:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        ) from None
    if start_ip.version != end_ip.version or int(start_ip) > int(end_ip):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if family and start_ip.version != int(family[-1]):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return {
        start_key: str(start_ip),
        end_key: str(end_ip),
    }


def _upcloud_rule_port_range(rule, prefix, protocol):
    start_key = f"{prefix}_port_start"
    end_key = f"{prefix}_port_end"
    start = _upcloud_rule_text(rule, start_key).strip()
    end = _upcloud_rule_text(rule, end_key).strip()
    if bool(start) != bool(end):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if not start:
        return {}
    if protocol not in {"tcp", "udp"}:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    start_port = _upcloud_rule_number(
        rule, start_key, minimum=1, maximum=65535
    )
    end_port = _upcloud_rule_number(rule, end_key, minimum=1, maximum=65535)
    if start_port > end_port:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return {
        start_key: str(start_port),
        end_key: str(end_port),
    }


def _upcloud_normalize_firewall_rule(rule, expected_position):
    if not isinstance(rule, dict) or set(rule) - _UPCLOUD_FIREWALL_RULE_FIELDS:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    position = _upcloud_rule_number(
        rule, "position", minimum=1, maximum=UPCLOUD_FIREWALL_MAX_RULES
    )
    if position != expected_position:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    direction = _upcloud_rule_text(rule, "direction").strip().casefold()
    action = _upcloud_rule_text(rule, "action").strip().casefold()
    if direction not in {"in", "out"} or action not in {"accept", "drop"}:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    family = _upcloud_rule_text(rule, "family").strip()
    if family not in {"", "IPv4", "IPv6"}:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    protocol = _upcloud_rule_text(rule, "protocol").strip().casefold()
    if protocol not in {"", "tcp", "udp", "icmp"}:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    if protocol and not family:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    comment = _upcloud_rule_text(rule, "comment")
    if len(comment) > 250:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    icmp_type = _upcloud_rule_text(rule, "icmp_type").strip()
    if icmp_type:
        if protocol != "icmp":
            raise _BackupProviderError(
                "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
            )
        icmp_type = str(
            _upcloud_rule_number(
                rule, "icmp_type", minimum=0, maximum=255
            )
        )
    elif protocol == "icmp":
        icmp_type = ""
    normalized = {
        "position": position,
        "direction": direction,
        "action": action,
    }
    if comment:
        normalized["comment"] = comment
    if family:
        normalized["family"] = family
    if protocol:
        normalized["protocol"] = protocol
    if icmp_type:
        normalized["icmp_type"] = icmp_type
    normalized.update(_upcloud_rule_ip_range(rule, "source", family))
    normalized.update(_upcloud_rule_ip_range(rule, "destination", family))
    normalized.update(_upcloud_rule_port_range(rule, "source", protocol))
    normalized.update(_upcloud_rule_port_range(rule, "destination", protocol))

    is_default = all(
        not _upcloud_rule_text(rule, field).strip()
        for field in _UPCLOUD_FIREWALL_OPTIONAL_FIELDS
    )
    return normalized, is_default


def normalize_upcloud_firewall_rules(payload):
    """Return a strict, canonical UpCloud firewall chain.

    UpCloud returns positions as strings and may omit empty optional fields in
    write responses.  Canonicalization makes those representations comparable,
    while rejecting unknown fields, gaps, duplicate rules, invalid ranges, and
    an absent final default rule before any restore mutation.
    """
    container = payload.get("firewall_rules") if isinstance(payload, dict) else None
    rules = container.get("firewall_rule") if isinstance(container, dict) else None
    if not isinstance(rules, list) or not rules:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if len(rules) > UPCLOUD_FIREWALL_MAX_RULES:
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    normalized = []
    default_flags = []
    seen = set()
    for position, rule in enumerate(rules, start=1):
        canonical, is_default = _upcloud_normalize_firewall_rule(
            rule, position
        )
        duplicate_key = json.dumps(
            {key: value for key, value in canonical.items() if key != "position"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if duplicate_key in seen:
            raise _BackupProviderError(
                "PROVIDER_DUPLICATE_MATCH", manual_review=True
            )
        seen.add(duplicate_key)
        normalized.append(canonical)
        default_flags.append(is_default)
    if not default_flags[-1] or any(default_flags[:-1]):
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    return normalized


def _upcloud_firewall_fingerprint(rules):
    encoded = json.dumps(
        rules, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_upcloud_firewall_witness(witness, *, enabled=None):
    if not isinstance(witness, dict) or not isinstance(
        witness.get("enabled"), bool
    ):
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if enabled is not None and witness["enabled"] is not bool(enabled):
        raise _BackupProviderError(
            "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
        )
    rules = witness.get("rules")
    normalized = normalize_upcloud_firewall_rules(
        {"firewall_rules": {"firewall_rule": rules}}
    )
    fingerprint = _upcloud_firewall_fingerprint(normalized)
    if str(witness.get("fingerprint") or "") != fingerprint:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    if normalized != rules:
        raise _BackupProviderError(
            "PROVIDER_MALFORMED_RESPONSE", manual_review=True
        )
    return {
        "enabled": witness["enabled"],
        "rules": normalized,
        "fingerprint": fingerprint,
    }


def get_upcloud_server_firewall(server_id, auth, *, enabled=True):
    if not enabled:
        rules = [{"position": 1, "direction": "in", "action": "drop"}]
        return {
            "enabled": False,
            "rules": rules,
            "fingerprint": _upcloud_firewall_fingerprint(rules),
        }
    response = requests.get(
        f"{settings.UPCLOUD_API}/server/{server_id}/firewall_rule",
        auth=auth,
        verify=True,
        timeout=request_timeout(),
        headers={"accept": "application/json"},
    )
    rules = normalize_upcloud_firewall_rules(_upcloud_json(response))
    return {
        "enabled": True,
        "rules": rules,
        "fingerprint": _upcloud_firewall_fingerprint(rules),
    }


def replace_upcloud_server_firewall(server_id, auth, rules):
    normalized = normalize_upcloud_firewall_rules(
        {"firewall_rules": {"firewall_rule": rules}}
    )
    payload_rules = [
        {key: value for key, value in rule.items() if key != "position"}
        for rule in normalized
    ]
    try:
        response = requests.put(
            f"{settings.UPCLOUD_API}/server/{server_id}/firewall_rule",
            auth=auth,
            verify=True,
            timeout=request_timeout(),
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            json={"firewall_rules": {"firewall_rule": payload_rules}},
        )
    except Exception as error:
        raise _backup_provider_exception(error, mutation=True) from None
    problem = classify_upcloud_response(response, mutation=True)
    if problem is not None:
        raise problem
    return normalized


def _upcloud_safe_server_networking(server, *, include_public=True):
    contract = _upcloud_server_network_contract(server)
    return contract["full_networking" if include_public else "networking"]


def _upcloud_server_public_ip_families(server):
    return _upcloud_server_network_contract(server)["public_ip_families"]


def _upcloud_safe_server_config(server, boot_device, firewall_witness=None):
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
    # Firewall rules are a separate server resource. A firewall-enabled source
    # is restorable only when its complete, bounded chain was witnessed before
    # the storage-backup mutation. Never turn on an empty or unverified chain.
    if firewall == "on" and not (
        isinstance(firewall_witness, dict)
        and firewall_witness.get("enabled") is True
    ):
        raise _BackupProviderError(
            "PROVIDER_RECONCILIATION_REQUIRED", manual_review=True
        )
    if firewall == "off" and firewall_witness not in (None, {}):
        if not (
            isinstance(firewall_witness, dict)
            and firewall_witness.get("enabled") is False
        ):
            raise _BackupProviderError(
                "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
            )

    network_contract = _upcloud_server_network_contract(server)
    config = {
        "schema": 1,
        "zone": zone,
        "plan": plan,
        "firewall": firewall,
        "metadata": metadata_enabled,
        # Public interfaces are intentionally omitted from the create request.
        # They are reconstructed only after the exact firewall chain is read
        # back, using the durable family/count witness below.
        "networking": network_contract["networking"],
        "public_ip_families": network_contract["public_ip_families"],
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

    boot_device = select_upcloud_boot_device(server)
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
    storage_configuration = _upcloud_storage_configuration(
        integration, source_storage
    )

    firewall = str(server.get("firewall") or "off").casefold()
    firewall_witness = get_upcloud_server_firewall(
        server_id, auth, enabled=firewall == "on"
    )
    safe_config = _upcloud_safe_server_config(
        server, boot_device, firewall_witness=firewall_witness
    )
    safe_config.update(
        {
            "boot_storage_tier": storage_configuration["tier"],
            "boot_storage_encrypted": storage_configuration["encrypted"],
        }
    )
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
            "firewall_fingerprint": firewall_witness["fingerprint"],
            "tier": storage_configuration["tier"],
            "encrypted": storage_configuration["encrypted"],
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
            "upcloud_firewall": firewall_witness,
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
    storage_configuration = _upcloud_storage_configuration(integration, source)
    witness = _backup_provider_witness(
        backup,
        provider="upcloud",
        source_id=integration.unique_id,
        resource_type="storage",
        scope={
            "zone": source["zone"],
            "tier": storage_configuration["tier"],
            "encrypted": storage_configuration["encrypted"],
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
