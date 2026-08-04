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
      python scripts/vultr_live_e2e.py --report /code/docs/vultr-live-e2e-test-report.md

The token is read only from the environment and is never written to the report
or printed.  This test has real provider cost and may take 20-45 minutes,
mostly because managed database provisioning and deletion are asynchronous.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any, Callable

import boto3
import django
import requests
from botocore.client import Config
from botocore.exceptions import ClientError


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")


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

from apps.api.v1.utils.api_helpers import bs_encrypt  # noqa: E402
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
from apps.console.vultr_monitoring import list_instance_backups  # noqa: E402


class HarnessError(RuntimeError):
    """A fail-closed harness error."""


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
        self.token = os.environ.get("VULTR_API_KEY", "").strip()
        if not self.token:
            raise HarnessError("VULTR_API_KEY is required; it is never read from a repository file.")
        if os.environ.get("VULTR_E2E_ALLOW_MUTATION") != "YES":
            raise HarnessError(
                "Refusing provider mutations. Set VULTR_E2E_ALLOW_MUTATION=YES for this disposable run."
            )

        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
        self.prefix = f"bs-vultr-e2e-{stamp}-{secrets.token_hex(3)}"
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
            "object_keys": [],
        }
        self.local_ids: dict[str, Any] = {}
        # Provider fork targets use their durable restore marker as the label,
        # which is intentionally different from the run prefix. Keep the
        # exact label alongside every created database ID for ownership-safe
        # cleanup and final inventory verification.
        self.database_labels: dict[str, str] = {}
        self.block_labels: dict[str, str] = {}
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

    # ---------- provider client ----------

    def _safe_error(self, value: Any) -> str:
        text = str(value)
        return text.replace(self.token, "<redacted>")[:400]

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
                )
                break
            except requests.RequestException as error:
                if attempt + 1 >= attempts:
                    raise HarnessError(
                        f"Vultr {method} {path} request failed: {self._safe_error(error)}"
                    ) from error
                time.sleep(3 * (attempt + 1))
            if (
                method.upper() == "GET"
                and response.status_code in {429, 500, 502, 503, 504}
                and attempt + 1 < attempts
            ):
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = max(1, min(30, int(retry_after))) if retry_after else 3 * (attempt + 1)
                except ValueError:
                    delay = 3 * (attempt + 1)
                response.close()
                response = None
                time.sleep(delay)
                continue
            break
        if response is None:
            raise HarnessError(f"Vultr {method} {path} returned no response")
        try:
            if response.status_code not in expected:
                try:
                    detail = response.json()
                except ValueError:
                    detail = response.text[:300]
                raise HarnessError(
                    f"Vultr {method} {path} returned HTTP {response.status_code}: {detail}"
                )
            if response.status_code == 204 or not response.content:
                return None
            try:
                payload = response.json()
            except ValueError as error:
                raise HarnessError(f"Vultr {method} {path} returned malformed JSON") from error
            if not isinstance(payload, dict):
                raise HarnessError(f"Vultr {method} {path} returned a non-object response")
            return payload
        finally:
            response.close()

    def collection(
        self,
        path: str,
        item_key: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        base = dict(params or {})
        base.setdefault("per_page", 500)
        cursor = None
        seen: set[str] = set()
        while True:
            query = dict(base)
            if cursor:
                query["cursor"] = cursor
            payload = self.request("GET", path, params=query) or {}
            page = payload.get(item_key)
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise HarnessError(f"Malformed Vultr {path} inventory")
            items.extend(page)
            links = (payload.get("meta") or {}).get("links") or {}
            if not isinstance(links, dict):
                raise HarnessError(f"Malformed Vultr {path} pagination links")
            next_cursor = links.get("next")
            if next_cursor in (None, ""):
                return items
            if not isinstance(next_cursor, str) or not next_cursor.strip() or next_cursor in seen:
                raise HarnessError(f"Repeated or malformed Vultr {path} cursor")
            seen.add(next_cursor)
            cursor = next_cursor

    def wait_for(
        self,
        label: str,
        read: Callable[[], Any],
        done: Callable[[Any], bool],
        *,
        timeout_seconds: int = 1800,
        interval_seconds: int = 10,
    ) -> Any:
        deadline = time.monotonic() + timeout_seconds
        last = None
        while time.monotonic() < deadline:
            last = read()
            if done(last):
                return last
            time.sleep(interval_seconds)
        raise HarnessError(f"Timed out waiting for {label}; last state={last!r}")

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
        collisions = {
            key: [item.get("id") for item in values if self._has_marker(item)]
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

    def ledger(self, resource_class: str, service: str, provider_id: str, **fields: Any) -> None:
        self.report["ledger"].append(
            {
                "resource_class": resource_class,
                "provider_service": service,
                "provider_id": provider_id,
                **fields,
                "created_by_run": True,
            }
        )

    def record_test(self, test_id: str, status: str, **evidence: Any) -> None:
        self.report["tests"][test_id] = {"status": status, **evidence}

    # ---------- local BackupSheep graph ----------

    def setup_local(self) -> None:
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
        instance_payload = self.request(
            "POST",
            "/instances",
            expected=(201, 202),
            body={
                "region": self.region,
                "plan": self.server_plan,
                "os_id": self.os_id,
                "label": f"{self.prefix}-source-instance",
                "hostname": f"{self.prefix}-source",
                "tags": [self.prefix],
                "backups": "disabled",
            },
        ) or {}
        instance = instance_payload.get("instance") or {}
        instance_id = str(instance.get("id") or "")
        if not instance_id:
            raise HarnessError("Vultr instance create response omitted id")
        self.created["instances"].append(instance_id)
        self.ledger(
            "source",
            "Vultr Compute",
            instance_id,
            label=instance.get("label"),
            region=instance.get("region"),
            plan=instance.get("plan"),
            ownership_proof={"id": instance_id, "tags": [self.prefix]},
            cleanup_allowed=False,
        )
        source_instance = self.wait_for(
            "source instance active",
            lambda: (self.request("GET", f"/instances/{instance_id}") or {}).get("instance") or {},
            lambda item: (
                str(item.get("status", "")).lower() == "active"
                and str(item.get("power_status", "")).lower() in {"running", "on"}
                and str(item.get("server_status", "")).lower() in {"ok", "running", "active"}
                and str(item.get("main_ip", "")).strip() not in {"", "0.0.0.0"}
            ),
            timeout_seconds=900,
        )
        self.source_instance = source_instance
        # Vultr can report an instance as active while the snapshot lock is
        # still settling.  Requiring the provider's running/readiness fields
        # above and allowing a short stabilization window avoids treating a
        # transient provider 400 as a completed snapshot operation.
        time.sleep(20)

        block_payload = self.request(
            "POST",
            "/blocks",
            expected=(201, 202),
            body={
                "region": self.region,
                "size_gb": self.block_size_gb,
                "label": f"{self.prefix}-source-block",
            },
        ) or {}
        block = block_payload.get("block") or {}
        block_id = str(block.get("id") or "")
        if not block_id:
            raise HarnessError("Vultr block create response omitted id")
        self.created["blocks"].append(block_id)
        self.ledger(
            "source",
            "Vultr Block Storage",
            block_id,
            label=block.get("label"),
            region=block.get("region"),
            size_gb=block.get("size_gb"),
            ownership_proof={"id": block_id, "label": f"{self.prefix}-source-block"},
            cleanup_allowed=False,
        )
        self.source_block = self.wait_for(
            "source block active",
            lambda: (self.request("GET", f"/blocks/{block_id}") or {}).get("block") or {},
            lambda item: str(item.get("status", "")).lower() == "active",
            timeout_seconds=900,
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
            cloud.create_snapshot(cloud_backup)
        finally:
            node_models.requests.post = original_post
        cloud_backup.refresh_from_db()
        if not cloud_backup.unique_id:
            raise HarnessError("Instance snapshot did not persist provider ID")
        self.created["snapshots"].append(str(cloud_backup.unique_id))
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
        cloud.create_snapshot(cloud_backup)  # durable duplicate-delivery replay
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
        cloud.restore_snapshot(cloud_backup, cloud_restore)
        cloud_restore.refresh_from_db()
        if not cloud_restore.resource_id:
            raise HarnessError("Instance restore did not persist target ID")
        restore_instance_id = str(cloud_restore.resource_id)
        self.created["instances"].append(restore_instance_id)
        self.wait_for(
            "restored instance active",
            lambda: cloud_restore.poll_status(),
            lambda state: state == CoreCloudRestore.Status.COMPLETE,
            timeout_seconds=1200,
            interval_seconds=15,
        )
        cloud.restore_snapshot(cloud_backup, cloud_restore)  # replay must not create a second target
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
        block.create_snapshot(block_backup)
        block_backup.refresh_from_db()
        if not block_backup.unique_id:
            raise HarnessError("Block snapshot did not persist provider ID")
        self.created["block_snapshots"].append(str(block_backup.unique_id))
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
        block.restore_snapshot(block_backup, block_restore)
        block_restore.refresh_from_db()
        if not block_restore.resource_id:
            raise HarnessError("Block restore did not persist target ID")
        restore_block_id = str(block_restore.resource_id)
        self.created["blocks"].append(restore_block_id)
        self.block_labels[restore_block_id] = str(block_restore.restore_marker or "")
        self.ledger(
            "restore-target",
            "Vultr Block Storage",
            restore_block_id,
            label=block_restore.restore_marker,
            region=self.region,
            size_gb=self.block_size_gb,
            ownership_proof={"id": restore_block_id, "label": block_restore.restore_marker},
            cleanup_allowed=True,
        )
        self.wait_for(
            "restored block active",
            lambda: block_restore.poll_status(),
            lambda state: state == CoreCloudRestore.Status.COMPLETE,
            timeout_seconds=900,
            interval_seconds=15,
        )
        block.restore_snapshot(block_backup, block_restore)
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

    def create_object_storage_and_test(self) -> None:
        label = f"{self.prefix}-object-storage"
        payload = self.request(
            "POST",
            "/object-storage",
            expected=(201, 202),
            body={"cluster_id": self.object_cluster_id, "tier_id": self.object_tier_id, "label": label},
        ) or {}
        object_storage = payload.get("object_storage") or {}
        storage_id = str(object_storage.get("id") or "")
        if not storage_id:
            raise HarnessError("Object Storage create response omitted id")
        self.created["object_storages"].append(storage_id)
        self.ledger(
            "source",
            "Vultr Object Storage",
            storage_id,
            label=label,
            region=object_storage.get("region"),
            endpoint=object_storage.get("s3_hostname"),
            ownership_proof={"id": storage_id, "label": label},
            cleanup_allowed=True,
        )
        object_storage = self.wait_for(
            "object storage active",
            lambda: (
                self.request("GET", f"/object-storage/{storage_id}", expected=(200, 202)) or {}
            ).get("object_storage") or {},
            lambda item: str(item.get("status", "")).lower() in {"active", "running"},
            timeout_seconds=900,
            interval_seconds=15,
        )
        # Credentials are returned on create and/or get. Keep them in memory only.
        access_key = object_storage.get("s3_access_key") or payload.get("object_storage", {}).get("s3_access_key")
        secret_key = object_storage.get("s3_secret_key") or payload.get("object_storage", {}).get("s3_secret_key")
        endpoint = object_storage.get("s3_hostname") or payload.get("object_storage", {}).get("s3_hostname")
        if not access_key or not secret_key or not endpoint:
            raise HarnessError("Object Storage response omitted S3 credentials or hostname")
        self.object_credentials = {"access_key": access_key, "secret_key": secret_key, "endpoint": endpoint}
        bucket = f"{self.prefix}-bucket"[:63]
        key = f"{self.prefix}/fixture.zip"
        content = b"BackupSheep Vultr live E2E object fixture\n"
        client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, connect_timeout=10, read_timeout=60),
        )
        client.create_bucket(Bucket=bucket)
        self.created["object_buckets"].append(bucket)

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
        try:
            storage_vultr(point)
            point.refresh_from_db()
            metadata = (point.metadata or {}).get(VULTR_OBJECT_METADATA_KEY) or {}
            expected_hash = hashlib.sha256(content).hexdigest()
            head = client.head_object(Bucket=bucket, Key=point.storage_file_id)
            body = client.get_object(Bucket=bucket, Key=point.storage_file_id)["Body"].read()
            first_identity = (metadata.get("etag"), metadata.get("version_id"), point.storage_file_id)
            # Keep the local archive present for the replay. A worker retry has
            # the source archive available; deleting it before this call would
            # test the file-not-found path instead of crash-safe object adoption.
            storage_vultr(point)  # retry/replay adopts the same verified object
            point.refresh_from_db()
            second_metadata = (point.metadata or {}).get(VULTR_OBJECT_METADATA_KEY) or {}
            second_identity = (second_metadata.get("etag"), second_metadata.get("version_id"), point.storage_file_id)
            self.created["object_keys"].append(point.storage_file_id)
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
        self.object_client = client

    # ---------- managed database ----------

    def create_managed_database_and_test(self) -> None:
        label = f"{self.prefix}-database"
        payload = self.request(
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
        ) or {}
        database = payload.get("database") or {}
        database_id = str(database.get("id") or "")
        if not database_id:
            raise HarnessError("Managed database create response omitted id")
        self.created["databases"].append(database_id)
        self.database_labels[database_id] = label
        self.ledger(
            "source",
            "Vultr Managed Database",
            database_id,
            label=label,
            region=self.region,
            plan=self.database_plan,
            ownership_proof={"id": database_id, "label": label},
            cleanup_allowed=False,
        )
        self.wait_for(
            "managed database running",
            lambda: (self.request("GET", f"/databases/{database_id}") or {}).get("database") or {},
            lambda item: str(item.get("status", "")).lower() in {"running", "active", "available"},
            timeout_seconds=1800,
            interval_seconds=20,
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
        managed.restore_snapshot(db_backup, db_restore)
        db_restore.refresh_from_db()
        if not db_restore.resource_id:
            raise HarnessError("Managed database fork did not persist target ID")
        restore_id = str(db_restore.resource_id)
        self.created["databases"].append(restore_id)
        self.database_labels[restore_id] = str(db_restore.provider_marker or "")
        self.ledger(
            "restore-target",
            "Vultr Managed Database",
            restore_id,
            label=db_restore.provider_marker,
            region=self.region,
            plan=self.database_plan,
            ownership_proof={"id": restore_id, "label": db_restore.provider_marker},
            cleanup_allowed=True,
        )

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
        managed.restore_snapshot(db_backup, db_restore)
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

    def _get(self, path: str, key: str) -> dict[str, Any] | None:
        try:
            payload = self.request("GET", path, expected=(200, 202)) or {}
            if key == "snapshot" and key not in payload and payload.get("id"):
                # Block-snapshot detail responses are the snapshot object
                # itself; instance-snapshot responses use {"snapshot": ...}.
                return payload
            return payload.get(key)
        except HarnessError as error:
            if "HTTP 404" in str(error):
                return None
            raise

    def _delete_owned(self, kind: str, resource_id: str, path: str, predicate: Callable[[dict[str, Any]], bool]) -> None:
        deadline = time.monotonic() + 1800
        while True:
            resource = self._get(path, kind)
            if resource is None:
                return
            if not predicate(resource):
                raise HarnessError(f"Refusing cleanup of {kind} {resource_id}: ownership proof failed")
            try:
                self.request("DELETE", path, expected=(204,))
                return
            except HarnessError as error:
                # Newly-created Vultr resources can remain locked for a short
                # period after reaching active. Retry only this exact, already
                # ownership-verified ID; all other delete errors fail closed.
                error_text = str(error)
                retryable = any(
                    f"HTTP {status_code}" in error_text
                    for status_code in (409, 429, 500, 502, 503, 504)
                )
                # Vultr can keep a just-deleted block snapshot dependency
                # visible to the block-delete endpoint after the snapshot list
                # has already gone empty.  The exact resource was ownership
                # verified immediately above, so retry this known eventual-
                # consistency response instead of leaving our source block.
                if (
                    "HTTP 400" in error_text
                    and "snapshots associated with this block subscription" in error_text.lower()
                ):
                    retryable = True
                if not retryable or time.monotonic() >= deadline:
                    raise
                time.sleep(15)

    def cleanup(self) -> None:
        errors: list[str] = []
        # Remove test objects and buckets before deleting the Object Storage subscription.
        object_client = getattr(self, "object_client", None)
        for bucket in self.created["object_buckets"]:
            try:
                if object_client:
                    for obj in object_client.list_objects_v2(Bucket=bucket).get("Contents", []):
                        key = obj.get("Key")
                        if key and self.prefix in key:
                            object_client.delete_object(Bucket=bucket, Key=key)
                    object_client.delete_bucket(Bucket=bucket)
            except Exception as error:
                errors.append(f"object bucket {bucket}: {self._safe_error(error)}")
        for resource_id in reversed(self.created["object_storages"]):
            try:
                self._delete_owned(
                    "object_storage",
                    resource_id,
                    f"/object-storage/{resource_id}",
                    lambda item: item.get("label") == f"{self.prefix}-object-storage",
                )
            except Exception as error:
                errors.append(f"object storage {resource_id}: {self._safe_error(error)}")

        # Managed DB restore target first; never delete provider-owned backup metadata.
        for resource_id in reversed(self.created["databases"]):
            try:
                self._delete_owned(
                    "database",
                    resource_id,
                    f"/databases/{resource_id}",
                    lambda item, expected=self.database_labels.get(resource_id): item.get("label") == expected,
                )
            except Exception as error:
                errors.append(f"database {resource_id}: {self._safe_error(error)}")

        # Restore targets must be removed before their source snapshots.  Keep
        # source resources until every dependent provider snapshot is deleted.
        for resource_id in reversed(self.created["blocks"]):
            if resource_id == getattr(self, "source_block_id", None):
                continue
            try:
                self._delete_owned(
                    "block",
                    resource_id,
                    f"/blocks/{resource_id}",
                    lambda item, expected=self.block_labels.get(resource_id): item.get("label") == expected,
                )
            except Exception as error:
                errors.append(f"block {resource_id}: {self._safe_error(error)}")
        for resource_id in reversed(self.created["instances"]):
            if resource_id == getattr(self, "source_instance_id", None):
                continue
            try:
                self._delete_owned(
                    "instance",
                    resource_id,
                    f"/instances/{resource_id}",
                    lambda item: self.prefix in str(item.get("label"))
                    or self.prefix in str(item.get("hostname"))
                    or self.prefix in str(item.get("tags") or []),
                )
            except Exception as error:
                errors.append(f"instance {resource_id}: {self._safe_error(error)}")

        # Provider snapshots must be removed before their source block/instance.
        for resource_id in reversed(self.created["block_snapshots"]):
            try:
                self._delete_owned(
                    "snapshot", resource_id, f"/blocks/snapshots/{resource_id}",
                    lambda item: self.prefix in str(item.get("description")),
                )
            except Exception as error:
                errors.append(f"block snapshot {resource_id}: {self._safe_error(error)}")
        for resource_id in reversed(self.created["snapshots"]):
            try:
                snapshot = self._get(f"/snapshots/{resource_id}", "snapshot")
                if snapshot is None:
                    continue
                if (
                    self.prefix not in str(snapshot.get("description"))
                    or snapshot.get("instance_id") not in (None, "", self.source_instance_id)
                ):
                    raise HarnessError(f"instance snapshot {resource_id} ownership proof failed")
                self.request("DELETE", f"/snapshots/{resource_id}", expected=(204,))
            except Exception as error:
                errors.append(f"instance snapshot {resource_id}: {self._safe_error(error)}")

        for resource_id in reversed(self.created["blocks"]):
            if resource_id != getattr(self, "source_block_id", None):
                continue
            try:
                self._delete_owned(
                    "block",
                    resource_id,
                    f"/blocks/{resource_id}",
                    lambda item: self.prefix in str(item.get("label")),
                )
            except Exception as error:
                errors.append(f"block {resource_id}: {self._safe_error(error)}")
        for resource_id in reversed(self.created["instances"]):
            if resource_id != getattr(self, "source_instance_id", None):
                continue
            try:
                self._delete_owned(
                    "instance",
                    resource_id,
                    f"/instances/{resource_id}",
                    lambda item: self.prefix in str(item.get("label"))
                    or self.prefix in str(item.get("hostname"))
                    or self.prefix in str(item.get("tags") or []),
                )
            except Exception as error:
                errors.append(f"instance {resource_id}: {self._safe_error(error)}")

        # Verify eventual consistency and fail closed if any exact run-owned resource remains.
        try:
            def remaining(path, item_key, created_key):
                created_ids = set(self.created[created_key])
                return [
                    item.get("id")
                    for item in self.collection(path, item_key)
                    if item.get("id") in created_ids or self._has_marker(item)
                ]

            remaining = {
                "instances": remaining("/instances", "instances", "instances"),
                "snapshots": remaining("/snapshots", "snapshots", "snapshots"),
                "blocks": remaining("/blocks", "blocks", "blocks"),
                "block_snapshots": remaining("/blocks/snapshots", "snapshots", "block_snapshots"),
                "databases": remaining("/databases", "databases", "databases"),
                "object_storages": remaining("/object-storage", "object_storages", "object_storages"),
            }
            self.report["cleanup"]["remaining"] = remaining
            if any(remaining.values()):
                errors.append(f"run-owned provider resources remain after cleanup: {remaining}")
        except Exception as error:
            errors.append(f"final inventory: {self._safe_error(error)}")

        if self.account is not None:
            try:
                account_id = self.account.id
                self.account.delete()
                self.member.delete()
                self.user.delete()
                self.report["cleanup"]["local_account_id"] = account_id
            except Exception as error:
                errors.append(f"local BackupSheep records: {self._safe_error(error)}")
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
            report = self.render_report()
            if self.report_path:
                self.report_path.parent.mkdir(parents=True, exist_ok=True)
                self.report_path.write_text(report, encoding="utf-8")
            print(json.dumps(self.report, indent=2, sort_keys=True, default=str))
        return 0 if self.report.get("result") == "PASS" and self.report["cleanup"]["status"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="Write a sanitized Markdown report to this path")
    args = parser.parse_args()
    return LiveVultrHarness(report_path=args.report).run()


if __name__ == "__main__":
    raise SystemExit(main())
