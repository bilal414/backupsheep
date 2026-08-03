"""Safety-first Hetzner Cloud end-to-end test for BackupSheep.

This harness creates one uniquely named Hetzner server, drives the existing
BackupSheep Hetzner snapshot/restore methods against it, and removes only
resources whose exact name/description, ID, and ownership label match this
run.  It intentionally does not call a volume-snapshot endpoint: the current
Hetzner Cloud API has no native volume snapshot/restore operation, and the
current BackupSheep integration is expected to reject that path explicitly.

Required environment variables:

    HCLOUD_TOKEN
    HETZNER_E2E_SERVER_TYPE   # e.g. cx23; must be available in the project
    HETZNER_E2E_LOCATION       # e.g. fsn1; must be available in the project
    HETZNER_E2E_IMAGE          # an available system image name or numeric ID

Optional environment variables:

    HETZNER_E2E_API             # API host, defaults to https://api.hetzner.cloud
    HETZNER_E2E_POLL_SECONDS     # default 15
    HETZNER_E2E_TIMEOUT_SECONDS  # default 1800

The token is read only from the process environment.  It is never included in
the report, request errors, or application database fixture data in plaintext.
Run this from the application image/environment, for example:

    HCLOUD_TOKEN=... \
    HETZNER_E2E_SERVER_TYPE=cx23 \
    HETZNER_E2E_LOCATION=fsn1 \
    HETZNER_E2E_IMAGE=ubuntu-24.04 \
      python scripts/hetzner_cloud_e2e.py
"""

import datetime as dt
import json
import os
import secrets
import sys
import time

import django
import requests


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")


class HarnessError(RuntimeError):
    """A clear, actionable harness failure."""


class ProviderNotFound(HarnessError):
    """The requested provider resource no longer exists."""


def _redact(value, secrets_to_redact):
    text = str(value)
    for secret in secrets_to_redact:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _api_host():
    configured = os.environ.get("HETZNER_E2E_API") or os.environ.get(
        "HETZNER_API", "https://api.hetzner.cloud"
    )
    configured = configured.rstrip("/")
    if configured.endswith("/v1"):
        return configured[:-3]
    return configured


def _unique_prefix():
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%y%m%d%H%M%S")
    return f"bs-e2e-{stamp}-{secrets.token_hex(3)}"


class HetznerHarness:
    LABEL_KEY = "backupsheep.com/e2e"

    def __init__(self, token):
        self.token = token
        self.api = f"{_api_host()}/v1"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )
        self.prefix = _unique_prefix()
        self.source_name = f"{self.prefix}-source"
        self.restore_name = f"{self.prefix}-restore"
        self.snapshot_description = f"{self.prefix}-server-snapshot"
        self.server_type = os.environ["HETZNER_E2E_SERVER_TYPE"]
        self.location = os.environ["HETZNER_E2E_LOCATION"]
        self.image = os.environ["HETZNER_E2E_IMAGE"]
        self.poll_seconds = max(int(os.environ.get("HETZNER_E2E_POLL_SECONDS", "15")), 5)
        self.timeout_seconds = max(
            int(os.environ.get("HETZNER_E2E_TIMEOUT_SECONDS", "1800")), 60
        )
        self.created = {
            "source_server_id": None,
            "restore_server_id": None,
            "snapshot_image_id": None,
            "account": None,
            "member": None,
        }
        self.mutation_started = False
        self.report = {
            "prefix": self.prefix,
            "server_type": self.server_type,
            "location": self.location,
            "image": self.image,
            "tests": {},
            "cleanup": {"status": "NOT_RUN", "errors": []},
        }

    @property
    def labels(self):
        return {self.LABEL_KEY: self.prefix}

    def _safe_error(self, error):
        return _redact(error, (self.token, os.environ.get("HCLOUD_TOKEN")))

    def request(self, method, path, *, expected=(200,), **kwargs):
        try:
            response = self.session.request(
                method,
                f"{self.api}{path}",
                timeout=(15, 60),
                **kwargs,
            )
        except requests.RequestException as error:
            raise HarnessError(
                f"Hetzner {method} {path} request failed: {self._safe_error(error)}"
            ) from error

        if response.status_code == 404:
            raise ProviderNotFound(f"Hetzner {method} {path} returned HTTP 404")
        if response.status_code not in expected:
            try:
                detail = response.json().get("error", {}).get("message", "")
            except ValueError:
                detail = ""
            suffix = f": {detail}" if detail else ""
            raise HarnessError(
                f"Hetzner {method} {path} returned HTTP {response.status_code}{suffix}"
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as error:
            raise HarnessError(
                f"Hetzner {method} {path} returned non-JSON content"
            ) from error

    def collection(self, resource, params=None):
        """Read one paginated collection without mutating provider state."""
        items = []
        page = 1
        base_params = dict(params or {})
        while True:
            query = {**base_params, "page": page, "per_page": 50}
            payload = self.request("GET", f"/{resource}", params=query)
            items.extend(payload.get(resource) or [])
            pagination = (payload.get("meta") or {}).get("pagination") or {}
            next_page = pagination.get("next_page")
            if not next_page:
                return items
            page = int(next_page)

    def get_resource(self, resource, identifier):
        try:
            return self.request("GET", f"/{resource}/{identifier}")[resource.rstrip("s")]
        except ProviderNotFound:
            return None

    def baseline(self):
        """Inventory only; no provider mutation occurs in this method."""
        servers = self.collection("servers")
        images = self.collection("images", {"type": "snapshot"})
        volumes = self.collection("volumes")

        def server_match(item):
            return item.get("name", "").startswith(self.prefix) or (
                (item.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
            )

        def image_match(item):
            return item.get("description", "").startswith(self.prefix) or (
                (item.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
            )

        def volume_match(item):
            return item.get("name", "").startswith(self.prefix) or (
                (item.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
            )

        collisions = {
            "servers": [item for item in servers if server_match(item)],
            "snapshot_images": [item for item in images if image_match(item)],
            "volumes": [item for item in volumes if volume_match(item)],
        }
        self.report["baseline"] = {
            "counts": {
                "servers": len(servers),
                "snapshot_images": len(images),
                "volumes": len(volumes),
            },
            "prefix_collisions": {
                key: [self._inventory_identity(item) for item in values]
                for key, values in collisions.items()
            },
        }
        if any(collisions.values()):
            raise HarnessError(
                f"Unique prefix collision detected before mutation: "
                f"{self.report['baseline']['prefix_collisions']}"
            )

    @staticmethod
    def _inventory_identity(item):
        return {
            "id": item.get("id"),
            "name": item.get("name"),
            "description": item.get("description"),
            "labels": item.get("labels") or {},
        }

    def preflight_capabilities(self):
        """Validate all selected create inputs using read-only API calls."""
        server_types = self.collection("server_types")
        locations = self.collection("locations")
        images = self.collection("images", {"type": "system"})

        selected_type = next(
            (item for item in server_types if item.get("name") == self.server_type), None
        )
        if not selected_type:
            raise HarnessError(
                f"Configured server type {self.server_type!r} is not available in this project"
            )
        selected_location = next(
            (item for item in locations if item.get("name") == self.location), None
        )
        if not selected_location:
            raise HarnessError(
                f"Configured location {self.location!r} is not available in this project"
            )
        selected_image = next(
            (
                item
                for item in images
                if str(item.get("id")) == self.image or item.get("name") == self.image
            ),
            None,
        )
        if not selected_image or selected_image.get("status") not in {"available", None}:
            raise HarnessError(
                f"Configured system image {self.image!r} is not available in this project"
            )
        self.report["preflight"] = {
            "server_type_id": selected_type.get("id"),
            "location_id": selected_location.get("id"),
            "image_id": selected_image.get("id"),
            "image_type": selected_image.get("type"),
        }

    def create_server(self, name, role):
        payload = {
            "name": name,
            "server_type": self.server_type,
            "image": int(self.image) if self.image.isdigit() else self.image,
            "location": self.location,
            "start_after_create": True,
            "labels": self.labels,
        }
        self.mutation_started = True
        response = self.request("POST", "/servers", expected=(201,), json=payload)
        server = response.get("server") or {}
        identifier = server.get("id")
        if identifier is None:
            raise HarnessError(f"Hetzner server create returned no server ID for {role}")
        self.created[f"{role}_server_id"] = str(identifier)
        return server

    def wait_for(self, label, callback, complete, failed=()):
        started = time.monotonic()
        history = []
        while True:
            value = callback()
            history.append(str(value))
            if value in complete:
                return value, history[-8:]
            if value in failed:
                raise HarnessError(f"{label} failed with state {value!r}")
            if time.monotonic() - started > self.timeout_seconds:
                raise HarnessError(
                    f"Timed out waiting for {label}; recent states={history[-8:]}"
                )
            time.sleep(self.poll_seconds)

    def wait_for_server(self, identifier, label):
        def state():
            server = self.get_resource("servers", identifier)
            if not server:
                raise HarnessError(f"{label} disappeared before reaching running")
            return server.get("status")

        return self.wait_for(label, state, {"running"}, {"deleting", "unknown"})

    def create_app_graph(self, source_id):
        from apps.api.v1.utils.api_helpers import bs_encrypt
        from apps.console.connection.models import CoreAuthHetzner
        from apps.console.node.models import CoreHetzner, CoreNode
        from apps.tests import factories

        account, member, _ = factories.make_account(
            email=f"{self.prefix}@example.invalid"
        )
        self.created["account"] = account
        self.created["member"] = member
        key = account.get_encryption_key()
        connection = factories.make_connection(
            account, member, code="hetzner", name=f"{self.prefix}-connection"
        )
        CoreAuthHetzner.objects.create(
            connection=connection,
            api_key=bs_encrypt(self.token, key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name=self.source_name,
            added_by=member,
        )
        provider = CoreHetzner.objects.create(
            node=node,
            name=self.source_name,
            unique_id=str(source_id),
        )
        return account, member, node, provider

    def run_server_backup_restore(self):
        from apps.console.backup.models import CoreCloudRestore, CoreHetznerBackup
        from apps.console.utils.models import UtilBackup

        source = self.create_server(self.source_name, "source")
        source_id = str(source["id"])
        self.wait_for_server(source_id, "source server")
        account, member, node, provider = self.create_app_graph(source_id)

        backup = CoreHetznerBackup.objects.create(
            hetzner=provider,
            uuid=self.snapshot_description,
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        provider.create_snapshot(backup)
        if not backup.unique_id:
            raise HarnessError(
                "BackupSheep Hetzner snapshot create returned without an image ID"
            )
        self.created["snapshot_image_id"] = str(backup.unique_id)

        def backup_state():
            return backup.poll_status()

        state, history = self.wait_for(
            "BackupSheep Hetzner server snapshot",
            backup_state,
            {UtilBackup.Status.COMPLETE},
            {UtilBackup.Status.FAILED},
        )
        image = self.get_resource("images", self.created["snapshot_image_id"])
        if not image or image.get("type") != "snapshot":
            raise HarnessError("Created Hetzner image is missing or is not a snapshot")
        if image.get("description") != self.snapshot_description:
            raise HarnessError("Created Hetzner snapshot description does not match this run")
        if image.get("status") != "available":
            raise HarnessError(
                f"Created Hetzner snapshot did not become available: {image.get('status')!r}"
            )
        self.report["tests"]["server snapshot"] = {
            "status": "PASS",
            "image_id": self.created["snapshot_image_id"],
            "backup_state": int(state),
            "recent_states": history,
        }

        original_image_id = str(backup.unique_id)
        provider.create_snapshot(backup)
        if str(backup.unique_id) != original_image_id:
            raise HarnessError("Repeated snapshot create changed the provider image ID")
        self.report["tests"]["server snapshot duplicate recovery"] = {"status": "PASS"}

        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name=self.restore_name,
            params={
                "server_type": self.server_type,
                "location": self.location,
                "labels": self.labels,
            },
        )
        provider.restore_snapshot(backup, restore)
        if not restore.resource_id:
            raise HarnessError(
                "BackupSheep Hetzner restore returned without a target server ID"
            )
        self.created["restore_server_id"] = str(restore.resource_id)

        def restore_state():
            return restore.poll_status()

        restore_status, restore_history = self.wait_for(
            "BackupSheep Hetzner server restore",
            restore_state,
            {CoreCloudRestore.Status.COMPLETE},
            {CoreCloudRestore.Status.FAILED},
        )
        restored_server = self.get_resource("servers", self.created["restore_server_id"])
        if not restored_server or restored_server.get("name") != self.restore_name:
            raise HarnessError("Restored Hetzner server is missing or has the wrong name")
        if (restored_server.get("labels") or {}).get(self.LABEL_KEY) != self.prefix:
            raise HarnessError("Restored Hetzner server is missing the ownership label")
        if restored_server.get("status") != "running":
            raise HarnessError(
                f"Restored Hetzner server is not running: {restored_server.get('status')!r}"
            )
        restore.status = restore_status
        restore.save(update_fields=["status", "modified"])
        self.report["tests"]["server restore"] = {
            "status": "PASS",
            "server_id": self.created["restore_server_id"],
            "recent_states": [str(value) for value in restore_history],
        }

        # Keep references alive for callers inspecting this file in a debugger;
        # the account is owned by this run and is removed during cleanup.
        del account, member

    def run_volume_capability_guard(self):
        """Assert the unsupported volume path fails without a provider write."""
        from apps._tasks.exceptions import NodeBackupFailedError
        from apps.console.backup.models import CoreHetznerBackup
        from apps.console.node.models import CoreHetzner, CoreNode
        from apps.console.utils.models import UtilBackup

        account = self.created["account"]
        member = self.created["member"]
        connection = account.connections.get(name=f"{self.prefix}-connection")
        volume_node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.VOLUME,
            name=f"{self.prefix}-volume-capability-guard",
            added_by=member,
        )
        provider = CoreHetzner.objects.create(
            node=volume_node,
            name=volume_node.name,
            unique_id=f"{self.prefix}-no-provider-volume",
        )
        backup = CoreHetznerBackup.objects.create(
            hetzner=provider,
            uuid=f"{self.prefix}-volume-snapshot",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        try:
            provider.create_snapshot(backup)
        except NodeBackupFailedError as error:
            message = str(error)
            if "does not provide native volume snapshots" not in message:
                raise HarnessError(
                    "Hetzner volume path failed, but not with the expected explicit "
                    f"unsupported-capability error: {message}"
                ) from error
            self.report["tests"]["volume snapshot capability guard"] = {
                "status": "PASS",
                "provider_call": "not attempted",
                "reason": "Hetzner Cloud has no native volume snapshot operation",
            }
            return
        raise HarnessError(
            "Hetzner volume snapshot path unexpectedly succeeded; the harness will "
            "not guess a volume snapshot/restore API"
        )

    def _find_owned_server(self, name):
        matches = [
            item
            for item in self.collection("servers")
            if item.get("name") == name
            and (item.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
        ]
        if len(matches) > 1:
            raise HarnessError(f"Multiple exact owned server matches found for {name!r}")
        return matches[0] if matches else None

    def _find_owned_snapshot(self):
        matches = [
            item
            for item in self.collection("images", {"type": "snapshot"})
            if item.get("description") == self.snapshot_description
        ]
        if len(matches) > 1:
            raise HarnessError("Multiple exact owned snapshot matches found")
        return matches[0] if matches else None

    def adopt_after_partial_create(self, cleanup_errors):
        """Recover IDs after a lost create response, still using exact ownership."""
        if not self.mutation_started:
            return
        try:
            if not self.created["source_server_id"]:
                source = self._find_owned_server(self.source_name)
                if source:
                    self.created["source_server_id"] = str(source["id"])
            if not self.created["restore_server_id"]:
                restored = self._find_owned_server(self.restore_name)
                if restored:
                    self.created["restore_server_id"] = str(restored["id"])
            if not self.created["snapshot_image_id"]:
                snapshot = self._find_owned_snapshot()
                if snapshot:
                    self.created["snapshot_image_id"] = str(snapshot["id"])
        except Exception as error:
            cleanup_errors.append(f"adopt partial creates: {self._safe_error(error)}")

    def _delete_owned_server(self, identifier, expected_name, cleanup_errors):
        if not identifier:
            return
        resource = self.get_resource("servers", identifier)
        if not resource:
            return
        owned = (
            str(resource.get("id")) == str(identifier)
            and resource.get("name") == expected_name
            and (resource.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
        )
        if not owned:
            cleanup_errors.append(
                f"refused server deletion for {identifier}: exact ownership proof failed"
            )
            return
        try:
            self.request("DELETE", f"/servers/{identifier}", expected=(200, 204))
        except Exception as error:
            cleanup_errors.append(
                f"delete server {identifier}: {self._safe_error(error)}"
            )

    def _delete_owned_snapshot(self, identifier, cleanup_errors):
        if not identifier:
            return
        image = self.get_resource("images", identifier)
        if not image:
            return
        bound_to = image.get("bound_to")
        owned = (
            str(image.get("id")) == str(identifier)
            and image.get("type") == "snapshot"
            and image.get("description") == self.snapshot_description
            and (not bound_to or str(bound_to) == str(self.created["source_server_id"]))
        )
        if not owned:
            cleanup_errors.append(
                f"refused image deletion for {identifier}: exact ownership proof failed"
            )
            return
        try:
            self.request("DELETE", f"/images/{identifier}", expected=(200, 204))
        except Exception as error:
            cleanup_errors.append(
                f"delete snapshot image {identifier}: {self._safe_error(error)}"
            )

    def _wait_until_owned_resources_absent(self, cleanup_errors):
        """Require eventual consistency to settle before declaring cleanup green."""
        started = time.monotonic()
        while True:
            remaining = {
                "servers": [
                    self._inventory_identity(item)
                    for item in self.collection("servers")
                    if (item.get("labels") or {}).get(self.LABEL_KEY) == self.prefix
                    or item.get("name") in {self.source_name, self.restore_name}
                ],
                "snapshot_images": [
                    self._inventory_identity(item)
                    for item in self.collection("images", {"type": "snapshot"})
                    if item.get("description") == self.snapshot_description
                ],
            }
            if not any(remaining.values()):
                self.report["cleanup"]["remaining_exact_prefix_resources"] = remaining
                return
            if time.monotonic() - started > min(self.timeout_seconds, 300):
                cleanup_errors.append(
                    f"provider resources remained after cleanup: {remaining}"
                )
                self.report["cleanup"]["remaining_exact_prefix_resources"] = remaining
                return
            time.sleep(self.poll_seconds)

    def cleanup(self):
        cleanup_errors = []
        self.adopt_after_partial_create(cleanup_errors)
        # Delete the restore target first, then the source server, then its image.
        self._delete_owned_server(
            self.created["restore_server_id"], self.restore_name, cleanup_errors
        )
        self._delete_owned_server(
            self.created["source_server_id"], self.source_name, cleanup_errors
        )
        self._delete_owned_snapshot(self.created["snapshot_image_id"], cleanup_errors)
        self._wait_until_owned_resources_absent(cleanup_errors)

        account = self.created.get("account")
        if account is not None:
            try:
                account.delete()
            except Exception as error:
                cleanup_errors.append(f"delete local test account: {self._safe_error(error)}")

        self.report["cleanup"] = {
            "status": "PASS" if not cleanup_errors else "FAIL",
            "errors": cleanup_errors,
            "provider_resources_considered": {
                "source_server_id": self.created["source_server_id"],
                "restore_server_id": self.created["restore_server_id"],
                "snapshot_image_id": self.created["snapshot_image_id"],
            },
        }

    def run(self):
        try:
            self.baseline()
            self.preflight_capabilities()
            self.run_server_backup_restore()
            self.run_volume_capability_guard()
            self.report["status"] = "PASS"
        except Exception as error:
            self.report["status"] = "FAIL"
            self.report["error"] = self._safe_error(error)
        finally:
            self.cleanup()
            print(json.dumps(self.report, indent=2, sort_keys=True, default=str))
        return 0 if self.report.get("status") == "PASS" and self.report["cleanup"]["status"] == "PASS" else 1


def main():
    required = (
        "HCLOUD_TOKEN",
        "HETZNER_E2E_SERVER_TYPE",
        "HETZNER_E2E_LOCATION",
        "HETZNER_E2E_IMAGE",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": "Missing required environment variables: " + ", ".join(missing),
                },
                indent=2,
            )
        )
        return 1

    # Keep the application integration pointed at the same host when a test
    # endpoint override is supplied.  This changes process configuration only.
    if os.environ.get("HETZNER_E2E_API") and not os.environ.get("HETZNER_API"):
        os.environ["HETZNER_API"] = _api_host()
    django.setup()
    return HetznerHarness(os.environ["HCLOUD_TOKEN"]).run()


if __name__ == "__main__":
    sys.exit(main())
