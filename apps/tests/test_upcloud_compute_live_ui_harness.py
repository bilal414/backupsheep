"""Offline safety tests for UpCloud compute/workload live UI support."""

from __future__ import annotations

import io
import json
import tempfile
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from scripts import upcloud_live_ui_e2e as live_harness
from scripts import upcloud_manifest_export


SOURCE_VOLUME_ID = "01a00000-0000-4000-8000-000000000001"
SOURCE_SERVER_ID = "00a00000-0000-4000-8000-000000000002"
SOURCE_BOOT_ID = "01a00000-0000-4000-8000-000000000003"
RESTORE_VOLUME_ID = "01a00000-0000-4000-8000-000000000004"
FOREIGN_SERVER_ID = "00a00000-0000-4000-8000-000000000099"
OS_TEMPLATE_ID = "01000000-0000-4000-8000-000030220200"


class UpCloudComputeLiveUIHarnessSafetyTests(SimpleTestCase):
    run_id = "bs-e2e-upcloud-compute"
    account = "allowed-account"

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self, *, apply=True, cleanup=False):
        return live_harness.HarnessConfig(
            run_id=self.run_id,
            ledger_path=self.root / "ledger.json",
            account=self.account,
            region="",
            runtime_path=self.root / "runtime.json",
            zone="fi-hel1",
            server_plan="1xCPU-1GB",
            os_template=OS_TEMPLATE_ID,
            ssh_user="root",
            volume_size_gb=10,
            boot_size_gb=25,
            allowed_cidrs=("198.51.100.10/32", "2001:db8::10/128"),
            apply=apply,
            cleanup=cleanup,
        )

    def harness(self, *, apply=True, cleanup=False, control=None):
        value = live_harness.UpCloudLiveHarness(
            self.config(apply=apply, cleanup=cleanup),
            environment={"UPCLOUD_API_TOKEN": "TOKEN-CANARY"},
            control=control or mock.Mock(),
            sleeper=lambda _seconds: None,
        )
        value.account = self.account
        return value

    def manifest_payloads(self):
        objects = [
            {
                "kind": "website",
                "backup_id": 11,
                "backup_uuid": "website-backup-2026-08-15",
                "storage_point_id": 201,
                "storage_id": 202,
                "artifact_id": 203,
                "artifact_status": "verified",
                "object_key": "backupsheep-e2e/website-backup-2026-08-15.zip",
                "sha256": "a" * 64,
                "byte_count": 128,
                "etag": "etag-website",
                "version_id": "version-website",
            },
            {
                "kind": "database",
                "backup_id": 12,
                "backup_uuid": "database-backup-2026-08-15",
                "storage_point_id": 204,
                "storage_id": 202,
                "artifact_id": 205,
                "artifact_status": "verified",
                "object_key": "backupsheep-e2e/database-backup-2026-08-15.zip",
                "sha256": "b" * 64,
                "byte_count": 129,
                "etag": "etag-database",
                "version_id": "version-database",
            },
        ]
        return {
            "compute": {
                "schema": 1,
                "run_id": self.run_id,
                "volume": {"node_id": 1, "backup_id": 2, "restore_id": 3},
                "server": {"node_id": 4, "backup_id": 5, "restore_id": 6},
            },
            "workload": {
                "schema": 1,
                "run_id": self.run_id,
                "website": {"node_id": 7, "backup_id": 11, "restore_id": 8},
                "postgresql": {"node_id": 9, "backup_id": 12, "restore_id": 10},
            },
            "object": {"schema": 1, "run_id": self.run_id, "objects": objects},
        }

    def storage(
        self,
        resource_id=SOURCE_VOLUME_ID,
        *,
        title=None,
        storage_type="normal",
        origin="",
        servers=None,
    ):
        value = {
            "uuid": resource_id,
            "title": title or live_harness._resource_names(self.run_id)[
                "source_volume"
            ],
            "type": storage_type,
            "zone": "fi-hel1",
            "tier": "standard",
            "encrypted": "yes",
            "size": 10,
            "state": "online",
            "labels": live_harness._labels(self.run_id),
            "servers": {"server": list(servers or [])},
        }
        if origin:
            value["origin"] = origin
        return value

    @staticmethod
    def server(resource_id=SOURCE_SERVER_ID, *, firewall="on"):
        return {
            "uuid": resource_id,
            "firewall": firewall,
        }

    @staticmethod
    def wire_firewall_rules(rules):
        return [
            {**rule, "position": str(position)}
            for position, rule in enumerate(rules, start=1)
        ]

    def exact_provider_firewall_observation(self, harness):
        rules = [
            live_harness._normalize_firewall_rule(rule)
            for rule in harness._provider_firewall_expected_rules()
        ]
        return {
            "firewall": "on",
            "rules": rules,
            "rules_sha256": live_harness._fingerprint(rules),
            "allow_rule_fingerprints": [
                live_harness._fingerprint(rule)
                for rule in rules
                if rule["action"] == "accept"
            ],
        }

    def test_cli_dispatches_all_compute_and_workload_commands(self):
        fake = mock.Mock()
        fake.setup_compute.return_value = {"status": "setup"}
        fake.verify_compute.return_value = {"status": "compute"}
        fake.verify_workloads.return_value = {"status": "workloads"}
        fake.cleanup_compute.return_value = {"status": "cleanup"}
        commands = (
            (["setup-compute"], "setup_compute"),
            (["verify-compute", "--manifest", "manifest.json"], "verify_compute"),
            (["verify-workloads", "--manifest", "manifest.json"], "verify_workloads"),
            (["cleanup-compute", "--require-evidence"], "cleanup_compute"),
        )
        with mock.patch.object(
            live_harness.HarnessConfig, "from_environment", return_value=self.config()
        ), mock.patch.object(
            live_harness, "UpCloudLiveHarness", return_value=fake
        ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            for argv, method in commands:
                self.assertEqual(live_harness.main(argv, environment={}), 0)
                self.assertTrue(getattr(fake, method).called)
        fake.verify_compute.assert_called_with("manifest.json")
        fake.verify_workloads.assert_called_with("manifest.json")
        fake.cleanup_compute.assert_called_with(require_evidence=True)

    def test_compute_commands_require_apply_before_provider_io(self):
        control = mock.Mock()
        harness = self.harness(apply=False, control=control)
        with self.assertRaises(live_harness.HarnessError):
            harness.setup_compute()
        control.request.assert_not_called()

    def test_environment_rejects_broad_cidrs_and_accepts_host_cidrs(self):
        base = {
            "BACKUPSHEEP_E2E_RUN_ID": self.run_id,
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(self.root / "config-ledger.json"),
            "UPCLOUD_E2E_ALLOWED_ACCOUNT": self.account,
            "UPCLOUD_E2E_ZONE": "fi-hel1",
            "UPCLOUD_E2E_SERVER_PLAN": "1xCPU-1GB",
            "UPCLOUD_E2E_OS_TEMPLATE": OS_TEMPLATE_ID,
        }
        for broad in ("0.0.0.0/0", "198.51.100.0/24", "::/0"):
            with self.assertRaises(live_harness.HarnessError):
                live_harness.HarnessConfig.from_environment(
                    {**base, "UPCLOUD_E2E_ALLOWED_CIDRS": broad}
                )
        config = live_harness.HarnessConfig.from_environment(
            {
                **base,
                "UPCLOUD_E2E_ALLOWED_CIDRS": (
                    "198.51.100.10/32,2001:db8::10/128"
                ),
            }
        )
        self.assertEqual(
            set(config.allowed_cidrs),
            {"198.51.100.10/32", "2001:db8::10/128"},
        )

    def test_source_server_is_created_with_provider_firewall_enabled(self):
        harness = self.harness()
        request = harness._source_server_request(SOURCE_VOLUME_ID, "ssh-rsa PUBLIC")
        self.assertEqual(request["server"]["firewall"], "on")
        self.assertEqual(request["server"]["metadata"], "yes")
        devices = request["server"]["storage_devices"]["storage_device"]
        self.assertTrue(all("boot_disk" not in device for device in devices))

    def test_boot_storage_is_inferred_only_from_exact_virtio_zero(self):
        boot = {
            "storage": SOURCE_BOOT_ID,
            "type": "disk",
            "address": "virtio:0",
            "boot_disk": "0",
            "labels": [
                {"key": "_os_type", "value": "linux"},
                {"key": "_template_uuid", "value": OS_TEMPLATE_ID},
            ],
        }
        data = {
            "storage": SOURCE_VOLUME_ID,
            "type": "disk",
            "address": "scsi:0:0",
            "boot_disk": "0",
        }
        server = {
            "boot_order": "disk",
            "storage_devices": {"storage_device": [boot, data]},
        }
        self.assertEqual(live_harness.UpCloudLiveHarness._boot_device(server), boot)
        with self.assertRaises(live_harness.HarnessError):
            live_harness.UpCloudLiveHarness._boot_device(
                {
                    "boot_order": "disk",
                    "storage_devices": {
                        "storage_device": [boot, {**data, "address": "virtio:0"}]
                    }
                }
            )

    def test_compute_inventory_uses_live_limit_and_order_parameters(self):
        control = mock.Mock()
        control.request.return_value = {
            "servers": {"server": [{"uuid": SOURCE_SERVER_ID}]}
        }
        harness = self.harness(control=control)
        self.assertEqual(harness._compute_inventory("server")[0]["uuid"], SOURCE_SERVER_ID)
        params = control.request.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 100)
        self.assertEqual(params["offset"], 0)
        self.assertEqual(params["order"], "asc")
        self.assertEqual(params["sort_by"], "title")
        self.assertNotIn("order_by", params)

        control.reset_mock()
        control.request.return_value = {
            "storages": {
                "storage": [self.storage(storage_type="normal")]
            }
        }
        self.assertEqual(harness._compute_inventory("storage")[0]["uuid"], SOURCE_VOLUME_ID)
        params = control.request.call_args.kwargs["params"]
        self.assertEqual(control.request.call_args.args[:2], ("GET", "/storage/normal"))
        self.assertEqual(params["limit"], 100)
        self.assertEqual(params["order"], "asc")
        self.assertEqual(params["sort_by"], "title")
        self.assertNotIn("type", params)
        self.assertNotIn("order_by", params)

    def test_compute_plan_preflight_requires_exact_boot_size_and_standard_tier(self):
        control = mock.Mock()
        control.request.return_value = {
            "plans": {
                "plan": [
                    {
                        "name": "1xCPU-1GB",
                        "core_number": 1,
                        "memory_amount": 1024,
                        "storage_size": 25,
                        "storage_tier": "standard",
                    }
                ]
            }
        }
        harness = self.harness(control=control)
        self.assertEqual(harness.verify_compute_plan()["storage_size"], 25)
        control.request.assert_called_once_with("GET", "/plan")

        control.reset_mock()
        control.request.return_value = {
            "plans": {
                "plan": [
                    {
                        "name": "1xCPU-1GB",
                        "core_number": 1,
                        "memory_amount": 1024,
                        "storage_size": 50,
                        "storage_tier": "standard",
                    }
                ]
            }
        }
        with self.assertRaises(live_harness.HarnessError):
            harness.verify_compute_plan()

    def test_definite_server_create_rejection_clears_only_its_intent(self):
        control = mock.Mock()
        control.request.side_effect = live_harness.HarnessError(
            "definite provider rejection", definitive_rejection=True
        )
        harness = self.harness(control=control)
        with mock.patch.object(
            harness, "_compute_inventory", return_value=[]
        ), self.assertRaises(live_harness.HarnessError):
            harness.ensure_source_server(self.storage())
        self.assertIsNone(harness.intents.get("compute_source_server_create"))

    def test_provider_firewall_request_is_exact_host_allowlist_with_drop(self):
        harness = self.harness()
        rules = harness._provider_firewall_request()["firewall_rules"]["firewall_rule"]
        self.assertEqual(len(rules), 7)
        self.assertEqual(rules[-1], {"direction": "in", "action": "drop"})
        self.assertEqual(
            {
                (rule["family"], rule["source_address_start"], rule["destination_port_start"])
                for rule in rules[:-1]
            },
            {
                ("IPv4", "198.51.100.10", str(port))
                for port in (22, 80, 5432)
            }
            | {
                ("IPv6", "2001:db8::10", str(port))
                for port in (22, 80, 5432)
            },
        )
        self.assertTrue(
            all(
                rule["action"] == "accept"
                and rule["direction"] == "in"
                and rule["protocol"] == "tcp"
                and rule["source_address_start"] == rule["source_address_end"]
                and rule["destination_port_start"] == rule["destination_port_end"]
                for rule in rules[:-1]
            )
        )
        self.assertNotIn("0.0.0.0/0", json.dumps(rules))
        self.assertNotIn("::/0", json.dumps(rules))

    def test_lost_provider_firewall_put_adopts_exact_chain_without_duplicate_put(self):
        harness = self.harness()
        observation = self.exact_provider_firewall_observation(harness)
        harness.intents.put(
            "compute_source_firewall:" + SOURCE_SERVER_ID,
            {
                "marker": self.run_id,
                "kind": live_harness.FIREWALL_LEDGER_KIND,
                "name": harness.names["source_server"],
                "operation": "replace-chain",
                "server_id": SOURCE_SERVER_ID,
                "request_fingerprint": live_harness._fingerprint(
                    harness._provider_firewall_request()
                ),
            },
        )
        harness.intents.update(
            "compute_source_firewall:" + SOURCE_SERVER_ID,
            request_boundary_crossed=True,
        )
        wire = self.wire_firewall_rules(observation["rules"])
        harness.control.request.return_value = {
            "firewall_rules": {"firewall_rule": wire}
        }
        with mock.patch.object(
            harness, "_server_read", return_value=self.server()
        ):
            evidence = harness._ensure_provider_firewall(SOURCE_SERVER_ID)
        self.assertEqual(evidence["allow_rule_count"], 6)
        self.assertFalse(
            any(
                call.args[:2] == ("PUT", f"/server/{SOURCE_SERVER_ID}/firewall_rule")
                for call in harness.control.request.call_args_list
            )
        )

    def test_duplicate_provider_firewall_rule_is_rejected(self):
        harness = self.harness()
        expected = harness._provider_firewall_expected_rules()
        wire = self.wire_firewall_rules(expected)
        wire.insert(1, dict(wire[0], position="2"))
        wire = [dict(rule, position=str(position)) for position, rule in enumerate(wire, 1)]
        harness.control.request.return_value = {
            "firewall_rules": {"firewall_rule": wire}
        }
        with self.assertRaises(live_harness.HarnessError):
            harness._provider_firewall_inventory(SOURCE_SERVER_ID)
        harness.control.request.assert_called_once()

    def test_cleanup_removes_only_ledgered_allow_rules_and_keeps_drop(self):
        harness = self.harness(cleanup=True)
        observation = self.exact_provider_firewall_observation(harness)
        evidence = harness._record_provider_firewall_rules(
            SOURCE_SERVER_ID, observation
        )
        entry = {
            "kind": "compute_source_server",
            "resource_id": SOURCE_SERVER_ID,
            "ownership": {
                "account": self.account,
                "run_id": self.run_id,
                "provider_firewall": evidence,
            },
        }
        rules = list(observation["rules"])
        requests = []

        def request(method, path, **kwargs):
            requests.append((method, path, kwargs))
            if method == "GET":
                return {
                    "firewall_rules": {
                        "firewall_rule": self.wire_firewall_rules(rules)
                    }
                }
            if method == "DELETE":
                position = int(path.rsplit("/", 1)[-1])
                rules.pop(position - 1)
                return None
            raise AssertionError(f"unexpected method: {method}")

        harness.control.request.side_effect = request
        with mock.patch.object(
            harness, "_server_read", return_value=self.server()
        ):
            harness._cleanup_provider_firewall(entry, self.server())
        deleted_paths = [path for method, path, _kwargs in requests if method == "DELETE"]
        self.assertEqual(len(deleted_paths), 6)
        self.assertNotIn(
            f"/server/{SOURCE_SERVER_ID}/firewall_rule/7", deleted_paths
        )
        self.assertEqual(rules, [live_harness._normalize_firewall_rule({"direction": "in", "action": "drop"})])

    def test_cleanup_refuses_foreign_provider_firewall_rule(self):
        harness = self.harness(cleanup=True)
        observation = self.exact_provider_firewall_observation(harness)
        evidence = harness._record_provider_firewall_rules(
            SOURCE_SERVER_ID, observation
        )
        entry = {
            "kind": "compute_source_server",
            "resource_id": SOURCE_SERVER_ID,
            "ownership": {
                "account": self.account,
                "run_id": self.run_id,
                "provider_firewall": evidence,
            },
        }
        foreign = {
            **live_harness._normalize_firewall_rule(
                {
                    "direction": "in",
                    "family": "IPv4",
                    "protocol": "tcp",
                    "source_address_start": "203.0.113.55",
                    "source_address_end": "203.0.113.55",
                    "destination_port_start": "22",
                    "destination_port_end": "22",
                    "action": "accept",
                    "comment": "foreign",
                }
            )
        }
        rules = list(observation["rules"])
        rules.insert(0, foreign)
        harness.control.request.return_value = {
            "firewall_rules": {
                "firewall_rule": self.wire_firewall_rules(rules)
            }
        }
        with mock.patch.object(
            harness, "_server_read", return_value=self.server()
        ), self.assertRaises(live_harness.HarnessError):
            harness._cleanup_provider_firewall(entry, self.server())
        self.assertFalse(
            any(call.args and call.args[0] == "DELETE" for call in harness.control.request.call_args_list)
        )

    def test_lost_source_volume_response_adopts_exact_owned_id_without_post(self):
        harness = self.harness()
        request = harness._source_volume_request()
        harness.intents.put(
            "compute_source_volume_create",
            {
                "marker": self.run_id,
                "kind": "compute_source_volume",
                "name": harness.names["source_volume"],
                "operation": "create",
                "request_fingerprint": live_harness._fingerprint(request),
                "preflight_absent": True,
            },
        )
        harness.intents.update(
            "compute_source_volume_create", request_boundary_crossed=True
        )
        storage = self.storage()
        with mock.patch.object(
            harness, "_compute_inventory", return_value=[storage]
        ), mock.patch.object(
            harness, "_storage_read", return_value=storage
        ):
            result = harness.ensure_source_volume()
        self.assertEqual(result["uuid"], SOURCE_VOLUME_ID)
        self.assertEqual(
            harness._one_active("compute_source_volume")["resource_id"],
            SOURCE_VOLUME_ID,
        )
        harness.control.request.assert_not_called()

    def test_unledgered_exact_title_collision_never_posts(self):
        harness = self.harness()
        storage = self.storage()
        with mock.patch.object(
            harness, "_compute_inventory", return_value=[storage]
        ), self.assertRaises(live_harness.HarnessError):
            harness.ensure_source_volume()
        harness.control.request.assert_not_called()

    def test_foreign_attachment_is_refused_before_detach_mutation(self):
        harness = self.harness(cleanup=True)
        entry = harness._record_attachment(
            kind="compute_restore_attachment",
            server_id=SOURCE_SERVER_ID,
            storage_id=RESTORE_VOLUME_ID,
        )
        storage = self.storage(
            RESTORE_VOLUME_ID,
            title="backupsheep-upcloud-restore",
            servers=[FOREIGN_SERVER_ID],
        )
        with mock.patch.object(
            harness, "_storage_read", return_value=storage
        ), self.assertRaises(live_harness.HarnessError):
            harness._detach_attachment(entry, intent_key="cleanup:test")
        harness.control.request.assert_not_called()

    def test_changed_ui_storage_ownership_refuses_delete(self):
        harness = self.harness(cleanup=True)
        harness.ledger.record(
            kind="ui_volume_restore",
            resource_id=RESTORE_VOLUME_ID,
            name="backupsheep-upcloud-restore",
            ownership={
                "account": self.account,
                "run_id": self.run_id,
                "zone": "fi-hel1",
                "marker": "backupsheep-upcloud-restore",
                "type": "normal",
                "origin": "01a00000-0000-4000-8000-000000000010",
            },
            source_witness="01a00000-0000-4000-8000-000000000010",
        )
        changed = self.storage(
            RESTORE_VOLUME_ID,
            title="backupsheep-upcloud-restore",
            origin="01a00000-0000-4000-8000-000000000011",
        )
        with mock.patch.object(
            harness, "_storage_read", return_value=changed
        ), self.assertRaises(live_harness.HarnessError):
            harness._delete_compute_storage(
                harness._one_active("ui_volume_restore")
            )
        harness.control.request.assert_not_called()

    def test_normal_clone_may_omit_origin_but_not_size_tier_or_encryption(self):
        harness = self.harness()
        marker = "backupsheep-upcloud-storage-restore"
        clone = self.storage(
            RESTORE_VOLUME_ID,
            title=marker,
            origin="",
        )
        with mock.patch.object(
            harness, "_compute_inventory", return_value=[clone]
        ), mock.patch.object(harness, "_storage_read", return_value=clone):
            verified = harness._verify_ui_storage(
                kind="ui_volume_restore",
                resource_id=RESTORE_VOLUME_ID,
                marker=marker,
                storage_type="normal",
                origin="01a00000-0000-4000-8000-000000000010",
                allow_omitted_origin=True,
                expected_size=10,
                expected_tier="standard",
                expected_encrypted="yes",
            )
        self.assertEqual(verified["uuid"], RESTORE_VOLUME_ID)
        entry = harness._one_active("ui_volume_restore")
        self.assertTrue(entry["ownership"]["origin_may_be_omitted"])
        self.assertTrue(harness._storage_entry_owned(entry, clone))

        for field, value in (
            ("origin", "foreign-backup"),
            ("size", 11),
            ("tier", "maxiops"),
            ("encrypted", "no"),
        ):
            changed = dict(clone, **{field: value})
            with self.subTest(field=field), mock.patch.object(
                harness, "_compute_inventory", return_value=[changed]
            ), mock.patch.object(harness, "_storage_read", return_value=changed):
                with self.assertRaises(live_harness.HarnessError):
                    harness._verify_ui_storage(
                        kind="ui_volume_restore",
                        resource_id=RESTORE_VOLUME_ID,
                        marker=marker,
                        storage_type="normal",
                        origin="01a00000-0000-4000-8000-000000000010",
                        allow_omitted_origin=True,
                        expected_size=10,
                        expected_tier="standard",
                        expected_encrypted="yes",
                    )

    def test_compute_runtime_is_0600_and_credentials_never_enter_ledger(self):
        harness = self.harness()
        path = live_harness._compute_runtime_path(
            harness.config.runtime_path, self.run_id
        )
        payload = {
            "schema": live_harness.COMPUTE_RUNTIME_SCHEMA,
            "provider": "upcloud",
            "run_id": self.run_id,
            "account": self.account,
            "server_uuid": SOURCE_SERVER_ID,
            "ssh_user": "root",
            "website_root": f"/srv/backupsheep-e2e/{self.run_id}/website",
            "database_host": "203.0.113.10",
            "database_port": "5432",
            "database_name": "bs_e2e_database",
            "database_user": "bs_e2e_user",
            "database_password": "PASSWORD-CANARY",
        }
        live_harness._write_compute_runtime_secret(path, payload)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(live_harness._read_compute_runtime_secret(path), payload)
        ledger = harness.config.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn("PASSWORD-CANARY", ledger)

    def test_generated_ssh_key_stays_in_mode_0600_runtime_material(self):
        harness = self.harness()
        private_path, public_key = harness._ensure_ssh_key()
        _private, public_path, _known_hosts = harness._key_paths()
        self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(public_path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(public_key.startswith("ssh-rsa "))
        ledger = harness.config.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn(public_key, ledger)

    def test_ssh_readiness_waiter_retries_without_recreating_server(self):
        harness = self.harness()
        client = mock.Mock()
        with mock.patch.object(
            harness,
            "_ssh_client",
            side_effect=[
                live_harness.HarnessError("not ready"),
                live_harness.HarnessError("not ready"),
                client,
            ],
        ) as connect:
            self.assertIs(
                harness._wait_ssh_client(
                    {"uuid": SOURCE_SERVER_ID},
                    host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST",
                ),
                client,
            )
        self.assertEqual(connect.call_count, 3)

    def test_ssh_host_key_fingerprint_is_stable_and_secret_free(self):
        key = mock.Mock()
        key.asbytes.return_value = b"public-host-key-material"
        client = mock.Mock()
        client.get_transport.return_value.get_remote_server_key.return_value = key
        fingerprint = live_harness.UpCloudLiveHarness._ssh_host_key_fingerprint(client)
        self.assertTrue(fingerprint.startswith("SHA256:"))
        self.assertNotIn("public-host-key-material", fingerprint)

    def test_ssh_requires_independent_exact_host_key_pin_and_never_uses_tofu(self):
        host = "198.51.100.30"
        host_key = mock.Mock()
        host_key.asbytes.return_value = b"upcloud-exact-host-key"
        expected = live_harness._ssh_public_key_fingerprint(host_key)
        harness = self.harness()
        harness.environment.update(
            {
                "UPCLOUD_E2E_SOURCE_SSH_HOST": host,
                "UPCLOUD_E2E_SOURCE_SSH_HOST_KEY_SHA256": expected,
            }
        )
        server = {
            "ip_addresses": {
                "ip_address": [
                    {
                        "access": "public",
                        "family": "IPv4",
                        "address": host,
                    }
                ]
            }
        }
        client = mock.Mock()
        client.get_transport.return_value.get_remote_server_key.return_value = host_key
        with (
            mock.patch.object(
                harness,
                "_ensure_ssh_key",
                return_value=(self.root / "upcloud-key", "ssh-rsa TEST"),
            ),
            mock.patch("paramiko.SSHClient", return_value=client),
            mock.patch(
                "paramiko.RSAKey.from_private_key_file",
                return_value=mock.sentinel.private_key,
            ),
        ):
            connected = harness._ssh_client(
                server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
            )

        self.assertIs(connected, client)
        policy = client.set_missing_host_key_policy.call_args.args[0]
        self.assertEqual(policy.expected_fingerprint, expected)
        policy.missing_host_key(client, host, host_key)
        client.load_host_keys.assert_not_called()
        client.save_host_keys.assert_not_called()

        wrong_key = mock.Mock()
        wrong_key.asbytes.return_value = b"upcloud-attacker-host-key"
        with self.assertRaisesRegex(live_harness.HarnessError, "exact pin"):
            policy.missing_host_key(client, host, wrong_key)

    def test_ssh_missing_host_key_pin_fails_before_paramiko_client(self):
        host = "198.51.100.30"
        harness = self.harness()
        harness.environment["UPCLOUD_E2E_SOURCE_SSH_HOST"] = host
        server = {
            "ip_addresses": {
                "ip_address": [
                    {
                        "access": "public",
                        "family": "IPv4",
                        "address": host,
                    }
                ]
            }
        }
        with (
            mock.patch.object(
                harness,
                "_ensure_ssh_key",
                return_value=(self.root / "upcloud-key", "ssh-rsa TEST"),
            ),
            mock.patch("paramiko.SSHClient") as ssh_client,
            self.assertRaisesRegex(
                live_harness.HarnessError,
                "UPCLOUD_E2E_SOURCE_SSH_HOST_KEY_SHA256 must be",
            ),
        ):
            harness._ssh_client(
                server, host_variable="UPCLOUD_E2E_SOURCE_SSH_HOST"
            )
        ssh_client.assert_not_called()

    def test_mount_detection_ignores_parent_root_and_requires_exact_target(self):
        mount_path = f"/mnt/backupsheep-e2e-{self.run_id}"
        self.assertEqual(
            live_harness.UpCloudLiveHarness._exact_mount_source(
                "/dev/vda2 /", mount_path
            ),
            "",
        )
        self.assertEqual(
            live_harness.UpCloudLiveHarness._exact_mount_source(
                f"/dev/sda {mount_path}", mount_path
            ),
            "/dev/sda",
        )
        with self.assertRaises(live_harness.HarnessError):
            live_harness.UpCloudLiveHarness._exact_mount_source(
                f"/dev/sda {mount_path}\n/dev/sdb {mount_path}", mount_path
            )

    def test_website_and_postgresql_fixtures_are_deterministic(self):
        harness = self.harness()
        archive_one, website_one = harness._website_archive()
        archive_two, website_two = harness._website_archive()
        self.assertEqual(archive_one, archive_two)
        self.assertEqual(website_one, website_two)
        self.assertEqual(website_one["file_count"], 4)
        database_one = harness._database_fixture(
            "bs_e2e_database", "bs_e2e_user", "a" * 64
        )
        database_two = harness._database_fixture(
            "bs_e2e_database", "bs_e2e_user", "a" * 64
        )
        self.assertEqual(database_one, database_two)
        self.assertEqual(
            database_one["total_rows"],
            sum(database_one["row_counts"].values()),
        )
        self.assertEqual(database_one["row_counts"], {"customers": 120, "events": 480})

    def test_firewall_evidence_requires_only_exact_host_rules(self):
        harness = self.harness()
        allowed = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    198.51.100.10
80/tcp                     ALLOW IN    198.51.100.10
5432/tcp                   ALLOW IN    198.51.100.10
22/tcp (v6)                ALLOW IN    2001:db8::10
80/tcp (v6)                ALLOW IN    2001:db8::10
5432/tcp (v6)              ALLOW IN    2001:db8::10
"""
        with mock.patch.object(harness, "_ssh_run", return_value=allowed):
            evidence = harness._firewall_evidence(mock.Mock())
        self.assertEqual(evidence["default_incoming"], "deny")
        world = allowed + "22/tcp ALLOW IN Anywhere\n"
        with mock.patch.object(
            harness, "_ssh_run", return_value=world
        ), self.assertRaises(live_harness.HarnessError):
            harness._firewall_evidence(mock.Mock())

    def test_firewall_evidence_accepts_compact_live_ufw_format(self):
        harness = self.harness()
        allowed = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       198.51.100.10
80/tcp                     ALLOW       198.51.100.10
5432/tcp                   ALLOW       198.51.100.10
22/tcp (v6)                ALLOW       2001:db8::10
80/tcp (v6)                ALLOW       2001:db8::10
5432/tcp (v6)              ALLOW       2001:db8::10
"""
        with mock.patch.object(harness, "_ssh_run", return_value=allowed):
            evidence = harness._firewall_evidence(mock.Mock())
        self.assertEqual(
            set(evidence["allowed_cidrs"]),
            {"198.51.100.10/32", "2001:db8::10/128"},
        )

    def test_completed_workload_is_adopted_without_replaying_mutations(self):
        harness = self.harness()
        runtime = {
            "database_name": "bs_e2e_database",
            "database_user": "bs_e2e_user",
            "database_password": "a" * 64,
        }
        website = {"file_count": 4}
        database = {"total_rows": 600}
        firewall = {"default_incoming": "deny"}
        with mock.patch.object(
            harness, "_ensure_compute_runtime", return_value=runtime
        ), mock.patch.object(
            harness, "_website_archive", return_value=(b"archive", website)
        ), mock.patch.object(
            harness,
            "_database_fixture",
            return_value={
                "row_counts": {"customers": 120, "events": 480},
                "total_rows": 600,
                "canonical_sha256": "b" * 64,
                "schema_sha256": "c" * 64,
            },
        ), mock.patch.object(
            harness,
            "_completed_workload_evidence",
            return_value=(website, database, firewall),
        ) as recovered, mock.patch.object(harness, "_ssh_client") as ssh_client:
            result = harness.setup_workloads(self.server())
        self.assertEqual(result["status"], "ready_for_ui_file_database_backups")
        recovered.assert_called_once()
        ssh_client.assert_not_called()
        entry = harness._one_active("compute_workload_fixture")
        self.assertEqual(entry["resource_id"], SOURCE_SERVER_ID)
        self.assertEqual(entry["ownership"]["database"], database)

    def test_database_evidence_hashes_rows_remotely_with_bounded_output(self):
        harness = self.harness()
        run = mock.Mock(
            side_effect=["120|480", "a" * 64, "b" * 64]
        )
        with mock.patch.object(harness, "_ssh_run", run):
            evidence = harness._database_evidence(mock.Mock(), "bs_e2e_database")
        self.assertEqual(evidence["row_counts"], {"customers": 120, "events": 480})
        self.assertEqual(evidence["canonical_sha256"], "a" * 64)
        self.assertEqual(evidence["schema_sha256"], "b" * 64)
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list[1:]:
            self.assertIn("bash -o pipefail -c", call.args[1])
            self.assertIn("hashlib.sha256", call.args[1])
        self.assertIn("COLLATE", run.call_args_list[1].args[1])

    def test_evidence_gated_cleanup_stops_before_provider_io(self):
        harness = self.harness(cleanup=True)
        with mock.patch.object(
            harness, "verify_account", return_value=self.account
        ), self.assertRaises(live_harness.HarnessError):
            harness.cleanup_compute(require_evidence=True)
        harness.control.request.assert_not_called()

    def test_workload_manifest_cannot_escape_restore_scope(self):
        harness = self.harness()
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "website": {
                "node_id": 10,
                "backup_id": 11,
                "restore_id": 12,
                "restore_path": "/tmp/foreign",
            },
            "postgresql": {
                "node_id": 20,
                "backup_id": 21,
                "restore_id": 22,
                "restore_database": "foreign_database",
            },
        }
        path = self.root / "workloads.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(live_harness.HarnessError):
            harness._load_workload_manifest(str(path))

    def test_workload_manifest_rejects_retired_loose_path(self):
        harness = self.harness()
        names = harness._workload_names()
        target = (
            "bs_restore_45c7b8c781e6_"
            f"{names['database']}_"
            + live_harness.hashlib.sha256(names["database"].encode()).hexdigest()[:12]
        )[:63]
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "website": {
                "node_id": 10,
                "backup_id": 11,
                "restore_id": 9,
                "restore_path": names["base"],
            },
            "postgresql": {
                "node_id": 20,
                "backup_id": 21,
                "restore_id": 22,
                "restore_database": target,
            },
        }
        path = self.root / "durable-workloads.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            live_harness.HarnessError, r"complete new generation directory"
        ):
            harness._load_workload_manifest(str(path))

    def test_workload_manifest_rejects_escaped_or_ambiguous_durable_paths(self):
        harness = self.harness()
        names = harness._workload_names()
        for value in (
            f"{names['base']}/../foreign",
            f"{names['base']}//website",
            f"{names['base']}/./website",
            f"{names['base']}\\website",
            "/srv/backupsheep-e2e/foreign-run",
        ):
            with self.subTest(value=value), self.assertRaises(live_harness.HarnessError):
                harness._owned_website_restore_path(value)
        self.assertEqual(
            harness._owned_website_restore_path(f"{names['base']}/website"),
            f"{names['base']}/website",
        )

    def test_website_evidence_rejects_remote_symlink_ambiguity(self):
        harness = self.harness()
        root = harness._workload_names()["base"]
        with mock.patch.object(
            harness,
            "_ssh_run",
            return_value=json.dumps(
                {"realpath": "/srv/foreign", "symlinks": [root]}
            ),
        ) as run, self.assertRaises(live_harness.HarnessError):
            harness._website_evidence(mock.Mock(), root, {"files": {}})
        self.assertEqual(run.call_count, 1)

    def test_workload_manifest_rejects_escaped_or_foreign_database_target(self):
        harness = self.harness()
        names = harness._workload_names()
        base = {
            "schema": 1,
            "run_id": self.run_id,
            "website": {
                "node_id": 10,
                "backup_id": 11,
                "restore_id": 12,
                "restore_path": names["base"],
            },
            "postgresql": {
                "node_id": 20,
                "backup_id": 21,
                "restore_id": 22,
                "restore_database": "",
            },
        }
        for target in ("foreign_database", "bad-name", "../escape", names["database"]):
            manifest = json.loads(json.dumps(base))
            manifest["postgresql"]["restore_database"] = target
            path = self.root / f"invalid-database-{len(target)}.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.subTest(target=target), self.assertRaises(live_harness.HarnessError):
                harness._load_workload_manifest(str(path))

    def _durable_website_rows(self, *, target=None):
        target = target or f"/srv/backupsheep-e2e/{self.run_id}"
        backup_uuid = uuid.UUID("11111111-1111-4111-8111-111111111111")
        correlation = uuid.UUID("22222222-2222-4222-8222-222222222222")
        source_digest = "a" * 64
        fingerprint = live_harness.hashlib.sha256(
            f"{backup_uuid}|{source_digest}".encode()
        ).hexdigest()
        file_row = {"path": "index.html", "bytes": 12, "sha256": "b" * 64}
        parent, basename = target.rsplit("/", 1)
        stage_root = (
            f"{parent}/.backupsheep_restore_"
            f"{str(correlation).replace('-', '')[:16]}_{fingerprint[:16]}"
        )
        website = SimpleNamespace(
            all_paths=False,
            paths=[{"name": target, "path": target, "type": "directory"}],
        )
        backup = SimpleNamespace(uuid=backup_uuid, website=website)
        restore = SimpleNamespace(
            pk=9,
            correlation_id=correlation,
            execution_phase="complete",
            progress_completed=1,
            progress_total=1,
            progress_unit="paths",
            execution_metadata={
                "source_manifest": {
                    f"directory:{target}": {
                        "path": target,
                        "type": "directory",
                        "source_digest": source_digest,
                        "files": [file_row],
                    }
                },
                "source_states": {
                    fingerprint: {
                        "path": target,
                        "target_path": target,
                        "type": "directory",
                        "source_digest": source_digest,
                        "status": "complete",
                        "files": {
                            "index.html": {
                                "bytes": 12,
                                "sha256": "b" * 64,
                                "status": "complete",
                            }
                        },
                        "stage_root": stage_root,
                        "payload": f"{stage_root}/payload",
                        "old": (
                            f"{parent}/.{basename}.backupsheep_previous_"
                            f"{str(correlation).replace('-', '')[:16]}_{fingerprint[:16]}"
                        ),
                    }
                },
                "completed_sources": [fingerprint],
            },
        )
        return backup, restore, target

    def test_exporter_uses_exact_completed_in_place_website_target(self):
        backup, restore, target = self._durable_website_rows()
        self.assertEqual(
            upcloud_manifest_export._durable_website_restore_target(
                restore, backup=backup, run_id=self.run_id
            ),
            target,
        )

    def test_exporter_rejects_ambiguous_or_escaped_website_restore_evidence(self):
        backup, restore, _target = self._durable_website_rows()
        fingerprint, state = next(iter(restore.execution_metadata["source_states"].items()))
        restore.execution_metadata["source_states"]["c" * 64] = dict(state)
        with self.assertRaises(upcloud_manifest_export.UpCloudManifestExportError):
            upcloud_manifest_export._durable_website_restore_target(
                restore, backup=backup, run_id=self.run_id
            )
        escaped_backup, escaped_restore, _target = self._durable_website_rows(
            target=f"/srv/backupsheep-e2e/{self.run_id}/../foreign"
        )
        with self.assertRaises(upcloud_manifest_export.UpCloudManifestExportError):
            upcloud_manifest_export._durable_website_restore_target(
                escaped_restore, backup=escaped_backup, run_id=self.run_id
            )

    def _durable_database_rows(self):
        source = "bs_e2e_50d32a3bb404"
        target = "bs_restore_45c7b8c781e6_bs_e2e_50d32a3bb404_b51c2326c3b4"
        backup_uuid = uuid.UUID("33333333-3333-4333-8333-333333333333")
        mapping = {source: target}
        backup = SimpleNamespace(
            uuid=backup_uuid,
            database=SimpleNamespace(all_databases=False, databases=[source]),
        )
        restore = SimpleNamespace(
            pk=22,
            correlation_id=uuid.UUID("45c7b8c7-81e6-4444-8444-444444444444"),
            params={
                "mode": "fork",
                "target_mapping": mapping,
                "mapping_locked": True,
                "source_backup_uuid": str(backup_uuid),
            },
            execution_metadata={
                "source_to_target": mapping,
                "mapping_locked": True,
                "target_checkpoints": {
                    target: {
                        "source": source,
                        "source_digest": "d" * 64,
                        "status": "complete",
                    }
                },
            },
            execution_phase="complete",
            progress_completed=1,
            progress_total=1,
            progress_unit="databases",
        )
        return backup, restore, source, target

    def test_exporter_accepts_native_postgresql_fork_target_mapping(self):
        backup, restore, _source, target = self._durable_database_rows()
        self.assertEqual(
            upcloud_manifest_export._durable_database_restore_target(
                restore, backup=backup
            ),
            target,
        )

    def test_exporter_rejects_foreign_or_escaped_database_mapping(self):
        for kind in ("foreign", "escaped"):
            backup, restore, source, target = self._durable_database_rows()
            if kind == "foreign":
                restore.params["target_mapping"] = {"foreign_database": target}
            else:
                restore.params["target_mapping"] = {source: "bad-name"}
            with self.subTest(kind=kind), self.assertRaises(
                upcloud_manifest_export.UpCloudManifestExportError
            ):
                upcloud_manifest_export._durable_database_restore_target(
                    restore, backup=backup
                )

    def test_guest_restore_evidence_binds_interface_route_boot_and_reachability(self):
        harness = self.harness()
        server = {
            "ip_addresses": {
                "ip_address": [
                    {
                        "access": "public",
                        "family": "IPv4",
                        "address": "203.0.113.8",
                    }
                ]
            }
        }
        outputs = [
            json.dumps(
                [
                    {
                        "ifname": "ens3",
                        "operstate": "UP",
                        "addr_info": [
                            {
                                "family": "inet",
                                "scope": "global",
                                "local": "203.0.113.8",
                            }
                        ],
                    }
                ]
            ),
            json.dumps([{"dst": "default", "dev": "ens3", "gateway": "203.0.113.1"}]),
            "11111111-1111-4111-8111-111111111111|42",
            "reachable",
        ]
        with mock.patch.object(harness, "_ssh_run", side_effect=outputs) as run:
            evidence = harness._guest_restore_evidence(mock.Mock(), server)
        self.assertEqual(evidence["interface"], "ens3")
        self.assertEqual(evidence["default_route_interface"], "ens3")
        self.assertEqual(evidence["uptime_seconds"], 42)
        self.assertNotIn("203.0.113.8", json.dumps(evidence))
        self.assertEqual(run.call_count, 4)

    def test_guest_restore_evidence_rejects_default_route_on_other_interface(self):
        harness = self.harness()
        server = {
            "ip_addresses": {
                "ip_address": [
                    {"access": "public", "family": "IPv4", "address": "203.0.113.8"}
                ]
            }
        }
        with mock.patch.object(
            harness,
            "_ssh_run",
            side_effect=[
                json.dumps(
                    [
                        {
                            "ifname": "ens3",
                            "operstate": "UP",
                            "addr_info": [
                                {"family": "inet", "scope": "global", "local": "203.0.113.8"}
                            ],
                        }
                    ]
                ),
                json.dumps([{"dst": "default", "dev": "ens4"}]),
            ],
        ), self.assertRaises(live_harness.HarnessError):
            harness._guest_restore_evidence(mock.Mock(), server)

    def test_soft_stop_lost_response_reconciles_without_second_post(self):
        harness = self.harness(cleanup=True)
        entry = harness.ledger.record(
            kind="ui_server_restore_server",
            resource_id=SOURCE_SERVER_ID,
            name="restored",
            ownership={"account": self.account, "run_id": self.run_id},
            source_witness="witness",
        )
        intent_key = f"cleanup:compute-stop:{SOURCE_SERVER_ID}"
        harness.intents.put(
            intent_key,
            {
                "marker": self.run_id,
                "kind": entry["kind"],
                "name": "restored",
                "operation": "stop",
                "resource_id": SOURCE_SERVER_ID,
            },
        )
        harness.intents.update(intent_key, request_boundary_crossed=True)
        with mock.patch.object(
            harness,
            "_server_read",
            side_effect=[{"uuid": SOURCE_SERVER_ID, "state": "maintenance"}, {"uuid": SOURCE_SERVER_ID, "state": "stopped"}],
        ), mock.patch.object(harness, "_control_mutation") as mutate:
            result = harness._stop_server_for_cleanup(
                entry, {"uuid": SOURCE_SERVER_ID, "state": "started"}
            )
        self.assertEqual(result["state"], "stopped")
        mutate.assert_not_called()

    def test_crossed_delete_intent_adopts_absence_without_replay(self):
        harness = self.harness(cleanup=True)
        entry = harness.ledger.record(
            kind="ui_volume_restore",
            resource_id=RESTORE_VOLUME_ID,
            name="restore",
            ownership={"account": self.account, "run_id": self.run_id},
            source_witness="witness",
        )
        key = "cleanup:test-delete"
        harness.intents.put(
            key,
            {"marker": self.run_id, "kind": entry["kind"], "name": "restore", "operation": "delete"},
        )
        harness.intents.update(key, request_boundary_crossed=True)
        with mock.patch.object(harness, "_control_mutation") as mutate:
            harness._control_delete(
                intent_key=key,
                kind=entry["kind"],
                entry=entry,
                path="/storage/exact",
                verify_absent=lambda: True,
            )
        mutate.assert_not_called()
        self.assertEqual(harness.ledger.get(entry["kind"], entry["resource_id"])["cleanup_state"], "deleted")

    def test_manifest_export_writes_atomic_mode_0600_files(self):
        output = self.root / "external"
        parent_mode = self.root.stat().st_mode & 0o777
        payloads = self.manifest_payloads()
        with mock.patch.object(
            upcloud_manifest_export,
            "collect_upcloud_manifest_payloads",
            return_value=payloads,
        ):
            result = upcloud_manifest_export.export_upcloud_manifests(
                output_dir=output, run_id=self.run_id
            )
        self.assertEqual(result["status"], "exported")
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.root.stat().st_mode & 0o777, parent_mode)
        self.assertEqual(Path(result["generation_dir"]), output)
        marker_path = Path(result["generation_marker"])
        self.assertEqual(marker_path.stat().st_mode & 0o777, 0o600)
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        self.assertEqual(marker["schema"], 1)
        self.assertEqual(marker["provider"], "upcloud")
        self.assertEqual(marker["run_id"], self.run_id)
        self.assertEqual(set(marker["manifests"]), {"compute", "workload", "object"})
        for path in result["files"].values():
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        for kind, path in result["files"].items():
            payload = Path(path).read_bytes()
            self.assertEqual(
                marker["manifests"][kind]["sha256"],
                upcloud_manifest_export.hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(
                marker["manifests"][kind]["byte_count"], len(payload)
            )

    def test_manifest_export_rejects_existing_destination_without_chmod_or_overwrite(self):
        payloads = self.manifest_payloads()
        existing_directory = self.root / "existing-generation"
        existing_directory.mkdir(mode=0o755)
        canary = existing_directory / "canary.txt"
        canary.write_bytes(b"DO-NOT-OVERWRITE")
        directory_mode = existing_directory.stat().st_mode & 0o777
        existing_file = self.root / "existing-file"
        existing_file.write_bytes(b"DO-NOT-OVERWRITE-FILE")
        file_mode = existing_file.stat().st_mode & 0o777

        with mock.patch.object(
            upcloud_manifest_export,
            "collect_upcloud_manifest_payloads",
            return_value=payloads,
        ) as collect:
            for destination in (existing_directory, existing_file):
                with self.subTest(destination=destination), self.assertRaisesRegex(
                    upcloud_manifest_export.UpCloudManifestExportError,
                    r"destination already exists",
                ):
                    upcloud_manifest_export.export_upcloud_manifests(
                        output_dir=destination, run_id=self.run_id
                    )
        collect.assert_not_called()
        self.assertEqual(canary.read_bytes(), b"DO-NOT-OVERWRITE")
        self.assertEqual(existing_directory.stat().st_mode & 0o777, directory_mode)
        self.assertEqual(existing_file.read_bytes(), b"DO-NOT-OVERWRITE-FILE")
        self.assertEqual(existing_file.stat().st_mode & 0o777, file_mode)

    def test_manifest_export_failure_before_publish_leaves_no_generation(self):
        output = self.root / "failed-generation"
        payloads = self.manifest_payloads()
        original = upcloud_manifest_export._write_exclusive_file

        def fail_on_workload(path, payload):
            if path.name == upcloud_manifest_export.MANIFEST_FILENAMES["workload"]:
                raise OSError("simulated crash before publish")
            return original(path, payload)

        with mock.patch.object(
            upcloud_manifest_export,
            "collect_upcloud_manifest_payloads",
            return_value=payloads,
        ), mock.patch.object(
            upcloud_manifest_export,
            "_write_exclusive_file",
            side_effect=fail_on_workload,
        ), self.assertRaises(OSError):
            upcloud_manifest_export.export_upcloud_manifests(
                output_dir=output, run_id=self.run_id
            )
        self.assertFalse(output.exists())
        self.assertEqual(
            list(self.root.glob(".failed-generation.upcloud-staging-*")), []
        )

    def test_manifest_export_exclusive_publish_never_replaces_racing_destination(self):
        output = self.root / "racing-generation"
        payloads = self.manifest_payloads()
        original = upcloud_manifest_export._rename_directory_exclusive

        def create_racing_destination(source, destination):
            destination.mkdir(mode=0o755)
            (destination / "canary.txt").write_bytes(b"RACING-OWNER")
            return original(source, destination)

        with mock.patch.object(
            upcloud_manifest_export,
            "collect_upcloud_manifest_payloads",
            return_value=payloads,
        ), mock.patch.object(
            upcloud_manifest_export,
            "_rename_directory_exclusive",
            side_effect=create_racing_destination,
        ), self.assertRaisesRegex(
            upcloud_manifest_export.UpCloudManifestExportError,
            r"destination already exists",
        ):
            upcloud_manifest_export.export_upcloud_manifests(
                output_dir=output, run_id=self.run_id
            )
        self.assertEqual((output / "canary.txt").read_bytes(), b"RACING-OWNER")
        self.assertEqual(
            list(self.root.glob(".racing-generation.upcloud-staging-*")), []
        )

    def test_manifest_builder_rejects_duplicate_verified_artifacts(self):
        artifacts = mock.Mock()
        queryset = mock.MagicMock()
        queryset.__getitem__.return_value = [
            mock.Mock(),
            mock.Mock(),
        ]
        artifacts.filter.return_value.order_by.return_value = queryset
        backup = mock.Mock(artifact_records=artifacts)
        with self.assertRaises(upcloud_manifest_export.UpCloudManifestExportError):
            upcloud_manifest_export._artifact_for(
                backup,
                storage_id=1,
                storage_point=mock.Mock(),
                label="website",
            )
