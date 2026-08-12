"""Offline safety tests for UpCloud compute/workload live UI support."""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from scripts import upcloud_live_ui_e2e as live_harness


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
        }
        data = {
            "storage": SOURCE_VOLUME_ID,
            "type": "disk",
            "address": "scsi:0:0",
            "boot_disk": "0",
        }
        server = {"storage_devices": {"storage_device": [boot, data]}}
        self.assertEqual(live_harness.UpCloudLiveHarness._boot_device(server), boot)
        with self.assertRaises(live_harness.HarnessError):
            live_harness.UpCloudLiveHarness._boot_device(
                {
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
                "backup_id": "website-backup-1",
                "restore_id": "website-restore-1",
                "restore_path": "/tmp/foreign",
            },
            "postgresql": {
                "backup_id": "database-backup-1",
                "restore_id": "database-restore-1",
                "restore_database": "foreign_database",
            },
        }
        path = self.root / "workloads.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(live_harness.HarnessError):
            harness._load_workload_manifest(str(path))
