"""Static and unit safety tests for the disposable Hetzner UI fixture."""

import ast
import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

import requests

from scripts.hetzner_web_database_fixture_e2e import (
    AmbiguousMutation,
    PASSWORD_ENV_NAMES,
    HetznerFixtureHarness,
    _fixture_inputs_from_environment,
    _bootstrap_script,
    build_cloud_init,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "hetzner_web_database_fixture_e2e.py"
RUN_ID = "bs-e2e-20260810-ab12cd34"
PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB "
    "fixture"
)


class HetznerWebDatabaseFixtureScriptSafetyTests(TestCase):
    def setUp(self):
        super().setUp()
        self.source = SCRIPT.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.env = {
            "BACKUPSHEEP_E2E_RUN_ID": RUN_ID,
            "BACKUPSHEEP_E2E_LEDGER_PATH": "/tmp/backupsheep-fixture-ledger.json",
            "BACKUPSHEEP_E2E_APPLY": "YES",
            "HETZNER_E2E_SSH_PUBLIC_KEY": PUBLIC_KEY,
            "HETZNER_E2E_MARIADB_DATABASE": "bs_mariadb",
            "HETZNER_E2E_MARIADB_USERNAME": "bs_maria",
            "HETZNER_E2E_MARIADB_PASSWORD": "maria-secret-unsafe-to-print",
            "HETZNER_E2E_POSTGRES_DATABASE": "bs_postgres",
            "HETZNER_E2E_POSTGRES_USERNAME": "bs_postgres",
            "HETZNER_E2E_POSTGRES_PASSWORD": "postgres-secret-unsafe-to-print",
        }

    def _harness(self, path, *, cleanup=False):
        environment = dict(self.env)
        environment["BACKUPSHEEP_E2E_LEDGER_PATH"] = str(path)
        if cleanup:
            environment["BACKUPSHEEP_E2E_CLEANUP"] = "YES"
        with mock.patch.dict(os.environ, environment, clear=False):
            return HetznerFixtureHarness("token-that-must-never-be-reported")

    def test_explicit_gates_and_safe_defaults_are_present(self):
        self.assertIn('os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"', self.source)
        self.assertIn('os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"', self.source)
        self.assertIn("if self.cleanup_requested and not self.apply:", self.source)
        self.assertIn('os.environ.get("HETZNER_E2E_SERVER_TYPE", "cx23")', self.source)
        self.assertIn('os.environ.get("HETZNER_E2E_LOCATION", "fsn1")', self.source)
        self.assertIn('os.environ.get("HETZNER_E2E_IMAGE", "ubuntu-24.04")', self.source)
        self.assertIn(
            'require_run_id(os.environ.get("BACKUPSHEEP_E2E_RUN_ID"))',
            self.source,
        )
        self.assertIn("BACKUPSHEEP_E2E_LEDGER_PATH is required", self.source)

    def test_only_ssh_keys_and_servers_are_provider_resources(self):
        self.assertNotIn("/volumes", self.source)
        self.assertNotIn("delete_volume", self.source)
        self.assertNotIn("create_volume", self.source)
        self.assertIn('path = f"/ssh_keys/{identifier}"', self.source)
        self.assertIn('path = f"/servers/{identifier}"', self.source)
        cleanup_source = self.source.split("    def cleanup(self):", 1)[1]
        self.assertNotIn("inventory match", cleanup_source)
        self.assertIn("self.ledger.entries()", cleanup_source)

    def test_bounded_http_and_no_blind_mutation_retry(self):
        self.assertIn("timeout=self.http_timeout", self.source)
        self.assertIn("class AmbiguousMutation", self.source)
        self.assertIn("no mutation retry was issued", self.source)
        self.assertNotIn("HTTPAdapter", self.source)
        self.assertNotIn("Retry(", self.source)
        self.assertIn("mutation=True", self.source)

    def test_cloud_init_has_deterministic_fixture_and_no_plaintext_passwords(self):
        with mock.patch.dict(os.environ, self.env, clear=False):
            fixture_inputs = _fixture_inputs_from_environment()
        cloud_init = build_cloud_init(RUN_ID, PUBLIC_KEY, fixture_inputs)
        bootstrap = _bootstrap_script()
        fixture_source = cloud_init + bootstrap

        self.assertIn("EXECUTE 'CREATE ROLE %s LOGIN';", bootstrap)
        self.assertNotIn("LOGIN PASSWORD ' ||", bootstrap)
        self.assertIn('SSH_USER = "backupsheep"', bootstrap)
        self.assertIn("ALTER TABLE customers OWNER TO %s;", bootstrap)
        bootstrap_tree = ast.parse(bootstrap)
        uppercase_loads = {
            node.id
            for node in ast.walk(bootstrap_tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id.isupper()
        }
        assigned_names = {
            node.id
            for node in ast.walk(bootstrap_tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }
        self.assertEqual(uppercase_loads - assigned_names, set())
        for marker in (
            "nginx",
            "mariadb-server",
            "postgresql",
            "backupsheep",
            "127.0.0.1",
            "3306",
            "5432",
            "fixture_metadata",
            "customers",
            "orders",
            "backupsheep-e2e-readiness.json",
        ):
            self.assertIn(marker, fixture_source)
        self.assertNotIn(self.env["HETZNER_E2E_MARIADB_PASSWORD"], cloud_init)
        self.assertNotIn(self.env["HETZNER_E2E_POSTGRES_PASSWORD"], cloud_init)

    def test_passwords_are_not_reported_or_ledgered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            harness = self._harness(path)
            harness.report["tests"]["synthetic"] = {"status": "PASS"}
            harness.ledger.record(
                kind="ssh_key",
                resource_id="1001",
                name=harness.ssh_key_name,
                ownership={
                    "labels": harness.labels_for_key,
                    "public_key_sha256": "x",
                },
                source_witness="public-key-sha256:x",
            )
            serialized_report = json.dumps(harness.report, sort_keys=True)
            serialized_ledger = path.read_text(encoding="utf-8")
            for secret_name in PASSWORD_ENV_NAMES:
                self.assertNotIn(self.env[secret_name], serialized_report)
                self.assertNotIn(self.env[secret_name], serialized_ledger)
            self.assertNotIn("token-that-must-never-be-reported", serialized_report)
            self.assertNotIn("token-that-must-never-be-reported", serialized_ledger)
            self.assertNotIn('"password"', serialized_report)
            self.assertNotIn('"password"', serialized_ledger)

    def test_crash_safe_cleanup_adopts_only_durable_exact_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            harness = self._harness(path, cleanup=True)
            key_id = "1001"
            server_id = "2002"
            public_key_sha256 = hashlib.sha256(PUBLIC_KEY.encode()).hexdigest()
            key_ownership = {
                "labels": harness.labels_for_key,
                "public_key_sha256": public_key_sha256,
            }
            server_ownership = {"labels": harness.labels_for_server(key_id)}
            harness.ledger.record(
                kind="ssh_key",
                resource_id=key_id,
                name=harness.ssh_key_name,
                ownership=key_ownership,
                source_witness="public-key-sha256:" + public_key_sha256,
            )
            harness.ledger.record(
                kind="server",
                resource_id=server_id,
                name=harness.server_name,
                ownership=server_ownership,
                source_witness="ssh-key:" + key_id,
            )
            restarted = self._harness(path, cleanup=True)
            self.assertEqual(
                restarted.active,
                {"ssh_key": key_id, "server": server_id},
            )
            resources = {
                ("ssh_key", key_id): {
                    "id": int(key_id),
                    "name": restarted.ssh_key_name,
                    "labels": restarted.labels_for_key,
                    "public_key": PUBLIC_KEY,
                },
                ("server", server_id): {
                    "id": int(server_id),
                    "name": restarted.server_name,
                    "labels": restarted.labels_for_server(key_id),
                },
            }
            calls = []

            def fake_get(kind, identifier):
                return resources.get((kind, str(identifier)))

            def fake_request(method, path_value, **kwargs):
                calls.append((method, path_value))
                self.assertTrue(kwargs.get("mutation"))
                if path_value == f"/servers/{server_id}":
                    resources.pop(("server", server_id), None)
                elif path_value == f"/ssh_keys/{key_id}":
                    resources.pop(("ssh_key", key_id), None)
                return {}

            with mock.patch.object(
                restarted,
                "_get_resource_once",
                side_effect=fake_get,
            ), mock.patch.object(
                restarted,
                "request",
                side_effect=fake_request,
            ):
                restarted._wait_absent = (
                    lambda kind, identifier: fake_get(kind, identifier) is None
                )
                restarted.cleanup()
            self.assertEqual(
                calls,
                [
                    ("DELETE", f"/servers/{server_id}"),
                    ("DELETE", f"/ssh_keys/{key_id}"),
                ],
            )
            self.assertEqual(restarted.report["cleanup"]["status"], "PASS")
            self.assertEqual(
                restarted.ledger.get("server", server_id)["cleanup_state"],
                "deleted",
            )
            self.assertEqual(
                restarted.ledger.get("ssh_key", key_id)["cleanup_state"],
                "deleted",
            )

    def test_cleanup_never_deletes_unledgered_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = self._harness(Path(directory) / "ledger.json", cleanup=True)
            calls = []
            with mock.patch.object(
                harness,
                "request",
                side_effect=lambda *args, **kwargs: calls.append(args),
            ):
                harness.cleanup()
            self.assertEqual(calls, [])
            self.assertEqual(harness.report["cleanup"]["considered"], [])

    def test_ambiguous_mutation_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = self._harness(Path(directory) / "ledger.json")
            calls = []

            def lost_response(*args, **kwargs):
                calls.append((args, kwargs))
                raise requests.ConnectionError("connection reset")

            with mock.patch.object(
                harness.session,
                "request",
                side_effect=lost_response,
            ):
                with self.assertRaises(AmbiguousMutation):
                    harness.request(
                        "POST",
                        "/ssh_keys",
                        mutation=True,
                        json={"name": "owned"},
                    )
            self.assertEqual(len(calls), 1)

    def test_ownership_mismatch_marks_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            harness = self._harness(path, cleanup=True)
            public_key_sha256 = hashlib.sha256(PUBLIC_KEY.encode()).hexdigest()
            harness.ledger.record(
                kind="ssh_key",
                resource_id="1001",
                name=harness.ssh_key_name,
                ownership={
                    "labels": harness.labels_for_key,
                    "public_key_sha256": public_key_sha256,
                },
                source_witness="public-key-sha256:" + public_key_sha256,
            )
            harness.ledger.record(
                kind="server",
                resource_id="2002",
                name=harness.server_name,
                ownership={"labels": harness.labels_for_server("1001")},
                source_witness="ssh-key:1001",
            )
            restarted = self._harness(path, cleanup=True)
            with mock.patch.object(
                restarted,
                "_get_resource_once",
                return_value={
                    "id": 2002,
                    "name": restarted.server_name,
                    "labels": restarted.labels_for_server("9999"),
                },
            ), mock.patch.object(restarted, "request") as request:
                restarted.cleanup()
            request.assert_not_called()
            self.assertEqual(restarted.report["cleanup"]["status"], "MANUAL_REVIEW")
