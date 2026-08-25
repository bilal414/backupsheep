"""Offline safety tests for the Oracle live UI support harness."""

import tempfile
import os
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import oci
from django.test import SimpleTestCase

from scripts.oracle_live_ui_e2e import (
    BACKUP_KIND_TAG,
    BACKUP_MARKER_TAG,
    BACKUP_REQUEST_TAG,
    BACKUP_SOURCE_TAG,
    E2E_KIND_TAG,
    E2E_OWNED_TAG,
    E2E_RUN_TAG,
    HarnessConfig,
    HarnessError,
    OracleLiveUIHarness,
    RESTORE_MARKER_TAG,
    RESTORE_ORIGIN_TAG,
    RESTORE_SOURCE_TAG,
    RuntimeScope,
    SOURCE_BLOCK_DEVICE,
    main,
)


def response(data=None, *, status=200, next_page=None):
    return SimpleNamespace(
        data=data,
        status=status,
        opc_next_page=next_page,
        headers={},
    )


class OracleLiveUIHarnessSafetyTests(SimpleTestCase):
    compartment_id = "ocid1.compartment.oc1..backupsheeptest"
    tenancy_id = "ocid1.tenancy.oc1..backupsheeptest"
    availability_domain = "AD-1"
    run_id = "bs-e2e-oracle-20260812-a7c42f91"
    workload_run_id = "bs-e2e-upcloud-20260812-74c9f2a1"
    workload_server_id = "00e6027e-d4e5-4779-bc3f-18080a4ee0d3"
    workload_database = "bs_e2e_50d32a3bb404"
    workload_restore_database = (
        "bs_restore_45c7b8c781e6_bs_e2e_50d32a3bb404_b51c2326c3b4"
    )
    workload_key_bytes = b"protected-upcloud-private-key-fixture\n"
    workload_known_hosts_bytes = b"152.44.38.25 ssh-ed25519 pinned-host-key-fixture\n"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self, *, apply=False, cleanup=False):
        ui_ledger = self.root / "oracle-ledger.json"
        network_ledger = self.root / "oracle-network-ledger.json"
        runtime_payload = {
            "schema": 1,
            "run_id": self.run_id,
            "profile": "BACKUPSHEEP_E2E",
            "tenancy_id": self.tenancy_id,
            "compartment_id": self.compartment_id,
            "subnet_id": "ocid1.subnet.oc1.iad.testsubnet",
            "availability_domain": self.availability_domain,
            "region": "us-chicago-1",
            "ui_ledger_path": str(ui_ledger),
            "network_ledger_path": str(network_ledger),
        }
        runtime = RuntimeScope(
            run_id=self.run_id,
            profile="BACKUPSHEEP_E2E",
            tenancy_id=self.tenancy_id,
            compartment_id=self.compartment_id,
            subnet_id="ocid1.subnet.oc1.iad.testsubnet",
            availability_domain=self.availability_domain,
            region="us-chicago-1",
            ui_ledger_path=ui_ledger,
            network_ledger_path=network_ledger,
            source_path=self.root / "runtime-scope.json",
            digest=hashlib.sha256(
                json.dumps(runtime_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        return HarnessConfig(
            run_id=self.run_id,
            ledger_path=ui_ledger,
            profile="BACKUPSHEEP_E2E",
            config_file=self.root / "oci-config",
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            apply=apply,
            cleanup=cleanup,
            poll_seconds=2,
            timeout_seconds=60,
            runtime_scope=runtime,
        )

    @staticmethod
    def clients():
        return {
            "_config": {
                "tenancy": OracleLiveUIHarnessSafetyTests.tenancy_id,
                "region": "us-chicago-1",
            },
            "identity": mock.MagicMock(),
            "compute": mock.MagicMock(),
            "block": mock.MagicMock(),
            "network": mock.MagicMock(),
            "object": mock.MagicMock(),
        }

    def harness(
        self,
        *,
        apply=False,
        cleanup=False,
        clients=None,
        environment=None,
        read_only=False,
    ):
        values = {
            "ORACLE_E2E_UI_CLEANUP_RECEIPT": str(self.root / "ui-cleanup-receipt.json"),
            "ORACLE_E2E_SUBNET_OCID": "ocid1.subnet.oc1.iad.testsubnet",
            "ORACLE_E2E_IMAGE_OCID": "ocid1.image.oc1.iad.testimage",
            "ORACLE_E2E_SHAPE": "VM.Standard.E2.1",
            "ORACLE_E2E_ALLOWED_TENANCY_OCID": self.tenancy_id,
        }
        values.update(environment or {})
        return OracleLiveUIHarness(
            self.config(apply=apply, cleanup=cleanup),
            clients=clients or self.clients(),
            environment=values,
            sleep=lambda _seconds: None,
            read_only=read_only,
        )

    def storage_secret(self, harness, *, bucket="bucket", user_ocid=None):
        user_ocid = user_ocid or "ocid1.user.oc1..backupsheeptest"
        return {
            "access_key_id": "A" * 40,
            "secret_access_key": "credential-canary",
            "bucket": bucket,
            "namespace": "namespace",
            "region": "us-chicago-1",
            "endpoint": "https://namespace.compat.objectstorage.us-chicago-1.oraclecloud.com",
            "prefix": f"{self.run_id}/",
            "user_ocid": user_ocid,
            "tenancy_ocid": self.tenancy_id,
            "compartment_ocid": self.compartment_id,
        }

    def test_ssh_requires_independent_exact_host_key_pin_and_never_uses_tofu(self):
        host = "198.51.100.25"
        host_key = mock.Mock()
        host_key.asbytes.return_value = b"oracle-exact-host-key"
        expected = OracleLiveUIHarness._ssh_key_fingerprint(host_key)
        environment = {
            "ORACLE_E2E_SOURCE_SSH_HOST": host,
            "ORACLE_E2E_SOURCE_SSH_HOST_KEY_SHA256": expected,
            "ORACLE_E2E_SSH_USER": "opc",
        }
        harness = self.harness(apply=True, environment=environment)
        client = mock.Mock()
        client.get_transport.return_value.get_remote_server_key.return_value = host_key
        with (
            mock.patch.object(
                harness,
                "_ensure_ssh_key",
                return_value=(self.root / "oracle-key", "ssh-rsa TEST"),
            ),
            mock.patch("paramiko.SSHClient", return_value=client),
            mock.patch(
                "paramiko.RSAKey.from_private_key_file",
                return_value=mock.sentinel.private_key,
            ),
        ):
            connected = harness._ssh_client(
                {"public_ip": host},
                host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
            )

        self.assertIs(connected, client)
        policy = client.set_missing_host_key_policy.call_args.args[0]
        self.assertEqual(policy.expected_fingerprint, expected)
        policy.missing_host_key(client, host, host_key)
        client.load_host_keys.assert_not_called()
        client.save_host_keys.assert_not_called()

        wrong_key = mock.Mock()
        wrong_key.asbytes.return_value = b"oracle-attacker-host-key"
        with self.assertRaisesRegex(HarnessError, "exact pin"):
            policy.missing_host_key(client, host, wrong_key)

    def test_ssh_missing_host_key_pin_fails_before_paramiko_client(self):
        host = "198.51.100.25"
        harness = self.harness(
            apply=True,
            environment={
                "ORACLE_E2E_SOURCE_SSH_HOST": host,
                "ORACLE_E2E_SSH_USER": "opc",
            },
        )
        with (
            mock.patch.object(
                harness,
                "_ensure_ssh_key",
                return_value=(self.root / "oracle-key", "ssh-rsa TEST"),
            ),
            mock.patch("paramiko.SSHClient") as ssh_client,
            self.assertRaisesRegex(
                HarnessError,
                "ORACLE_E2E_SOURCE_SSH_HOST_KEY_SHA256 is required",
            ),
        ):
            harness._ssh_client(
                {"public_ip": host},
                host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
            )
        ssh_client.assert_not_called()

    def establish_storage_scope(self, harness, *, bucket_name="bucket"):
        bucket = SimpleNamespace(
            id="ocid1.bucket.oc1.iad.backupsheeptest",
            name=bucket_name,
            compartment_id=self.compartment_id,
            lifecycle_state="ACTIVE",
            versioning="Enabled",
            freeform_tags=harness._storage_tags("object_bucket"),
        )
        user = self._iam_user(harness)
        harness._record_storage(
            "object_bucket",
            bucket,
            resource_id=bucket.id,
            name=bucket.name,
            compartment_id=self.compartment_id,
            tags=bucket.freeform_tags,
        )
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        customer_key = SimpleNamespace(
            id="A" * 40,
            display_name=harness.names["customer_secret_key"],
            user_id=user.id,
            lifecycle_state="ACTIVE",
        )
        harness._record_storage(
            "customer_secret_key",
            customer_key,
            resource_id=customer_key.id,
            name=customer_key.display_name,
            compartment_id="",
            relationships={"user_id": user.id},
        )
        scope = harness._storage_scope(
            bucket_name=bucket.name,
            namespace="namespace",
            region="us-chicago-1",
            user_ocid=user.id,
        )
        harness._persist_storage_scope(scope)
        return bucket, user, scope

    @staticmethod
    def request_token(marker):
        return "bs-" + hashlib.sha256(str(marker).encode("utf-8")).hexdigest()[:61]

    def valid_manifest(self):
        hashes = {
            "website": {
                "tree_sha256": "a" * 64,
                "file_count": 3,
                "byte_count": 4096,
                "mode_sha256": "b" * 64,
            },
            "database": {
                "schema_sha256": "4768a03a122f1e6f2fe7b2dd8a609174e0c9ccaa5391012d8472c4484b76df87",
                "table_count": 2,
                "row_count": 600,
                "data_sha256": "f8621cd4a65a00c394f8ead3e427e16859248450bc7cc23ebf529764c5934cb7",
            },
        }
        native = {}
        source_types = {
            "compute": "instance",
            "block": "volume",
            "boot": "bootvolume",
        }
        restore_types = source_types
        for index, kind in enumerate(("compute", "block", "boot"), start=1):
            backup_uuid = f"bs-bs-e2e-oracle-{kind}-n29-b{index + 3}"
            restore_marker = f"bs-bs-e2e-oracle-{kind}-restore-r{index + 13}"
            native[kind] = {
                "source_ocid": f"ocid1.{source_types[kind]}.oc1.iad.source{kind}",
                "backup": {
                    "backup_row_id": index,
                    "backup_uuid": backup_uuid,
                    "ocid": f"ocid1.{('image' if kind == 'compute' else kind + 'backup')}.oc1.iad.backup{kind}",
                    "marker": backup_uuid,
                    "request_token": self.request_token(backup_uuid),
                },
                "restore": {
                    "restore_row_id": index + 10,
                    "ocid": f"ocid1.{restore_types[kind]}.oc1.iad.restore{kind}",
                    "name": f"{self.run_id}-{kind}-restore",
                    "marker": restore_marker,
                    "request_token": self.request_token(restore_marker),
                },
            }
        objects = []
        object_rows = {
            "website": {
                "backup_row_id": 11,
                "restore_row_id": 9,
                "marker": "bs-upcloud-website-fixture-n27-b11",
                "storage_point_id": 11,
                "sha256": "b314a0a5904870745888360bab2b2c65a9fb4519e7dcb02b2dfb231983ce1e19",
                "byte_count": 69165,
                "etag": "3ee4294c9255347ad26dcebc26631774",
                "version_id": "1786575272066",
            },
            "database": {
                "backup_row_id": 10,
                "restore_row_id": 16,
                "marker": "bs-upcloud-postgresql-fixtu-n28-b10",
                "storage_point_id": 12,
                "sha256": "b2a91db4540e66cca7db61d28723eb9ca0b9a05a28f6efc0fe31d72ae0aaa8bd",
                "byte_count": 5129,
                "etag": "2ea8fb94f064c943c0c0689f81e2fb96",
                "version_id": "1786575287925",
            },
        }
        for kind in ("website", "database"):
            row = object_rows[kind]
            objects.append(
                {
                    "kind": kind,
                    "backup_row_id": row["backup_row_id"],
                    "backup_uuid": row["marker"],
                    "storage_point_id": row["storage_point_id"],
                    "restore_row_id": row["restore_row_id"],
                    "key": f"{self.run_id}/{row['marker']}.zip",
                    "sha256": row["sha256"],
                    "byte_count": row["byte_count"],
                    "etag": row["etag"],
                    "version_id": row["version_id"],
                }
            )
        return {
            "schema": 3,
            "run_id": self.run_id,
            "profile": "BACKUPSHEEP_E2E",
            "tenancy_id": self.tenancy_id,
            "compartment_id": self.compartment_id,
            **native,
            "storage": {"objects": objects},
            "workload_guest_scope": {
                "provider": "upcloud",
                "run_id": self.workload_run_id,
                "durable_ledger_path": str(self.root / "upcloud-workload-ledger.json"),
                "durable_ledger_scope": "bilal414",
                "source_server_id": self.workload_server_id,
                "safe_root": f"/srv/backupsheep-e2e/{self.workload_run_id}",
                "website_source_root": (
                    f"/srv/backupsheep-e2e/{self.workload_run_id}/website"
                ),
                "source_database": self.workload_database,
                "ssh_host": "152.44.38.25",
                "ssh_port": 22,
                "ssh_user": "root",
                "ssh_private_key_path": str(self.root / "upcloud-workload-key"),
                "ssh_private_key_sha256": hashlib.sha256(
                    self.workload_key_bytes
                ).hexdigest(),
                "known_hosts_path": str(self.root / "upcloud-known-hosts"),
                "known_hosts_sha256": hashlib.sha256(
                    self.workload_known_hosts_bytes
                ).hexdigest(),
                "known_host_key_type": "ssh-ed25519",
                "known_host_fingerprint": "SHA256:" + "A" * 43,
            },
            "workloads": {
                "website": {
                    "backup_row_id": 11,
                    "restore_row_id": 9,
                    "restore_path": (
                        f"/srv/backupsheep-e2e/{self.workload_run_id}/restores/9"
                    ),
                    "row_witness": {
                        "node_row_id": 27,
                        "backup_row_id": 11,
                        "backup_status": "Complete",
                        "backup_marker": "bs-upcloud-website-fixture-n27-b11",
                        "restore_row_id": 9,
                        "restore_status": "Complete",
                        "restore_target": (
                            f"/srv/backupsheep-e2e/{self.workload_run_id}/restores/9"
                        ),
                    },
                    "source": hashes["website"],
                    "restored": hashes["website"],
                },
                "database": {
                    "backup_row_id": 10,
                    "restore_row_id": 16,
                    "restore_database": self.workload_restore_database,
                    "row_witness": {
                        "node_row_id": 28,
                        "backup_row_id": 10,
                        "backup_status": "Complete",
                        "backup_marker": "bs-upcloud-postgresql-fixtu-n28-b10",
                        "restore_row_id": 16,
                        "restore_status": "Complete",
                        "restore_target": self.workload_restore_database,
                    },
                    "source": hashes["database"],
                    "restored": hashes["database"],
                },
            },
        }

    def write_workload_scope_artifacts(self, manifest=None):
        manifest = manifest or self.valid_manifest()
        scope = manifest["workload_guest_scope"]
        ledger = {
            "schema": 1,
            "provider": "upcloud",
            "run_id": self.workload_run_id,
            "scope": "bilal414",
            "created_at": "2026-08-12T00:00:00+00:00",
            "resources": [
                {
                    "kind": "compute_workload_fixture",
                    "resource_id": self.workload_server_id,
                    "name": scope["safe_root"],
                    "ownership": {
                        "account": "bilal414",
                        "run_id": self.workload_run_id,
                        "server_id": self.workload_server_id,
                        "website_root": scope["website_source_root"],
                        "website": manifest["workloads"]["website"]["source"],
                        "database_name": self.workload_database,
                        "database": manifest["workloads"]["database"]["source"],
                        "firewall": {"status": "active"},
                        "runtime_path_sha256": "f" * 64,
                    },
                    "source_witness": self.workload_server_id,
                    "created_at": "2026-08-12T00:00:00+00:00",
                    "cleanup_state": "eligible",
                    "cleanup_error": "",
                }
            ],
        }
        artifacts = {
            Path(scope["durable_ledger_path"]): (
                json.dumps(ledger, sort_keys=True) + "\n"
            ).encode(),
            Path(scope["ssh_private_key_path"]): self.workload_key_bytes,
            Path(scope["known_hosts_path"]): self.workload_known_hosts_bytes,
        }
        for path, payload in artifacts.items():
            path.write_bytes(payload)
            os.chmod(path, 0o600)
        return manifest

    def test_plan_is_inert_and_does_not_load_oci_profile_or_clients(self):
        harness = self.harness()
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            result = harness.plan()
        self.assertFalse(result["live_calls"])
        self.assertEqual(result["compartment_id"], self.compartment_id)

    def test_cli_plan_short_circuits_before_config_profile_ledger_or_harness(self):
        output = StringIO()
        with (
            mock.patch.object(
                HarnessConfig,
                "from_environment",
                side_effect=AssertionError("config must not load"),
            ),
            mock.patch.object(
                OracleLiveUIHarness,
                "__init__",
                side_effect=AssertionError("harness must not initialize"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--phase", "plan"], environment={}), 0)
        result = __import__("json").loads(output.getvalue())
        self.assertFalse(result["live_calls"])
        self.assertFalse(result["config_loaded"])
        self.assertFalse(result["profile_loaded"])
        self.assertFalse(result["ledger_initialized"])
        self.assertFalse(result["harness_initialized"])
        self.assertFalse(result["client_initialized"])

    def test_runtime_scope_requires_exact_private_nonsymlinked_artifact_and_binding(self):
        payload = self.config().runtime_scope.payload()
        path = self.root / "protected-runtime.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)

        loaded = RuntimeScope.load(
            path,
            environment={"ORACLE_E2E_REGION": "us-chicago-1"},
        )
        self.assertEqual(loaded.payload(), payload)

        os.chmod(path, 0o640)
        with self.assertRaisesRegex(HarnessError, "regular 0600"):
            RuntimeScope.load(path)
        os.chmod(path, 0o600)

        payload["unexpected"] = "field"
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(HarnessError, "schema"):
            RuntimeScope.load(path)
        payload.pop("unexpected")
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)

        link = self.root / "runtime-link.json"
        link.symlink_to(path)
        with self.assertRaisesRegex(HarnessError, "symlinked"):
            RuntimeScope.load(link)
        with self.assertRaisesRegex(HarnessError, "protected runtime scope"):
            RuntimeScope.load(path, environment={"OCI_CLI_PROFILE": "FOREIGN"})

        real_ledger_directory = self.root / "real-ledger-directory"
        real_ledger_directory.mkdir(mode=0o700)
        linked_ledger_directory = self.root / "linked-ledger-directory"
        linked_ledger_directory.symlink_to(
            real_ledger_directory, target_is_directory=True
        )
        payload["ui_ledger_path"] = str(
            linked_ledger_directory / "oracle-ledger.json"
        )
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(HarnessError, "symlinked"):
            RuntimeScope.load(path)

    def test_manifest_builder_is_exact_secret_free_private_and_never_overwrites(self):
        harness = self.harness(read_only=True)
        source = self.root / "manifest-source.json"
        output = self.root / "manifest.json"
        candidate = self.valid_manifest()
        source.write_text(json.dumps(candidate), encoding="utf-8")
        os.chmod(source, 0o600)

        result = harness.build_manifest(source, output)

        self.assertEqual(result["phase"], "MANIFEST_BUILT")
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")),
            harness._validate_ui_manifest(candidate),
        )
        with self.assertRaisesRegex(HarnessError, "overwrite"):
            harness.build_manifest(source, source)
        with self.assertRaisesRegex(HarnessError, "already exists"):
            harness.build_manifest(source, output)

        nested_output = self.root / "new-private-parent" / "nested" / "manifest.json"
        nested_result = harness.build_manifest(source, nested_output)
        self.assertEqual(nested_result["output"], str(nested_output))
        self.assertEqual(nested_output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(nested_output.parent.stat().st_mode & 0o777, 0o700)

        real_directory = self.root / "real-output-directory"
        real_directory.mkdir()
        linked_directory = self.root / "linked-output-directory"
        linked_directory.symlink_to(real_directory, target_is_directory=True)
        with self.assertRaisesRegex(HarnessError, "symlinked"):
            harness.build_manifest(source, linked_directory / "manifest.json")

        candidate["api_key"] = "credential-shaped-canary"
        source.write_text(json.dumps(candidate), encoding="utf-8")
        os.chmod(source, 0o600)
        rejected = self.root / "rejected-manifest.json"
        with self.assertRaisesRegex(HarnessError, "credential-shaped"):
            harness.build_manifest(source, rejected)
        self.assertFalse(rejected.exists())

    def test_protected_manifest_publish_detects_parent_swap_and_leaves_no_target(self):
        harness = self.harness(read_only=True)
        source = self.root / "parent-swap-source.json"
        source.write_text(json.dumps(self.valid_manifest()), encoding="utf-8")
        os.chmod(source, 0o600)
        parent = self.root / "publish-parent"
        parent.mkdir(mode=0o700)
        output = parent / "manifest.json"
        real_stat = os.stat
        checks = {"count": 0}

        def swapped(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if Path(path) == parent and kwargs.get("follow_symlinks") is False:
                checks["count"] += 1
                if checks["count"] == 2:
                    return SimpleNamespace(
                        st_mode=result.st_mode,
                        st_dev=result.st_dev + 1,
                        st_ino=result.st_ino,
                    )
            return result

        with mock.patch("scripts.oracle_live_ui_e2e.os.stat", side_effect=swapped):
            with self.assertRaisesRegex(HarnessError, "parent directory changed"):
                harness.build_manifest(source, output)
        self.assertFalse(output.exists())

    def test_manifest_requires_exact_restore_token_and_both_object_witnesses(self):
        harness = self.harness(read_only=True)
        manifest = self.valid_manifest()
        manifest["compute"]["restore"]["request_token"] = self.request_token("other")
        with self.assertRaisesRegex(HarnessError, "restore witness"):
            harness._validate_ui_manifest(manifest)

        manifest = self.valid_manifest()
        manifest["storage"]["objects"].pop()
        with self.assertRaisesRegex(HarnessError, "exactly two"):
            harness._validate_ui_manifest(manifest)

    def test_manifest_accepts_live_backupsheep_markers_and_rejects_rfc_uuid_aliases(self):
        harness = self.harness(read_only=True)
        manifest = self.valid_manifest()

        normalized = harness._validate_ui_manifest(manifest)

        self.assertEqual(
            normalized["compute"]["backup"]["backup_uuid"],
            "bs-bs-e2e-oracle-compute-n29-b4",
        )
        self.assertEqual(
            normalized["storage"]["objects"][1]["backup_uuid"],
            "bs-upcloud-website-fixture-n27-b11",
        )

        manifest = self.valid_manifest()
        current_restore_marker = "backupsheep-oracle-19-e48aa9f7326ecf2c5aaf0a0c"
        manifest["compute"]["restore"]["marker"] = current_restore_marker
        manifest["compute"]["restore"]["request_token"] = self.request_token(
            current_restore_marker
        )
        self.assertEqual(
            harness._validate_ui_manifest(manifest)["compute"]["restore"]["marker"],
            current_restore_marker,
        )

        manifest = self.valid_manifest()
        legacy_uuid = "00000000-0000-4000-8000-000000000001"
        manifest["compute"]["backup"].update(
            {
                "backup_uuid": legacy_uuid,
                "marker": legacy_uuid,
                "request_token": self.request_token(legacy_uuid),
            }
        )
        with self.assertRaisesRegex(HarnessError, "safe BackupSheep marker"):
            harness._validate_ui_manifest(manifest)

        manifest = self.valid_manifest()
        exact_marker = manifest["compute"]["backup"]["backup_uuid"]
        manifest["compute"]["backup"]["backup_uuid"] = f" {exact_marker}"
        with self.assertRaisesRegex(HarnessError, "safe BackupSheep marker"):
            harness._validate_ui_manifest(manifest)

        manifest = self.valid_manifest()
        manifest["workloads"]["website"]["row_witness"][
            "backup_marker"
        ] = "bs-upcloud-website-fixture-n27-b12"
        with self.assertRaisesRegex(HarnessError, "object and workload row IDs"):
            harness._validate_ui_manifest(manifest)

    def test_legacy_verify_alias_fails_closed_before_config_or_harness(self):
        output = StringIO()
        with (
            mock.patch.object(
                HarnessConfig,
                "from_environment",
                side_effect=AssertionError("legacy verify must not load config"),
            ),
            mock.patch.object(
                OracleLiveUIHarness,
                "__init__",
                side_effect=AssertionError("legacy verify must not construct harness"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--phase", "verify"], environment={}), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "FAILED_SAFE")
        self.assertIn("verify-apply", result["error"])

    def test_orphan_reconciliation_is_exact_inventory_bound_and_atomic(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        source_id = "ocid1.instance.oc1.iad.sourcecompute"
        backup_id = "ocid1.image.oc1.iad.orphanbackup"
        restore_id = "ocid1.instance.oc1.iad.orphanrestore"
        boot_id = "ocid1.bootvolume.oc1.iad.orphanrestoreboot"
        vnic_id = "ocid1.vnic.oc1.iad.orphanrestorevnic"
        backup_marker = "bs-bs-e2e-oracle-compute-n29-b4"
        restore_marker = "bs-bs-e2e-oracle-compute-restore-r14"
        backup_tags = harness._backup_tags(
            backup_marker, source_id, "compute_image"
        )
        restore_tags = harness._restore_tags(
            {
                "marker": restore_marker,
                "request_token": self.request_token(restore_marker),
            },
            source_backup_id=backup_id,
            source_id=source_id,
            target_type="instance",
        )
        boot_tags = harness._source_tags("ui_compute_restore_boot_volume")
        vnic_tags = dict(restore_tags)
        backup = SimpleNamespace(
            id=backup_id,
            display_name=backup_marker,
            compartment_id=self.compartment_id,
            lifecycle_state="AVAILABLE",
            freeform_tags=backup_tags,
        )
        restore = SimpleNamespace(
            id=restore_id,
            display_name=f"{self.run_id}-adopted-compute-restore",
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            image_id=backup_id,
            source_details=SimpleNamespace(image_id=backup_id),
            freeform_tags=restore_tags,
        )
        boot = SimpleNamespace(
            id=boot_id,
            display_name=harness.names["ui_compute_restore_boot_volume"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="AVAILABLE",
            freeform_tags=boot_tags,
            source_details=None,
        )
        vnic = SimpleNamespace(
            id=vnic_id,
            display_name=f"{restore.display_name}-vnic",
            compartment_id=self.compartment_id,
            lifecycle_state="AVAILABLE",
            subnet_id=harness.config.runtime_scope.subnet_id,
            freeform_tags=vnic_tags,
        )
        boot_attachment = SimpleNamespace(
            id="ocid1.bootvolumeattachment.oc1.iad.orphanrestoreboot",
            instance_id=restore_id,
            boot_volume_id=boot_id,
            lifecycle_state="ATTACHED",
        )
        vnic_attachment = SimpleNamespace(
            id="ocid1.vnicattachment.oc1.iad.orphanrestorevnic",
            instance_id=restore_id,
            vnic_id=vnic_id,
            lifecycle_state="ATTACHED",
        )
        clients["compute"].list_images.return_value = response([backup])
        clients["compute"].list_instances.return_value = response([restore])
        clients["compute"].list_vnic_attachments.return_value = response(
            [vnic_attachment]
        )
        clients["compute"].list_boot_volume_attachments.return_value = response(
            [boot_attachment]
        )
        clients["block"].list_volume_backups.return_value = response([])
        clients["block"].list_boot_volume_backups.return_value = response([])
        clients["block"].list_volumes.return_value = response([])
        clients["block"].list_boot_volumes.return_value = response([boot])
        clients["network"].get_vnic.return_value = response(vnic)
        harness.ledger.record(
            kind="source_instance",
            resource_id=source_id,
            name=harness.names["source_instance"],
            ownership={
                "compartment_id": self.compartment_id,
                "availability_domain": self.availability_domain,
                "tags": harness._source_tags("source_instance"),
            },
            source_witness="ocid1.image.oc1.iad.source",
        )
        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "profile": "BACKUPSHEEP_E2E",
            "tenancy_id": self.tenancy_id,
            "compartment_id": self.compartment_id,
            "resources": [
                {
                    "kind": "ui_compute_backup",
                    "provider_ocid": backup_id,
                    "name": backup.display_name,
                    "freeform_tags": backup_tags,
                    "lifecycle_state": "AVAILABLE",
                    "source_relationship": {
                        "kind": "source_instance",
                        "ocid": source_id,
                    },
                    "demo_row_witness": {
                        "row_type": "backup",
                        "row_id": 4,
                        "status": "Failed",
                        "marker": backup_marker,
                        "provider_ocid": backup_id,
                    },
                },
                {
                    "kind": "ui_compute_restore",
                    "provider_ocid": restore_id,
                    "name": restore.display_name,
                    "freeform_tags": restore_tags,
                    "lifecycle_state": "RUNNING",
                    "source_relationship": {
                        "kind": "ui_compute_backup",
                        "ocid": backup_id,
                    },
                    "demo_row_witness": {
                        "row_type": "restore",
                        "row_id": 14,
                        "status": "Failed",
                        "marker": restore_marker,
                        "provider_ocid": restore_id,
                    },
                },
                {
                    "kind": "ui_compute_restore_boot_volume",
                    "provider_ocid": boot_id,
                    "name": boot.display_name,
                    "freeform_tags": boot_tags,
                    "lifecycle_state": "AVAILABLE",
                    "source_relationship": {
                        "kind": "ui_compute_restore",
                        "ocid": restore_id,
                    },
                    "demo_row_witness": {
                        "row_type": "restore",
                        "row_id": 14,
                        "status": "Failed",
                        "marker": restore_marker,
                        "provider_ocid": restore_id,
                    },
                },
                {
                    "kind": "ui_compute_restore_vnic",
                    "provider_ocid": vnic_id,
                    "name": vnic.display_name,
                    "freeform_tags": vnic_tags,
                    "lifecycle_state": "AVAILABLE",
                    "source_relationship": {
                        "kind": "ui_compute_restore",
                        "ocid": restore_id,
                    },
                    "demo_row_witness": {
                        "row_type": "restore",
                        "row_id": 14,
                        "status": "Failed",
                        "marker": restore_marker,
                        "provider_ocid": restore_id,
                    },
                },
            ],
        }
        manifest_path = self.root / "orphan-reconciliation.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        before = harness.config.ledger_path.read_bytes()

        manifest["resources"][0]["freeform_tags"]["CUSTOM_NOTE"] = (
            "not-allowlisted"
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "tags are malformed"):
            harness.reconcile_orphans(manifest_path)
        self.assertEqual(harness.config.ledger_path.read_bytes(), before)
        manifest["resources"][0]["freeform_tags"].pop("CUSTOM_NOTE")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        os.chmod(manifest_path, 0o600)

        clients["block"].list_boot_volumes.return_value = response([])
        with mock.patch.object(harness, "_validate_scope"):
            with self.assertRaisesRegex(HarnessError, "zero or duplicate"):
                harness.reconcile_orphans(manifest_path)
        self.assertEqual(harness.config.ledger_path.read_bytes(), before)

        clients["block"].list_boot_volumes.return_value = response([boot, boot])
        with mock.patch.object(harness, "_validate_scope"):
            with self.assertRaisesRegex(HarnessError, "zero or duplicate"):
                harness.reconcile_orphans(manifest_path)
        self.assertEqual(harness.config.ledger_path.read_bytes(), before)

        clients["block"].list_boot_volumes.return_value = response([boot])
        original_name = boot.display_name
        boot.display_name = "foreign-boot-name"
        with mock.patch.object(harness, "_validate_scope"):
            with self.assertRaisesRegex(HarnessError, "does not match"):
                harness.reconcile_orphans(manifest_path)
        self.assertEqual(harness.config.ledger_path.read_bytes(), before)
        boot.display_name = original_name

        with mock.patch.object(harness, "_validate_scope"):
            result = harness.reconcile_orphans(manifest_path)
        self.assertEqual(result["ledger_rows_added"], 4)
        self.assertEqual(result["provider_mutations"], False)
        self.assertEqual(
            {row["kind"] for row in harness.ledger.entries() if row["kind"].startswith("ui_")},
            {
                "ui_compute_backup",
                "ui_compute_restore",
                "ui_compute_restore_boot_volume",
                "ui_compute_restore_vnic",
            },
        )
        after = harness.config.ledger_path.read_bytes()
        with mock.patch.object(harness, "_validate_scope"):
            repeated = harness.reconcile_orphans(manifest_path)
        self.assertEqual(repeated["ledger_rows_added"], 0)
        self.assertEqual(repeated["ledger_rows_already_exact"], 4)
        self.assertEqual(harness.config.ledger_path.read_bytes(), after)
        for method in (
            clients["compute"].create_image,
            clients["compute"].launch_instance,
            clients["block"].create_volume,
            clients["block"].create_boot_volume,
            clients["block"].update_boot_volume,
            clients["network"].update_vnic,
        ):
            method.assert_not_called()

    def test_report_uses_only_read_only_phases_and_creates_no_local_files(self):
        harness = self.harness(read_only=True)
        before = sorted(path.name for path in self.root.iterdir())
        resource = SimpleNamespace(id="ocid1.image.oc1.iad.readonly")
        local = {"manifest": self.valid_manifest()}
        checked = {
            **local,
            "backups": {kind: resource for kind in ("compute", "block", "boot")},
            "restores": {kind: resource for kind in ("compute", "block", "boot")},
            "storage": {"objects_verified": 2},
        }
        with (
            mock.patch.object(
                harness, "_local_verification_preflight", return_value=local
            ) as local_preflight,
            mock.patch.object(
                harness, "_provider_verification_preflight", return_value=checked
            ) as provider_preflight,
            mock.patch.object(
                harness,
                "_verify_workloads_manifest",
                return_value={"all_evidence_matches": True},
            ) as workloads,
            mock.patch.object(
                harness, "_verify_restored_data", side_effect=AssertionError("mutation")
            ),
        ):
            result = harness.report(self.root / "manifest.json")
        self.assertEqual(result["phase"], "READ_ONLY_REPORT")
        self.assertFalse(result["local_writes"])
        self.assertFalse(result["provider_mutations"])
        local_preflight.assert_called_once()
        provider_preflight.assert_called_once_with(local)
        workloads.assert_called_once_with(local["manifest"], record=False)
        self.assertEqual(before, sorted(path.name for path in self.root.iterdir()))

    def test_actual_local_report_preflight_leaves_every_protected_byte_unchanged(self):
        secret_path = self.root / "report-storage-secret.json"
        mutable = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        manifest = self.write_workload_scope_artifacts()
        for section, ledger_kind in (
            ("compute", "source_instance"),
            ("block", "source_block_volume"),
            ("boot", "source_boot_volume"),
        ):
            mutable.ledger.record(
                kind=ledger_kind,
                resource_id=manifest[section]["source_ocid"],
                name=f"{self.run_id}-{ledger_kind}",
                ownership={
                    "compartment_id": self.compartment_id,
                    "run_id": self.run_id,
                },
                source_witness="protected-source",
            )
        mutable.evidence.put(
            "payload",
            {
                "operation": "evidence",
                "kind": "payload",
                "name": self.run_id,
                "marker": self.run_id,
                "sha256": "a" * 64,
                "byte_count": 4096,
                "filesystem_flushed": True,
            },
        )
        self.establish_storage_scope(mutable)
        mutable._write_storage_secret(self.storage_secret(mutable))
        manifest_path = self.root / "read-only-report-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        read_only = self.harness(
            read_only=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )

        def snapshot():
            return {
                str(path.relative_to(self.root)): (
                    path.lstat().st_mode & 0o777,
                    path.read_bytes(),
                )
                for path in sorted(self.root.rglob("*"))
                if path.is_file()
            }

        before = snapshot()
        local = read_only._local_verification_preflight(manifest_path)

        self.assertEqual(local["manifest"]["workload_guest_scope"]["provider"], "upcloud")
        self.assertEqual(snapshot(), before)

    def test_verify_apply_stops_before_provider_or_guest_when_local_preflight_fails(self):
        harness = self.harness(apply=True)
        with (
            mock.patch.object(
                harness,
                "_local_verification_preflight",
                side_effect=HarnessError("storage_scope is missing"),
            ),
            mock.patch.object(harness, "_provider_verification_preflight") as provider,
            mock.patch.object(harness, "_verify_workloads_manifest") as guest,
            mock.patch.object(harness, "_verify_restored_data") as mutation,
        ):
            with self.assertRaisesRegex(HarnessError, "storage_scope"):
                harness.verify_apply(self.root / "manifest.json")
        provider.assert_not_called()
        guest.assert_not_called()
        mutation.assert_not_called()

    def test_storage_object_read_only_verification_does_not_record_evidence(self):
        harness = self.harness(read_only=True)
        payload = b"object-body"
        digest = hashlib.sha256(payload).hexdigest()
        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-one",
            "ETag": '"etag-one"',
            "ContentLength": len(payload),
            "Metadata": {
                "backupsheep-sha256": digest,
                "backupsheep-bytes": str(len(payload)),
            },
        }
        bodies = []

        def get_object(**_kwargs):
            body = mock.MagicMock()
            body.read.side_effect = [payload, b""]
            bodies.append(body)
            return {"Body": body}

        client.get_object.side_effect = get_object
        secret = {"prefix": f"{self.run_id}/", "bucket": "bucket"}
        objects = [
            {
                "kind": kind,
                "key": f"{self.run_id}/{kind}.bin",
                "version_id": "version-one",
                "etag": "etag-one",
                "sha256": digest,
                "byte_count": len(payload),
            }
            for kind in ("website", "database")
        ]
        with mock.patch.object(
            harness, "_storage_s3_client", return_value=(client, secret)
        ):
            result = harness._verify_storage_objects(
                {"objects": objects}, record=False
            )
        self.assertEqual(result["objects_verified"], 2)
        self.assertEqual(len(bodies), 2)
        self.assertTrue(all(body.close.called for body in bodies))
        self.assertFalse((self.root / "oracle-ledger.json.oracle-evidence.json").exists())

    def test_workload_mismatch_fails_without_recording_success(self):
        harness = self.harness(read_only=True)
        manifest = harness._validate_ui_manifest(self.valid_manifest())
        website = manifest["workloads"]["website"]["source"]
        website_drift = {**website, "byte_count": website["byte_count"] + 1}
        database = manifest["workloads"]["database"]["source"]
        ssh = mock.MagicMock()
        with (
            mock.patch.object(
                harness,
                "_local_verification_preflight",
                return_value={"manifest": manifest},
            ),
            mock.patch.object(harness, "_load_clients") as load_oci,
            mock.patch.object(harness, "_validate_scope") as validate_oci,
            mock.patch.object(
                harness,
                "_readonly_workload_ssh_client",
                return_value=ssh,
            ),
            mock.patch.object(
                harness,
                "_website_workload_evidence",
                side_effect=[website, website_drift],
            ),
            mock.patch.object(
                harness,
                "_database_workload_evidence",
                side_effect=[database, database],
            ),
        ):
            with self.assertRaisesRegex(HarnessError, "website"):
                harness.verify_workloads(self.root / "manifest.json", record=False)
        ssh.close.assert_called_once()
        load_oci.assert_not_called()
        validate_oci.assert_not_called()
        self.assertFalse((self.root / "oracle-ledger.json.oracle-evidence.json").exists())

    def test_read_only_workload_ssh_uses_only_pinned_preexisting_files_without_writes(self):
        harness = self.harness(read_only=True)
        manifest = self.write_workload_scope_artifacts()
        scope = harness._validate_ui_manifest(manifest)["workload_guest_scope"]
        host_key = mock.MagicMock()
        host_key.asbytes.return_value = b"exact-pinned-upcloud-host-key"
        host_key.get_name.return_value = "ssh-ed25519"
        scope["known_host_fingerprint"] = harness._ssh_key_fingerprint(host_key)
        client = mock.MagicMock()
        client.get_host_keys.return_value.lookup.return_value = {
            "ssh-ed25519": host_key
        }
        client.get_transport.return_value.get_remote_server_key.return_value = host_key

        def snapshot():
            result = {}
            for path in sorted(self.root.rglob("*")):
                relative = str(path.relative_to(self.root))
                metadata = path.lstat()
                if path.is_dir():
                    result[relative] = ("directory", metadata.st_mode & 0o777)
                else:
                    result[relative] = (
                        "file",
                        metadata.st_mode & 0o777,
                        path.read_bytes(),
                    )
            return result

        before = snapshot()
        with (
            mock.patch("paramiko.SSHClient", return_value=client),
            mock.patch(
                "paramiko.RSAKey.from_private_key",
                return_value=mock.sentinel.private_key,
            ) as load_key,
            mock.patch.object(
                harness, "_ensure_ssh_key", side_effect=AssertionError("key generation")
            ),
            mock.patch.object(
                harness, "_ssh_client", side_effect=AssertionError("TOFU SSH path")
            ),
            mock.patch(
                "scripts.oracle_live_ui_e2e.os.chmod",
                side_effect=AssertionError("chmod in read-only path"),
            ),
        ):
            connected = harness._readonly_workload_ssh_client(scope)
            connected.close()

        self.assertEqual(snapshot(), before)
        self.assertEqual(load_key.call_count, 1)
        self.assertEqual(
            load_key.call_args.args[0].read(),
            self.workload_key_bytes.decode("ascii"),
        )
        client.load_host_keys.assert_called_once_with(scope["known_hosts_path"])
        client.save_host_keys.assert_not_called()
        client.connect.assert_called_once()

        os.chmod(scope["ssh_private_key_path"], 0o640)
        with self.assertRaisesRegex(HarnessError, "regular 0600"):
            harness._validate_workload_guest_files(scope)

    def test_workload_guest_scope_rejects_symlinked_protected_path_components(self):
        harness = self.harness(read_only=True)
        real_parent = self.root / "real-workload-artifacts"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-workload-artifacts"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        manifest = self.valid_manifest()
        manifest["workload_guest_scope"]["ssh_private_key_path"] = str(
            linked_parent / "upcloud-workload-key"
        )

        with self.assertRaisesRegex(HarnessError, "symlinked"):
            harness._validate_ui_manifest(manifest)

    def test_database_workload_readback_uses_canonical_read_only_queries(self):
        harness = self.harness(read_only=True)
        client = mock.MagicMock()
        with mock.patch.object(
            harness,
            "_ssh_run",
            side_effect=["a" * 64, "b" * 64, "2", "8"],
        ) as run:
            evidence = harness._database_workload_evidence(
                client,
                self.workload_restore_database,
                allowed_databases={self.workload_restore_database},
            )

        self.assertEqual(evidence["table_count"], 2)
        self.assertEqual(evidence["row_count"], 8)
        commands = [call.args[1] for call in run.call_args_list]
        self.assertIn("information_schema.columns", commands[0])
        self.assertIn("to_jsonb", commands[1])
        self.assertTrue(commands[0].startswith("bash -o pipefail -c "))
        self.assertTrue(commands[1].startswith("bash -o pipefail -c "))
        self.assertTrue(commands[3].startswith("bash -o pipefail -c "))
        self.assertFalse(
            any(
                token in command.upper()
                for command in commands
                for token in ("INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ")
            )
        )

    def test_provision_and_cleanup_have_independent_fail_closed_gates(self):
        harness = self.harness(apply=False, cleanup=True)
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            with self.assertRaisesRegex(HarnessError, "APPLY"):
                harness.provision()
            with self.assertRaisesRegex(HarnessError, "APPLY"):
                harness.cleanup()

        harness = self.harness(apply=True, cleanup=False)
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            with self.assertRaisesRegex(HarnessError, "CLEANUP"):
                harness.cleanup()

    def test_environment_requires_two_exact_compartment_confirmations(self):
        runtime = self.config().runtime_scope.payload()
        runtime_path = self.root / "runtime-scope.json"
        runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
        os.chmod(runtime_path, 0o600)
        environment = {
            "BACKUPSHEEP_E2E_RUN_ID": self.run_id,
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(self.root / "ledger.json"),
            "BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH": str(self.root / "network.json"),
            "ORACLE_E2E_RUNTIME_SCOPE_FILE": str(runtime_path),
            "OCI_CLI_PROFILE": "BACKUPSHEEP_E2E",
            "OCI_CLI_CONFIG_FILE": str(self.root / "config"),
            "ORACLE_E2E_COMPARTMENT_OCID": self.compartment_id,
            "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID": "ocid1.compartment.oc1..foreign",
            "ORACLE_E2E_ALLOWED_TENANCY_OCID": self.tenancy_id,
            "ORACLE_E2E_SUBNET_OCID": "ocid1.subnet.oc1.iad.testsubnet",
            "ORACLE_E2E_REGION": "us-chicago-1",
            "ORACLE_E2E_AVAILABILITY_DOMAIN": self.availability_domain,
        }
        with self.assertRaisesRegex(HarnessError, "protected runtime scope"):
            HarnessConfig.from_environment(environment)

        environment["ORACLE_E2E_ALLOWED_COMPARTMENT_OCID"] = self.compartment_id
        environment["BACKUPSHEEP_E2E_LEDGER_PATH"] = str(self.root / "oracle-ledger.json")
        environment["BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH"] = str(
            self.root / "oracle-network-ledger.json"
        )
        environment["OCI_CLI_CONFIG_FILE"] = str(self.root / "_docs" / "oracle.txt")
        with self.assertRaisesRegex(HarnessError, "must not point inside _docs"):
            HarnessConfig.from_environment(environment)

    def test_scope_check_does_not_send_pagination_to_unpaged_ad_endpoint(self):
        clients = self.clients()
        clients["identity"].get_compartment.return_value = response(
            SimpleNamespace(
                id=self.compartment_id,
                compartment_id=self.tenancy_id,
                lifecycle_state="ACTIVE",
            )
        )
        clients["identity"].list_availability_domains.return_value = response(
            [SimpleNamespace(name=self.availability_domain)]
        )
        harness = self.harness(clients=clients)

        harness._validate_scope()

        kwargs = clients["identity"].list_availability_domains.call_args.kwargs
        self.assertNotIn("limit", kwargs)
        self.assertNotIn("page", kwargs)

    def test_attachment_device_must_be_exact_and_provider_available(self):
        clients = self.clients()
        clients["compute"].list_instance_devices.return_value = response(
            [
                SimpleNamespace(name=SOURCE_BLOCK_DEVICE, is_available=True),
                SimpleNamespace(name="/dev/oracleoci/oraclevdc", is_available=False),
            ]
        )
        harness = self.harness(clients=clients)
        instance_id = "ocid1.instance.oc1.iad.backupsheeptest"
        self.assertEqual(
            harness._require_attachment_device(instance_id, SOURCE_BLOCK_DEVICE),
            SOURCE_BLOCK_DEVICE,
        )
        with self.assertRaisesRegex(HarnessError, "not available"):
            harness._require_attachment_device(
                instance_id, "/dev/oracleoci/oraclevdc"
            )
        with self.assertRaisesRegex(HarnessError, "safe allowlist"):
            harness._require_attachment_device(instance_id, "/dev/sdb")

    def _volume(self, harness, *, tags=None, state="AVAILABLE"):
        return SimpleNamespace(
            id="ocid1.volume.oc1.iad.backupsheeptest",
            display_name=harness.names["source_block_volume"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state=state,
            freeform_tags=tags
            if tags is not None
            else {
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "source_block_volume",
            },
            source_details=None,
        )

    def test_foreign_same_name_blocks_create(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["block"].list_volumes.return_value = response(
            [self._volume(harness, tags={E2E_RUN_TAG: "foreign-run"})]
        )

        with self.assertRaisesRegex(HarnessError, "foreign"):
            harness._provision_block_volume()

        clients["block"].create_volume.assert_not_called()

    def test_unresolved_mutation_intent_blocks_blind_replay(self):
        harness = self.harness(apply=True)
        harness._put_intent(
            "source_block_volume",
            operation="create",
            name=harness.names["source_block_volume"],
        )

        with self.assertRaisesRegex(HarnessError, "unresolved durable mutation"):
            harness._put_intent(
                "source_block_volume",
                operation="create",
                name=harness.names["source_block_volume"],
            )

    def _iam_user(self, harness):
        return SimpleNamespace(
            id="ocid1.user.oc1..backupsheeptest",
            name=harness.names["iam_user"],
            compartment_id=self.tenancy_id,
            lifecycle_state="ACTIVE",
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "iam_user",
            },
        )

    def test_identity_domain_user_create_has_reserved_primary_email(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        user = self._iam_user(harness)
        clients["identity"].list_users.return_value = response([])
        clients["identity"].create_user.return_value = response(user)
        clients["identity"].get_user.return_value = response(user)

        created = harness._provision_iam_named(
            kind="iam_user",
            tenancy_id=self.tenancy_id,
            list_method=clients["identity"].list_users,
            create_method=clients["identity"].create_user,
            details_class=oci.identity.models.CreateUserDetails,
        )

        self.assertEqual(created.id, user.id)
        details = clients["identity"].create_user.call_args.kwargs[
            "create_user_details"
        ]
        self.assertEqual(details.email, f"{self.run_id}@example.invalid")
        self.assertIsNone(harness.intents.get("iam_user"))

    def test_definite_iam_rejection_clears_intent_after_exact_absence(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["identity"].list_users.return_value = response([])
        rejected = RuntimeError("sensitive provider detail")
        rejected.status = 400
        rejected.code = "IdcsConversionError"
        clients["identity"].create_user.side_effect = rejected

        with self.assertRaisesRegex(HarnessError, "PROVIDER_REQUEST_FAILED"):
            harness._provision_iam_named(
                kind="iam_user",
                tenancy_id=self.tenancy_id,
                list_method=clients["identity"].list_users,
                create_method=clients["identity"].create_user,
                details_class=oci.identity.models.CreateUserDetails,
            )

        self.assertIsNone(harness.intents.get("iam_user"))

    def test_oci_mutation_definitive_4xx_categories_clear_only_their_intent(self):
        for status in (400, 403, 404, 429):
            with self.subTest(status=status):
                clients = self.clients()
                harness = self.harness(apply=True, clients=clients)
                clients["identity"].create_user.return_value = response(
                    status=status
                )
                harness._put_intent(
                    "iam_user",
                    operation="create",
                    name=harness.names["iam_user"],
                )
                with self.assertRaises(HarnessError) as raised:
                    harness._mutation_call(
                        "iam_user", clients["identity"].create_user
                    )
                self.assertTrue(raised.exception.definitive_rejection)
                self.assertFalse(raised.exception.mutation_outcome_unknown)
                self.assertIsNone(harness.intents.get("iam_user"))

    def test_oci_mutation_transient_and_unknown_categories_retain_intent(self):
        cases = (
            ("408", 408, None),
            ("500", 500, None),
            ("504", 504, None),
            ("timeout", None, TimeoutError("lost response")),
            ("connection", None, ConnectionError("lost response")),
            ("unknown", None, RuntimeError("unclassified SDK failure")),
        )
        for label, status, exception in cases:
            with self.subTest(category=label):
                clients = self.clients()
                harness = self.harness(apply=True, clients=clients)
                if exception is not None:
                    clients["identity"].create_user.side_effect = exception
                else:
                    clients["identity"].create_user.return_value = response(
                        status=status
                    )
                intent_key = f"iam_user_{label}"
                harness._put_intent(
                    intent_key,
                    operation="create",
                    name=harness.names["iam_user"],
                )
                with self.assertRaises(HarnessError) as raised:
                    harness._mutation_call(
                        intent_key, clients["identity"].create_user
                    )
                self.assertFalse(raised.exception.definitive_rejection)
                self.assertTrue(raised.exception.mutation_outcome_unknown)
                self.assertIsNotNone(harness.intents.get(intent_key))

    def test_ambiguous_iam_timeout_keeps_intent_after_exact_absence(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["identity"].list_users.return_value = response([])
        clients["identity"].create_user.side_effect = TimeoutError("lost response")

        with self.assertRaisesRegex(HarnessError, "outcome may be unknown"):
            harness._provision_iam_named(
                kind="iam_user",
                tenancy_id=self.tenancy_id,
                list_method=clients["identity"].list_users,
                create_method=clients["identity"].create_user,
                details_class=oci.identity.models.CreateUserDetails,
            )

        self.assertIsNotNone(harness.intents.get("iam_user"))

    def test_lost_block_create_response_adopts_one_exact_match(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        volume = self._volume(harness)
        clients["block"].list_volumes.side_effect = [
            response([]),
            response([volume]),
        ]
        clients["block"].create_volume.side_effect = oci.exceptions.RequestException(
            "credential-canary"
        )
        clients["block"].get_volume.return_value = response(volume)

        adopted = harness._provision_block_volume()

        self.assertEqual(adopted.id, volume.id)
        clients["block"].create_volume.assert_called_once()
        row = harness.ledger.get("source_block_volume", volume.id)
        self.assertEqual(row["resource_id"], volume.id)
        self.assertNotIn("credential-canary", repr(row))

    def test_cleanup_refuses_changed_ownership_before_delete(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.return_value = response(
            [self._volume(harness, tags={E2E_RUN_TAG: "foreign-run"})]
        )

        with self.assertRaisesRegex(HarnessError, "ownership tags"):
            harness._cleanup_graph_kind("source_block_volume")

        clients["block"].delete_volume.assert_not_called()

    def test_cleanup_blocks_incomplete_instance_dependency_ledger(self):
        harness = self.harness(apply=True, cleanup=True)
        instance = SimpleNamespace(
            id="ocid1.instance.oc1.iad.backupsheeptest",
            display_name=harness.names["source_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            image_id="ocid1.image.oc1.iad.base",
            source_details=None,
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "source_instance",
            },
        )
        proof = harness._expected_proof(
            name=instance.display_name,
            tags=instance.freeform_tags,
            availability_domain=self.availability_domain,
            source_id=instance.image_id,
        )
        harness._record(
            "source_instance",
            instance,
            proof,
            source_id=instance.image_id,
        )

        with self.assertRaisesRegex(HarnessError, "incomplete dependency ledger"):
            harness._assert_cleanup_graph_complete()

    def _boot_verifier_resources(self, harness):
        boot_id = "ocid1.bootvolume.oc1.iad.restoredboot"
        instance_id = "ocid1.instance.oc1.iad.bootverifier"
        restored_boot = SimpleNamespace(id=boot_id)
        instance = SimpleNamespace(
            id=instance_id,
            display_name=harness.names["ui_boot_verify_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            # OCI retains the original image here even when launch source was an
            # existing boot volume. The attachment is the authoritative witness.
            image_id="ocid1.image.oc1.iad.originalimage",
            source_details=None,
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "ui_boot_verify_instance",
            },
        )
        attachment = SimpleNamespace(
            id="ocid1.bootvolumeattachment.oc1.iad.bootverifier",
            instance_id=instance_id,
            boot_volume_id=boot_id,
            lifecycle_state="ATTACHED",
        )
        return restored_boot, instance, attachment

    def test_boot_verifier_uses_exact_attachment_not_original_image_as_source(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        restored_boot, instance, attachment = self._boot_verifier_resources(harness)
        clients["compute"].list_instances.return_value = response([instance])
        clients["compute"].get_instance.return_value = response(instance)
        clients["compute"].list_boot_volume_attachments.return_value = response(
            [attachment]
        )

        observed = harness._launch_boot_verifier(
            restored_boot,
            subnet_id="ocid1.subnet.oc1.iad.testsubnet",
            shape="VM.Standard.E2.1",
        )

        self.assertEqual(observed.id, instance.id)
        clients["compute"].launch_instance.assert_not_called()
        row = harness.ledger.get("ui_boot_verify_instance", instance.id)
        self.assertEqual(row["source_witness"], restored_boot.id)
        self.assertEqual(row["ownership"]["source_id"], restored_boot.id)

        # A resumed verifier validates the same provider relationship and does
        # not regress to comparing the instance's original image ID.
        resumed = harness._launch_boot_verifier(
            restored_boot,
            subnet_id="ocid1.subnet.oc1.iad.testsubnet",
            shape="VM.Standard.E2.1",
        )
        self.assertEqual(resumed.id, instance.id)

    def test_boot_verifier_refuses_a_different_attached_boot_volume(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        restored_boot, instance, attachment = self._boot_verifier_resources(harness)
        attachment.boot_volume_id = "ocid1.bootvolume.oc1.iad.foreignboot"
        clients["compute"].list_instances.return_value = response([instance])
        clients["compute"].get_instance.return_value = response(instance)
        clients["compute"].list_boot_volume_attachments.return_value = response(
            [attachment]
        )

        with self.assertRaisesRegex(HarnessError, "different boot volume"):
            harness._launch_boot_verifier(
                restored_boot,
                subnet_id="ocid1.subnet.oc1.iad.testsubnet",
                shape="VM.Standard.E2.1",
            )

        clients["compute"].launch_instance.assert_not_called()
        self.assertIsNone(
            harness.ledger.get("ui_boot_verify_instance", instance.id)
        )

    def test_secret_file_is_outside_repo_chmod_600_and_not_reported(self):
        secret_path = self.root / "runtime" / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)

        written = harness._write_storage_secret(secret)

        self.assertEqual(written, secret_path)
        self.assertEqual(written.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("credential-canary", repr(harness.plan()))
        self.assertEqual(harness._read_storage_secret(), secret)
        with self.assertRaisesRegex(HarnessError, "refusing overwrite"):
            harness._write_storage_secret(secret)

    def test_secret_loader_requires_exact_0600_exact_keys_and_no_symlink(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)

        os.chmod(secret_path, 0o640)
        with self.assertRaisesRegex(HarnessError, "0600"):
            harness._read_storage_secret()

        os.chmod(secret_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "unsupported or incomplete"):
            harness._write_storage_secret({**secret, "unexpected": "value"})

        secret_path.unlink()
        target = self.root / "target-secret.json"
        target.write_text(__import__("json").dumps(secret), encoding="utf-8")
        os.chmod(target, 0o600)
        secret_path.symlink_to(target)
        with self.assertRaisesRegex(HarnessError, "symlink"):
            harness._read_storage_secret()

        secret_path.unlink()
        secret_path.mkdir(mode=0o700)
        os.chmod(secret_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "regular 0600 file"):
            harness._read_storage_secret()

    def test_storage_s3_use_requires_durable_scope_and_rejects_scope_drift(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)
        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(HarnessError, "durable storage scope"):
                harness._storage_s3_client()
        client.assert_not_called()

        self.establish_storage_scope(harness)
        changed = dict(secret, bucket="other-bucket")
        secret_path.write_text(json.dumps(changed), encoding="utf-8")
        os.chmod(secret_path, 0o600)
        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(HarnessError, "scope does not match"):
                harness._storage_s3_client()
        client.assert_not_called()

    def test_storage_scope_change_in_durable_evidence_fails_closed_before_s3(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        self.establish_storage_scope(harness)
        harness._write_storage_secret(self.storage_secret(harness))
        harness.evidence.update("storage_scope", bucket="foreign-bucket")

        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(
                HarnessError, "does not match (durable ownership|OCI configuration)"
            ):
                harness._storage_s3_client()
        client.assert_not_called()

    def test_storage_scope_repair_requires_exact_agreement_and_preserves_sources(self):
        secret_path = self.root / "oracle-storage.json"
        output = self.root / "repaired-storage-scope.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        self.establish_storage_scope(harness)
        harness.evidence.clear("storage_scope")
        harness._write_storage_secret(self.storage_secret(harness))
        secret_digest = hashlib.sha256(secret_path.read_bytes()).hexdigest()
        ledger_digest = hashlib.sha256(harness.config.ledger_path.read_bytes()).hexdigest()

        result = harness.repair_storage_scope(output)

        self.assertEqual(result["phase"], "STORAGE_SCOPE_REPAIRED")
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(secret_path.read_bytes()).hexdigest(), secret_digest)
        self.assertEqual(
            hashlib.sha256(harness.config.ledger_path.read_bytes()).hexdigest(),
            ledger_digest,
        )
        repaired = json.loads(output.read_text(encoding="utf-8"))
        self.assertNotIn("access_key_id", repaired["storage_scope"])
        self.assertNotIn("secret_access_key", repaired["storage_scope"])
        self.assertNotIn("ui_ledger_digest", repaired)
        self.assertEqual(repaired["bucket_witness"]["kind"], "object_bucket")
        self.assertEqual(repaired["user_witness"]["kind"], "iam_user")
        self.assertEqual(
            repaired["customer_secret_witness"]["resource_id"], "A" * 40
        )

        # The immutable three-row witness must remain usable when verify-apply
        # appends an unrelated exact resource to the same durable ledger.
        harness.ledger.record(
            kind="source_instance",
            resource_id="ocid1.instance.oc1.iad.afterverifyapply",
            name="post-verify-apply-resource",
            ownership={
                "compartment_id": self.compartment_id,
                "availability_domain": self.availability_domain,
                "tags": {E2E_RUN_TAG: self.run_id},
            },
            source_witness="ocid1.image.oc1.iad.source",
        )
        harness.environment["ORACLE_E2E_STORAGE_SCOPE_FILE"] = str(output)
        self.assertEqual(harness._load_repaired_storage_scope(), repaired["storage_scope"])
        with self.assertRaisesRegex(HarnessError, "already exists"):
            harness.repair_storage_scope(output)
        with self.assertRaisesRegex(HarnessError, "must not overwrite"):
            harness.repair_storage_scope(secret_path)

        secret = self.storage_secret(harness, bucket="foreign-bucket")
        secret_path.write_text(json.dumps(secret), encoding="utf-8")
        os.chmod(secret_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "durable ownership|disagree"):
            harness.repair_storage_scope(self.root / "drifted-scope.json")

    def test_cleanup_receipt_is_exact_private_and_cannot_be_replaced(self):
        harness = self.harness(apply=True, cleanup=True)
        instance_id = "ocid1.instance.oc1.iad.receipt"
        harness.ledger.record(
            kind="source_instance",
            resource_id=instance_id,
            name=harness.names["source_instance"],
            ownership={
                "compartment_id": self.compartment_id,
                "availability_domain": self.availability_domain,
                "tags": harness._source_tags("source_instance"),
            },
        )
        harness.ledger.mark_cleanup("source_instance", instance_id, state="deleted")
        receipt_path = self.root / "cleanup-receipt.json"

        written = harness._write_cleanup_receipt(receipt_path)

        self.assertEqual(written, str(receipt_path))
        self.assertEqual(os.stat(receipt_path).st_mode & 0o777, 0o600)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(
            set(receipt),
            {
                "schema",
                "run_id",
                "tenancy_id",
                "compartment_id",
                "runtime_scope_digest",
                "ui_ledger_path",
                "ui_ledger_digest",
                "terminal_resources",
            },
        )
        self.assertEqual(
            receipt["terminal_resources"],
            [{"kind": "source_instance", "resource_id": instance_id, "state": "deleted"}],
        )
        before = receipt_path.read_bytes()
        self.assertEqual(harness._write_cleanup_receipt(receipt_path), str(receipt_path))
        self.assertEqual(receipt_path.read_bytes(), before)

    def test_cleanup_preserves_customer_key_file_and_complete_iam_dependencies(self):
        clients = self.clients()
        secret_path = self.root / "oracle-storage.json"
        receipt_path = self.root / "credential-preserving-cleanup-receipt.json"
        harness = self.harness(
            apply=True,
            cleanup=True,
            clients=clients,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        bucket, user, _scope = self.establish_storage_scope(harness)
        group = SimpleNamespace(
            id="ocid1.group.oc1..backupsheeptest",
            name=harness.names["iam_group"],
            compartment_id=self.tenancy_id,
            lifecycle_state="ACTIVE",
            freeform_tags=harness._storage_tags("iam_group"),
        )
        membership = SimpleNamespace(
            id="ocid1.usergroupmembership.oc1..backupsheeptest",
            compartment_id=self.tenancy_id,
            lifecycle_state="ACTIVE",
            user_id=user.id,
            group_id=group.id,
        )
        policy = SimpleNamespace(
            id="ocid1.policy.oc1..backupsheeptest",
            name=harness.names["iam_policy"],
            compartment_id=self.compartment_id,
            lifecycle_state="ACTIVE",
            freeform_tags=harness._storage_tags("iam_policy"),
            statements=harness._policy_statements(group.name),
        )
        customer_key = SimpleNamespace(
            id="A" * 40,
            display_name=harness.names["customer_secret_key"],
            lifecycle_state="ACTIVE",
            user_id=user.id,
        )
        harness._record_storage(
            "iam_group",
            group,
            resource_id=group.id,
            name=group.name,
            compartment_id=self.tenancy_id,
            tags=group.freeform_tags,
        )
        harness._record_storage(
            "iam_membership",
            membership,
            resource_id=membership.id,
            name="",
            compartment_id=self.tenancy_id,
            relationships={"user_id": user.id, "group_id": group.id},
        )
        harness._record_storage(
            "iam_policy",
            policy,
            resource_id=policy.id,
            name=policy.name,
            compartment_id=self.compartment_id,
            tags=policy.freeform_tags,
        )
        harness._write_storage_secret(self.storage_secret(harness, bucket=bucket.name))
        before_secret = secret_path.read_bytes()
        clients["identity"].list_users.return_value = response([user])
        clients["identity"].list_groups.return_value = response([group])
        clients["identity"].list_policies.return_value = response([policy])
        clients["identity"].list_user_group_memberships.return_value = response(
            [membership]
        )
        clients["identity"].list_customer_secret_keys.return_value = response(
            [customer_key]
        )

        before_ledger = harness.config.ledger_path.read_bytes()
        clients["identity"].list_customer_secret_keys.return_value = response([])
        with (
            mock.patch.object(harness, "_validate_scope"),
            mock.patch.object(
                harness,
                "_storage_context",
                return_value=(self.tenancy_id, "us-chicago-1", "namespace"),
            ),
            self.assertRaisesRegex(HarnessError, "absent.*before mutation"),
        ):
            harness.cleanup(receipt_path)
        self.assertEqual(harness.config.ledger_path.read_bytes(), before_ledger)
        self.assertEqual(secret_path.read_bytes(), before_secret)
        self.assertFalse(receipt_path.exists())
        clients["object"].delete_bucket.assert_not_called()
        clients["identity"].list_customer_secret_keys.return_value = response(
            [customer_key]
        )

        class MissingBucket(Exception):
            status = 404
            code = "NotFound"

        clients["object"].get_bucket.side_effect = MissingBucket()
        with (
            mock.patch.object(harness, "_validate_scope"),
            mock.patch.object(
                harness,
                "_storage_context",
                return_value=(self.tenancy_id, "us-chicago-1", "namespace"),
            ),
        ):
            result = harness.cleanup(receipt_path)

        self.assertTrue(result["credentials_preserved"])
        self.assertEqual(secret_path.read_bytes(), before_secret)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        retained = {
            row["kind"]
            for row in receipt["terminal_resources"]
            if row["state"] == "user_retained"
        }
        self.assertEqual(
            retained,
            {
                "customer_secret_key",
                "iam_membership",
                "iam_policy",
                "iam_group",
                "iam_user",
            },
        )
        for method_name in (
            "delete_customer_secret_key",
            "delete_policy",
            "remove_user_from_group",
            "delete_group",
            "delete_user",
        ):
            getattr(clients["identity"], method_name).assert_not_called()

        receipt_bytes = receipt_path.read_bytes()
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("provider reuse")
        ):
            repeated = harness.cleanup(receipt_path)
        self.assertEqual(repeated["phase"], "ALREADY_CLEANED")
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(secret_path.read_bytes(), before_secret)

    def test_provider_error_messages_are_sanitized_and_statuses_are_classified(self):
        harness = self.harness(apply=True)
        with self.assertRaises(HarnessError) as raised:
            harness._call(
                mock.Mock(side_effect=RuntimeError("Authorization: Bearer secret-canary")),
                mutation=True,
            )
        self.assertNotIn("secret-canary", str(raised.exception))
        self.assertEqual(raised.exception.code, "PROVIDER_REQUEST_FAILED")

        for status, code in (
            (404, "PROVIDER_NOT_FOUND"),
            (429, "PROVIDER_RATE_LIMIT"),
            (500, "PROVIDER_TRANSIENT_OUTAGE"),
        ):
            with self.subTest(status=status):
                with self.assertRaises(HarnessError) as raised:
                    harness._call(mock.Mock(return_value=response(status=status)), mutation=True)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(raised.exception.mutation_outcome_unknown, status == 500)

    def test_customer_secret_key_uses_oci_access_key_id_not_ocid(self):
        harness = self.harness(apply=True)
        key_id = "A" * 40
        key = SimpleNamespace(
            id=key_id,
            display_name=harness.names["customer_secret_key"],
            user_id="ocid1.user.oc1..backupsheeptest",
            lifecycle_state="ACTIVE",
        )

        row = harness._record_storage(
            "customer_secret_key",
            key,
            resource_id=key_id,
            name=key.display_name,
            compartment_id="",
            relationships={"user_id": key.user_id},
        )

        self.assertEqual(row["resource_id"], key_id)
        with self.assertRaisesRegex(HarnessError, "ID is malformed"):
            harness._record_storage(
                "customer_secret_key",
                key,
                resource_id="not-an-access-key",
                name=key.display_name,
                compartment_id="",
                relationships={"user_id": key.user_id},
            )

    def test_oracle_s3_client_disables_unsupported_aws_chunked_checksums(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        self.establish_storage_scope(harness)
        secret = self.storage_secret(harness)
        secret_path.write_text(
            __import__("json").dumps(
                secret
            ),
            encoding="utf-8",
        )
        os.chmod(secret_path, 0o600)
        with mock.patch("boto3.client", return_value=mock.sentinel.client) as client:
            created, _secret = harness._storage_s3_client(secret_path)

        self.assertIs(created, mock.sentinel.client)
        config = client.call_args.kwargs["config"]
        self.assertEqual(config.request_checksum_calculation, "when_required")
        self.assertEqual(config.response_checksum_validation, "when_required")

    def test_hash_mismatch_never_persists_restore_or_seed_success(self):
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_DATA_BYTES": "4096"},
        )
        payload, digest, byte_count = harness._payload()
        ssh = mock.MagicMock()
        expected = {"sha256": digest, "byte_count": byte_count}
        mismatched = {"sha256": "0" * 64, "byte_count": byte_count}
        with mock.patch.object(harness, "_ssh_client", return_value=ssh), mock.patch.object(
            harness, "_upload_payload", return_value="/tmp/payload"
        ), mock.patch.object(harness, "_ssh_run", return_value=""), mock.patch.object(
            harness, "_mount_volume"
        ), mock.patch.object(
            harness, "_remote_evidence", side_effect=[expected, mismatched]
        ):
            with self.assertRaisesRegex(HarnessError, "hash evidence"):
                harness._seed_data(
                    mock.MagicMock(),
                    mock.MagicMock(),
                    instance_id="ocid1.instance.oc1.iad.instance",
                    block_volume_id="ocid1.volume.oc1.iad.volume",
                    boot_volume_id="ocid1.bootvolume.oc1.iad.boot",
                )
        self.assertEqual(len(payload), byte_count)
        self.assertIsNone(harness.evidence.get("payload"))

    def test_storage_verification_requires_versioned_hash_witness_before_get(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)
        s3 = mock.MagicMock()
        manifest = {
            "objects": [
                {
                    "kind": "website",
                    "key": f"{self.run_id}/website.zip",
                    "sha256": "a" * 64,
                    "byte_count": 10,
                    "etag": "etag",
                    "version_id": "",
                },
                {
                    "kind": "database",
                    "key": f"{self.run_id}/database.zip",
                    "sha256": "b" * 64,
                    "byte_count": 10,
                    "etag": "etag",
                    "version_id": "version-two",
                },
            ]
        }
        with mock.patch.object(
            harness, "_storage_s3_client", return_value=(s3, secret)
        ):
            with self.assertRaisesRegex(HarnessError, "witness failed"):
                harness._verify_storage_objects(manifest)
        s3.get_object.assert_not_called()

    def test_graph_delete_lost_response_adopts_exact_absence_without_replay(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.side_effect = [
            response([volume]),
            response([]),
        ]
        clients["block"].delete_volume.side_effect = TimeoutError("lost response")

        self.assertEqual(harness._cleanup_graph_kind("source_block_volume"), "DELETED")
        clients["block"].delete_volume.assert_called_once()
        self.assertEqual(
            harness.ledger.get("source_block_volume", volume.id)["cleanup_state"],
            "deleted",
        )
        self.assertFalse(
            any(key.startswith("cleanup:") for key in harness.intents.pending())
        )

    def test_graph_unknown_response_with_live_resource_is_manual_and_never_replayed(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.return_value = response([volume])
        clients["block"].delete_volume.side_effect = TimeoutError("accepted-but-lost")

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        self.assertEqual(
            harness.ledger.get("source_block_volume", volume.id)["cleanup_state"],
            "manual_review",
        )
        clients["block"].delete_volume.assert_called_once()

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        clients["block"].delete_volume.assert_called_once()

    def test_prepared_cleanup_intent_is_fail_closed_before_provider_call(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        key = harness._cleanup_intent_key(
            "source_block_volume", volume.id, "delete_volume"
        )
        harness.intents.put(
            key,
            {
                "operation": "delete_volume",
                "kind": "source_block_volume",
                "name": volume.display_name,
                "marker": self.run_id,
                "provider_resource_id": volume.id,
                "state": "prepared",
            },
        )
        clients["block"].list_volumes.return_value = response([volume])

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        clients["block"].delete_volume.assert_not_called()

    def test_graph_success_polls_accepted_termination_to_terminal_state(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        instance = SimpleNamespace(
            id="ocid1.instance.oc1.iad.backupsheeptest",
            display_name=harness.names["source_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            image_id="ocid1.image.oc1.iad.backupsheeptest",
            source_details=None,
            freeform_tags=harness._source_tags("source_instance"),
        )
        proof = harness._expected_proof(
            name=instance.display_name,
            tags=instance.freeform_tags,
            availability_domain=self.availability_domain,
            source_id=instance.image_id,
        )
        harness._record(
            "source_instance", instance, proof, source_id=instance.image_id
        )
        terminated = SimpleNamespace(**{**vars(instance), "lifecycle_state": "TERMINATED"})
        clients["compute"].list_instances.side_effect = [
            response([instance]),
            response([terminated]),
        ]
        clients["compute"].terminate_instance.return_value = response(status=202)

        self.assertEqual(harness._cleanup_graph_kind("source_instance"), "DELETED")
        clients["compute"].terminate_instance.assert_called_once_with(
            instance_id=instance.id,
            preserve_boot_volume=True,
        )

    def test_graph_detach_persists_intent_and_adopts_detached_attachment(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        attachment = SimpleNamespace(
            id="ocid1.volumeattachment.oc1.iad.backupsheeptest",
            display_name=harness.names["source_block_attachment"],
            compartment_id=self.compartment_id,
            lifecycle_state="ATTACHED",
        )
        proof = harness._expected_proof(
            name=attachment.display_name,
            tags={},
        )
        harness._record("source_block_attachment", attachment, proof)
        clients["compute"].list_volume_attachments.side_effect = [
            response([attachment]),
            response([]),
        ]
        clients["compute"].detach_volume.return_value = response(status=202)
        with mock.patch.object(harness, "_unmount_test_attachment") as unmount:
            self.assertEqual(
                harness._cleanup_graph_kind("source_block_attachment"), "DELETED"
            )
        unmount.assert_called_once_with("source_block_attachment")
        clients["compute"].detach_volume.assert_called_once_with(
            volume_attachment_id=attachment.id
        )

    def test_default_cleanup_api_refuses_to_revoke_retained_iam_user(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        user = self._iam_user(harness)
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        with self.assertRaisesRegex(HarnessError, "preserves customer credentials"):
            harness._cleanup_storage_kind(
                "iam_user", tenancy_id=self.tenancy_id, namespace="namespace"
            )
        clients["identity"].delete_user.assert_not_called()
        self.assertEqual(
            harness.ledger.get("iam_user", user.id)["cleanup_state"], "eligible"
        )

    def test_retained_iam_readback_marks_user_retained_without_delete(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        user = self._iam_user(harness)
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        clients["identity"].list_users.return_value = response([user])
        self.assertEqual(
            harness._retain_storage_kind(
                "iam_user", tenancy_id=self.tenancy_id, namespace="namespace"
            ),
            "USER_RETAINED",
        )
        clients["identity"].delete_user.assert_not_called()

    def test_object_version_delete_lost_response_reconciles_before_bucket_delete(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket, _user, _scope = self.establish_storage_scope(harness)
        key = f"{self.run_id}/website.zip"
        version = SimpleNamespace(name=key, version_id="version-one")
        current = SimpleNamespace(name=key)
        clients["object"].get_bucket.side_effect = [
            response(bucket),
            response(status=404),
        ]
        clients["object"].list_object_versions.side_effect = [
            response([version]),
            response([]),
            response([]),
        ]
        clients["object"].list_objects.side_effect = [
            response(SimpleNamespace(objects=[current], next_start_with=None)),
            response(SimpleNamespace(objects=[], next_start_with=None)),
            response(SimpleNamespace(objects=[], next_start_with=None)),
        ]
        clients["object"].delete_object.side_effect = TimeoutError("lost response")
        clients["object"].delete_bucket.return_value = response(status=204)

        self.assertEqual(
            harness._cleanup_bucket(
                harness.ledger.get("object_bucket", bucket.id),
                namespace="namespace",
            ),
            "DELETED",
        )
        clients["object"].delete_object.assert_called_once()
        clients["object"].delete_bucket.assert_called_once()
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket.id)["cleanup_state"],
            "deleted",
        )

    def test_object_version_unknown_response_is_manual_and_never_replayed(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket, _user, _scope = self.establish_storage_scope(harness)
        key_name = f"{self.run_id}/website.zip"
        version = SimpleNamespace(name=key_name, version_id="version-one")
        current = SimpleNamespace(name=key_name)
        clients["object"].get_bucket.return_value = response(bucket)
        clients["object"].list_object_versions.return_value = response([version])
        clients["object"].list_objects.return_value = response(
            SimpleNamespace(objects=[current], next_start_with=None)
        )
        clients["object"].delete_object.side_effect = TimeoutError("lost response")
        row = harness.ledger.get("object_bucket", bucket.id)

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_bucket(row, namespace="namespace")
        clients["object"].delete_object.assert_called_once()
        clients["object"].delete_bucket.assert_not_called()
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket.id)["cleanup_state"],
            "manual_review",
        )

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_bucket(row, namespace="namespace")
        clients["object"].delete_object.assert_called_once()

    def test_bucket_cleanup_refuses_any_object_outside_exact_run_prefix(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket = SimpleNamespace(
            id="ocid1.bucket.oc1.iad.backupsheeptest",
            name=harness.names["object_bucket"],
            compartment_id=self.compartment_id,
            lifecycle_state="ACTIVE",
            versioning="Enabled",
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "object_bucket",
            },
        )
        harness._record_storage(
            "object_bucket",
            bucket,
            resource_id=bucket.id,
            name=bucket.name,
            compartment_id=self.compartment_id,
            tags=bucket.freeform_tags,
        )
        clients["object"].list_buckets.return_value = response([bucket])
        clients["object"].get_bucket.return_value = response(bucket)
        clients["object"].list_object_versions.return_value = response(
            SimpleNamespace(
                items=[
                    SimpleNamespace(
                        name="foreign-prefix/do-not-delete.zip",
                        version_id="version-one",
                        is_delete_marker=False,
                    )
                ],
                prefixes=[],
            )
        )
        clients["object"].list_objects.return_value = response(
            SimpleNamespace(objects=[], next_start_with=None)
        )
        row = harness.ledger.get("object_bucket", bucket.id)

        with self.assertRaisesRegex(HarnessError, "outside the run prefix"):
            harness._cleanup_bucket(row, namespace="safe_namespace")

        clients["object"].delete_object.assert_not_called()
        clients["object"].delete_bucket.assert_not_called()
