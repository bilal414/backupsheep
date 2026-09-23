import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import TestCase, mock

from scripts import digitalocean_live_e2e as harness_module


RUN_ID = "bs-e2e-do-safety-test"
TEAM_UUID = "personal-team-uuid"
PREFIX = f"ui/{RUN_ID}/"


def manifest_object(kind, *, index=1):
    payload = f"{kind}-payload".encode()
    checksum = hashlib.sha256(payload).hexdigest()
    return {
        "kind": kind,
        "key": f"{PREFIX}{kind}/fixture-{index}.bin",
        "version_id": f"version-{index}",
        "sha256": checksum,
        "etag": f"etag-{index}",
        "backup_id": str(index),
        "byte_count": len(payload),
        "metadata": {
            "backupsheep-backup-id": str(index),
            "backupsheep-bytes": str(len(payload)),
            "backupsheep-sha256": checksum,
        },
    }


def manifest_payload():
    return {
        "schema": 1,
        "run_id": RUN_ID,
        "prefix": PREFIX,
        "objects": [
            manifest_object("website", index=1),
            manifest_object("database", index=2),
        ],
    }


class DigitalOceanFirewallAndVolumeSafetyTests(TestCase):
    def restore_harness(self, *, resource_type):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_tag = RUN_ID
        harness.account = {"team_uuid": TEAM_UUID}
        harness.headers = {"Authorization": "Bearer redacted"}
        harness.payload_expectation = {"sha256": "a" * 64, "byte_count": 1}
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": TEAM_UUID,
                "run_tag": RUN_ID,
                "snapshot_marker": "snapshot-marker",
                "source_id": "source-1",
                "resource_type": resource_type,
            },
        }
        return harness

    def test_non_apply_droplet_verification_never_attaches_firewall(self):
        harness = self.restore_harness(resource_type="droplet")
        candidate = {
            "id": 901,
            "name": "restored-droplet",
            "tags": ["restore-marker", "backupsheep-restore-droplet"],
            "image": {"id": 123456},
            "region": {"slug": "nyc3"},
            "size_slug": "s-1vcpu-1gb",
            "status": "active",
        }
        harness._read_resource = mock.Mock(return_value=candidate)
        harness._attach_payload_firewall = mock.Mock()
        harness.wait_droplet_active = mock.Mock()
        harness.wait_payload_ready = mock.Mock()
        harness.record_payload_verification = mock.Mock()

        with mock.patch.object(
            harness_module, "iter_collection", return_value=[candidate]
        ):
            result = harness.verify_ui_restore(
                target_kind="droplet",
                provider_id="901",
                name="restored-droplet",
                snapshot_id="123456",
                run_tag=RUN_ID,
                snapshot_marker="snapshot-marker",
                restore_marker="restore-marker",
            )

        self.assertNotIn("firewall_attached", result)
        self.assertEqual(result["status"], "CONTROL_PLANE_ONLY")
        self.assertNotIn("payload_verified", result)
        self.assertFalse(result["cleanup_evidence_recorded"])
        harness._attach_payload_firewall.assert_not_called()
        harness.wait_droplet_active.assert_not_called()
        harness.wait_payload_ready.assert_not_called()
        harness.ledger.record.assert_not_called()

    def test_firewall_action_requires_both_environment_gates_before_provider_read(self):
        args = harness_module._parser().parse_args(
            [
                "--run-id",
                RUN_ID,
                "--ledger",
                "/tmp/nonexistent-digitalocean-safety-ledger.json",
                "--team-uuid",
                TEAM_UUID,
                "--verify-ui-droplet-restore",
                "--attach-ui-droplet-firewall",
            ]
        )
        for apply, firewall_apply in (("", ""), ("YES", "")):
            with self.subTest(apply=apply, firewall_apply=firewall_apply), mock.patch.dict(
                os.environ,
                {
                    "DIGITALOCEAN_TOKEN": "credential-canary",
                    "BACKUPSHEEP_E2E_APPLY": apply,
                    "BACKUPSHEEP_E2E_FIREWALL_APPLY": firewall_apply,
                },
            ), mock.patch.object(harness_module, "get_json") as provider_read:
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.DigitalOceanHarness(args)
                provider_read.assert_not_called()

    def test_firewall_action_is_classified_as_mutation_and_requires_exact_team_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.json"
            args = harness_module._parser().parse_args(
                [
                    "--run-id",
                    RUN_ID,
                    "--ledger",
                    str(ledger),
                    "--team-uuid",
                    TEAM_UUID,
                    "--verify-ui-droplet-restore",
                    "--attach-ui-droplet-firewall",
                ]
            )
            account = {
                "account": {
                    "uuid": "account-uuid",
                    "status": "active",
                    "team": {"name": "Personal", "uuid": "foreign-team"},
                }
            }
            with mock.patch.dict(
                os.environ,
                {
                    "DIGITALOCEAN_TOKEN": "credential-canary",
                    "BACKUPSHEEP_E2E_APPLY": "YES",
                    "BACKUPSHEEP_E2E_FIREWALL_APPLY": "YES",
                },
            ), mock.patch.object(harness_module, "get_json", return_value=account):
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.DigitalOceanHarness(args)
            self.assertFalse(ledger.exists())

    def test_firewall_action_requires_uuid_allowlist_before_provider_read(self):
        args = harness_module._parser().parse_args(
            [
                "--run-id",
                RUN_ID,
                "--ledger",
                "/tmp/nonexistent-digitalocean-safety-ledger.json",
                "--verify-ui-droplet-restore",
                "--attach-ui-droplet-firewall",
            ]
        )
        with mock.patch.dict(
            os.environ,
            {
                "DIGITALOCEAN_TOKEN": "credential-canary",
                "BACKUPSHEEP_E2E_APPLY": "YES",
                "BACKUPSHEEP_E2E_FIREWALL_APPLY": "YES",
            },
        ), mock.patch.object(harness_module, "get_json") as provider_read:
            with self.assertRaises(harness_module.HarnessError):
                harness_module.DigitalOceanHarness(args)
        provider_read.assert_not_called()

    def test_firewall_mutation_boundary_rechecks_all_gates(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.apply = False
        harness.attach_ui_droplet_firewall = True
        harness.expected_team_uuid = TEAM_UUID
        harness.account = {"team_uuid": TEAM_UUID, "team_name": "Personal"}
        harness.ledger = mock.Mock()
        with mock.patch.dict(
            os.environ, {"BACKUPSHEEP_E2E_FIREWALL_APPLY": "YES"}
        ):
            with self.assertRaises(harness_module.HarnessError):
                harness._attach_payload_firewall("901")
        harness.ledger.entries.assert_not_called()

    def test_volume_ownership_checks_precede_every_ledger_write(self):
        base = {
            "id": 902,
            "name": "restored-volume",
            "tags": ["restore-marker", "backupsheep-restore-volume"],
            "snapshot_id": 123456,
            "region": {"slug": "nyc3"},
            "size_gigabytes": 7,
            "droplet_ids": [],
            "status": "available",
        }
        invalid = {
            "wrong-region": {"region": {"slug": "sfo3"}},
            "wrong-size": {"size_gigabytes": 8},
            "missing-attachments": {"droplet_ids": None},
            "attached": {"droplet_ids": [42]},
        }
        for label, changes in invalid.items():
            with self.subTest(label=label):
                harness = self.restore_harness(resource_type="volume")
                candidate = {**base, **changes}
                harness._read_resource = mock.Mock(return_value=candidate)
                with mock.patch.object(
                    harness_module, "iter_collection", return_value=[candidate]
                ):
                    with self.assertRaises(harness_module.HarnessError):
                        harness.verify_ui_restore(
                            target_kind="volume",
                            provider_id="902",
                            name="restored-volume",
                            snapshot_id="123456",
                            run_tag=RUN_ID,
                            snapshot_marker="snapshot-marker",
                            restore_marker="restore-marker",
                            expected_region="nyc3",
                            expected_size_gigabytes=7,
                        )
                harness.ledger.record.assert_not_called()

    def test_volume_requires_positive_expected_size_before_inventory_or_ledger(self):
        for value in (None, 0, -1, True, 7.5):
            with self.subTest(value=value):
                harness = self.restore_harness(resource_type="volume")
                with mock.patch.object(harness_module, "iter_collection") as inventory:
                    with self.assertRaises(harness_module.HarnessError):
                        harness.verify_ui_restore(
                            target_kind="volume",
                            provider_id="902",
                            name="restored-volume",
                            snapshot_id="123456",
                            run_tag=RUN_ID,
                            snapshot_marker="snapshot-marker",
                            restore_marker="restore-marker",
                            expected_region="nyc3",
                            expected_size_gigabytes=value,
                        )
                inventory.assert_not_called()
                harness.ledger.record.assert_not_called()


class DigitalOceanSpacesSafetyTests(TestCase):
    def bucket_ownership(self, *, created_at="2026-08-12T00:00:00+00:00"):
        creation = {
            "bucket": "owned-bucket",
            "region": "nyc3",
            "prefix": PREFIX,
            "acl": "private",
            "versioning": "Enabled",
            "created_at": created_at,
        }
        return {
            "team_uuid": TEAM_UUID,
            "run_tag": RUN_ID,
            "region": "nyc3",
            "prefix": PREFIX,
            "versioning": "Enabled",
            "creation_witness": {
                **creation,
                "immutable_fingerprint": harness_module._fingerprint(creation),
            },
        }

    def client(self, *, versioning="Enabled", region="nyc3"):
        client = mock.Mock()
        client.list_buckets.return_value = {
            "Buckets": [
                {
                    "Name": "owned-bucket",
                    "CreationDate": "2026-08-12T00:00:00+00:00",
                }
            ]
        }
        client.head_bucket.return_value = {}
        client.get_bucket_location.return_value = {
            "LocationConstraint": region
        }
        client.get_bucket_versioning.return_value = {"Status": versioning}
        return client

    def test_bucket_state_is_freshly_read_and_compared_to_creation_witness(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        client = self.client()

        result = harness._verify_spaces_bucket_state(
            client, bucket="owned-bucket", ownership=self.bucket_ownership()
        )

        self.assertEqual(result["region"], "nyc3")
        self.assertEqual(result["versioning"], "Enabled")
        client.list_buckets.assert_called_once_with()
        client.head_bucket.assert_called_once_with(Bucket="owned-bucket")
        client.get_bucket_location.assert_called_once_with(Bucket="owned-bucket")
        client.get_bucket_versioning.assert_called_once_with(Bucket="owned-bucket")

    def test_bucket_drift_stops_before_any_object_read_or_ledger_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = object.__new__(harness_module.DigitalOceanHarness)
            harness.account = {"team_uuid": TEAM_UUID}
            harness.run_id = RUN_ID
            harness.run_tag = RUN_ID
            harness.region = "nyc3"
            harness.spaces_prefix = PREFIX
            harness.spaces_secret_path = root / "spaces.json"
            credentials = {
                "endpoint_url": "https://nyc3.digitaloceanspaces.com",
                "region": "nyc3",
                "bucket": "owned-bucket",
                "access_key": "ACCESS-CANARY",
                "secret_key": "SECRET-CANARY",
            }
            harness_module._write_runtime_secret(harness.spaces_secret_path, credentials)
            ownership = {
                **self.bucket_ownership(),
                "access_key_sha256": harness._spaces_key_hash(credentials["access_key"]),
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode()
                ).hexdigest(),
            }
            harness.ledger = mock.Mock()
            harness.ledger.get.return_value = {
                "cleanup_state": "eligible",
                "ownership": ownership,
            }
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(manifest_payload()))
            client = self.client(versioning="Suspended")
            harness._spaces_inventory = mock.Mock()

            with mock.patch.object(
                harness_module, "_spaces_client", return_value=client
            ):
                with self.assertRaises(harness_module.HarnessError):
                    harness.verify_spaces_ui_uploads(
                        str(manifest), maximum_bytes=1024
                    )

            harness._spaces_inventory.assert_not_called()
            client.head_object.assert_not_called()
            client.get_object.assert_not_called()
            harness.ledger.record.assert_not_called()


class DigitalOceanManifestAndReportSafetyTests(TestCase):
    def test_manifest_rejects_unknown_envelope_row_and_legacy_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            valid = manifest_payload()
            path.write_text(json.dumps(valid))
            parsed = harness_module._load_ui_object_manifest(
                str(path), run_id=RUN_ID, prefix=PREFIX, maximum_bytes=1024
            )
            self.assertEqual(len(parsed), 2)

            invalid = []
            envelope = json.loads(json.dumps(valid))
            envelope["unknown"] = True
            invalid.append(envelope)
            row = json.loads(json.dumps(valid))
            row["objects"][0]["unknown"] = True
            invalid.append(row)
            legacy = json.loads(json.dumps(valid))
            legacy["objects"][0]["metadata"]["backupsheep-size"] = "1"
            invalid.append(legacy)
            boolean_bytes = json.loads(json.dumps(valid))
            boolean_bytes["objects"][0]["byte_count"] = True
            invalid.append(boolean_bytes)
            for candidate in invalid:
                path.write_text(json.dumps(candidate))
                with self.subTest(candidate=candidate):
                    with self.assertRaises(harness_module.HarnessError):
                        harness_module._load_ui_object_manifest(
                            str(path),
                            run_id=RUN_ID,
                            prefix=PREFIX,
                            maximum_bytes=1024,
                        )

    def test_report_is_local_only_and_leaves_every_artifact_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "ledger.json"
            intents = root / "ledger.json.mutation-intents.json"
            manifest = root / "manifest.json"
            ledger.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "provider": "digitalocean",
                        "run_id": RUN_ID,
                        "scope": TEAM_UUID,
                        "created_at": "2026-08-12T00:00:00+00:00",
                        "resources": [],
                    },
                    sort_keys=True,
                )
            )
            intents.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "provider": "digitalocean",
                        "run_id": RUN_ID,
                        "scope": TEAM_UUID,
                        "pending": {},
                    },
                    sort_keys=True,
                )
            )
            manifest.write_text(json.dumps(manifest_payload(), sort_keys=True))
            before_names = sorted(path.name for path in root.iterdir())
            before_bytes = {path.name: path.read_bytes() for path in root.iterdir()}
            output = io.StringIO()

            with mock.patch.object(
                harness_module, "DigitalOceanHarness"
            ) as provider_harness, mock.patch.object(
                harness_module, "get_json"
            ) as provider_get, mock.patch.object(
                harness_module, "_read_runtime_secret"
            ) as secret_read, mock.patch.object(
                harness_module, "_spaces_client"
            ) as spaces_client, redirect_stdout(output):
                result = harness_module.main(
                    [
                        "--report",
                        "--run-id",
                        RUN_ID,
                        "--ledger",
                        str(ledger),
                        "--team-uuid",
                        TEAM_UUID,
                        "--spaces-prefix",
                        PREFIX,
                        "--spaces-ui-upload-manifest",
                        str(manifest),
                    ]
                )

            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["mode"], "local-read-only")
            self.assertEqual(report["storage_manifest"]["object_count"], 2)
            provider_harness.assert_not_called()
            provider_get.assert_not_called()
            secret_read.assert_not_called()
            spaces_client.assert_not_called()
            self.assertEqual(sorted(path.name for path in root.iterdir()), before_names)
            self.assertEqual(
                {path.name: path.read_bytes() for path in root.iterdir()}, before_bytes
            )
            self.assertFalse((root / "ledger.json.lock").exists())

    def test_report_rejects_operational_flags_before_constructing_harness(self):
        args = harness_module._parser().parse_args(
            ["--report", "--run-id", RUN_ID, "--provision-sources"]
        )
        with self.assertRaises(harness_module.HarnessError):
            harness_module._local_read_only_report(args)


class DigitalOceanLegacyNormalizationSafetyTests(TestCase):
    SOURCE_DROPLET_ID = "101"
    SOURCE_VOLUME_ID = "202"
    FIREWALL_ID = "303"
    DROPLET_SNAPSHOT_ID = "401"
    VOLUME_SNAPSHOT_ID = "402"
    RESTORE_DROPLET_ID = "501"
    RESTORE_VOLUME_ID = "502"
    DROPLET_SNAPSHOT_MARKER = "ui-droplet-snapshot-marker"
    VOLUME_SNAPSHOT_MARKER = "ui-volume-snapshot-marker"
    DROPLET_RESTORE_MARKER = "ui-droplet-restore-marker"
    VOLUME_RESTORE_MARKER = "ui-volume-restore-marker"
    CREATED_AT = "2026-08-12T00:00:00+00:00"
    PROBE_CIDR = "203.0.113.10/32"
    CONTENT_SHA256 = "b" * 64

    def fixture(self, root):
        bucket = harness_module._spaces_bucket_name(RUN_ID, TEAM_UUID, "nyc3")
        access_key = "FAKE-NORMALIZATION-ACCESS-KEY"
        key_hash = hashlib.sha256(access_key.encode()).hexdigest()
        source_droplet_name = harness_module._resource_name(RUN_ID, "droplet")
        source_volume_name = harness_module._resource_name(RUN_ID, "volume")
        firewall_name = harness_module._resource_name(RUN_ID, "payload-firewall")
        key_name = harness_module._resource_name(RUN_ID, "spaces-key")
        droplet_tags = sorted(
            {
                RUN_ID,
                self.DROPLET_RESTORE_MARKER,
                "backupsheep-restore-droplet",
                harness_module._digitalocean_source_tag(
                    self.DROPLET_SNAPSHOT_ID
                ),
            }
        )
        volume_tags = sorted(
            {
                RUN_ID,
                self.VOLUME_RESTORE_MARKER,
                "backupsheep-restore-volume",
                harness_module._digitalocean_source_tag(self.VOLUME_SNAPSHOT_ID),
            }
        )
        source_droplet = {
            "id": int(self.SOURCE_DROPLET_ID),
            "name": source_droplet_name,
            "tags": [RUN_ID],
            "region": {"slug": "nyc3"},
            "size_slug": "s-1vcpu-1gb",
            "image": {"slug": "ubuntu-24-04-x64"},
            "created_at": self.CREATED_AT,
        }
        source_volume = {
            "id": self.SOURCE_VOLUME_ID,
            "name": source_volume_name,
            "tags": [RUN_ID],
            "region": {"slug": "nyc3"},
            "size_gigabytes": 7,
            "droplet_ids": [],
            "created_at": self.CREATED_AT,
        }
        firewall = {
            "id": self.FIREWALL_ID,
            "name": firewall_name,
            "droplet_ids": [
                int(self.SOURCE_DROPLET_ID),
                int(self.RESTORE_DROPLET_ID),
            ],
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": str(harness_module.PAYLOAD_PORT),
                    "sources": {"addresses": [self.PROBE_CIDR]},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": protocol,
                    "ports": "0",
                    "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                }
                for protocol in ("tcp", "udp", "icmp")
            ],
        }
        droplet_snapshot = {
            "id": int(self.DROPLET_SNAPSHOT_ID),
            "name": self.DROPLET_SNAPSHOT_MARKER,
            "resource_id": int(self.SOURCE_DROPLET_ID),
            "resource_type": "droplet",
        }
        volume_snapshot = {
            "id": int(self.VOLUME_SNAPSHOT_ID),
            "name": self.VOLUME_SNAPSHOT_MARKER,
            "resource_id": self.SOURCE_VOLUME_ID,
            "resource_type": "volume",
        }
        restore_droplet = {
            "id": int(self.RESTORE_DROPLET_ID),
            "name": "ui-restored-droplet",
            "tags": droplet_tags,
            "region": {"slug": "nyc3"},
            "size_slug": "s-1vcpu-1gb",
            "image": {"id": int(self.DROPLET_SNAPSHOT_ID)},
            "status": "active",
            "created_at": self.CREATED_AT,
        }
        restore_volume = {
            "id": self.RESTORE_VOLUME_ID,
            "name": "ui-restored-volume",
            "tags": volume_tags,
            "region": {"slug": "nyc3"},
            "size_gigabytes": 7,
            "droplet_ids": [],
            "snapshot_id": self.VOLUME_SNAPSHOT_ID,
            "status": "available",
            "created_at": self.CREATED_AT,
        }
        spaces_key = {
            "access_key": access_key,
            "name": key_name,
            "grants": [{"bucket": "", "permission": "fullaccess"}],
        }
        resources = [
            {
                "kind": "source_droplet",
                "resource_id": self.SOURCE_DROPLET_ID,
                "name": source_droplet_name,
                "ownership": {"team_uuid": TEAM_UUID, "run_tag": RUN_ID},
            },
            {
                "kind": "source_volume",
                "resource_id": self.SOURCE_VOLUME_ID,
                "name": source_volume_name,
                "ownership": {"team_uuid": TEAM_UUID, "run_tag": RUN_ID},
            },
            {
                "kind": "payload_firewall",
                "resource_id": self.FIREWALL_ID,
                "name": firewall_name,
                "ownership": {
                    "team_uuid": TEAM_UUID,
                    "run_tag": RUN_ID,
                    "source_droplet_id": self.SOURCE_DROPLET_ID,
                    "probe_cidrs": [self.PROBE_CIDR],
                },
            },
            {
                "kind": "spaces_bucket",
                "resource_id": bucket,
                "name": bucket,
                "ownership": {
                    "team_uuid": TEAM_UUID,
                    "run_tag": RUN_ID,
                    "region": "nyc3",
                    "prefix": PREFIX,
                    "versioning": "Enabled",
                    "access_key_sha256": key_hash,
                    "endpoint_sha256": hashlib.sha256(
                        b"https://nyc3.digitaloceanspaces.com"
                    ).hexdigest(),
                },
            },
            {
                "kind": "spaces_key",
                "resource_id": key_hash,
                "name": key_name,
                "ownership": {
                    "team_uuid": TEAM_UUID,
                    "run_tag": RUN_ID,
                    "access_key_sha256": key_hash,
                    "permission": "fullaccess",
                },
            },
            {
                "kind": "ui_snapshot_droplet",
                "resource_id": self.DROPLET_SNAPSHOT_ID,
                "name": self.DROPLET_SNAPSHOT_MARKER,
                "ownership": {
                    "team_uuid": TEAM_UUID,
                    "run_tag": RUN_ID,
                    "marker": self.DROPLET_SNAPSHOT_MARKER,
                    "source_id": self.SOURCE_DROPLET_ID,
                    "resource_type": "droplet",
                },
            },
            {
                "kind": "ui_snapshot_volume",
                "resource_id": self.VOLUME_SNAPSHOT_ID,
                "name": self.VOLUME_SNAPSHOT_MARKER,
                "ownership": {
                    "team_uuid": TEAM_UUID,
                    "run_tag": RUN_ID,
                    "marker": self.VOLUME_SNAPSHOT_MARKER,
                    "source_id": self.SOURCE_VOLUME_ID,
                    "resource_type": "volume",
                },
            },
        ]
        verifier_droplet_id = "601"
        source_live = {
            "schema": harness_module.NATIVE_VOLUME_VERIFIER_SCHEMA,
            "team_uuid": TEAM_UUID,
            "run_tag": RUN_ID,
            "proof": "LIVE_NATIVE_VOLUME_SOURCE_WRITE_READ",
            "volume_id": self.SOURCE_VOLUME_ID,
            "volume_name": source_volume_name,
            "verifier_droplet_id": verifier_droplet_id,
            "observed_region": "nyc3",
            "size_gigabytes": 7,
            "stable_device": harness_module._native_volume_device_path(
                source_volume_name
            ),
            "resolved_device": "/dev/sdb",
            "device_size_bytes": 7 * 1024 * 1024 * 1024,
            "offset_bytes": harness_module.NATIVE_VOLUME_DEFAULT_OFFSET_BYTES,
            "byte_count": 4096,
            "sha256": self.CONTENT_SHA256,
            "fixture_fingerprint": "c" * 64,
            "guest_observed_at": self.CREATED_AT,
            "guest_operation": "seed",
            "guest_write_performed": True,
            "client_fingerprint": "SHA256:client",
            "host_fingerprint": "SHA256:host",
            "attach_readback": {
                "volume_id": self.SOURCE_VOLUME_ID,
                "verifier_droplet_id": verifier_droplet_id,
                "droplet_ids": [verifier_droplet_id],
            },
            "detached_readback": {
                "volume_id": self.SOURCE_VOLUME_ID,
                "verifier_droplet_id": verifier_droplet_id,
                "droplet_ids": [],
                "observed_at": self.CREATED_AT,
            },
            "provider_detached": True,
            "provider_detached_at": self.CREATED_AT,
        }
        source_live["evidence_fingerprint"] = (
            harness_module.DigitalOceanHarness._native_volume_evidence_fingerprint(
                source_live
            )
        )
        restore_live = {
            "schema": harness_module.NATIVE_VOLUME_VERIFIER_SCHEMA,
            "team_uuid": TEAM_UUID,
            "run_tag": RUN_ID,
            "proof": "LIVE_NATIVE_VOLUME_RESTORE_READ_ONLY",
            "volume_id": self.RESTORE_VOLUME_ID,
            "volume_name": restore_volume["name"],
            "source_volume_id": self.SOURCE_VOLUME_ID,
            "source_evidence_fingerprint": source_live["evidence_fingerprint"],
            "verifier_droplet_id": verifier_droplet_id,
            "observed_region": "nyc3",
            "size_gigabytes": 7,
            "stable_device": harness_module._native_volume_device_path(
                restore_volume["name"]
            ),
            "resolved_device": "/dev/sdb",
            "device_size_bytes": 7 * 1024 * 1024 * 1024,
            "offset_bytes": source_live["offset_bytes"],
            "byte_count": source_live["byte_count"],
            "sha256": source_live["sha256"],
            "guest_observed_at": self.CREATED_AT,
            "guest_operation": "read",
            "read_only": True,
            "guest_write_performed": False,
            "client_fingerprint": source_live["client_fingerprint"],
            "host_fingerprint": source_live["host_fingerprint"],
            "attach_readback": {
                "volume_id": self.RESTORE_VOLUME_ID,
                "verifier_droplet_id": verifier_droplet_id,
                "droplet_ids": [verifier_droplet_id],
            },
            "detached_readback": {
                "volume_id": self.RESTORE_VOLUME_ID,
                "verifier_droplet_id": verifier_droplet_id,
                "droplet_ids": [],
                "observed_at": self.CREATED_AT,
            },
            "provider_detached": True,
            "provider_detached_at": self.CREATED_AT,
        }
        restore_live["evidence_fingerprint"] = (
            harness_module.DigitalOceanHarness._native_volume_evidence_fingerprint(
                restore_live
            )
        )
        resources.extend(
            [
                {
                    "kind": "native_volume_source_content_witness",
                    "resource_id": self.SOURCE_VOLUME_ID,
                    "name": source_volume_name,
                    "ownership": source_live,
                },
                {
                    "kind": "native_volume_restore_content_witness",
                    "resource_id": self.RESTORE_VOLUME_ID,
                    "name": restore_volume["name"],
                    "ownership": restore_live,
                },
            ]
        )
        for row in resources:
            row.update(
                {
                    "source_witness": f"legacy:{row['kind']}",
                    "created_at": self.CREATED_AT,
                    "cleanup_state": "eligible",
                    "cleanup_error": "",
                }
            )
        ledger = root / "ledger.json"
        ledger.write_bytes(
            (
                json.dumps(
                    {
                        "schema": 1,
                        "provider": "digitalocean",
                        "run_id": RUN_ID,
                        "scope": TEAM_UUID,
                        "created_at": self.CREATED_AT,
                        "resources": resources,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode()
        )
        os.chmod(ledger, 0o600)
        ledger_lock = root / "ledger.json.lock"
        ledger_lock.write_bytes(b"")
        os.chmod(ledger_lock, 0o600)
        intents = root / "ledger.json.mutation-intents.json"
        intents.write_bytes(
            (
                json.dumps(
                    {
                        "schema": 1,
                        "provider": "digitalocean",
                        "run_id": RUN_ID,
                        "scope": TEAM_UUID,
                        "pending": {},
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode()
        )
        os.chmod(intents, 0o600)
        intent_lock = root / "ledger.json.mutation-intents.json.lock"
        intent_lock.write_bytes(b"")
        os.chmod(intent_lock, 0o600)
        secret = root / "spaces.json"
        credentials = {
            "endpoint_url": "https://nyc3.digitaloceanspaces.com",
            "region": "nyc3",
            "bucket": bucket,
            "access_key": access_key,
            "secret_key": "FAKE-NORMALIZATION-SECRET",
        }
        harness_module._write_runtime_secret(secret, credentials)
        client = mock.Mock()
        client.list_buckets.return_value = {
            "Buckets": [{"Name": bucket, "CreationDate": self.CREATED_AT}]
        }
        client.head_bucket.return_value = {}
        client.get_bucket_location.return_value = {"LocationConstraint": "nyc3"}
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        return {
            "root": root,
            "ledger": ledger,
            "intents": intents,
            "secret": secret,
            "bucket": bucket,
            "access_key": access_key,
            "spaces_key": spaces_key,
            "client": client,
            "inventories": {
                "/v2/droplets": [source_droplet, restore_droplet],
                "/v2/volumes": [source_volume, restore_volume],
                "/v2/firewalls": [firewall],
                "/v2/snapshots": [droplet_snapshot, volume_snapshot],
            },
            "direct": {
                f"/v2/droplets/{self.SOURCE_DROPLET_ID}": {
                    "droplet": source_droplet
                },
                f"/v2/droplets/{self.RESTORE_DROPLET_ID}": {
                    "droplet": restore_droplet
                },
                f"/v2/volumes/{self.SOURCE_VOLUME_ID}": {"volume": source_volume},
                f"/v2/volumes/{self.RESTORE_VOLUME_ID}": {
                    "volume": restore_volume
                },
                f"/v2/firewalls/{self.FIREWALL_ID}": {"firewall": firewall},
                f"/v2/snapshots/{self.DROPLET_SNAPSHOT_ID}": {
                    "snapshot": droplet_snapshot
                },
                f"/v2/snapshots/{self.VOLUME_SNAPSHOT_ID}": {
                    "snapshot": volume_snapshot
                },
                f"/v2/spaces/keys/{access_key}": {"key": spaces_key},
            },
            "droplet_tags": droplet_tags,
            "volume_tags": volume_tags,
        }

    def argv(self, fixture, mode, report_sha256=None):
        expectation = harness_module._payload_expectation(RUN_ID)
        values = [
            "--normalize-legacy-ledger",
            mode,
            "--run-id",
            RUN_ID,
            "--ledger",
            str(fixture["ledger"]),
            "--team-uuid",
            TEAM_UUID,
            "--team-name",
            "Personal",
            "--region",
            "nyc3",
            "--droplet-size",
            "s-1vcpu-1gb",
            "--droplet-image",
            "ubuntu-24-04-x64",
            "--volume-size-gib",
            "7",
            "--probe-cidr",
            self.PROBE_CIDR,
            "--droplet-snapshot-marker",
            self.DROPLET_SNAPSHOT_MARKER,
            "--droplet-source-id",
            self.SOURCE_DROPLET_ID,
            "--volume-snapshot-marker",
            self.VOLUME_SNAPSHOT_MARKER,
            "--volume-source-id",
            self.SOURCE_VOLUME_ID,
            "--normalize-source-volume-unattached",
            "--normalize-firewall-source-droplet-id",
            self.SOURCE_DROPLET_ID,
            "--normalize-firewall-droplet-id",
            self.SOURCE_DROPLET_ID,
            "--normalize-firewall-droplet-id",
            self.RESTORE_DROPLET_ID,
            "--normalize-ui-droplet-restore",
            "--normalize-ui-droplet-guest-proof",
            "--ui-droplet-restore-id",
            self.RESTORE_DROPLET_ID,
            "--ui-droplet-restore-name",
            "ui-restored-droplet",
            "--ui-droplet-snapshot-marker",
            self.DROPLET_SNAPSHOT_MARKER,
            "--ui-droplet-restore-marker",
            self.DROPLET_RESTORE_MARKER,
            "--ui-droplet-restore-snapshot-id",
            self.DROPLET_SNAPSHOT_ID,
            "--ui-droplet-restore-run-tag",
            RUN_ID,
            "--ui-droplet-expected-region",
            "nyc3",
            "--ui-droplet-expected-size",
            "s-1vcpu-1gb",
            "--ui-droplet-payload-sha256",
            expectation["sha256"],
            "--ui-droplet-payload-byte-count",
            str(expectation["byte_count"]),
            "--normalize-ui-volume-restore",
            "--normalize-ui-volume-content-proof",
            "--ui-volume-restore-id",
            self.RESTORE_VOLUME_ID,
            "--ui-volume-restore-name",
            "ui-restored-volume",
            "--ui-volume-snapshot-marker",
            self.VOLUME_SNAPSHOT_MARKER,
            "--ui-volume-restore-marker",
            self.VOLUME_RESTORE_MARKER,
            "--ui-volume-restore-snapshot-id",
            self.VOLUME_SNAPSHOT_ID,
            "--ui-volume-restore-run-tag",
            RUN_ID,
            "--ui-volume-expected-region",
            "nyc3",
            "--ui-volume-expected-size-gib",
            "7",
            "--ui-volume-source-content-sha256",
            self.CONTENT_SHA256,
            "--ui-volume-source-content-byte-count",
            "4096",
            "--ui-volume-restore-content-sha256",
            self.CONTENT_SHA256,
            "--ui-volume-restore-content-byte-count",
            "4096",
            "--spaces-prefix",
            PREFIX,
            "--spaces-secret-file",
            str(fixture["secret"]),
        ]
        for tag in fixture["droplet_tags"]:
            values.extend(["--normalize-ui-droplet-tag", tag])
        for tag in fixture["volume_tags"]:
            values.extend(["--normalize-ui-volume-tag", tag])
        if report_sha256:
            values.extend(["--normalization-report-sha256", report_sha256])
        return values

    def provider_mocks(self, fixture):
        stack = ExitStack()

        def provider_get(path, **_kwargs):
            if path == "/v2/account":
                return {
                    "account": {
                        "uuid": "account-uuid",
                        "status": "active",
                        "team": {"name": "Personal", "uuid": TEAM_UUID},
                    }
                }
            if path in fixture["direct"]:
                return json.loads(json.dumps(fixture["direct"][path]))
            raise AssertionError(f"unexpected provider GET: {path}")

        def inventory(path, _key, **_kwargs):
            return json.loads(json.dumps(fixture["inventories"][path]))

        def spaces_call(operation, *, mutation=False, required_scope=None):
            self.assertFalse(mutation, required_scope)
            return operation()

        stack.enter_context(
            mock.patch.object(harness_module, "get_json", side_effect=provider_get)
        )
        stack.enter_context(
            mock.patch.object(harness_module, "iter_collection", side_effect=inventory)
        )
        stack.enter_context(
            mock.patch.object(
                harness_module,
                "_iter_provider_collection",
                return_value=[json.loads(json.dumps(fixture["spaces_key"]))],
            )
        )
        stack.enter_context(
            mock.patch.object(
                harness_module, "_spaces_client", return_value=fixture["client"]
            )
        )
        stack.enter_context(
            mock.patch.object(harness_module, "_spaces_call", side_effect=spaces_call)
        )
        mutation = stack.enter_context(
            mock.patch.object(
                harness_module,
                "_mutation_response",
                side_effect=AssertionError("provider mutation forbidden"),
            )
        )
        return stack, mutation

    @staticmethod
    def artifact_bytes(root):
        return {
            path.name: path.read_bytes()
            for path in root.iterdir()
            if path.is_file()
        }

    def run_report(self, fixture):
        output = io.StringIO()
        stack, mutation = self.provider_mocks(fixture)
        with stack, mock.patch.dict(
            os.environ, {"DIGITALOCEAN_TOKEN": "FAKE-TOKEN"}, clear=False
        ), redirect_stdout(output):
            self.assertEqual(harness_module.main(self.argv(fixture, "report")), 0)
        mutation.assert_not_called()
        return json.loads(output.getvalue())

    def test_dry_report_uses_only_reads_and_leaves_all_artifacts_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            before = self.artifact_bytes(fixture["root"])
            report = self.run_report(fixture)

            self.assertEqual(report["provider_mutation_count"], 0)
            self.assertEqual(report["requested_mode"], "report")
            self.assertFalse(report["ledger_updated"])
            self.assertEqual(report["ledger"]["current_resource_count"], 9)
            self.assertEqual(report["ledger"]["proposed_resource_count"], 11)
            self.assertEqual(len(report["witnesses"]), 9)
            self.assertEqual(self.artifact_bytes(fixture["root"]), before)
            fixture["client"].put_bucket_versioning.assert_not_called()

    def test_apply_requires_exact_report_hash_and_atomically_adds_full_e2e_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            report = self.run_report(fixture)
            intent_before = fixture["intents"].read_bytes()
            secret_before = fixture["secret"].read_bytes()
            output = io.StringIO()
            stack, mutation = self.provider_mocks(fixture)
            with stack, mock.patch.dict(
                os.environ,
                {
                    "DIGITALOCEAN_TOKEN": "FAKE-TOKEN",
                    harness_module.LEGACY_NORMALIZATION_APPLY_ENV: "YES",
                },
                clear=False,
            ), redirect_stdout(output):
                self.assertEqual(
                    harness_module.main(
                        self.argv(fixture, "apply", report["report_sha256"])
                    ),
                    0,
                )
            mutation.assert_not_called()
            applied = json.loads(output.getvalue())
            self.assertTrue(applied["ledger_updated"])
            self.assertEqual(stat.S_IMODE(fixture["ledger"].stat().st_mode), 0o600)
            normalized = json.loads(fixture["ledger"].read_text())
            rows = {row["kind"]: row for row in normalized["resources"]}
            for kind in harness_module.LEGACY_NORMALIZATION_KINDS:
                self.assertRegex(
                    rows[kind]["ownership"]["creation_witness"][
                        "immutable_fingerprint"
                    ],
                    r"^[0-9a-f]{64}$",
                )
            for kind in ("ui_restore_droplet", "ui_restore_volume"):
                self.assertEqual(
                    rows[kind]["ownership"]["verification_level"], "FULL_E2E"
                )
                self.assertTrue(rows[kind]["ownership"]["cleanup_authorized"])
            self.assertEqual(
                rows["ui_restore_volume"]["ownership"]["expected_droplet_ids"],
                [],
            )
            self.assertEqual(
                rows["ui_restore_volume"]["ownership"]["content_witness"][
                    "proof"
                ],
                "LIVE_NATIVE_VOLUME_BYTE_PROOF",
            )
            self.assertEqual(fixture["intents"].read_bytes(), intent_before)
            self.assertEqual(fixture["secret"].read_bytes(), secret_before)

    def test_apply_confirmation_gate_fails_before_provider_reads_or_local_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            report = self.run_report(fixture)
            before = self.artifact_bytes(fixture["root"])
            with mock.patch.object(harness_module, "get_json") as provider_get, mock.patch.dict(
                os.environ, {"DIGITALOCEAN_TOKEN": "FAKE-TOKEN"}, clear=False
            ):
                os.environ.pop(harness_module.LEGACY_NORMALIZATION_APPLY_ENV, None)
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.main(
                        self.argv(fixture, "apply", report["report_sha256"])
                    )
            provider_get.assert_not_called()
            self.assertEqual(self.artifact_bytes(fixture["root"]), before)

    def test_atomic_replace_failure_preserves_original_ledger_and_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            report = self.run_report(fixture)
            before = self.artifact_bytes(fixture["root"])
            stack, _mutation = self.provider_mocks(fixture)
            with stack, mock.patch.dict(
                os.environ,
                {
                    "DIGITALOCEAN_TOKEN": "FAKE-TOKEN",
                    harness_module.LEGACY_NORMALIZATION_APPLY_ENV: "YES",
                },
                clear=False,
            ), mock.patch.object(
                harness_module.os,
                "replace",
                side_effect=OSError("simulated atomic replace failure"),
            ):
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.main(
                        self.argv(fixture, "apply", report["report_sha256"])
                    )
            self.assertEqual(self.artifact_bytes(fixture["root"]), before)

    def test_provider_zero_duplicate_and_mismatch_failures_never_touch_ledger(self):
        mutations = {
            "zero-source": lambda fixture: fixture["inventories"].__setitem__(
                "/v2/droplets", fixture["inventories"]["/v2/droplets"][1:]
            ),
            "duplicate-snapshot-marker": lambda fixture: fixture["inventories"][
                "/v2/snapshots"
            ].append(
                {
                    **fixture["inventories"]["/v2/snapshots"][0],
                    "id": 999,
                }
            ),
            "source-volume-attached": lambda fixture: fixture["inventories"][
                "/v2/volumes"
            ][0].__setitem__("droplet_ids", [101]),
            "restore-volume-attached": lambda fixture: fixture["direct"][
                f"/v2/volumes/{self.RESTORE_VOLUME_ID}"
            ]["volume"].__setitem__("droplet_ids", [101]),
            "wrong-key-grant": lambda fixture: fixture["spaces_key"].__setitem__(
                "grants", [{"bucket": "", "permission": "readonly"}]
            ),
            "bucket-versioning-disabled": lambda fixture: fixture["client"].get_bucket_versioning.configure_mock(
                return_value={"Status": "Suspended"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(Path(temporary))
                mutate(fixture)
                before = fixture["ledger"].read_bytes()
                stack, mutation = self.provider_mocks(fixture)
                with stack, mock.patch.dict(
                    os.environ,
                    {
                        "DIGITALOCEAN_TOKEN": "FAKE-TOKEN",
                        harness_module.LEGACY_NORMALIZATION_APPLY_ENV: "YES",
                    },
                    clear=False,
                ):
                    with self.assertRaises(harness_module.HarnessError):
                        harness_module.main(self.argv(fixture, "apply", "0" * 64))
                mutation.assert_not_called()
                self.assertEqual(fixture["ledger"].read_bytes(), before)

    def test_stale_report_hash_leaves_externally_changed_ledger_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            report = self.run_report(fixture)
            payload = json.loads(fixture["ledger"].read_text())
            payload["operator_note"] = "concurrent-change"
            fixture["ledger"].write_text(json.dumps(payload, sort_keys=True) + "\n")
            os.chmod(fixture["ledger"], 0o600)
            changed = fixture["ledger"].read_bytes()
            stack, _mutation = self.provider_mocks(fixture)
            with stack, mock.patch.dict(
                os.environ,
                {
                    "DIGITALOCEAN_TOKEN": "FAKE-TOKEN",
                    harness_module.LEGACY_NORMALIZATION_APPLY_ENV: "YES",
                },
                clear=False,
            ):
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.main(
                        self.argv(fixture, "apply", report["report_sha256"])
                    )
            self.assertEqual(fixture["ledger"].read_bytes(), changed)

    def test_normalization_rejects_recursive_duplicate_ledger_keys_before_provider_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            text = fixture["ledger"].read_text()
            needle = f'"team_uuid": "{TEAM_UUID}",'
            self.assertIn(needle, text)
            fixture["ledger"].write_text(
                text.replace(needle, f"{needle}\n          {needle}", 1)
            )
            os.chmod(fixture["ledger"], 0o600)
            before = fixture["ledger"].read_bytes()
            with mock.patch.object(harness_module, "get_json") as provider_get, mock.patch.dict(
                os.environ, {"DIGITALOCEAN_TOKEN": "FAKE-TOKEN"}, clear=False
            ):
                with self.assertRaises(harness_module.HarnessError):
                    harness_module.main(self.argv(fixture, "report"))
            provider_get.assert_not_called()
            self.assertEqual(fixture["ledger"].read_bytes(), before)


class DigitalOceanRetentionRecoveryAndTruthfulnessTests(TestCase):
    def test_spaces_cleanup_never_deletes_key_or_credential_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = harness_module.DurableResourceLedger(
                root / "ledger.json",
                provider="digitalocean",
                run_id=RUN_ID,
                scope=TEAM_UUID,
            )
            harness = object.__new__(harness_module.DigitalOceanHarness)
            harness.account = {"team_uuid": TEAM_UUID}
            harness.run_id = RUN_ID
            harness.run_tag = RUN_ID
            harness.region = "nyc3"
            harness.spaces_prefix = PREFIX
            harness.apply = True
            harness.cleanup_enabled = True
            harness.spaces_cleanup_enabled = True
            harness.ledger = ledger
            harness.intents = mock.Mock()
            harness.intents.get.return_value = None
            harness.spaces_secret_path = root / "spaces.json"
            credentials = {
                "endpoint_url": "https://nyc3.digitaloceanspaces.com",
                "region": "nyc3",
                "bucket": "retained-bucket",
                "access_key": "FAKE-RETAINED-ACCESS",
                "secret_key": "FAKE-RETAINED-SECRET",
            }
            harness_module._write_runtime_secret(
                harness.spaces_secret_path, credentials
            )
            before = harness.spaces_secret_path.read_bytes()
            key = {
                "access_key": credentials["access_key"],
                "name": harness_module._resource_name(RUN_ID, "spaces-key"),
                "grants": [{"bucket": "", "permission": "fullaccess"}],
            }
            entry = harness._record_spaces_key(
                key, {"name": key["name"], "grants": key["grants"]}
            )
            harness._spaces_keys = mock.Mock(return_value=[key])
            harness._read_spaces_key = mock.Mock(return_value=key)
            harness._delete_spaces_with_intent = mock.Mock(
                side_effect=AssertionError("delete helper must not run")
            )
            with mock.patch.object(
                harness_module,
                "_mutation_response",
                side_effect=AssertionError("key DELETE endpoint must not run"),
            ) as mutation:
                result = harness.cleanup_spaces()

            mutation.assert_not_called()
            harness._delete_spaces_with_intent.assert_not_called()
            self.assertEqual(harness.spaces_secret_path.read_bytes(), before)
            retained = ledger.get("spaces_key", entry["resource_id"])
            self.assertEqual(retained["cleanup_state"], "manual_review")
            self.assertEqual(
                retained["cleanup_error"],
                harness_module.USER_RETAINED_BY_INSTRUCTION,
            )
            retention = ledger.get(
                "spaces_key_retention_witness", entry["resource_id"]
            )
            self.assertEqual(
                retention["ownership"]["status"],
                harness_module.USER_RETAINED_BY_INSTRUCTION,
            )
            self.assertEqual(
                result["spaces_key"]["status"],
                harness_module.USER_RETAINED_BY_INSTRUCTION,
            )

    def test_present_bucket_creation_drift_never_mutates_versioning(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_id = RUN_ID
        harness.run_tag = RUN_ID
        harness.region = "nyc3"
        harness.spaces_prefix = PREFIX
        harness.spaces_apply = True
        harness.account = {"team_uuid": TEAM_UUID}
        bucket = harness_module._spaces_bucket_name(RUN_ID, TEAM_UUID, "nyc3")
        credentials = {
            "endpoint_url": "https://nyc3.digitaloceanspaces.com",
            "region": "nyc3",
            "bucket": bucket,
            "access_key": "FAKE-ACCESS",
            "secret_key": "FAKE-SECRET",
        }
        creation = {
            "bucket": bucket,
            "region": "nyc3",
            "prefix": PREFIX,
            "acl": "private",
            "versioning": "Enabled",
            "created_at": "foreign-created-at",
        }
        entry = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": TEAM_UUID,
                "run_tag": RUN_ID,
                "region": "nyc3",
                "prefix": PREFIX,
                "endpoint_sha256": hashlib.sha256(
                    credentials["endpoint_url"].encode()
                ).hexdigest(),
                "access_key_sha256": harness._spaces_key_hash(
                    credentials["access_key"]
                ),
                "request_fingerprint": harness_module._fingerprint(
                    {
                        "bucket": bucket,
                        "region": "nyc3",
                        "acl": "private",
                        "versioning": "Enabled",
                        "prefix": PREFIX,
                    }
                ),
                "versioning": "Enabled",
                "creation_witness": {
                    **creation,
                    "immutable_fingerprint": harness_module._fingerprint(creation),
                },
            },
        }
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = entry
        harness.intents = mock.Mock()
        harness.intents.get.return_value = None
        harness.ensure_spaces_key = mock.Mock(return_value=({}, credentials))
        client = mock.Mock()
        client.list_buckets.return_value = {
            "Buckets": [
                {"Name": bucket, "CreationDate": "actual-created-at"}
            ]
        }
        with mock.patch.object(
            harness_module, "_spaces_client", return_value=client
        ):
            with self.assertRaises(harness_module.HarnessError):
                harness.ensure_spaces_bucket()
        client.put_bucket_versioning.assert_not_called()
        harness.ledger.record.assert_not_called()

        exact_creation = {**creation, "created_at": "actual-created-at"}
        entry["ownership"]["creation_witness"] = {
            **exact_creation,
            "immutable_fingerprint": harness_module._fingerprint(exact_creation),
        }
        client.get_bucket_location.return_value = {"LocationConstraint": "nyc3"}
        client.get_bucket_versioning.return_value = {"Status": "Suspended"}
        with mock.patch.object(
            harness_module, "_spaces_client", return_value=client
        ):
            with self.assertRaises(harness_module.HarnessError):
                harness.ensure_spaces_bucket()
        client.put_bucket_versioning.assert_not_called()
        harness.ledger.record.assert_not_called()

    def test_ambiguous_bucket_recovery_requires_marker_before_any_record_or_mutation(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_id = RUN_ID
        harness.run_tag = RUN_ID
        harness.region = "nyc3"
        harness.spaces_prefix = PREFIX
        harness.spaces_apply = True
        harness.account = {"team_uuid": TEAM_UUID}
        bucket = harness_module._spaces_bucket_name(RUN_ID, TEAM_UUID, "nyc3")
        credentials = {
            "endpoint_url": "https://nyc3.digitaloceanspaces.com",
            "region": "nyc3",
            "bucket": bucket,
            "access_key": "FAKE-ACCESS",
            "secret_key": "FAKE-SECRET",
        }
        request = {
            "bucket": bucket,
            "region": "nyc3",
            "acl": "private",
            "versioning": "Enabled",
            "prefix": PREFIX,
        }
        bucket_intent = {
            "request_boundary_crossed": True,
            "name": bucket,
            "request_fingerprint": harness_module._fingerprint(request),
            "preflight_absent": True,
        }
        ownership_payload = harness._spaces_ownership_payload(RUN_ID, TEAM_UUID)
        ownership_sha256 = hashlib.sha256(ownership_payload).hexdigest()
        ownership_key = ".backupsheep-e2e/ownership.bin"
        ownership_metadata = {
            "backupsheep-run": RUN_ID,
            "sha256": ownership_sha256,
            "byte-count": str(len(ownership_payload)),
        }
        ownership_intent = {
            "request_boundary_crossed": True,
            "name": ownership_key,
            "request_fingerprint": harness_module._fingerprint(
                {
                    "bucket": bucket,
                    "key": ownership_key,
                    "sha256": ownership_sha256,
                    "byte_count": len(ownership_payload),
                    "metadata": ownership_metadata,
                }
            ),
        }
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = None
        harness.ledger.entries.return_value = []
        harness.intents = mock.Mock()
        harness.intents.get.side_effect = lambda key: {
            "spaces_bucket_create": bucket_intent,
            "spaces_ownership_upload": ownership_intent,
        }.get(key)
        harness.ensure_spaces_key = mock.Mock(return_value=({}, credentials))
        harness._spaces_inventory = mock.Mock(
            return_value={
                "versions": [],
                "delete_markers": [],
                "objects": [],
                "multipart_uploads": [],
            }
        )
        client = mock.Mock()
        client.list_buckets.return_value = {
            "Buckets": [{"Name": bucket, "CreationDate": "created-at"}]
        }
        with mock.patch.object(
            harness_module, "_spaces_client", return_value=client
        ):
            with self.assertRaises(harness_module.HarnessError):
                harness.ensure_spaces_bucket()
        client.put_bucket_versioning.assert_not_called()
        client.create_bucket.assert_not_called()
        harness.ledger.record.assert_not_called()

    def test_ambiguous_bucket_recovery_rejects_wrong_marker_bytes(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_id = RUN_ID
        harness.run_tag = RUN_ID
        harness.account = {"team_uuid": TEAM_UUID}
        harness.spaces_prefix = PREFIX
        bucket = "owned-bucket"
        payload = harness._spaces_ownership_payload(RUN_ID, TEAM_UUID)
        sha256 = hashlib.sha256(payload).hexdigest()
        key = ".backupsheep-e2e/ownership.bin"
        metadata = {
            "backupsheep-run": RUN_ID,
            "sha256": sha256,
            "byte-count": str(len(payload)),
        }
        request = {
            "bucket": bucket,
            "key": key,
            "sha256": sha256,
            "byte_count": len(payload),
            "metadata": metadata,
        }
        harness.ledger = mock.Mock()
        harness.ledger.entries.return_value = []
        harness.intents = mock.Mock()
        harness.intents.get.return_value = {
            "request_boundary_crossed": True,
            "name": key,
            "request_fingerprint": harness_module._fingerprint(request),
        }
        harness._spaces_inventory = mock.Mock(
            return_value={
                "versions": [{"Key": key, "VersionId": "v1", "ETag": "etag"}],
                "delete_markers": [],
                "objects": [],
                "multipart_uploads": [],
            }
        )
        client = mock.Mock()
        client.head_object.return_value = {
            "ContentLength": len(payload),
            "ETag": '"etag"',
            "VersionId": "v1",
            "Metadata": metadata,
        }
        client.get_object.return_value = {"Body": io.BytesIO(b"wrong-bytes")}

        with self.assertRaises(harness_module.HarnessError):
            harness._adopt_exact_spaces_ownership_marker(client, bucket=bucket)

        harness.ledger.record.assert_not_called()
        harness.intents.clear.assert_not_called()

    def test_volume_control_plane_only_never_writes_cleanup_evidence(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_tag = RUN_ID
        harness.account = {"team_uuid": TEAM_UUID}
        harness.headers = {"Authorization": "Bearer redacted"}
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": TEAM_UUID,
                "run_tag": RUN_ID,
                "snapshot_marker": "snapshot-marker",
                "source_id": "source-volume",
                "resource_type": "volume",
            },
        }
        candidate = {
            "id": 902,
            "name": "restored-volume",
            "tags": ["restore-marker", "backupsheep-restore-volume"],
            "snapshot_id": 123456,
            "region": {"slug": "nyc3"},
            "size_gigabytes": 7,
            "droplet_ids": [],
        }
        harness._read_resource = mock.Mock(return_value=candidate)
        with mock.patch.object(
            harness_module, "iter_collection", return_value=[candidate]
        ):
            result = harness.verify_ui_restore(
                target_kind="volume",
                provider_id="902",
                name="restored-volume",
                snapshot_id="123456",
                run_tag=RUN_ID,
                snapshot_marker="snapshot-marker",
                restore_marker="restore-marker",
                expected_region="nyc3",
                expected_size_gigabytes=7,
            )
        self.assertEqual(result["status"], "CONTROL_PLANE_ONLY")
        self.assertNotIn("content_verified", result)
        harness.ledger.record.assert_not_called()

    def test_droplet_guest_probe_failure_never_writes_full_e2e_cleanup_row(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_tag = RUN_ID
        harness.account = {"team_uuid": TEAM_UUID, "team_name": "Personal"}
        harness.expected_team_uuid = TEAM_UUID
        harness.apply = True
        harness.attach_ui_droplet_firewall = True
        harness.headers = {"Authorization": "Bearer redacted"}
        harness.payload_expectation = harness_module._payload_expectation(RUN_ID)
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": TEAM_UUID,
                "run_tag": RUN_ID,
                "snapshot_marker": "snapshot-marker",
                "source_id": "source-droplet",
                "resource_type": "droplet",
            },
        }
        candidate = {
            "id": 901,
            "name": "restored-droplet",
            "tags": ["restore-marker", "backupsheep-restore-droplet"],
            "image": {"id": 123456},
            "region": {"slug": "nyc3"},
            "size_slug": "s-1vcpu-1gb",
        }
        harness._read_resource = mock.Mock(return_value=candidate)
        harness._attach_payload_firewall = mock.Mock()
        harness.wait_droplet_active = mock.Mock(return_value=candidate)
        harness.wait_payload_ready = mock.Mock(
            side_effect=harness_module.HarnessError("guest proof failed")
        )
        harness.record_payload_verification = mock.Mock()
        with mock.patch.dict(
            os.environ, {"BACKUPSHEEP_E2E_FIREWALL_APPLY": "YES"}, clear=False
        ), mock.patch.object(
            harness_module, "iter_collection", return_value=[candidate]
        ):
            with self.assertRaises(harness_module.HarnessError):
                harness.verify_ui_restore(
                    target_kind="droplet",
                    provider_id="901",
                    name="restored-droplet",
                    snapshot_id="123456",
                    run_tag=RUN_ID,
                    snapshot_marker="snapshot-marker",
                    restore_marker="restore-marker",
                    attach_payload_firewall=True,
                )
        harness._attach_payload_firewall.assert_called_once_with("901")
        harness.ledger.record.assert_not_called()
        harness.record_payload_verification.assert_not_called()

    def test_control_plane_only_legacy_restore_is_blocked_before_cleanup_read(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.apply = True
        harness.cleanup_enabled = True
        harness.run_id = RUN_ID
        harness.run_tag = RUN_ID
        harness.account = {"team_uuid": TEAM_UUID}
        harness.payload_expectation = harness_module._payload_expectation(RUN_ID)
        harness.ledger = mock.Mock()
        row = {
            "kind": "ui_restore_droplet",
            "resource_id": "901",
            "name": "restored-droplet",
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": TEAM_UUID,
                "run_tag": RUN_ID,
                "snapshot_id": "123456",
                "restore_marker": "restore-marker",
                "verification_level": "CONTROL_PLANE_ONLY",
                "cleanup_authorized": False,
            },
        }
        harness.ledger.entries.side_effect = lambda kind=None: (
            [row] if kind == "ui_restore_droplet" else []
        )
        harness.ledger.cleanup_eligible.return_value = True
        harness._read_resource = mock.Mock()

        with self.assertRaises(harness_module.HarnessError):
            harness.cleanup()

        harness._read_resource.assert_not_called()
        harness.ledger.mark_cleanup.assert_called_once_with(
            "ui_restore_droplet", "901", state="manual_review"
        )


class DigitalOceanStrictJSONSafetyTests(TestCase):
    def test_manifest_rejects_recursive_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(
                '{"schema":1,"run_id":"%s","prefix":"%s","objects":['
                '{"kind":"website","key":"%swebsite/a","version_id":"v1",'
                '"sha256":"%s","etag":"e","backup_id":"1","byte_count":1,'
                '"metadata":{"backupsheep-backup-id":"1",'
                '"backupsheep-bytes":"1","backupsheep-bytes":"1",'
                '"backupsheep-sha256":"%s"}}]}'
                % (RUN_ID, PREFIX, PREFIX, "a" * 64, "a" * 64)
            )
            with self.assertRaises(harness_module.HarnessError):
                harness_module._load_ui_object_manifest(
                    str(path), run_id=RUN_ID, prefix=PREFIX, maximum_bytes=1024
                )

    def test_report_reader_rejects_nested_duplicate_keys_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.json"
            raw = (
                '{"schema":1,"provider":"digitalocean","run_id":"%s",'
                '"scope":"%s","created_at":"x","resources":['
                '{"kind":"source_droplet","resource_id":"1","name":"n",'
                '"ownership":{"run_tag":"%s","run_tag":"%s"}}]}'
                % (RUN_ID, TEAM_UUID, RUN_ID, RUN_ID)
            ).encode()
            path.write_bytes(raw)
            before = path.read_bytes()
            args = harness_module._parser().parse_args(
                ["--report", "--run-id", RUN_ID, "--ledger", str(path)]
            )
            with self.assertRaises(harness_module.HarnessError):
                harness_module._local_read_only_report(args)
            self.assertEqual(path.read_bytes(), before)

    def test_normalization_secret_reader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "spaces.json"
            raw = (
                '{"endpoint_url":"https://nyc3.digitaloceanspaces.com",'
                '"region":"nyc3","bucket":"b","access_key":"a",'
                '"access_key":"a","secret_key":"s"}'
            ).encode()
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            with self.assertRaises(harness_module.HarnessError):
                harness_module._read_runtime_secret(path)
            self.assertEqual(path.read_bytes(), raw)


class DigitalOceanNativeVolumeVerifierMethodTests(TestCase):
    """Method-level failure tests for the live native-volume verifier.

    These tests deliberately use only local durable stores and provider-shaped
    fakes.  They exercise the mutation boundary and ownership contracts without
    reading credentials or making a DigitalOcean request.
    """

    def setUp(self):
        self.run_id = "bs-e2e-do-native-method-test"
        self.team_uuid = "personal-team-uuid"
        self.env = mock.patch.dict(
            os.environ,
            {
                "BACKUPSHEEP_E2E_APPLY": "YES",
                "BACKUPSHEEP_E2E_VOLUME_VERIFY_APPLY": "YES",
                "BACKUPSHEEP_E2E_VOLUME_SEED_APPLY": "YES",
                "BACKUPSHEEP_E2E_CLEANUP": "YES",
                "BACKUPSHEEP_E2E_VOLUME_VERIFY_CLEANUP": "YES",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.harness = object.__new__(harness_module.DigitalOceanHarness)
        self.harness.apply = True
        self.harness.cleanup_enabled = True
        self.harness.expected_team_uuid = self.team_uuid
        self.harness.run_id = self.run_id
        self.harness.run_tag = self.run_id
        self.harness.region = "nyc3"
        self.harness.account = {
            "team_uuid": self.team_uuid,
            "team_name": "Personal",
        }
        self.harness.headers = {"Authorization": "Bearer redacted"}
        self.harness.probe_cidrs = ["203.0.113.10/32"]
        self.harness.native_volume_offset_bytes = 16 * 1024 * 1024
        self.harness.native_volume_byte_count = 4096
        self.harness.source_volume_size_gib = 1
        self.harness.native_volume_verifier_key_dir = (
            Path(self.temporary.name) / "verifier-keys"
        )
        self.harness.mutation_reconcile_timeout_seconds = 0
        self.harness.mutation_reconcile_interval_seconds = 0.01
        self.harness.intents = harness_module.DurableMutationIntentStore(
            Path(self.temporary.name) / "ledger.json",
            provider="digitalocean",
            run_id=self.run_id,
            scope=self.team_uuid,
        )
        self.harness.ledger = mock.Mock()

    def test_native_volume_key_material_files_are_private_and_reusable(self):
        if shutil.which("ssh-keygen") is None:
            self.skipTest("ssh-keygen is required for native-volume key tests")

        key_directory = Path(self.temporary.name) / "mode-test-keys"
        created = harness_module._ensure_native_volume_key_material(
            key_directory,
            run_id=self.run_id,
            team_uuid=self.team_uuid,
        )

        self.assertEqual(stat.S_IMODE(key_directory.stat().st_mode), 0o700)
        for filename in harness_module.NATIVE_VOLUME_KEY_FILES:
            key_file = key_directory / filename
            self.assertTrue(key_file.is_file())
            self.assertFalse(key_file.is_symlink())
            self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)

        reused = harness_module._ensure_native_volume_key_material(
            key_directory,
            run_id=self.run_id,
            team_uuid=self.team_uuid,
        )
        self.assertEqual(reused["client_fingerprint"], created["client_fingerprint"])
        self.assertEqual(reused["host_fingerprint"], created["host_fingerprint"])

    def _witnessed_verifier(self):
        droplet = {
            "id": "601",
            "name": harness_module._resource_name(self.run_id, "volume-verifier"),
            "tags": [self.run_id, "backupsheep-native-volume-verifier"],
            "region": {"slug": "nyc3"},
            "size_slug": "s-1vcpu-1gb",
            "image": {"slug": "ubuntu-24-04-x64"},
            "created_at": "2026-08-15T00:00:00Z",
            "status": "active",
        }
        request = {
            "name": droplet["name"],
            "region": "nyc3",
            "size": "s-1vcpu-1gb",
            "image": "ubuntu-24-04-x64",
            "tags": list(droplet["tags"]),
        }
        creation = harness_module._creation_witness(
            "native_volume_verifier_droplet", droplet, request
        )
        creation["immutable_fingerprint"] = harness_module._fingerprint(creation)
        key_id = harness_module._fingerprint(
            {"kind": "native-volume-key", "run_id": self.run_id}
        )
        key_ownership = {
            "team_uuid": self.team_uuid,
            "run_tag": self.run_id,
            "client_fingerprint": "SHA256:client",
            "host_fingerprint": "SHA256:host",
            "immutable_fingerprint": key_id,
        }
        ready_sha256 = "r" * 64
        verifier_creation = {
            "resource_id": "601",
            "name": droplet["name"],
            "created_at": droplet["created_at"],
            "region": "nyc3",
            "size": "s-1vcpu-1gb",
            "image": "ubuntu-24-04-x64",
            "tags": sorted(droplet["tags"]),
            "key_witness_id": key_id,
            "ready_sha256": ready_sha256,
        }
        verifier_creation["immutable_fingerprint"] = harness_module._fingerprint(
            verifier_creation
        )
        ownership = {
            "team_uuid": self.team_uuid,
            "run_tag": self.run_id,
            "client_fingerprint": key_ownership["client_fingerprint"],
            "host_fingerprint": key_ownership["host_fingerprint"],
            "key_witness_id": key_id,
            "ready_sha256": ready_sha256,
            "creation_witness": creation,
            "verifier_creation_witness": verifier_creation,
        }
        droplet_entry = {
            "resource_id": "601",
            "name": droplet["name"],
            "cleanup_state": "eligible",
            "ownership": ownership,
        }
        key_entry = {
            "resource_id": key_id,
            "name": "verifier-keys",
            "cleanup_state": "eligible",
            "ownership": key_ownership,
        }
        entries = {
            ("native_volume_verifier_droplet", "601"): droplet_entry,
            ("native_volume_verifier_key_witness", key_id): key_entry,
        }

        def get(kind, resource_id):
            return entries.get((kind, str(resource_id)))

        self.harness.ledger.get.side_effect = get
        self.harness.ledger.entries.side_effect = lambda kind=None: [
            value for (entry_kind, _), value in entries.items() if entry_kind == kind
        ]
        return droplet, ownership, key_id

    def _volume(self, *, attached=False):
        return {
            "id": "902",
            "name": "restored-volume",
            "region": {"slug": "nyc3"},
            "size_gigabytes": 1,
            "droplet_ids": ["601"] if attached else [],
        }

    def _guest_proof(self, *, operation="read", write=False, open_mode="read-only"):
        volume = self._volume()
        sha256 = "a" * 64
        return {
            "schema": 1,
            "operation": operation,
            "run_id": self.run_id,
            "team_uuid": self.team_uuid,
            "verifier_droplet_id": "601",
            "observed_region": "nyc3",
            "observed_at": "2026-08-15T00:00:00+00:00",
            "status": "observed" if operation in {"inspect", "read"} else "seeded",
            "volume_id": volume["id"],
            "volume_name": volume["name"],
            "stable_device": harness_module._native_volume_device_path(volume["name"]),
            "resolved_device": "/dev/sdb",
            "device_size_bytes": self.harness.native_volume_offset_bytes
            + self.harness.native_volume_byte_count
            + 4096,
            "offset_bytes": self.harness.native_volume_offset_bytes,
            "byte_count": self.harness.native_volume_byte_count,
            "sha256": sha256,
            "preimage_sha256": "b" * 64,
            "mounted": False,
            "signatures": [],
            "open_mode": open_mode,
            "write_performed": write,
        }

    def test_fresh_verifier_owner_requires_direct_inventory_ledger_and_active_state(self):
        droplet, _ownership, _key_id = self._witnessed_verifier()
        self.harness._resources = mock.Mock(return_value=[droplet])
        self.harness._read_resource = mock.Mock(return_value=droplet)
        fresh, fingerprint = self.harness._fresh_owned_verifier_droplet_for_mutation(
            "601", expected_region="nyc3"
        )
        self.assertEqual(fresh["id"], "601")
        self.assertEqual(len(fingerprint), 64)
        self.harness._read_resource.assert_called_once_with(
            "native_volume_verifier_droplet", "601"
        )

        for label, inventory, direct in (
            ("duplicate", [droplet, dict(droplet)], droplet),
            (
                "foreign-tags",
                [{**droplet, "tags": ["foreign-run", "backupsheep-native-volume-verifier"]}],
                {**droplet, "tags": ["foreign-run", "backupsheep-native-volume-verifier"]},
            ),
            ("not-active", [droplet], {**droplet, "status": "off"}),
        ):
            with self.subTest(label=label):
                self.harness._resources.return_value = inventory
                self.harness._read_resource.return_value = direct
                with self.assertRaises(harness_module.HarnessError):
                    self.harness._fresh_owned_verifier_droplet_for_mutation(
                        "601", expected_region="nyc3"
                    )

    def test_ensure_verifier_droplet_validates_key_and_creation_witness(self):
        droplet, _ownership, key_id = self._witnessed_verifier()
        key_material = {
            "client_fingerprint": "SHA256:client",
            "host_fingerprint": "SHA256:host",
            "key_witness_id": key_id,
        }
        self.harness.probe_cidrs = ["203.0.113.10/32"]
        self.harness.native_volume_verifier_size = "s-1vcpu-1gb"
        self.harness.native_volume_verifier_image = "ubuntu-24-04-x64"
        self.harness._resources = mock.Mock(return_value=[])
        self.harness._ensure_native_volume_key_witness = mock.Mock(
            return_value=key_material
        )
        self.harness.ensure_source = mock.Mock(return_value=droplet)
        self.harness.wait_droplet_active = mock.Mock(return_value=droplet)
        with mock.patch.object(
            harness_module, "_native_volume_verifier_cloud_init", return_value="cloud-init"
        ), mock.patch.object(
            harness_module, "_public_ipv4", return_value="198.51.100.2"
        ):
            result, returned_keys = self.harness.ensure_native_volume_verifier_droplet()
        self.assertEqual(result["id"], "601")
        self.assertEqual(returned_keys, key_material)
        request = self.harness.ensure_source.call_args.args[1]
        self.assertEqual(request["tags"], droplet["tags"])

    def test_verifier_firewall_binds_fresh_droplet_fingerprint_before_post(self):
        droplet, _ownership, _key_id = self._witnessed_verifier()
        self.harness._resources = mock.Mock(return_value=[])
        firewall = {
            "id": "fw-1",
            "name": harness_module._resource_name(
                self.run_id, "volume-verifier-firewall"
            ),
            "created_at": "2026-08-15T00:01:00Z",
            "status": "succeeded",
            "pending_changes": [],
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "22",
                    "sources": {"addresses": list(self.harness.probe_cidrs)},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": "80",
                    "destinations": {"addresses": ["169.254.169.254/32"]},
                }
            ],
            "droplet_ids": ["601"],
        }
        self.harness._read_resource = mock.Mock(return_value=firewall)
        self.harness._fresh_owned_verifier_droplet_for_mutation = mock.Mock(
            return_value=(droplet, "d" * 64)
        )
        events = []

        def mutation(*args, **kwargs):
            events.append("post")
            return {"firewall": {"id": "fw-1"}}

        self.harness._fresh_owned_verifier_droplet_for_mutation.side_effect = (
            lambda *args, **kwargs: (events.append("fresh") or (droplet, "d" * 64))
        )
        with mock.patch.object(harness_module, "_mutation_response", side_effect=mutation):
            result = self.harness.ensure_native_volume_verifier_firewall("601")
        self.assertEqual(result["id"], "fw-1")
        self.assertEqual(events, ["fresh", "post"])
        self.assertEqual(
            self.harness.ledger.record.call_args.kwargs["kind"],
            "native_volume_verifier_firewall",
        )
        self.assertEqual(
            self.harness.intents.pending(), {}, "successful firewall creation clears its intent"
        )

    def test_native_volume_attach_lost_response_is_adopted_after_restart_without_replay(self):
        _droplet, _ownership, _key_id = self._witnessed_verifier()
        self.harness._fresh_owned_verifier_droplet_for_mutation = mock.Mock(
            return_value=({}, "v" * 64)
        )
        self.harness._read_exact_native_volume = mock.Mock(
            side_effect=[self._volume(attached=False), self._volume(attached=False)]
        )
        with mock.patch.object(
            harness_module,
            "_mutation_response",
            side_effect=harness_module.AmbiguousMutation("lost attach"),
        ) as post:
            with self.assertRaises(harness_module.AmbiguousMutation):
                self.harness._transition_native_volume_attachment(
                    kind="ui_restore_volume",
                    volume_id="902",
                    volume_name="restored-volume",
                    verifier_droplet_id="601",
                    region="nyc3",
                    size_gigabytes=1,
                    attach=True,
                    restore_witness={
                        "provider_id": "902",
                        "name": "restored-volume",
                        "target_kind": "volume",
                        "marker": "restore-marker",
                        "snapshot_id": "snapshot-1",
                        "expected_region": "nyc3",
                        "expected_size_gigabytes": 1,
                    },
                )
        post.assert_called_once()
        pending = self.harness.intents.get("native-volume:attach:902:601")
        self.assertEqual(pending["state"], "submitted")
        self.assertTrue(pending["request_boundary_crossed"])
        self.assertEqual(pending["verifier_droplet_fingerprint"], "v" * 64)

        resumed = self.harness
        resumed._read_exact_native_volume = mock.Mock(
            return_value=self._volume(attached=True)
        )
        resumed._fresh_owned_verifier_droplet_for_mutation.reset_mock()
        with mock.patch.object(harness_module, "_mutation_response") as replay:
            result = resumed._transition_native_volume_attachment(
                kind="ui_restore_volume",
                volume_id="902",
                volume_name="restored-volume",
                verifier_droplet_id="601",
                region="nyc3",
                size_gigabytes=1,
                attach=True,
                restore_witness={
                    "provider_id": "902",
                    "name": "restored-volume",
                    "target_kind": "volume",
                    "marker": "restore-marker",
                    "snapshot_id": "snapshot-1",
                    "expected_region": "nyc3",
                    "expected_size_gigabytes": 1,
                },
            )
        self.assertTrue(result["reconciled"])
        replay.assert_not_called()
        resumed._fresh_owned_verifier_droplet_for_mutation.assert_not_called()
        self.assertIsNone(resumed.intents.get("native-volume:attach:902:601"))

    def test_native_volume_detach_lost_response_is_adopted_after_restart_without_replay(self):
        self.harness._fresh_owned_verifier_droplet_for_mutation = mock.Mock(
            return_value=({}, "v" * 64)
        )
        self.harness._read_exact_native_volume = mock.Mock(
            side_effect=[self._volume(attached=True), self._volume(attached=True)]
        )
        with mock.patch.object(
            harness_module,
            "_mutation_response",
            side_effect=harness_module.AmbiguousMutation("lost detach"),
        ) as post:
            with self.assertRaises(harness_module.AmbiguousMutation):
                self.harness._transition_native_volume_attachment(
                    kind="source_volume",
                    volume_id="902",
                    volume_name="restored-volume",
                    verifier_droplet_id="601",
                    region="nyc3",
                    size_gigabytes=1,
                    attach=False,
                )
        post.assert_called_once()
        pending = self.harness.intents.get("native-volume:detach:902:601")
        self.assertEqual(pending["state"], "submitted")
        self.harness._read_exact_native_volume = mock.Mock(
            return_value=self._volume(attached=False)
        )
        self.harness._fresh_owned_verifier_droplet_for_mutation.reset_mock()
        with mock.patch.object(harness_module, "_mutation_response") as replay:
            result = self.harness._transition_native_volume_attachment(
                kind="source_volume",
                volume_id="902",
                volume_name="restored-volume",
                verifier_droplet_id="601",
                region="nyc3",
                size_gigabytes=1,
                attach=False,
            )
        self.assertTrue(result["reconciled"])
        replay.assert_not_called()
        self.assertIsNone(self.harness.intents.get("native-volume:detach:902:601"))

    def test_seed_crash_leaves_durable_submitted_intent_for_restart(self):
        droplet, _ownership, key_id = self._witnessed_verifier()
        key_material = {
            "client_fingerprint": "SHA256:client",
            "host_fingerprint": "SHA256:host",
            "key_witness_id": key_id,
        }
        source = {
            "id": "source-1",
            "name": "source-volume",
            "region": {"slug": "nyc3"},
            "size_gigabytes": 1,
            "droplet_ids": [],
        }
        self.harness._source_volume_contract = mock.Mock(
            return_value=({"name": "source-volume"}, {})
        )
        self.harness.ledger.entries.side_effect = lambda kind=None: (
            [
                {
                    "resource_id": "601",
                    "cleanup_state": "eligible",
                }
            ]
            if kind == "native_volume_verifier_droplet"
            else []
        )
        self.harness.ledger.get.return_value = None
        self.harness._read_exact_native_volume = mock.Mock(side_effect=[source, source])
        self.harness.ensure_native_volume_verifier_droplet = mock.Mock(
            return_value=(droplet, key_material)
        )
        self.harness.ensure_native_volume_verifier_firewall = mock.Mock()
        self.harness.wait_native_volume_verifier_ready = mock.Mock(
            return_value={"operation": "identity"}
        )
        self.harness._transition_native_volume_attachment = mock.Mock(
            return_value={"operation": "attach", "droplet_ids": ["601"]}
        )
        self.harness._run_native_volume_guest = mock.Mock(
            side_effect=[
                {"sha256": "i" * 64},
                harness_module.AmbiguousMutation("worker crashed during seed"),
            ]
        )
        with self.assertRaises(harness_module.AmbiguousMutation):
            self.harness.prepare_native_volume_source("source-1")
        seed = self.harness.intents.get("native-volume:seed-bytes:source-1")
        self.assertEqual(seed["state"], "submitted")
        self.assertTrue(seed["request_boundary_crossed"])
        restarted_intents = harness_module.DurableMutationIntentStore(
            Path(self.temporary.name) / "ledger.json",
            provider="digitalocean",
            run_id=self.run_id,
            scope=self.team_uuid,
        )
        self.assertEqual(
            restarted_intents.get("native-volume:seed-bytes:source-1")[
                "request_fingerprint"
            ],
            seed["request_fingerprint"],
        )

    def test_guest_read_proof_rejects_write_and_preserves_read_only_contract(self):
        droplet = {
            "id": "601",
            "networks": {"v4": [{"type": "public", "ip_address": "198.51.100.2"}]},
        }
        key_material = {
            "client_private_path": Path(self.temporary.name) / "client_key",
            "known_hosts_path": Path(self.temporary.name) / "known_hosts",
            "client_fingerprint": "SHA256:client",
            "host_fingerprint": "SHA256:host",
        }
        good = self._guest_proof()
        with mock.patch.object(
            harness_module,
            "_secret_safe_subprocess",
            return_value=mock.Mock(stdout=json.dumps(good).encode()),
        ):
            result = self.harness._run_native_volume_guest(
                operation="read",
                droplet=droplet,
                key_material=key_material,
                volume=self._volume(),
                expected_sha256="a" * 64,
            )
        self.assertFalse(result["write_performed"])
        bad = dict(good, open_mode="read-write", write_performed=True)
        with mock.patch.object(
            harness_module,
            "_secret_safe_subprocess",
            return_value=mock.Mock(stdout=json.dumps(bad).encode()),
        ):
            with self.assertRaises(harness_module.HarnessError):
                self.harness._run_native_volume_guest(
                    operation="read",
                    droplet=droplet,
                    key_material=key_material,
                    volume=self._volume(),
                    expected_sha256="a" * 64,
                )

    def test_caller_asserted_hashes_are_rejected_before_provider_reads(self):
        harness = object.__new__(harness_module.DigitalOceanHarness)
        harness.run_tag = self.run_id
        harness.account = {"team_uuid": self.team_uuid, "team_name": "Personal"}
        harness.ledger = mock.Mock()
        with mock.patch.object(harness_module, "iter_collection") as inventory:
            with self.assertRaises(harness_module.HarnessError):
                harness.verify_ui_restore(
                    target_kind="volume",
                    provider_id="902",
                    name="restored-volume",
                    snapshot_id="snapshot-1",
                    run_tag=self.run_id,
                    snapshot_marker="snapshot-marker",
                    restore_marker="restore-marker",
                    expected_region="nyc3",
                    expected_size_gigabytes=1,
                    source_content_sha256="a" * 64,
                )
        inventory.assert_not_called()

    def test_native_volume_restore_requires_durable_snapshot_witness_before_reads(self):
        self.harness.ledger.get.return_value = None
        self.harness._read_exact_native_volume = mock.Mock()
        with self.assertRaises(harness_module.HarnessError):
            self.harness.verify_native_volume_restore(
                provider_id="902",
                name="restored-volume",
                snapshot_id="snapshot-1",
                snapshot_marker="snapshot-marker",
                restore_marker="restore-marker",
                run_tag=self.run_id,
                expected_region="nyc3",
                expected_size_gigabytes=1,
            )
        self.harness._read_exact_native_volume.assert_not_called()

    def test_verifier_cleanup_is_idempotent_after_all_exact_rows_are_deleted(self):
        rows = {
            "native_volume_verifier_droplet": "601",
            "native_volume_verifier_firewall": "fw-1",
            "native_volume_verifier_key_witness": "key-1",
        }
        def entries(kind=None):
            return (
                [{"resource_id": rows[kind], "cleanup_state": "deleted"}]
                if kind in rows
                else []
            )
        self.harness.ledger.entries.side_effect = entries
        with mock.patch.object(self.harness, "_resources", side_effect=AssertionError("provider read")):
            result = self.harness.cleanup_native_volume_verifier()
        self.assertEqual(result["status"], "VERIFIER_ALREADY_CLEANED")
        self.assertEqual(result["tokens_revoked"], 0)
