from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import release_transition as transition  # noqa: E402
import collect_release_transition as collector  # noqa: E402

_migration_module_spec = importlib.util.spec_from_file_location(
    "backupsheep_release_migration_contract",
    ROOT / "apps" / "release_migration_contract.py",
)
assert _migration_module_spec is not None and _migration_module_spec.loader is not None
_migration_module = importlib.util.module_from_spec(_migration_module_spec)
_migration_module_spec.loader.exec_module(_migration_module)
build_contract = _migration_module.build_contract


class MigrationContractTests(TestCase):
    def test_exact_sorted_graph_and_hashes_are_emitted(self):
        migrations = {
            ("apps", "0001_initial"): SimpleNamespace(atomic=True, replaces=[]),
            ("apps", "0002_next"): SimpleNamespace(atomic=True, replaces=[]),
            ("auth", "0001_initial"): SimpleNamespace(atomic=True, replaces=[]),
        }
        contract = build_contract(
            migrations,
            migrations,
            (("apps", "0002_next"), ("auth", "0001_initial")),
        )
        self.assertEqual(
            contract["migrations"],
            ["apps.0001_initial", "apps.0002_next", "auth.0001_initial"],
        )
        self.assertEqual(
            contract["migration_set_sha256"],
            transition.migration_digest(contract["migrations"]),
        )
        self.assertEqual(
            contract["leaf_set_sha256"],
            transition.migration_digest(contract["leaves"], leaves=True),
        )
        self.assertEqual(transition.validate_migration_contract(contract), contract)

    def test_incomplete_replacement_or_nontransactional_graph_is_rejected(self):
        good = SimpleNamespace(atomic=True, replaces=[])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            build_contract({("apps", "0001_initial"): good}, [], [("apps", "0001_initial")])
        with self.assertRaisesRegex(ValueError, "replacement"):
            build_contract(
                {("apps", "0001_initial"): SimpleNamespace(atomic=True, replaces=[("apps", "zero")])},
                [("apps", "0001_initial")],
                [("apps", "0001_initial")],
            )
        with self.assertRaisesRegex(ValueError, "nontransactional"):
            build_contract(
                {("apps", "0001_initial"): SimpleNamespace(atomic=False, replaces=[])},
                [("apps", "0001_initial")],
                [("apps", "0001_initial")],
            )


class SignedTransitionContractTests(TestCase):
    def setUp(self):
        self.migrations = ["apps.0001_initial", "apps.0002_next", "auth.0001_initial"]
        self.migration_contract = {
            "schema_version": 1,
            "all_migrations_atomic": True,
            "migrations": self.migrations,
            "migration_set_sha256": transition.migration_digest(self.migrations),
            "leaves": ["apps.0002_next", "auth.0001_initial"],
            "leaf_set_sha256": transition.migration_digest(
                ["apps.0002_next", "auth.0001_initial"], leaves=True
            ),
        }
        self.verifier = {
            "reference": "ghcr.io/bilal414/backupsheep-release-verifier@sha256:" + "1" * 64,
            "runtime_contract_version": 1,
            "linux_amd64_manifest": "sha256:" + "2" * 64,
            "linux_amd64_config": "sha256:" + "3" * 64,
            "linux_arm64_manifest": "sha256:" + "4" * 64,
            "linux_arm64_config": "sha256:" + "5" * 64,
            "trusted_root_sha256": "sha256:" + "6" * 64,
        }
        self.predecessor = {
            "release_tag": "v1.2.3",
            "release_epoch": 7,
            "source_commit": "a" * 40,
            "release_manifest_sha256": "sha256:" + "7" * 64,
            "descriptor_sha256": "sha256:" + "8" * 64,
            "descriptor_bundle_sha256": "sha256:" + "9" * 64,
            "migration_set_sha256": self.migration_contract["migration_set_sha256"],
            "migration_leaf_set_sha256": self.migration_contract["leaf_set_sha256"],
            "verifier": self.verifier,
        }
        self.policy = {
            "schema_version": 1,
            "release_epoch": 8,
            "accepted_predecessors": [self.predecessor],
        }

    def test_exact_predecessor_and_migration_contract_are_bound(self):
        record = transition.build_transition_record(
            reviewed_policy=self.policy,
            migration_contract=self.migration_contract,
            reviewed_policy_file="transition/reviewed-policy.json",
            reviewed_policy_sha256="sha256:" + "a" * 64,
            migration_contract_file="transition/django-migrations.json",
            migration_contract_sha256="sha256:" + "b" * 64,
        )
        self.assertEqual(record["release_epoch"], 8)
        self.assertEqual(record["accepted_predecessors"], [self.predecessor])
        self.assertEqual(
            transition.validate_transition_record(
                record,
                reviewed_policy=self.policy,
                migration_contract=self.migration_contract,
                reviewed_policy_sha256="sha256:" + "a" * 64,
                migration_contract_sha256="sha256:" + "b" * 64,
            ),
            record,
        )

    def test_ranges_wrong_epoch_reordering_and_digest_drift_fail_closed(self):
        cases = []
        wildcard = copy.deepcopy(self.policy)
        wildcard["accepted_predecessors"][0]["release_tag"] = "v1.*"
        cases.append(wildcard)
        same_epoch = copy.deepcopy(self.policy)
        same_epoch["accepted_predecessors"][0]["release_epoch"] = 8
        cases.append(same_epoch)
        duplicate = copy.deepcopy(self.policy)
        second = copy.deepcopy(self.predecessor)
        second["release_tag"] = "v1.2.4"
        second["source_commit"] = "b" * 40
        duplicate["accepted_predecessors"].append(second)
        duplicate["accepted_predecessors"].reverse()
        cases.append(duplicate)
        collision = copy.deepcopy(self.policy)
        second = copy.deepcopy(self.predecessor)
        second["release_tag"] = "v1.2.4"
        second["source_commit"] = "b" * 40
        collision["accepted_predecessors"].append(second)
        cases.append(collision)
        for policy in cases:
            with self.subTest(policy=policy), self.assertRaises(transition.TransitionContractError):
                transition.validate_transition_policy(policy)

        drifted = copy.deepcopy(self.migration_contract)
        drifted["migrations"].append("apps.0003_late")
        drifted["migrations"].sort()
        with self.assertRaisesRegex(transition.TransitionContractError, "digest mismatch"):
            transition.validate_migration_contract(drifted)

        drifted_policy = copy.deepcopy(self.policy)
        drifted_policy["accepted_predecessors"][0]["migration_leaf_set_sha256"] = (
            "sha256:" + "f" * 64
        )
        normalized = transition.validate_transition_policy(drifted_policy)
        self.assertEqual(
            normalized["accepted_predecessors"][0]["migration_leaf_set_sha256"],
            "sha256:" + "f" * 64,
        )
        # The producer deliberately cannot infer an authorized predecessor's
        # historical graph.  The upgrade consumer must compare this signed
        # tuple to the authenticated source manifest before any mutation.

    def test_predecessor_verifier_contract_is_exact_and_versioned(self):
        wrong_runtime = copy.deepcopy(self.policy)
        wrong_runtime["accepted_predecessors"][0]["verifier"][
            "runtime_contract_version"
        ] = 2
        with self.assertRaisesRegex(transition.TransitionContractError, "not supported"):
            transition.validate_transition_policy(wrong_runtime)

        index_collision = copy.deepcopy(self.policy)
        index_digest = index_collision["accepted_predecessors"][0]["verifier"][
            "reference"
        ].rsplit("@", 1)[1]
        index_collision["accepted_predecessors"][0]["verifier"][
            "linux_amd64_manifest"
        ] = index_digest
        with self.assertRaisesRegex(transition.TransitionContractError, "colliding trust digests"):
            transition.validate_transition_policy(index_collision)

    def test_duplicate_json_keys_are_rejected(self):
        temporary = Path(tempfile.mkdtemp(prefix="backupsheep-transition-json-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(temporary))
        path = temporary / "policy.json"
        path.write_text(
            '{"schema_version":1,"schema_version":1,"release_epoch":1,"accepted_predecessors":[]}\n',
            encoding="ascii",
        )
        with self.assertRaisesRegex(transition.TransitionContractError, "duplicate key"):
            transition.load_json(path)

    def test_checked_in_initial_policy_is_fresh_only(self):
        policy = transition.load_json(ROOT / "deploy" / "release-transition-policy.json")
        self.assertEqual(
            transition.validate_transition_policy(policy),
            {"schema_version": 1, "release_epoch": 1, "accepted_predecessors": []},
        )


class ReleaseTransitionCollectorTests(TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="backupsheep-transition-collector-"))
        self.addCleanup(shutil.rmtree, self.root)
        self.artifacts = self.root / "artifacts"
        self.layout = self.root / "layout"
        self.artifacts.mkdir(mode=0o700)
        self.layout.mkdir(mode=0o700)
        self.docker = self.root / "docker"
        self.docker.write_text("#!/bin/sh\n", encoding="ascii")
        self.docker.chmod(0o555)
        self.config_digest = "sha256:" + "a" * 64
        self.contract = {
            "schema_version": 1,
            "all_migrations_atomic": True,
            "migrations": ["apps.0001_initial", "apps.0002_next"],
            "migration_set_sha256": transition.migration_digest(
                ["apps.0001_initial", "apps.0002_next"]
            ),
            "leaves": ["apps.0002_next"],
            "leaf_set_sha256": transition.migration_digest(
                ["apps.0002_next"], leaves=True
            ),
        }
        self.contract_bytes = (
            json.dumps(self.contract, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )

    def _inspect_result(self, *, image_id=None):
        document = {
            "Id": image_id or self.config_digest,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": "10001:10001",
                "WorkingDir": "/code",
                "Labels": {
                    "org.opencontainers.image.source": "https://github.com/bilal414/backupsheep",
                    "org.opencontainers.image.revision": "a" * 40,
                    "org.opencontainers.image.version": "v1.2.3",
                },
            },
        }
        return subprocess.CompletedProcess([str(self.docker)], 0, json.dumps([document]), "")

    def test_exact_built_child_emits_private_canonical_transition_artifacts(self):
        run_result = subprocess.CompletedProcess(
            [str(self.docker)], 0, self.contract_bytes.decode("ascii"), ""
        )
        with (
            mock.patch.object(
                collector,
                "_expected_amd64_config_digest",
                return_value=self.config_digest,
            ),
            mock.patch.object(
                collector,
                "run_text",
                side_effect=(self._inspect_result(), run_result),
            ) as runner,
        ):
            result = collector.collect(
                policy_path=ROOT / "deploy" / "release-policy.json",
                artifacts_dir=self.artifacts,
                oci_layout=self.layout,
                image="backupsheep-release-migration-inventory:v1.2.3",
                docker=self.docker,
                source_commit="a" * 40,
                release_tag="v1.2.3",
                docker_environment={"PATH": "/usr/bin:/bin"},
            )
        self.assertEqual(result, self.contract)
        reviewed = self.artifacts / "transition" / "reviewed-policy.json"
        migrations = self.artifacts / "transition" / "django-migrations.json"
        self.assertEqual(
            reviewed.read_bytes(),
            (ROOT / "deploy" / "release-transition-policy.json").read_bytes(),
        )
        self.assertEqual(migrations.read_bytes(), self.contract_bytes)
        self.assertEqual(os.stat(reviewed).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(migrations).st_mode & 0o777, 0o600)
        run_command = runner.call_args_list[1].args[0]
        self.assertIn(self.config_digest, run_command)
        self.assertNotIn("backupsheep-release-migration-inventory:v1.2.3", run_command)
        for required in (
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "no-new-privileges:true",
            "--memory-swap",
            "512m",
            "--log-driver",
            "/usr/local/bin/python",
            "apps.release_migration_contract",
        ):
            self.assertIn(required, run_command)

    def test_oci_index_child_manifest_and_config_are_digest_bound(self):
        (self.artifacts / "oci").mkdir(mode=0o700)
        blobs = self.layout / "blobs" / "sha256"
        blobs.mkdir(parents=True, mode=0o700)

        config_payload = b'{"architecture":"amd64","os":"linux"}\n'
        config_hex = hashlib.sha256(config_payload).hexdigest()
        (blobs / config_hex).write_bytes(config_payload)
        amd64_manifest_payload = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{config_hex}",
                    "size": len(config_payload),
                },
                "layers": [],
            },
            separators=(",", ":"),
        ).encode("ascii")
        amd64_hex = hashlib.sha256(amd64_manifest_payload).hexdigest()
        (blobs / amd64_hex).write_bytes(amd64_manifest_payload)
        arm64_digest = "sha256:" + "b" * 64
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{amd64_hex}",
                    "size": len(amd64_manifest_payload),
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": arm64_digest,
                    "size": 1,
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + "c" * 64,
                    "size": 1,
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": f"sha256:{amd64_hex}",
                    },
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + "d" * 64,
                    "size": 1,
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": arm64_digest,
                    },
                },
            ],
        }
        (self.artifacts / "oci" / "app.index.json").write_text(
            json.dumps(index, separators=(",", ":")), encoding="ascii"
        )
        self.assertEqual(
            collector._expected_amd64_config_digest(self.artifacts, self.layout),
            f"sha256:{config_hex}",
        )

        (blobs / amd64_hex).write_bytes(amd64_manifest_payload + b" ")
        with self.assertRaisesRegex(
            collector.ReleaseVerificationError,
            "manifest blob digest mismatch",
        ):
            collector._expected_amd64_config_digest(self.artifacts, self.layout)

    def test_wrong_local_image_or_noncanonical_output_never_publishes_evidence(self):
        with (
            mock.patch.object(
                collector,
                "_expected_amd64_config_digest",
                return_value=self.config_digest,
            ),
            mock.patch.object(
                collector,
                "run_text",
                return_value=self._inspect_result(image_id="sha256:" + "b" * 64),
            ),
            self.assertRaisesRegex(
                collector.ReleaseVerificationError,
                "not the exact release child",
            ),
        ):
            collector.collect(
                policy_path=ROOT / "deploy" / "release-policy.json",
                artifacts_dir=self.artifacts,
                oci_layout=self.layout,
                image="backupsheep-release-migration-inventory:v1.2.3",
                docker=self.docker,
                source_commit="a" * 40,
                release_tag="v1.2.3",
                docker_environment={"PATH": "/usr/bin:/bin"},
            )
        self.assertFalse((self.artifacts / "transition").exists())

    def test_preexisting_or_symlinked_transition_parent_is_never_reused(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (self.artifacts / "transition").symlink_to(outside, target_is_directory=True)
        with (
            mock.patch.object(
                collector,
                "_expected_amd64_config_digest",
                return_value=self.config_digest,
            ),
            mock.patch.object(
                collector,
                "run_text",
                side_effect=(
                    self._inspect_result(),
                    subprocess.CompletedProcess(
                        [str(self.docker)], 0, self.contract_bytes.decode("ascii"), ""
                    ),
                ),
            ) as runner,
            self.assertRaisesRegex(
                collector.ReleaseVerificationError,
                "transition directory already exists",
            ),
        ):
            collector.collect(
                policy_path=ROOT / "deploy" / "release-policy.json",
                artifacts_dir=self.artifacts,
                oci_layout=self.layout,
                image="backupsheep-release-migration-inventory:v1.2.3",
                docker=self.docker,
                source_commit="a" * 40,
                release_tag="v1.2.3",
                docker_environment={"PATH": "/usr/bin:/bin"},
            )
        runner.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_reviewed_transition_policy_cannot_be_a_symlink_or_escape_checkout(self):
        checkout = self.root / "checkout"
        deploy = checkout / "deploy"
        deploy.mkdir(parents=True, mode=0o700)
        shutil.copyfile(ROOT / "deploy" / "release-policy.json", deploy / "release-policy.json")
        outside_policy = self.root / "outside-policy.json"
        shutil.copyfile(
            ROOT / "deploy" / "release-transition-policy.json",
            outside_policy,
        )
        (deploy / "release-transition-policy.json").symlink_to(outside_policy)
        with (
            mock.patch.object(
                collector,
                "_expected_amd64_config_digest",
                return_value=self.config_digest,
            ),
            mock.patch.object(collector, "run_text") as runner,
            self.assertRaisesRegex(
                collector.ReleaseVerificationError,
                "contains a symlink",
            ),
        ):
            collector.collect(
                policy_path=(deploy / "release-policy.json").resolve(),
                artifacts_dir=self.artifacts,
                oci_layout=self.layout,
                image="backupsheep-release-migration-inventory:v1.2.3",
                docker=self.docker,
                source_commit="a" * 40,
                release_tag="v1.2.3",
                docker_environment={"PATH": "/usr/bin:/bin"},
            )
        runner.assert_not_called()
