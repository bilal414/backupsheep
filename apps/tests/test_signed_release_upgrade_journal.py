from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
import sys

sys.path.insert(0, str(ROOT / "scripts"))

import release_transition  # noqa: E402
import signed_release_upgrade as upgrade  # noqa: E402


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"


class SignedReleaseUpgradeJournalTests(TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="backupsheep-upgrade-journal-")).resolve()
        self.addCleanup(shutil.rmtree, self.root)
        self.install = self.root / "install"
        self.install.mkdir(mode=0o700)
        self.source_evidence = self.install / ".release-evidence"
        self.target_evidence = self.install / ".release-evidence.target"
        self.source_env = self.install / ".env"
        self.target_env = self.install / ".env.signed-upgrade.target"
        self.source_verification = (
            self.install / ".release-evidence.source-verification.json"
        )
        self.request = self.install / ".signed-upgrade-witness.json"
        self.source_env.write_bytes(b"BACKUPSHEEP_RELEASE_TAG='v1.0.0'\n")
        self.target_env.write_bytes(b"BACKUPSHEEP_RELEASE_TAG='v2.0.0'\n")
        self.request.write_bytes(canonical(self._request()))
        for path in (self.source_env, self.target_env, self.request):
            path.chmod(0o600)
        source = self._make_evidence(
            self.source_evidence,
            tag="v1.0.0",
            commit="1" * 40,
            epoch=1,
            accepted=[],
            seed=1,
        )
        predecessor = {
            "release_tag": source["release_tag"],
            "release_epoch": source["release_epoch"],
            "source_commit": source["source_commit"],
            "release_manifest_sha256": source["manifest_sha256"],
            "descriptor_sha256": source["descriptor_sha256"],
            "descriptor_bundle_sha256": source["descriptor_bundle_sha256"],
            "migration_set_sha256": source["migration"]["migration_set_sha256"],
            "migration_leaf_set_sha256": source["migration"]["leaf_set_sha256"],
            "verifier": source["verifier"],
        }
        self.target_state = self._make_evidence(
            self.target_evidence,
            tag="v2.0.0",
            commit="2" * 40,
            epoch=2,
            accepted=[predecessor],
            seed=8,
        )
        self._write_source_verification(source, self.target_state)

    def _request(self):
        volumes = {
            role: {
                "name": f"backupsheep_{role}",
                "inspect_sha256": digest(f"volume-inspect-{role}"),
                "ownership_witness_sha256": digest(f"volume-owner-{role}"),
            }
            for role in upgrade.VOLUME_ROLES
        }
        return {
            "schema_version": 2,
            "attempt_nonce": "b" * 64,
            "installation_id": "a" * 64,
            "compose_project": "backupsheep",
            "daemon": {"os": "linux", "architecture": "amd64", "identity_sha256": digest("daemon")},
            "checkouts": {
                "source": {
                    "commit": "1" * 40,
                    "tree_sha256": digest("source-tree"),
                    "runtime_files_sha256": digest("source-runtime-files"),
                },
                "target": {
                    "commit": "2" * 40,
                    "tree_sha256": digest("target-tree"),
                    "runtime_files_sha256": digest("target-runtime-files"),
                },
            },
            "compose": {
                "source_model_sha256": digest("2"),
                "target_model_sha256": digest("3"),
            },
            "target_active_pointer_sha256": digest("target-active-pointer"),
            "volumes": volumes,
            "artifact_provider": {
                "generation": 1,
                "witness_sha256": digest("a"),
                "database_keyring_sha256": digest("b"),
                "files_keyring_sha256": digest("c"),
            },
        }

    def _write_source_verification(self, source: dict, target: dict) -> None:
        platform = "linux/amd64"
        receipt = {
            "authorized_predecessor_sha256": upgrade._sha256_bytes(
                canonical(upgrade._predecessor_projection(source))
            ),
            "authorizing_target_descriptor_sha256": target["descriptor_sha256"],
            "daemon_identity_sha256": digest("daemon"),
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "platform": platform,
            "purpose": "authorized-predecessor",
            "schema_version": 3,
            "source_descriptor_bundle_sha256": source["descriptor_bundle_sha256"],
            "source_descriptor_sha256": source["descriptor_sha256"],
            "source_evidence_sha256": upgrade._state_digest(source),
            "source_manifest_sha256": source["manifest_sha256"],
            "source_migration_leaf_set_sha256": source["migration"]["leaf_set_sha256"],
            "source_migration_set_sha256": source["migration"]["migration_set_sha256"],
            "source_release_epoch": source["release_epoch"],
            "source_release_tag": source["release_tag"],
            "source_commit": source["source_commit"],
            "source_trusted_root_sha256": source["trusted_root_sha256"],
            "trigger": "push",
            "verifier_config_digest": source["verifier"]["linux_amd64_config"],
            "verifier_manifest_digest": source["verifier"]["linux_amd64_manifest"],
            "verifier_reference": source["verifier"]["reference"],
            "verifier_runtime_contract_version": source["verifier"][
                "runtime_contract_version"
            ],
            "workflow_identity": source["workflow_identity"],
            "workflow_ref": source["workflow_ref"],
        }
        self.source_verification.write_bytes(canonical(receipt))
        self.source_verification.chmod(0o600)

    def _migration(self, seed: int):
        names = ["apps.0001_initial", "apps.0002_release"]
        if seed > 1:
            names.append(f"apps.00{seed + 1}_release")
        names.sort()
        leaves = [names[-1]]
        return {
            "schema_version": 1,
            "all_migrations_atomic": True,
            "migrations": names,
            "migration_set_sha256": release_transition.migration_digest(names),
            "leaves": leaves,
            "leaf_set_sha256": release_transition.migration_digest(leaves, leaves=True),
        }

    def _make_evidence(self, directory: Path, *, tag: str, commit: str, epoch: int, accepted, seed: int):
        directory.mkdir(mode=0o700)
        root_bytes = (f'{{"trustedRoot":{seed}}}\n').encode("ascii")
        root_digest = upgrade._sha256_bytes(root_bytes)
        bundle_bytes = (f'{{"bundle":{seed}}}\n').encode("ascii")
        verifier_index = digest(hex(seed)[2:])
        verifier = {
            "reference": f"ghcr.io/bilal414/backupsheep-release-verifier@{verifier_index}",
            "runtime_contract_version": 1,
            "linux_amd64_manifest": digest(hex(seed + 1)[2:]),
            "linux_amd64_config": digest(hex(seed + 2)[2:]),
            "linux_arm64_manifest": digest(hex(seed + 3)[2:]),
            "linux_arm64_config": digest(hex(seed + 4)[2:]),
            "trusted_root_sha256": root_digest,
        }
        migration = self._migration(seed)
        transition = release_transition.build_transition_record(
            reviewed_policy={"schema_version": 1, "release_epoch": epoch, "accepted_predecessors": accepted},
            migration_contract=migration,
            reviewed_policy_file="transition/reviewed-policy.json",
            reviewed_policy_sha256=digest("d"),
            migration_contract_file="transition/django-migrations.json",
            migration_contract_sha256=digest("e"),
        )
        roles = {
            "app": "ghcr.io/bilal414/backupsheep",
            "postgres": "ghcr.io/bilal414/backupsheep-postgres",
            "egress": "ghcr.io/bilal414/backupsheep-egress",
            "rabbitmq": "ghcr.io/bilal414/backupsheep-rabbitmq",
            "rabbitmq-upgrade": "ghcr.io/bilal414/backupsheep-rabbitmq-upgrade",
        }
        images = {}
        image_references = {}
        receipts = {}
        for index, (role, repository) in enumerate(roles.items(), start=seed + 10):
            index_digest = digest(hex(index)[2:])
            reference = f"{repository}@{index_digest}"
            image_references[role] = reference
            receipts[f"{role.replace('-', '_')}_image_id"] = digest(hex(index + 20)[2:])
            images[role] = {
                "official_reference": reference,
                "digest": index_digest,
                "platforms": {
                    "linux/amd64": digest(hex(index + 30)[2:]),
                    "linux/arm64": digest(hex(index + 40)[2:]),
                },
            }
        receipts["cosign_image_id"] = verifier["linux_amd64_config"]
        manifest = {
            "schema_version": 4,
            "release": {
                "tag": tag,
                "source_commit": commit,
                "workflow_identity": f"https://github.com/bilal414/backupsheep/.github/workflows/release-images.yml@refs/tags/{tag}",
            },
            "vulnerability_database": {},
            "consumer": {
                "cosign_image": {
                    "version": "3.1.3",
                    "runtime_contract_version": 1,
                    "repository": "ghcr.io/bilal414/backupsheep-release-verifier",
                    "index_digest": verifier_index,
                    "reference": verifier["reference"],
                    "platforms": [
                        {
                            "platform": "linux/amd64",
                            "manifest_digest": verifier["linux_amd64_manifest"],
                            "config_digest": verifier["linux_amd64_config"],
                            "source_catalog": {},
                            "vulnerability_report": {},
                        },
                        {
                            "platform": "linux/arm64",
                            "manifest_digest": verifier["linux_arm64_manifest"],
                            "config_digest": verifier["linux_arm64_config"],
                            "source_catalog": {},
                            "vulnerability_report": {},
                        },
                    ],
                }
            },
            "transition": transition,
            "images": images,
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("ascii") + b"\n"
        manifest_digest = upgrade._sha256_bytes(manifest_bytes)
        descriptor = [
            "BACKUPSHEEP-SIGNED-RELEASE-V2",
            f"release_tag={tag}",
            f"source_commit={commit}",
            f"release_manifest_sha256={manifest_digest}",
            f"app_image={image_references['app']}",
            f"postgres_image={image_references['postgres']}",
            f"egress_image={image_references['egress']}",
            f"rabbitmq_image={image_references['rabbitmq']}",
            f"rabbitmq_upgrade_image={image_references['rabbitmq-upgrade']}",
            f"release_verifier_image={verifier['reference']}",
            "release_verifier_runtime_contract_version=1",
            f"release_verifier_linux_amd64_manifest={verifier['linux_amd64_manifest']}",
            f"release_verifier_linux_amd64_config={verifier['linux_amd64_config']}",
            f"release_verifier_linux_arm64_manifest={verifier['linux_arm64_manifest']}",
            f"release_verifier_linux_arm64_config={verifier['linux_arm64_config']}",
            f"trusted_root_sha256={root_digest}",
        ]
        descriptor_bytes = ("\n".join(descriptor) + "\n").encode("ascii")
        verification = {
            "daemon_identity_sha256": digest("daemon"),
            "descriptor_bundle_sha256": upgrade._sha256_bytes(bundle_bytes),
            "descriptor_sha256": upgrade._sha256_bytes(descriptor_bytes),
            "manifest_sha256": manifest_digest,
            "migration_leaf_set_sha256": migration["leaf_set_sha256"],
            "migration_set_sha256": migration["migration_set_sha256"],
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "platform": "linux/amd64",
            "purpose": "target",
            "release_epoch": epoch,
            "release_tag": tag,
            "runtime_contract_version": 1,
            "schema_version": 2,
            "source_commit": commit,
            "trigger": "push",
            "trusted_root_sha256": root_digest,
            "verifier_config_digest": verifier["linux_amd64_config"],
            "verifier_manifest_digest": verifier["linux_amd64_manifest"],
            "verifier_reference": verifier["reference"],
            "workflow_identity": f"https://github.com/bilal414/backupsheep/.github/workflows/release-images.yml@refs/tags/{tag}",
            "workflow_ref": f"refs/tags/{tag}",
        }
        files = {
            "backupsheep-release-descriptor-v2.txt": descriptor_bytes,
            "backupsheep-release-descriptor-v2.sigstore.json": bundle_bytes,
            "release-manifest.json": manifest_bytes,
            "sigstore-trusted-root.json": root_bytes,
            "signature-verification.json": canonical(verification),
            "local-images.txt": "".join(f"{key}={value}\n" for key, value in receipts.items()).encode("ascii"),
        }
        for name, payload in files.items():
            path = directory / name
            path.write_bytes(payload)
            path.chmod(0o600)
        return upgrade.build_release_state(directory, "linux/amd64")

    def _initialize(self):
        return upgrade.initialize_journal(
            install_dir=self.install,
            source_evidence=self.source_evidence,
            target_evidence=self.target_evidence,
            source_env=self.source_env,
            target_env=self.target_env,
            source_verification=self.source_verification,
            witness_request=self.request,
        )

    def test_authorized_source_receipt_uses_source_verifier_contract(self):
        source = upgrade.build_release_state(self.source_evidence, "linux/amd64")
        target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        self.assertNotEqual(source["verifier"], target["verifier"])
        receipt = upgrade.build_authorized_predecessor_verification(
            source_evidence=self.source_evidence,
            target_evidence=self.target_evidence,
            daemon_os="linux",
            daemon_architecture="amd64",
            daemon_identity_sha256=digest("daemon"),
        )
        self.assertEqual(receipt["verifier_reference"], source["verifier"]["reference"])
        self.assertEqual(
            receipt["verifier_manifest_digest"],
            source["verifier"]["linux_amd64_manifest"],
        )
        self.assertEqual(
            receipt["verifier_config_digest"],
            source["verifier"]["linux_amd64_config"],
        )
        self.assertEqual(self.source_verification.read_bytes(), canonical(receipt))

    def test_shell_stage_contract_accepts_only_exact_target_authorized_source(self):
        receipt = upgrade.build_authorized_predecessor_verification(
            source_evidence=self.source_evidence,
            target_evidence=self.target_evidence,
            daemon_os="linux",
            daemon_architecture="amd64",
            daemon_identity_sha256=digest("daemon"),
        )
        receipt_path = self.install / ".authorization-candidate.json"
        receipt_path.write_bytes(canonical(receipt))
        receipt_path.chmod(0o600)
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        command = r'''
source "$1"
INSTALL_DIR="$2"
RUNTIME_JSON_PARSER="$3"
SOURCE_EVIDENCE_DIR="$4"
TARGET_EVIDENCE_DIR="$5"
SOURCE_RELEASE_TAG=v1.0.0
SOURCE_RELEASE_COMMIT=1111111111111111111111111111111111111111
DAEMON_OS=linux
DAEMON_ARCH=amd64
DAEMON_IDENTITY_SHA256="$6"
receipt="$(<"$7")"
validate_authorized_source_receipt "$receipt"
RELEASE_TAG="$SOURCE_RELEASE_TAG"
SOURCE_COMMIT="$SOURCE_RELEASE_COMMIT"
INSTALLATION_PATH_DIGEST=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
activate_authorized_source_verifier_contract "$receipt"
[[ "$VERIFIER_PURPOSE" == authorized-predecessor ]]
[[ "$ACTIVE_VERIFIER_IMAGE" == "$8" ]]
[[ "$ACTIVE_VERIFIER_AMD64_IMAGE_ID" == "$9" ]]
[[ "$VERIFIER_AUTHORIZING_DESCRIPTOR_SHA256" == "${10}" ]]
[[ "$VERIFIER_NAME" == *-s-* ]]
'''
        arguments = [
            "bash",
            "-c",
            command,
            "signed-stage-contract",
            str(consumer),
            str(self.install),
            str(ROOT / "deploy/runtime/compose-json.awk"),
            str(self.source_evidence),
            str(self.target_evidence),
            digest("daemon"),
            str(receipt_path),
            receipt["verifier_reference"],
            receipt["verifier_config_digest"],
            receipt["authorizing_target_descriptor_sha256"],
        ]
        accepted = subprocess.run(arguments, check=False, capture_output=True, text=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        for key, replacement in (
            ("source_release_tag", "v9.9.9"),
            ("source_commit", "f" * 40),
            ("daemon_identity_sha256", digest("other-daemon")),
            ("authorizing_target_descriptor_sha256", digest("other-target")),
            ("source_trusted_root_sha256", digest("other-root")),
            ("verifier_reference", f"ghcr.io/bilal414/backupsheep-release-verifier@{digest('other-verifier')}"),
            ("verifier_runtime_contract_version", 2),
        ):
            with self.subTest(key=key):
                tampered = dict(receipt)
                tampered[key] = replacement
                receipt_path.write_bytes(canonical(tampered))
                refused = subprocess.run(
                    arguments, check=False, capture_output=True, text=True
                )
                self.assertNotEqual(refused.returncode, 0)

    def test_authorized_source_receipt_publication_is_no_clobber_and_retryable(self):
        receipt = upgrade.build_authorized_predecessor_verification(
            source_evidence=self.source_evidence,
            target_evidence=self.target_evidence,
            daemon_os="linux",
            daemon_architecture="amd64",
            daemon_identity_sha256=digest("daemon"),
        )
        payload = canonical(receipt).decode("ascii").rstrip("\n")
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        command = r'''
source "$1"
INSTALL_DIR="$2"
SOURCE_VERIFICATION_PATH="$3"
durable_sync() { :; }
publish_authorized_source_receipt "$4"
'''
        call = [
            "bash",
            "-c",
            command,
            "signed-source-receipt-publish",
            str(consumer),
            str(self.install),
            str(self.source_verification),
            payload,
        ]
        self.source_verification.unlink()
        candidate = Path(f"{self.source_verification}.new")
        candidate.write_text(payload + "\n", encoding="ascii")
        candidate.chmod(0o600)
        resumed = subprocess.run(call, check=False, capture_output=True, text=True)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertFalse(candidate.exists())
        self.assertEqual(self.source_verification.read_text(encoding="ascii"), payload + "\n")
        replay = subprocess.run(call, check=False, capture_output=True, text=True)
        self.assertEqual(replay.returncode, 0, replay.stderr)

        os.link(self.source_verification, candidate)
        linked_retry = subprocess.run(
            call, check=False, capture_output=True, text=True
        )
        self.assertEqual(linked_retry.returncode, 0, linked_retry.stderr)
        self.assertFalse(candidate.exists())
        self.assertEqual(self.source_verification.stat().st_nlink, 1)

        self.source_verification.write_text("tampered\n", encoding="ascii")
        self.source_verification.chmod(0o600)
        refused = subprocess.run(call, check=False, capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("conflicts", refused.stderr)

    def test_release_state_parses_the_same_bytes_it_hashes(self):
        manifest_path = self.target_evidence / "release-manifest.json"
        original_manifest = manifest_path.read_bytes()
        tampered_manifest = json.loads(original_manifest)
        tampered_manifest["transition"]["accepted_predecessors"] = []
        tampered_bytes = json.dumps(tampered_manifest, indent=2).encode("ascii") + b"\n"
        original_read = upgrade._read_regular
        reads: dict[str, int] = {}

        def swap_after_read(path: Path, *args, **kwargs):
            payload = original_read(path, *args, **kwargs)
            reads[path.name] = reads.get(path.name, 0) + 1
            if path == manifest_path:
                manifest_path.write_bytes(tampered_bytes)
                manifest_path.chmod(0o600)
            return payload

        with mock.patch.object(upgrade, "_read_regular", side_effect=swap_after_read):
            state = upgrade.build_release_state(
                self.target_evidence, "linux/amd64"
            )
        self.assertEqual(reads["release-manifest.json"], 1)
        self.assertEqual(len(state["accepted_predecessors"]), 1)
        self.assertEqual(
            state["manifest_sha256"], upgrade._sha256_bytes(original_manifest)
        )

    def test_regular_reader_refuses_fifo_without_blocking(self):
        fifo = self.install / "untrusted-input"
        os.mkfifo(fifo, 0o600)
        started = __import__("time").monotonic()
        with self.assertRaises(upgrade.UpgradeJournalError):
            upgrade._read_regular(fifo, owner=os.geteuid(), modes={0o600})
        self.assertLess(__import__("time").monotonic() - started, 1.0)

    def _operation_dir(self, intent: dict) -> Path:
        return (
            self.install
            / upgrade.JOURNAL_ROOT_NAME
            / upgrade.OPERATIONS_NAME
            / intent["operation_id"]
        )

    def _complete(self, intent: dict) -> None:
        for phase in upgrade.PHASES:
            self._append(phase, intent)

    def _prepare_next_transition(
        self, source_state: dict, *, target_tag: str, target_commit: str, target_epoch: int
    ) -> None:
        shutil.rmtree(self.source_evidence)
        shutil.copytree(self.target_evidence, self.source_evidence)
        for path in self.source_evidence.iterdir():
            path.chmod(0o600)
        self.source_env.write_bytes(
            f"BACKUPSHEEP_RELEASE_TAG='{source_state['release_tag']}'\n".encode("ascii")
        )
        self.source_env.chmod(0o600)
        shutil.rmtree(self.target_evidence)
        predecessor = upgrade._predecessor_projection(source_state)
        self._make_evidence(
            self.target_evidence,
            tag=target_tag,
            commit=target_commit,
            epoch=target_epoch,
            accepted=[predecessor],
            seed=8,
        )
        target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        request = json.loads(self.request.read_text())
        request["checkouts"] = {
            "source": {
                "commit": source_state["source_commit"],
                "tree_sha256": digest(f"tree-{source_state['source_commit']}"),
                "runtime_files_sha256": digest(
                    f"runtime-{source_state['source_commit']}"
                ),
            },
            "target": {
                "commit": target["source_commit"],
                "tree_sha256": digest(f"tree-{target['source_commit']}"),
                "runtime_files_sha256": digest(
                    f"runtime-{target['source_commit']}"
                ),
            },
        }
        request["attempt_nonce"] = hashlib.sha256(target_tag.encode("ascii")).hexdigest()
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        self._write_source_verification(source_state, target)
        self.target_env.write_bytes(
            f"BACKUPSHEEP_RELEASE_TAG='{target_tag}'\n".encode("ascii")
        )
        self.target_env.chmod(0o600)

    def _payload(self, phase: str, intent: dict):
        source_state = upgrade._state_digest(intent["source"])
        target_state = upgrade._state_digest(intent["target"])
        source_checkout = intent["checkouts"]["source"]
        target_checkout = intent["checkouts"]["target"]
        source_checkout_digest = upgrade._domain_digest(
            "BackupSheep/upgrade-checkout/v1", source_checkout
        )
        target_checkout_digest = upgrade._domain_digest(
            "BackupSheep/upgrade-checkout/v1", target_checkout
        )

        def migrations(release):
            return {
                "count": len(release["migration"]["migrations"]),
                "set_sha256": release["migration"]["migration_set_sha256"],
                "leaf_count": len(release["migration"]["leaves"]),
                "leaf_set_sha256": release["migration"]["leaf_set_sha256"],
                "missing": [],
                "unknown": [],
            }

        def resources(model_sha256: str, marker: str):
            value = {
                "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
                "compose_model_sha256": model_sha256,
                "volume_records_sha256": intent["resource_digests"][
                    "volume_records_sha256"
                ],
                "network_records_sha256": digest(f"network-{marker}"),
                "container_records_sha256": digest(f"containers-{marker}"),
                "storage_aggregate_sha256": intent["resource_digests"][
                    "volume_records_sha256"
                ],
                "artifact_provider_aggregate_sha256": intent["resource_digests"][
                    "artifact_provider_sha256"
                ],
            }
            value["aggregate_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-resource-set/v1", value
            )
            return value

        def container(service: str, state: str = "running"):
            if state == "absent":
                return {"service": service, "state": "absent"}
            return {
                "service": service,
                "container_id": hashlib.sha256(service.encode("ascii")).hexdigest(),
                "image_config_sha256": digest(f"image-{service}"),
                "compose_config_sha256": digest(f"compose-{service}"),
                "state": state,
                "health": "healthy",
                "restart_count": 0,
            }

        def runtime(services, running):
            records = [
                container(service, "running" if service in running else "absent")
                for service in services
            ]
            return {
                "records": records,
                "records_sha256": upgrade._domain_digest(
                    "BackupSheep/upgrade-runtime-records/v1", records
                ),
            }

        forward_binding = {
            "active_checkout_sha256": target_checkout_digest,
            "active_env_sha256": intent["environment"]["target_sha256"],
            "active_evidence_sha256": target_state,
            "active_model_sha256": intent["compose"]["target_model_sha256"],
            "source_pre_migration": migrations(intent["source"]),
            "target_code_inventory": [],
            "storage_aggregate_sha256": intent["resource_digests"][
                "volume_records_sha256"
            ],
            "artifact_provider_aggregate_sha256": intent["resource_digests"][
                "artifact_provider_sha256"
            ],
            "boundary_nonce": intent["attempt_nonce"],
        }
        forward_binding["boundary_sha256"] = upgrade._domain_digest(
            f"BackupSheep/forward-only/{intent['operation_id']}/v1", forward_binding
        )
        values = {
            "10-prepared": {
                "source_release_sha256": source_state,
                "target_release_sha256": target_state,
                "source_verification_sha256": intent["authorization"]["source_verification_sha256"],
                "target_verification_sha256": intent["target"]["signature_verification_sha256"],
                "authorized_predecessor_sha256": intent["authorization"]["predecessor_sha256"],
                "source_checkout": source_checkout,
                "target_checkout": target_checkout,
                "source_env_sha256": intent["environment"]["source_sha256"],
                "target_env_sha256": intent["environment"]["target_sha256"],
                "target_model_sha256": intent["compose"]["target_model_sha256"],
                "source_migrations": migrations(intent["source"]),
                "resources": resources(intent["compose"]["source_model_sha256"], "prepared"),
            },
            "20-stopped": {
                "source_checkout_sha256": source_checkout_digest,
                "source_env_sha256": intent["environment"]["source_sha256"],
                "source_evidence_sha256": source_state,
                "source_keyrings_sha256": intent["resource_digests"]["artifact_provider_sha256"],
                "stopped_writer_services": [
                    {"service": service, "state": "absent"}
                    for service in upgrade.WRITER_SERVICES
                ],
                "source_migrations": migrations(intent["source"]),
                "detached_volume_records_sha256": intent["resource_digests"]["volume_records_sha256"],
                "resources": resources(intent["compose"]["source_model_sha256"], "stopped"),
            },
            "30-switched": {
                "active_checkout": target_checkout,
                "active_env_sha256": intent["environment"]["target_sha256"],
                "active_evidence_sha256": target_state,
                "active_model_sha256": intent["compose"]["target_model_sha256"],
                "target_code_inventory": [],
                "target_writer_inventory": [],
                "active_pointer_sha256": intent["target_active_pointer_sha256"],
                "resources": resources(intent["compose"]["target_model_sha256"], "switched"),
            },
            "40-forward-only": forward_binding,
            "50-migrated": {
                "target_app_config_sha256": intent["target"]["images"]["app"]["config_digest"],
                "runner": {
                    "container_id": "d" * 64,
                    "image_config_sha256": intent["target"]["images"]["app"]["config_digest"],
                    "compose_config_sha256": digest("migration-compose-config"),
                    "outcome": "exit-zero",
                    "exit_code": 0,
                    "receipt_sha256": digest("migration-runner-receipt"),
                },
                "target_migrations": migrations(intent["target"]),
                "storage_aggregate_sha256": intent["resource_digests"]["volume_records_sha256"],
            },
            "60-core-accepted": {
                "db_seal": {"outcome": "exit-zero", "receipt_sha256": digest("db-seal")},
                "preflight": {"outcome": "exit-zero", "receipt_sha256": digest("preflight")},
                "core_runtime": runtime(upgrade.CORE_SERVICES, set(upgrade.CORE_SERVICES)),
                "target_migrations": migrations(intent["target"]),
                "functional_probe_sha256": digest("core-probe"),
                "resources": resources(intent["compose"]["target_model_sha256"], "core"),
            },
            "70-activated": {
                "activation_mode": "core-only",
                "active_pointer_sha256": intent["target_active_pointer_sha256"],
                "active_checkout_sha256": target_checkout_digest,
                "active_env_sha256": intent["environment"]["target_sha256"],
                "active_evidence_sha256": target_state,
                "active_release_sha256": target_state,
                "local_images_sha256": intent["target"]["local_images_sha256"],
                "runtime": runtime(upgrade.ALL_SERVICES, set(upgrade.CORE_SERVICES)),
                "resources": resources(intent["compose"]["target_model_sha256"], "activated"),
            },
        }
        return values[phase]

    def _append(self, phase: str, intent: dict):
        payload = self.install / f".{phase}.payload.json"
        payload.write_bytes(canonical(self._payload(phase, intent)))
        payload.chmod(0o600)
        try:
            return upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase=phase,
                payload_path=payload,
            )
        finally:
            payload.unlink(missing_ok=True)

    def _rollback_payload(self, intent: dict):
        migration = intent["source"]["migration"]
        resources = {
            "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
            "compose_model_sha256": intent["compose"]["source_model_sha256"],
            "volume_records_sha256": intent["resource_digests"]["volume_records_sha256"],
            "network_records_sha256": digest("rollback-networks"),
            "container_records_sha256": digest("rollback-containers"),
            "storage_aggregate_sha256": intent["resource_digests"]["volume_records_sha256"],
            "artifact_provider_aggregate_sha256": intent["resource_digests"]["artifact_provider_sha256"],
        }
        resources["aggregate_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-resource-set/v1", resources
        )
        return {
            "source_checkout_sha256": upgrade._domain_digest(
                "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["source"]
            ),
            "source_env_sha256": intent["environment"]["source_sha256"],
            "source_evidence_sha256": upgrade._state_digest(intent["source"]),
            "source_model_sha256": intent["compose"]["source_model_sha256"],
            "source_migrations": {
                "count": len(migration["migrations"]),
                "set_sha256": migration["migration_set_sha256"],
                "leaf_count": len(migration["leaves"]),
                "leaf_set_sha256": migration["leaf_set_sha256"],
                "missing": [],
                "unknown": [],
            },
            "target_code_inventory": [],
            "resources": resources,
        }

    def _rollback(self, intent: dict):
        payload = self.install / ".rollback.payload.json"
        payload.write_bytes(canonical(self._rollback_payload(intent)))
        payload.chmod(0o600)
        try:
            return upgrade.append_rollback(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                payload_path=payload,
            )
        finally:
            payload.unlink(missing_ok=True)

    def test_exact_authorized_transition_initializes_and_all_phases_chain(self):
        intent = self._initialize()
        self.assertEqual(intent["source"]["release_tag"], "v1.0.0")
        self.assertEqual(intent["target"]["release_tag"], "v2.0.0")
        operation_dir = self._operation_dir(intent)
        self.assertEqual(
            (operation_dir / "pre-upgrade.env").read_bytes(), self.source_env.read_bytes()
        )
        for phase in upgrade.PHASES:
            self._append(phase, intent)
            _, actual = upgrade.validate_journal(
                self.install, operation_id=intent["operation_id"]
            )
            self.assertEqual(actual, phase)
        operation = upgrade.finalize_completed(
            install_dir=self.install, operation_id=intent["operation_id"]
        )
        self.assertEqual(operation, intent["operation_id"])
        self.assertTrue(operation_dir.is_dir())
        self.assertEqual(
            upgrade.journal_status(install_dir=self.install, operation_id=operation),
            {
                "schema_version": 1,
                "forward_only": True,
                "highest_phase": "70-activated",
                "next_phase": None,
                "operation_id": operation,
                "receipt_chain_head_sha256": upgrade._sha256_bytes(
                    (operation_dir / "70-activated.json").read_bytes()
                ),
                "rollback_eligible": False,
                "source_release_tag": "v1.0.0",
                "source_execution_allowed": False,
                "state": "activated",
                "target_release_tag": "v2.0.0",
                "terminal": True,
                "terminal_outcome": "activated",
            },
        )

    def test_rollback_is_terminal_before_boundary_and_attempt_nonce_allows_retry(self):
        first = self._initialize()
        for phase in upgrade.PHASES[:3]:
            self._append(phase, first)
        self._rollback(first)
        status = upgrade.journal_status(
            install_dir=self.install, operation_id=first["operation_id"]
        )
        self.assertEqual(status["state"], "rolled-back")
        self.assertTrue(status["terminal"])
        self.assertFalse(status["forward_only"])
        self.assertTrue(status["source_execution_allowed"])
        self.assertFalse(status["rollback_eligible"])
        self._rollback(first)

        request = json.loads(self.request.read_text())
        request["attempt_nonce"] = "c" * 64
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        second = self._initialize()
        self.assertNotEqual(second["operation_id"], first["operation_id"])

    def test_rollback_is_forbidden_after_forward_only_boundary(self):
        intent = self._initialize()
        for phase in upgrade.PHASES[:4]:
            self._append(phase, intent)
        payload = self.install / ".rollback.payload.json"
        payload.write_bytes(canonical(self._rollback_payload(intent)))
        payload.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "forward-only"):
            upgrade.append_rollback(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                payload_path=payload,
            )

    def test_completed_operations_are_retained_and_only_one_may_remain_open(self):
        first = self._initialize()
        self._complete(first)
        upgrade.finalize_completed(
            install_dir=self.install, operation_id=first["operation_id"]
        )

        self._prepare_next_transition(
            self.target_state,
            target_tag="v3.0.0",
            target_commit="3" * 40,
            target_epoch=3,
        )
        second = self._initialize()
        self._complete(second)
        upgrade.finalize_completed(
            install_dir=self.install, operation_id=second["operation_id"]
        )
        self.assertTrue(self._operation_dir(first).is_dir())
        self.assertTrue(self._operation_dir(second).is_dir())
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "selection is ambiguous"):
            upgrade.validate_journal(self.install)

        second_target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        self._prepare_next_transition(
            second_target,
            target_tag="v4.0.0",
            target_commit="4" * 40,
            target_epoch=4,
        )
        third = self._initialize()
        self.assertFalse(upgrade.journal_status(
            install_dir=self.install, operation_id=third["operation_id"]
        )["terminal"])
        third_target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        self._prepare_next_transition(
            third_target,
            target_tag="v5.0.0",
            target_commit="5" * 40,
            target_epoch=5,
        )
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "remains open"):
            self._initialize()

    def test_corrupt_completed_operation_blocks_before_new_operation_creation(self):
        first = self._initialize()
        self._complete(first)
        first_operation = self._operation_dir(first)
        (first_operation / "70-activated.json").chmod(0o600)
        self._prepare_next_transition(
            self.target_state,
            target_tag="v3.0.0",
            target_commit="3" * 40,
            target_epoch=3,
        )
        operations = first_operation.parent
        self.assertEqual({item.name for item in operations.iterdir()}, {first["operation_id"]})
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "unsafe permissions"):
            self._initialize()
        self.assertEqual({item.name for item in operations.iterdir()}, {first["operation_id"]})

    def test_retry_is_idempotent_but_alternate_target_and_payload_fail(self):
        intent = self._initialize()
        self.assertEqual(self._initialize(), intent)
        self._append("10-prepared", intent)
        self._append("10-prepared", intent)
        bad = self._payload("10-prepared", intent)
        bad["target_verification_sha256"] = digest("f")
        payload = self.install / ".bad.payload.json"
        payload.write_bytes(canonical(bad))
        payload.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "differs|mismatch"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="10-prepared",
                payload_path=payload,
            )
        self.target_env.write_bytes(b"BACKUPSHEEP_RELEASE_TAG='v2.0.1'\n")
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "target.env differs|intent.json differs"):
            self._initialize()

    def test_target_environment_and_fresh_source_verification_are_retained(self):
        intent = self._initialize()
        operation = self._operation_dir(intent)
        self.assertEqual(
            (operation / upgrade.TARGET_ENV_NAME).read_bytes(),
            self.target_env.read_bytes(),
        )
        self.assertEqual(
            (operation / upgrade.SOURCE_VERIFICATION_NAME).read_bytes(),
            self.source_verification.read_bytes(),
        )
        self.assertEqual(
            (operation / upgrade.SOURCE_VERIFICATION_NAME).stat().st_mode & 0o777,
            0o400,
        )

    def test_replayed_target_receipt_is_not_authorized_predecessor_proof(self):
        self.source_verification.write_bytes(
            (self.source_evidence / "signature-verification.json").read_bytes()
        )
        self.source_verification.chmod(0o600)
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError,
            "authorized-predecessor verification receipt",
        ):
            self._initialize()
        self.assertFalse((self.install / upgrade.JOURNAL_ROOT_NAME).exists())

    def test_volume_witness_set_and_physical_names_are_exact(self):
        request = json.loads(self.request.read_text())
        request["volumes"].pop("backup_workdir")
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "volume witnesses"):
            self._initialize()
        self.assertFalse((self.install / upgrade.JOURNAL_ROOT_NAME).exists())

        request = self._request()
        request["volumes"]["postgres_data_v1"]["name"] = "foreign_postgres_data_v1"
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "Compose project identity"):
            self._initialize()

    def test_unauthorized_source_epoch_or_verifier_contract_fails_before_journal(self):
        manifest_path = self.target_evidence / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["transition"]["accepted_predecessors"][0]["verifier"]["linux_amd64_config"] = digest("f")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="ascii")
        descriptor_path = self.target_evidence / "backupsheep-release-descriptor-v2.txt"
        lines = descriptor_path.read_text().splitlines()
        lines[3] = f"release_manifest_sha256={upgrade._sha256_bytes(manifest_path.read_bytes())}"
        descriptor_path.write_text("\n".join(lines) + "\n", encoding="ascii")
        verification_path = self.target_evidence / "signature-verification.json"
        verification = json.loads(verification_path.read_text())
        verification["manifest_sha256"] = upgrade._sha256_bytes(manifest_path.read_bytes())
        verification["descriptor_sha256"] = upgrade._sha256_bytes(descriptor_path.read_bytes())
        verification_path.write_bytes(canonical(verification))
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "authorize"):
            self._initialize()
        self.assertFalse((self.install / upgrade.JOURNAL_ROOT_NAME).exists())

    def test_gap_extra_tamper_and_wrong_migration_receipt_fail_closed(self):
        intent = self._initialize()
        active = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME / intent["operation_id"]
        (active / "unexpected").write_text("x", encoding="ascii")
        (active / "unexpected").chmod(0o400)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "unexpected"):
            upgrade.validate_journal(self.install)
        (active / "unexpected").unlink()
        bad_payload = self._payload("10-prepared", intent)
        bad_payload["source_migrations"]["set_sha256"] = digest("f")
        path = self.install / ".bad.payload.json"
        path.write_bytes(canonical(bad_payload))
        path.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "migration"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="10-prepared",
                payload_path=path,
            )
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "next contiguous"):
            self._append("20-stopped", intent)

    def test_migration_unknowns_and_core_only_operation_container_fail_closed(self):
        intent = self._initialize()
        for phase in upgrade.PHASES[:4]:
            self._append(phase, intent)
        bad_migration = self._payload("50-migrated", intent)
        bad_migration["target_migrations"]["unknown"] = ["apps.9999_attacker"]
        payload = self.install / ".50-migrated.payload.json"
        payload.write_bytes(canonical(bad_migration))
        payload.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "signed migration graph"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="50-migrated",
                payload_path=payload,
            )
        payload.unlink()
        self._append("50-migrated", intent)
        self._append("60-core-accepted", intent)
        bad_activation = self._payload("70-activated", intent)
        worker_index = upgrade.ALL_SERVICES.index("worker-cloud")
        record = {
            "service": "worker-cloud",
            "container_id": "e" * 64,
            "image_config_sha256": digest("worker-cloud-image"),
            "compose_config_sha256": digest("worker-cloud-compose"),
            "state": "running",
            "health": "healthy",
            "restart_count": 0,
        }
        bad_activation["runtime"]["records"][worker_index] = record
        bad_activation["runtime"]["records_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-runtime-records/v1",
            bad_activation["runtime"]["records"],
        )
        payload = self.install / ".70-activated.payload.json"
        payload.write_bytes(canonical(bad_activation))
        payload.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "forbidden service"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="70-activated",
                payload_path=payload,
            )

    def test_interrupted_hardlink_publication_is_reconciled_only_for_exact_bytes(self):
        intent = self._initialize()
        self._append("10-prepared", intent)
        active = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME / intent["operation_id"]
        receipt = active / "10-prepared.json"
        temporary = active / ".10-prepared.json.new"
        os.link(receipt, temporary)
        self._append("10-prepared", intent)
        self.assertFalse(temporary.exists())
        self.assertEqual(receipt.stat().st_nlink, 1)

    def test_truncated_unpublished_temporary_is_safely_recreated(self):
        intent = self._initialize()
        self._append("10-prepared", intent)
        operation = self._operation_dir(intent)
        receipt = operation / "10-prepared.json"
        expected = receipt.read_bytes()
        receipt.unlink()
        temporary = operation / ".10-prepared.json.new"
        temporary.write_bytes(expected[:17])
        temporary.chmod(0o400)
        self._append("10-prepared", intent)
        self.assertEqual(receipt.read_bytes(), expected)
        self.assertFalse(temporary.exists())

        receipt.unlink()
        temporary.write_bytes(b"")
        temporary.chmod(0o400)
        self._append("10-prepared", intent)
        self.assertEqual(receipt.read_bytes(), expected)
        self.assertFalse(temporary.exists())

    def test_noncanonical_evidence_and_journal_symlinks_are_rejected(self):
        local_images = self.source_evidence / "local-images.txt"
        local_images.write_text(local_images.read_text() + "app_image_id=" + digest("f") + "\n")
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "line count"):
            self._initialize()
        # Restore evidence, initialize, then replace a receipt candidate with a symlink.
        shutil.rmtree(self.source_evidence)
        source = self._make_evidence(self.source_evidence, tag="v1.0.0", commit="1" * 40, epoch=1, accepted=[], seed=1)
        intent = self._initialize()
        active = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME / intent["operation_id"]
        (active / ".10-prepared.json.new").symlink_to(self.source_env)
        with self.assertRaises((UpgradeJournalError, OSError)):
            self._append("10-prepared", intent)

    def test_dangling_receipt_symlink_is_never_treated_as_absent(self):
        intent = self._initialize()
        operation = self._operation_dir(intent)
        (operation / "20-stopped.json").symlink_to(operation / "missing")
        with self.assertRaises((UpgradeJournalError, OSError)):
            upgrade.validate_journal(
                self.install, operation_id=intent["operation_id"]
            )


UpgradeJournalError = upgrade.UpgradeJournalError
