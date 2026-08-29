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
        for path in (self.source_env, self.target_env):
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
        request = self._request()
        self._set_request_pointers(request, source, self.target_state)
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)

    def _request(self):
        volumes = {
            role: {
                "name": f"backupsheep_{role}",
                "inspect_sha256": digest(f"volume-inspect-{role}"),
                "ownership_witness_sha256": digest(f"volume-owner-{role}"),
            }
            for role in upgrade.VOLUME_ROLES
        }
        compose = {}
        for side in ("source", "target"):
            contract = {
                "service_config_sha256": {
                    service: digest(f"{side}-service-{service}")
                    for service in upgrade.ALL_SERVICES
                },
                "network_config_sha256": {
                    network: digest(f"{side}-network-{network}")
                    for network in upgrade.NETWORK_ROLES
                },
            }
            contract["model_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-compose-model/v1", contract
            )
            compose[side] = contract
        return {
            "schema_version": 3,
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
            "compose": compose,
            "active_pointer_sha256": {
                "source": digest("source-active-pointer-placeholder"),
                "target": digest("target-active-pointer-placeholder"),
            },
            "source_activation_mode": "core-only",
            "volumes": volumes,
            "artifact_provider": {
                "generation": 1,
                "witness_sha256": digest("a"),
                "database_keyring_sha256": digest("b"),
                "files_keyring_sha256": digest("c"),
            },
        }

    def _set_request_pointers(self, request: dict, source: dict, target: dict) -> None:
        request["active_pointer_sha256"] = {
            "source": upgrade._active_release_pointer_digest(
                release=source,
                checkout=request["checkouts"]["source"],
                environment_sha256=upgrade._sha256_bytes(self.source_env.read_bytes()),
                compose=request["compose"]["source"],
            ),
            "target": upgrade._active_release_pointer_digest(
                release=target,
                checkout=request["checkouts"]["target"],
                environment_sha256=upgrade._sha256_bytes(self.target_env.read_bytes()),
                compose=request["compose"]["target"],
            ),
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

    def _complete_version_chain(self, final_version: int):
        intents = []
        current = None
        for version in range(2, final_version + 1):
            if version > 2:
                assert current is not None
                self._prepare_next_transition(
                    current,
                    target_tag=f"v{version}.0.0",
                    target_commit=str(version) * 40,
                    target_epoch=version,
                )
            intent = self._initialize()
            self._complete(intent)
            intents.append(intent)
            current = upgrade.build_release_state(
                self.target_evidence, "linux/amd64"
            )
        return intents, current

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
        request["compose"]["source"] = request["compose"]["target"]
        request["compose"]["target"] = {
            "service_config_sha256": {
                service: digest(f"target-{target_tag}-service-{service}")
                for service in upgrade.ALL_SERVICES
            },
            "network_config_sha256": {
                network: digest(f"target-{target_tag}-network-{network}")
                for network in upgrade.NETWORK_ROLES
            },
        }
        request["compose"]["target"]["model_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-compose-model/v1",
            {
                key: request["compose"]["target"][key]
                for key in ("service_config_sha256", "network_config_sha256")
            },
        )
        request["attempt_nonce"] = hashlib.sha256(target_tag.encode("ascii")).hexdigest()
        self._write_source_verification(source_state, target)
        self.target_env.write_bytes(
            f"BACKUPSHEEP_RELEASE_TAG='{target_tag}'\n".encode("ascii")
        )
        self.target_env.chmod(0o600)
        self._set_request_pointers(request, source_state, target)
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)

    def _functional_probe(
        self, intent: dict, container_id: str, *, purpose: str, body_label: str
    ) -> dict:
        value = {
            "schema_version": 1,
            "operation_id": intent["operation_id"],
            "installation_id": intent["installation_id"],
            "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
            "purpose": purpose,
            "service": "app",
            "container_id": container_id,
            "endpoint": "http://127.0.0.1:8000/healthz",
            "status_code": 200,
            "outcome": "accepted",
            "body_sha256": digest(body_label),
            "attempts": 1,
        }
        value["receipt_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-functional-probe/v1", value
        )
        return value

    def _rehash_resource_payload(
        self, payload: dict, *, runtime_key: str = "runtime", network_key: str = "networks"
    ) -> None:
        runtime = payload[runtime_key]
        networks = payload[network_key]
        runtime["records_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-runtime-records/v1", runtime["records"]
        )
        for network_record in networks["records"]:
            if network_record["state"] == "absent":
                continue
            endpoint_ids = sorted(
                record["container_id"]
                for record in runtime["records"]
                if record["state"] != "absent"
                and network_record["network"]
                in upgrade.SERVICE_NETWORK_ENDPOINTS.get(record["service"], ())
            )
            network_record["endpoint_container_ids"] = endpoint_ids
            network_record[
                "endpoint_container_ids_sha256"
            ] = upgrade._domain_digest(
                "BackupSheep/upgrade-network-endpoints/v1", endpoint_ids
            )
        networks["records_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-network-records/v1", networks["records"]
        )
        payload["resources"]["container_records_sha256"] = runtime[
            "records_sha256"
        ]
        payload["resources"]["network_records_sha256"] = networks[
            "records_sha256"
        ]
        aggregate = {
            key: payload["resources"][key]
            for key in sorted(set(payload["resources"]) - {"aggregate_sha256"})
        }
        payload["resources"]["aggregate_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-resource-set/v1", aggregate
        )

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

        def container(side: str, service: str, state: str = "running"):
            if state == "absent":
                return {"service": service, "state": "absent"}
            role = upgrade.SERVICE_IMAGE_ROLES[service]
            return {
                "service": service,
                "container_id": hashlib.sha256(
                    f"{side}:{service}".encode("ascii")
                ).hexdigest(),
                "image_config_sha256": intent[side]["images"][role][
                    "config_digest"
                ],
                "compose_config_sha256": intent["compose"][side][
                    "service_config_sha256"
                ][service],
                "state": state,
                "health": "none" if service == "beat" else "healthy",
                "restart_count": 0,
            }

        def runtime(side: str, running):
            records = [
                container(side, service, "running" if service in running else "absent")
                for service in upgrade.ALL_SERVICES
            ]
            project_ids = sorted(
                record["container_id"]
                for record in records
                if record["state"] != "absent"
            )
            return {
                "records": records,
                "records_sha256": upgrade._domain_digest(
                    "BackupSheep/upgrade-runtime-records/v1", records
                ),
                "project_container_ids": project_ids,
                "project_container_ids_sha256": upgrade._domain_digest(
                    "BackupSheep/upgrade-project-container-ids/v1", project_ids
                ),
            }

        def networks(side: str, present, runtime_value: dict):
            records = []
            for network in upgrade.NETWORK_ROLES:
                if network not in present:
                    records.append({"network": network, "state": "absent"})
                    continue
                endpoint_ids = sorted(
                    record["container_id"]
                    for record in runtime_value["records"]
                    if record["state"] != "absent"
                    and network
                    in upgrade.SERVICE_NETWORK_ENDPOINTS.get(
                        record["service"], ()
                    )
                )
                records.append(
                    {
                        "network": network,
                        "name": f"{intent['compose_project']}_{network}",
                        "network_id": hashlib.sha256(
                            f"{side}:{network}".encode("ascii")
                        ).hexdigest(),
                        "compose_config_sha256": intent["compose"][side][
                            "network_config_sha256"
                        ][network],
                        "endpoint_container_ids": endpoint_ids,
                        "endpoint_container_ids_sha256": upgrade._domain_digest(
                            "BackupSheep/upgrade-network-endpoints/v1",
                            endpoint_ids,
                        ),
                        "state": "present",
                    }
                )
            return {
                "records": records,
                "records_sha256": upgrade._domain_digest(
                    "BackupSheep/upgrade-network-records/v1", records
                ),
            }

        def resources(side: str, runtime_value: dict, network_value: dict):
            value = {
                "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
                "compose_model_sha256": intent["compose"][side]["model_sha256"],
                "volume_records_sha256": intent["resource_digests"][
                    "volume_records_sha256"
                ],
                "network_records_sha256": network_value["records_sha256"],
                "container_records_sha256": runtime_value["records_sha256"],
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

        def runner(service: str):
            value = {
                "service": service,
                "container_id": hashlib.sha256(
                    f"runner:{service}".encode("ascii")
                ).hexdigest(),
                "image_config_sha256": intent["target"]["images"][
                    upgrade.SERVICE_IMAGE_ROLES[service]
                ]["config_digest"],
                "compose_config_sha256": intent["compose"]["target"][
                    "service_config_sha256"
                ][service],
                "state": "exited",
                "exit_code": 0,
                "restart_count": 0,
                "outcome": "exit-zero",
            }
            value["inspect_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-one-shot-runner/v1",
                {
                    "operation_id": intent["operation_id"],
                    "installation_id": intent["installation_id"],
                    "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
                    "runner": value,
                },
            )
            return value

        def probe(container_id: str, purpose: str, body_label: str):
            value = {
                "schema_version": 1,
                "operation_id": intent["operation_id"],
                "installation_id": intent["installation_id"],
                "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
                "purpose": purpose,
                "service": "app",
                "container_id": container_id,
                "endpoint": "http://127.0.0.1:8000/healthz",
                "status_code": 200,
                "outcome": "accepted",
                "body_sha256": digest(body_label),
                "attempts": 1,
            }
            value["receipt_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-functional-probe/v1", value
            )
            return value

        source_running = set(upgrade.CORE_SERVICES)
        if intent["source_activation_mode"] == "operations":
            source_running.update(upgrade.OPERATION_SERVICES)
        source_networks_present = (
            set(upgrade.NETWORK_ROLES)
            if intent["source_activation_mode"] == "operations"
            else set(upgrade.CORE_NETWORK_ROLES)
        )
        source_runtime = runtime("source", source_running)
        source_networks = networks(
            "source", source_networks_present, source_runtime
        )
        source_stopped_runtime = runtime("source", set())
        source_stopped_networks = networks(
            "source", set(), source_stopped_runtime
        )
        target_empty_runtime = runtime("target", set())
        target_empty_networks = networks("target", set(), target_empty_runtime)
        target_migrated_runtime = runtime("target", {"db", "rabbitmq"})
        target_core_runtime = runtime("target", set(upgrade.CORE_SERVICES))
        target_migrated_networks = networks(
            "target",
            set(upgrade.CORE_NETWORK_ROLES),
            target_migrated_runtime,
        )
        target_core_networks = networks(
            "target", set(upgrade.CORE_NETWORK_ROLES), target_core_runtime
        )

        forward_binding = {
            "active_checkout_sha256": target_checkout_digest,
            "active_env_sha256": intent["environment"]["target_sha256"],
            "active_evidence_sha256": target_state,
            "active_model_sha256": intent["compose"]["target"]["model_sha256"],
            "source_pre_migration": migrations(intent["source"]),
            "target_code_inventory": [],
            "runtime": target_empty_runtime,
            "networks": target_empty_networks,
            "resources": resources(
                "target", target_empty_runtime, target_empty_networks
            ),
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
                "target_model_sha256": intent["compose"]["target"]["model_sha256"],
                "source_migrations": migrations(intent["source"]),
                "source_runtime": source_runtime,
                "source_networks": source_networks,
                "resources": resources("source", source_runtime, source_networks),
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
                "runtime": source_stopped_runtime,
                "networks": source_stopped_networks,
                "resources": resources(
                    "source", source_stopped_runtime, source_stopped_networks
                ),
            },
            "30-switched": {
                "active_checkout": target_checkout,
                "active_env_sha256": intent["environment"]["target_sha256"],
                "active_evidence_sha256": target_state,
                "active_model_sha256": intent["compose"]["target"]["model_sha256"],
                "target_code_inventory": [],
                "target_writer_inventory": [],
                "active_pointer_sha256": intent["active_pointer_sha256"]["target"],
                "runtime": target_empty_runtime,
                "networks": target_empty_networks,
                "resources": resources(
                    "target", target_empty_runtime, target_empty_networks
                ),
            },
            "40-forward-only": forward_binding,
            "50-migrated": {
                "runner": runner("migrate"),
                "target_migrations": migrations(intent["target"]),
                "runtime": target_migrated_runtime,
                "networks": target_migrated_networks,
                "resources": resources(
                    "target", target_migrated_runtime, target_migrated_networks
                ),
            },
            "60-core-accepted": {
                "db_seal": runner("db-seal"),
                "preflight": runner("preflight"),
                "runtime": target_core_runtime,
                "networks": target_core_networks,
                "target_migrations": migrations(intent["target"]),
                "functional_probe": probe(
                    target_core_runtime["records"][upgrade.ALL_SERVICES.index("app")][
                        "container_id"
                    ],
                    "core-acceptance",
                    "core-probe-body",
                ),
                "resources": resources(
                    "target", target_core_runtime, target_core_networks
                ),
            },
            "70-activated": {
                "activation_mode": "core-only",
                "active_pointer_sha256": intent["active_pointer_sha256"]["target"],
                "active_checkout_sha256": target_checkout_digest,
                "active_env_sha256": intent["environment"]["target_sha256"],
                "active_evidence_sha256": target_state,
                "active_release_sha256": target_state,
                "local_images_sha256": intent["target"]["local_images_sha256"],
                "runtime": target_core_runtime,
                "networks": target_core_networks,
                "resources": resources(
                    "target", target_core_runtime, target_core_networks
                ),
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
        source_running = set(upgrade.CORE_SERVICES)
        if intent["source_activation_mode"] == "operations":
            source_running.update(upgrade.OPERATION_SERVICES)

        records = []
        for service in upgrade.ALL_SERVICES:
            if service not in source_running:
                records.append({"service": service, "state": "absent"})
                continue
            role = upgrade.SERVICE_IMAGE_ROLES[service]
            records.append(
                {
                    "service": service,
                    "container_id": hashlib.sha256(
                        f"rollback:{service}".encode("ascii")
                    ).hexdigest(),
                    "image_config_sha256": intent["source"]["images"][role][
                        "config_digest"
                    ],
                    "compose_config_sha256": intent["compose"]["source"][
                        "service_config_sha256"
                    ][service],
                    "state": "running",
                    "health": "none" if service == "beat" else "healthy",
                    "restart_count": 0,
                }
            )
        runtime = {
            "records": records,
            "records_sha256": upgrade._domain_digest(
                "BackupSheep/upgrade-runtime-records/v1", records
            ),
            "project_container_ids": sorted(
                record["container_id"]
                for record in records
                if record["state"] != "absent"
            ),
        }
        runtime["project_container_ids_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-project-container-ids/v1",
            runtime["project_container_ids"],
        )
        present_networks = (
            set(upgrade.NETWORK_ROLES)
            if intent["source_activation_mode"] == "operations"
            else set(upgrade.CORE_NETWORK_ROLES)
        )
        network_records = []
        for network in upgrade.NETWORK_ROLES:
            if network not in present_networks:
                network_records.append({"network": network, "state": "absent"})
                continue
            endpoint_ids = sorted(
                record["container_id"]
                for record in runtime["records"]
                if record["state"] != "absent"
                and network
                in upgrade.SERVICE_NETWORK_ENDPOINTS.get(record["service"], ())
            )
            network_records.append(
                {
                    "network": network,
                    "name": f"{intent['compose_project']}_{network}",
                    "network_id": hashlib.sha256(
                        f"rollback:{network}".encode("ascii")
                    ).hexdigest(),
                    "compose_config_sha256": intent["compose"]["source"][
                        "network_config_sha256"
                    ][network],
                    "endpoint_container_ids": endpoint_ids,
                    "endpoint_container_ids_sha256": upgrade._domain_digest(
                        "BackupSheep/upgrade-network-endpoints/v1", endpoint_ids
                    ),
                    "state": "present",
                }
            )
        networks = {
            "records": network_records,
            "records_sha256": upgrade._domain_digest(
                "BackupSheep/upgrade-network-records/v1", network_records
            ),
        }
        resources = {
            "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
            "compose_model_sha256": intent["compose"]["source"]["model_sha256"],
            "volume_records_sha256": intent["resource_digests"]["volume_records_sha256"],
            "network_records_sha256": networks["records_sha256"],
            "container_records_sha256": runtime["records_sha256"],
            "storage_aggregate_sha256": intent["resource_digests"]["volume_records_sha256"],
            "artifact_provider_aggregate_sha256": intent["resource_digests"]["artifact_provider_sha256"],
        }
        resources["aggregate_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-resource-set/v1", resources
        )
        target_absence = []
        for service in upgrade.ALL_SERVICES:
            role = upgrade.SERVICE_IMAGE_ROLES[service]
            source_pair = (
                intent["source"]["images"][role]["config_digest"],
                intent["compose"]["source"]["service_config_sha256"][service],
            )
            target_pair = (
                intent["target"]["images"][role]["config_digest"],
                intent["compose"]["target"]["service_config_sha256"][service],
            )
            if source_pair != target_pair:
                target_absence.append(
                    {
                        "service": service,
                        "target_image_config_sha256": target_pair[0],
                        "target_compose_config_sha256": target_pair[1],
                        "state": "absent",
                    }
                )
        app_record = runtime["records"][upgrade.ALL_SERVICES.index("app")]
        return {
            "active_pointer_sha256": intent["active_pointer_sha256"]["source"],
            "active_checkout_sha256": upgrade._domain_digest(
                "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["source"]
            ),
            "active_env_sha256": intent["environment"]["source_sha256"],
            "active_evidence_sha256": upgrade._state_digest(intent["source"]),
            "active_release_sha256": upgrade._state_digest(intent["source"]),
            "local_images_sha256": intent["source"]["local_images_sha256"],
            "active_model_sha256": intent["compose"]["source"]["model_sha256"],
            "source_migrations": {
                "count": len(migration["migrations"]),
                "set_sha256": migration["migration_set_sha256"],
                "leaf_count": len(migration["leaves"]),
                "leaf_set_sha256": migration["leaf_set_sha256"],
                "missing": [],
                "unknown": [],
            },
            "runtime": runtime,
            "networks": networks,
            "target_absence": {
                "project_container_ids_sha256": runtime[
                    "project_container_ids_sha256"
                ],
                "records": target_absence,
            },
            "functional_probe": self._functional_probe(
                intent,
                app_record["container_id"],
                purpose="rollback-source",
                body_label="rollback-probe-body",
            ),
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
                "schema_version": 2,
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

    def test_same_nonce_is_an_idempotence_discriminator_not_global_authorization(self):
        first = self._initialize()
        self._append("10-prepared", first)
        self._rollback(first)

        second = self._initialize()
        self.assertEqual(second["attempt_nonce"], first["attempt_nonce"])
        self.assertNotEqual(second["operation_id"], first["operation_id"])
        self.assertEqual(second["lineage"]["parent_outcome"], "rolled-back")
        self.assertEqual(
            second["lineage"]["source_release_sha256"],
            first["lineage"]["source_release_sha256"],
        )

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
        latest_intent, latest_phase = upgrade.validate_journal(self.install)
        self.assertEqual(latest_intent["operation_id"], second["operation_id"])
        self.assertEqual(latest_phase, "70-activated")

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
        request = json.loads(self.request.read_text())
        request["attempt_nonce"] = "f" * 64
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
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
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError,
            "target.env differs|intent.json differs|another signed upgrade remains open|active-release pointer",
        ):
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
            "image_config_sha256": intent["target"]["images"]["app"][
                "config_digest"
            ],
            "compose_config_sha256": intent["compose"]["target"][
                "service_config_sha256"
            ]["worker-cloud"],
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

    def test_interrupted_terminal_activation_hardlink_is_reconciled_before_lineage_read(self):
        intent = self._initialize()
        for phase in upgrade.PHASES:
            self._append(phase, intent)
        operation = self._operation_dir(intent)
        receipt = operation / "70-activated.json"
        temporary = operation / ".70-activated.json.new"
        os.link(receipt, temporary)

        self._append("70-activated", intent)

        self.assertFalse(temporary.exists())
        self.assertEqual(receipt.stat().st_nlink, 1)
        self.assertEqual(
            upgrade.journal_status(
                install_dir=self.install, operation_id=intent["operation_id"]
            )["state"],
            "activated",
        )

    def test_interrupted_terminal_rollback_hardlink_is_reconciled_before_lineage_read(self):
        intent = self._initialize()
        self._append("10-prepared", intent)
        self._rollback(intent)
        operation = self._operation_dir(intent)
        receipt = operation / upgrade.ROLLBACK_RECEIPT_NAME
        temporary = operation / f".{upgrade.ROLLBACK_RECEIPT_NAME}.new"
        os.link(receipt, temporary)

        self._rollback(intent)

        self.assertFalse(temporary.exists())
        self.assertEqual(receipt.stat().st_nlink, 1)
        self.assertEqual(
            upgrade.journal_status(
                install_dir=self.install, operation_id=intent["operation_id"]
            )["state"],
            "rolled-back",
        )

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

    def test_activated_transition_cannot_be_replayed_with_a_fresh_nonce(self):
        intent = self._initialize()
        self._complete(intent)
        request = json.loads(self.request.read_text())
        request["attempt_nonce"] = "c" * 64
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "globally active release"):
            self._initialize()
        operations = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME
        self.assertEqual({entry.name for entry in operations.iterdir()}, {intent["operation_id"]})

    def test_rollback_allows_exact_new_attempt_but_preserves_epoch_floor(self):
        first = self._initialize()
        self._append("10-prepared", first)
        self._rollback(first)
        request = json.loads(self.request.read_text())
        request["attempt_nonce"] = "c" * 64
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        second = self._initialize()
        self.assertNotEqual(first["operation_id"], second["operation_id"])
        self.assertEqual(second["source"]["release_tag"], "v1.0.0")

    def test_environment_copies_retire_at_forward_and_terminal_boundaries(self):
        intent = self._initialize()
        operation = self._operation_dir(intent)
        for phase in upgrade.PHASES[:3]:
            self._append(phase, intent)
        self.assertTrue((operation / upgrade.ROLLBACK_ENV_NAME).is_file())
        self.assertTrue((operation / upgrade.TARGET_ENV_NAME).is_file())
        self._append("40-forward-only", intent)
        self.assertFalse((operation / upgrade.ROLLBACK_ENV_NAME).exists())
        self.assertTrue((operation / upgrade.TARGET_ENV_NAME).is_file())
        for phase in upgrade.PHASES[4:]:
            self._append(phase, intent)
        self.assertFalse((operation / upgrade.TARGET_ENV_NAME).exists())
        self.assertEqual(upgrade.validate_journal(self.install)[1], "70-activated")

    def test_rollback_retires_both_environment_copies(self):
        intent = self._initialize()
        operation = self._operation_dir(intent)
        self._append("10-prepared", intent)
        self._rollback(intent)
        self.assertFalse((operation / upgrade.ROLLBACK_ENV_NAME).exists())
        self.assertFalse((operation / upgrade.TARGET_ENV_NAME).exists())
        self.assertEqual(upgrade.validate_journal(self.install)[1], "rolled-back")

    def test_compaction_checkpoints_exact_lineage_and_allows_next_upgrade(self):
        intents = []
        current = None
        for version in range(2, 6):
            if version > 2:
                assert current is not None
                self._prepare_next_transition(
                    current,
                    target_tag=f"v{version}.0.0",
                    target_commit=str(version) * 40,
                    target_epoch=version,
                )
            intent = self._initialize()
            self._complete(intent)
            intents.append(intent)
            current = upgrade.build_release_state(
                self.target_evidence, "linux/amd64"
            )
        self.assertTrue(upgrade.compact_journal(install_dir=self.install, retain_operations=2))
        checkpoint = upgrade.export_checkpoint(install_dir=self.install)
        self.assertEqual(checkpoint["compacted_operation_count"], 2)
        self.assertEqual(
            [item["operation_id"] for item in checkpoint["pruned_operations"]],
            [item["operation_id"] for item in intents[:2]],
        )
        operations = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME
        self.assertEqual(
            {entry.name for entry in operations.iterdir()},
            {item["operation_id"] for item in intents[2:]},
        )
        latest, phase = upgrade.validate_journal(self.install)
        self.assertEqual(latest["operation_id"], intents[-1]["operation_id"])
        self.assertEqual(phase, "70-activated")
        assert current is not None
        self._prepare_next_transition(
            current,
            target_tag="v6.0.0",
            target_commit="6" * 40,
            target_epoch=6,
        )
        next_intent = self._initialize()
        self.assertEqual(next_intent["source"]["release_tag"], "v5.0.0")

    def test_compaction_refuses_symlinked_journal_root_without_mutating_target(self):
        external = self.root / "external-journal"
        external.mkdir(mode=0o700)
        for name in (
            upgrade.OPERATIONS_NAME,
            upgrade.LINEAGE_NAME,
            upgrade.PRUNING_NAME,
        ):
            (external / name).mkdir(mode=0o700)
        lock = external / upgrade.LOCK_NAME
        lock.write_bytes(b"")
        lock.chmod(0o600)
        candidate = external / upgrade.NEXT_CHECKPOINT_NAME
        candidate.write_bytes(b"{")
        candidate.chmod(0o400)
        (self.install / upgrade.JOURNAL_ROOT_NAME).symlink_to(external)

        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "must be a real directory"
        ):
            upgrade.compact_journal(install_dir=self.install)

        self.assertEqual(candidate.read_bytes(), b"{")

    def test_checkpoint_count_is_derived_from_terminal_lineage_sequence(self):
        self._complete_version_chain(5)
        self.assertTrue(
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        )
        checkpoint_path = (
            self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.CHECKPOINT_NAME
        )
        checkpoint = json.loads(checkpoint_path.read_text())
        checkpoint["compacted_operation_count"] = 123456
        checkpoint_path.chmod(0o600)
        checkpoint_path.write_bytes(canonical(checkpoint))
        checkpoint_path.chmod(0o400)
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "checkpoint boundary binding"
        ):
            upgrade.export_checkpoint(install_dir=self.install)

    def test_lineage_sequence_rejects_json_boolean_even_when_head_is_rehashed(self):
        self._initialize()
        root = self.install / upgrade.JOURNAL_ROOT_NAME
        lineage_path = root / upgrade.LINEAGE_NAME / upgrade._lineage_filename(1)
        record = json.loads(lineage_path.read_text())
        record["sequence"] = True
        body = dict(record)
        body.pop("history_sha256")
        record["history_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-lineage-history/v1", body
        )
        lineage_path.chmod(0o600)
        lineage_path.write_bytes(canonical(record))
        lineage_path.chmod(0o400)

        head_path = root / upgrade.HEAD_NAME
        head = json.loads(head_path.read_text())
        head["record_sha256"] = upgrade._sha256_bytes(lineage_path.read_bytes())
        head["history_sha256"] = record["history_sha256"]
        head_path.chmod(0o600)
        head_path.write_bytes(canonical(head))
        head_path.chmod(0o400)

        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "nonnegative bounded integer"
        ):
            upgrade.validate_journal(self.install)

    def test_intent_lineage_started_sequence_rejects_json_boolean(self):
        intent = self._initialize()
        tampered = json.loads(canonical(intent))
        tampered["lineage"]["started_sequence"] = True
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "nonnegative bounded integer"
        ):
            upgrade._validate_intent(tampered)

    def test_journal_control_files_reject_floating_point_schema_values(self):
        intent = self._initialize()
        operation = self._operation_dir(intent)
        self._append("10-prepared", intent)

        cases = (
            (operation / upgrade.INTENT_NAME, "upgrade intent"),
            (operation / "10-prepared.json", "10-prepared.json"),
        )
        for path, label in cases:
            original = path.read_bytes()
            value = json.loads(original)
            value["schema_version"] = 2.0
            path.chmod(0o600)
            path.write_bytes(canonical(value))
            path.chmod(0o400)
            with self.subTest(label=label), self.assertRaisesRegex(
                upgrade.UpgradeJournalError, "unsupported float"
            ):
                upgrade.validate_journal(self.install)
            path.chmod(0o600)
            path.write_bytes(original)
            path.chmod(0o400)

        self._rollback(intent)
        rollback = operation / upgrade.ROLLBACK_RECEIPT_NAME
        value = json.loads(rollback.read_bytes())
        value["schema_version"] = 2.0
        rollback.chmod(0o600)
        rollback.write_bytes(canonical(value))
        rollback.chmod(0o400)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "unsupported float"):
            upgrade.validate_journal(self.install)

    def test_checkpoint_export_refuses_a_missing_retained_operation(self):
        intents, _ = self._complete_version_chain(5)
        self.assertTrue(
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        )
        operation = (
            self.install
            / upgrade.JOURNAL_ROOT_NAME
            / upgrade.OPERATIONS_NAME
            / intents[-1]["operation_id"]
        )
        shutil.rmtree(operation)
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "directories and global lineage"
        ):
            upgrade.export_checkpoint(install_dir=self.install)

    def test_torn_started_lineage_prefix_is_rebuilt_by_exact_retry(self):
        original = upgrade._write_exclusive
        injected = {"done": False}

        def tear(path, payload, *, mode):
            if (
                not injected["done"]
                and path.parent.name == upgrade.LINEAGE_NAME
                and path.name == upgrade._lineage_filename(1)
            ):
                injected["done"] = True
                temporary = path.with_name(f".{path.name}.new")
                temporary.write_bytes(payload[:19])
                temporary.chmod(mode)
                raise OSError("injected lineage interruption")
            return original(path, payload, mode=mode)

        with mock.patch.object(upgrade, "_write_exclusive", side_effect=tear):
            with self.assertRaisesRegex(OSError, "lineage interruption"):
                self._initialize()
        intent = self._initialize()
        self.assertEqual(upgrade.validate_journal(self.install)[0], intent)

    def test_unpublished_operation_id_binds_every_base_intent_field(self):
        source = upgrade.build_release_state(self.source_evidence, "linux/amd64")
        target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        mutations = {
            "artifact provider": lambda request: request["artifact_provider"].update(
                generation=2
            ),
            "volume witness": lambda request: request["volumes"][
                "backup_workdir"
            ].update(ownership_witness_sha256=digest("changed-volume-owner")),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                journal = self.install / upgrade.JOURNAL_ROOT_NAME
                if journal.exists() or journal.is_symlink():
                    shutil.rmtree(journal)
                request = self._request()
                self._set_request_pointers(request, source, target)
                self.request.write_bytes(canonical(request))
                self.request.chmod(0o600)
                original = upgrade._write_exclusive
                injected = {"done": False}

                def fail_before_intent(path, payload, *, mode):
                    if not injected["done"] and path.name == upgrade.INTENT_NAME:
                        injected["done"] = True
                        raise OSError("injected before intent publication")
                    return original(path, payload, mode=mode)

                with mock.patch.object(
                    upgrade, "_write_exclusive", side_effect=fail_before_intent
                ):
                    with self.assertRaisesRegex(OSError, "before intent publication"):
                        self._initialize()
                operations = journal / upgrade.OPERATIONS_NAME
                original_operation = next(operations.iterdir())
                self.assertFalse((original_operation / upgrade.INTENT_NAME).exists())

                changed = json.loads(self.request.read_text())
                mutate(changed)
                self.request.write_bytes(canonical(changed))
                self.request.chmod(0o600)
                with self.assertRaisesRegex(
                    upgrade.UpgradeJournalError,
                    "interrupted unstarted operation requires its exact retry",
                ):
                    self._initialize()
                self.assertEqual(
                    {entry.name for entry in operations.iterdir()},
                    {original_operation.name},
                )

    def test_large_valid_intent_reconciles_after_publication_before_lineage(self):
        names = sorted(
            "a" * 64 + "." + str(index).zfill(6) + "x" * 121
            for index in range(3000)
        )
        migration = {
            "schema_version": 1,
            "all_migrations_atomic": True,
            "migrations": names,
            "migration_set_sha256": release_transition.migration_digest(names),
            "leaves": [names[-1]],
            "leaf_set_sha256": release_transition.migration_digest(
                [names[-1]], leaves=True
            ),
        }
        shutil.rmtree(self.source_evidence)
        shutil.rmtree(self.target_evidence)
        with mock.patch.object(self, "_migration", return_value=migration):
            source = self._make_evidence(
                self.source_evidence,
                tag="v1.0.0",
                commit="1" * 40,
                epoch=1,
                accepted=[],
                seed=1,
            )
            target = self._make_evidence(
                self.target_evidence,
                tag="v2.0.0",
                commit="2" * 40,
                epoch=2,
                accepted=[upgrade._predecessor_projection(source)],
                seed=8,
            )
        self._write_source_verification(source, target)
        request = self._request()
        self._set_request_pointers(request, source, target)
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)

        original = upgrade._publish_lineage_and_head
        injected = {"done": False}

        def fail_before_started_lineage(*, root, record, expected_head):
            if not injected["done"] and record["event"] == "started":
                injected["done"] = True
                raise OSError("injected after large intent publication")
            return original(root=root, record=record, expected_head=expected_head)

        with mock.patch.object(
            upgrade,
            "_publish_lineage_and_head",
            side_effect=fail_before_started_lineage,
        ):
            with self.assertRaisesRegex(OSError, "large intent publication"):
                self._initialize()

        operations = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME
        operation = next(operations.iterdir())
        intent_path = operation / upgrade.INTENT_NAME
        self.assertGreater(intent_path.stat().st_size, upgrade.MAX_CONTROL_BYTES)
        expected_operation_id = operation.name

        intent = self._initialize()
        self.assertEqual(intent["operation_id"], expected_operation_id)
        self.assertEqual(
            upgrade.validate_journal(
                self.install, operation_id=expected_operation_id
            )[1],
            None,
        )

    def test_missing_genesis_head_and_torn_head_candidate_reconcile(self):
        original = upgrade._atomic_replace
        injected = {"genesis": False}

        def stop_before_genesis_head(path, payload, *, mode, expected_previous):
            if expected_previous is None and path.name == upgrade.HEAD_NAME:
                injected["genesis"] = True
                raise OSError("injected genesis head interruption")
            return original(
                path,
                payload,
                mode=mode,
                expected_previous=expected_previous,
            )

        with mock.patch.object(
            upgrade, "_atomic_replace", side_effect=stop_before_genesis_head
        ):
            with self.assertRaisesRegex(OSError, "genesis head interruption"):
                self._initialize()
        self.assertTrue(injected["genesis"])
        intent = self._initialize()
        self.assertEqual(upgrade.validate_journal(self.install)[0], intent)

    def test_torn_head_candidate_is_recreated_from_exact_lineage(self):
        original = upgrade._atomic_replace
        injected = {"done": False}

        def tear_head(path, payload, *, mode, expected_previous):
            if (
                not injected["done"]
                and path.name == upgrade.HEAD_NAME
                and expected_previous is not None
            ):
                injected["done"] = True
                temporary = path.with_name(f".{path.name}.new")
                temporary.write_bytes(payload[:23])
                temporary.chmod(mode)
                raise OSError("injected head candidate interruption")
            return original(
                path,
                payload,
                mode=mode,
                expected_previous=expected_previous,
            )

        with mock.patch.object(upgrade, "_atomic_replace", side_effect=tear_head):
            with self.assertRaisesRegex(OSError, "head candidate interruption"):
                self._initialize()
        intent = self._initialize()
        self.assertEqual(upgrade.validate_journal(self.install)[0], intent)
        self.assertFalse(
            (
                self.install
                / upgrade.JOURNAL_ROOT_NAME
                / f".{upgrade.HEAD_NAME}.new"
            ).exists()
        )

    def test_lineage_gap_or_deleted_operation_is_detected(self):
        intents, _ = self._complete_version_chain(3)
        root = self.install / upgrade.JOURNAL_ROOT_NAME
        missing = root / upgrade.LINEAGE_NAME / upgrade._lineage_filename(1)
        saved = missing.read_bytes()
        missing.unlink()
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "gap"):
            upgrade.validate_journal(self.install)
        missing.write_bytes(saved)
        missing.chmod(0o400)
        operation = root / upgrade.OPERATIONS_NAME / intents[0]["operation_id"]
        shutil.rmtree(operation)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "directories and global lineage"):
            upgrade.validate_journal(self.install)

    def test_stable_journal_control_files_reject_external_hard_links(self):
        self._initialize()
        root = self.install / upgrade.JOURNAL_ROOT_NAME
        alias = self.install / "hidden-head-alias"
        os.link(root / upgrade.HEAD_NAME, alias)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "without hard links"):
            upgrade.validate_journal(self.install)

    def test_unrelated_lineage_temporary_cannot_be_erased_as_recovery(self):
        self._initialize()
        lineage = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.LINEAGE_NAME
        temporary = lineage / f".{upgrade._lineage_filename(1)}.new"
        temporary.write_bytes(b"")
        temporary.chmod(0o400)
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "publication differs from final"
        ):
            upgrade.validate_journal(self.install)
        self.assertTrue(temporary.exists())

    def test_torn_checkpoint_candidate_is_discarded_only_by_compaction_retry(self):
        _, _ = self._complete_version_chain(5)
        captured = {}
        original = upgrade._atomic_replace

        def dispatch(path, payload, *, mode, expected_previous):
            if path.name == upgrade.CHECKPOINT_NAME:
                captured["payload"] = payload
                temporary = path.with_name(f".{path.name}.new")
                temporary.write_bytes(payload[:29])
                temporary.chmod(mode)
                raise OSError("injected checkpoint interruption")
            return original(
                path,
                payload,
                mode=mode,
                expected_previous=expected_previous,
            )

        with mock.patch.object(upgrade, "_atomic_replace", side_effect=dispatch):
            with self.assertRaisesRegex(OSError, "checkpoint interruption"):
                upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        with self.assertRaises((upgrade.UpgradeJournalError, ValueError)):
            upgrade.validate_journal(self.install)
        self.assertTrue(
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        )
        self.assertEqual(
            upgrade.export_checkpoint(install_dir=self.install)[
                "compacted_operation_count"
            ],
            2,
        )

    def test_checkpoint_replacement_before_pruning_is_reported_as_recovered(self):
        _, current = self._complete_version_chain(5)
        self.assertTrue(
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        )
        assert current is not None
        for version in (6, 7):
            self._prepare_next_transition(
                current,
                target_tag=f"v{version}.0.0",
                target_commit=str(version) * 40,
                target_epoch=version,
            )
            intent = self._initialize()
            self._complete(intent)
            current = upgrade.build_release_state(
                self.target_evidence, "linux/amd64"
            )

        original = upgrade._atomic_replace
        injected = {"done": False}

        def crash_after_replace(path, payload, *, mode, expected_previous):
            result = original(
                path,
                payload,
                mode=mode,
                expected_previous=expected_previous,
            )
            if (
                not injected["done"]
                and path.name == upgrade.CHECKPOINT_NAME
                and expected_previous is not None
            ):
                injected["done"] = True
                raise OSError("injected after checkpoint replacement")
            return result

        with mock.patch.object(
            upgrade, "_atomic_replace", side_effect=crash_after_replace
        ):
            with self.assertRaisesRegex(OSError, "after checkpoint replacement"):
                upgrade.compact_journal(
                    install_dir=self.install, retain_operations=2
                )
        operations = (
            self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME
        )
        self.assertEqual(len(list(operations.iterdir())), 4)
        self.assertTrue(
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        )
        self.assertEqual(len(list(operations.iterdir())), 2)

    def test_journal_lock_refuses_a_concurrent_operation(self):
        intent = self._initialize()
        with upgrade._journal_lock(self.install):
            with self.assertRaisesRegex(
                upgrade.UpgradeJournalError, "another journal operation"
            ):
                upgrade.journal_status(
                    install_dir=self.install, operation_id=intent["operation_id"]
                )

    def test_checkpoint_candidate_must_summarize_exact_next_interval(self):
        self._complete_version_chain(5)
        captured = {}
        original = upgrade._atomic_replace

        def capture(path, payload, *, mode, expected_previous):
            if path.name == upgrade.CHECKPOINT_NAME:
                captured["payload"] = payload
                raise OSError("capture checkpoint")
            return original(
                path,
                payload,
                mode=mode,
                expected_previous=expected_previous,
            )

        with mock.patch.object(upgrade, "_atomic_replace", side_effect=capture):
            with self.assertRaisesRegex(OSError, "capture checkpoint"):
                upgrade.compact_journal(install_dir=self.install, retain_operations=2)
        candidate = json.loads(captured["payload"])
        candidate["pruned_operations"][0]["source_release_sha256"] = digest(
            "unrelated-source"
        )
        candidate["compacted_operations_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-compacted-operations/v2",
            {
                "previous_checkpoint_sha256": candidate[
                    "previous_checkpoint_sha256"
                ],
                "previous_compacted_operations_sha256": candidate[
                    "previous_compacted_operations_sha256"
                ],
                "boundary_record_sha256": candidate["boundary_record_sha256"],
                "compacted_operation_count": candidate[
                    "compacted_operation_count"
                ],
                "operations": candidate["pruned_operations"],
            },
        )
        path = (
            self.install
            / upgrade.JOURNAL_ROOT_NAME
            / upgrade.NEXT_CHECKPOINT_NAME
        )
        path.write_bytes(canonical(candidate))
        path.chmod(0o400)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "exact next interval"):
            upgrade.compact_journal(install_dir=self.install, retain_operations=2)

    def test_wrong_retry_cannot_create_second_partial_operation(self):
        original_request = self.request.read_bytes()
        original_retain = upgrade._retain_evidence
        injected = {"done": False}

        def interrupt_once(source, destination):
            if not injected["done"]:
                injected["done"] = True
                raise OSError("injected before retained evidence")
            return original_retain(source, destination)

        with mock.patch.object(upgrade, "_retain_evidence", side_effect=interrupt_once):
            with self.assertRaisesRegex(OSError, "before retained evidence"):
                self._initialize()
        operations = self.install / upgrade.JOURNAL_ROOT_NAME / upgrade.OPERATIONS_NAME
        first_partial = {entry.name for entry in operations.iterdir()}
        self.assertEqual(len(first_partial), 1)
        request = json.loads(original_request)
        request["attempt_nonce"] = "c" * 64
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "exact retry"):
            self._initialize()
        self.assertEqual({entry.name for entry in operations.iterdir()}, first_partial)
        self.request.write_bytes(original_request)
        self.request.chmod(0o600)
        self._initialize()

    def test_runner_reuse_is_rejected_before_immutable_phase_publication(self):
        intent = self._initialize()
        for phase in upgrade.PHASES[:5]:
            self._append(phase, intent)
        bad = self._payload("60-core-accepted", intent)
        bad["db_seal"]["container_id"] = self._payload("50-migrated", intent)[
            "runner"
        ]["container_id"]
        bad["db_seal"]["inspect_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-one-shot-runner/v1",
            {
                "operation_id": intent["operation_id"],
                "installation_id": intent["installation_id"],
                "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
                "runner": {
                    key: value
                    for key, value in bad["db_seal"].items()
                    if key != "inspect_sha256"
                },
            },
        )
        path = self.install / ".60-core-accepted.payload.json"
        path.write_bytes(canonical(bad))
        path.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "reused"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="60-core-accepted",
                payload_path=path,
            )
        self.assertFalse((self._operation_dir(intent) / "60-core-accepted.json").exists())
        self._append("60-core-accepted", intent)

    def test_activation_cannot_replace_the_probed_core_container(self):
        intent = self._initialize()
        for phase in upgrade.PHASES[:6]:
            self._append(phase, intent)
        bad = self._payload("70-activated", intent)
        app_index = upgrade.ALL_SERVICES.index("app")
        bad["runtime"]["records"][app_index]["container_id"] = "e" * 64
        bad["runtime"]["records_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-runtime-records/v1", bad["runtime"]["records"]
        )
        bad["runtime"]["project_container_ids"] = sorted(
            record["container_id"]
            for record in bad["runtime"]["records"]
            if record["state"] != "absent"
        )
        bad["runtime"]["project_container_ids_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-project-container-ids/v1",
            bad["runtime"]["project_container_ids"],
        )
        bad["resources"]["container_records_sha256"] = bad["runtime"][
            "records_sha256"
        ]
        aggregate = {
            key: bad["resources"][key]
            for key in sorted(set(bad["resources"]) - {"aggregate_sha256"})
        }
        bad["resources"]["aggregate_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-resource-set/v1", aggregate
        )
        path = self.install / ".70-activated.payload.json"
        path.write_bytes(canonical(bad))
        path.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "probed core"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="70-activated",
                payload_path=path,
            )
        self.assertFalse((self._operation_dir(intent) / "70-activated.json").exists())

    def test_runtime_image_and_compose_role_drift_fail_after_consistent_rehash(self):
        intent = self._initialize()
        for field, replacement, message in (
            (
                "image_config_sha256",
                intent["source"]["images"]["egress"]["config_digest"],
                "signed image role",
            ),
            ("compose_config_sha256", digest("sibling-compose-config"), "Compose service"),
        ):
            bad = self._payload("10-prepared", intent)
            app_index = upgrade.ALL_SERVICES.index("app")
            bad["source_runtime"]["records"][app_index][field] = replacement
            self._rehash_resource_payload(
                bad, runtime_key="source_runtime", network_key="source_networks"
            )
            path = self.install / ".10-prepared.payload.json"
            path.write_bytes(canonical(bad))
            path.chmod(0o600)
            with self.assertRaisesRegex(upgrade.UpgradeJournalError, message):
                upgrade.append_receipt(
                    install_dir=self.install,
                    operation_id=intent["operation_id"],
                    phase="10-prepared",
                    payload_path=path,
                )
            self.assertFalse((self._operation_dir(intent) / "10-prepared.json").exists())

    def test_duplicate_runtime_and_network_ids_fail_closed(self):
        intent = self._initialize()
        bad = self._payload("10-prepared", intent)
        db_index = upgrade.ALL_SERVICES.index("db")
        rabbit_index = upgrade.ALL_SERVICES.index("rabbitmq")
        bad["source_runtime"]["records"][rabbit_index]["container_id"] = bad[
            "source_runtime"
        ]["records"][db_index]["container_id"]
        bad["source_runtime"]["project_container_ids"] = sorted(
            record["container_id"]
            for record in bad["source_runtime"]["records"]
            if record["state"] != "absent"
        )
        bad["source_runtime"]["project_container_ids_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-project-container-ids/v1",
            bad["source_runtime"]["project_container_ids"],
        )
        self._rehash_resource_payload(
            bad, runtime_key="source_runtime", network_key="source_networks"
        )
        path = self.install / ".10-prepared.payload.json"
        path.write_bytes(canonical(bad))
        path.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "repeats a container"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="10-prepared",
                payload_path=path,
            )

    def test_network_endpoint_membership_is_bound_to_complete_runtime(self):
        intent = self._initialize()
        path = self.install / ".10-prepared.payload.json"

        for mutation in ("missing", "extra", "swapped", "duplicate"):
            bad = self._payload("10-prepared", intent)
            networks = bad["source_networks"]
            record = next(
                item
                for item in networks["records"]
                if item.get("network") == "app-database"
            )
            endpoint_ids = list(record["endpoint_container_ids"])
            if mutation == "missing":
                endpoint_ids.pop()
            elif mutation == "extra":
                endpoint_ids.append("f" * 64)
                endpoint_ids.sort()
            elif mutation == "swapped":
                rabbit = bad["source_runtime"]["records"][
                    upgrade.ALL_SERVICES.index("rabbitmq")
                ]["container_id"]
                endpoint_ids[0] = rabbit
                endpoint_ids.sort()
            else:
                endpoint_ids.append(endpoint_ids[0])
                endpoint_ids.sort()
            record["endpoint_container_ids"] = endpoint_ids
            record["endpoint_container_ids_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-network-endpoints/v1", endpoint_ids
            )
            networks["records_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-network-records/v1", networks["records"]
            )
            bad["resources"]["network_records_sha256"] = networks[
                "records_sha256"
            ]
            aggregate = {
                key: bad["resources"][key]
                for key in sorted(
                    set(bad["resources"]) - {"aggregate_sha256"}
                )
            }
            bad["resources"]["aggregate_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-resource-set/v1", aggregate
            )
            path.write_bytes(canonical(bad))
            path.chmod(0o600)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                upgrade.UpgradeJournalError,
                "endpoint set is malformed|complete runtime topology",
            ):
                upgrade.append_receipt(
                    install_dir=self.install,
                    operation_id=intent["operation_id"],
                    phase="10-prepared",
                    payload_path=path,
                )
            self.assertFalse(
                (self._operation_dir(intent) / "10-prepared.json").exists()
            )

        bad = self._payload("10-prepared", intent)
        present = [
            index
            for index, record in enumerate(bad["source_networks"]["records"])
            if record["state"] == "present"
        ]
        bad["source_networks"]["records"][present[1]]["network_id"] = bad[
            "source_networks"
        ]["records"][present[0]]["network_id"]
        self._rehash_resource_payload(
            bad, runtime_key="source_runtime", network_key="source_networks"
        )
        path.write_bytes(canonical(bad))
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "repeats a Docker network"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="10-prepared",
                payload_path=path,
            )

    def test_source_restart_history_is_admitted_but_target_restarts_are_not(self):
        intent = self._initialize()
        prepared = self._payload("10-prepared", intent)
        app_index = upgrade.ALL_SERVICES.index("app")
        prepared["source_runtime"]["records"][app_index]["restart_count"] = 4
        self._rehash_resource_payload(
            prepared, runtime_key="source_runtime", network_key="source_networks"
        )
        path = self.install / ".10-prepared.payload.json"
        path.write_bytes(canonical(prepared))
        path.chmod(0o600)
        upgrade.append_receipt(
            install_dir=self.install,
            operation_id=intent["operation_id"],
            phase="10-prepared",
            payload_path=path,
        )
        for phase in upgrade.PHASES[1:5]:
            self._append(phase, intent)
        core = self._payload("60-core-accepted", intent)
        core["runtime"]["records"][app_index]["restart_count"] = 1
        self._rehash_resource_payload(core)
        path = self.install / ".60-core-accepted.payload.json"
        path.write_bytes(canonical(core))
        path.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "restarted"):
            upgrade.append_receipt(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                phase="60-core-accepted",
                payload_path=path,
            )

    def test_functional_probe_is_bound(self):
        intent = self._initialize()
        for phase in upgrade.PHASES[:5]:
            self._append(phase, intent)
        path = self.install / ".60-core-accepted.payload.json"
        for field, value, message in (
            ("status_code", 503, "acceptance probe"),
            ("schema_version", True, "positive bounded integer"),
        ):
            bad = self._payload("60-core-accepted", intent)
            bad["functional_probe"][field] = value
            bad["functional_probe"]["receipt_sha256"] = upgrade._domain_digest(
                "BackupSheep/upgrade-functional-probe/v1",
                {
                    key: item
                    for key, item in bad["functional_probe"].items()
                    if key != "receipt_sha256"
                },
            )
            path.write_bytes(canonical(bad))
            path.chmod(0o600)
            with self.subTest(field=field), self.assertRaisesRegex(
                upgrade.UpgradeJournalError, message
            ):
                upgrade.append_receipt(
                    install_dir=self.install,
                    operation_id=intent["operation_id"],
                    phase="60-core-accepted",
                    payload_path=path,
                )

    def test_rollback_requires_complete_source_and_target_absence_inventory(self):
        intent = self._initialize()
        self._append("10-prepared", intent)
        payload_path = self.install / ".rollback.payload.json"

        extra = self._rollback_payload(intent)
        extra_id = "f" * 64
        extra["runtime"]["project_container_ids"].append(extra_id)
        extra["runtime"]["project_container_ids"].sort()
        extra["runtime"]["project_container_ids_sha256"] = upgrade._domain_digest(
            "BackupSheep/upgrade-project-container-ids/v1",
            extra["runtime"]["project_container_ids"],
        )
        extra["target_absence"]["project_container_ids_sha256"] = extra[
            "runtime"
        ]["project_container_ids_sha256"]
        payload_path.write_bytes(canonical(extra))
        payload_path.chmod(0o600)
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "complete exact project container inventory"
        ):
            upgrade.append_rollback(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                payload_path=payload_path,
            )

        missing = self._rollback_payload(intent)
        missing["target_absence"]["records"].pop()
        payload_path.write_bytes(canonical(missing))
        with self.assertRaisesRegex(
            upgrade.UpgradeJournalError, "bind target absence"
        ):
            upgrade.append_rollback(
                install_dir=self.install,
                operation_id=intent["operation_id"],
                payload_path=payload_path,
            )
        self.assertFalse(
            (self._operation_dir(intent) / upgrade.ROLLBACK_RECEIPT_NAME).exists()
        )

    def test_pointer_and_compose_aggregates_are_not_free_form(self):
        request = json.loads(self.request.read_text())
        request["active_pointer_sha256"]["source"] = request[
            "active_pointer_sha256"
        ]["target"]
        self.request.write_bytes(canonical(request))
        self.request.chmod(0o600)
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "active-release pointer"):
            self._initialize()
        self.assertFalse((self.install / upgrade.JOURNAL_ROOT_NAME).exists())

        request = self._request()
        source = upgrade.build_release_state(self.source_evidence, "linux/amd64")
        target = upgrade.build_release_state(self.target_evidence, "linux/amd64")
        self._set_request_pointers(request, source, target)
        request["compose"]["source"]["model_sha256"] = digest("free-form-model")
        self.request.write_bytes(canonical(request))
        with self.assertRaisesRegex(upgrade.UpgradeJournalError, "model digest"):
            self._initialize()


UpgradeJournalError = upgrade.UpgradeJournalError
