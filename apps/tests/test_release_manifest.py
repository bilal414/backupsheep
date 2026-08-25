import base64
import copy
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_release_manifest as builder  # noqa: E402
import verify_release as verifier  # noqa: E402


class ReleaseFixtureMixin:
    def setUp(self):
        super().setUp()
        self.temporary_directory = Path(tempfile.mkdtemp(prefix="backupsheep-release-"))
        self.artifacts = self.temporary_directory / "artifacts"
        for directory in ("oci", "sbom", "scans", "provenance"):
            (self.artifacts / directory).mkdir(parents=True, exist_ok=True)
        self.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text(encoding="utf-8"))
        self.commit = "a" * 40
        self.index_digests = {"app": "sha256:" + "1" * 64, "postgres": "sha256:" + "4" * 64}
        self.platform_digests = {
            "app": {"linux/amd64": "sha256:" + "2" * 64, "linux/arm64": "sha256:" + "3" * 64},
            "postgres": {"linux/amd64": "sha256:" + "5" * 64, "linux/arm64": "sha256:" + "6" * 64},
        }
        self._write_evidence()
        self.manifest = self._build_manifest()

    def tearDown(self):
        shutil.rmtree(self.temporary_directory)
        super().tearDown()

    @staticmethod
    def _json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def _write_evidence(self):
        for image in ("app", "postgres"):
            descriptors = []
            for platform, digest in self.platform_digests[image].items():
                operating_system, architecture = platform.split("/", 1)
                descriptors.append(
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest,
                        "size": 100,
                        "platform": {"os": operating_system, "architecture": architecture},
                    }
                )
            descriptors.append(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + ("7" if image == "app" else "8") * 64,
                    "size": 100,
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {"os": "unknown", "architecture": "unknown"},
                }
            )
            self._json(
                self.artifacts / "oci" / f"{image}.index.json",
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": descriptors,
                },
            )
            for platform, digest in self.platform_digests[image].items():
                slug = platform.replace("/", "-")
                self._json(
                    self.artifacts / "sbom" / f"{image}-{slug}.spdx.json",
                    {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "name": f"{image}-{slug}",
                        "packages": [],
                    },
                )
                self._json(
                    self.artifacts / "sbom" / f"{image}-{slug}.cdx.json",
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "version": 1,
                        "metadata": {},
                        "components": [],
                    },
                )
                self._json(
                    self.artifacts / "scans" / f"{image}-{slug}.trivy.json",
                    {
                        "SchemaVersion": 2,
                        "ArtifactName": f"{self.policy['images'][image]}@{digest}",
                        "Results": [],
                    },
                )

    def _build_manifest(self):
        return builder.build_manifest(
            policy=self.policy,
            artifacts_dir=self.artifacts,
            tag="v1.2.3",
            source_commit=self.commit,
            workflow_run="https://github.com/bilal414/backupsheep/actions/runs/123/attempts/1",
            created_at="2026-08-25T12:34:56Z",
            image_inputs={
                image: (self.index_digests[image], self.artifacts / "oci" / f"{image}.index.json")
                for image in ("app", "postgres")
            },
        )


class ReleaseManifestContractTests(ReleaseFixtureMixin, TestCase):
    def test_complete_digest_bound_manifest_passes_offline_validation(self):
        result = verifier.validate_release(self.policy, self.manifest, self.artifacts)
        self.assertEqual(result["manifest"]["images"]["app"]["digest"], self.index_digests["app"])
        self.assertEqual(
            set(result["attestation_predicates"]["postgres"]["sboms"]),
            {
                ("linux/amd64", "spdx-json"),
                ("linux/amd64", "cyclonedx-json"),
                ("linux/arm64", "spdx-json"),
                ("linux/arm64", "cyclonedx-json"),
            },
        )

    def test_mutable_tag_reference_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["app"]["reference"] = "ghcr.io/bilal414/backupsheep:v1.2.3"
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "exact digest"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_wrong_repository_and_workflow_identity_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["release"]["workflow_identity"] = (
            "https://github.com/attacker/backupsheep/.github/workflows/release-images.yml@refs/tags/v1.2.3"
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "workflow identity"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["postgres"]["repository"] = "ghcr.io/attacker/postgres"
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "not authorized"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_missing_platform_or_sbom_fails_closed(self):
        manifest = copy.deepcopy(self.manifest)
        del manifest["images"]["app"]["platforms"]["linux/arm64"]
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "platforms"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["app"]["sboms"].pop()
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "every required platform SBOM"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_tampered_artifact_hash_is_rejected(self):
        record = self.manifest["images"]["app"]["sboms"][0]
        path = self.artifacts / record["file"]
        path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "digest mismatch"):
            verifier.validate_release(self.policy, self.manifest, self.artifacts)

    def test_high_or_critical_finding_blocks_even_without_a_fix(self):
        report_path = self.artifacts / "scans" / "app-linux-amd64.trivy.json"
        self._json(
            report_path,
            {
                "SchemaVersion": 2,
                "ArtifactName": (
                    f"{self.policy['images']['app']}@{self.platform_digests['app']['linux/amd64']}"
                ),
                "Results": [
                    {
                        "Target": "python",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2099-0001",
                                "Severity": "HIGH",
                                "FixedVersion": "",
                            }
                        ],
                    }
                ],
            },
        )
        manifest = self._build_manifest()
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "release-blocking vulnerabilities"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_policy_and_report_cannot_ignore_unfixed_findings(self):
        policy = copy.deepcopy(self.policy)
        policy["vulnerability_policy"]["ignore_unfixed"] = True
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "may not be ignored"):
            verifier.validate_release(policy, self.manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["postgres"]["vulnerability_reports"][0]["ignore_unfixed"] = True
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "ignored unfixed"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_duplicate_json_keys_and_symlink_artifacts_are_rejected(self):
        duplicate = self.temporary_directory / "duplicate.json"
        duplicate.write_text('{"schema_version": 1, "schema_version": 1}\n', encoding="utf-8")
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "duplicate JSON key"):
            verifier._load_json(duplicate, maximum_bytes=1024)

        record = self.manifest["images"]["app"]["sboms"][0]
        original = self.artifacts / record["file"]
        replacement = original.with_suffix(".real.json")
        original.rename(replacement)
        original.symlink_to(replacement.name)
        replacement_digest = hashlib.sha256(replacement.read_bytes()).hexdigest()
        record["sha256"] = f"sha256:{replacement_digest}"
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "symlink"):
            verifier.validate_release(self.policy, self.manifest, self.artifacts)

    def test_generator_rejects_an_unapproved_third_platform(self):
        index_path = self.artifacts / "oci" / "app.index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["manifests"].append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + "9" * 64,
                "size": 100,
                "platform": {"os": "linux", "architecture": "s390x"},
            }
        )
        self._json(index_path, index)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "unauthorized platform"):
            self._build_manifest()

    def test_verified_dsse_payload_must_match_subject_type_and_predicate(self):
        predicate = {"buildDefinition": {}, "runDetails": {}}
        digest = "sha256:" + "b" * 64
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "ghcr.io/bilal414/backupsheep",
                    "digest": {"sha256": digest.removeprefix("sha256:")},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": predicate,
        }
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"sig": "test"}],
        }
        statements = verifier._statements_from_cosign(json.dumps(envelope))
        verifier._require_matching_attestation(
            statements,
            repository="ghcr.io/bilal414/backupsheep",
            digest=digest,
            predicate_type="https://slsa.dev/provenance/v1",
            predicate=predicate,
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "no verified"):
            verifier._require_matching_attestation(
                statements,
                repository="ghcr.io/attacker/backupsheep",
                digest=digest,
                predicate_type="https://slsa.dev/provenance/v1",
                predicate=predicate,
            )


class ReleaseWorkflowContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.workflow = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(
            encoding="utf-8"
        )

    def test_every_action_is_pinned_to_a_full_commit(self):
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, flags=re.MULTILINE)
        self.assertGreaterEqual(len(actions), 8)
        for action in actions:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_release_is_dormant_until_admin_and_environment_opt_in(self):
        self.assertIn("vars.BACKUPSHEEP_SIGNED_RELEASES_ENABLED == 'true'", self.workflow)
        self.assertIn("github.repository == 'bilal414/backupsheep'", self.workflow)
        self.assertIn("environment: signed-release", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertIn("packages: write", self.workflow)
        self.assertNotIn("workflow_dispatch", self.workflow)

    def test_build_and_verification_boundaries_are_immutable(self):
        self.assertNotIn(":latest", self.workflow)
        self.assertIn("provenance: mode=max", self.workflow)
        self.assertEqual(self.workflow.count("sbom: true"), 2)
        self.assertIn('index_reference="$repository@$index_digest"', self.workflow)
        self.assertIn('child_reference="$repository@$child_digest"', self.workflow)
        self.assertIn('reference="$repository@$digest"', self.workflow)
        self.assertNotIn("--ignore-unfixed", self.workflow)
        self.assertIn("--severity HIGH,CRITICAL", self.workflow)
        self.assertIn("--exit-code 1", self.workflow)
        self.assertIn("--type slsaprovenance1", self.workflow)
        self.assertIn("--type spdxjson", self.workflow)
        self.assertIn("--type cyclonedx", self.workflow)

    def test_builder_and_emulator_images_are_digest_pinned(self):
        self.assertRegex(
            self.workflow,
            r"tonistiigi/binfmt:[^\s]+@sha256:[0-9a-f]{64}",
        )
        self.assertRegex(
            self.workflow,
            r"moby/buildkit:[^\s]+@sha256:[0-9a-f]{64}",
        )
