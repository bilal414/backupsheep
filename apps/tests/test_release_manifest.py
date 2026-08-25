import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_release_manifest as builder  # noqa: E402
import install_release_tools as installer  # noqa: E402
import promote_release_images as promoter  # noqa: E402
import stage_release_images as stager  # noqa: E402
import verify_release as verifier  # noqa: E402


class ReleaseFixtureMixin:
    def setUp(self):
        super().setUp()
        self.temporary_directory = Path(tempfile.mkdtemp(prefix="backupsheep-release-"))
        self.artifacts = self.temporary_directory / "artifacts"
        for directory in ("oci", "sbom", "scans", "provenance", "bundles"):
            (self.artifacts / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
        self.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text(encoding="utf-8"))
        self.commit = "a" * 40
        self.tag = "v1.2.3"
        self.workflow_identity = (
            "https://github.com/bilal414/backupsheep/.github/workflows/"
            "release-images.yml@refs/tags/v1.2.3"
        )
        self.platform_digests = {
            "app": {"linux/amd64": "sha256:" + "2" * 64, "linux/arm64": "sha256:" + "3" * 64},
            "postgres": {"linux/amd64": "sha256:" + "5" * 64, "linux/arm64": "sha256:" + "6" * 64},
            "egress": {"linux/amd64": "sha256:" + "7" * 64, "linux/arm64": "sha256:" + "8" * 64},
        }
        self.statements = {}
        self._write_evidence()
        self.manifest = self._build_manifest()

    def tearDown(self):
        shutil.rmtree(self.temporary_directory)
        super().tearDown()

    @staticmethod
    def _json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        path.chmod(0o600)

    @staticmethod
    def _hash(path):
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def _statement(self, image, platform, digest):
        image_policy = self.policy["images"][image]
        source_uri = f"https://github.com/bilal414/backupsheep.git#{self.commit}"
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": f"pkg:docker/{image}?platform={platform}",
                    "digest": {"sha256": digest.removeprefix("sha256:")},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": self.policy["attestations"]["buildkit_build_type"],
                    "externalParameters": {
                        "configSource": {
                            "uri": source_uri,
                            "digest": {"sha1": self.commit},
                            "path": image_policy["dockerfile"],
                        },
                        "request": {
                            "frontend": "dockerfile.v0",
                            "args": {
                                "label:org.opencontainers.image.source": "https://github.com/bilal414/backupsheep",
                                "label:org.opencontainers.image.revision": self.commit,
                                "label:org.opencontainers.image.version": self.tag,
                            },
                            "locals": [],
                            "secrets": [],
                            "ssh": [],
                        },
                    },
                    "internalParameters": {
                        "builderPlatform": "linux/amd64",
                        "buildConfig": {"llbDefinition": [{"id": "step0", "op": {}}]},
                    },
                    "resolvedDependencies": [
                        {"uri": source_uri, "digest": {"sha1": self.commit}},
                        {"uri": "pkg:docker/debian@bookworm", "digest": {"sha256": "9" * 64}},
                    ],
                },
                "runDetails": {
                    "builder": {"id": self.workflow_identity},
                    "metadata": {
                        "invocationId": "test-build",
                        "startedOn": "2026-08-25T12:34:56Z",
                        "finishedOn": "2026-08-25T12:35:56Z",
                        "buildkit_completeness": {"request": True, "resolvedDependencies": True},
                        "buildkit_metadata": {
                            "source": {"infos": [{"filename": image_policy["dockerfile"]}]},
                            "layers": {"step0:0": [{"digest": "sha256:" + "8" * 64}]},
                        },
                    },
                },
            },
        }

    def _write_evidence(self):
        self.index_digests = {}
        for image in self.policy["images"]:
            child_descriptors = []
            attestation_descriptors = []
            quarantine = self.policy["images"][image]["quarantine_repository"]
            for platform, digest in self.platform_digests[image].items():
                slug = platform.replace("/", "-")
                statement = self._statement(image, platform, digest)
                self.statements[(image, platform)] = statement
                statement_path = self.artifacts / "provenance" / f"{image}-{slug}.intoto.json"
                self._json(statement_path, statement)
                statement_digest = self._hash(statement_path)

                attestation = {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.empty.v1+json",
                        "digest": "sha256:" + "0" * 64,
                        "size": 2,
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.in-toto+json",
                            "digest": statement_digest,
                            "size": statement_path.stat().st_size,
                            "annotations": {
                                "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"
                            },
                        }
                    ],
                }
                attestation_path = self.artifacts / "oci" / f"{image}-{slug}.attestation.json"
                self._json(attestation_path, attestation)
                attestation_digest = self._hash(attestation_path)
                operating_system, architecture = platform.split("/", 1)
                child_descriptors.append(
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest,
                        "size": 100,
                        "platform": {"os": operating_system, "architecture": architecture},
                    }
                )
                attestation_descriptors.append(
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": attestation_digest,
                        "size": attestation_path.stat().st_size,
                        "annotations": {
                            "vnd.docker.reference.type": "attestation-manifest",
                            "vnd.docker.reference.digest": digest,
                        },
                        "platform": {"os": "unknown", "architecture": "unknown"},
                    }
                )

                self._json(
                    self.artifacts / "sbom" / f"{image}-{slug}.syft.json",
                    {
                        "artifacts": [{"id": f"{image}-{slug}-package", "name": "openssl"}],
                        "artifactRelationships": [],
                        "source": {
                            "type": "image",
                            "metadata": {
                                "userInput": f"{quarantine}@{digest}",
                                "manifestDigest": digest,
                            },
                        },
                        "descriptor": {"name": "syft", "version": "1.51.0"},
                    },
                )
                self._json(
                    self.artifacts / "sbom" / f"{image}-{slug}.spdx.json",
                    {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "name": f"{image}-{slug}",
                        "packages": [{"SPDXID": "SPDXRef-Package", "name": "openssl"}],
                    },
                )
                self._json(
                    self.artifacts / "sbom" / f"{image}-{slug}.cdx.json",
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "version": 1,
                        "metadata": {},
                        "components": [{"type": "library", "name": "openssl", "version": "3"}],
                    },
                )
                self._json(
                    self.artifacts / "scans" / f"{image}-{slug}.trivy.json",
                    {
                        "SchemaVersion": 2,
                        "ArtifactName": f"{quarantine}@{digest}",
                        "ArtifactType": "container_image",
                        "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
                        "Results": [
                            {
                                "Target": "debian:12",
                                "Class": "os-pkgs",
                                "Type": "debian",
                                "Packages": [{"Name": "openssl", "Version": "3"}],
                                "Vulnerabilities": [],
                            }
                        ],
                    },
                )

            index_path = self.artifacts / "oci" / f"{image}.index.json"
            self._json(
                index_path,
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": child_descriptors + attestation_descriptors,
                },
            )
            self.index_digests[image] = self._hash(index_path)

    def _build_manifest(self):
        return builder.build_manifest(
            policy=self.policy,
            artifacts_dir=self.artifacts,
            tag=self.tag,
            source_commit=self.commit,
            workflow_run="https://github.com/bilal414/backupsheep/actions/runs/123/attempts/1",
            created_at="2026-08-25T12:34:56Z",
            image_inputs={
                image: (self.index_digests[image], self.artifacts / "oci" / f"{image}.index.json")
                for image in self.policy["images"]
            },
        )

    def _rehash_record(self, record):
        record["sha256"] = self._hash(self.artifacts / record["file"])


class ReleaseManifestContractTests(ReleaseFixtureMixin, TestCase):
    def test_complete_index_bound_manifest_passes_offline_validation(self):
        result = verifier.validate_release(self.policy, self.manifest, self.artifacts)
        self.assertEqual(result["manifest"]["images"]["app"]["digest"], self.index_digests["app"])
        self.assertEqual(
            set(result["attestation_predicates"]["postgres"]["provenance"]),
            {"linux/amd64", "linux/arm64"},
        )

    def test_raw_index_hash_and_every_child_membership_are_mandatory(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["app"]["oci_index"]["sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "OCI index record"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["app"]["platforms"]["linux/arm64"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "not members"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_index_requires_one_bound_attestation_manifest_per_child(self):
        index_path = self.artifacts / "oci" / "app.index.json"
        index = json.loads(index_path.read_text())
        index["manifests"].pop()
        self._json(index_path, index)
        self.index_digests["app"] = self._hash(index_path)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "exactly one attestation"):
            self._build_manifest()

    def test_mutable_or_wrong_repository_references_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["app"]["quarantine_reference"] = (
            "ghcr.io/bilal414/backupsheep-quarantine:v1.2.3"
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "exact digest"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["images"]["postgres"]["official_repository"] = "ghcr.io/attacker/postgres"
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "not authorized"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_spdx_and_cyclonedx_must_have_nonempty_inventories(self):
        for fmt, key, message in (
            ("spdx-json", "packages", "no packages"),
            ("cyclonedx-json", "components", "no components"),
        ):
            manifest = copy.deepcopy(self.manifest)
            record = next(
                item
                for item in manifest["images"]["app"]["sboms"]
                if item["platform"] == "linux/amd64" and item["format"] == fmt
            )
            path = self.artifacts / record["file"]
            document = json.loads(path.read_text())
            document[key] = []
            self._json(path, document)
            self._rehash_record(record)
            with self.subTest(format=fmt), self.assertRaisesRegex(
                verifier.ReleaseVerificationError, message
            ):
                verifier.validate_release(self.policy, manifest, self.artifacts)
            self._write_evidence()

    def test_syft_source_catalog_is_complete_and_digest_bound(self):
        manifest = copy.deepcopy(self.manifest)
        record = manifest["images"]["app"]["source_catalogs"][0]
        path = self.artifacts / record["file"]
        catalog = json.loads(path.read_text())
        catalog["source"]["metadata"]["userInput"] = "ghcr.io/attacker/image@sha256:" + "2" * 64
        self._json(path, catalog)
        self._rehash_record(record)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "exact image digest"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        catalog["source"]["metadata"]["userInput"] = (
            f"{self.policy['images']['app']['quarantine_repository']}@"
            f"{self.platform_digests['app']['linux/amd64']}"
        )
        catalog["artifacts"] = []
        self._json(path, catalog)
        self._rehash_record(record)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "no artifacts"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_trivy_report_requires_structure_packages_and_fails_high_unfixed(self):
        manifest = copy.deepcopy(self.manifest)
        record = manifest["images"]["app"]["vulnerability_reports"][0]
        path = self.artifacts / record["file"]
        report = json.loads(path.read_text())
        report["Results"][0]["Packages"] = []
        self._json(path, report)
        self._rehash_record(record)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "no package inventory"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        report["Results"][0]["Packages"] = [{"Name": "openssl", "Version": "3"}]
        report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2099-0001", "Severity": "HIGH", "FixedVersion": ""}
        ]
        self._json(path, report)
        self._rehash_record(record)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "release-blocking"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_buildkit_provenance_requires_exact_source_and_max_completeness(self):
        statement = copy.deepcopy(self.statements[("app", "linux/amd64")])
        statement["predicate"]["buildDefinition"]["externalParameters"]["configSource"]["uri"] = (
            "https://github.com/attacker/backupsheep.git#" + self.commit
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "exact remote Git commit"):
            verifier._validate_buildkit_statement(
                statement,
                release=self.manifest["release"],
                child_digest=self.platform_digests["app"]["linux/amd64"],
                dockerfile="Dockerfile",
                policy=self.policy,
                label="provenance",
            )

        statement = copy.deepcopy(self.statements[("app", "linux/amd64")])
        statement["predicate"]["buildDefinition"]["internalParameters"]["buildConfig"][
            "llbDefinition"
        ] = []
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "mode=max"):
            verifier._validate_buildkit_statement(
                statement,
                release=self.manifest["release"],
                child_digest=self.platform_digests["app"]["linux/amd64"],
                dockerfile="Dockerfile",
                policy=self.policy,
                label="provenance",
            )

    def test_duplicate_json_keys_symlinks_and_world_readable_generation_are_handled(self):
        duplicate = self.temporary_directory / "duplicate.json"
        duplicate.write_text('{"schema_version":2,"schema_version":2}\n')
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "duplicate JSON key"):
            verifier._load_json(duplicate, maximum_bytes=1024)

        output = self.artifacts / "generated.json"
        builder._write_json(output, {"safe": True})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        record = self.manifest["images"]["app"]["sboms"][0]
        original = self.artifacts / record["file"]
        replacement = original.with_suffix(".real.json")
        original.rename(replacement)
        original.symlink_to(replacement.name)
        record["sha256"] = self._hash(replacement)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "symlink"):
            verifier.validate_release(self.policy, self.manifest, self.artifacts)

    def test_verified_dsse_payload_binds_digest_type_and_predicate_not_mutable_name(self):
        predicate = {"buildDefinition": {}, "runDetails": {}}
        digest = "sha256:" + "b" * 64
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "pkg:docker/example", "digest": {"sha256": "b" * 64}}],
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
            digest=digest,
            predicate_type="https://slsa.dev/provenance/v1",
            predicate=predicate,
        )
        legacy_statement = copy.deepcopy(statement)
        legacy_statement["_type"] = "https://in-toto.io/Statement/v0.1"
        verifier._require_matching_attestation(
            [legacy_statement],
            digest=digest,
            predicate_type="https://slsa.dev/provenance/v1",
            predicate=predicate,
            statement_type=verifier.IN_TOTO_STATEMENT_V01_TYPE,
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "no verified"):
            verifier._require_matching_attestation(
                statements,
                digest="sha256:" + "c" * 64,
                predicate_type="https://slsa.dev/provenance/v1",
                predicate=predicate,
            )


class ReleaseToolInstallerTests(TestCase):
    def test_installer_verifies_asset_hash_extracts_only_regular_member_and_uses_private_modes(self):
        temporary = Path(tempfile.mkdtemp(prefix="backupsheep-tools-"))
        self.addCleanup(shutil.rmtree, temporary)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            payload = b"#!/bin/sh\nexit 0\n"
            member = tarfile.TarInfo("syft")
            member.size = len(payload)
            member.mode = 0o777
            archive.addfile(member, io.BytesIO(payload))
        asset = buffer.getvalue()
        policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text())
        policy["tools"]["syft"]["sha256"] = hashlib.sha256(asset).hexdigest()
        with mock.patch.object(installer, "_download", return_value=asset):
            installer.install(policy, temporary / "bin", ["syft"])
        self.assertEqual(stat.S_IMODE((temporary / "bin" / "syft").stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((temporary / "bin" / "empty-syft.yaml").stat().st_mode), 0o600)

    def test_installer_rejects_hash_mismatch(self):
        temporary = Path(tempfile.mkdtemp(prefix="backupsheep-tools-"))
        self.addCleanup(shutil.rmtree, temporary)
        policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text())
        with mock.patch.object(installer, "_download", return_value=b"tampered"):
            with self.assertRaisesRegex(verifier.ReleaseVerificationError, "SHA-256 mismatch"):
                installer.install(policy, temporary / "bin", ["syft"])


class ReleasePromotionRecoveryTests(ReleaseFixtureMixin, TestCase):
    def _registry(self, initially_present):
        indexes = {
            name: (self.artifacts / image["oci_index"]["file"]).read_bytes()
            for name, image in self.manifest["images"].items()
        }
        registry = {}
        for name in initially_present:
            image = self.manifest["images"][name]
            registry[f"{image['official_repository']}:{self.tag}"] = indexes[name]
            registry[image["official_reference"]] = indexes[name]
        copies = []

        def fake_oras(_oras, arguments, *, allow_not_found=False):
            if arguments[:2] == ["manifest", "fetch"]:
                output = Path(arguments[arguments.index("--output") + 1])
                reference = arguments[-1]
                payload = registry.get(reference)
                if payload is None:
                    if allow_not_found:
                        return "NOT_FOUND"
                    raise verifier.ReleaseVerificationError(f"missing test reference {reference}")
                output.write_bytes(payload)
                return ""
            if arguments[0] == "cp":
                _command, _source, destination = arguments
                copies.append(destination)
                image_name = next(
                    name
                    for name, image in self.manifest["images"].items()
                    if destination.startswith(f"{image['official_repository']}:")
                )
                image = self.manifest["images"][image_name]
                registry[destination] = indexes[image_name]
                registry[image["official_reference"]] = indexes[image_name]
                return ""
            raise AssertionError(arguments)

        return registry, copies, fake_oras

    def test_partial_release_resumes_only_missing_exact_tags(self):
        _registry, copies, fake_oras = self._registry({"app"})
        with mock.patch.object(promoter, "_oras", side_effect=fake_oras):
            promoter.promote(self.policy, self.manifest, self.artifacts, "oras")
        self.assertEqual(
            copies,
            [
                f"{self.manifest['images']['postgres']['official_repository']}:{self.tag}",
                f"{self.manifest['images']['egress']['official_repository']}:{self.tag}",
            ],
        )

    def test_exact_completed_release_is_idempotent(self):
        _registry, copies, fake_oras = self._registry(set(self.manifest["images"]))
        with mock.patch.object(promoter, "_oras", side_effect=fake_oras):
            promoter.promote(self.policy, self.manifest, self.artifacts, "oras")
        self.assertEqual(copies, [])

    def test_existing_mismatched_tag_fails_before_any_write(self):
        registry, copies, fake_oras = self._registry({"app"})
        registry[f"{self.manifest['images']['app']['official_repository']}:{self.tag}"] = b"wrong"
        with mock.patch.object(promoter, "_oras", side_effect=fake_oras), self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "wrong OCI digest"
        ):
            promoter.promote(self.policy, self.manifest, self.artifacts, "oras")
        self.assertEqual(copies, [])

    def test_official_digest_is_staged_before_semver_and_is_idempotent(self):
        _registry, copies, fake_oras = self._registry(set())
        staging_tag = f"staged-{self.commit}-123-1"
        with mock.patch.object(stager, "_oras", side_effect=fake_oras), mock.patch.object(
            stager, "_fetch_and_verify_index", wraps=stager._fetch_and_verify_index
        ):
            # The shared fetch helper calls promote_release_images._oras, so patch
            # that exact credential-scrubbing boundary as well.
            with mock.patch.object(promoter, "_oras", side_effect=fake_oras):
                stager.stage(
                    self.policy,
                    self.manifest,
                    self.artifacts,
                    "oras",
                    staging_tag,
                )
        self.assertEqual(len(copies), len(self.manifest["images"]))
        self.assertTrue(all(destination.endswith(f":{staging_tag}") for destination in copies))
        self.assertTrue(all(not destination.endswith(f":{self.tag}") for destination in copies))

        copies.clear()
        with mock.patch.object(stager, "_oras", side_effect=fake_oras), mock.patch.object(
            promoter, "_oras", side_effect=fake_oras
        ):
            stager.stage(
                self.policy,
                self.manifest,
                self.artifacts,
                "oras",
                staging_tag,
            )
        self.assertEqual(copies, [])

    def test_official_staging_tag_is_commit_bound(self):
        _registry, copies, fake_oras = self._registry(set())
        with mock.patch.object(stager, "_oras", side_effect=fake_oras), self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "source-commit bound"
        ):
            stager.stage(
                self.policy,
                self.manifest,
                self.artifacts,
                "oras",
                f"staged-{'b' * 40}-123-1",
            )
        self.assertEqual(copies, [])

class ReleaseWorkflowContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.workflow = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(
            encoding="utf-8"
        )
        cls.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text())

    def test_every_action_is_pinned_to_a_full_commit(self):
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, flags=re.MULTILINE)
        self.assertGreaterEqual(len(actions), 10)
        for action in actions:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_release_is_dormant_and_signing_permissions_are_separated(self):
        self.assertIn("vars.BACKUPSHEEP_SIGNED_RELEASES_ENABLED == 'true'", self.workflow)
        self.assertIn("github.repository == 'bilal414/backupsheep'", self.workflow)
        self.assertIn("environment: signed-release", self.workflow)
        self.assertNotIn("workflow_dispatch", self.workflow)
        build_job = self.workflow.split("  sign_promote:", 1)[0]
        self.assertNotIn("id-token: write", build_job)
        publish_job = self.workflow.split("  publish_evidence:", 1)[1]
        self.assertNotIn("packages: write", publish_job)
        self.assertNotIn("id-token: write", publish_job)

    def test_no_mutable_tool_installer_action_and_all_assets_are_sha_pinned(self):
        self.assertNotIn("anchore/sbom-action", self.workflow)
        self.assertNotIn("aquasecurity/setup-trivy", self.workflow)
        self.assertNotIn("sigstore/cosign-installer", self.workflow)
        self.assertIn("scripts/install_release_tools.py", self.workflow)
        for name, record in self.policy["tools"].items():
            with self.subTest(tool=name):
                self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn(record["version"], record["url"])

    def test_candidates_are_quarantined_and_official_tags_are_post_gate_semver_only(self):
        self.assertIn("backupsheep-quarantine:candidate-", self.workflow)
        self.assertIn("backupsheep-postgres-quarantine:candidate-", self.workflow)
        self.assertIn("backupsheep-egress-quarantine:candidate-", self.workflow)
        self.assertNotIn("backupsheep:candidate-", self.workflow)
        self.assertNotIn("backupsheep-postgres:candidate-", self.workflow)
        self.assertNotIn("backupsheep-egress:candidate-", self.workflow)
        verify_position = self.workflow.index("Verify quarantine before any official write")
        stage_position = self.workflow.index("Stage exact verified indexes")
        sign_position = self.workflow.index("Sign official digests")
        promote_position = self.workflow.index("Publish signed official digests under SemVer tags last")
        self.assertLess(verify_position, stage_position)
        self.assertLess(stage_position, sign_position)
        self.assertLess(sign_position, promote_position)
        self.assertLess(verify_position, promote_position)
        self.assertIn("scripts/stage_release_images.py", self.workflow)
        self.assertIn("scripts/promote_release_images.py", self.workflow)

    def test_buildkit_provenance_is_real_remote_source_bound_mode_max(self):
        self.assertEqual(self.workflow.count("provenance: mode=max,version=v1,builder-id="), 3)
        self.assertEqual(
            self.workflow.count("context: https://github.com/${{ github.repository }}.git#${{ github.sha }}"),
            3,
        )
        self.assertIn("scripts/collect_release_evidence.py", self.workflow)
        self.assertIn("--statement \"$ARTIFACT_DIR/$statement\"", self.workflow)
        self.assertNotIn("mobyproject.org/buildkit@v1", self.workflow)

    def test_scanners_cannot_auto_load_repository_config_or_ignore_files(self):
        self.assertGreaterEqual(self.workflow.count("env -i"), 2)
        self.assertIn('--config "$TOOL_DIR/empty-trivy.yaml"', self.workflow)
        self.assertIn('--ignorefile "$TOOL_DIR/empty-trivy.ignore"', self.workflow)
        self.assertIn('--config "$TOOL_DIR/empty-syft.yaml"', self.workflow)
        self.assertIn("--list-all-pkgs", self.workflow)
        self.assertIn("--severity HIGH,CRITICAL", self.workflow)
        self.assertIn("--exit-code 1", self.workflow)
        self.assertNotIn("--ignore-unfixed", self.workflow)

    def test_evidence_is_retained_and_published_durably(self):
        self.assertGreaterEqual(self.workflow.count("retention-days: 90"), 2)
        self.assertIn("signed-release-evidence.tar.gz", self.workflow)
        self.assertIn("scripts/publish_release_evidence.py", self.workflow)
        self.assertIn("tar --sort=name", self.workflow)
        self.assertNotIn("chmod 0644", self.workflow)
