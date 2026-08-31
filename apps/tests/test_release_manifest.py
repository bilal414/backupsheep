import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_release_manifest as builder  # noqa: E402
import build_release_descriptor as descriptor_builder  # noqa: E402
import collect_release_evidence as collector  # noqa: E402
import install_release_tools as installer  # noqa: E402
import materialize_legacy_rabbitmq_vex as legacy_vex  # noqa: E402
import normalize_local_scan_evidence as normalizer  # noqa: E402
import prepare_trivy_db as trivy_db  # noqa: E402
import protect_release_evidence as protected_export  # noqa: E402
import promote_release_images as promoter  # noqa: E402
import release_transition as transition  # noqa: E402
import release_subprocess  # noqa: E402
import push_quarantine_layouts as quarantine_pusher  # noqa: E402
import stage_release_images as stager  # noqa: E402
import verify_release as verifier  # noqa: E402
import verify_quarantine_indexes as quarantine_verifier  # noqa: E402


class ReleaseFixtureMixin:
    def setUp(self):
        super().setUp()
        self.temporary_directory = Path(tempfile.mkdtemp(prefix="backupsheep-release-"))
        self.artifacts = self.temporary_directory / "artifacts"
        for directory in (
            "oci",
            "sbom",
            "scans",
            "provenance",
            "bundles",
            "vulnerability",
            "transition",
        ):
            (self.artifacts / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
        self.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text(encoding="utf-8"))
        self.trivy_lock = json.loads(
            (ROOT / "deploy" / "trivy-db-lock.json").read_text(encoding="utf-8")
        )
        self.grype_lock = json.loads(
            (ROOT / "deploy" / "grype-db-lock.json").read_text(encoding="utf-8")
        )
        trivy_created_at = datetime.fromisoformat(
            self.trivy_lock["manifest"]["created_at"].replace("Z", "+00:00")
        )
        trivy_next_update = datetime.fromisoformat(
            self.trivy_lock["database"]["next_update"].replace("Z", "+00:00")
        )
        self.trivy_prepared_at = trivy_created_at + timedelta(minutes=1)
        self.release_created_at = self.trivy_prepared_at + timedelta(minutes=1)
        self.assertLess(self.release_created_at, trivy_next_update)
        self.release_created_at_text = self.release_created_at.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.commit = "a" * 40
        self.tag = "v1.2.3"
        self.workflow_identity = (
            "https://github.com/bilal414/backupsheep/.github/workflows/"
            "release-images.yml@refs/tags/v1.2.3"
        )
        self.child_manifests = {}
        self.platform_digests = {}
        for image_position, image in enumerate(self.policy["images"], start=1):
            self.platform_digests[image] = {}
            for platform_position, platform in enumerate(self.policy["platforms"], start=1):
                seed = f"{image_position:x}{platform_position:x}"
                config_digest = "sha256:" + seed.ljust(64, "c")
                layer_digest = "sha256:" + seed.ljust(64, "d")
                manifest = {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {"digest": config_digest, "size": 123},
                    "layers": [{"digest": layer_digest, "size": 456}],
                }
                manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
                child_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
                self.platform_digests[image][platform] = child_digest
                self.child_manifests[(image, platform)] = (
                    manifest_bytes,
                    config_digest,
                    layer_digest,
                )
        for platform_position, platform in enumerate(self.policy["platforms"], start=1):
            seed = f"f{platform_position:x}"
            config_digest = "sha256:" + seed.ljust(64, "c")
            layer_digest = "sha256:" + seed.ljust(64, "d")
            manifest = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": config_digest, "size": 123},
                "layers": [{"digest": layer_digest, "size": 456}],
            }
            manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
            child_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            verifier_identity = self.policy["consumer"]["cosign_image"]["platforms"][platform]
            verifier_identity["manifest_digest"] = child_digest
            verifier_identity["config_digest"] = config_digest
            self.child_manifests[("release-verifier", platform)] = (
                manifest_bytes,
                config_digest,
                layer_digest,
            )
        self.fixture_policy_path = self.temporary_directory / "release-policy.json"
        self._json(self.fixture_policy_path, self.policy)
        self.statements = {}
        self._write_vulnerability_database_evidence()
        self._write_consumer_evidence()
        self._write_evidence()
        shutil.copyfile(
            ROOT / "deploy" / "release-transition-policy.json",
            self.artifacts / "transition" / "reviewed-policy.json",
        )
        (self.artifacts / "transition" / "reviewed-policy.json").chmod(0o600)
        migrations = ["apps.0001_initial", "apps.0002_next"]
        leaves = ["apps.0002_next"]
        self._json(
            self.artifacts / "transition" / "django-migrations.json",
            {
                "schema_version": 1,
                "all_migrations_atomic": True,
                "migrations": migrations,
                "migration_set_sha256": transition.migration_digest(migrations),
                "leaves": leaves,
                "leaf_set_sha256": transition.migration_digest(leaves, leaves=True),
            },
        )
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

    def _grype_report(self, reference, manifest_bytes, config_digest, layer_digest):
        return {
            "matches": [],
            "source": {
                "type": "image",
                "target": {
                    "userInput": reference,
                    "imageID": config_digest,
                    "manifestDigest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
                    "layers": [{"digest": layer_digest}],
                    "manifest": base64.b64encode(manifest_bytes).decode(),
                },
            },
            "distro": {"name": "debian", "version": "12"},
            "descriptor": {
                "name": "grype",
                "version": "0.116.1",
                "db": {
                    "status": {
                        "schemaVersion": self.grype_lock["database"]["schema_version"],
                        "from": "manual import",
                        "built": self.grype_lock["database"]["built_at"],
                        "path": "/private/grype-cache/6/vulnerability.db",
                        "valid": True,
                    },
                    "providers": {
                        "nvd": {
                            "captured": self.grype_lock["database"]["built_at"],
                            "input": "xxh64:test",
                        }
                    },
                },
                "configuration": {
                    "name": "",
                    "fail-on-severity": "high",
                    "only-fixed": False,
                    "only-notfixed": False,
                    "check-for-app-update": False,
                    "ignore-wontfix": "",
                    "ignore": [],
                    "exclude": [],
                    "vex-documents": [],
                    "vex-add": [],
                },
            },
        }

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

    def _write_vulnerability_database_evidence(self):
        vulnerability = self.artifacts / "vulnerability"
        lock_source = ROOT / "deploy" / "trivy-db-lock.json"
        lock_copy = vulnerability / "trivy-db-lock.json"
        lock_copy.write_bytes(lock_source.read_bytes())
        lock_copy.chmod(0o600)
        self.assertEqual(
            self._hash(lock_copy),
            self.policy["vulnerability_policy"]["database"]["lock_sha256"],
        )
        lock = json.loads(lock_copy.read_text(encoding="utf-8"))
        evidence = trivy_db.evidence_for(
            lock,
            self._hash(lock_copy).removeprefix("sha256:"),
            self.trivy_prepared_at,
        )
        self._json(vulnerability / "trivy-db-evidence.json", evidence)
        grype_lock_source = ROOT / "deploy" / "grype-db-lock.json"
        grype_lock_copy = vulnerability / "grype-db-lock.json"
        grype_lock_copy.write_bytes(grype_lock_source.read_bytes())
        grype_lock_copy.chmod(0o600)
        self.assertEqual(
            self._hash(grype_lock_copy),
            self.policy["vulnerability_policy"]["secondary_database"]["lock_sha256"],
        )
        grype_lock = json.loads(grype_lock_copy.read_text(encoding="utf-8"))
        self._json(
            vulnerability / "grype-db-evidence.json",
            {
                "schema_version": 1,
                "lock_sha256": self._hash(grype_lock_copy).removeprefix("sha256:"),
                "grype_version": "0.116.1",
                "prepared_at": (self.release_created_at - timedelta(seconds=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "archive_sha256": grype_lock["archive"]["sha256"],
                "archive_size": grype_lock["archive"]["size"],
                "database_schema_version": grype_lock["database"]["schema_version"],
                "database_built_at": grype_lock["database"]["built_at"],
                "database_sha256": grype_lock["database"]["sha256"],
                "database_size": grype_lock["database"]["size"],
            },
        )

    def _write_consumer_evidence(self):
        consumer = self.artifacts / "consumer"
        consumer.mkdir(mode=0o700, exist_ok=True)
        trusted_root = ROOT / "deploy" / "release" / "sigstore-trusted-root.json"
        trusted_copy = consumer / "sigstore-trusted-root.json"
        trusted_copy.write_bytes(trusted_root.read_bytes())
        trusted_copy.chmod(0o600)
        verifier_policy = self.policy["consumer"]["cosign_image"]
        for platform, identity in verifier_policy["platforms"].items():
            slug = platform.replace("/", "-")
            reference = f"{verifier_policy['repository']}@{identity['manifest_digest']}"
            manifest_bytes, config_digest, layer_digest = self.child_manifests[
                ("release-verifier", platform)
            ]
            self._json(
                consumer / f"release-verifier-{slug}.syft.json",
                {
                    "artifacts": [
                        {
                            "id": f"release-verifier-{slug}-cosign",
                            "name": "github.com/sigstore/cosign/v3",
                        }
                    ],
                    "artifactRelationships": [],
                    "source": {
                        "type": "image",
                        "metadata": {
                            "userInput": reference,
                            "manifestDigest": identity["manifest_digest"],
                            "imageID": identity["config_digest"],
                            "manifest": base64.b64encode(manifest_bytes).decode(),
                        },
                    },
                    "descriptor": {"name": "syft", "version": "1.51.0"},
                },
            )
            self._json(
                consumer / f"release-verifier-{slug}.trivy.json",
                {
                    "SchemaVersion": 2,
                    "ArtifactName": reference,
                    "ArtifactType": "container_image",
                    "Metadata": {
                        "ImageID": identity["config_digest"],
                    },
                    "Results": [
                        {
                            "Target": "/ko-app/cosign",
                            "Class": "lang-pkgs",
                            "Type": "gobinary",
                            "Packages": [
                                {
                                    "Name": "github.com/sigstore/cosign/v3",
                                    "Version": "v3.1.3",
                                }
                            ],
                            "Vulnerabilities": [],
                        }
                    ],
                },
            )
            self._json(
                consumer / f"release-verifier-{slug}.grype.json",
                self._grype_report(
                    reference, manifest_bytes, config_digest, layer_digest
                ),
            )

    def _write_evidence(self):
        self.index_digests = {}
        for image in self.policy["images"]:
            child_descriptors = []
            attestation_descriptors = []
            quarantine = self.policy["images"][image]["quarantine_repository"]
            for platform, digest in self.platform_digests[image].items():
                slug = platform.replace("/", "-")
                manifest_bytes, config_digest, layer_digest = self.child_manifests[
                    (image, platform)
                ]
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
                                "imageID": config_digest,
                                "manifest": base64.b64encode(manifest_bytes).decode(),
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
                self._json(
                    self.artifacts / "scans" / f"{image}-{slug}.grype.json",
                    self._grype_report(
                        f"{quarantine}@{digest}",
                        manifest_bytes,
                        config_digest,
                        layer_digest,
                    ),
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
            created_at=self.release_created_at_text,
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
        self.assertEqual(tuple(result["manifest"]["images"]), verifier.RELEASE_IMAGE_NAMES)
        self.assertEqual(result["manifest"]["images"]["app"]["digest"], self.index_digests["app"])
        self.assertEqual(result["transition"]["release_epoch"], 1)
        self.assertEqual(
            set(result["attestation_predicates"]["postgres"]["provenance"]),
            {"linux/amd64", "linux/arm64"},
        )
        self.assertEqual(
            result["consumer"]["manifest"]["cosign_image"]["index_digest"],
            self.policy["consumer"]["cosign_image"]["index_digest"],
        )
        self.assertEqual(
            result["vulnerability_database"]["lock"]["manifest"]["digest"],
            json.loads(
                (ROOT / "deploy" / "trivy-db-lock.json").read_text(encoding="utf-8")
            )["manifest"]["digest"],
        )

    def test_vulnerability_database_lock_and_preparation_time_are_mandatory(self):
        manifest = copy.deepcopy(self.manifest)
        record = manifest["vulnerability_database"]["preparation_evidence"]
        path = self.artifacts / record["file"]
        evidence = json.loads(path.read_text(encoding="utf-8"))
        evidence["prepared_at"] = (
            self.release_created_at + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._json(path, evidence)
        record["sha256"] = self._hash(path)
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError,
            "Trivy DB evidence preparation time is inconsistent",
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        manifest["vulnerability_database"]["lock"]["sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "lock digest differs from policy"
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_descriptor_v1_cannot_be_reinterpreted_as_the_five_image_contract(self):
        old_v1 = (
            "BACKUPSHEEP-SIGNED-RELEASE-V1\n"
            f"release_tag={self.tag}\n"
            f"source_commit={self.commit}\n"
            "release_manifest_sha256=sha256:"
            + "1" * 64
            + "\napp_image=ghcr.io/bilal414/backupsheep@sha256:"
            + "2" * 64
            + "\npostgres_image=ghcr.io/bilal414/backupsheep-postgres@sha256:"
            + "3" * 64
            + "\negress_image=ghcr.io/bilal414/backupsheep-egress@sha256:"
            + "4" * 64
            + "\n"
        ).encode("ascii")
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "exact canonical V2 payload"
        ):
            descriptor_builder.validate_descriptor_payload(
                self.policy,
                self.manifest,
                "sha256:" + "1" * 64,
                old_v1,
            )

        downgraded = copy.deepcopy(self.policy)
        downgraded["consumer"]["descriptor_filename"] = (
            "backupsheep-release-descriptor-v1.txt"
        )
        downgraded["consumer"]["descriptor_bundle_filename"] = (
            "backupsheep-release-descriptor-v1.sigstore.json"
        )
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "canonical consumer filename"
        ):
            verifier._validate_policy(downgraded)

    def test_release_image_repositories_and_dockerfiles_are_exact_and_distinct(self):
        self.assertEqual(self.policy["images"], verifier.EXPECTED_RELEASE_IMAGES)
        tampered = copy.deepcopy(self.policy)
        tampered["images"]["rabbitmq-upgrade"]["dockerfile"] = "Dockerfile.rabbitmq"
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "exact release contract"
        ):
            verifier._validate_policy(tampered)

    def test_v2_descriptor_exactly_binds_five_images_verifier_graph_and_trusted_root(self):
        manifest_path = self.artifacts / "release-manifest.json"
        builder._write_json(manifest_path, self.manifest)
        descriptor_path = self.artifacts / self.policy["consumer"]["descriptor_filename"]
        arguments = [
            "--policy",
            str(self.fixture_policy_path),
            "--manifest",
            str(manifest_path),
            "--artifacts-dir",
            str(self.artifacts),
            "--output",
            str(descriptor_path),
        ]
        self.assertEqual(descriptor_builder.main(arguments), 0)
        lines = descriptor_path.read_text(encoding="ascii").splitlines()
        self.assertEqual(len(lines), 16)
        self.assertEqual(lines[0], "BACKUPSHEEP-SIGNED-RELEASE-V2")
        self.assertEqual(
            lines[4:9],
            [
                f"{image.replace('-', '_')}_image={self.manifest['images'][image]['official_reference']}"
                for image in verifier.RELEASE_IMAGE_NAMES
            ],
        )
        verifier_policy = self.policy["consumer"]["cosign_image"]
        self.assertEqual(lines[9], f"release_verifier_image={verifier_policy['reference']}")
        self.assertEqual(
            lines[10],
            "release_verifier_runtime_contract_version=1",
        )
        self.assertEqual(
            lines[11],
            "release_verifier_linux_amd64_manifest="
            + verifier_policy["platforms"]["linux/amd64"]["manifest_digest"],
        )
        self.assertEqual(
            lines[15],
            "trusted_root_sha256=sha256:"
            + self.policy["consumer"]["trusted_root"]["sha256"],
        )
        self.assertEqual(descriptor_builder.main([*arguments, "--verify"]), 0)

        descriptor_path.write_bytes(descriptor_path.read_bytes() + b"unknown=value\n")
        self.assertEqual(descriptor_builder.main([*arguments, "--verify"]), 1)

    def test_consumer_verifier_evidence_is_exactly_policy_and_config_bound(self):
        unsupported = copy.deepcopy(self.policy)
        unsupported["consumer"]["cosign_image"]["runtime_contract_version"] = 2
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "runtime contract is not supported"
        ):
            verifier._validate_policy(unsupported)

        manifest = copy.deepcopy(self.manifest)
        manifest["consumer"]["cosign_image"]["platforms"][0]["config_digest"] = (
            "sha256:" + "e" * 64
        )
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "differs from policy"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        manifest = copy.deepcopy(self.manifest)
        record = manifest["consumer"]["cosign_image"]["platforms"][0][
            "source_catalog"
        ]
        path = self.artifacts / record["file"]
        catalog = json.loads(path.read_text())
        catalog["source"]["metadata"]["imageID"] = "sha256:" + "e" * 64
        self._json(path, catalog)
        record["sha256"] = self._hash(path)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "config-digest bound"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_manifest_cli_requires_and_accepts_the_complete_five_image_set(self):
        output = self.artifacts / "cli-release-manifest.json"
        arguments = [
            "--policy",
            str(self.fixture_policy_path),
            "--artifacts-dir",
            str(self.artifacts),
            "--output",
            str(output),
            "--tag",
            self.tag,
            "--source-commit",
            self.commit,
            "--workflow-run",
            "https://github.com/bilal414/backupsheep/actions/runs/123/attempts/1",
            "--created-at",
            self.release_created_at_text,
        ]
        for image in ("app", "postgres", "egress", "rabbitmq", "rabbitmq-upgrade"):
            arguments.extend(
                (
                    f"--{image}-digest",
                    self.index_digests[image],
                    f"--{image}-index",
                    str(self.artifacts / "oci" / f"{image}.index.json"),
                )
            )
        self.assertEqual(builder.main(arguments), 0)
        generated = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(tuple(generated["images"]), tuple(self.policy["images"]))
        self.assertEqual(generated["transition"], self.manifest["transition"])

    def test_signed_transition_record_and_reviewed_source_are_mandatory(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["transition"]["migration_contract"]["leaf_set_sha256"] = (
            "sha256:" + "f" * 64
        )
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError,
            "manifest transition authorization is invalid",
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        reviewed_path = self.artifacts / "transition" / "reviewed-policy.json"
        self._json(
            reviewed_path,
            {"schema_version": 1, "release_epoch": 2, "accepted_predecessors": []},
        )
        migration_path = self.artifacts / "transition" / "django-migrations.json"
        manifest = copy.deepcopy(self.manifest)
        manifest["transition"] = transition.build_transition_record(
            reviewed_policy=transition.load_json(reviewed_path),
            migration_contract=transition.load_json(migration_path),
            reviewed_policy_file="transition/reviewed-policy.json",
            reviewed_policy_sha256=self._hash(reviewed_path),
            migration_contract_file="transition/django-migrations.json",
            migration_contract_sha256=self._hash(migration_path),
        )
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError,
            "does not byte-match the reviewed source input",
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

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

    def test_grype_report_is_digest_bound_and_fails_high_unfixed(self):
        manifest = copy.deepcopy(self.manifest)
        record = manifest["images"]["app"]["secondary_vulnerability_reports"][0]
        path = self.artifacts / record["file"]
        report = json.loads(path.read_text())
        report["matches"] = [
            {
                "vulnerability": {"id": "CVE-2099-0002", "severity": "High"},
                "artifact": {"name": "openssl", "version": "3", "type": "deb"},
            }
        ]
        self._json(path, report)
        self._rehash_record(record)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "release-blocking"):
            verifier.validate_release(self.policy, manifest, self.artifacts)

        report["matches"] = []
        report["source"]["target"]["imageID"] = "sha256:" + "e" * 64
        self._json(path, report)
        self._rehash_record(record)
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "child config digest"
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_grype_database_lock_and_evidence_are_signed_and_fail_closed(self):
        database_policy = self.policy["vulnerability_policy"]["secondary_database"]
        lock_path = ROOT / database_policy["lock_path"]
        self.assertEqual(self._hash(lock_path), database_policy["lock_sha256"])
        manifest = copy.deepcopy(self.manifest)
        record = manifest["vulnerability_database"]["secondary_preparation_evidence"]
        path = self.artifacts / record["file"]
        evidence = json.loads(path.read_text())
        evidence["database_sha256"] = "0" * 64
        self._json(path, evidence)
        self._rehash_record(record)
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError,
            "Grype DB preparation evidence differs from the lock",
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_each_scan_report_is_bound_to_the_exact_database_receipt(self):
        for image_key, report_key, binding_key in (
            ("app", "vulnerability_reports", "trivy"),
            ("app", "secondary_vulnerability_reports", "grype"),
        ):
            with self.subTest(scanner=binding_key):
                manifest = copy.deepcopy(self.manifest)
                record = manifest["images"][image_key][report_key][0]
                record["database"]["database_sha256"] = "sha256:" + "f" * 64
                with self.assertRaisesRegex(
                    verifier.ReleaseVerificationError,
                    "not bound to the exact reviewed scanner DB",
                ):
                    verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_grype_report_descriptor_must_name_the_locked_database(self):
        manifest = copy.deepcopy(self.manifest)
        record = manifest["images"]["app"]["secondary_vulnerability_reports"][0]
        path = self.artifacts / record["file"]
        report = json.loads(path.read_text(encoding="utf-8"))
        report["descriptor"]["db"]["status"]["schemaVersion"] = "v6.9.9"
        self._json(path, report)
        self._rehash_record(record)
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError,
            "exact locked Grype DB",
        ):
            verifier.validate_release(self.policy, manifest, self.artifacts)

    def test_protected_export_excludes_every_unreferenced_producer_file(self):
        manifest_path = self.artifacts / "release-manifest.json"
        builder._write_json(manifest_path, self.manifest)
        policy_copy = self.artifacts / "release-policy.json"
        policy_copy.write_bytes(self.fixture_policy_path.read_bytes())
        policy_copy.chmod(0o600)
        descriptor_path = self.artifacts / self.policy["consumer"]["descriptor_filename"]
        descriptor_path.write_bytes(
            descriptor_builder.descriptor_payload(
                self.policy,
                self.manifest,
                self._hash(manifest_path),
            )
        )
        descriptor_path.chmod(0o600)
        (self.artifacts / "producer-controlled-extra.bin").write_bytes(b"untrusted")

        exported = self.temporary_directory / "protected-export"
        expected = protected_export.export(
            self.fixture_policy_path,
            self.artifacts,
            exported,
        )
        self.assertNotIn("producer-controlled-extra.bin", expected)
        self.assertFalse((exported / "producer-controlled-extra.bin").exists())
        protected_export.verify(self.fixture_policy_path, exported)

        (exported / "attacker-added-after-export.bin").write_bytes(b"untrusted")
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "exact manifest-derived inventory"
        ):
            protected_export.verify(self.fixture_policy_path, exported)

    def test_pre_sign_remote_verifier_fetches_every_exact_manifest(self):
        expected_references = set()
        for image in self.manifest["images"].values():
            expected_references.add(image["quarantine_reference"])
            expected_references.update(
                f"{image['quarantine_repository']}@{digest}"
                for digest in image["platforms"].values()
            )
            expected_references.update(
                f"{image['quarantine_repository']}@{record['digest']}"
                for record in image["attestation_manifests"]
            )
        consumer = self.manifest["consumer"]["cosign_image"]
        expected_references.update(
            f"{consumer['repository']}@{record['manifest_digest']}"
            for record in consumer["platforms"]
        )
        with mock.patch.object(
            quarantine_verifier,
            "_fetch_and_verify_index",
            return_value=True,
        ) as fetch:
            quarantine_verifier.verify(
                self.policy,
                self.manifest,
                self.artifacts,
                "/private/oras",
            )
        self.assertEqual(
            {call.args[1] for call in fetch.call_args_list},
            expected_references,
        )
        self.assertEqual(fetch.call_count, 27)

    def test_legacy_grype_vex_compensation_is_exact_package_and_cve_bound(self):
        image = "rabbitmq"
        platform = "linux/amd64"
        manifest_bytes, config_digest, layer_digest = self.child_manifests[
            (image, platform)
        ]
        digest = self.platform_digests[image][platform]
        report = self._grype_report(
            "legacy-source", manifest_bytes, config_digest, layer_digest
        )
        allowed = {
            "CVE-2026-42792",
            "CVE-2026-49759",
            "CVE-2026-55737",
            "CVE-2026-55952",
            "CVE-2026-55953",
            "CVE-2026-58227",
            "CVE-2026-59250",
            "CVE-2026-59251",
        }
        vex_path = "/private/evidence/rabbitmq-legacy-source.openvex.json"
        vex_policy = json.loads(
            (ROOT / "deploy/rabbitmq/legacy-source-otp26.vex-policy.json").read_text()
        )
        vex_document = legacy_vex.materialize(vex_policy, digest)
        legacy_vex.validate_materialized(vex_document, vex_policy, digest)
        expected_source_tags = [legacy_vex.product_reference(digest)]
        report["source"]["target"]["tags"] = expected_source_tags
        report["descriptor"]["configuration"]["name"] = (
            "backupsheep-rabbitmq-legacy-source"
        )
        report["descriptor"]["configuration"]["vex-documents"] = [vex_path]
        report["descriptor"]["configuration"]["ignore"].extend(
            ({"vex-status": "not_affected"}, {"vex-status": "fixed"})
        )
        report["ignoredMatches"] = [
            {
                "vulnerability": {"id": vulnerability, "severity": "High"},
                "artifact": {
                    "name": "erlang",
                    "version": "26.2.5.21",
                    "type": "binary",
                    "purl": "pkg:generic/erlang@26.2.5.21",
                },
                "appliedIgnoreRules": [
                    {"namespace": "vex", "vex-status": "not_affected"}
                ],
            }
            for vulnerability in sorted(allowed)
        ]
        verifier._validate_grype_report(
            report,
            "legacy-source",
            digest,
            "0.116.1",
            {"HIGH", "CRITICAL"},
            "legacy Grype report",
            self.grype_lock,
            allowed_ignored=allowed,
            expected_vex_document=vex_path,
            expected_source_tags=expected_source_tags,
            expected_name="backupsheep-rabbitmq-legacy-source",
        )
        report["source"]["target"]["tags"] = [
            "backupsheep-rabbitmq-legacy-source:manifest-" + "f" * 64
        ]
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "exact VEX product tag"
        ):
            verifier._validate_grype_report(
                report,
                "legacy-source",
                digest,
                "0.116.1",
                {"HIGH", "CRITICAL"},
                "legacy Grype report",
                self.grype_lock,
                allowed_ignored=allowed,
                expected_vex_document=vex_path,
                expected_source_tags=expected_source_tags,
                expected_name="backupsheep-rabbitmq-legacy-source",
            )
        report["source"]["target"]["tags"] = expected_source_tags
        report["descriptor"]["configuration"]["name"] = "attacker-controlled"
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "unauthorized Grype source name"
        ):
            verifier._validate_grype_report(
                report,
                "legacy-source",
                digest,
                "0.116.1",
                {"HIGH", "CRITICAL"},
                "legacy Grype report",
                self.grype_lock,
                allowed_ignored=allowed,
                expected_vex_document=vex_path,
                expected_source_tags=expected_source_tags,
                expected_name="backupsheep-rabbitmq-legacy-source",
            )
        report["descriptor"]["configuration"]["name"] = (
            "backupsheep-rabbitmq-legacy-source"
        )
        report["ignoredMatches"][0]["artifact"]["purl"] = (
            "pkg:generic/erlang@26.2.5.20"
        )
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "unauthorized ignored Grype finding"
        ):
            verifier._validate_grype_report(
                report,
                "legacy-source",
                digest,
                "0.116.1",
                {"HIGH", "CRITICAL"},
                "legacy Grype report",
                self.grype_lock,
                allowed_ignored=allowed,
                expected_vex_document=vex_path,
                expected_source_tags=expected_source_tags,
                expected_name="backupsheep-rabbitmq-legacy-source",
            )

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

    def test_image_signature_output_is_exactly_one_digest_bound_record(self):
        digest = "sha256:" + "a" * 64
        record = {
            "critical": {"image": {"docker-manifest-digest": digest}}
        }
        verifier._require_one_verified_signature(json.dumps([record]), digest=digest)
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "exactly one verified image signature"
        ):
            verifier._require_one_verified_signature(
                json.dumps([record, record]), digest=digest
            )
        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "does not bind exact digest"
        ):
            verifier._require_one_verified_signature(
                json.dumps([record]), digest="sha256:" + "b" * 64
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
        self.assertEqual(
            (temporary / "bin" / "empty-actionlint.yaml").read_text(encoding="utf-8"),
            "{}\n",
        )
        self.assertEqual(
            stat.S_IMODE(
                (temporary / "bin" / "empty-actionlint.yaml").stat().st_mode
            ),
            0o600,
        )
        self.assertEqual(
            (temporary / "bin" / "empty-bandit.ini").read_text(encoding="utf-8"),
            "[bandit]\n",
        )
        self.assertEqual(
            (temporary / "bin" / "empty-bandit.yaml").read_text(encoding="utf-8"),
            "{}\n",
        )
        self.assertEqual(
            stat.S_IMODE(
                (temporary / "bin" / "empty-bandit.ini").stat().st_mode
            ),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(
                (temporary / "bin" / "empty-bandit.yaml").stat().st_mode
            ),
            0o600,
        )
        self.assertEqual(stat.S_IMODE((temporary / "bin" / "empty-syft.yaml").stat().st_mode), 0o600)
        self.assertEqual(
            (temporary / "bin" / "empty-grype.yaml").read_text(encoding="utf-8"),
            "{}\n",
        )
        self.assertEqual(
            stat.S_IMODE((temporary / "bin" / "empty-grype.yaml").stat().st_mode),
            0o600,
        )
        self.assertEqual(
            (temporary / "bin" / "empty-trivy-secret.yaml").read_text(encoding="utf-8"),
            "{}\n",
        )
        self.assertEqual(
            stat.S_IMODE(
                (temporary / "bin" / "empty-trivy-secret.yaml").stat().st_mode
            ),
            0o600,
        )
        self.assertEqual(
            (temporary / "bin" / "strict-trivy-secret.yaml").read_text(
                encoding="utf-8"
            ),
            "disable-allow-rules:\n"
            "  - dist-info\n"
            "  - tests\n"
            "  - examples\n"
            "  - vendor\n"
            "  - usr-dirs\n"
            "  - locale-dir\n"
            "  - markdown\n"
            "  - node.js\n"
            "  - golang\n"
            "  - python\n"
            "  - rubygems\n"
            "  - wordpress\n"
            "  - anaconda-log\n"
            "skip-patterns: []\n",
        )
        self.assertEqual(
            stat.S_IMODE(
                (temporary / "bin" / "strict-trivy-secret.yaml").stat().st_mode
            ),
            0o600,
        )

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
        for name, image in self.manifest["images"].items():
            registry[image["official_reference"]] = indexes[name]
        for name in initially_present:
            image = self.manifest["images"][name]
            registry[f"{image['official_repository']}:{self.tag}"] = indexes[name]
        copies = []

        def fake_oras(_oras, arguments):
            if arguments[:2] == ["manifest", "fetch"]:
                output = Path(arguments[arguments.index("--output") + 1])
                reference = arguments[-1]
                payload = registry.get(reference)
                if payload is None:
                    raise verifier.ReleaseVerificationError(f"missing test reference {reference}")
                output.write_bytes(payload)
                return ""
            if arguments[:2] == ["repo", "tags"]:
                repository = arguments[-1]
                prefix = f"{repository}:"
                tags = sorted(
                    reference.removeprefix(prefix)
                    for reference in registry
                    if reference.startswith(prefix)
                )
                return json.dumps({"tags": tags})
            if arguments[0] == "cp":
                destination = arguments[-1]
                copies.append(destination)
                image_name = next(
                    name
                    for name, image in self.manifest["images"].items()
                    if destination.startswith(f"{image['official_repository']}:")
                    or destination.startswith(f"{image['quarantine_repository']}:")
                )
                image = self.manifest["images"][image_name]
                registry[destination] = indexes[image_name]
                digest_reference = (
                    image["official_reference"]
                    if destination.startswith(f"{image['official_repository']}:")
                    else image["quarantine_reference"]
                )
                registry[digest_reference] = indexes[image_name]
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
                f"{self.manifest['images']['rabbitmq']['official_repository']}:{self.tag}",
                f"{self.manifest['images']['rabbitmq-upgrade']['official_repository']}:{self.tag}",
            ],
        )

    def test_exact_completed_release_is_idempotent(self):
        _registry, copies, fake_oras = self._registry(set(self.manifest["images"]))
        with mock.patch.object(promoter, "_oras", side_effect=fake_oras):
            promoter.promote(self.policy, self.manifest, self.artifacts, "oras")
        self.assertEqual(copies, [])

    def test_masked_registry_not_found_error_is_never_tag_absence(self):
        result = subprocess.CompletedProcess(
            ["oras"],
            1,
            stdout="",
            stderr="404 Not Found: authorization denied",
        )
        with mock.patch.object(subprocess, "run", return_value=result), self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "ORAS failed closed"
        ):
            promoter._oras("oras", ["repo", "tags", "--format", "json", "ghcr.io/example/image"])

    def test_tag_inventory_is_strict_bounded_json(self):
        invalid_documents = (
            "",
            "not-json",
            '{"tags":[],"unknown":true}',
            '{"tags":[],"tags":["v1.2.3"]}',
            '{"tags":["v1.2.3","v1.2.3"]}',
            '{"tags":["bad/tag"]}',
        )
        for document in invalid_documents:
            with self.subTest(document=document), mock.patch.object(
                promoter, "_oras", return_value=document
            ), self.assertRaises(verifier.ReleaseVerificationError):
                promoter._repository_tags("oras", "ghcr.io/example/image")

    def test_invalid_tag_inventory_blocks_every_promotion_write(self):
        _registry, copies, fake_oras = self._registry(set())

        def malformed_inventory(oras, arguments):
            if arguments[:2] == ["repo", "tags"]:
                return '{"tags":["v1.2.3","v1.2.3"]}'
            return fake_oras(oras, arguments)

        with mock.patch.object(
            promoter, "_oras", side_effect=malformed_inventory
        ), self.assertRaisesRegex(verifier.ReleaseVerificationError, "duplicate tags"):
            promoter.promote(self.policy, self.manifest, self.artifacts, "oras")
        self.assertEqual(copies, [])


class LocalOCIReleaseEvidenceTests(ReleaseFixtureMixin, TestCase):
    _registry = ReleasePromotionRecoveryTests._registry

    def test_layout_reader_rejects_links_and_unexpected_members(self):
        layout = self.temporary_directory / "layout"
        (layout / "blobs" / "sha256").mkdir(parents=True)
        (layout / "index.json").write_text("{}")
        (layout / "oci-layout").write_text("{}")
        (layout / "blobs" / "sha256" / ("a" * 64)).symlink_to(layout / "index.json")
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "unsafe member"):
            collector._OCILayoutDirectory(layout)

        archive = self.temporary_directory / "layout.tar"
        with tarfile.open(archive, "w") as output:
            link = tarfile.TarInfo("blobs/sha256/" + "b" * 64)
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            output.addfile(link)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "unsafe member"):
            collector._OCILayoutArchive(archive)

    def test_local_scanner_reports_are_bound_to_exact_child_manifest(self):
        image = "egress"
        platform = "linux/amd64"
        child_digest = self.platform_digests[image][platform]
        config_digest = "sha256:" + "c" * 64
        layer_digest = "sha256:" + "d" * 64
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config_digest, "size": 123},
            "layers": [{"digest": layer_digest, "size": 456}],
        }
        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        actual_child = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        index = json.loads((self.artifacts / "oci" / f"{image}.index.json").read_text())
        descriptor = next(
            item
            for item in index["manifests"]
            if item.get("platform") == {"os": "linux", "architecture": "amd64"}
        )
        descriptor["digest"] = actual_child
        descriptor["size"] = len(manifest_bytes)
        attestation = next(
            item
            for item in index["manifests"]
            if item.get("annotations", {}).get("vnd.docker.reference.digest") == child_digest
        )
        attestation["annotations"]["vnd.docker.reference.digest"] = actual_child
        index_path = self.temporary_directory / "index.json"
        self._json(index_path, index)
        syft_path = self.temporary_directory / "syft.json"
        trivy_path = self.temporary_directory / "trivy.json"
        grype_path = self.temporary_directory / "grype.json"
        self._json(
            syft_path,
            {
                "source": {
                    "type": "image",
                    "metadata": {
                        "userInput": "local-layout",
                        "manifestDigest": actual_child,
                        "imageID": config_digest,
                        "manifest": base64.b64encode(manifest_bytes).decode(),
                    },
                }
            },
        )
        self._json(
            trivy_path,
            {
                "ArtifactName": "local-layout",
                "Metadata": {
                    "ImageID": config_digest,
                    "Layers": [{"Digest": layer_digest}],
                },
            },
        )
        self._json(
            grype_path,
            self._grype_report(
                "local-layout", manifest_bytes, config_digest, layer_digest
            ),
        )
        normalizer.normalize(
            policy=self.policy,
            index_path=index_path,
            image_name=image,
            platform=platform,
            syft_path=syft_path,
            trivy_path=trivy_path,
            grype_path=grype_path,
        )
        expected = f"{self.policy['images'][image]['quarantine_repository']}@{actual_child}"
        self.assertEqual(json.loads(syft_path.read_text())["source"]["metadata"]["userInput"], expected)
        self.assertEqual(json.loads(trivy_path.read_text())["ArtifactName"], expected)
        self.assertNotEqual(actual_child, child_digest)

        tampered = json.loads(trivy_path.read_text())
        tampered["Metadata"]["Layers"][0]["Digest"] = "sha256:" + "e" * 64
        self._json(trivy_path, tampered)
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "layers do not match"):
            normalizer.normalize(
                policy=self.policy,
                index_path=index_path,
                image_name=image,
                platform=platform,
                syft_path=syft_path,
                trivy_path=trivy_path,
                grype_path=grype_path,
            )

    def test_consumer_verifier_scan_normalization_uses_only_exact_policy_children(self):
        platform = "linux/amd64"
        config_digest = "sha256:" + "e" * 64
        layer_digest = "sha256:" + "f" * 64
        child_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config_digest, "size": 123},
            "layers": [{"digest": layer_digest, "size": 456}],
        }
        manifest_bytes = json.dumps(child_manifest, separators=(",", ":")).encode()
        child_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        policy = copy.deepcopy(self.policy)
        identity = policy["consumer"]["cosign_image"]["platforms"][platform]
        identity["manifest_digest"] = child_digest
        identity["config_digest"] = config_digest
        reference = f"{policy['consumer']['cosign_image']['repository']}@{child_digest}"

        syft_path = self.temporary_directory / "consumer-verifier.syft.json"
        trivy_path = self.temporary_directory / "consumer-verifier.trivy.json"
        grype_path = self.temporary_directory / "consumer-verifier.grype.json"
        self._json(
            syft_path,
            {
                "source": {
                    "type": "image",
                    "metadata": {
                        "userInput": "registry:" + reference,
                        "manifestDigest": child_digest,
                        "imageID": config_digest,
                        "manifest": base64.b64encode(manifest_bytes).decode(),
                    },
                }
            },
        )
        self._json(
            trivy_path,
            {
                "ArtifactName": reference,
                "Metadata": {
                    "ImageID": config_digest,
                    "Layers": [{"Digest": layer_digest}],
                },
            },
        )
        self._json(
            grype_path,
            self._grype_report(reference, manifest_bytes, config_digest, layer_digest),
        )
        normalizer.normalize(
            policy=policy,
            index_path=None,
            image_name="release-verifier",
            platform=platform,
            syft_path=syft_path,
            trivy_path=trivy_path,
            grype_path=grype_path,
        )
        self.assertEqual(
            json.loads(syft_path.read_text())["source"]["metadata"]["userInput"],
            reference,
        )

        with self.assertRaisesRegex(
            verifier.ReleaseVerificationError, "must not accept a release OCI index"
        ):
            normalizer.normalize(
                policy=policy,
                index_path=self.artifacts / "oci" / "app.index.json",
                image_name="release-verifier",
                platform=platform,
                syft_path=syft_path,
                trivy_path=trivy_path,
                grype_path=grype_path,
            )

    def test_local_layouts_are_pushed_only_to_commit_bound_quarantine_tags(self):
        layouts = self.temporary_directory / "layouts"
        layouts.mkdir()
        quarantine_tag = f"candidate-{self.commit}-123-1"
        for image_name, image in self.manifest["images"].items():
            layout = layouts / image_name
            blob_directory = layout / "blobs" / "sha256"
            blob_directory.mkdir(parents=True)
            index_bytes = (self.artifacts / image["oci_index"]["file"]).read_bytes()
            (blob_directory / image["digest"].removeprefix("sha256:")).write_bytes(index_bytes)
            self._json(
                layout / "index.json",
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.index.v1+json",
                            "digest": image["digest"],
                            "size": len(index_bytes),
                            "annotations": {
                                "org.opencontainers.image.ref.name": quarantine_tag,
                                "io.containerd.image.name": (
                                    f"{image['quarantine_repository']}:{quarantine_tag}"
                                ),
                            },
                        }
                    ],
                },
            )
            self._json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})

        _registry, copies, fake_oras = self._registry(set())
        with mock.patch.object(quarantine_pusher, "_oras", side_effect=fake_oras), mock.patch.object(
            promoter, "_oras", side_effect=fake_oras
        ):
            quarantine_pusher.push(
                policy=self.policy,
                manifest=self.manifest,
                artifacts_dir=self.artifacts,
                layouts_dir=layouts,
                quarantine_tag=quarantine_tag,
                oras="oras",
            )
        self.assertEqual(len(copies), len(self.manifest["images"]))
        self.assertTrue(all(destination.endswith(f":{quarantine_tag}") for destination in copies))
        self.assertTrue(all("-quarantine:" in destination for destination in copies))

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
        cls.supply_chain_workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        cls.policy = json.loads((ROOT / "deploy" / "release-policy.json").read_text())

    def test_every_action_is_pinned_to_a_full_commit(self):
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, flags=re.MULTILINE)
        self.assertGreaterEqual(len(actions), 10)
        local_workflows = [action for action in actions if action.startswith("./")]
        self.assertEqual(
            local_workflows,
            ["./.github/workflows/supply-chain-security.yml"],
        )
        for action in (action for action in actions if not action.startswith("./")):
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_python_release_subprocess_timeout_kills_descendant_group(self):
        with tempfile.TemporaryDirectory(
            prefix="backupsheep-python-tool-tree-"
        ) as directory:
            descendant = Path(directory) / "descendant.pid"
            with self.assertRaises(subprocess.TimeoutExpired):
                release_subprocess.run_text(
                    [
                        "sh",
                        "-c",
                        'trap "" TERM; printf "%s\\n" "$$" > "$1"; sleep 30',
                        "child",
                        str(descendant),
                    ],
                    environment={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    timeout=1,
                )
            descendant_pid = int(descendant.read_text(encoding="ascii").strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(descendant_pid, 0)

    def test_every_release_checkout_is_detached_at_the_event_sha(self):
        self.assertEqual(
            self.workflow.count(
                "uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
            ),
            4,
        )
        self.assertEqual(self.workflow.count("ref: ${{ github.sha }}"), 4)
        build_checkout = self.workflow.split(
            "      - name: Check out the exact tagged commit\n", 1
        )[1].split("      - name: Validate immutable release inputs\n", 1)[0]
        self.assertIn("fetch-depth: 0", build_checkout)
        self.assertIn("persist-credentials: false", build_checkout)

    def test_release_and_privileged_jobs_require_the_fresh_exact_main_tip(self):
        self.assertNotIn("merge-base --is-ancestor", self.workflow)
        self.assertEqual(
            self.workflow.count(
                "git fetch --no-tags --force origin \\\n"
                "            +refs/heads/main:refs/remotes/origin/main"
            ),
            3,
        )
        self.assertEqual(self.workflow.count('test "$SOURCE_COMMIT" = "$MAIN_TIP"'), 3)

    def test_hostile_candidate_artifact_never_enters_protected_or_oidc_jobs(self):
        protected = self.workflow.split("  protected_rescan:", 1)[1].split(
            "  sign_promote:", 1
        )[0]
        signing = self.workflow.split("  sign_promote:", 1)[1].split(
            "  publish_evidence:", 1
        )[0]
        ordered = (
            "Rebuild the protected application from the exact remote commit",
            "Rebuild the protected PostgreSQL image from the exact remote commit",
            "Rebuild the protected egress guard from the exact remote commit",
            "Rebuild protected RabbitMQ from the exact remote commit",
            "Rebuild the protected RabbitMQ upgrade helper from the exact remote commit",
            "Extract protected indexes and BuildKit provenance from rebuilt layouts",
            "Regenerate protected migration transition evidence from the exact app child",
            "Prepare fresh protected scanner databases",
            "Generate protected SBOMs and scans from every rebuilt platform",
            "Generate every protected verifier catalog and scan",
            "Build the protected manifest and exact signer inventory",
            "scripts/protect_release_evidence.py export",
            "Push exact verified local layouts to quarantine after approval",
            "Retain only the protected evidence for the OIDC signing job",
        )
        positions = [protected.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("id-token: write", protected)
        self.assertNotIn("actions/download-artifact", protected)
        self.assertNotIn("signed-release-candidate", protected)
        self.assertNotIn("candidate-download", protected)
        self.assertNotIn("release-candidate", protected)
        self.assertNotIn("needs.build_scan.outputs", protected)
        self.assertNotIn("release-candidate/release-layouts", protected)
        self.assertIn(
            "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
            protected,
        )
        self.assertIn(
            "tonistiigi/binfmt:qemu-v10.0.4@sha256:"
            "8f58e6214f4cc9dc83ce8f5acad1ece508eb6b20e696a8c1e9f274481982c541",
            protected,
        )
        self.assertIn(
            "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
            protected,
        )
        self.assertIn("version: v0.29.1", protected)
        self.assertIn(
            "moby/buildkit:v0.26.2@sha256:"
            "de10faf919fc71ba4eb1dd7bd6449566d012b0c9436b1c61bfee21d621b009aa",
            protected,
        )
        self.assertEqual(protected.count("docker/build-push-action@"), 6)
        self.assertEqual(
            protected.count(
                "context: https://github.com/${{ github.repository }}.git#${{ github.sha }}"
            ),
            6,
        )
        self.assertEqual(protected.count("platforms: linux/amd64,linux/arm64"), 5)
        self.assertEqual(protected.count("pull: true"), 5)
        self.assertEqual(protected.count("push: false"), 5)
        self.assertEqual(protected.count("outputs: type=oci,dest="), 5)
        for image in ("app", "postgres", "egress", "rabbitmq", "rabbitmq-upgrade"):
            self.assertIn(
                "outputs: type=oci,dest=${{ github.workspace }}/protected-build/"
                f"release-layouts/{image},tar=false",
                protected,
            )
        self.assertEqual(protected.count("no-cache: true"), 5)
        self.assertEqual(protected.count("provenance: mode=max,version=v1,builder-id="), 5)
        self.assertEqual(protected.count("scripts/collect_release_evidence.py"), 5)
        self.assertEqual(protected.count("scripts/collect_release_transition.py"), 1)
        self.assertIn('--output "syft-json=$syft_report"', protected)
        self.assertIn('--output "spdx-json=$spdx_report"', protected)
        self.assertIn('--output "cyclonedx-json=$cdx_report"', protected)
        manifest_step = protected.split(
            "      - name: Build the protected manifest and exact signer inventory\n", 1
        )[1].split("\n      - name: Authenticate for quarantine write only", 1)[0]
        for image, step_id in (
            ("APP", "app"),
            ("POSTGRES", "postgres"),
            ("EGRESS", "egress"),
            ("RABBITMQ", "rabbitmq"),
            ("RABBITMQ_UPGRADE", "rabbitmq-upgrade"),
        ):
            self.assertIn(
                f"{image}_DIGEST: ${{{{ steps.protected-build-{step_id}.outputs.digest }}}}",
                manifest_step,
            )
        self.assertEqual(manifest_step.count("steps.protected-build-"), 5)
        self.assertNotIn("needs.build_scan", manifest_step)
        self.assertIn("path: protected-release-artifacts", protected)
        self.assertNotIn("path: candidate-download/release-artifacts", protected)
        self.assertIn("protected-release-evidence-${{ github.run_id }}", signing)
        self.assertNotIn("signed-release-candidate-${{ github.run_id }}", signing)
        self.assertNotIn("candidate-download/release-layouts", signing)
        self.assertIn("scripts/protect_release_evidence.py verify", signing)
        self.assertIn("Create the private signer-only bundle directory", signing)
        self.assertIn('test ! -e "$ARTIFACT_DIR/bundles"', signing)
        self.assertIn('test ! -L "$ARTIFACT_DIR/bundles"', signing)
        self.assertIn('install -d -m 0700 "$ARTIFACT_DIR/bundles"', signing)
        self.assertLess(
            signing.index("Strictly verify protected evidence"),
            signing.index("Create the private signer-only bundle directory"),
        )
        self.assertLess(
            signing.index("Create the private signer-only bundle directory"),
            signing.index("Authenticate for signatures and promotion"),
        )
        self.assertLess(
            signing.index("Re-fetch and verify every quarantine index"),
            signing.index("Sign and attest quarantine digests"),
        )

    def test_release_repeats_the_exact_security_regression_before_building(self):
        self.assertIn("on:\n  workflow_call:\n", self.supply_chain_workflow)
        regression_job = self.workflow.split("  release_regression:", 1)[1].split(
            "  build_scan:", 1
        )[0]
        self.assertIn(
            "uses: ./.github/workflows/supply-chain-security.yml", regression_job
        )
        self.assertIn("contents: read", regression_job)
        self.assertNotIn("id-token: write", regression_job)
        self.assertNotIn("packages: write", regression_job)
        build_job_header = self.workflow.split("  build_scan:", 1)[1].split(
            "    steps:", 1
        )[0]
        self.assertIn("needs: release_regression", build_job_header)

    def test_signed_release_regression_includes_pinned_static_analysis(self):
        static_job = self.supply_chain_workflow.split(
            "  static-python-security:", 1
        )[1].split("  rabbitmq-arm64-migration:", 1)[0]
        self.assertIn("deploy/static-analysis-requirements.lock", static_job)
        self.assertIn("--require-hashes", static_job)
        self.assertIn("--only-binary=:all:", static_job)
        self.assertIn("actionlint", static_job)
        self.assertIn("--ignore-nosec", static_job)
        self.assertIn("empty-bandit.ini", static_job)
        self.assertIn("empty-bandit.yaml", static_job)
        self.assertIn("python -m bandit -q -r apps backupsheep scripts", static_job)
        self.assertIn("-x apps/tests", static_job)
        self.assertIn("-f json -ll", static_job)
        self.assertIn("scripts/validate_static_security.py", static_job)
        self.assertIn("deploy/static-analysis-policy.json", static_job)
        self.assertIn("uses: ./.github/workflows/supply-chain-security.yml", self.workflow)

    def test_git_checkout_concealment_attack_runs_on_the_host_not_in_the_runtime_image(self):
        test_name = (
            "apps.tests.test_installer_security.InstallerSecurityContractTests."
            "test_signed_consumer_attests_exact_clean_source_checkout_even_with_skip_worktree"
        )
        dependency_job = self.supply_chain_workflow.split(
            "  dependency-and-deployment-checks:", 1
        )[1].split("  static-python-security:", 1)[0]
        self.assertIn("Attack signed-release checkout index concealment", dependency_job)
        attack_step = dependency_job.split(
            "      - name: Attack signed-release checkout index concealment\n", 1
        )[1].split("\n      - name:", 1)[0]
        self.assertIn("set -euo pipefail", attack_step)
        self.assertIn("command -v git >/dev/null", attack_step)
        self.assertIn("git --version >/dev/null", attack_step)
        self.assertEqual(attack_step.count(test_name), 1)
        self.assertLess(attack_step.index("command -v git"), attack_step.index(test_name))
        self.assertIn(
            "Unexpected Git executable in the production application image",
            self.supply_chain_workflow,
        )

    def test_release_is_dormant_and_signing_permissions_are_separated(self):
        self.assertIn("vars.BACKUPSHEEP_SIGNED_RELEASES_ENABLED == 'true'", self.workflow)
        self.assertIn("github.repository == 'bilal414/backupsheep'", self.workflow)
        self.assertIn("environment: signed-release", self.workflow)
        self.assertNotIn("workflow_dispatch", self.workflow)
        build_job = self.workflow.split("  build_scan:", 1)[1].split(
            "  protected_rescan:", 1
        )[0]
        self.assertNotIn("id-token: write", build_job)
        self.assertNotIn("packages: write", build_job)
        self.assertNotIn("docker/login-action", build_job)
        self.assertEqual(build_job.count("push: false"), 5)
        self.assertEqual(build_job.count("type=oci,dest="), 5)
        self.assertEqual(build_job.count("tar=false"), 5)
        self.assertIn("scripts/normalize_local_scan_evidence.py", build_job)
        protected_job = self.workflow.split("  protected_rescan:", 1)[1].split(
            "  sign_promote:", 1
        )[0]
        self.assertIn("environment: signed-release", protected_job)
        self.assertIn("packages: write", protected_job)
        self.assertNotIn("id-token: write", protected_job)
        self.assertIn("scripts/push_quarantine_layouts.py", protected_job)
        self.assertIn("scripts/build_release_manifest.py", protected_job)
        self.assertNotIn("scripts/rebuild_protected_release_manifest.py", protected_job)
        self.assertIn("Generate protected SBOMs and scans", protected_job)
        self.assertIn("Generate every protected verifier catalog", protected_job)
        self.assertNotIn("actions/download-artifact", protected_job)
        signing_job = self.workflow.split("  sign_promote:", 1)[1].split(
            "  publish_evidence:", 1
        )[0]
        self.assertIn("needs: protected_rescan", signing_job)
        self.assertIn("id-token: write", signing_job)
        self.assertIn("packages: write", signing_job)
        self.assertNotIn("release-layouts", signing_job)
        self.assertNotIn("--tool trivy", signing_job)
        self.assertNotIn("--tool grype", signing_job)
        self.assertNotIn("push_quarantine_layouts.py", signing_job)
        self.assertIn("scripts/verify_quarantine_indexes.py", signing_job)
        self.assertLess(
            signing_job.index("verify_quarantine_indexes.py"),
            signing_job.index("Sign and attest quarantine digests"),
        )
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
        self.assertIn("backupsheep-rabbitmq-quarantine:candidate-", self.workflow)
        self.assertIn("backupsheep-rabbitmq-upgrade-quarantine:candidate-", self.workflow)
        self.assertNotIn("backupsheep:candidate-", self.workflow)
        self.assertNotIn("backupsheep-postgres:candidate-", self.workflow)
        self.assertNotIn("backupsheep-egress:candidate-", self.workflow)
        self.assertNotIn("backupsheep-rabbitmq:candidate-", self.workflow)
        self.assertNotIn("backupsheep-rabbitmq-upgrade:candidate-", self.workflow)
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
        self.assertEqual(self.workflow.count("provenance: mode=max,version=v1,builder-id="), 10)
        self.assertEqual(
            self.workflow.count("context: https://github.com/${{ github.repository }}.git#${{ github.sha }}"),
            12,
        )
        self.assertIn("scripts/collect_release_evidence.py", self.workflow)
        self.assertIn("--statement \"$ARTIFACT_DIR/$statement\"", self.workflow)
        self.assertNotIn("mobyproject.org/buildkit@v1", self.workflow)

    def test_transition_migrations_are_emitted_by_the_exact_built_child_and_archived(self):
        app_build = self.workflow.index("Build application candidate from exact remote commit")
        materialize = self.workflow.index(
            "Materialize the exact amd64 application child for migration inventory"
        )
        collect = self.workflow.index("Collect raw OCI indexes and actual BuildKit provenance")
        transition = self.workflow.index(
            "Generate the exact transactional migration transition evidence"
        )
        manifest = self.workflow.index("Build and verify the digest-bound candidate manifest")
        archive = self.workflow.index(
            "Create and verify the complete signed publication"
        )
        self.assertLess(app_build, materialize)
        self.assertLess(materialize, collect)
        self.assertLess(collect, transition)
        self.assertLess(transition, manifest)
        self.assertLess(manifest, archive)
        transition_step = self.workflow[transition:manifest]
        self.assertIn("scripts/collect_release_transition.py", transition_step)
        collector_source = (ROOT / "scripts/collect_release_transition.py").read_text()
        self.assertIn('"--network",\n            "none"', collector_source)
        self.assertIn('"--read-only"', collector_source)
        self.assertIn("transition/reviewed-policy.json", self.workflow[transition:archive])
        self.assertIn("transition/django-migrations.json", self.workflow[transition:archive])
        archive_step = self.workflow[archive:]
        self.assertIn("grep -Fx './transition/reviewed-policy.json'", archive_step)
        self.assertIn("grep -Fx './transition/django-migrations.json'", archive_step)

    def test_scanners_cannot_auto_load_repository_config_or_ignore_files(self):
        self.assertGreaterEqual(self.workflow.count("env -i"), 2)
        self.assertIn('--config "$TOOL_DIR/empty-trivy.yaml"', self.workflow)
        self.assertIn('--ignorefile "$TOOL_DIR/empty-trivy.ignore"', self.workflow)
        self.assertIn('--config "$TOOL_DIR/empty-syft.yaml"', self.workflow)
        self.assertIn('--config "$TOOL_DIR/empty-grype.yaml"', self.workflow)
        self.assertIn("--list-all-pkgs", self.workflow)
        self.assertIn("--severity HIGH,CRITICAL", self.workflow)
        self.assertIn("--exit-code 1", self.workflow)
        self.assertNotIn("--ignore-unfixed", self.workflow)
        build_job = self.workflow.split("  build_scan:", 1)[1].split(
            "  protected_rescan:", 1
        )[0]
        self.assertNotIn("--vex", build_job)

    def test_every_release_scan_uses_one_exact_offline_grype_database(self):
        database = self.policy["vulnerability_policy"]["secondary_database"]
        lock_path = ROOT / database["lock_path"]
        self.assertEqual(
            "sha256:" + hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            database["lock_sha256"],
        )
        build_job = self.workflow.split("  build_scan:", 1)[1].split(
            "  protected_rescan:", 1
        )[0]
        self.assertIn("--tool grype", build_job)
        self.assertIn("^Version: +0\\.116\\.1$", build_job)
        self.assertIn("Prepare the exact reviewed Grype vulnerability database", build_job)
        self.assertIn("scripts/prepare_grype_db.py prepare", build_job)
        self.assertEqual(build_job.count("scripts/prepare_grype_db.py verify"), 3)
        self.assertEqual(build_job.count('--config "$TOOL_DIR/empty-grype.yaml"'), 2)
        self.assertEqual(build_job.count("--fail-on high"), 2)
        self.assertIn('GRYPE_DB_AUTO_UPDATE=false', build_job)
        self.assertIn('GRYPE_CHECK_FOR_APP_UPDATE=false', build_job)
        self.assertIn('"$ARTIFACT_DIR/vulnerability/grype-db-lock.json"', build_job)
        self.assertIn('"$ARTIFACT_DIR/vulnerability/grype-db-evidence.json"', build_job)
        self.assertIn('--grype "$ARTIFACT_DIR/scans/$image-$platform_slug.grype.json"', build_job)
        self.assertIn('--grype "$grype_report"', build_job)
        self.assertNotIn("--vex", build_job)

    def test_every_release_scan_uses_one_exact_offline_trivy_database(self):
        database = self.policy["vulnerability_policy"]["database"]
        lock_path = ROOT / database["lock_path"]
        self.assertEqual(
            "sha256:" + hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            database["lock_sha256"],
        )
        build_job = self.workflow.split("  build_scan:", 1)[1].split(
            "  protected_rescan:", 1
        )[0]
        prepare_position = build_job.index(
            "Prepare the exact reviewed Trivy vulnerability database"
        )
        image_scan_position = build_job.index(
            "Scan exact child digests and generate complete SBOMs"
        )
        verifier_scan_position = build_job.index(
            "Freshly scan the separately bootstrapped consumer verifier"
        )
        bind_position = build_job.index(
            "Bind private scanner state to runner scratch space"
        )
        build_job_environment = build_job.split("    steps:", 1)[0]
        self.assertLess(prepare_position, image_scan_position)
        self.assertLess(image_scan_position, verifier_scan_position)
        self.assertLess(bind_position, prepare_position)
        self.assertNotIn("${{ runner.temp }}", build_job_environment)
        self.assertIn(
            '"$RUNNER_TEMP/backupsheep-release-trivy-cache" >>"$GITHUB_ENV"',
            build_job,
        )
        self.assertIn(
            '"$RUNNER_TEMP/backupsheep-release-trivy-db-evidence.json" '
            '>>"$GITHUB_ENV"',
            build_job,
        )
        self.assertIn(
            '"$RUNNER_TEMP/backupsheep-release-trivy-home" >>"$GITHUB_ENV"',
            build_job,
        )
        self.assertEqual(build_job.count("--skip-db-update"), 2)
        self.assertEqual(build_job.count("--skip-java-db-update"), 2)
        self.assertEqual(build_job.count("--skip-check-update"), 2)
        self.assertEqual(build_job.count("--offline-scan"), 2)
        self.assertEqual(build_job.count('--cache-dir "$TRIVY_CACHE_DIR"'), 6)
        self.assertEqual(
            build_job.count("python3 scripts/prepare_trivy_db.py verify"), 3
        )
        self.assertIn(
            '"$ARTIFACT_DIR/vulnerability/trivy-db-lock.json"', build_job
        )
        self.assertIn(
            '"$ARTIFACT_DIR/vulnerability/trivy-db-evidence.json"', build_job
        )

    def test_evidence_is_retained_and_published_durably(self):
        self.assertGreaterEqual(self.workflow.count("retention-days: 90"), 2)
        self.assertIn("signed-release-evidence.tar.gz", self.workflow)
        self.assertIn("scripts/publish_release_evidence.py", self.workflow)
        self.assertIn("tar --sort=name", self.workflow)
        self.assertNotIn("chmod 0644", self.workflow)

    def test_verifier_is_a_separate_exact_consumer_trust_root_and_is_freshly_scanned(self):
        self.assertEqual(tuple(self.policy["images"]), verifier.RELEASE_IMAGE_NAMES)
        pinned = self.policy["consumer"]["cosign_image"]
        self.assertEqual(
            pinned["reference"],
            f"{pinned['repository']}@{pinned['index_digest']}",
        )
        self.assertEqual(list(pinned["platforms"]), ["linux/amd64", "linux/arm64"])
        for platform, record in pinned["platforms"].items():
            with self.subTest(platform=platform):
                self.assertRegex(record["manifest_digest"], r"^sha256:[0-9a-f]{64}$")
                self.assertRegex(record["config_digest"], r"^sha256:[0-9a-f]{64}$")

        build_job = self.workflow.split("  build_scan:", 1)[1].split(
            "  protected_rescan:", 1
        )[0]
        verifier_scan = build_job.split(
            "      - name: Freshly scan the separately bootstrapped consumer verifier\n",
            1,
        )[1].split("      - name: Build and verify the digest-bound candidate manifest\n", 1)[0]
        self.assertIn('scan "registry:$reference"', verifier_scan)
        self.assertIn("--image-src remote", verifier_scan)
        self.assertIn("--image release-verifier", verifier_scan)
        self.assertIn("--platform \"$platform\"", verifier_scan)
        self.assertIn("env -i", verifier_scan)
        self.assertNotIn("DOCKER_CONFIG", verifier_scan)
        self.assertNotIn("Dockerfile.release-verifier", self.workflow)
        self.assertNotIn("backupsheep-release-verifier-quarantine", self.workflow)
        protected_job = self.workflow.split("  sign_promote:", 1)[1].split(
            "  publish_evidence:", 1
        )[0]
        self.assertNotIn("backupsheep-release-verifier", protected_job)

    def test_signed_v2_consumer_is_a_durable_pre_execution_release_asset(self):
        consumer = self.policy["consumer"]
        self.assertEqual(
            consumer["consumer_script_filename"],
            "backupsheep-consume-signed-release-v2.sh",
        )
        self.assertEqual(
            consumer["consumer_script_bundle_filename"],
            "backupsheep-consume-signed-release-v2.sigstore.json",
        )
        copy_position = self.workflow.index(
            'install -m 0600 deploy/release/consume-signed-release.sh'
        )
        sign_position = self.workflow.index(
            '--bundle "$ARTIFACT_DIR/backupsheep-consume-signed-release-v2.sigstore.json"'
        )
        publish_position = self.workflow.index(
            '--asset "$PUBLICATION_DIR/backupsheep-consume-signed-release-v2.sh"'
        )
        self.assertLess(copy_position, sign_position)
        self.assertLess(sign_position, publish_position)
        publisher = self.workflow.split("  publish_evidence:", 1)[1]
        self.assertIn("cosign\" verify-blob", publisher)
        self.assertIn(
            '"$PUBLICATION_DIR/backupsheep-consume-signed-release-v2.sh"',
            publisher,
        )

    def test_complete_signed_publication_precedes_semver_promotion(self):
        protected_job = self.workflow.split("  sign_promote:", 1)[1].split(
            "  publish_evidence:", 1
        )[0]
        publication_position = protected_job.index(
            "Create and verify the complete signed publication"
        )
        consumer_signature_position = protected_job.index(
            '--bundle "$ARTIFACT_DIR/backupsheep-consume-signed-release-v2.sigstore.json"'
        )
        archive_position = protected_job.index("tar --sort=name")
        archive_signature_position = protected_job.index(
            '--bundle "$PUBLICATION_DIR/signed-release-evidence.tar.gz.bundle.json"'
        )
        promotion_position = protected_job.index(
            "Publish signed official digests under SemVer tags last"
        )
        upload_position = protected_job.index("Retain signed publication evidence")
        self.assertLess(publication_position, consumer_signature_position)
        self.assertLess(consumer_signature_position, archive_position)
        self.assertLess(archive_position, archive_signature_position)
        self.assertLess(archive_signature_position, promotion_position)
        self.assertLess(promotion_position, upload_position)

    def test_consumer_policy_pins_first_party_cosign_verifier_by_version_and_digest(self):
        self.assertEqual(self.policy["schema_version"], 4)
        reference = self.policy["consumer"]["cosign_image"]["reference"]
        self.assertRegex(
            reference,
            r"^ghcr\.io/bilal414/backupsheep-release-verifier@sha256:[0-9a-f]{64}$",
        )
        consumer_script = (
            ROOT / "deploy/release/consume-signed-release.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(reference, consumer_script)
        self.assertIn("--network none", consumer_script)

    def test_v2_descriptor_is_built_signed_verified_and_published(self):
        consumer = self.policy["consumer"]
        self.assertEqual(
            consumer["descriptor_filename"],
            "backupsheep-release-descriptor-v2.txt",
        )
        self.assertEqual(
            consumer["descriptor_bundle_filename"],
            "backupsheep-release-descriptor-v2.sigstore.json",
        )
        build_position = self.workflow.index("python3 scripts/build_release_descriptor.py")
        sign_position = self.workflow.index(
            '--bundle "$ARTIFACT_DIR/backupsheep-release-descriptor-v2.sigstore.json"'
        )
        verify_position = self.workflow.index(
            '--output "$ARTIFACT_DIR/backupsheep-release-descriptor-v2.txt" \\\n            --verify'
            ,
            sign_position,
        )
        stage_position = self.workflow.index("Stage exact verified indexes")
        publish_position = self.workflow.index(
            '--asset "$PUBLICATION_DIR/backupsheep-release-descriptor-v2.txt"'
        )
        self.assertLess(build_position, sign_position)
        self.assertLess(sign_position, verify_position)
        self.assertLess(verify_position, stage_position)
        self.assertLess(stage_position, publish_position)
        self.assertNotIn("BACKUPSHEEP-SIGNED-RELEASE-V1", self.workflow)
        publisher = self.workflow.split("  publish_evidence:", 1)[1]
        self.assertIn("backupsheep-release-descriptor-v2.sigstore.json", publisher)
