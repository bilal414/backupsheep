import hashlib
import importlib.util
import io
import os
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
IMAGE_SCAN_SPEC = importlib.util.spec_from_file_location(
    "validate_image_scan",
    ROOT / "deploy" / "ci" / "validate-image-scan.py",
)
image_scan = importlib.util.module_from_spec(IMAGE_SCAN_SPEC)
sys.modules[IMAGE_SCAN_SPEC.name] = image_scan
IMAGE_SCAN_SPEC.loader.exec_module(image_scan)


class CISecurityTopologyContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        cls.runner = (
            ROOT / "deploy" / "ci" / "run-security-topology.sh"
        ).read_text(encoding="utf-8")
        cls.override = (
            ROOT / "deploy" / "ci" / "docker-compose.security-topology.yml"
        ).read_text(encoding="utf-8")

    def test_workflow_builds_and_exercises_product_images_and_pinned_pg_fixture(self):
        for expected in (
            'TEST_APP_IMAGE: "backupsheep-ci-app:',
            'TEST_POSTGRES_IMAGE: "backupsheep-ci-postgres:',
            'TEST_LEGACY_POSTGRES_IMAGE: "backupsheep-ci-postgres-legacy:',
            'TEST_EGRESS_IMAGE: "backupsheep-ci-egress:',
            'TEST_RABBITMQ_IMAGE: "backupsheep-ci-rabbitmq:',
            'TEST_RABBITMQ_UPGRADE_IMAGE: "backupsheep-ci-rabbitmq-upgrade:',
            'TEST_RELEASE_VERIFIER_IMAGE: "backupsheep-ci-release-verifier:',
            '--file Dockerfile --tag "$TEST_APP_IMAGE"',
            '--file Dockerfile.postgres --tag "$TEST_POSTGRES_IMAGE"',
            '--file deploy/ci/Dockerfile.postgres-runtime-source',
            '--tag "$TEST_LEGACY_POSTGRES_IMAGE"',
            '--file Dockerfile.egress --tag "$TEST_EGRESS_IMAGE"',
            '--file Dockerfile.rabbitmq --tag "$TEST_RABBITMQ_IMAGE"',
            '--file Dockerfile.rabbitmq-upgrade --tag "$TEST_RABBITMQ_UPGRADE_IMAGE"',
            '--file Dockerfile.release-verifier --tag "$TEST_RELEASE_VERIFIER_IMAGE"',
            'BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION: "1"',
            'BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION: "2"',
            'BACKUPSHEEP_EGRESS_POLICY_GENERATION: "2"',
            "run: deploy/ci/run-security-topology.sh",
            "run: timeout --signal=TERM --kill-after=30s 45m deploy/ci/run-postgres-runtime-migration-e2e.sh",
            'run: deploy/egress/test-policy.sh "$TEST_EGRESS_IMAGE"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.workflow)

    def test_recurring_workflow_scans_exact_images_with_strict_pinned_tools(self):
        gate = self.workflow.split("  application-security-regression:\n", 1)[1]
        job_environment = gate.split("    steps:\n", 1)[0]
        self.assertNotIn("runner.temp", job_environment)
        for expected in (
            "scripts/install_release_tools.py",
            "--tool syft",
            "--tool trivy",
            "1\\.51\\.0",
            "0\\.74\\.0",
            'docker image save --output "$archive" "$image_id"',
            'owner="$(ci_image_ownership_label "$image_id")"',
            '[[ "$owner" == "$TEST_OWNERSHIP_VALUE" ]]',
            'scan "docker-archive:$archive"',
            '--config "$CI_SCAN_TOOL_DIR/empty-syft.yaml"',
            '--config "$CI_SCAN_TOOL_DIR/empty-trivy.yaml" image',
            '--ignorefile "$CI_SCAN_TOOL_DIR/empty-trivy.ignore"',
            "--scanners vuln",
            "--pkg-types os,library",
            "--list-all-pkgs",
            "--severity HIGH,CRITICAL",
            "--exit-code 1",
            "deploy/ci/validate-image-scan.py",
            '--requirements-lock "$GITHUB_WORKSPACE/requirements.lock"',
            "app\t$TEST_APP_IMAGE",
            "postgres\t$TEST_POSTGRES_IMAGE",
            "egress\t$TEST_EGRESS_IMAGE",
            "rabbitmq\t$TEST_RABBITMQ_IMAGE",
            "rabbitmq-upgrade\t$TEST_RABBITMQ_UPGRADE_IMAGE",
            "release-verifier\t$TEST_RELEASE_VERIFIER_IMAGE",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            'CI_SCAN_TOOL_DIR: "${{ runner.temp }}/backupsheep-ci-scan-tools"',
            "path: ${{ runner.temp }}/backupsheep-ci-image-evidence",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, gate)
        self.assertNotIn("--ignore-unfixed", gate)
        self.assertNotIn("--skip-db-update", gate)
        self.assertIn('test ! -s "$CI_SCAN_TOOL_DIR/empty-trivy.ignore"', gate)

    def test_rabbitmq_scan_requires_exact_patched_openssl_packages(self):
        expected = {"libcrypto3": "3.5.8-r0", "libssl3": "3.5.8-r0"}
        image_scan.validate_rabbitmq_security_packages(expected, "fixture")
        for package, vulnerable_version in (
            ("libcrypto3", "3.5.7-r0"),
            ("libssl3", "3.5.7-r0"),
        ):
            with self.subTest(package=package):
                observed = dict(expected)
                observed[package] = vulnerable_version
                with self.assertRaises(SystemExit):
                    image_scan.validate_rabbitmq_security_packages(
                        observed, "fixture"
                    )

    def test_release_verifier_scan_requires_exact_patched_go_graph(self):
        syft = {
            "stdlib": {"go1.26.6"},
            "golang.org/x/mod": {"v0.40.0"},
            "golang.org/x/text": {"v0.41.0"},
            "google.golang.org/grpc": {"v1.82.1"},
        }
        image_scan.validate_verifier_go_packages(syft, "Syft")
        vulnerable = dict(syft)
        vulnerable["stdlib"] = {"go1.26.4"}
        with self.assertRaises(SystemExit):
            image_scan.validate_verifier_go_packages(vulnerable, "Syft")

        validator = (
            ROOT / "deploy" / "ci" / "validate-image-scan.py"
        ).read_text(encoding="utf-8")
        for package in (
            "backupsheep-mariadb-dump",
            "backupsheep-oracle-mysql-client",
            "backupsheep-postgresql-client-14",
            "backupsheep-postgresql-client-15",
            "backupsheep-postgresql-client-16",
            "backupsheep-postgresql-client-17",
            "backupsheep-postgresql-client-18",
            "iproute2-minimal",
            "nftables",
            "setpriv",
        ):
            with self.subTest(package=package):
                self.assertIn(package, validator)
        self.assertIn('artifact.get("name") == "postgresql"', validator)
        self.assertIn('version == "18.6"', validator)

    def test_scan_validator_rejects_omitted_python_and_unsafe_results(self):
        validator = ROOT / "deploy" / "ci" / "validate-image-scan.py"
        expected_packages = (
            "backupsheep-mariadb-dump",
            "backupsheep-oracle-mysql-client",
            "backupsheep-postgresql-client-14",
            "backupsheep-postgresql-client-15",
            "backupsheep-postgresql-client-16",
            "backupsheep-postgresql-client-17",
            "backupsheep-postgresql-client-18",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "app.tar"
            archive.write_bytes(b"exact-test-archive")
            syft = root / "app.syft.json"
            trivy = root / "app.trivy.json"
            requirements_lock = root / "requirements.lock"
            summary = root / "app.summary.json"
            locked_requirements = (
                "django==6.0.8 \\\n"
                f"    --hash=sha256:{'1' * 64}\n"
                "typing-extensions==4.16.0 \\\n"
                f"    --hash=sha256:{'2' * 64}\n"
            )
            requirements_lock.write_text(locked_requirements, encoding="utf-8")

            def write_archive(
                *,
                config_bytes=b'{"architecture":"amd64","os":"linux"}',
                config_name=None,
                manifest_entries=1,
                declared_digest=None,
                repo_tags=None,
            ):
                digest = declared_digest or hashlib.sha256(config_bytes).hexdigest()
                name = config_name or f"blobs/sha256/{digest}"
                image_manifest = json.dumps(
                    {
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {
                            "mediaType": "application/vnd.oci.image.config.v1+json",
                            "digest": f"sha256:{digest}",
                            "size": len(config_bytes),
                        },
                        "layers": [],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                image_manifest_digest = hashlib.sha256(image_manifest).hexdigest()
                image_index = json.dumps(
                    {
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": f"sha256:{image_manifest_digest}",
                                "size": len(image_manifest),
                            }
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                docker_digest = hashlib.sha256(image_index).hexdigest()
                archive_index = json.dumps(
                    {
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.index.v1+json",
                                "digest": f"sha256:{docker_digest}",
                                "size": len(image_index),
                            }
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                manifest = json.dumps(
                    [{"Config": name, "RepoTags": repo_tags, "Layers": []}]
                    * manifest_entries
                ).encode()
                with tarfile.open(archive, mode="w") as bundle:
                    for member_name, content in (
                        (name, config_bytes),
                        (
                            f"blobs/sha256/{image_manifest_digest}",
                            image_manifest,
                        ),
                        (f"blobs/sha256/{docker_digest}", image_index),
                        ("index.json", archive_index),
                        ("manifest.json", manifest),
                    ):
                        member = tarfile.TarInfo(name=member_name)
                        member.size = len(content)
                        bundle.addfile(member, io.BytesIO(content))
                return (
                    "sha256:" + hashlib.sha256(config_bytes).hexdigest(),
                    "sha256:" + docker_digest,
                )

            archive_image_id, docker_image_id = write_archive()
            os_package_names = (*expected_packages, "ca-certificates")
            valid_syft = {
                "schema": {
                    "version": "16.1.10",
                    "url": (
                        "https://raw.githubusercontent.com/anchore/syft/main/"
                        "schema/json/schema-16.1.10.json"
                    ),
                },
                "descriptor": {"name": "syft", "version": "1.51.0"},
                "artifacts": [
                    {"name": name, "version": "1", "type": "deb"}
                    for name in os_package_names
                ]
                + [
                    {
                        "name": "Django",
                        "version": "6.0.8",
                        "type": "python",
                        "locations": [
                            {
                                "path": "/usr/local/lib/python3.14/site-packages/"
                                "django-6.0.8.dist-info/METADATA"
                            }
                        ],
                    },
                    {
                        "name": "typing_extensions",
                        "version": "4.16.0",
                        "type": "python",
                        "locations": [
                            {
                                "path": "/usr/local/lib/python3.14/site-packages/"
                                "typing_extensions-4.16.0.dist-info/METADATA"
                            }
                        ],
                    },
                ],
                "source": {
                    "type": "image",
                    "metadata": {
                        "userInput": str(archive),
                        "imageID": archive_image_id,
                    },
                },
            }
            valid_trivy = {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.74.0"},
                "ArtifactID": archive_image_id,
                "ArtifactName": str(archive),
                "ArtifactType": "container_image",
                "Metadata": {"ImageID": archive_image_id},
                "Results": [
                    {
                        "Target": "app (ubuntu 26.04)",
                        "Class": "os-pkgs",
                        "Type": "ubuntu",
                        "Packages": [
                            {"Name": name, "Version": "1"}
                            for name in os_package_names
                        ],
                    },
                    {
                        "Target": "Python",
                        "Class": "lang-pkgs",
                        "Type": "python-pkg",
                        "Packages": [
                            {
                                "Name": "Django",
                                "Version": "6.0.8",
                                "FilePath": "usr/local/lib/python3.14/"
                                "site-packages/django-6.0.8.dist-info/METADATA",
                            },
                            {
                                "Name": "typing_extensions",
                                "Version": "4.16.0",
                                "FilePath": "usr/local/lib/python3.14/"
                                "site-packages/typing_extensions-4.16.0.dist-info/"
                                "METADATA",
                            },
                        ],
                    },
                ],
            }

            def run_validator(
                syft_report, trivy_report, requested_image_id=docker_image_id
            ):
                syft.write_text(json.dumps(syft_report), encoding="utf-8")
                trivy.write_text(json.dumps(trivy_report), encoding="utf-8")
                return subprocess.run(
                    [
                        "python3",
                        str(validator),
                        "--image-kind",
                        "app",
                        "--image-id",
                        requested_image_id,
                        "--archive",
                        str(archive),
                        "--syft",
                        str(syft),
                        "--trivy",
                        str(trivy),
                        "--requirements-lock",
                        str(requirements_lock),
                        "--summary",
                        str(summary),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            valid = run_validator(valid_syft, valid_trivy)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(
                json.loads(summary.read_text())["trivy_high_critical_count"], 0
            )
            valid_summary = json.loads(summary.read_text())
            self.assertEqual(valid_summary["docker_image_id"], docker_image_id)
            self.assertEqual(
                valid_summary["archive_config_image_id"], archive_image_id
            )
            self.assertEqual(valid_summary["os_package_count"], 8)
            self.assertEqual(valid_summary["expected_python_package_count"], 2)
            self.assertEqual(valid_summary["syft_python_package_count"], 2)
            self.assertEqual(
                valid_summary["syft_top_level_python_package_count"], 2
            )
            self.assertEqual(valid_summary["syft_locked_python_package_count"], 2)
            self.assertEqual(valid_summary["trivy_python_package_count"], 2)
            self.assertEqual(
                valid_summary["trivy_top_level_python_package_count"], 2
            )
            self.assertEqual(valid_summary["trivy_locked_python_package_count"], 2)
            self.assertEqual(
                valid_summary["requirements_lock_sha256"],
                hashlib.sha256(locked_requirements.encode()).hexdigest(),
            )
            self.assertEqual(
                valid_summary["expected_python_inventory_sha256"],
                hashlib.sha256(
                    b"django==6.0.8\ntyping-extensions==4.16.0\n"
                ).hexdigest(),
            )

            syft_without_schema = json.loads(json.dumps(valid_syft))
            del syft_without_schema["schema"]
            missing_syft_schema = run_validator(
                syft_without_schema, valid_trivy
            )
            self.assertNotEqual(missing_syft_schema.returncode, 0)
            self.assertIn("Syft report schema is absent", missing_syft_schema.stderr)

            wrong_syft_tool = json.loads(json.dumps(valid_syft))
            wrong_syft_tool["descriptor"]["version"] = "1.50.0"
            unsupported_syft = run_validator(wrong_syft_tool, valid_trivy)
            self.assertNotEqual(unsupported_syft.returncode, 0)
            self.assertIn("Syft report tool identity", unsupported_syft.stderr)

            wrong_trivy_schema = json.loads(json.dumps(valid_trivy))
            wrong_trivy_schema["SchemaVersion"] = 999
            unsupported_trivy_schema = run_validator(
                valid_syft, wrong_trivy_schema
            )
            self.assertNotEqual(unsupported_trivy_schema.returncode, 0)
            self.assertIn("Trivy schema version", unsupported_trivy_schema.stderr)

            wrong_trivy_tool = json.loads(json.dumps(valid_trivy))
            wrong_trivy_tool["Trivy"]["Version"] = "0.73.0"
            unsupported_trivy_tool = run_validator(valid_syft, wrong_trivy_tool)
            self.assertNotEqual(unsupported_trivy_tool.returncode, 0)
            self.assertIn("Trivy report tool identity", unsupported_trivy_tool.stderr)

            malformed_trivy_artifact_id = json.loads(json.dumps(valid_trivy))
            malformed_trivy_artifact_id["ArtifactID"] = "sha256:not-a-digest"
            malformed_trivy_identity = run_validator(
                valid_syft, malformed_trivy_artifact_id
            )
            self.assertNotEqual(malformed_trivy_identity.returncode, 0)
            self.assertIn("Trivy artifact ID", malformed_trivy_identity.stderr)

            wrong_trivy_artifact_id = json.loads(json.dumps(valid_trivy))
            wrong_trivy_artifact_id["ArtifactID"] = "sha256:" + "e" * 64
            mismatched_trivy_identity = run_validator(
                valid_syft, wrong_trivy_artifact_id
            )
            self.assertNotEqual(mismatched_trivy_identity.returncode, 0)
            self.assertIn(
                "Trivy artifact ID does not match",
                mismatched_trivy_identity.stderr,
            )

            syft_without_python = json.loads(json.dumps(valid_syft))
            syft_without_python["artifacts"] = [
                artifact
                for artifact in syft_without_python["artifacts"]
                if artifact["type"] != "python"
            ]
            missing_syft_python = run_validator(
                syft_without_python, valid_trivy
            )
            self.assertNotEqual(missing_syft_python.returncode, 0)
            self.assertIn(
                "Syft Python inventory is missing locked top-level package identities",
                missing_syft_python.stderr,
            )
            self.assertIn("django==6.0.8", missing_syft_python.stderr)

            trivy_without_python = json.loads(json.dumps(valid_trivy))
            trivy_without_python["Results"] = [
                result
                for result in trivy_without_python["Results"]
                if result.get("Type") != "python-pkg"
            ]
            missing_trivy_python = run_validator(
                valid_syft, trivy_without_python
            )
            self.assertNotEqual(missing_trivy_python.returncode, 0)
            self.assertIn(
                "Trivy Python inventory is missing locked top-level package identities",
                missing_trivy_python.stderr,
            )
            self.assertIn("typing-extensions==4.16.0", missing_trivy_python.stderr)

            syft_wrong_runtime = json.loads(json.dumps(valid_syft))
            for artifact in syft_wrong_runtime["artifacts"]:
                for location in artifact.get("locations", []):
                    location["path"] = location["path"].replace(
                        "/python3.14/", "/python3.13/"
                    )
            inactive_syft_runtime = run_validator(
                syft_wrong_runtime, valid_trivy
            )
            self.assertNotEqual(inactive_syft_runtime.returncode, 0)
            self.assertIn("django==6.0.8", inactive_syft_runtime.stderr)

            trivy_wrong_runtime = json.loads(json.dumps(valid_trivy))
            for result in trivy_wrong_runtime["Results"]:
                for package in result.get("Packages", []):
                    if "FilePath" in package:
                        package["FilePath"] = package["FilePath"].replace(
                            "/python3.14/", "/python3.13/"
                        )
            inactive_trivy_runtime = run_validator(
                valid_syft, trivy_wrong_runtime
            )
            self.assertNotEqual(inactive_trivy_runtime.returncode, 0)
            self.assertIn("typing-extensions==4.16.0", inactive_trivy_runtime.stderr)

            wrong_python_version = json.loads(json.dumps(valid_syft))
            next(
                artifact
                for artifact in wrong_python_version["artifacts"]
                if artifact["name"] == "Django"
            )["version"] = "6.0.7"
            wrong_version = run_validator(wrong_python_version, valid_trivy)
            self.assertNotEqual(wrong_version.returncode, 0)
            self.assertIn("django==6.0.8", wrong_version.stderr)

            wrong_trivy_version = json.loads(json.dumps(valid_trivy))
            next(
                package
                for result in wrong_trivy_version["Results"]
                for package in result.get("Packages", [])
                if package["Name"] == "typing_extensions"
            )["Version"] = "4.15.0"
            wrong_trivy = run_validator(valid_syft, wrong_trivy_version)
            self.assertNotEqual(wrong_trivy.returncode, 0)
            self.assertIn("typing-extensions==4.16.0", wrong_trivy.stderr)

            vendored_trivy_identity = json.loads(json.dumps(valid_trivy))
            next(
                package
                for result in vendored_trivy_identity["Results"]
                for package in result.get("Packages", [])
                if package["Name"] == "Django"
            )["FilePath"] = (
                "usr/local/lib/python3.14/site-packages/setuptools/_vendor/"
                "django-6.0.8.dist-info/METADATA"
            )
            vendored_only = run_validator(valid_syft, vendored_trivy_identity)
            self.assertNotEqual(vendored_only.returncode, 0)
            self.assertIn("django==6.0.8", vendored_only.stderr)

            syft_with_unlocked_python = json.loads(json.dumps(valid_syft))
            syft_with_unlocked_python["artifacts"].append(
                {
                    "name": "undeclared-package",
                    "version": "1.0",
                    "type": "python",
                    "locations": [
                        {
                            "path": "/usr/local/lib/python3.14/site-packages/"
                            "undeclared_package-1.0.dist-info/METADATA"
                        }
                    ],
                }
            )
            unlocked_python = run_validator(
                syft_with_unlocked_python, valid_trivy
            )
            self.assertNotEqual(unlocked_python.returncode, 0)
            self.assertIn(
                "unlocked top-level package identities", unlocked_python.stderr
            )
            self.assertIn("undeclared-package==1.0", unlocked_python.stderr)

            syft_with_unlocked_egg = json.loads(json.dumps(valid_syft))
            syft_with_unlocked_egg["artifacts"].append(
                {
                    "name": "unlocked-egg",
                    "version": "9.9",
                    "type": "python",
                    "locations": [
                        {
                            "path": "/usr/local/lib/python3.14/site-packages/"
                            "unlocked_egg.egg-info/PKG-INFO"
                        }
                    ],
                }
            )
            unlocked_egg = run_validator(syft_with_unlocked_egg, valid_trivy)
            self.assertNotEqual(unlocked_egg.returncode, 0)
            self.assertIn("unlocked-egg==9.9", unlocked_egg.stderr)

            trivy_with_unlocked_uppercase = json.loads(json.dumps(valid_trivy))
            next(
                result
                for result in trivy_with_unlocked_uppercase["Results"]
                if result.get("Type") == "python-pkg"
            )["Packages"].append(
                {
                    "Name": "uppercase-metadata",
                    "Version": "9.8",
                    "FilePath": "usr/local/lib/python3.14/site-packages/"
                    "UPPERCASE_METADATA-9.8.DIST-INFO/METADATA",
                }
            )
            unlocked_uppercase = run_validator(
                valid_syft, trivy_with_unlocked_uppercase
            )
            self.assertNotEqual(unlocked_uppercase.returncode, 0)
            self.assertIn("uppercase-metadata==9.8", unlocked_uppercase.stderr)

            trivy_without_os = json.loads(json.dumps(valid_trivy))
            trivy_without_os["Results"] = [
                result
                for result in trivy_without_os["Results"]
                if result.get("Class") != "os-pkgs"
            ]
            missing_os_inventory = run_validator(valid_syft, trivy_without_os)
            self.assertNotEqual(missing_os_inventory.returncode, 0)
            self.assertIn("no unique ubuntu OS package", missing_os_inventory.stderr)

            syft_missing_one_os_package = json.loads(json.dumps(valid_syft))
            syft_missing_one_os_package["artifacts"] = [
                artifact
                for artifact in syft_missing_one_os_package["artifacts"]
                if artifact.get("name") != "ca-certificates"
            ]
            asymmetric_os_inventory = run_validator(
                syft_missing_one_os_package, valid_trivy
            )
            self.assertNotEqual(asymmetric_os_inventory.returncode, 0)
            self.assertIn(
                "missing from Syft=['ca-certificates']",
                asymmetric_os_inventory.stderr,
            )

            requirements_lock.write_text(
                "django>=6.0.8\n", encoding="utf-8"
            )
            malformed_lock = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(malformed_lock.returncode, 0)
            self.assertIn("unsupported or unpinned line", malformed_lock.stderr)
            requirements_lock.write_text(locked_requirements, encoding="utf-8")

            requirements_lock.write_text(
                "django==6.0.8 \\\n",
                encoding="utf-8",
            )
            unhashed_lock = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(unhashed_lock.returncode, 0)
            self.assertIn("has no SHA-256 artifact hash", unhashed_lock.stderr)

            requirements_lock.write_text(
                "django==6.0.8 \\\n"
                f"    --hash=sha256:{'1' * 64}\n"
                "Django==6.0.8 \\\n"
                f"    --hash=sha256:{'2' * 64}\n",
                encoding="utf-8",
            )
            duplicate_lock = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(duplicate_lock.returncode, 0)
            self.assertIn("duplicate normalized package name", duplicate_lock.stderr)
            requirements_lock.write_text(locked_requirements, encoding="utf-8")

            empty = run_validator({**valid_syft, "artifacts": []}, valid_trivy)
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn("Syft contains no package inventory", empty.stderr)

            vulnerable_trivy = json.loads(json.dumps(valid_trivy))
            vulnerable_trivy["Results"][0]["Vulnerabilities"] = [
                {"VulnerabilityID": "CVE-TEST-1", "Severity": "CRITICAL"}
            ]
            vulnerable = run_validator(valid_syft, vulnerable_trivy)
            self.assertNotEqual(vulnerable.returncode, 0)
            self.assertIn("CVE-TEST-1", vulnerable.stderr)

            swapped_syft = json.loads(json.dumps(valid_syft))
            swapped_syft["source"]["metadata"]["imageID"] = "sha256:" + "b" * 64
            swapped_id = run_validator(swapped_syft, valid_trivy)
            self.assertNotEqual(swapped_id.returncode, 0)
            self.assertIn("Syft source image ID does not match", swapped_id.stderr)

            swapped_syft_path = json.loads(json.dumps(valid_syft))
            swapped_syft_path["source"]["metadata"]["userInput"] = str(
                root / "other.tar"
            )
            swapped_input = run_validator(swapped_syft_path, valid_trivy)
            self.assertNotEqual(swapped_input.returncode, 0)
            self.assertIn("Syft source input does not identify", swapped_input.stderr)

            swapped_trivy = json.loads(json.dumps(valid_trivy))
            swapped_trivy["ArtifactName"] = str(root / "other.tar")
            swapped_path = run_validator(valid_syft, swapped_trivy)
            self.assertNotEqual(swapped_path.returncode, 0)
            self.assertIn("Trivy artifact does not identify", swapped_path.stderr)

            swapped_trivy_id = json.loads(json.dumps(valid_trivy))
            swapped_trivy_id["Metadata"]["ImageID"] = "sha256:" + "c" * 64
            swapped_scan = run_validator(valid_syft, swapped_trivy_id)
            self.assertNotEqual(swapped_scan.returncode, 0)
            self.assertIn("Trivy image ID does not match", swapped_scan.stderr)

            swapped_archive = run_validator(
                valid_syft, valid_trivy, "sha256:" + "d" * 64
            )
            self.assertNotEqual(swapped_archive.returncode, 0)
            self.assertIn(
                "does not identify the image archive root",
                swapped_archive.stderr,
            )

            write_archive(manifest_entries=2)
            multiple = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(multiple.returncode, 0)
            self.assertIn("exactly one image manifest", multiple.stderr)

            write_archive(config_name="../config.json")
            traversal = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(traversal.returncode, 0)
            self.assertIn("config member name is unsafe", traversal.stderr)

            write_archive(declared_digest="0" * 64)
            invalid_digest = run_validator(valid_syft, valid_trivy)
            self.assertNotEqual(invalid_digest.returncode, 0)
            self.assertIn("config digest does not match", invalid_digest.stderr)

            tagged_reference = "registry.example.com/team/backupsheep:test"
            write_archive(repo_tags=[tagged_reference])
            tagged_trivy = json.loads(json.dumps(valid_trivy))
            tagged_trivy["Metadata"]["RepoTags"] = [tagged_reference]
            tagged_trivy["Metadata"]["Reference"] = tagged_reference
            tagged_trivy["ArtifactID"] = "sha256:" + hashlib.sha256(
                f"{archive_image_id}:registry.example.com/team/backupsheep".encode()
            ).hexdigest()
            tagged_identity = run_validator(valid_syft, tagged_trivy)
            self.assertEqual(tagged_identity.returncode, 0, tagged_identity.stderr)

    def test_regression_postgres_entrypoint_receives_explicit_server_command(self):
        launch_start = self.workflow.index("          docker run --detach \\\n")
        launch_end = self.workflow.index("\n\n          database_ready=", launch_start)
        launch = self.workflow[launch_start:launch_end]
        self.assertIn(
            '"$TEST_POSTGRES_IMAGE" postgres >/dev/null',
            launch,
        )
        with tempfile.TemporaryDirectory() as temporary:
            arguments_file = Path(temporary) / "docker-arguments"
            script = f'''set -euo pipefail
docker() {{ printf '%s\\0' "$@" > "$MOCK_ARGUMENTS_FILE"; }}
database_name=backupsheep_test
database_user=backupsheep_test
database_password=test-only-password
{launch}
'''
            environment = os.environ.copy()
            environment.update(
                MOCK_ARGUMENTS_FILE=str(arguments_file),
                TEST_OWNERSHIP_VALUE="test-owner",
                TEST_NETWORK="test-network",
                TEST_POSTGRES_CONTAINER="test-postgres-container",
                TEST_POSTGRES_IMAGE="test-postgres-image",
            )
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            arguments = arguments_file.read_bytes().split(b"\0")[:-1]
            self.assertEqual(arguments[-2:], [b"test-postgres-image", b"postgres"])
            entrypoint_index = arguments.index(b"--entrypoint")
            self.assertEqual(
                arguments[entrypoint_index + 1],
                b"/usr/local/bin/docker-entrypoint.sh",
            )

    def test_read_only_regression_container_uses_only_narrow_contract_mounts(self):
        create_start = self.workflow.index(
            '          docker create \\\n            --name "$TEST_APPLICATION_CONTAINER"'
        )
        create_end = self.workflow.index("\n\n          # Only tests", create_start)
        create = self.workflow[create_start:create_end]
        self.assertIn("            --read-only \\\n", create)
        self.assertIn(
            "--tmpfs /run/backupsheep-test-tmp:rw,exec,nosuid,nodev,size=2g,mode=0700,uid=10001,gid=10001",
            create,
        )
        self.assertIn("--env TMPDIR=/run/backupsheep-test-tmp", create)
        self.assertEqual(self.workflow.count("/run/backupsheep-test-tmp"), 2)
        smoke = self.workflow.split(
            "# Exercise the production image's own /code tree", 1
        )[1]
        self.assertIn("--tmpfs /tmp:rw,noexec,nosuid,nodev", smoke)
        self.assertNotIn("/run/backupsheep-test-tmp", smoke)
        self.assertNotIn("docker cp", self.workflow)
        for source, target in (
            ("apps/tests", "/code/apps/tests"),
            (
                "apps/console/onboarding/tests.py",
                "/code/apps/console/onboarding/tests.py",
            ),
            (".github", "/code/.github"),
            ("bruno", "/code/bruno"),
            ("deploy", "/code/deploy"),
            ("docs", "/code/docs"),
            ("Dockerfile.rabbitmq", "/code/Dockerfile.rabbitmq"),
            (
                "Dockerfile.rabbitmq-upgrade",
                "/code/Dockerfile.rabbitmq-upgrade",
            ),
            (
                "Dockerfile.release-verifier",
                "/code/Dockerfile.release-verifier",
            ),
            ("scripts", "/code/scripts"),
            ("Dockerfile", "/code/Dockerfile"),
            ("docker-compose.yml", "/code/docker-compose.yml"),
            ("install.sh", "/code/install.sh"),
        ):
            with self.subTest(source=source):
                self.assertIn(
                    f"source=$GITHUB_WORKSPACE/{source},target={target},readonly",
                    create,
                )
        self.assertNotIn("source=$GITHUB_WORKSPACE,target=", create)
        self.assertNotIn("source=$GITHUB_WORKSPACE/.env", create)
        self.assertNotIn("source=$GITHUB_WORKSPACE/_storage", create)
        self.assertNotIn("target=/code/apps/api", create)
        self.assertNotIn("target=/code/backupsheep,readonly", create)

    def test_topology_project_validation_is_ascii_and_locale_invariant(self):
        self.assertLess(
            self.runner.index("export LC_ALL=C"),
            self.runner.index('[[ "${TEST_TOPOLOGY_PROJECT}" =~'),
        )
        environment = os.environ.copy()
        environment.update(
            LC_ALL="tr_TR.UTF-8",
            TEST_APP_IMAGE="unused-app",
            TEST_POSTGRES_IMAGE="unused-postgres",
            TEST_EGRESS_IMAGE="unused-egress",
            TEST_TOPOLOGY_PROJECT="BackupsheepCI",
            TEST_OWNERSHIP_VALUE="unused-owner",
        )
        result = subprocess.run(
            ["bash", str(ROOT / "deploy" / "ci" / "run-security-topology.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a bounded Compose project name", result.stderr)
        self.assertNotIn("required local image", result.stderr)

    def test_hostile_image_ownership_labels_never_reach_topology_mutation(self):
        self.assertIn("__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__", self.runner)
        self.assertIn("{{len .}}:{{.}}", self.runner)
        self.assertIn('[[ "$label_value" != *[[:cntrl:]]* ]]', self.runner)
        self.assertIn(
            'docker_resource_label container "$container" com.backupsheep.installation-id',
            self.runner,
        )
        self.assertIn(
            'docker_resource_label network "$network" com.docker.compose.project',
            self.runner,
        )
        self.assertIn(
            'docker_resource_label volume "$volume" com.docker.compose.project',
            self.runner,
        )
        self.assertNotIn(
            "docker image inspect --format '{{ index .Config.Labels",
            self.runner,
        )
        hostile_labels = {
            "line-feed": b"expected-owner\n",
            "nul": b"expected-owner\x00",
            "frame-marker": (
                b"expected-owner__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
            ),
            "utf8": "expected-ownér".encode(),
        }
        mock_source = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
mutation_log = Path(os.environ["MOCK_MUTATION_LOG"])
if arguments and (
    arguments[0] in {"run", "rm", "compose"}
    or arguments[:2] in (
        ["container", "rm"],
        ["network", "create"],
        ["network", "rm"],
        ["volume", "create"],
        ["volume", "rm"],
    )
):
    with mutation_log.open("ab") as handle:
        handle.write((" ".join(arguments) + "\n").encode())
    raise SystemExit(97)
if arguments[:2] == ["image", "inspect"]:
    if "--format" not in arguments:
        raise SystemExit(0)
    payload = bytes.fromhex(os.environ["MOCK_LABEL_HEX"])
    marker = b"__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
    sys.stdout.buffer.write(str(len(payload)).encode() + b":" + payload + marker + b"\n")
    raise SystemExit(0)
raise SystemExit(99)
'''

        for scenario, hostile_label in hostile_labels.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                temporary_path = Path(temporary)
                mock_docker = temporary_path / "docker"
                mock_docker.write_text(mock_source, encoding="utf-8")
                mock_docker.chmod(0o700)
                mutation_log = temporary_path / "mutations.log"
                environment = os.environ.copy()
                environment.update(
                    LC_ALL="tr_TR.UTF-8",
                    PATH=f"{temporary}{os.pathsep}{environment['PATH']}",
                    MOCK_MUTATION_LOG=str(mutation_log),
                    MOCK_LABEL_HEX=hostile_label.hex(),
                    TEST_APP_IMAGE="test-app",
                    TEST_POSTGRES_IMAGE="test-postgres",
                    TEST_EGRESS_IMAGE="test-egress",
                    TEST_TOPOLOGY_PROJECT="backupsheep-ci",
                    TEST_OWNERSHIP_VALUE="expected-owner",
                )
                result = subprocess.run(
                    ["bash", str(ROOT / "deploy" / "ci" / "run-security-topology.sh")],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not owned by this CI run", result.stderr)
                self.assertFalse(
                    mutation_log.exists(),
                    f"hostile {scenario} label reached mutation: "
                    + (mutation_log.read_text() if mutation_log.exists() else ""),
                )

    def test_topology_uses_stock_compose_without_build_or_host_listener(self):
        self.assertIn('--file "$compose_file"', self.runner)
        self.assertIn('--file "$topology_override"', self.runner)
        self.assertIn("up --detach --no-build --wait", self.runner)
        self.assertIn("app worker-cloud", self.runner)
        self.assertIn("ports: !reset []", self.override)
        self.assertNotIn("ports:", self.override.split("app-egress-guard:", 1)[0])
        self.assertIn("overrides image content with a host bind mount", self.runner)
        self.assertIn("#!/usr/local/bin/python3", self.runner)
        self.assertIn("fixed-interpreter egress workload healthcheck", self.runner)
        self.assertIn("does not use the stock database/broker healthcheck", self.runner)
        self.assertIn("cannot reach its exact database and broker peers", self.runner)
        self.assertIn("assert_worker_restart_clears_stale_readiness", self.runner)
        self.assertIn("/run/backupsheep/.celery-ready.999999", self.runner)
        self.assertNotIn("--privileged", self.runner)
        self.assertNotIn("docker.sock", self.runner)

    def test_topology_proves_the_stock_no_public_egress_mode(self):
        self.assertIn("BACKUPSHEEP_EGRESS_POLICY_GENERATION=2", self.runner)
        self.assertIn("does not render egress policy generation 2", self.runner)
        self.assertIn('environment.get("BACKUPSHEEP_EGRESS_MODE") != "deny"', self.runner)
        self.assertIn("did not boot in stock deny mode", self.runner)
        self.assertIn("may restart into a namespace its workload does not share", self.runner)
        self.assertIn("may start before its required {peer} peer is healthy", self.runner)
        self.assertIn("did not renew its kernel authorization", self.runner)
        self.assertIn("docker kill", self.runner)
        self.assertIn("running:unhealthy", self.runner)
        self.assertIn("--force-recreate --no-deps", self.runner)
        self.assertIn(
            "assert_pair_fails_closed_and_recovers app-egress-guard app",
            self.runner,
        )
        self.assertIn(
            "assert_pair_fails_closed_and_recovers cloud-egress-guard worker-cloud",
            self.runner,
        )
        self.assertIn("retained database access after its guard lease expired", self.runner)
        self.assertIn("retained broker access after its guard lease expired", self.runner)
        self.assertNotIn("BACKUPSHEEP_APP_EGRESS_MODE=", self.runner)
        self.assertNotIn("BACKUPSHEEP_CLOUD_EGRESS_MODE=", self.runner)

    def test_policy_harness_stops_a_non_pid1_client_before_tuple_revocation(self):
        harness = (
            ROOT / "deploy" / "egress" / "test-policy.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'docker run -d --init --name "$persistent_client"', harness
        )
        self.assertIn('/proc/1/task/1/children', harness)
        self.assertIn('^State:[[:space:]]+T', harness)
        for gateway in (".1", ".17", ".33"):
            self.assertIn(
                f'--gateway "10.253.${{subnet_octet}}{gateway}"',
                harness,
            )

    def test_topology_proves_real_preflight_database_and_broker_identities(self):
        for expected in (
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION=3",
            "BACKUPSHEEP_CELERY_SECURITY_GENERATION=3",
            "BACKUPSHEEP_RABBITMQ_DATA_GENERATION=4.3",
            "db-provision migrate db-seal preflight",
            "python manage.py docker_preflight",
            "assert_healthy app",
            "assert_healthy worker-cloud",
            "RabbitMQ dedicated identities drifted",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.runner)

    def test_runtime_credentials_are_files_not_direct_environment_values(self):
        self.assertIn('chmod 0444 "$secret_dir"/*', self.runner)
        self.assertIn('DJANGO_SECRET_KEY", "DB_PASSWORD", "RABBITMQ_PASSWORD', self.runner)
        self.assertIn("env_file: !reset []", self.override)
        self.assertNotIn("DB_PASSWORD=", self.runner)
        self.assertNotIn("RABBITMQ_PASSWORD=", self.runner)
