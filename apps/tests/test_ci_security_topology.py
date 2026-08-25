import hashlib
import io
import os
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


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

    def test_workflow_builds_and_exercises_the_exact_three_local_images(self):
        for expected in (
            'TEST_APP_IMAGE: "backupsheep-ci-app:',
            'TEST_POSTGRES_IMAGE: "backupsheep-ci-postgres:',
            'TEST_EGRESS_IMAGE: "backupsheep-ci-egress:',
            '--file Dockerfile --tag "$TEST_APP_IMAGE"',
            '--file Dockerfile.postgres --tag "$TEST_POSTGRES_IMAGE"',
            '--file Dockerfile.egress --tag "$TEST_EGRESS_IMAGE"',
            'BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION: "1"',
            'BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION: "2"',
            'BACKUPSHEEP_EGRESS_POLICY_GENERATION: "2"',
            "run: deploy/ci/run-security-topology.sh",
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
            "app\t$TEST_APP_IMAGE",
            "postgres\t$TEST_POSTGRES_IMAGE",
            "egress\t$TEST_EGRESS_IMAGE",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            'CI_SCAN_TOOL_DIR: "${{ runner.temp }}/backupsheep-ci-scan-tools"',
            "path: ${{ runner.temp }}/backupsheep-ci-image-evidence",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, gate)
        self.assertNotIn("--ignore-unfixed", gate)
        self.assertNotIn("--skip-db-update", gate)
        self.assertIn('test ! -s "$CI_SCAN_TOOL_DIR/empty-trivy.ignore"', gate)

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

    def test_scan_validator_rejects_empty_inventory_and_high_critical_results(self):
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
            summary = root / "app.summary.json"

            def write_archive(
                *,
                config_bytes=b'{"architecture":"amd64","os":"linux"}',
                config_name=None,
                manifest_entries=1,
                declared_digest=None,
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
                    [{"Config": name, "RepoTags": None, "Layers": []}]
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
            valid_syft = {
                "artifacts": [
                    {"name": name, "version": "1", "type": "deb"}
                    for name in expected_packages
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
                "ArtifactName": str(archive),
                "ArtifactType": "container_image",
                "Metadata": {"ImageID": archive_image_id},
                "Results": [
                    {
                        "Target": "app",
                        "Packages": [{"Name": "python", "Version": "3.14"}],
                    }
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
            self.assertIn("does not identify the image archive root", swapped_archive.stderr)

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
            ("integrations", "/code/integrations"),
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
