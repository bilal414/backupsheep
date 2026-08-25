import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]

LOG_ARCHIVE_CREDENTIALS = (
    "S3_ACCESS_KEY_ID",
    "S3_SECRET_ACCESS_KEY",
    "S3_STORAGE_BUCKET_NAME",
    "S3_ENDPOINT_URL",
    "S3_SIGNATURE_VERSION",
    "AWS_S3_ACCESS_KEY",
    "AWS_S3_SECRET_ACCESS_KEY",
    "AWS_S3_LOGS_BUCKET",
    "AWS_S3_LOGS_ENDPOINT",
    "AWS_S3_LOGS_REGION",
    "LOGS_S3_ACCESS_KEY_ID",
    "LOGS_S3_SECRET_ACCESS_KEY",
    "LOGS_S3_BUCKET",
    "LOGS_S3_ENDPOINT",
)
NOTIFICATION_CREDENTIALS = (
    "POSTMARK_API_KEY",
    "POSTMARK_DOMAIN",
    "POSTMARK_EMAIL",
    "POSTMARK_API_URL",
    "SES_REGION_NAME",
    "SES_REGION_ENDPOINT",
    "SES_ACCESS_KEY_ID",
    "SES_SECRET_ACCESS_KEY",
    "AWS_SES_REGION_NAME",
    "AWS_SES_REGION_ENDPOINT",
    "AWS_SES_ACCESS_KEY_ID",
    "AWS_SES_SECRET_ACCESS_KEY",
    "MAILGUN_DOMAIN",
    "MAILGUN_EMAIL",
    "MAILGUN_API_KEY",
    "MAILGUN_API_URL",
    "EMAIL_PROVIDER",
    "SLACK_TOKEN_URL",
    "SLACK_CLIENT_ID",
    "SLACK_CLIENT_SECRET",
    "TELEGRAM_BOT_KEY",
)
CLOUD_PROVIDER_CREDENTIALS = (
    "DIGITALOCEAN_APP_CLIENT_ID",
    "DIGITALOCEAN_APP_CLIENT_SECRET",
    "OVH_CA_APP_KEY",
    "OVH_CA_APP_SECRET",
    "OVH_EU_APP_KEY",
    "OVH_EU_APP_SECRET",
    "OVH_US_APP_KEY",
    "OVH_US_APP_SECRET",
)
BASECAMP_CREDENTIALS = (
    "BASECAMP_CLIENT_ID",
    "BASECAMP_CLIENT_SECRET",
)
STORAGE_PROVIDER_CREDENTIALS = (
    "DROPBOX_APP_KEY",
    "DROPBOX_APP_SECRET",
    "PCLOUD_CLIENT_ID",
    "PCLOUD_CLIENT_SECRET",
    "MS_CLIENT_ID",
    "MS_OBJECT_ID",
    "MS_TENANT_ID",
    "MS_APPLICATION_ID",
    "MS_CLIENT_SECRET_VALUE",
    "MS_CLIENT_SECRET_ID",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
)
OPTIONAL_INTEGRATION_CREDENTIALS = (
    LOG_ARCHIVE_CREDENTIALS
    + NOTIFICATION_CREDENTIALS
    + CLOUD_PROVIDER_CREDENTIALS
    + BASECAMP_CREDENTIALS
    + STORAGE_PROVIDER_CREDENTIALS
)
INTEGRATION_CREDENTIAL_ALLOWLIST = {
    "db-provision": frozenset(),
    "migrate": frozenset(),
    "db-seal": frozenset(),
    "preflight": frozenset(),
    "app": frozenset(OPTIONAL_INTEGRATION_CREDENTIALS),
    "worker-cloud": frozenset(CLOUD_PROVIDER_CREDENTIALS),
    "worker-database": frozenset(),
    "worker-files": frozenset(BASECAMP_CREDENTIALS),
    "worker-storage": frozenset(STORAGE_PROVIDER_CREDENTIALS),
    "worker-logs": frozenset(NOTIFICATION_CREDENTIALS),
    "beat": frozenset(),
}


class DeploymentHardeningContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        manifest = ast.parse(
            (ROOT / "backupsheep" / "celery_task_manifest.py").read_text(
                encoding="utf-8"
            )
        )
        policies = next(
            node.value
            for node in manifest.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "TASK_POLICIES"
        )
        cls.task_queues = {
            key.value: value.args[0].value
            for key, value in zip(policies.keys, policies.values, strict=True)
        }

    def service_block(self, name):
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|^networks:\n)",
            self.compose,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing Compose service {name}")
        return match.group("body")

    def test_compose_binds_web_to_loopback_by_default(self):
        self.assertIn(
            "${BACKUPSHEEP_BIND_ADDRESS:-127.0.0.1}:"
            "${BACKUPSHEEP_BIND_PORT:-8000}:8000",
            self.compose,
        )
        self.assertNotIn('- "8000:8000"', self.compose)

    def test_bundled_postgres_uses_the_new_digest_pinned_alpine_icu_runtime(self):
        postgres_dockerfile = (ROOT / "Dockerfile.postgres").read_text(encoding="utf-8")
        self.assertIn(
            "postgres:18.6-alpine3.24@sha256:"
            "d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
            postgres_dockerfile,
        )
        self.assertIn("apk add --no-cache 'su-exec=0.3-r0'", postgres_dockerfile)
        self.assertNotIn("apk upgrade", postgres_dockerfile)
        self.assertIn("USER 70:70", postgres_dockerfile)
        database = self.service_block("db")
        self.assertIn("--locale-provider=icu --icu-locale=und", database)
        self.assertIn("postgres_data_v1:/var/lib/postgresql", database)
        self.assertNotIn("pgdata:/var/lib/postgresql", database)

    def test_postgres_logical_runtime_migration_is_deterministic_and_fail_closed(self):
        migration = (
            ROOT / "deploy" / "postgres" / "migrate-runtime.sh"
        ).read_text(encoding="utf-8")
        witness = (
            ROOT / "deploy" / "postgres" / "storage-witness.sh"
        ).read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertIn("SHOW server_version_num", migration)
        self.assertIn('[[ "$source_version_num" == 180006 ]]', migration)
        self.assertNotIn("source_version=\"$(psql_source 'SHOW server_version')\"", migration)
        self.assertIn('grep -Eq "(GLIBC|GNU libc)"', migration)
        self.assertIn("SHOW server_version_num", witness)

        self.assertIn("BackupSheep/postgres-dump-restrict/v1", migration)
        self.assertIn("openssl dgst -sha256", migration)
        self.assertGreaterEqual(migration.count("--restrict-key=\"$"), 2)
        self.assertGreaterEqual(migration.count("--restrict-key=$4"), 3)
        for exact_header in (
            "^-- Dumped from database version .*",
            "^-- Dumped by pg_dump version .*",
            "^-- Dumped by pg_dumpall version .*",
        ):
            self.assertIn(exact_header, migration)

        marker_read = migration.index(
            'marker_status="$(sed -n \'1p\' <<< "$evidence")"'
        )
        complete_branch = migration.index(
            "if [[ \"$marker_status\" == 'status=complete' ]]"
        )
        pending_reset = migration.index(
            '"$docker_bin" volume rm "$target_volume"'
        )
        self.assertLess(marker_read, complete_branch)
        self.assertLess(complete_branch, pending_reset)
        self.assertIn(
            '[[ -z "$marker_status" || "$marker_status" == \'status=pending\' ]]',
            migration,
        )

        self.assertIn("migration-target.XXXXXXXX", migration)
        self.assertIn("/run/secrets/source_password:ro", migration)
        self.assertIn("/run/secrets/target_password:ro", migration)
        self.assertIn("legacy source server must not mount a plaintext credential", migration)
        self.assertIn("ephemeral target credential remains after migration", migration)
        self.assertIn('grep -Fxq -- "$bootstrap_user"', migration)
        self.assertIn('grep -Fxq -- "$database_owner"', migration)
        self.assertIn('grep -Fxq -- "${data_volume}|${data_target}"', migration)
        self.assertIn("__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__", migration)
        self.assertIn("{{len .}}:{{.}}", migration)
        self.assertIn('[[ "$label_value" != *[[:cntrl:]]* ]]', migration)
        self.assertNotIn("{{index .Config.Labels", migration)
        self.assertNotIn("{{index .Labels", migration)
        for catalog in (
            "pg_tablespace",
            "pg_event_trigger",
            "pg_foreign_data_wrapper",
            "pg_foreign_server",
            "pg_foreign_table",
            "pg_user_mapping",
            "pg_publication",
            "pg_subscription",
        ):
            self.assertIn(catalog, migration)

        configure = installer.split(
            "configure_postgres_storage_generation() {", 1
        )[1].split("\n}\n", 1)[0]
        self.assertNotIn("legacy PostgreSQL volume must be detached", configure)
        ownership = installer.split("validate_compose_project_ownership() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        self.assertIn("exact retained UID/GID-999 database container", ownership)
        start_core = installer.split("start_core() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(
            start_core.index("stop_operations"),
            start_core.index("run_postgres_runtime_migration"),
        )
        migrate_runner = installer.split(
            "run_postgres_runtime_migration() {", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn(
            "prove legacy PostgreSQL detachment immediately before migration",
            migrate_runner,
        )

    def test_postgres_migration_hostile_label_bytes_never_reach_deletion(self):
        migration = ROOT / "deploy" / "postgres" / "migrate-runtime.sh"
        project = "backupsheep"
        installation_id = "a" * 64
        source_image_id = "sha256:" + "b" * 64
        storage_witness = "c" * 64
        roles = ",".join(
            f"backupsheep_{role}"
            for role in (
                "bootstrap",
                "migrator",
                "app",
                "preflight",
                "beat",
                "cloud",
                "database",
                "files",
                "storage",
                "logs",
            )
        )
        hostile_labels = {
            "line-feed": b"backupsheep\n",
            "nul": b"backupsheep\x00",
            "frame-marker": (
                b"backupsheep__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
            ),
            "utf8": "backupshéep".encode(),
        }
        mock_source = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
source_volume = os.environ["MOCK_SOURCE_VOLUME"]
mutation_log = Path(os.environ["MOCK_MUTATION_LOG"])

if arguments and (
    arguments[0] in {"rm", "run", "stop"}
    or arguments[:2] in (["volume", "create"], ["volume", "rm"])
):
    with mutation_log.open("ab") as handle:
        handle.write((" ".join(arguments) + "\n").encode())
    raise SystemExit(97)

if arguments and arguments[0] == "ps":
    raise SystemExit(0)

if arguments[:2] == ["volume", "inspect"]:
    resource = arguments[-1]
    if resource != source_volume:
        raise SystemExit(1)
    if "--format" not in arguments:
        raise SystemExit(0)
    template = arguments[arguments.index("--format") + 1]
    if template == "{{.Name}}":
        print(source_volume)
        raise SystemExit(0)
    if "com.docker.compose.project" in template:
        payload = bytes.fromhex(os.environ["MOCK_LABEL_HEX"])
        marker = b"__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
        sys.stdout.buffer.write(str(len(payload)).encode() + b":" + payload + marker + b"\n")
        raise SystemExit(0)
    raise SystemExit(98)

raise SystemExit(99)
'''

        for scenario, hostile_label in hostile_labels.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                temporary_path = Path(temporary)
                mock_docker = temporary_path / "docker"
                mock_docker.write_text(mock_source, encoding="utf-8")
                mock_docker.chmod(0o700)
                secret_file = temporary_path / "db_bootstrap_password"
                secret_file.write_text("test-only-source-password\n", encoding="ascii")
                secret_file.chmod(0o600)
                mutation_log = temporary_path / "mutations.log"
                source_volume = f"{project}_pgdata"
                environment = os.environ.copy()
                environment.update(
                    LC_ALL="tr_TR.UTF-8",
                    MOCK_SOURCE_VOLUME=source_volume,
                    MOCK_MUTATION_LOG=str(mutation_log),
                    MOCK_LABEL_HEX=hostile_label.hex(),
                )
                result = subprocess.run(
                    [
                        "bash",
                        str(migration),
                        str(mock_docker),
                        project,
                        installation_id,
                        source_image_id,
                        "target-image:test",
                        source_volume,
                        f"{project}_postgres_data_v1",
                        str(secret_file),
                        "backupsheep",
                        "backupsheep_bootstrap",
                        roles,
                        storage_witness,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("legacy source volume ownership is invalid", result.stderr)
                self.assertFalse(
                    mutation_log.exists(),
                    f"hostile {scenario} label reached mutation: "
                    + (mutation_log.read_text() if mutation_log.exists() else ""),
                )

    def test_compose_project_identity_is_required_by_the_model(self):
        self.assertIn(
            'name: "${BACKUPSHEEP_COMPOSE_PROJECT_NAME:', self.compose
        )

    def test_supply_chain_ci_supplies_compose_ownership_witnesses(self):
        workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")

        self.assertRegex(
            workflow,
            r'BACKUPSHEEP_COMPOSE_PROJECT_NAME:\s+["\']backupsheep-ci["\']',
        )
        self.assertRegex(
            workflow,
            r'BACKUPSHEEP_INSTALLATION_ID:\s+["\'][0-9a-f]{64}["\']',
        )
        self.assertRegex(
            workflow,
            r'BACKUPSHEEP_DATABASE_IDENTITY_GENERATION:\s+["\']3["\']',
        )
        self.assertRegex(
            workflow,
            r'BACKUPSHEEP_CELERY_SECURITY_GENERATION:\s+["\']3["\']',
        )

    def test_supply_chain_ci_blocks_on_the_full_offline_application_suite(self):
        workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        gate = workflow.split("  application-security-regression:\n", 1)[1]

        for required in (
            "name: Full application/security regression gate",
            "runs-on: ubuntu-24.04",
            "timeout-minutes: 180",
            "Refusing to load a checkout .env in the regression gate",
            "Refusing a pre-existing checkout _storage path",
            "Refusing a pre-existing CI container-name collision",
            "Refusing a pre-existing CI network-name collision",
            "Refusing a pre-existing CI image-tag collision",
            'com.backupsheep.ci-run=$TEST_OWNERSHIP_VALUE',
            ".backupsheep-ci-owner",
            "--network-alias db",
            "--env DB_HOST=db",
            '--file Dockerfile --tag "$TEST_APP_IMAGE"',
            '--file Dockerfile.postgres --tag "$TEST_POSTGRES_IMAGE"',
            "docker network create --driver bridge --internal",
            'docker create \\\n',
            "--tmpfs /code/_storage:rw,noexec,nosuid,nodev",
            "--tmpfs /run/backupsheep-test-tmp:rw,exec,nosuid,nodev,size=2g,mode=0700,uid=10001,gid=10001",
            '--workdir /code',
            '--env PYTHONPATH=/code',
            '--env TMPDIR=/run/backupsheep-test-tmp',
            'source=$GITHUB_WORKSPACE/apps/tests,target=/code/apps/tests,readonly',
            'docker start --attach "$TEST_APPLICATION_CONTAINER"',
            'BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=bse1',
            'BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=true',
            'BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=false',
            '"$TEST_APP_IMAGE" python manage.py migrate --plan',
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=legacy-only",
            "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=false",
            "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=true",
            "apps.tests.test_installer_security",
            "apps.tests.test_compose_wrapper_security",
            "apps.tests.test_docker_preflight_command",
            "python bruno/scripts/validate_collection.py",
            "python docs/enterprise/tools/validate_docs.py",
            "python manage.py test apps.tests apps.console.onboarding --noinput",
            "if: ${{ always() }}",
        ):
            with self.subTest(required=required):
                self.assertIn(required, gate)
        self.assertNotIn("--network-alias database", gate)
        self.assertNotIn("--env DB_HOST=database", gate)

        self.assertEqual(gate.count("docker build --pull --no-cache"), 3)
        self.assertNotIn("continue-on-error", gate)
        self.assertNotIn("--privileged", gate)
        self.assertNotIn("docker.sock", gate)
        self.assertNotIn("docker cp", gate)
        self.assertNotIn("target=/workspace", gate)
        self.assertNotIn('echo "$database_password"', gate)
        self.assertNotIn("set -x", gate)

    def test_postgres_healthcheck_authenticates_with_the_file_secret(self):
        database = self.service_block("db")
        self.assertIn("cat /run/secrets/db_bootstrap_password", database)
        self.assertIn("--host=127.0.0.1", database)
        self.assertIn("--command='SELECT 1'", database)
        self.assertNotIn('test: ["CMD-SHELL", "pg_isready', database)

    def test_compose_uses_supported_pinned_broker_without_guest_defaults(self):
        self.assertIn(
            "rabbitmq:4.3.5-alpine@sha256:"
            "d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7",
            self.compose,
        )
        self.assertNotIn("RABBITMQ_DEFAULT_PASS:", self.compose)
        self.assertIn(
            "/run/secrets/rabbitmq_bootstrap_password",
            (ROOT / "deploy" / "rabbitmq" / "entrypoint.sh").read_text(
                encoding="utf-8"
            ),
        )
        self.assertIn("/run/secrets/rabbitmq_app_password", self.compose)
        self.assertIn(
            "exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server",
            (ROOT / "deploy" / "rabbitmq" / "entrypoint.sh").read_text(
                encoding="utf-8"
            ),
        )
        provisioner = (ROOT / "deploy" / "rabbitmq" / "provision.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('add_user "$user" "$hash" --pre-hashed-password', provisioner)
        self.assertIn('stored_password_hash "$user"', provisioner)
        self.assertIn("rabbit_password_hashing_sha256", provisioner)
        self.assertNotIn("rabbitmq_password:/run/secrets/rabbitmq_password", self.compose)
        self.assertIn(
            '["CMD", "rabbitmq-diagnostics", "-q", "ping"]',
            self.service_block("rabbitmq"),
        )
        self.assertIn("start_period: 30s", self.compose)
        self.assertNotIn("guest:guest", self.compose)

    def test_existing_broker_upgrade_has_a_pinned_compatible_hop(self):
        overlay = (
            ROOT / "deploy" / "rabbitmq" / "upgrade-4.2.9.compose.yml"
        ).read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "guides" / "rabbitmq-upgrade.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("rabbitmq:4.2.9-alpine@sha256:", overlay)
        self.assertIn("must not be started directly", guide)
        self.assertIn("3.13.x to 4.2.x", guide)

    def test_compose_bounds_logs_and_isolates_backend(self):
        self.assertEqual(self.compose.count("logging: *default-logging"), 17)
        self.assertIn("max-size: \"${DOCKER_LOG_MAX_SIZE:-10m}\"", self.compose)
        self.assertEqual(self.compose.count(": *internal-network"), 19)
        self.assertEqual(self.compose.count(": *egress-network"), 6)
        self.assertIn("com.docker.network.bridge.enable_icc: \"false\"", self.compose)

    def test_application_image_and_compose_drop_runtime_privileges(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")
        env_sample = (ROOT / ".env_sample").read_text(encoding="utf-8")

        for uid in range(10001, 10009):
            with self.subTest(uid=uid):
                self.assertIn(f"useradd --uid {uid} --gid {uid}", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("/code/_storage", dockerfile)
        self.assertIn("/backups", dockerfile)
        self.assertIn("/code/static", dockerfile)
        self.assertIn("umask 077", entrypoint)
        self.assertEqual(self.compose.count("<<: *app-runtime"), 12)
        self.assertIn('user: "10001:10001"', self.compose)
        self.assertIn("pull_policy: never", self.compose)
        self.assertIn("read_only: true", self.compose)
        self.assertGreaterEqual(self.compose.count("cgroup: private"), 2)
        self.assertNotIn("pid: host", self.compose)
        self.assertIn("privileged: false", self.compose)
        self.assertIn("pids_limit: \"${BACKUPSHEEP_PIDS_LIMIT:-512}\"", self.compose)
        self.assertIn("cap_drop:\n    - ALL", self.compose)
        self.assertIn("security_opt:\n    - no-new-privileges:true", self.compose)
        self.assertIn("init: true", self.compose)
        self.assertIn(
            "/run/backupsheep:rw,noexec,nosuid,nodev,size=16m,"
            "mode=0700,uid=10001,gid=10001",
            self.compose,
        )
        self.assertNotIn("/code/static:rw", self.compose)
        self.assertIn("BACKUPSHEEP_PIDS_LIMIT=512", env_sample)
        self.assertNotIn('entrypoint: ["celery"', self.compose)
        self.assertNotIn('entrypoint: ["python", "manage.py", "migrate"', self.compose)
        for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertIn(f'require_all_zero "$capability_set"', entrypoint)
        self.assertIn("require_mount / any ro", entrypoint)
        self.assertIn("/sys/fs/cgroup/pids.max", entrypoint)
        self.assertIn("/sys/fs/cgroup/memory.max", entrypoint)
        self.assertIn("/sys/fs/cgroup/cpu.max", entrypoint)
        self.assertIn("cgroup limit is missing or unlimited", entrypoint)
        self.assertIn("max_pids='4096'", entrypoint)
        self.assertIn("max_memory_bytes='34359738368'", entrypoint)
        self.assertIn("max_cpu_cores='32'", entrypoint)
        self.assertIn("immutable container ceiling", entrypoint)
        self.assertIn("the deployment preflight did not pass", entrypoint)

    def test_runtime_backup_work_directory_is_never_a_git_candidate(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("/_storage/", gitignore)

    def test_every_application_role_uses_one_explicit_image_reference(self):
        image_reference = 'image: "${BACKUPSHEEP_IMAGE:-backupsheep:local}"'
        self.assertEqual(self.compose.count(image_reference), 12)
        self.assertNotIn("backupsheep:latest", self.compose)

        env_sample = (ROOT / ".env_sample").read_text(encoding="utf-8")
        self.assertIn("BACKUPSHEEP_IMAGE=backupsheep:local", env_sample)
        self.assertIn(
            "BACKUPSHEEP_POSTGRES_IMAGE=backupsheep-postgres:local", env_sample
        )
        self.assertIn("BACKUPSHEEP_INSTALLATION_ID=''", env_sample)

    def test_every_compose_resource_has_an_installation_identity(self):
        self.assertIn(
            "com.backupsheep.installation-id: "
            '"${BACKUPSHEEP_INSTALLATION_ID:?',
            self.compose,
        )
        self.assertEqual(self.compose.count("labels: *installation-labels"), 5)
        self.assertIn("source: installation_identity", self.service_block("app"))

    def test_provider_mutating_roles_require_an_explicit_profile_and_preflight(self):
        operation_workers = (
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-storage",
            "worker-logs",
            "beat",
        )
        operation_guards = (
            "cloud-egress-guard",
            "database-egress-guard",
            "files-egress-guard",
            "storage-egress-guard",
            "logs-egress-guard",
        )
        self.assertEqual(
            self.compose.count('profiles: ["operations"]'),
            len(operation_workers) + len(operation_guards),
        )
        for service in (*operation_workers, *operation_guards):
            with self.subTest(service=service):
                block = self.service_block(service)
                self.assertIn('profiles: ["operations"]', block)

        for service in operation_workers:
            with self.subTest(preflight_dependency=service):
                block = self.service_block(service)
                self.assertIn(
                    "preflight:\n        condition: service_completed_successfully",
                    block,
                )

        # Guards have restart:no and therefore must not race peer service-name
        # creation on their only startup attempt.
        for service in ("app-egress-guard", *operation_guards):
            with self.subTest(peer_readiness_dependency=service):
                block = self.service_block(service)
                self.assertIn(
                    "db:\n        condition: service_healthy", block
                )
                self.assertIn(
                    "rabbitmq:\n        condition: service_healthy", block
                )

        for service in (
            "db",
            "rabbitmq-volume-init",
            "rabbitmq",
            "rabbitmq-provision",
            "staging-provision",
            "db-provision",
            "migrate",
            "db-seal",
            "preflight",
            "app-egress-guard",
            "app",
        ):
            with self.subTest(core_service=service):
                self.assertNotIn("profiles:", self.service_block(service))

    def test_preflight_is_a_core_one_shot_fail_closed_gate(self):
        preflight = self.service_block("preflight")
        app = self.service_block("app")
        self.assertIn(
            'command: ["python", "manage.py", "docker_preflight"]', preflight
        )
        self.assertIn('restart: "no"', preflight)
        self.assertIn("preflight-database", preflight)
        self.assertIn("preflight-broker", preflight)
        self.assertIn(
            "preflight:\n        condition: service_completed_successfully", app
        )

    def test_installation_secrets_are_files_not_inspectable_environment_values(self):
        secrets = self.compose.split("\nsecrets:\n", 1)[1]
        for name in (
            "django_secret_key",
            "db_bootstrap_password",
            "db_migrator_password",
            "db_app_password",
            "db_preflight_password",
            "db_beat_password",
            "db_cloud_password",
            "db_database_password",
            "db_files_password",
            "db_storage_password",
            "db_logs_password",
            "rabbitmq_bootstrap_password",
            "rabbitmq_app_password",
            "rabbitmq_preflight_password",
            "rabbitmq_beat_password",
            "rabbitmq_cloud_password",
            "rabbitmq_database_password",
            "rabbitmq_files_password",
            "rabbitmq_storage_password",
            "rabbitmq_logs_password",
            "onboarding_token",
            "ssh_managed_database_private_key",
            "ssh_managed_files_private_key",
            "artifact_kms_database_aws_credentials",
            "artifact_kms_files_aws_credentials",
        ):
            with self.subTest(secret=name):
                self.assertIn(
                    f"file: ${{BACKUPSHEEP_SECRETS_DIR:-.secrets}}/{name}",
                    secrets,
                )
        self.assertNotRegex(secrets, r"(?m)^  db_password:")
        self.assertNotIn("environment:", secrets)

        secret_environment = self.compose.split(
            "x-app-secret-environment: &app-secret-environment\n", 1
        )[1].split("\nx-app-secrets:", 1)[0]
        for variable in (
            "DJANGO_SECRET_KEY",
            "DB_PASSWORD",
            "RABBITMQ_PASSWORD",
            "ONBOARDING_INSTALL_TOKEN",
            "DATABASE_URL",
            "CELERY_BROKER_URL",
            "BACKUPSHEEP_SECRETS",
        ):
            with self.subTest(blanked_variable=variable):
                self.assertIn(f'{variable}: ""', secret_environment)
        self.assertIn(
            "DJANGO_SETTINGS_MODULE: backupsheep.settings", secret_environment
        )
        for variable in (
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "SSLKEYLOGFILE",
        ):
            with self.subTest(blanked_loader_variable=variable):
                self.assertIn(f'{variable}: ""', secret_environment)

        app = self.service_block("app")
        self.assertIn("ONBOARDING_INSTALL_TOKEN_SECRET_FILE", app)
        for service in (
            "db-provision",
            "migrate",
            "preflight",
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-storage",
            "worker-logs",
            "beat",
        ):
            with self.subTest(no_onboarding_secret=service):
                self.assertNotIn(
                    "ONBOARDING_INSTALL_TOKEN_SECRET_FILE",
                    self.service_block(service),
                )

    def test_optional_integration_credentials_are_scoped_to_actual_consumers(self):
        secret_environment = self.compose.split(
            "x-app-secret-environment: &app-secret-environment\n", 1
        )[1].split("\nx-stateful-runtime:", 1)[0]
        for variable in OPTIONAL_INTEGRATION_CREDENTIALS:
            with self.subTest(globally_blanked=variable):
                self.assertIn(f'{variable}: ""', secret_environment)

        for service, allowed in INTEGRATION_CREDENTIAL_ALLOWLIST.items():
            service_environment = self.service_block(service)
            for variable in OPTIONAL_INTEGRATION_CREDENTIALS:
                interpolation = f'{variable}: "${{{variable}:-}}"'
                with self.subTest(service=service, variable=variable):
                    if variable in allowed:
                        self.assertIn(interpolation, service_environment)
                    else:
                        self.assertNotIn(interpolation, service_environment)

        entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")
        self.assertIn("reject_credential_group()", entrypoint)
        for group in (
            "log-archive",
            "email/notification",
            "cloud-provider application",
            "Basecamp application",
            "storage-provider application",
        ):
            with self.subTest(runtime_enforced_group=group):
                self.assertIn(f"reject_credential_group '{group}'", entrypoint)
        self.assertIn(
            "$runtime_role must not receive $rejected_group credentials",
            entrypoint,
        )

    def test_application_services_use_an_explicit_environment_allowlist(self):
        for service in INTEGRATION_CREDENTIAL_ALLOWLIST:
            with self.subTest(service=service):
                self.assertNotIn("env_file:", self.service_block(service))

        sample_keys = {
            match.group(1)
            for line in (ROOT / ".env_sample").read_text(encoding="utf-8").splitlines()
            if (match := re.match(r"\s*([A-Z][A-Z0-9_]*)\s*=", line))
        }
        reviewed_keys = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", self.compose))
        reviewed_keys.update(
            re.findall(r"^\s+([A-Z][A-Z0-9_]*):", self.compose, re.MULTILINE)
        )
        # This compatibility-only path is deliberately unavailable in stock Compose;
        # managed SSH trust is materialized per operation from PostgreSQL instead.
        self.assertEqual(
            sample_keys - reviewed_keys,
            {"SSH_KNOWN_HOSTS_PATH", "BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID"},
        )
        self.assertNotIn("BACKUPSHEEP_UNREVIEWED_SECRET", reviewed_keys)

    def test_rendered_compose_model_does_not_bleed_integration_canaries(self):
        """Exercise real .env interpolation without attaching it to a service."""

        if shutil.which("docker") is None:
            self.skipTest("Docker Compose is unavailable in this test environment")
        version = subprocess.run(
            ["docker", "compose", "version"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose v2 is unavailable in this test environment")

        environment = os.environ.copy()
        credential_fixture = (
            ROOT
            / "apps"
            / "tests"
            / "fixtures"
            / "compose-credential-render.env"
        )
        canaries = {
            variable: "credential-canary"
            for variable in OPTIONAL_INTEGRATION_CREDENTIALS
        }
        for line in credential_fixture.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                environment.pop(line.split("=", 1)[0], None)
        rendered = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(credential_fixture),
                "--file",
                str(ROOT / "docker-compose.yml"),
                "--profile",
                "operations",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        model = json.loads(rendered.stdout)
        for service, allowed in INTEGRATION_CREDENTIAL_ALLOWLIST.items():
            service_environment = model["services"][service]["environment"]
            self.assertEqual(
                service_environment.get("WORDPRESS_INTEGRATION_ENABLED"), "true"
            )
            self.assertEqual(
                service_environment.get("BASECAMP_INTEGRATION_ENABLED"), "true"
            )
            for variable, canary in canaries.items():
                with self.subTest(rendered_service=service, variable=variable):
                    expected = canary if variable in allowed else ""
                    self.assertEqual(service_environment.get(variable), expected)
            self.assertNotIn("BACKUPSHEEP_UNREVIEWED_SECRET", service_environment)
            for variable in (
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
            ):
                with self.subTest(rendered_service=service, proxy_hook=variable):
                    self.assertEqual(service_environment.get(variable), "")

        for guard in (
            "app-egress-guard",
            "cloud-egress-guard",
            "database-egress-guard",
            "files-egress-guard",
            "storage-egress-guard",
            "logs-egress-guard",
        ):
            with self.subTest(rendered_guard=guard):
                guard_environment = model["services"][guard]["environment"]
                self.assertEqual(
                    guard_environment["BACKUPSHEEP_EGRESS_POLICY_GENERATION"], "2"
                )
                self.assertEqual(guard_environment["BACKUPSHEEP_EGRESS_MODE"], "deny")
                self.assertEqual(guard_environment["BACKUPSHEEP_EGRESS_ALLOW_IPV4"], "")
                self.assertEqual(guard_environment["BACKUPSHEEP_EGRESS_ALLOW_IPV6"], "")
                self.assertEqual(
                    guard_environment[
                        "BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS"
                    ],
                    "",
                )
                self.assertEqual(
                    guard_environment[
                        "BACKUPSHEEP_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS"
                    ],
                    "",
                )
                self.assertEqual(
                    guard_environment["BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES"], ""
                )

    def test_database_bootstrap_migrator_and_runtime_identities_are_separated(self):
        database = self.service_block("db")
        provisioner = self.service_block("db-provision")
        migrator = self.service_block("migrate")
        sealer = self.service_block("db-seal")
        configuration_environment = self.compose.split(
            "x-app-configuration-environment: &app-configuration-environment\n", 1
        )[1].split("\nx-app-secret-environment:", 1)[0]

        for role_variable in (
            "DB_BOOTSTRAP_USER",
            "DB_MIGRATOR_USER",
            "DB_APP_USER",
            "DB_PREFLIGHT_USER",
            "DB_BEAT_USER",
            "DB_CLOUD_USER",
            "DB_DATABASE_USER",
            "DB_FILES_USER",
            "DB_STORAGE_USER",
            "DB_LOGS_USER",
        ):
            with self.subTest(shared_non_secret_role_name=role_variable):
                self.assertIn(f"  {role_variable}:", configuration_environment)
        self.assertNotIn("PASSWORD", configuration_environment)

        self.assertIn(
            "POSTGRES_USER: ${DB_BOOTSTRAP_USER:-backupsheep_bootstrap}",
            database,
        )
        self.assertIn("POSTGRES_PASSWORD_FILE: /run/secrets/db_bootstrap_password", database)
        self.assertNotIn("db_migrator_password", database)
        self.assertNotIn("- db_password\n", database)

        self.assertIn(
            'command: ["python", "-m", "backupsheep.database_identity", "provision"]',
            provisioner,
        )
        self.assertIn(
            'BACKUPSHEEP_DATABASE_IDENTITY_GENERATION: "3"', provisioner
        )
        self.assertIn("DB_HOST: db", provisioner)
        self.assertIn('DB_PORT: "5432"', provisioner)
        for secret_name in (
            "db_bootstrap_password",
            "db_migrator_password",
            "db_app_password",
            "db_preflight_password",
            "db_beat_password",
            "db_cloud_password",
            "db_database_password",
            "db_files_password",
            "db_storage_password",
            "db_logs_password",
        ):
            self.assertIn(f"- {secret_name}", provisioner)
            self.assertIn(f"- {secret_name}", sealer)
        self.assertNotIn("- db_password\n", provisioner)
        self.assertNotIn("- db_password\n", sealer)
        self.assertNotIn("django_secret_key", provisioner)
        self.assertNotIn("rabbitmq_password", provisioner)
        self.assertIn("- provision-database", provisioner)
        self.assertNotIn("- migrate-database", provisioner)
        self.assertIn(
            'command: ["python", "-m", "backupsheep.database_identity", "seal"]',
            sealer,
        )
        self.assertIn(
            "migrate:\n        condition: service_completed_successfully", sealer
        )

        self.assertIn(
            'DB_USER: "${DB_MIGRATOR_USER:-backupsheep_migrator}"', migrator
        )
        self.assertIn("DB_PASSWORD_FILE: /run/secrets/db_migrator_password", migrator)
        self.assertNotIn("db_bootstrap_password", migrator)
        self.assertIn(
            "db-provision:\n        condition: service_completed_successfully",
            migrator,
        )

        runtime_identities = {
            "preflight": "preflight",
            "app": "app",
            "worker-cloud": "cloud",
            "worker-database": "database",
            "worker-files": "files",
            "worker-storage": "storage",
            "worker-logs": "logs",
            "beat": "beat",
        }
        for service, lane in runtime_identities.items():
            with self.subTest(runtime_service=service):
                block = self.service_block(service)
                self.assertNotIn("db_bootstrap_password", block)
                self.assertNotIn("db_migrator_password", block)
                self.assertIn(
                    f'DB_USER: "${{DB_{lane.upper()}_USER:-backupsheep_{lane}}}"',
                    block,
                )
                self.assertIn(
                    f"DB_PASSWORD_FILE: /run/secrets/db_{lane}_password", block
                )

    def test_stateful_services_are_unpublished_and_minimally_privileged(self):
        for service in ("db", "rabbitmq"):
            with self.subTest(service=service):
                block = self.service_block(service)
                self.assertNotIn("ports:", block)
                self.assertIn("<<: *stateful-runtime", block)
                self.assertIn("pids_limit:", block)
                self.assertIn("mem_limit:", block)
                self.assertIn("cpus:", block)

        stateful = self.compose.split(
            "x-stateful-runtime: &stateful-runtime\n", 1
        )[1].split("\nx-egress-network:", 1)[0]
        self.assertIn("read_only: true", stateful)
        self.assertIn("cap_drop:\n    - ALL", stateful)
        self.assertNotIn("cap_add:", stateful)
        database = self.service_block("db")
        self.assertIn('user: "70:70"', database)
        self.assertNotIn("cap_add:", database)
        rabbitmq = self.service_block("rabbitmq")
        self.assertIn('user: "100:101"', rabbitmq)
        self.assertNotIn("cap_add:", rabbitmq)
        self.assertNotIn("SYS_ADMIN", rabbitmq)
        self.assertNotIn("NET_ADMIN", rabbitmq)
        self.assertNotIn("init: true", stateful)

        volume_init = self.service_block("rabbitmq-volume-init")
        self.assertIn('user: "100:101"', volume_init)
        self.assertIn("network_mode: none", volume_init)
        self.assertIn('restart: "no"', volume_init)
        self.assertNotIn("cap_add:", volume_init)
        self.assertIn("backupsheep-rabbitmq-volume-init", volume_init)

    def test_role_networks_prevent_worker_to_worker_lateral_reachability(self):
        role_networks = {}
        role_guards = {
            "app": "app-egress-guard",
            "worker-cloud": "cloud-egress-guard",
            "worker-database": "database-egress-guard",
            "worker-files": "files-egress-guard",
            "worker-storage": "storage-egress-guard",
            "worker-logs": "logs-egress-guard",
        }
        for service, guard in role_guards.items():
            block = self.service_block(guard)
            networks = block.split("\n    networks:\n", 1)[1]
            role_networks[service] = set(
                re.findall(r"^      ([a-z][a-z0-9-]+):(?: .*)?$", networks, re.MULTILINE)
            )
            self.assertEqual(len(role_networks[service]), 3)
            self.assertIn("gw_priority: 1", networks)
            self.assertIn(
                f"network_mode: service:{guard}", self.service_block(service)
            )

        services = tuple(role_networks)
        for index, left in enumerate(services):
            for right in services[index + 1 :]:
                with self.subTest(left=left, right=right):
                    self.assertTrue(role_networks[left].isdisjoint(role_networks[right]))

    def test_egress_guards_allow_only_exact_internal_peer_tcp_tuples(self):
        entrypoint = (ROOT / "deploy" / "egress" / "entrypoint.sh").read_text(
            encoding="utf-8"
        )
        dns_proxy = (ROOT / "deploy" / "egress" / "dns-proxy.c").read_text(
            encoding="utf-8"
        )
        dns_forwarder = (
            ROOT / "deploy" / "egress" / "dns-forwarder.c"
        ).read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile.egress").read_text(encoding="utf-8")
        application_dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        egress_harness = (
            ROOT / "deploy" / "egress" / "test-policy.sh"
        ).read_text(encoding="utf-8")
        healthcheck = (ROOT / "deploy" / "egress" / "healthcheck.sh").read_text(
            encoding="utf-8"
        )
        workload_healthcheck = (
            ROOT / "deploy" / "egress" / "workload-healthcheck.py"
        ).read_text(encoding="utf-8")
        self.assertTrue(
            workload_healthcheck.startswith("#!/usr/local/bin/python3\n")
        )
        self.assertNotIn('oifname != "%s" accept', entrypoint)
        self.assertNotIn("'flush ruleset'", entrypoint)
        self.assertIn("Docker owns the embedded-DNS plumbing", entrypoint)
        self.assertIn(
            "oifname . ip daddr . tcp dport @internal_ipv4 accept", entrypoint
        )
        self.assertIn(
            "oifname . ip6 daddr . tcp dport @internal_ipv6 accept", entrypoint
        )
        self.assertIn(
            "peer must use a dedicated non-default internal interface", entrypoint
        )
        self.assertIn("peer must be directly connected", entrypoint)
        self.assertIn(
            "Flush and add operations in one nft batch are one atomic", entrypoint
        )
        self.assertIn("flags timeout; timeout %ss", entrypoint)
        self.assertIn("set strict_workload_lease { type uid; flags timeout", entrypoint)
        self.assertIn("Renew on every complete observation", entrypoint)
        self.assertIn("short-lived proof", entrypoint)
        self.assertIn(
            'timeout --foreground -s KILL 1 getent "$database" "$peer_host"',
            entrypoint,
        )
        self.assertIn("$(($1 * 3 + 12))", entrypoint)
        self.assertIn(
            '[ "$lease_seconds" -ge 15 ] && [ "$lease_seconds" -le 912 ]',
            healthcheck,
        )
        self.assertIn("hung-getent-fixture.sh", egress_harness)
        self.assertIn(
            "hung DNS left the egress guard healthy beyond its kernel lease",
            egress_harness,
        )
        self.assertIn(
            "timeout --version | grep -Fqx 'timeout (GNU coreutils) 9.7'",
            dockerfile,
        )
        self.assertIn(
            "meta skuid != 10020 meta skuid != @strict_workload_lease reject",
            entrypoint,
        )
        self.assertLess(
            entrypoint.index(
                "meta skuid != 10020 meta skuid != @strict_workload_lease reject"
            ),
            entrypoint.index(
                "ct direction reply ct state established,related accept"
            ),
        )
        output_chain = entrypoint.split("'  chain output {'", 1)[1].split(
            "'  chain input {'", 1
        )[0]
        self.assertNotIn(
            "printf '%s\\n' '    ct state established,related accept'", output_chain
        )
        self.assertIn("--bounding-set=-all,+net_admin", entrypoint)
        self.assertIn("must retain only NET_ADMIN", entrypoint)
        self.assertIn("exec env -i PATH=", entrypoint)
        self.assertIn("environment=minimal-shell-only", entrypoint)
        self.assertNotIn("/proc/1/environ", healthcheck)
        self.assertIn("environment=minimal-shell-only", healthcheck)
        self.assertIn("renewed_monotonic_seconds", healthcheck)
        self.assertIn('renewal_age=$((current_monotonic_seconds - renewed_monotonic_seconds))', healthcheck)
        self.assertIn('[ "$renewal_age" -ge 0 ] && [ "$renewal_age" -lt "$lease_seconds" ]', healthcheck)
        self.assertIn("ip daddr %s reject with icmpx", entrypoint)
        self.assertIn("chain dns_redirect", entrypoint)
        self.assertIn(
            "meta skuid != 10020 meta skuid != 10021 meta skuid != 10022",
            entrypoint,
        )
        self.assertIn("redirect to :1053", entrypoint)
        parser_udp_reply = (
            "meta skuid 10021 ip saddr 127.0.0.1 ip daddr 127.0.0.1 "
            "udp sport 1053 ct direction reply counter accept"
        )
        parser_tcp_reply = (
            "meta skuid 10021 ip saddr 127.0.0.1 ip daddr 127.0.0.1 "
            "tcp sport 1053 ct direction reply counter accept"
        )
        self.assertIn(parser_udp_reply, entrypoint)
        self.assertIn(parser_tcp_reply, entrypoint)
        self.assertNotIn(
            "meta skuid 10021 ip daddr 127.0.0.1 counter accept", entrypoint
        )
        for parser_reply in (parser_udp_reply, parser_tcp_reply):
            self.assertLess(
                entrypoint.index(parser_reply),
                entrypoint.index("meta skuid 10021 counter reject"),
            )
        for canary in (
            "TCP:WORKLOAD-TCP",
            "UDP:WORKLOAD-UDP",
            "PARSER-TCP",
            "PARSER-UDP",
        ):
            self.assertIn(canary, egress_harness)
        self.assertIn("legitimate redirected UDP DNS", egress_harness)
        self.assertIn("legitimate redirected TCP DNS", egress_harness)
        self.assertIn(
            'BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES is valid only in allowlist mode',
            entrypoint,
        )
        self.assertIn(
            'mode="${BACKUPSHEEP_EGRESS_MODE:-deny}"', entrypoint
        )
        self.assertIn(
            "allowlist mode requires at least one exact TCP endpoint", entrypoint
        )
        self.assertIn(
            "deny mode does not accept an outward TCP endpoint", entrypoint
        )
        self.assertIn("address-only egress allowlists are retired", entrypoint)
        self.assertIn("BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 is required", entrypoint)
        self.assertIn("allowed_ipv4_tcp", entrypoint)
        self.assertIn("ip daddr . tcp dport @allowed_ipv4_tcp accept", entrypoint)
        self.assertIn("ct original proto-dst 53", entrypoint)
        self.assertIn("64:ff9b::/96", entrypoint)
        never_ipv6_definition = entrypoint.split("set never_ipv6", 1)[1].split(
            "set special_ipv4", 1
        )[0]
        self.assertIn("64:ff9b::/96", never_ipv6_definition)
        self.assertIn("64:ff9b:1::/48", never_ipv6_definition)
        self.assertLess(
            entrypoint.index("ip6 daddr @never_ipv6 reject"),
            entrypoint.index("ip6 daddr . tcp dport @allowed_ipv6_tcp accept"),
        )
        self.assertIn("^mode=(deny|allowlist|public)$", healthcheck)
        self.assertIn("th dport 53 reject with icmpx", entrypoint)
        self.assertIn("--reuid=10021", entrypoint)
        self.assertIn("--reuid=10022", entrypoint)
        self.assertIn("--bounding-set=-all", entrypoint)
        self.assertIn("DNS_PROXY_UID 10021U", dns_proxy)
        self.assertIn("question.qtype != 1U && question.qtype != 28U", dns_proxy)
        self.assertIn("two-byte immutable-name index", dns_proxy)
        self.assertIn("SO_PEERCRED", dns_proxy)
        self.assertIn("DNS_FORWARDER_UID 10022U", dns_forwarder)
        self.assertIn("received == 2", dns_forwarder)
        self.assertIn("peer.uid != DNS_PROXY_UID", dns_forwarder)
        self.assertIn("PR_SET_DUMPABLE", dns_proxy)
        self.assertIn("-fstack-protector-strong", dockerfile)
        self.assertIn("-static-pie", dockerfile)
        self.assertEqual(
            dockerfile.count(
                "FROM alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
            ),
            2,
        )
        self.assertNotIn("alpine:3.22.2", dockerfile)
        self.assertIn("-u 10021 -G backupsheep-dns", dockerfile)
        self.assertIn("-u 10022 -G backupsheep-dns-upstream", dockerfile)
        self.assertIn(
            "deploy/egress/workload-healthcheck.py", application_dockerfile
        )
        self.assertIn('required_endpoint("DB_HOST", "DB_PORT")', workload_healthcheck)
        self.assertIn(
            'required_endpoint("RABBITMQ_HOST", "RABBITMQ_PORT")',
            workload_healthcheck,
        )
        self.assertIn("socket.create_connection", workload_healthcheck)
        self.assertIn("validate_dns_witness", healthcheck)
        self.assertIn("resolver-state 10021", healthcheck)
        self.assertIn("forwarder-state 10022", healthcheck)
        self.assertIn("'0000000000000000'", healthcheck)

        role_guards = {
            "APP": "app-egress-guard",
            "CLOUD": "cloud-egress-guard",
            "DATABASE": "database-egress-guard",
            "FILES": "files-egress-guard",
            "STORAGE": "storage-egress-guard",
            "LOGS": "logs-egress-guard",
        }
        for role, guard in role_guards.items():
            with self.subTest(guard=guard):
                guard_block = self.service_block(guard)
                self.assertIn("<<: *egress-internal-peer-environment", guard_block)
                self.assertIn(
                    f'BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS: "${{BACKUPSHEEP_{role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS:-}}"',
                    guard_block,
                )
                self.assertIn(
                    f'BACKUPSHEEP_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS: "${{BACKUPSHEEP_{role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS:-}}"',
                    guard_block,
                )
                self.assertIn(
                    f'BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES: "${{BACKUPSHEEP_{role}_EGRESS_ALLOW_DNS_NAMES:-}}"',
                    guard_block,
                )

        guard_runtime = self.compose.split(
            "x-egress-guard-runtime: &egress-guard-runtime\n", 1
        )[1].split("\nx-egress-workload-healthcheck:", 1)[0]
        self.assertIn('restart: "no"', guard_runtime)
        self.assertNotIn("restart: unless-stopped", guard_runtime)
        workload_pairs = {
            "app": "app-egress-guard",
            "worker-cloud": "cloud-egress-guard",
            "worker-database": "database-egress-guard",
            "worker-files": "files-egress-guard",
            "worker-storage": "storage-egress-guard",
            "worker-logs": "logs-egress-guard",
        }
        for service, guard in workload_pairs.items():
            with self.subTest(service=service):
                service_block = self.service_block(service)
                self.assertIn(f"network_mode: service:{guard}", service_block)
                self.assertIn(
                    "healthcheck: *egress-workload-healthcheck", service_block
                )
                self.assertNotIn("pid: service:", service_block)

        peer_environment = self.compose.split(
            "x-egress-internal-peer-environment: &egress-internal-peer-environment\n",
            1,
        )[1].split("\nservices:\n", 1)[0]
        self.assertIn(
            'BACKUPSHEEP_EGRESS_DATABASE_HOST: "${DB_HOST:-db}"', peer_environment
        )
        self.assertIn(
            'BACKUPSHEEP_EGRESS_DATABASE_PORT: "${DB_PORT:-5432}"',
            peer_environment,
        )
        self.assertIn(
            'BACKUPSHEEP_EGRESS_BROKER_HOST: "${RABBITMQ_HOST:-rabbitmq}"',
            peer_environment,
        )
        self.assertIn(
            'BACKUPSHEEP_EGRESS_BROKER_PORT: "${RABBITMQ_PORT:-5672}"',
            peer_environment,
        )
        self.assertIn('BACKUPSHEEP_EGRESS_DNS_REFRESH_SECONDS: "1"', peer_environment)
        self.assertIn(
            'BACKUPSHEEP_EGRESS_POLICY_GENERATION: "${BACKUPSHEEP_EGRESS_POLICY_GENERATION:?BACKUPSHEEP_EGRESS_POLICY_GENERATION is required}"',
            peer_environment,
        )

        sample_environment = (ROOT / ".env_sample").read_text(encoding="utf-8")
        self.assertIn("BACKUPSHEEP_EGRESS_POLICY_GENERATION='2'", sample_environment)
        for role in role_guards:
            self.assertIn(
                f"BACKUPSHEEP_{role}_EGRESS_MODE='deny'",
                sample_environment,
            )
            self.assertIn(
                f"BACKUPSHEEP_{role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS=''",
                sample_environment,
            )
            self.assertIn(
                f"BACKUPSHEEP_{role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS=''",
                sample_environment,
            )
            self.assertIn(
                f"BACKUPSHEEP_{role}_EGRESS_ALLOW_DNS_NAMES=''",
                sample_environment,
            )

    def test_backup_storage_is_private_to_the_storage_worker(self):
        provisioner = self.service_block("staging-provision")
        self.assertIn("network_mode: none", provisioner)
        self.assertIn("- FSETID", provisioner)
        self.assertNotIn("NET_ADMIN", provisioner)
        self.assertNotIn("SYS_ADMIN", provisioner)

        for service in (
            "app",
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-logs",
            "beat",
        ):
            with self.subTest(service=service):
                self.assertNotRegex(
                    self.service_block(service),
                    r"(?m)^\s+(?:target: /backups|- [^\n]*:/backups(?:\s|$))",
                )

        storage_worker = self.service_block("worker-storage")
        self.assertIn("source: backup_storage", storage_worker)
        self.assertIn("target: /backups", storage_worker)
        self.assertIn(
            "source: backup_storage\n        target: /volumes/backup-storage",
            self.service_block("staging-provision"),
        )

    def test_all_local_storage_mutations_route_to_storage_worker(self):
        for task in (
            "validate_local_storage",
            "validate_pending_local_storages",
            "delete_backup_requested",
            "delete_storage_requested",
            "resume_requested_storage_deletions",
            "delete_local_node_requested",
            "resume_requested_local_node_deletions",
        ):
            with self.subTest(task=task):
                self.assertEqual(self.task_queues[task], "storage")

        self.assertEqual(self.task_queues["node_delete_requested"], "default")
        self.assertEqual(
            self.task_queues["resume_requested_node_deletions"], "default"
        )
        self.assertEqual(self.task_queues["delete_cloud_node_requested"], "cloud")
        for retired_task in (
            "clean_delete_failed_backups",
            "delete_requested_integrations",
            "delete_requested_storages",
            "account_delete",
        ):
            with self.subTest(retired_task=retired_task):
                self.assertNotIn(retired_task, self.task_queues)

    def test_web_and_notification_roles_cannot_modify_staged_artifacts(self):
        app = self.service_block("app")
        self.assertNotIn("source: backup_workdir", app)
        self.assertNotIn("- backup_workdir:/code/_storage", app)
        self.assertNotIn("ssh_trust:/var/lib/backupsheep/ssh-trust", app)
        self.assertNotIn("/code/_storage", self.service_block("worker-logs"))
        self.assertEqual(self.task_queues["delete_old_logs"], "files")
        self.assertEqual(self.task_queues["delete_old_database_logs"], "database")
        self.assertEqual(self.task_queues["delete_old_storage_logs"], "storage")
        self.assertEqual(self.task_queues["reset_incremental_cache"], "files")

    def test_tenant_trust_is_ephemeral_and_managed_identities_are_lane_split(self):
        app = self.service_block("app")
        database = self.service_block("worker-database")
        files = self.service_block("worker-files")
        secret_environment = self.compose.split(
            "x-app-secret-environment: &app-secret-environment\n", 1
        )[1].split("\nx-app-secrets:", 1)[0]
        self.assertNotIn("SSH_KNOWN_HOSTS_PATH", secret_environment)
        self.assertIn(
            'SSH_MANAGED_PRIVATE_KEY_PATH: ""',
            self.compose,
        )
        self.assertIn("SSH_MANAGED_DATABASE_PUBLIC_KEY", self.compose)
        self.assertIn("SSH_MANAGED_FILES_PUBLIC_KEY", self.compose)
        self.assertIn('SSH_MANAGED_LANE_ISOLATION_REQUIRED: "true"', self.compose)
        for block in (app, database, files):
            self.assertNotIn("ssh_trust:/var/lib/backupsheep/ssh-trust", block)
        self.assertIn("- ssh_managed_database_private_key", database)
        self.assertNotIn("- ssh_managed_files_private_key", database)
        self.assertIn("- ssh_managed_files_private_key", files)
        self.assertNotIn("- ssh_managed_database_private_key", files)
        self.assertNotIn("- ssh_managed_database_private_key", app)
        self.assertNotIn("- ssh_managed_files_private_key", app)
        retired_volume = self.compose.split("\nvolumes:\n", 1)[1].split(
            "\nsecrets:\n", 1
        )[0]
        self.assertNotRegex(retired_volume, r"(?m)^\s*ssh_trust:")

    def test_existing_volume_non_root_migration_is_operator_gated(self):
        guide = (ROOT / "docs" / "guides" / "upgrades.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("One-time non-root volume migration", guide)
        self.assertIn("--migrate-staging-layout", guide)
        self.assertIn("migrate-empty-legacy-v3", guide)
        self.assertIn("networkless\nroot one-shot", guide)
        self.assertIn("10004:10004", guide)
        self.assertNotIn("--user 0:0", guide)
        self.assertNotIn("chown -R 10001:10001 /code/_storage /backups", guide)

    def test_all_supported_paas_manifests_use_crash_safe_scheduler(self):
        expected = "backupsheep.scheduler:BackupDatabaseScheduler"
        for relative in (
            "heroku.yml",
            "render.yaml",
            "deploy/railway/beat.railway.json",
        ):
            with self.subTest(manifest=relative):
                self.assertIn(
                    expected,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )

    def test_onboarding_token_is_not_printed_by_installer(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("printf 'Onboarding token:", installer)
        self.assertIn("cat .secrets/onboarding_token", installer)
        self.assertIn('set_env_value ONBOARDING_INSTALL_TOKEN ""', installer)

    def test_installer_refuses_automatic_existing_broker_migration(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "guides" / "rabbitmq-upgrade.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("ENV_WAS_PRESENT", installer)
        self.assertIn("--migrate-rabbitmq-identities", installer)
        self.assertIn("still shares one RabbitMQ credential", installer)
        self.assertIn("refuses to open an existing volume", guide)

    def test_build_metadata_is_not_in_public_static_root(self):
        public_root = ROOT / "apps" / "console" / "_static" / "console"
        for filename in ("package.json", "package-lock.json", "tailwind.config.js"):
            with self.subTest(filename=filename):
                self.assertFalse((public_root / filename).exists())
        self.assertTrue((ROOT / "tailwind.config.js").is_file())

    def test_sample_documents_bounded_api_token_lifetime(self):
        env_sample = (ROOT / ".env_sample").read_text(encoding="utf-8")
        environment_reference = (
            ROOT / "docs" / "reference" / "environment-variables.md"
        ).read_text(encoding="utf-8")

        self.assertIn("API_TOKEN_TTL_SECONDS=2592000", env_sample)
        self.assertIn("`API_TOKEN_TTL_SECONDS`", environment_reference)
        self.assertIn("30 days", environment_reference)
        self.assertIn("90-day", environment_reference)

    def test_remote_build_installers_are_integrity_checked(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76",
            dockerfile,
        )
        self.assertIn("B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8", dockerfile)
        self.assertIn(
            "a4bcd9f16a53cc763f87b9955dbcdced33c7aa90296b157eb6ceef0f156f4327",
            dockerfile,
        )
        self.assertIn("BCA43417C3B485DD128EC6D4B7B3B788A8D3785C", dockerfile)
        self.assertIn("gpg --batch --verify", dockerfile)
        self.assertNotIn("mariadb_repo_setup | bash", dockerfile)
        self.assertNotIn("oh-my-zsh", dockerfile)
