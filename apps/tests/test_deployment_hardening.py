from pathlib import Path
import re
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DeploymentHardeningContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

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

    def test_bundled_postgres_preserves_the_cluster_collation_runtime(self):
        postgres_dockerfile = (ROOT / "Dockerfile.postgres").read_text(encoding="utf-8")
        self.assertIn(
            "postgres:18.6-trixie@sha256:"
            "06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941",
            postgres_dockerfile,
        )
        self.assertNotIn("postgres:18.6-bookworm", self.compose)

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
            r'BACKUPSHEEP_DATABASE_IDENTITY_GENERATION:\s+["\']2["\']',
        )

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
        self.assertIn(
            'ctl authenticate_user "$user" "$password"',
            (ROOT / "deploy" / "rabbitmq" / "provision.sh").read_text(
                encoding="utf-8"
            ),
        )
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
        self.assertEqual(self.compose.count("logging: *default-logging"), 12)
        self.assertIn("max-size: \"${DOCKER_LOG_MAX_SIZE:-10m}\"", self.compose)
        self.assertEqual(self.compose.count(": *internal-network"), 18)
        self.assertEqual(self.compose.count(": *egress-network"), 6)
        self.assertIn("com.docker.network.bridge.enable_icc: \"false\"", self.compose)

    def test_application_image_and_compose_drop_runtime_privileges(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")
        env_sample = (ROOT / ".env_sample").read_text(encoding="utf-8")

        self.assertIn("useradd --uid 10001 --gid 10001", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("/code/_storage /backups", dockerfile)
        self.assertIn("/code/static", dockerfile)
        self.assertIn("umask 077", entrypoint)
        self.assertEqual(self.compose.count("<<: *app-runtime"), 10)
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

    def test_every_application_role_uses_one_explicit_image_reference(self):
        image_reference = 'image: "${BACKUPSHEEP_IMAGE:-backupsheep:local}"'
        self.assertEqual(self.compose.count(image_reference), 10)
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
        self.assertEqual(self.compose.count("labels: *installation-labels"), 3)
        self.assertIn("source: installation_identity", self.service_block("app"))

    def test_provider_mutating_roles_require_an_explicit_profile_and_preflight(self):
        operations = (
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-storage",
            "worker-logs",
            "beat",
        )
        self.assertEqual(self.compose.count('profiles: ["operations"]'), len(operations))
        for service in operations:
            with self.subTest(service=service):
                block = self.service_block(service)
                self.assertIn('profiles: ["operations"]', block)
                self.assertIn(
                    "preflight:\n        condition: service_completed_successfully",
                    block,
                )

        for service in (
            "db",
            "rabbitmq-volume-init",
            "rabbitmq",
            "rabbitmq-provision",
            "db-provision",
            "migrate",
            "preflight",
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
            "db_password",
            "db_bootstrap_password",
            "db_migrator_password",
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
        ):
            with self.subTest(secret=name):
                self.assertIn(
                    f"file: ${{BACKUPSHEEP_SECRETS_DIR:-.secrets}}/{name}",
                    secrets,
                )
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

    def test_database_bootstrap_migrator_and_runtime_identities_are_separated(self):
        database = self.service_block("db")
        provisioner = self.service_block("db-provision")
        migrator = self.service_block("migrate")

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
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION is required", provisioner
        )
        self.assertIn("DB_HOST: db", provisioner)
        self.assertIn('DB_PORT: "5432"', provisioner)
        for secret_name in (
            "db_bootstrap_password",
            "db_migrator_password",
            "db_password",
        ):
            self.assertIn(f"- {secret_name}", provisioner)
        self.assertNotIn("django_secret_key", provisioner)
        self.assertNotIn("rabbitmq_password", provisioner)
        self.assertIn("- provision-database", provisioner)
        self.assertNotIn("- migrate-database", provisioner)

        self.assertIn(
            'DB_USER: "${DB_MIGRATOR_USER:-backupsheep_migrator}"', migrator
        )
        self.assertIn("DB_PASSWORD_FILE: /run/secrets/db_migrator_password", migrator)
        self.assertNotIn("db_bootstrap_password", migrator)
        self.assertIn(
            "db-provision:\n        condition: service_completed_successfully",
            migrator,
        )

        for service in (
            "preflight",
            "app",
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-storage",
            "worker-logs",
            "beat",
        ):
            with self.subTest(runtime_service=service):
                block = self.service_block(service)
                self.assertNotIn("db_bootstrap_password", block)
                self.assertNotIn("db_migrator_password", block)

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
        self.assertIn('user: "999:999"', database)
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
        for service in (
            "app",
            "worker-cloud",
            "worker-database",
            "worker-files",
            "worker-storage",
            "worker-logs",
        ):
            block = self.service_block(service)
            networks = block.split("\n    networks:\n", 1)[1].split(
                "\n    logging:", 1
            )[0]
            role_networks[service] = set(
                re.findall(r"^      ([a-z][a-z0-9-]+):(?: .*)?$", networks, re.MULTILINE)
            )
            self.assertIn("gw_priority: 1", networks)

        services = tuple(role_networks)
        for index, left in enumerate(services):
            for right in services[index + 1 :]:
                with self.subTest(left=left, right=right):
                    self.assertTrue(role_networks[left].isdisjoint(role_networks[right]))

    def test_backup_storage_is_read_only_outside_the_storage_worker(self):
        # The app retains read-only access solely for authenticated Local Storage
        # downloads. Source dump workers may inspect destinations but cannot mutate
        # them. The cloud/default worker has no proven read requirement at all.
        self.assertNotIn("/backups", self.service_block("worker-cloud"))
        for service in ("app", "worker-database", "worker-files"):
            with self.subTest(service=service):
                block = self.service_block(service)
                mount = block.split("target: /backups", 1)[1].split("\n", 2)
                self.assertIn("read_only: true", "\n".join(mount))

        storage_worker = self.service_block("worker-storage")
        self.assertIn("- backup_storage:/backups", storage_worker)

    def test_all_local_storage_mutations_route_to_storage_worker(self):
        settings = (ROOT / "backupsheep" / "settings.py").read_text(
            encoding="utf-8"
        )
        for task in (
            "validate_local_storage",
            "validate_pending_local_storages",
            "delete_backup_requested",
            "delete_storage_requested",
            "resume_requested_storage_deletions",
            "node_delete_requested",
            "resume_requested_node_deletions",
            "clean_delete_failed_backups",
            "delete_requested_integrations",
            "delete_requested_storages",
            "account_delete",
        ):
            with self.subTest(task=task):
                self.assertIn(f'"{task}": {{"queue": "storage"}}', settings)

    def test_web_and_notification_roles_cannot_modify_staged_artifacts(self):
        app = self.service_block("app")
        self.assertNotIn("source: backup_workdir", app)
        self.assertNotIn("- backup_workdir:/code/_storage", app)
        self.assertNotIn("ssh_trust:/var/lib/backupsheep/ssh-trust", app)
        self.assertNotIn("/code/_storage", self.service_block("worker-logs"))
        settings = (ROOT / "backupsheep" / "settings.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"delete_old_logs": {"queue": "storage"}', settings)
        self.assertIn('"reset_incremental_cache": {"queue": "storage"}', settings)

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
        self.assertIn("--user 0:0", guide)
        self.assertIn("chown -R 10001:10001 /code/_storage /backups", guide)
        self.assertIn("10001:10001:600", guide)

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
