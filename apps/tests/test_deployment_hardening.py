from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DeploymentHardeningContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    def test_compose_binds_web_to_loopback_by_default(self):
        self.assertIn(
            "${BACKUPSHEEP_BIND_ADDRESS:-127.0.0.1}:"
            "${BACKUPSHEEP_BIND_PORT:-8000}:8000",
            self.compose,
        )
        self.assertNotIn('- "8000:8000"', self.compose)

    def test_compose_uses_supported_pinned_broker_without_guest_defaults(self):
        self.assertIn(
            "rabbitmq:4.3.5-alpine@sha256:"
            "d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7",
            self.compose,
        )
        self.assertIn("RABBITMQ_DEFAULT_PASS:", self.compose)
        self.assertIn("RABBITMQ_PASSWORD:?", self.compose)
        self.assertIn(
            '["CMD", "su-exec", "rabbitmq", "rabbitmq-diagnostics", "-q", "ping"]',
            self.compose,
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
        self.assertEqual(self.compose.count("logging: *default-logging"), 10)
        self.assertIn("max-size: \"${DOCKER_LOG_MAX_SIZE:-10m}\"", self.compose)
        self.assertIn("backend:\n    internal: true", self.compose)

    def test_application_image_and_compose_drop_runtime_privileges(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")
        env_sample = (ROOT / ".env_sample").read_text(encoding="utf-8")

        self.assertIn("useradd --uid 10001 --gid 10001", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("/code/_storage /backups", dockerfile)
        self.assertIn("/code/static", dockerfile)
        self.assertIn("umask 077", entrypoint)
        self.assertEqual(self.compose.count("<<: *app-runtime"), 8)
        self.assertIn("pids_limit: \"${BACKUPSHEEP_PIDS_LIMIT:-512}\"", self.compose)
        self.assertIn("cap_drop:\n    - ALL", self.compose)
        self.assertIn("security_opt:\n    - no-new-privileges:true", self.compose)
        self.assertIn("init: true", self.compose)
        self.assertIn("BACKUPSHEEP_PIDS_LIMIT=512", env_sample)
        self.assertNotIn('entrypoint: ["celery"', self.compose)
        self.assertNotIn('entrypoint: ["python", "manage.py", "migrate"', self.compose)

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
        self.assertIn('grep "^ONBOARDING_INSTALL_TOKEN="', installer)

    def test_installer_refuses_automatic_existing_broker_migration(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "guides" / "rabbitmq-upgrade.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("ENV_FILE_WAS_PRESENT", installer)
        self.assertIn("require an operator migration", installer)
        self.assertIn("install.sh` refuses", guide)

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
            "7325ac7755809ca3312b446bd832542421699298f25b701f9a111bb42df0c7c1",
            dockerfile,
        )
        self.assertIn("BCA43417C3B485DD128EC6D4B7B3B788A8D3785C", dockerfile)
        self.assertIn("gpg --batch --verify", dockerfile)
        self.assertNotIn("mariadb_repo_setup | bash", dockerfile)
        self.assertNotIn("oh-my-zsh", dockerfile)
