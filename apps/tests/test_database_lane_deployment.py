import re
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DatabaseLaneDeploymentContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        cls.entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")

    def service_block(self, name):
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|^networks:\n)",
            self.compose,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing Compose service {name}")
        return match.group("body")

    def test_every_long_lived_lane_mounts_only_its_database_password(self):
        lanes = {
            "app": "app",
            "preflight": "preflight",
            "beat": "beat",
            "worker-cloud": "cloud",
            "worker-database": "database",
            "worker-files": "files",
            "worker-storage": "storage",
            "worker-logs": "logs",
        }
        for service, lane in lanes.items():
            block = self.service_block(service)
            with self.subTest(service=service, lane=lane):
                self.assertIn(f"BACKUPSHEEP_DATABASE_LANE: {lane}", block)
                self.assertIn(
                    f'DB_USER: "${{DB_{lane.upper()}_USER:-backupsheep_{lane}}}"',
                    block,
                )
                self.assertIn(
                    f"DB_PASSWORD_FILE: /run/secrets/db_{lane}_password", block
                )
                mounted = re.findall(r"^      - (db_[a-z]+_password)$", block, re.MULTILINE)
                self.assertEqual(mounted, [f"db_{lane}_password"])

    def test_only_provision_and_seal_receive_every_database_credential(self):
        expected = {
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
        }
        for service, phase in (("db-provision", "provision"), ("db-seal", "seal")):
            block = self.service_block(service)
            mounted = set(
                re.findall(r"^      - (db_[a-z]+_password)$", block, re.MULTILINE)
            )
            with self.subTest(service=service):
                self.assertEqual(mounted, expected)
                self.assertIn('BACKUPSHEEP_DATABASE_IDENTITY_GENERATION: "3"', block)
                self.assertIn(
                    f'["python", "-m", "backupsheep.database_identity", "{phase}"]',
                    block,
                )
                self.assertIn('DB_USER: ""', block)

        migrator = self.service_block("migrate")
        self.assertEqual(
            re.findall(r"^      - (db_[a-z]+_password)$", migrator, re.MULTILINE),
            ["db_migrator_password"],
        )

    def test_preflight_cannot_run_before_database_seal(self):
        preflight = self.service_block("preflight")
        self.assertRegex(
            preflight,
            r"db-seal:\n\s+condition: service_completed_successfully",
        )
        self.assertIn(
            "db-provision migrate db-seal", self.installer
        )
        self.assertLess(
            self.installer.index("wait_for_database_seal\n"),
            self.installer.index("complete_database_identity_generation\n"),
        )

    def test_legacy_shared_database_secret_is_absent_from_compose(self):
        self.assertNotIn("/run/secrets/db_password", self.compose)
        self.assertNotRegex(self.compose, r"(?m)^  db_password:")
        self.assertIn("provision|seal", self.entrypoint)
