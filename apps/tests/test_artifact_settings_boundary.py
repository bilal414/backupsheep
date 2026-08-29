"""Fresh-process startup tests for lane-scoped artifact keyring settings."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase
from dotenv import dotenv_values

from backupsheep.artifact_crypto.providers.local_file import canonical_keyring_bytes
from backupsheep.artifact_crypto.context import artifact_provider_policy_witness


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALLATION_ID = "a" * 64
KEY_ID = "lfk-11111111111111111111111111111111"


class ArtifactSettingsBoundaryTests(SimpleTestCase):
    def _keyring(self, root: Path, lane: str) -> Path:
        path = root / f"{lane}.keyring"
        path.write_bytes(
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane=lane,
                active_key_id=KEY_ID,
                keys=[(KEY_ID, "11" * 32)],
            )
        )
        path.chmod(0o400)
        return path

    def _import_settings(
        self,
        *,
        role: str,
        keyring_path: str = "",
        generation: str = "",
        witness: str = "",
        celery_lane: str = "__match_role__",
    ):
        environment = os.environ.copy()
        for name in (
            "BACKUPSHEEP_SECRETS",
            "BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY",
        ):
            environment.pop(name, None)
        environment.update(
            DJANGO_SERVER="dev",
            BACKUPSHEEP_RUNTIME_ROLE=role,
            BACKUPSHEEP_CELERY_LANE=(
                role if celery_lane == "__match_role__" else celery_lane
            ),
            BACKUPSHEEP_INSTALLATION_ID=INSTALLATION_ID,
            BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="bse1",
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE="false",
            BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE="false",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-file",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION=generation,
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS=witness,
            BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=keyring_path,
            BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID="local-v1",
        )
        return subprocess.run(
            [sys.executable, "-c", "import backupsheep.settings"],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_each_source_role_requires_its_exact_valid_lane_keyring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            database = self._keyring(root, "database")
            files = self._keyring(root, "files")
            for role, path in (("database", database), ("files", files)):
                with self.subTest(role=role):
                    result = self._import_settings(role=role, keyring_path=str(path))
                    self.assertEqual(result.returncode, 0, result.stderr)

            missing = self._import_settings(role="database")
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("requires its lane-scoped", missing.stderr)
            wrong_lane = self._import_settings(
                role="database",
                keyring_path=str(files),
            )
            self.assertNotEqual(wrong_lane.returncode, 0)
            self.assertIn("keyring is invalid", wrong_lane.stderr)

            missing_lane = self._import_settings(
                role="database",
                keyring_path=str(database),
                celery_lane="",
            )
            self.assertNotEqual(missing_lane.returncode, 0)
            self.assertIn("explicit matching BACKUPSHEEP_CELERY_LANE", missing_lane.stderr)
            mismatched_lane = self._import_settings(
                role="database",
                keyring_path=str(database),
                celery_lane="files",
            )
            self.assertNotEqual(mismatched_lane.returncode, 0)
            self.assertIn("explicit matching BACKUPSHEEP_CELERY_LANE", mismatched_lane.stderr)

    def test_every_non_source_role_rejects_a_keyring_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            path = str(self._keyring(root, "database"))
            for role in ("app", "beat", "cloud", "storage", "logs", "migration"):
                with self.subTest(role=role):
                    result = self._import_settings(role=role, keyring_path=path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Only database and files workers", result.stderr)

            permitted = self._import_settings(role="app")
            self.assertEqual(permitted.returncode, 0, permitted.stderr)

    def test_pending_provider_generation_is_migration_only_and_witness_bound(self):
        pending = "1-pending-empty"
        witness = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{INSTALLATION_ID}|local-file|generation={pending}"
            ).encode("ascii")
        ).hexdigest()

        migration = self._import_settings(
            role="migration",
            generation=pending,
            witness=witness,
        )
        self.assertEqual(migration.returncode, 0, migration.stderr)
        long_lived = self._import_settings(
            role="app",
            generation=pending,
            witness=witness,
        )
        self.assertNotEqual(long_lived.returncode, 0)
        self.assertIn("migration is pending", long_lived.stderr)
        wrong_witness = self._import_settings(
            role="migration",
            generation=pending,
            witness="0" * 64,
        )
        self.assertNotEqual(wrong_witness.returncode, 0)
        self.assertIn("witness does not match", wrong_witness.stderr)

    def test_direct_production_defaults_to_bse1_but_legacy_mode_is_explicit(self):
        base_config = dict(dotenv_values(PROJECT_ROOT / ".env_sample"))
        base_config.pop("BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE", None)
        base_config.update(
            DJANGO_SERVER="prod",
            DJANGO_SECRET_KEY="s" * 64,
            BACKUPSHEEP_INSTALLATION_ID=INSTALLATION_ID,
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE="false",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-file",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION="",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS="",
            BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH="",
            RABBITMQ_HOST="localhost",
            RABBITMQ_USER="settings-test",
            RABBITMQ_PASSWORD="p" * 32,
        )
        environment = os.environ.copy()
        environment.update(
            BACKUPSHEEP_RUNTIME_ROLE="app",
            BACKUPSHEEP_SECRETS=json.dumps(base_config),
        )
        program = (
            "from backupsheep import settings; "
            "print(settings.BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE); "
            "print(settings.BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE)"
        )
        missing_generation = subprocess.run(
            [sys.executable, "-c", program],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(missing_generation.returncode, 0)
        self.assertIn(
            "explicit sealed artifact key-provider generation",
            missing_generation.stderr,
        )

        base_config["BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION"] = "1"
        base_config["BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS"] = (
            artifact_provider_policy_witness(INSTALLATION_ID, "1")
        )
        environment["BACKUPSHEEP_SECRETS"] = json.dumps(base_config)
        hardened = subprocess.run(
            [sys.executable, "-c", program],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(hardened.returncode, 0, hardened.stderr)
        self.assertEqual(hardened.stdout.splitlines()[-2:], ["bse1", "False"])

        base_config["BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE"] = "legacy-only"
        base_config["BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE"] = "true"
        base_config["BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION"] = ""
        base_config["BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS"] = ""
        environment["BACKUPSHEEP_SECRETS"] = json.dumps(base_config)
        compatibility = subprocess.run(
            [sys.executable, "-c", program],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(compatibility.returncode, 0, compatibility.stderr)
        self.assertEqual(
            compatibility.stdout.splitlines()[-2:],
            ["legacy-only", "True"],
        )
