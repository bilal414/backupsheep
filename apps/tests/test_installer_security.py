import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"
SAMPLE_ENV = ROOT / ".env_sample"
COMMIT = "a" * 40


class InstallerSecurityContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.installer = INSTALLER.read_text(encoding="utf-8")

    def test_installer_never_provisions_or_reconfigures_the_host(self):
        forbidden = (
            "apt-get",
            "dnf ",
            "yum ",
            "apk add",
            "systemctl",
            "service docker",
            "/etc/apt",
            "/etc/docker",
            "ufw ",
            "iptables",
            "sysctl",
            "require_root",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.installer)

        self.assertIn("The Docker daemon is unavailable to this user", self.installer)
        self.assertIn("no host settings were changed", self.installer)
        self.assertIn("Do not run install.sh as root or through sudo", self.installer)
        self.assertIn("refuse_privileged_invocation", self.installer)

    def test_installer_fails_closed_on_unsupported_docker_versions(self):
        self.assertIn('semver_at_least "$engine_version" "28.0.0"', self.installer)
        self.assertIn('semver_at_least "$compose_version" "2.33.1"', self.installer)
        command = """
source "$1"
semver_at_least 28.0.0 28.0.0
semver_at_least 29.1.0-desktop.1 28.0.0
semver_at_least v2.33.1 2.33.1
semver_at_least 2.34.0-rc.1 2.33.1
! semver_at_least 27.9.9 28.0.0
! semver_at_least 2.33.0 2.33.1
! semver_at_least 2.33.1-rc.1 2.33.1
! semver_at_least latest 2.33.1
"""
        subprocess.run(
            ["bash", "-c", command, "installer-test", str(INSTALLER)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_installer_requires_an_exact_commit_and_matching_script(self):
        self.assertIn("^[0-9A-Fa-f]{40}$", self.installer)
        self.assertIn("GIT_ALLOW_PROTOCOL=https", self.installer)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", self.installer)
        self.assertIn("http.sslVerify=true", self.installer)
        self.assertIn('cmp -s -- "$SCRIPT_PATH" "$INSTALL_DIR/install.sh"', self.installer)
        self.assertIn("require_regular_checkout_file backupsheep-compose", self.installer)
        self.assertIn("require_regular_checkout_file Dockerfile.postgres", self.installer)
        self.assertIn("Mutable branches and tags are not accepted", self.installer)
        self.assertNotIn("DEFAULT_BRANCH", self.installer)
        self.assertNotIn("git clone --depth", self.installer)

    def test_installer_refuses_pipe_symlink_and_writable_source(self):
        self.assertIn("not a pipe, device or symlink", self.installer)
        self.assertIn("must not be writable by group or other users", self.installer)
        self.assertIn("must not be hard-linked", self.installer)
        self.assertNotRegex(self.installer, re.compile(r"curl[^\n]*\|[^\n]*(ba)?sh"))

    def test_installer_starts_only_the_core_without_explicit_operations_opt_in(self):
        self.assertIn(
            "readonly -a CORE_SERVICES=(db rabbitmq-volume-init rabbitmq rabbitmq-provision staging-provision db-provision migrate db-seal preflight app-egress-guard app)",
            self.installer,
        )
        self.assertIn('if [[ "$ENABLE_OPERATIONS" == true ]]', self.installer)
        self.assertIn("compose --profile operations up", self.installer)
        self.assertIn(
            '--force-recreate "${OPERATION_GUARD_SERVICES[@]}"', self.installer
        )
        self.assertIn('"${OPERATION_WORKER_SERVICES[@]}"', self.installer)
        self.assertIn(
            "compose --profile operations up --detach --no-build --no-deps beat",
            self.installer,
        )
        self.assertIn("compose --profile operations down --timeout 300", self.installer)
        stop_operations = self.installer.split("stop_operations() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertLess(
            stop_operations.index("refuse_egress_oneoffs_before_topology_removal"),
            stop_operations.index("compose --profile operations down --timeout 300"),
        )
        self.assertIn(
            "compose up --detach --no-build --no-deps --force-recreate",
            self.installer,
        )
        self.assertNotIn(
            'stop "${OPERATION_SERVICES[@]}" "${OPERATION_GUARD_SERVICES[@]}"',
            self.installer,
        )
        self.assertLess(
            self.installer.index("    stop_operations\n", self.installer.index("start_core()")),
            self.installer.index("    compose build --pull db app app-egress-guard", self.installer.index("start_core()")),
        )
        self.assertNotIn("up --build --detach --remove-orphans", self.installer)
        self.assertIn("/proc/1/task/1/children", self.installer)
        self.assertNotIn("celery -A backupsheep inspect ping", self.installer)
        self.assertIn("/run/backupsheep/celery-ready", self.installer)

    def test_installer_refuses_stranded_egress_oneoff_before_down(self):
        command = r'''
source "$1"
PROJECT_NAME=backupsheep
DOCKER_BIN=mock_docker
mock_docker() {
    if [[ "$1" == ps ]]; then
        printf 'oneoff-container\n'
        return 0
    fi
    return 91
}
docker_resource_label() {
    case "$3" in
        com.docker.compose.oneoff) printf 'True\n' ;;
        com.docker.compose.service) printf '%s\n' "${ONEOFF_SERVICE}" ;;
        *) return 92 ;;
    esac
}
refuse_egress_oneoffs_before_topology_removal
'''
        for service in ("app", "worker-storage"):
            with self.subTest(service=service):
                environment = os.environ.copy()
                environment["ONEOFF_SERVICE"] = service
                result = subprocess.run(
                    ["bash", "-c", command, "installer-test", str(INSTALLER)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"egress-backed Compose one-off for {service} still exists",
                    result.stderr,
                )

    def test_installer_mutation_lock_is_shared_portable_and_stale_fail_closed(self):
        wrapper = (ROOT / "backupsheep-compose").read_text(encoding="utf-8")
        self.assertIn(
            'mutation_lock_dir="${root_dir}.backupsheep-mutation-lock"', wrapper
        )
        self.assertIn(
            'MUTATION_LOCK_DIR="${INSTALL_DIR}.backupsheep-mutation-lock"',
            self.installer,
        )
        self.assertNotIn("command -v flock", wrapper)
        self.assertNotIn("command -v flock", self.installer)
        self.assertNotRegex(wrapper, re.compile(r"(?m)^\s*flock(?:\s|$)"))
        self.assertNotRegex(self.installer, re.compile(r"(?m)^\s*flock(?:\s|$)"))

        with tempfile.TemporaryDirectory(prefix="backupsheep-lock-test-") as directory:
            install_dir = Path(directory) / "installation"
            lock_dir = Path(f"{install_dir}.backupsheep-mutation-lock")
            command = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
[[ -d "$MUTATION_LOCK_DIR" && ! -L "$MUTATION_LOCK_DIR" ]]
[[ "$(file_mode "$MUTATION_LOCK_DIR")" == 700 ]]
[[ -f "$MUTATION_LOCK_OWNER_FILE" && ! -L "$MUTATION_LOCK_OWNER_FILE" ]]
[[ "$(file_mode "$MUTATION_LOCK_OWNER_FILE")" == 600 ]]
[[ "$(<"$MUTATION_LOCK_OWNER_FILE")" == "$MUTATION_LOCK_TOKEN" ]]
release_mutation_lock
[[ ! -e "$MUTATION_LOCK_DIR" && ! -L "$MUTATION_LOCK_DIR" ]]
'''
            subprocess.run(
                ["bash", "-c", command, "installer-lock-test", str(INSTALLER), str(install_dir)],
                check=True,
                capture_output=True,
                text=True,
            )

            lock_dir.mkdir(mode=0o700)
            owner = lock_dir / "owner"
            stale_value = "version=1;tool=install.sh;pid=999999;uid=0\n"
            owner.write_text(stale_value, encoding="utf-8")
            owner.chmod(0o600)
            stale = subprocess.run(
                ["bash", "-c", 'source "$1"; INSTALL_DIR="$2"; acquire_installation_mutation_lock',
                 "installer-lock-test", str(INSTALLER), str(install_dir)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("stale fail-closed lock remains", stale.stderr)
            self.assertEqual(owner.read_text(encoding="utf-8"), stale_value)

    def test_compose_control_plane_is_explicit(self):
        for token in (
            "/usr/bin/env -i",
            'unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES',
            'unset COMPOSE_REMOVE_ORPHANS',
            '"${compose_environment[@]}" "$DOCKER_BIN" compose',
            '--project-name "$PROJECT_NAME"',
            '--project-directory "$INSTALL_DIR"',
            '--env-file "$ENV_FILE"',
            '-f "$INSTALL_DIR/docker-compose.yml"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.installer)

        self.assertIn("validate_compose_project_ownership", self.installer)
        self.assertIn("com.backupsheep.installation-id", self.installer)
        self.assertIn("refusing cross-install reuse", self.installer)
        self.assertIn("DJANGO_SETTINGS_MODULE must be backupsheep.settings", self.installer)
        self.assertIn("contains BACKUPSHEEP_SECRETS", self.installer)

    def test_file_backed_secret_contract_is_fail_closed(self):
        self.assertIn('install -d -m 0700 -- "$SECRETS_DIR"', self.installer)
        self.assertIn('chmod 0444 "$temporary_file"', self.installer)
        self.assertIn('secret_links" == "1"', self.installer)
        self.assertIn("Unexpected entry in protected secret directory", self.installer)
        self.assertIn("exactly one non-empty logical line", self.installer)
        self.assertIn('set_env_value DJANGO_SECRET_KEY ""', self.installer)
        self.assertIn('set_env_value DB_PASSWORD ""', self.installer)
        self.assertIn('set_env_value RABBITMQ_PASSWORD ""', self.installer)
        self.assertIn('set_env_value ONBOARDING_INSTALL_TOKEN ""', self.installer)
        self.assertIn("ensure_installation_id", self.installer)
        self.assertIn("ensure_compose_project_name", self.installer)
        self.assertIn("Compose project drift refused", self.installer)
        self.assertIn("^[0-9a-f]{64}$", self.installer)
        self.assertNotIn("printf 'Onboarding token:", self.installer)

    def test_installer_fails_closed_on_unknown_broker_generation(self):
        self.assertIn("validate_rabbitmq_data_generation", self.installer)
        self.assertIn("rabbitmq-diagnostics -q server_version", self.installer)
        self.assertIn('exec --user rabbitmq "$rabbit_container_id"', self.installer)
        self.assertNotIn('exec --user 100:101 "$rabbit_container_id"', self.installer)
        self.assertIn("will not guess its format", self.installer)
        self.assertIn("exact pinned 4.3.5 target", self.installer)
        self.assertIn('[[ "$server_version" == "4.3.5" ]]', self.installer)

    def test_preflight_failure_is_terminal(self):
        self.assertIn("preflight_container_id", self.installer)
        self.assertIn("Docker security preflight failed", self.installer)
        self.assertIn(
            "logs --tail=100 rabbitmq-volume-init rabbitmq rabbitmq-provision db-provision migrate db-seal preflight app",
            self.installer,
        )
        self.assertIn("RabbitMQ identity provisioning failed", self.installer)
        self.assertIn("provision_container_id", self.installer)
        self.assertIn("Database identity provisioning failed", self.installer)


class InstallerSecretMigrationTests(TestCase):
    def setUp(self):
        self.temp_dir = Path(
            tempfile.mkdtemp(prefix="backupsheep-installer-test-")
        ).resolve()
        self.env_file = self.temp_dir / ".env"
        shutil.copyfile(SAMPLE_ENV, self.env_file)
        os.chmod(self.env_file, 0o600)
        content = self.env_file.read_text(encoding="utf-8")
        # Static canaries model a legacy plaintext installation; they are not
        # credentials and must disappear from .env during migration.
        self.legacy_canaries = {
            "framework": "d" * 64,
            "database": "p" * 32,
            "broker": "r" * 40,
            "onboarding": "o" * 40,
        }
        replacements = {
            "BACKUPSHEEP_COMPOSE_PROJECT_NAME=''": "BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'",
            "DJANGO_SECRET_KEY='change-this-key'": f"DJANGO_SECRET_KEY='{self.legacy_canaries['framework']}'",
            "DB_PASSWORD='change-this-password'": f"DB_PASSWORD='{self.legacy_canaries['database']}'",
            "RABBITMQ_PASSWORD=''": f"RABBITMQ_PASSWORD='{self.legacy_canaries['broker']}'",
            "ONBOARDING_INSTALL_TOKEN=''": f"ONBOARDING_INSTALL_TOKEN='{self.legacy_canaries['onboarding']}'",
        }
        for old, new in replacements.items():
            self.assertIn(old, content)
            content = content.replace(old, new, 1)
        # Model an installation created before generation-2 identities existed.
        content = content.replace("DB_USER='backupsheep_app'", "DB_USER='backupsheep'", 1)
        content = content.replace("RABBITMQ_USER='backupsheep_app'", "RABBITMQ_USER='backupsheep'", 1)
        content = "\n".join(
            line
            for line in content.splitlines()
            if not line.startswith(
                (
                    "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION=",
                    "DB_BOOTSTRAP_USER=",
                    "DB_MIGRATOR_USER=",
                    "DB_APP_USER=",
                    "DB_PREFLIGHT_USER=",
                    "DB_BEAT_USER=",
                    "DB_CLOUD_USER=",
                    "DB_DATABASE_USER=",
                    "DB_FILES_USER=",
                    "DB_STORAGE_USER=",
                    "DB_LOGS_USER=",
                    "BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION=",
                    "BACKUPSHEEP_CELERY_SECURITY_GENERATION=",
                    "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION=",
                    "RABBITMQ_LEGACY_USER=",
                )
            )
        ) + "\n"
        self.env_file.write_text(content, encoding="utf-8")
        os.chmod(self.env_file, 0o600)
        self.database_kms_credentials = self.temp_dir / "database-kms.ini"
        self.files_kms_credentials = self.temp_dir / "files-kms.ini"
        self.database_kms_credentials.write_text(
            "[default]\n"
            "aws_access_key_id = AKIADATABASE00001\n"
            f"aws_secret_access_key = {'d' * 40}\n",
            encoding="utf-8",
        )
        self.files_kms_credentials.write_text(
            "[default]\n"
            "aws_access_key_id = AKIAFILES00000001\n"
            f"aws_secret_access_key = {'f' * 40}\n",
            encoding="utf-8",
        )
        os.chmod(self.database_kms_credentials, 0o600)
        os.chmod(self.files_kms_credentials, 0o600)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def run_installer_functions(self, body, *, check=True):
        command = f"""
source "$1"
INSTALL_DIR="$2"
INSTALL_REF="$3"
PUBLIC_HOST=localhost
APP_DOMAIN=localhost:8000
INSTALL_WAS_PRESENT=true
ARTIFACT_KMS_KEY_ID='arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555'
ARTIFACT_KMS_REGION='us-east-1'
ARTIFACT_KMS_ALLOWED_KEY_ARNS="$ARTIFACT_KMS_KEY_ID"
ARTIFACT_KMS_DATABASE_AWS_CREDENTIALS_FILE="$2/database-kms.ini"
ARTIFACT_KMS_FILES_AWS_CREDENTIALS_FILE="$2/files-kms.ini"
ENV_FILE="$2/.env"
DOCKER_BIN=mock_docker
mock_docker() {{
    if [[ "$1" == volume && "$2" == ls && "$3" == --format ]]; then
        return 0
    fi
    return 64
}}
if [[ -z "$(read_env_value BACKUPSHEEP_STAGING_LAYOUT_INTENT)" ]]; then
    MIGRATE_STAGING_LAYOUT=true
fi
{body}
"""
        return subprocess.run(
            ["bash", "-c", command, "installer-test", str(INSTALLER), str(self.temp_dir), COMMIT],
            check=check,
            capture_output=True,
            text=True,
        )

    def test_existing_env_secrets_migrate_atomically_and_rerun_without_rotation(self):
        self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration\nvalidate_runtime_configuration"
        )

        secret_dir = self.temp_dir / ".secrets"
        self.assertEqual(stat.S_IMODE(secret_dir.stat().st_mode), 0o700)
        expected = {
            "django_secret_key": f"{self.legacy_canaries['framework']}\n",
            "db_bootstrap_password": f"{self.legacy_canaries['database']}\n",
            "rabbitmq_bootstrap_password": f"{self.legacy_canaries['broker']}\n",
            "onboarding_token": f"{self.legacy_canaries['onboarding']}\n",
        }
        for filename, value in expected.items():
            secret_path = secret_dir / filename
            with self.subTest(secret=filename):
                self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o444)
                self.assertEqual(secret_path.stat().st_nlink, 1)
                self.assertEqual(secret_path.read_text(encoding="utf-8"), value)

        migrated_env = self.env_file.read_text(encoding="utf-8")
        for secret in expected.values():
            self.assertNotIn(secret.strip(), migrated_env)
        self.assertIn("BACKUPSHEEP_SECRETS_DIR='.secrets'", migrated_env)
        self.assertRegex(
            migrated_env,
            r"BACKUPSHEEP_INSTALLATION_ID='[0-9a-f]{64}'",
        )
        self.assertIn("DJANGO_SECRET_KEY=''", migrated_env)
        self.assertIn(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3-pending-upgrade'",
            migrated_env,
        )
        self.assertIn("DB_BOOTSTRAP_USER='backupsheep'", migrated_env)
        self.assertIn("DB_MIGRATOR_USER='backupsheep_migrator'", migrated_env)
        for lane in (
            "app",
            "preflight",
            "beat",
            "cloud",
            "database",
            "files",
            "storage",
            "logs",
        ):
            self.assertIn(
                f"DB_{lane.upper()}_USER='backupsheep_{lane}'", migrated_env
            )
        self.assertIn("DB_USER='backupsheep_app'", migrated_env)
        self.assertIn("DB_PASSWORD=''", migrated_env)
        self.assertIn("BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION='2'", migrated_env)
        self.assertIn("BACKUPSHEEP_CELERY_SECURITY_GENERATION='3'", migrated_env)
        self.assertIn(
            "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION='1'", migrated_env
        )
        self.assertIn("RABBITMQ_USER='backupsheep_app'", migrated_env)
        self.assertIn("RABBITMQ_LEGACY_USER='backupsheep'", migrated_env)
        self.assertIn("RABBITMQ_PASSWORD=''", migrated_env)
        self.assertIn("SSH_MANAGED_PRIVATE_KEY_PATH=''", migrated_env)
        self.assertIn(f"BACKUPSHEEP_IMAGE='backupsheep:{COMMIT}'", migrated_env)
        self.assertIn(
            f"BACKUPSHEEP_POSTGRES_IMAGE='backupsheep-postgres:{COMMIT}'",
            migrated_env,
        )
        self.assertIn(
            f"BACKUPSHEEP_EGRESS_IMAGE='backupsheep-egress:{COMMIT}'",
            migrated_env,
        )
        self.assertIn(
            "BACKUPSHEEP_STAGING_LAYOUT_INTENT='migrate-empty-legacy-v3'",
            migrated_env,
        )
        database_kms = secret_dir / "artifact_kms_database_aws_credentials"
        files_kms = secret_dir / "artifact_kms_files_aws_credentials"
        self.assertEqual(stat.S_IMODE(database_kms.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(files_kms.stat().st_mode), 0o444)
        self.assertNotEqual(database_kms.read_bytes(), files_kms.read_bytes())
        self.assertFalse((secret_dir / "ssh_managed_private_key").exists())
        for lane in ("database", "files"):
            managed_key = secret_dir / f"ssh_managed_{lane}_private_key"
            self.assertEqual(stat.S_IMODE(managed_key.stat().st_mode), 0o444)
            self.assertEqual(managed_key.read_bytes(), b"")
        for generated_name in (
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
            generated_value = (secret_dir / generated_name).read_text(encoding="utf-8")
            self.assertRegex(generated_value, r"^[0-9a-f]{64}\n$")
            self.assertNotEqual(
                generated_value.strip(), self.legacy_canaries["database"]
            )
        rabbit_passwords = []
        for role in (
            "bootstrap",
            "app",
            "preflight",
            "beat",
            "cloud",
            "database",
            "files",
            "storage",
            "logs",
        ):
            value = (secret_dir / f"rabbitmq_{role}_password").read_text(
                encoding="utf-8"
            )
            if role == "bootstrap":
                self.assertEqual(value, f"{self.legacy_canaries['broker']}\n")
            else:
                self.assertRegex(value, r"^[0-9a-f]{64}\n$")
            rabbit_passwords.append(value)
        self.assertEqual(len(rabbit_passwords), len(set(rabbit_passwords)))
        for lane in ("app", "beat", "cloud", "database", "files", "storage", "logs"):
            key_path = secret_dir / f"celery_signing_{lane}_private_key"
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o444)
            self.assertIn("BEGIN OPENSSH PRIVATE KEY", key_path.read_text(encoding="utf-8"))
        registry = (secret_dir / "celery_trusted_public_keys").read_text(
            encoding="utf-8"
        )
        self.assertIn('"installation_id"', registry)
        self.assertIn('"version":2', registry)
        self.assertIn('"generation":1', registry)
        self.assertIn('"keys"', registry)

        before = {path.name: path.read_bytes() for path in secret_dir.iterdir()}
        self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "create_or_migrate_configuration\nvalidate_runtime_configuration"
        )
        after = {path.name: path.read_bytes() for path in secret_dir.iterdir()}
        self.assertEqual(before, after)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "complete_database_identity_generation\n"
            "validate_runtime_configuration"
        )
        completed_env = self.env_file.read_text(encoding="utf-8")
        self.assertIn(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3'", completed_env
        )
        self.assertFalse((secret_dir / "db_password").exists())
        completed = {
            path.name: path.read_bytes() for path in secret_dir.iterdir()
        }
        self.run_installer_functions(
            "create_or_migrate_configuration\nvalidate_runtime_configuration"
        )
        rerun = {path.name: path.read_bytes() for path in secret_dir.iterdir()}
        self.assertEqual(completed, rerun)

    def test_existing_database_identity_transition_requires_explicit_opt_in(self):
        result = self.run_installer_functions(
            "create_or_migrate_configuration", check=False
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--migrate-database-identities", result.stderr)
        self.assertIn("encrypted rollback", result.stderr)
        self.assertNotIn(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3'",
            self.env_file.read_text(encoding="utf-8"),
        )
        secret_dir = self.temp_dir / ".secrets"
        self.assertFalse((secret_dir / "db_bootstrap_password").exists())
        self.assertFalse((secret_dir / "db_migrator_password").exists())

    def test_generation_two_task_auth_requires_resumable_explicit_rotation(self):
        self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration"
        )
        secret_dir = self.temp_dir / ".secrets"
        registry_path = secret_dir / "celery_trusted_public_keys"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        legacy_registry = {
            "version": 1,
            "installation_id": registry["installation_id"],
            "keys": registry["keys"],
        }
        registry_path.chmod(0o600)
        registry_path.write_text(
            json.dumps(legacy_registry, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        registry_path.chmod(0o444)
        configured = self.env_file.read_text(encoding="utf-8")
        configured = configured.replace(
            "BACKUPSHEEP_CELERY_SECURITY_GENERATION='3'",
            "BACKUPSHEEP_CELERY_SECURITY_GENERATION='2'",
            1,
        ).replace(
            "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION='1'",
            "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION=''",
            1,
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)

        refused = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "configure_rabbitmq_identity_generation",
            check=False,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("--rotate-celery-signing-keys", refused.stderr)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "ROTATE_CELERY_SIGNING_KEYS=true\n"
            "configure_rabbitmq_identity_generation\n"
            "validate_secret_dir"
        )
        pending = self.env_file.read_text(encoding="utf-8")
        self.assertIn(
            "BACKUPSHEEP_CELERY_SECURITY_GENERATION='3-pending-rotation'",
            pending,
        )
        self.assertIn(
            "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION='2'", pending
        )
        for lane in ("app", "beat", "cloud", "database", "files", "storage", "logs"):
            candidate = secret_dir / f".celery_rotation_{lane}_private_key"
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o444)
        candidate_registry = json.loads(
            (secret_dir / ".celery_rotation_trusted_public_keys").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(candidate_registry["version"], 2)
        self.assertEqual(candidate_registry["generation"], 2)

    def test_kms_lane_credentials_require_distinct_access_key_identities(self):
        self.files_kms_credentials.write_text(
            "[default]\n"
            "aws_access_key_id = AKIADATABASE00001\n"
            f"aws_secret_access_key = {'f' * 40}\n",
            encoding="utf-8",
        )
        os.chmod(self.files_kms_credentials, 0o600)
        result = self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different AWS access-key identities", result.stderr)

    def test_ambiguous_partial_database_secret_transition_fails_closed(self):
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        for name in ("db_password", "db_migrator_password"):
            path = secret_dir / name
            path.write_text("x" * 32 + "\n", encoding="utf-8")
            path.chmod(0o444)

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "configure_database_identity_generation",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete or ambiguous", result.stderr)
        self.assertFalse((secret_dir / "db_bootstrap_password").exists())

    def test_fresh_database_identity_configuration_generates_per_lane_credentials(self):
        shutil.copyfile(SAMPLE_ENV, self.env_file)
        os.chmod(self.env_file, 0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=false\n"
            "set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION 3-pending-fresh\n"
            "configure_database_identity_generation"
        )

        configured = self.env_file.read_text(encoding="utf-8")
        self.assertIn(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3-pending-fresh'",
            configured,
        )
        for name in (
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
            self.assertRegex(
                (secret_dir / name).read_text(encoding="utf-8"),
                r"^[0-9a-f]{64}\n$",
            )

    def test_interrupted_fresh_database_identity_configuration_resumes_exactly(self):
        shutil.copyfile(SAMPLE_ENV, self.env_file)
        os.chmod(self.env_file, 0o600)
        content = self.env_file.read_text(encoding="utf-8").replace(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION=''",
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3-pending-fresh'",
            1,
        )
        self.env_file.write_text(content, encoding="utf-8")
        os.chmod(self.env_file, 0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        bootstrap = secret_dir / "db_bootstrap_password"
        bootstrap.write_text("b" * 64 + "\n", encoding="utf-8")
        bootstrap.chmod(0o444)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "configure_database_identity_generation"
        )

        self.assertEqual(bootstrap.read_text(encoding="utf-8"), "b" * 64 + "\n")
        self.assertTrue((secret_dir / "db_migrator_password").is_file())
        for lane in (
            "app",
            "preflight",
            "beat",
            "cloud",
            "database",
            "files",
            "storage",
            "logs",
        ):
            self.assertTrue((secret_dir / f"db_{lane}_password").is_file())
        self.assertIn(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION='3-pending-fresh'",
            self.env_file.read_text(encoding="utf-8"),
        )

    def test_database_image_tag_is_persisted_and_tampering_fails_closed(self):
        self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration"
        )
        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            'set_env_value BACKUPSHEEP_POSTGRES_IMAGE "attacker/postgres:latest"\n'
            "validate_runtime_configuration",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"BACKUPSHEEP_POSTGRES_IMAGE must be backupsheep-postgres:{COMMIT}",
            result.stderr,
        )

    def test_persisted_compose_project_name_refuses_drift(self):
        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'PROJECT_NAME="different-project"\n'
            "ensure_compose_project_name",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Compose project drift refused", result.stderr)

    def test_existing_install_without_egress_generation_requires_explicit_migration(self):
        result = self.run_installer_functions(
            'set_env_value BACKUPSHEEP_EGRESS_POLICY_GENERATION ""\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_EGRESS_POLICY=false\n"
            "configure_egress_policy_generation",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rerun once with --migrate-egress-policy", result.stderr)

    def test_old_stock_public_egress_is_reset_to_generation_two_deny(self):
        self.run_installer_functions(
            'set_env_value BACKUPSHEEP_EGRESS_POLICY_GENERATION ""\n'
            'for role in "${EGRESS_ROLES[@]}"; do\n'
            '  set_env_value "BACKUPSHEEP_${role}_EGRESS_MODE" public\n'
            "done\n"
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_EGRESS_POLICY=true\n"
            "configure_egress_policy_generation"
        )
        configured = self.env_file.read_text(encoding="utf-8")
        self.assertIn("BACKUPSHEEP_EGRESS_POLICY_GENERATION='2'", configured)
        for role in ("APP", "CLOUD", "DATABASE", "FILES", "STORAGE", "LOGS"):
            self.assertIn(f"BACKUPSHEEP_{role}_EGRESS_MODE='deny'", configured)
            for suffix in (
                "ALLOW_IPV4",
                "ALLOW_IPV6",
                "ALLOW_IPV4_TCP_ENDPOINTS",
                "ALLOW_IPV6_TCP_ENDPOINTS",
                "ALLOW_DNS_NAMES",
            ):
                self.assertIn(f"BACKUPSHEEP_{role}_EGRESS_{suffix}=''", configured)

    def test_custom_or_mixed_legacy_egress_is_never_guessed(self):
        original = self.env_file.read_text(encoding="utf-8")
        scenarios = (
            'set_env_value BACKUPSHEEP_APP_EGRESS_ALLOW_IPV4 "203.0.113.1/32"',
            'set_env_value BACKUPSHEEP_APP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS "203.0.113.1/32:443"',
            'set_env_value BACKUPSHEEP_APP_EGRESS_MODE allowlist',
        )
        for setup in scenarios:
            with self.subTest(setup=setup):
                self.env_file.write_text(original, encoding="utf-8")
                os.chmod(self.env_file, 0o600)
                result = self.run_installer_functions(
                    'set_env_value BACKUPSHEEP_EGRESS_POLICY_GENERATION ""\n'
                    'for role in "${EGRESS_ROLES[@]}"; do\n'
                    '  set_env_value "BACKUPSHEEP_${role}_EGRESS_MODE" public\n'
                    "done\n"
                    f"{setup}\n"
                    "ENV_WAS_PRESENT=true\n"
                    "MIGRATE_EGRESS_POLICY=true\n"
                    "configure_egress_policy_generation",
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Customized legacy egress", result.stderr)

    def test_generation_two_egress_validation_is_fail_closed(self):
        original = self.env_file.read_text(encoding="utf-8")
        scenarios = (
            (
                'set_env_value BACKUPSHEEP_APP_EGRESS_ALLOW_IPV4 "203.0.113.1/32"',
                "Address-only APP egress allowlists are retired",
            ),
            (
                'set_env_value BACKUPSHEEP_APP_EGRESS_MODE allowlist',
                "Allowlist-mode APP egress requires at least one exact TCP endpoint",
            ),
            (
                'set_env_value BACKUPSHEEP_APP_EGRESS_MODE public\n'
                'set_env_value BACKUPSHEEP_APP_EGRESS_ALLOW_DNS_NAMES provider.example',
                "must not carry an ignored exact-name list",
            ),
        )
        for setup, message in scenarios:
            with self.subTest(setup=setup):
                self.env_file.write_text(original, encoding="utf-8")
                os.chmod(self.env_file, 0o600)
                result = self.run_installer_functions(
                    f"{setup}\nconfigure_egress_policy_generation",
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_egress_migration_flag_is_one_time(self):
        result = self.run_installer_functions(
            "MIGRATE_EGRESS_POLICY=true\nconfigure_egress_policy_generation",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("one-time", result.stderr)

    def test_only_exact_private_deployment_override_is_approved_in_canonical_history(self):
        override = self.temp_dir / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        os.chmod(override, 0o600)
        result = self.run_installer_functions(
            f'APPROVED_COMPOSE_FILE="{override}"\n'
            "validate_approved_compose_file\n"
            "expected_compose_config_files"
        )
        self.assertEqual(
            result.stdout,
            f"{self.temp_dir}/docker-compose.yml,{override.resolve()}",
        )

        foreign = self.temp_dir / "foreign.yml"
        foreign.write_text("services: {}\n", encoding="utf-8")
        os.chmod(foreign, 0o600)
        result = self.run_installer_functions(
            f'APPROVED_COMPOSE_FILE="{foreign}"\nvalidate_approved_compose_file',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("accepts only", result.stderr)

        override.unlink()
        override.symlink_to(foreign)
        result = self.run_installer_functions(
            f'APPROVED_COMPOSE_FILE="{override}"\nvalidate_approved_compose_file',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular, non-symlink", result.stderr)

    def test_approved_compose_file_option_rejects_duplicates(self):
        result = subprocess.run(
            [
                "/bin/bash", "-c", 'source "$1"; parse_args '
                '--approved-compose-file /one --approved-compose-file=/two',
                "installer-test", str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("may be specified only once", result.stderr)

    def test_symlinked_secret_is_rejected_without_disclosing_value(self):
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        target = self.temp_dir / "target"
        target.write_text("do-not-disclose\n", encoding="utf-8")
        (secret_dir / "django_secret_key").symlink_to(target)

        result = self.run_installer_functions(
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            'validate_secret_file "$SECRETS_DIR/django_secret_key"',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular non-symlink", result.stderr)
        self.assertNotIn("do-not-disclose", result.stdout + result.stderr)

    def test_empty_legacy_onboarding_token_is_replaced_with_a_random_secret(self):
        content = self.env_file.read_text(encoding="utf-8")
        content = content.replace(
            f"ONBOARDING_INSTALL_TOKEN='{self.legacy_canaries['onboarding']}'",
            "ONBOARDING_INSTALL_TOKEN=''",
            1,
        )
        self.env_file.write_text(content, encoding="utf-8")
        os.chmod(self.env_file, 0o600)

        self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration"
        )
        token = (self.temp_dir / ".secrets" / "onboarding_token").read_text(
            encoding="utf-8"
        )
        self.assertRegex(token, r"^[0-9a-f]{64}\n$")

    def test_existing_managed_key_path_requires_explicit_secret_migration(self):
        content = self.env_file.read_text(encoding="utf-8")
        content = content.replace(
            "SSH_MANAGED_PRIVATE_KEY_PATH=''",
            "SSH_MANAGED_PRIVATE_KEY_PATH='_storage/legacy-managed-key'",
            1,
        )
        self.env_file.write_text(content, encoding="utf-8")
        os.chmod(self.env_file, 0o600)

        result = self.run_installer_functions(
            "MIGRATE_DATABASE_IDENTITIES=true\n"
            "MIGRATE_RABBITMQ_IDENTITIES=true\n"
            "create_or_migrate_configuration",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(".secrets/ssh_managed_private_key", result.stderr)
        self.assertFalse(
            (self.temp_dir / ".secrets" / "ssh_managed_private_key").exists()
        )

    def test_multiline_secret_without_final_newline_is_rejected(self):
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        secret_path = secret_dir / "django_secret_key"
        secret_path.write_bytes(b"first\nsecond")
        # Installer-managed secrets are intentionally exact 0444 so the
        # unprivileged container identities can read Docker's bind mount.
        secret_path.chmod(0o444)
        self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o444)

        result = self.run_installer_functions(
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            'validate_secret_file "$SECRETS_DIR/django_secret_key"',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one non-empty logical line", result.stderr)

    def test_hardlinked_secret_is_rejected(self):
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        first = secret_dir / "django_secret_key"
        first.write_text("secret\n", encoding="utf-8")
        first.chmod(0o444)
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o444)
        os.link(first, self.temp_dir / "second-link")

        result = self.run_installer_functions(
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            'validate_secret_file "$SECRETS_DIR/django_secret_key"',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not hard-linked", result.stderr)

    def test_compose_control_variable_in_env_is_rejected(self):
        original = self.env_file.read_text(encoding="utf-8")
        for key, value in (
            ("COMPOSE_FILE", "/tmp/attacker.yml"),
            ("COMPOSE_BAKE", "true"),
            ("BUILDX_BAKE_FILE", "/tmp/attacker.hcl"),
            ("DOCKER_BUILDKIT", "0"),
            ("DOCKER_DEFAULT_PLATFORM", "linux/amd64"),
        ):
            with self.subTest(key=key):
                self.env_file.write_text(
                    original + f"{key}={value}\n", encoding="utf-8"
                )
                os.chmod(self.env_file, 0o600)
                result = self.run_installer_functions(
                    'ENV_FILE="$INSTALL_DIR/.env"\nvalidate_env_file',
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Docker/Compose control variable", result.stderr)
        self.env_file.write_text(original, encoding="utf-8")
        os.chmod(self.env_file, 0o600)

    def test_nul_bytes_in_env_are_rejected_before_awk_parsing(self):
        original = self.env_file.read_bytes()
        expected = b"BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'"
        self.assertIn(expected, original)
        for replacement in (
            b"BACKUPSHEEP_COMPOSE_PROJECT_NAME=backupsheep\x00evil",
            b"BACKUPSHEEP_COMPOSE_PROJECT_NAME=\x00backupsheep",
        ):
            with self.subTest(replacement=replacement):
                self.env_file.write_bytes(original.replace(expected, replacement, 1))
                os.chmod(self.env_file, 0o600)
                result = self.run_installer_functions(
                    'ENV_FILE="$INSTALL_DIR/.env"\nvalidate_env_file',
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("NUL byte", result.stderr)

    def test_json_configuration_replacement_is_rejected(self):
        with self.env_file.open("a", encoding="utf-8") as handle:
            handle.write("BACKUPSHEEP_SECRETS='{}'\n")
        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\nvalidate_env_file',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contains BACKUPSHEEP_SECRETS", result.stderr)

    def test_remove_orphans_is_rejected_in_env_and_unset_from_invoking_shell(self):
        with self.env_file.open("a", encoding="utf-8") as handle:
            handle.write("COMPOSE_REMOVE_ORPHANS=1\n")
        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\nvalidate_env_file',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker/Compose control variable", result.stderr)

        mock_docker = self.temp_dir / "mock-docker"
        mock_docker.write_text(
            "#!/bin/bash\n"
            "[[ \"${COMPOSE_REMOVE_ORPHANS-}\" == '0' ]] || exit 41\n"
            "[[ -z \"${BACKUPSHEEP_BIND_ADDRESS+x}\" ]] || exit 42\n"
            "[[ -z \"${BACKUPSHEEP_SECRETS_DIR+x}\" ]] || exit 43\n"
            "[[ \"${DOCKER_HOST-}\" == 'ssh://reviewed-daemon' ]] || exit 44\n"
            "[[ \"${COMPOSE_BAKE-}\" == 'false' ]] || exit 45\n"
            "[[ -z \"${BUILDX_BAKE_FILE+x}\" ]] || exit 46\n"
            "[[ -z \"${DOCKER_BUILDKIT+x}\" ]] || exit 47\n"
            "[[ \"${LC_ALL-}\" == 'C' ]] || exit 48\n"
            "exit 0\n",
            encoding="utf-8",
        )
        mock_docker.chmod(0o700)

        command = r'''
source "$1"
INSTALL_DIR=/srv/backupsheep
ENV_FILE=/srv/backupsheep/.env
PROJECT_NAME=backupsheep
DOCKER_BIN="$2"
compose config --quiet
'''
        environment = os.environ.copy()
        environment.update(
            COMPOSE_REMOVE_ORPHANS="1",
            BACKUPSHEEP_BIND_ADDRESS="0.0.0.0",
            BACKUPSHEEP_SECRETS_DIR="/tmp/attacker-secrets",
            DOCKER_HOST="ssh://reviewed-daemon",
            COMPOSE_BAKE="true",
            BUILDX_BAKE_FILE="/tmp/attacker-bake.hcl",
            DOCKER_BUILDKIT="0",
        )
        subprocess.run(
            [
                "/bin/bash",
                "-c",
                command,
                "installer-test",
                str(INSTALLER),
                str(mock_docker),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_loader_and_tls_key_log_variables_in_env_are_rejected(self):
        for key in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "SSLKEYLOGFILE"):
            with self.subTest(key=key):
                original = self.env_file.read_text(encoding="utf-8")
                self.env_file.write_text(
                    original + f"{key}=/tmp/attacker-controlled\n",
                    encoding="utf-8",
                )
                os.chmod(self.env_file, 0o600)
                result = self.run_installer_functions(
                    'ENV_FILE="$INSTALL_DIR/.env"\nvalidate_env_file',
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("forbidden loader or TLS-key-logging", result.stderr)
                self.env_file.write_text(original, encoding="utf-8")
                os.chmod(self.env_file, 0o600)

    def test_connection_url_override_is_rejected_without_disclosing_credentials(self):
        content = self.env_file.read_text(encoding="utf-8")
        content = content.replace(
            "DATABASE_URL=''",
            "DATABASE_URL='postgresql://victim:do-not-print@example.invalid/db'",
            1,
        )
        self.env_file.write_text(content, encoding="utf-8")
        os.chmod(self.env_file, 0o600)

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\nreject_connection_url_overrides',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATABASE_URL is not accepted", result.stderr)
        self.assertNotIn("do-not-print", result.stdout + result.stderr)


class InstallerLegacyProjectAdoptionTests(TestCase):
    installation_id = "a" * 64
    legacy_volume_names = (
        "backupsheep_pgdata",
        "backupsheep_rabbitmq_data",
        "backupsheep_backup_workdir",
        "backupsheep_backup_storage",
    )

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="backupsheep-adoption-test-"))
        self.event_log = self.temp_dir / "events"

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def run_adoption(
        self, scenario="exact", *, full_ownership=False, direct=False,
        adopt_legacy=True,
    ):
        if direct:
            invocation = "adopt_legacy_compose_down_project"
        elif full_ownership:
            invocation = (
                "ensure_compose_project_name\n"
                "INSTALL_WAS_PRESENT=true\n"
                "validate_compose_project_ownership"
            )
        else:
            invocation = "ensure_compose_project_name"

        command = rf'''
source "$1"
INSTALL_DIR=/srv/backupsheep
ENV_FILE=/srv/backupsheep/.env
PROJECT_NAME=backupsheep
ADOPT_LEGACY_PROJECT={"backupsheep" if adopt_legacy else ""}
ENV_WAS_PRESENT=true
DOCKER_BIN=mock_docker
INSTALLATION_ID={self.installation_id}
POSTGRES_MIGRATION_REQUIRED=true

read_env_value() {{
    case "$1" in
        BACKUPSHEEP_COMPOSE_PROJECT_NAME) : ;;
        BACKUPSHEEP_INSTALLATION_ID) printf '%s' "$INSTALLATION_ID" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_GENERATION) printf '%s' '18-alpine-icu-v1-pending-upgrade' ;;
        BACKUPSHEEP_POSTGRES_STORAGE_INTENT) printf '%s' 'migrated-debian-v1' ;;
        BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID) printf '%s' 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
        *) : ;;
    esac
}}

set_env_value() {{ printf 'SET:%s=%s\n' "$1" "$2" >> "$EVENT_LOG"; }}

legacy_volume_listing() {{
    case "$SCENARIO" in
        missing_volume)
            printf '%s\n' \
                backupsheep_pgdata \
                backupsheep_rabbitmq_data \
                backupsheep_backup_workdir
            ;;
        extra_volume)
            printf '%s\n' \
                backupsheep_pgdata \
                backupsheep_rabbitmq_data \
                backupsheep_backup_workdir \
                backupsheep_backup_storage \
                backupsheep_extra
            ;;
        *)
            printf '%s\n' \
                backupsheep_pgdata \
                backupsheep_rabbitmq_data \
                backupsheep_backup_workdir \
                backupsheep_backup_storage
            ;;
    esac
}}

emit_label() {{
    local label_value="${{1-}}"
    local LC_ALL=C
    printf '%s:%s%s\n' "${{#label_value}}" "$label_value" \
        '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
}}

emit_project_label() {{
    case "$SCENARIO" in
        *_project_option) emit_label --version ;;
        *_project_uppercase) emit_label BackupSheep ;;
        *_project_embedded_lf)
            printf '17:backupsheep\nother%s\n' \
                '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
            ;;
        *_project_trailing_lf)
            printf '12:backupsheep\n%s\n' \
                '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
            ;;
        *_project_nul)
            printf '12:backupsheep\0%s\n' \
                '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
            ;;
        *_project_marker)
            emit_label 'backupsheep__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
            ;;
        *_project_utf8) emit_label 'backupsheepé' ;;
        *) emit_label backupsheep ;;
    esac
}}

mock_docker() {{
    local template="" resource_id="" last_arg=""
    local saw_project=false saw_logical=false saw_installation=false

    if [[ "$1" == ps ]]; then
        [[ "$SCENARIO" != container_inventory_error ]] || return 71
        if [[ "$SCENARIO" == container_project_* ]]; then
            printf 'legacy-container\n'
        elif [[ "$SCENARIO" == existing_container && "${{4:-}}" == --filter ]]; then
            printf 'legacy-container\n'
        fi
        return 0
    fi
    if [[ "$1" == network && "$2" == ls ]]; then
        [[ "$SCENARIO" != network_inventory_error ]] || return 72
        if [[ "$SCENARIO" == existing_network && "${{3:-}}" == --quiet ]]; then
            printf 'legacy-network\n'
        fi
        return 0
    fi
    if [[ "$1" == volume && "$2" == ls ]]; then
        if [[ "$3" == --format ]]; then
            [[ "$SCENARIO" != full_name_inventory_error ]] || return 73
            legacy_volume_listing
            [[ "$SCENARIO" != sentinel_name_collision ]] \
                || printf 'backupsheep_installation_identity\n'
            [[ "$SCENARIO" != ssh_trust_collision ]] \
                || printf 'backupsheep_ssh_trust\n'
            [[ "$SCENARIO" != unlabeled_prefix_extra ]] \
                || printf 'backupsheep_evil\n'
            [[ ! -f "$EVENT_LOG" || ! $(grep -c '^CREATE:' "$EVENT_LOG") -gt 0 ]] \
                || printf 'backupsheep_installation_identity\n'
            return 0
        fi
        if [[ "${{5:-}}" == label=com.backupsheep.installation-id=* ]]; then
            [[ "$SCENARIO" == sentinel_project_* ]] \
                && printf 'backupsheep_installation_identity\n'
            return 0
        fi
        [[ "$SCENARIO" != volume_inventory_error ]] || return 74
        legacy_volume_listing
        [[ ! -f "$EVENT_LOG" || ! $(grep -c '^CREATE:' "$EVENT_LOG") -gt 0 ]] \
            || printf 'backupsheep_installation_identity\n'
        return 0
    fi
    if [[ "$1" == volume && "$2" == create ]]; then
        [[ "$SCENARIO" != create_error ]] || return 75
        for last_arg in "$@"; do
            case "$last_arg" in
                com.docker.compose.project=backupsheep) saw_project=true ;;
                com.docker.compose.volume=installation_identity) saw_logical=true ;;
                com.backupsheep.installation-id="$INSTALLATION_ID") saw_installation=true ;;
            esac
        done
        [[ "$saw_project" == true && "$saw_logical" == true && "$saw_installation" == true ]] \
            || return 76
        printf 'CREATE:%s\n' "$last_arg" >> "$EVENT_LOG"
        if [[ "$SCENARIO" == wrong_create_name ]]; then
            printf 'unexpected-volume\n'
        else
            printf '%s\n' "$last_arg"
        fi
        return 0
    fi
    if [[ "$1" == inspect ]]; then
        template="$3"
        resource_id="$4"
        [[ "$resource_id" == legacy-container ]] || return 89
        if [[ "$template" == *'project.working_dir'* ]]; then
            emit_label /srv/backupsheep
        elif [[ "$template" == *'project.config_files'* ]]; then
            emit_label /srv/backupsheep/docker-compose.yml
        elif [[ "$template" == *'com.docker.compose.project'* ]]; then
            emit_project_label
        else
            return 90
        fi
        return 0
    fi
    if [[ "$1" == volume && "$2" == inspect ]]; then
        template="$4"
        resource_id="$5"
        [[ "$SCENARIO" != inspect_error ]] || return 77
        if [[ "$resource_id" == backupsheep_installation_identity ]]; then
            [[ "$SCENARIO" != sentinel_name_inspect_error || "$template" != '{{{{.Name}}}}' ]] \
                || return 81
            [[ "$SCENARIO" != sentinel_project_inspect_error || "$template" != *'com.docker.compose.project'* ]] \
                || return 82
            [[ "$SCENARIO" != sentinel_logical_inspect_error || "$template" != *'com.docker.compose.volume'* ]] \
                || return 83
            [[ "$SCENARIO" != sentinel_identity_inspect_error || "$template" != *'com.backupsheep.installation-id'* ]] \
                || return 84
        else
            [[ "$SCENARIO" != legacy_name_inspect_error || "$template" != '{{{{.Name}}}}' ]] \
                || return 85
            [[ "$SCENARIO" != legacy_project_inspect_error || "$template" != *'com.docker.compose.project'* ]] \
                || return 86
            [[ "$SCENARIO" != legacy_logical_inspect_error || "$template" != *'com.docker.compose.volume'* ]] \
                || return 87
            [[ "$SCENARIO" != legacy_identity_inspect_error || "$template" != *'com.backupsheep.installation-id'* ]] \
                || return 88
        fi
        if [[ "$template" == '{{{{.Name}}}}' ]]; then
            printf '%s\n' "$resource_id"
        elif [[ "$template" == *'com.docker.compose.project'* ]]; then
            if [[ "$SCENARIO" == wrong_project_label && "$resource_id" != backupsheep_installation_identity ]]; then
                emit_label foreign-project
            elif [[ "$SCENARIO" == sentinel_project_* \
                    && "$resource_id" == backupsheep_installation_identity ]]; then
                emit_project_label
            else
                emit_label backupsheep
            fi
        elif [[ "$template" == *'com.docker.compose.volume'* ]]; then
            if [[ "$resource_id" == backupsheep_installation_identity ]]; then
                emit_label installation_identity
            elif [[ "$SCENARIO" == wrong_logical_label && "$resource_id" == backupsheep_pgdata ]]; then
                emit_label foreign
            else
                emit_label "${{resource_id#backupsheep_}}"
            fi
        elif [[ "$template" == *'com.backupsheep.installation-id'* ]]; then
            if [[ "$resource_id" == backupsheep_installation_identity ]]; then
                if [[ "$SCENARIO" == wrong_sentinel_identity ]]; then
                    emit_label bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
                else
                    emit_label "$INSTALLATION_ID"
                fi
            elif [[ "$SCENARIO" == identified_legacy_volume && "$resource_id" == backupsheep_pgdata ]]; then
                emit_label bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            else
                emit_label ''
            fi
        else
            return 78
        fi
        return 0
    fi
    return 79
}}

compose() {{
    local last_arg=""
    for last_arg in "$@"; do :; done
    case "$last_arg" in
        --services)
            printf '%s\n' db rabbitmq-volume-init rabbitmq rabbitmq-provision db-provision migrate preflight app worker-cloud \
                worker-database worker-files worker-storage worker-logs beat
            ;;
        --networks) printf '%s\n' app-database app-broker ;;
        --volumes)
            printf '%s\n' pgdata rabbitmq_data backup_workdir \
                backup_storage installation_identity
            ;;
        *) return 80 ;;
    esac
}}

{invocation}
'''
        env = os.environ.copy()
        env.update(SCENARIO=scenario, EVENT_LOG=str(self.event_log))
        return subprocess.run(
            ["/bin/bash", "-c", command, "adoption-test", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def events(self):
        if not self.event_log.exists():
            return []
        return self.event_log.read_text(encoding="utf-8").splitlines()

    def run_exact_path_container_adoption(self, scenario="exact"):
        command = rf'''
source "$1"
INSTALL_DIR=/srv/backupsheep
ENV_FILE=/srv/backupsheep/.env
PROJECT_NAME=backupsheep
INSTALL_WAS_PRESENT=true
DOCKER_BIN=mock_docker
INSTALLATION_ID={self.installation_id}
POSTGRES_MIGRATION_REQUIRED=true

read_env_value() {{
    case "$1" in
        BACKUPSHEEP_INSTALLATION_ID) printf '%s' "$INSTALLATION_ID" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_GENERATION) printf '%s' '18-alpine-icu-v1-pending-upgrade' ;;
        BACKUPSHEEP_POSTGRES_STORAGE_INTENT) printf '%s' 'migrated-debian-v1' ;;
        BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID) printf '%s' 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
    esac
}}

emit_label() {{
    local label_value="${{1-}}"
    local LC_ALL=C
    printf '%s:%s%s\n' "${{#label_value}}" "$label_value" \
        '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
}}

mock_docker() {{
    local template="" resource_id="" last_arg=""
    if [[ "$1" == ps ]]; then
        if [[ "$*" == *'volume=backupsheep_ssh_trust'* ]]; then
            case "$SCENARIO" in
                retired_ssh_attached_running) printf 'running-legacy-container\n' ;;
                retired_ssh_attached_stopped) printf 'stopped-legacy-container\n' ;;
            esac
        elif [[ "$SCENARIO" != fresh && "$SCENARIO" != fresh_resume ]]; then
            printf 'legacy-app\n'
        fi
        return 0
    fi
    if [[ "$1" == network && "$2" == ls ]]; then
        if [[ "$SCENARIO" == fresh || "$SCENARIO" == fresh_resume ]]; then
            return 0
        fi
        if [[ "$3" == --format ]]; then
            if [[ "$SCENARIO" == option_network ]]; then
                printf 'backupsheep_--version\n'
            elif [[ "$SCENARIO" == noncanonical_network ]]; then
                printf 'backupsheep_evil-network\n'
            else
                printf 'backupsheep_app-database\n'
            fi
        elif [[ "$SCENARIO" == option_network ]]; then
            printf 'hostile-network\n'
        else
            printf 'legacy-network\n'
        fi
        return 0
    fi
    if [[ "$1" == volume && "$2" == ls ]]; then
        if [[ "$SCENARIO" == fresh ]]; then
            return 0
        fi
        if [[ "$SCENARIO" == fresh_resume ]]; then
            printf 'backupsheep_installation_identity\n'
            return 0
        fi
        if [[ "$SCENARIO" == option_volume ]]; then
            printf '%s\n' backupsheep_installation_identity backupsheep_--version
            return 0
        fi
        printf '%s\n' \
            backupsheep_pgdata \
            backupsheep_rabbitmq_data \
            backupsheep_backup_workdir \
            backupsheep_backup_storage
        case "$SCENARIO" in
            retired_ssh_trust|retired_ssh_wrong_id|retired_ssh_wrong_labels|retired_ssh_attached_running|retired_ssh_attached_stopped)
                printf 'backupsheep_installation_identity\n'
                ;;
        esac
        case "$SCENARIO" in
            retired_ssh_trust|retired_ssh_without_sentinel|retired_ssh_wrong_id|retired_ssh_wrong_labels|retired_ssh_attached_running|retired_ssh_attached_stopped)
                if [[ "$SCENARIO" != retired_ssh_wrong_labels || "$3" == --format ]]; then
                printf 'backupsheep_ssh_trust\n'
                fi
                ;;
        esac
        return 0
    fi
    if [[ "$1" == volume && "$2" == create ]]; then
        for last_arg in "$@"; do :; done
        printf 'CREATE:%s\n' "$last_arg" >> "$EVENT_LOG"
        printf '%s\n' "$last_arg"
        return 0
    fi
    if [[ "$1" == inspect ]]; then
        template="$3"
        if [[ "$template" == *'project.working_dir'* ]]; then
            [[ "$SCENARIO" != foreign_path ]] || {{ emit_label /srv/foreign; return 0; }}
            emit_label /srv/backupsheep
        elif [[ "$template" == *'project.config_files'* ]]; then
            [[ "$SCENARIO" != foreign_config ]] || {{ emit_label /srv/foreign.yml; return 0; }}
            emit_label /srv/backupsheep/docker-compose.yml
        elif [[ "$template" == *'compose.service'* ]]; then
            [[ "$SCENARIO" != foreign_service ]] || {{ emit_label foreign; return 0; }}
            if [[ "$SCENARIO" == option_service ]]; then
                emit_label --version
            else
                emit_label app
            fi
        elif [[ "$template" == *'installation-id'* ]]; then
            if [[ "$SCENARIO" == matching_id_without_sentinel ]]; then
                emit_label "$INSTALLATION_ID"
            elif [[ "$SCENARIO" == wrong_id ]]; then
                emit_label "$(printf '%064d' 0)"
            else
                emit_label ''
            fi
        fi
        return 0
    fi
    if [[ "$1" == network && "$2" == inspect ]]; then
        template="$4"
        if [[ "$template" == '{{{{.Name}}}}' ]]; then
            if [[ "$SCENARIO" == option_network ]]; then
                printf 'backupsheep_--version\n'
            elif [[ "$SCENARIO" == noncanonical_network ]]; then
                printf 'backupsheep_evil-network\n'
            else
                printf 'backupsheep_app-database\n'
            fi
        elif [[ "$template" == *'compose.project'* ]]; then
            emit_label backupsheep
        elif [[ "$template" == *'compose.network'* ]]; then
            if [[ "$SCENARIO" == option_network ]]; then
                emit_label --version
            else
                emit_label app-database
            fi
        elif [[ "$template" == *'installation-id'* ]]; then
            emit_label ''
        fi
        return 0
    fi
    if [[ "$1" == volume && "$2" == inspect ]]; then
        template="$4"
        resource_id="$5"
        if [[ "$resource_id" == backupsheep_installation_identity ]]; then
            if [[ "$template" == '{{{{.Name}}}}' ]]; then
                printf 'backupsheep_installation_identity\n'
            elif [[ "$template" == *'compose.project'* ]]; then
                emit_label backupsheep
            elif [[ "$template" == *'compose.volume'* ]]; then
                emit_label installation_identity
            elif [[ "$template" == *'installation-id'* ]]; then
                emit_label "$INSTALLATION_ID"
            fi
            return 0
        fi
        if [[ "$template" == '{{{{.Name}}}}' ]]; then
            if [[ "$SCENARIO" == noncanonical_volume && "$resource_id" == backupsheep_pgdata ]]; then
                printf 'backupsheep_evil-volume\n'
            else
                printf '%s\n' "$resource_id"
            fi
        elif [[ "$template" == *'compose.project'* ]]; then
            if [[ "$SCENARIO" == retired_ssh_wrong_labels \
                    && "$resource_id" == backupsheep_ssh_trust ]]; then
                emit_label foreign-project
            else
                emit_label backupsheep
            fi
        elif [[ "$template" == *'compose.volume'* ]]; then
            if [[ "$SCENARIO" == option_volume ]]; then
                emit_label --version
            else
                emit_label "${{resource_id#backupsheep_}}"
            fi
        elif [[ "$template" == *'installation-id'* ]]; then
            if [[ "$SCENARIO" == matching_id_without_sentinel ]]; then
                emit_label "$INSTALLATION_ID"
            elif [[ "$SCENARIO" == retired_ssh_wrong_id \
                    && "$resource_id" == backupsheep_ssh_trust ]]; then
                emit_label "$(printf '%064d' 0)"
            else
                emit_label ''
            fi
        fi
        return 0
    fi
    return 91
}}

compose() {{
    local last_arg=""
    for last_arg in "$@"; do :; done
    case "$last_arg" in
        --services) printf '%s\n' db rabbitmq-volume-init rabbitmq rabbitmq-provision db-provision migrate preflight app worker-cloud \
            worker-database worker-files worker-storage worker-logs beat ;;
        --networks) printf 'app-database\n' ;;
        --volumes) printf '%s\n' pgdata rabbitmq_data backup_workdir backup_storage \
            installation_identity ;;
        *) return 92 ;;
    esac
}}

validate_compose_project_ownership
'''
        env = os.environ.copy()
        env.update(SCENARIO=scenario, EVENT_LOG=str(self.event_log))
        return subprocess.run(
            ["/bin/bash", "-c", command, "adoption-test", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_exact_four_volume_adoption_creates_sentinel_before_persisting_project(self):
        result = self.run_adoption(full_ownership=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.events(),
            [
                "CREATE:backupsheep_installation_identity",
                "SET:BACKUPSHEEP_COMPOSE_PROJECT_NAME=backupsheep",
            ],
        )

    def test_exact_path_blank_identity_containers_create_only_verified_sentinel(self):
        result = self.run_exact_path_container_adoption()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.events(), ["CREATE:backupsheep_installation_identity"]
        )

    def test_fresh_project_creates_sentinel_before_mutation_and_resume_reuses_it(self):
        result = self.run_exact_path_container_adoption("fresh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.events(), ["CREATE:backupsheep_installation_identity"]
        )

        result = self.run_exact_path_container_adoption("fresh_resume")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.events(), ["CREATE:backupsheep_installation_identity"]
        )

    def test_develop_ssh_trust_volume_is_preserved_only_with_exact_ownership(self):
        result = self.run_exact_path_container_adoption("retired_ssh_trust")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])

        for scenario, message in (
            (
                "retired_ssh_without_sentinel",
                "exactly one matching installation-identity sentinel",
            ),
            ("retired_ssh_wrong_id", "belongs to a different"),
            (
                "retired_ssh_wrong_labels",
                "collides with the retired BackupSheep trust volume",
            ),
            ("retired_ssh_attached_running", "still has attached containers"),
            ("retired_ssh_attached_stopped", "still has attached containers"),
        ):
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_exact_path_container_adoption(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.events(), [])

    def test_exact_path_container_adoption_rejects_every_ownership_drift(self):
        scenarios = (
            "foreign_path",
            "foreign_config",
            "foreign_service",
            "noncanonical_network",
            "noncanonical_volume",
            "matching_id_without_sentinel",
            "wrong_id",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_exact_path_container_adoption(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])

    def test_legacy_adoption_rejects_non_exact_or_preidentified_volume_sets(self):
        scenarios = (
            "missing_volume",
            "extra_volume",
            "wrong_project_label",
            "wrong_logical_label",
            "identified_legacy_volume",
            "existing_container",
            "existing_network",
            "sentinel_name_collision",
            "ssh_trust_collision",
            "unlabeled_prefix_extra",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_adoption(scenario, direct=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("CREATE:", "\n".join(self.events()))
                self.assertNotIn("SET:", "\n".join(self.events()))

    def test_legacy_adoption_fails_closed_on_every_inventory_error(self):
        for scenario in (
            "container_inventory_error",
            "network_inventory_error",
            "volume_inventory_error",
            "full_name_inventory_error",
            "inspect_error",
            "legacy_name_inspect_error",
            "legacy_project_inspect_error",
            "legacy_logical_inspect_error",
            "legacy_identity_inspect_error",
        ):
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_adoption(scenario, direct=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])

    def test_sentinel_create_or_reinspection_failure_never_persists_project(self):
        for scenario in (
            "create_error",
            "wrong_create_name",
            "wrong_sentinel_identity",
            "sentinel_name_inspect_error",
            "sentinel_project_inspect_error",
            "sentinel_logical_inspect_error",
            "sentinel_identity_inspect_error",
        ):
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_adoption(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(
                    any(event.startswith("SET:") for event in self.events())
                )

    def test_adoption_and_project_name_options_must_match(self):
        command = r'''
source "$1"
parse_args --project-name first --adopt-legacy-project second
'''
        result = subprocess.run(
            ["/bin/bash", "-c", command, "adoption-test", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must name the same project", result.stderr)

    def test_project_name_option_is_single_use_and_boundary_checked(self):
        duplicate = subprocess.run(
            [
                "/bin/bash", "-c",
                'source "$1"; parse_args --project-name one --project-name two',
                "project-name-test", str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("may be specified only once", duplicate.stderr)

        safe_names = ("a", "0", "a_b-c", "a" * 63)
        invalid_names = (
            "", "A", "-project", "_project", "a" * 64, "project.name",
            "project/name", "project name", "--version", "project\nname",
            "backupsheepé",
        )
        command = (
            'source "$1"; parse_args --project-name "$2"; '
            'validate_project_name; printf "%s" "$PROJECT_NAME"'
        )
        for project_name in safe_names:
            with self.subTest(project_name=project_name):
                result = subprocess.run(
                    ["/bin/bash", "-c", command, "project-name-test", str(INSTALLER), project_name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, project_name)
        for project_name in invalid_names:
            with self.subTest(project_name=project_name):
                result = subprocess.run(
                    ["/bin/bash", "-c", command, "project-name-test", str(INSTALLER), project_name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_hostile_locale_cannot_broaden_installer_ascii_grammars(self):
        environment = os.environ.copy()
        environment["LC_ALL"] = "en_US.US-ASCII"

        project = subprocess.run(
            [
                "/bin/bash", "-c",
                'source "$1"; [[ "$LC_ALL" == C ]]; '
                'parse_args --project-name BackupSheep; validate_project_name',
                "project-locale-test", str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(project.returncode, 0)
        self.assertIn("lowercase letter or digit", project.stderr)

        uppercase_identity = "A" * 64
        identity = subprocess.run(
            [
                "/bin/bash", "-c",
                'source "$1"; [[ "$LC_ALL" == C ]]; '
                'UPPERCASE_ID="$2"; '
                'read_env_value() { printf "%s" "$UPPERCASE_ID"; }; '
                'ensure_installation_id',
                "identity-locale-test", str(INSTALLER), uppercase_identity,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(identity.returncode, 0)
        self.assertIn("lowercase hexadecimal", identity.stderr)

    def test_hostile_inferred_project_labels_never_persist_or_mutate(self):
        suffixes = (
            "option", "uppercase", "embedded_lf", "trailing_lf", "nul",
            "marker", "utf8",
        )
        for witness_kind in ("container", "sentinel"):
            for suffix in suffixes:
                scenario = f"{witness_kind}_project_{suffix}"
                with self.subTest(scenario=scenario):
                    self.event_log.unlink(missing_ok=True)
                    result = self.run_adoption(scenario, adopt_legacy=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.events(), [])

    def test_option_shaped_logical_labels_cannot_bypass_installer_membership(self):
        for scenario in ("option_service", "option_network", "option_volume"):
            with self.subTest(scenario=scenario):
                self.event_log.unlink(missing_ok=True)
                result = self.run_exact_path_container_adoption(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unexpected", result.stderr)
                self.assertEqual(self.events(), [])
