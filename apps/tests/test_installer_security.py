import json
import hashlib
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
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

        self.assertIn(
            "The Docker daemon is unavailable to the effective invoking UID",
            self.installer,
        )
        self.assertIn("no host settings were changed", self.installer)
        self.assertIn("Effective UID 0 is refused by default", self.installer)
        self.assertIn("validate_invocation_mode", self.installer)

    def test_rootful_daemon_mode_is_explicit_root_owned_and_never_chowns(self):
        wrapper = (ROOT / "backupsheep-compose").read_text(encoding="utf-8")
        self.assertTrue(self.installer.startswith("#!/bin/bash\n"))
        self.assertTrue(wrapper.startswith("#!/bin/bash\n"))
        self.assertIn("--allow-root-install", self.installer)
        self.assertIn('INSTALL_DIR="/opt/backupsheep"', self.installer)
        self.assertIn(
            'root_install_mode_allowed "$EUID" "$ALLOW_ROOT_INSTALL"',
            self.installer,
        )
        self.assertIn('"$(file_uid "$SCRIPT_PATH")"', self.installer)
        self.assertIn('"$(file_uid "$parent_dir")"', self.installer)
        self.assertIn('find "$INSTALL_DIR" -xdev ! -uid "$EUID"', self.installer)
        self.assertIn("validate_privileged_runtime_environment", self.installer)
        self.assertIn(
            "for variable in HOME DOCKER_CONFIG DOCKER_CERT_PATH",
            self.installer,
        )
        self.assertNotIn("SUDO_USER", self.installer + wrapper)
        self.assertNotIn("SUDO_UID", self.installer + wrapper)
        self.assertNotRegex(self.installer, re.compile(r"(?m)^\s*chown(?:\s|$)"))
        self.assertNotRegex(wrapper, re.compile(r"(?m)^\s*chown(?:\s|$)"))

        command = r'''
source "$1"
root_install_mode_allowed 0 true
! root_install_mode_allowed 0 false
root_install_mode_allowed 501 false
! root_install_mode_allowed 501 true
! root_install_mode_allowed invalid true
ALLOW_ROOT_INSTALL=true
INSTALL_DIR_WAS_EXPLICIT=false
INSTALL_DIR=/unprivileged/default
apply_install_dir_default_for_mode 0
[[ "$INSTALL_DIR" == /opt/backupsheep ]]
INSTALL_DIR_WAS_EXPLICIT=true
INSTALL_DIR=/srv/reviewed-backupsheep
apply_install_dir_default_for_mode 0
[[ "$INSTALL_DIR" == /srv/reviewed-backupsheep ]]
ALLOW_ROOT_INSTALL=false
validate_invocation_mode
'''
        subprocess.run(
            ["bash", "-c", command, "installer-root-mode-test", str(INSTALLER)],
            check=True,
            capture_output=True,
            text=True,
        )

        refused = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; ALLOW_ROOT_INSTALL=true; validate_invocation_mode',
                "installer-root-mode-test",
                str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(
            "valid only when the effective invoking UID is 0", refused.stderr
        )

        duplicate = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; parse_args --allow-root-install --allow-root-install',
                "installer-root-mode-test",
                str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("may be specified only once", duplicate.stderr)

    def test_root_install_docs_use_generated_lane_keyrings_without_kms_flags(self):
        obsolete_kms_contracts = (
            "--artifact-kms-",
            "KMS_DATABASE_CREDENTIALS",
            "KMS_FILES_CREDENTIALS",
            "KMS_KEY_ARN",
            "KMS_REGION",
        )
        for relative_path in ("docs/installation.md", "docs/guides/installation.md"):
            document = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(path=relative_path):
                self.assertIn("--allow-root-install", document)
                self.assertIn("keyrings", document)
                for obsolete_contract in obsolete_kms_contracts:
                    self.assertNotIn(obsolete_contract, document)

    def test_installer_disables_inherited_xtrace_before_handling_secrets(self):
        self.assertIn("set +x", self.installer)
        self.assertLess(self.installer.index("set +x"), self.installer.index("set -Eeuo pipefail"))
        self.assertLess(self.installer.index("set +x"), self.installer.index("random_hex()"))

    def test_artifact_keyring_creation_uses_atomic_no_clobber_publication(self):
        command = r'''
source "$1"
root="$2"
source_path="${root}/source"
destination_path="${root}/destination"
printf 'new-keyring\n' > "$source_path"
printf 'concurrent-owner\n' > "$destination_path"
! atomic_publish_new_file "$source_path" "$destination_path"
[[ "$(cat "$destination_path")" == concurrent-owner ]]
[[ "$(cat "$source_path")" == new-keyring ]]
'''
        with tempfile.TemporaryDirectory(prefix="backupsheep-publish-test-") as root:
            subprocess.run(
                ["bash", "-c", command, "installer-test", str(INSTALLER), root],
                check=True,
                capture_output=True,
                text=True,
            )
        keyring_writer = self.installer.split("write_artifact_keyring() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertIn("atomic_publish_new_file", keyring_writer)
        self.assertNotIn("atomic_move_new", keyring_writer)

    def test_artifact_keyring_publication_kill_boundaries_resume_safely(self):
        interrupted_template = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
atomic_publish_new_file() {{
    source_path="$1"
    destination_path="$2"
    {publication}
}}
write_artifact_keyring database
exit 97
'''
        resumed = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
reconcile_installer_temp_residues
destination="$(artifact_keyring_path database)"
if [[ ! -e "$destination" && ! -L "$destination" ]]; then
    write_artifact_keyring database
fi
validate_secret_file "$destination"
[[ "$(file_links "$destination")" == 1 ]]
'''
        phases = {
            "before-link": 'kill -KILL "$$"',
            "after-link": 'ln -- "$source_path" "$destination_path" && kill -KILL "$$"',
            "after-unlink": (
                'ln -- "$source_path" "$destination_path" '
                '&& rm -f -- "$source_path" && kill -KILL "$$"'
            ),
        }
        for phase, publication in phases.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(
                prefix="backupsheep-keyring-kill-"
            ) as root:
                install_dir = Path(root)
                install_dir.chmod(0o700)
                (install_dir / ".secrets").mkdir(mode=0o700)
                env_file = install_dir / ".env"
                env_file.write_text(
                    f"BACKUPSHEEP_INSTALLATION_ID='{'a' * 64}'\n",
                    encoding="utf-8",
                )
                env_file.chmod(0o600)
                interrupted = subprocess.run(
                    [
                        "bash",
                        "-c",
                        interrupted_template.format(publication=publication),
                        "keyring-kill-test",
                        str(INSTALLER),
                        str(install_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(
                    interrupted.returncode,
                    -signal.SIGKILL,
                    interrupted.stderr,
                )
                recovered = subprocess.run(
                    [
                        "bash",
                        "-c",
                        resumed,
                        "keyring-resume-test",
                        str(INSTALLER),
                        str(install_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                secret_dir = install_dir / ".secrets"
                destination = secret_dir / "artifact_local_file_database_keyring"
                self.assertTrue(destination.is_file())
                self.assertEqual(destination.stat().st_nlink, 1)
                self.assertEqual(
                    list(secret_dir.glob(".artifact-keyring-database.*")),
                    [],
                )

    def test_linked_keyring_residue_must_match_the_exact_destination_inode(self):
        with tempfile.TemporaryDirectory(
            prefix="backupsheep-keyring-identity-"
        ) as root:
            install_dir = Path(root)
            install_dir.chmod(0o700)
            secret_dir = install_dir / ".secrets"
            secret_dir.mkdir(mode=0o700)
            env_file = install_dir / ".env"
            env_file.write_text(
                f"BACKUPSHEEP_INSTALLATION_ID='{'a' * 64}'\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            setup = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
write_artifact_keyring database
candidate="$SECRETS_DIR/.artifact-keyring-database.ABC12345"
decoy="$SECRETS_DIR/.unrelated-hardlink"
cp -- "$(artifact_keyring_path database)" "$candidate"
chmod 0444 "$candidate"
ln -- "$candidate" "$decoy"
'''
            staged = subprocess.run(
                [
                    "bash",
                    "-c",
                    setup,
                    "keyring-identity-test",
                    str(INSTALLER),
                    str(install_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr)
            reconcile = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
reconcile_installer_temp_residues
'''
            refused = subprocess.run(
                [
                    "bash",
                    "-c",
                    reconcile,
                    "keyring-identity-test",
                    str(INSTALLER),
                    str(install_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(refused.returncode, 0)
            candidate = secret_dir / ".artifact-keyring-database.ABC12345"
            decoy = secret_dir / ".unrelated-hardlink"
            destination = secret_dir / "artifact_local_file_database_keyring"
            self.assertTrue(candidate.is_file())
            self.assertTrue(decoy.is_file())
            self.assertEqual(candidate.stat().st_nlink, 2)
            self.assertTrue(destination.is_file())
            self.assertEqual(destination.stat().st_nlink, 1)

    def test_provider_rollback_publication_link_kill_resumes_safely(self):
        interrupt_template = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
atomic_publish_new_file() {{
    source_path="$1"
    destination_path="$2"
    {publication}
}}
preserve_artifact_provider_rollback
exit 97
'''
        resume = r'''
source "$1"
INSTALL_DIR="$2"
ENV_FILE="$2/.env"
SECRETS_DIR="$2/.secrets"
reconcile_installer_temp_residues
rollback="$(artifact_provider_rollback_path)"
if [[ ! -e "$rollback" && ! -L "$rollback" ]]; then
    preserve_artifact_provider_rollback
fi
validate_artifact_provider_rollback
'''
        phases = {
            "before-link": 'kill -KILL "$$"',
            "after-link": 'ln -- "$source_path" "$destination_path" && kill -KILL "$$"',
            "after-unlink": (
                'ln -- "$source_path" "$destination_path" '
                '&& rm -f -- "$source_path" && kill -KILL "$$"'
            ),
        }
        for phase, publication in phases.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(
                prefix="backupsheep-provider-rollback-kill-"
            ) as root:
                install_dir = Path(root)
                install_dir.chmod(0o700)
                secret_dir = install_dir / ".secrets"
                secret_dir.mkdir(mode=0o700)
                env_file = install_dir / ".env"
                env_file.write_text(
                    (
                        f"BACKUPSHEEP_INSTALLATION_ID='{'a' * 64}'\n"
                        "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='aws-kms'\n"
                        "BACKUPSHEEP_ARTIFACT_KMS_KEY_ARN='retired-key'\n"
                    ),
                    encoding="utf-8",
                )
                env_file.chmod(0o600)
                interrupted = subprocess.run(
                    [
                        "bash",
                        "-c",
                        interrupt_template.format(publication=publication),
                        "provider-rollback-kill-test",
                        str(INSTALLER),
                        str(install_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(
                    interrupted.returncode,
                    -signal.SIGKILL,
                    interrupted.stderr,
                )
                recovered = subprocess.run(
                    [
                        "bash",
                        "-c",
                        resume,
                        "provider-rollback-resume-test",
                        str(INSTALLER),
                        str(install_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                rollback = secret_dir / "artifact_provider_transition_rollback"
                self.assertTrue(rollback.is_file())
                self.assertEqual(rollback.stat().st_nlink, 1)
                self.assertEqual(
                    list(secret_dir.glob(".artifact-provider-rollback.*")),
                    [],
                )

    def test_unrelated_mode_0400_residue_remains_a_hard_failure(self):
        with tempfile.TemporaryDirectory(
            prefix="backupsheep-unrelated-residue-"
        ) as root:
            install_dir = Path(root)
            install_dir.chmod(0o700)
            secret_dir = install_dir / ".secrets"
            secret_dir.mkdir(mode=0o700)
            residue = secret_dir / ".managed-key-check.ABC12345"
            residue.write_text("unrelated\n", encoding="utf-8")
            residue.chmod(0o400)
            command = r'''
source "$1"
INSTALL_DIR="$2"
SECRETS_DIR="$2/.secrets"
reconcile_installer_temp_residues
'''
            refused = subprocess.run(
                [
                    "bash",
                    "-c",
                    command,
                    "unrelated-residue-test",
                    str(INSTALLER),
                    str(install_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue(residue.is_file())
            self.assertEqual(stat.S_IMODE(residue.stat().st_mode), 0o400)

    def test_next_steps_warns_that_both_keyrings_and_postgres_are_one_recovery_set(self):
        command = r'''
source "$1"
INSTALL_DIR="$2"
INSTALL_REF=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PROJECT_NAME=backupsheep
ALLOW_ROOT_INSTALL=false
ENABLE_OPERATIONS=false
print_next_steps
'''
        install_dir = "/srv/backupsheep"
        result = subprocess.run(
            ["bash", "-c", command, "next-steps-test", str(INSTALLER), install_dir],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn(
            "PostgreSQL and both artifact keyrings are one cryptographic recovery set",
            result.stdout,
        )
        self.assertIn(
            f"{install_dir}/.secrets/artifact_local_file_database_keyring",
            result.stdout,
        )
        self.assertIn(
            f"{install_dir}/.secrets/artifact_local_file_files_keyring",
            result.stdout,
        )
        self.assertIn(
            "Loss, replacement, or regeneration of either keyring is unrecoverable",
            result.stdout,
        )

    def test_artifact_rotation_arguments_are_paired_and_fail_closed(self):
        cases = (
            (["--rotate-artifact-keyring", "database"], "requires --expected-artifact"),
            (
                [
                    "--expected-artifact-active-key-id",
                    "lfk-11111111111111111111111111111111",
                ],
                "requires --rotate-artifact-keyring",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                command = 'source "$1"; shift; parse_args "$@"'
                result = subprocess.run(
                    ["bash", "-c", command, "installer-test", str(INSTALLER), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

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

        with tempfile.TemporaryDirectory(
            prefix="backupsheep-installer-source-"
        ) as directory:
            source = Path(directory) / "install.sh"
            shutil.copyfile(INSTALLER, source)
            source.chmod(0o700)
            command = 'source "$1"; validate_installer_source'
            subprocess.run(
                ["bash", "-c", command, "installer-source-test", str(source)],
                check=True,
                capture_output=True,
                text=True,
            )

            source.chmod(0o720)
            writable = subprocess.run(
                ["bash", "-c", command, "installer-source-test", str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(writable.returncode, 0)
            self.assertIn("must not be writable by group", writable.stderr)

            source.chmod(0o700)
            hardlink = Path(directory) / "install-hardlink.sh"
            os.link(source, hardlink)
            linked = subprocess.run(
                ["bash", "-c", command, "installer-source-test", str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("must not be hard-linked", linked.stderr)

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

    def test_artifact_rotation_refuses_any_retained_worker_container(self):
        command = r'''
source "$1"
PROJECT_NAME=backupsheep
DOCKER_BIN=mock_docker
mock_docker() {
    [[ "$1" == ps ]] || return 91
    printf 'paused-worker-container\n'
}
assert_artifact_keyring_worker_stopped database
'''
        result = subprocess.run(
            ["bash", "-c", command, "installer-test", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stopped, paused, and restarting containers", result.stderr)
        self.assertIn("--all", self.installer)

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

    def test_installer_signal_handlers_kill_active_group_and_release_lock(self):
        for signal_number, expected in (
            (signal.SIGHUP, 129),
            (signal.SIGINT, 130),
            (signal.SIGTERM, 143),
        ):
            with self.subTest(signal=signal_number), tempfile.TemporaryDirectory(
                prefix="backupsheep-installer-signal-"
            ) as directory:
                install_dir = Path(directory) / "installation"
                install_dir.mkdir(mode=0o700)
                ready = Path(directory) / "ready"
                child_pid_path = Path(directory) / "child.pid"
                command = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
: > "$3"
run_installer_command 30 "signal test child" sh -c 'printf "%s\n" "$$" > "$1"; exec sleep 30' child "$4"
'''
                process = subprocess.Popen(
                    [
                        "bash",
                        "-c",
                        command,
                        "installer-signal-test",
                        str(INSTALLER),
                        str(install_dir),
                        str(ready),
                        str(child_pid_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 10
                while (not ready.exists() or not child_pid_path.exists()) and time.monotonic() < deadline:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        self.fail(f"installer exited before signal: {process.returncode}\n{stdout}\n{stderr}")
                    time.sleep(0.02)
                child_pid = int(child_pid_path.read_text(encoding="utf-8").strip())
                process.send_signal(signal_number)
                stdout, stderr = process.communicate(timeout=12)
                self.assertEqual(process.returncode, expected, f"{stdout}\n{stderr}")
                self.assertFalse(Path(f"{install_dir}.backupsheep-mutation-lock").exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)

    def test_install_path_grammar_matches_signed_consumer_mount_contract(self):
        consumer = (ROOT / "deploy/release/consume-signed-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("outside the reviewed Docker mount and attestation grammar", self.installer)
        self.assertIn("outside the reviewed Docker mount and attestation grammar", consumer)
        for suffix in ("bad:path", "bad=value", "bad%value", "bad#value", "bad~value", "bad(value)", "badé"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(
                prefix="backupsheep-path-contract-"
            ) as directory:
                path = str(Path(directory) / suffix)
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; INSTALL_DIR="$2"; validate_install_dir',
                        "installer-path-test",
                        str(INSTALLER),
                        path,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside the reviewed", result.stderr)

    def test_signed_release_consumer_serializes_and_postvalidates_evidence_publication(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        source_text = consumer.read_text(encoding="utf-8")
        self.assertIn('MUTATION_LOCK_DIR="${INSTALL_DIR}.backupsheep-mutation-lock"', source_text)
        self.assertIn('publish_fresh_evidence "$STAGING_DIR" "$EVIDENCE_DIR"', source_text)
        self.assertLess(
            source_text.index('publish_fresh_evidence "$STAGING_DIR" "$EVIDENCE_DIR"'),
            source_text.index("Verified signed release %s at source commit %s."),
        )

        with tempfile.TemporaryDirectory(prefix="backupsheep-consumer-lock-") as directory:
            install_dir = Path(directory) / "installation"
            install_dir.mkdir(mode=0o700)
            ready = Path(directory) / "ready"
            release = Path(directory) / "release"
            holder = subprocess.Popen(
                [
                    "bash",
                    "-c",
                    r'''source "$1"
INSTALL_DIR="$2"
acquire_or_inherit_mutation_lock
trap 'release_mutation_lock' EXIT
: > "$3"
while [[ ! -e "$4" ]]; do sleep 0.05; done
''',
                    "release-consumer-lock-holder",
                    str(consumer),
                    str(install_dir),
                    str(ready),
                    str(release),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(100):
                if ready.exists():
                    break
                time.sleep(0.02)
            self.assertTrue(ready.exists())
            contender = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; INSTALL_DIR="$2"; acquire_or_inherit_mutation_lock',
                    "release-consumer-lock-contender",
                    str(consumer),
                    str(install_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(contender.returncode, 0)
            self.assertIn("another mutation is active", contender.stderr)
            release.touch()
            holder.communicate(timeout=10)
            self.assertFalse(Path(f"{install_dir}.backupsheep-mutation-lock").exists())

        with tempfile.TemporaryDirectory(prefix="backupsheep-evidence-race-") as directory:
            install_dir = Path(directory) / "installation"
            install_dir.mkdir(mode=0o700)
            staging = install_dir / ".release-evidence.download.12345678"
            evidence = install_dir / ".release-evidence"
            staging.mkdir(mode=0o700)
            for name in (
                "backupsheep-release-descriptor-v2.txt",
                "backupsheep-release-descriptor-v2.sigstore.json",
                "release-manifest.json",
                "sigstore-trusted-root.json",
                "signature-verification.json",
            ):
                path = staging / name
                path.write_text("authenticated\n", encoding="utf-8")
                path.chmod(0o600)
            receipt = staging / "local-images.txt"
            receipt.write_text(
                "".join(
                    f"{role}_image_id=sha256:{index:064x}\n"
                    for index, role in enumerate(
                        (
                            "app",
                            "postgres",
                            "egress",
                            "rabbitmq",
                            "rabbitmq_upgrade",
                            "cosign",
                        ),
                        start=1,
                    )
                ),
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            raced = subprocess.run(
                [
                    "bash",
                    "-c",
                    r'''source "$1"
INSTALL_DIR="$2"
STAGING_DIR="$3"
EVIDENCE_DIR="$4"
acquire_or_inherit_mutation_lock
trap 'release_mutation_lock' EXIT
mv() {
  if [[ "$1" == --no-target-directory ]]; then return 1; fi
  mkdir -- "$EVIDENCE_DIR"
  command mv "$@"
}
publish_fresh_evidence "$STAGING_DIR" "$EVIDENCE_DIR"
''',
                    "release-evidence-race",
                    str(consumer),
                    str(install_dir),
                    str(staging),
                    str(evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(raced.returncode, 0)
            self.assertIn("persisted release evidence", raced.stderr)

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

    def test_signed_installer_routes_compose_through_exact_inherited_lock_wrapper(self):
        compose_body = self.installer.split("\ncompose() {", 1)[1].split(
            "\n}\n\nexpected_compose_config_files()", 1
        )[0]
        self.assertIn('if [[ "$IMAGE_MODE" == "signed-release" ]]', compose_body)
        self.assertIn('wrapper_arguments+=(--inherit-installer-lock)', compose_body)
        self.assertIn('"$INSTALL_DIR/backupsheep-compose"', compose_body)
        self.assertIn(
            'run_installer_command 3600 "hardened signed-release Compose operation"',
            compose_body,
        )
        signed_branch = compose_body.split(
            'if [[ "$IMAGE_MODE" == "signed-release" ]]', 1
        )[1].split("\n    else", 1)[0]
        self.assertNotIn('"$DOCKER_BIN" compose', signed_branch)
        wrapper = (ROOT / "backupsheep-compose").read_text(encoding="utf-8")
        self.assertIn(
            'expected_token="version=1;tool=install.sh;pid=${PPID};uid=${EUID}"',
            wrapper,
        )
        self.assertIn("validate_inherited_installer_lock", wrapper)

    def test_signed_operations_failure_quiesces_complete_guarded_topology(self):
        helper = self.installer.split(
            "\nquiesce_failed_operations_start() {", 1
        )[1].split("\n}\n\nstart_operations()", 1)[0]
        self.assertIn('if [[ "$IMAGE_MODE" == "signed-release" ]]', helper)
        signed = helper.split(
            'if [[ "$IMAGE_MODE" == "signed-release" ]]', 1
        )[1].split("\n    else", 1)[0]
        self.assertIn("compose --profile operations down --timeout 300", signed)
        self.assertNotIn(" compose --profile operations stop ", signed)
        start_operations = self.installer.split("\nstart_operations() {", 1)[1].split(
            "\n}\n\nprint_next_steps()", 1
        )[0]
        self.assertNotIn(
            'compose --profile operations stop "${OPERATION_SERVICES[@]}"',
            start_operations,
        )
        self.assertIn("quiesce_failed_operations_start", start_operations)

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

    def test_signed_release_mode_uses_only_a_pinned_locked_down_cosign_container(self):
        consumer = (ROOT / "deploy/release/consume-signed-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--release-tag TAG", self.installer)
        self.assertIn('IMAGE_MODE="local-build"', self.installer)
        self.assertIn('IMAGE_MODE="signed-release"', self.installer)
        self.assertIn("prepare_image_source", self.installer)
        self.assertIn("validate_local_release_images", self.installer)
        self.assertNotIn("apt-get", consumer)
        self.assertNotIn("apk add", consumer)
        self.assertRegex(
            consumer,
            r"ghcr\.io/bilal414/backupsheep-release-verifier@sha256:[0-9a-f]{64}",
        )
        for required in (
            "--pull=never",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "--pids-limit 64",
            "--user 65532:65532",
            "--certificate-identity",
            "--certificate-github-workflow-sha",
            "--certificate-github-workflow-ref",
            "--certificate-github-workflow-trigger push",
        ):
            with self.subTest(required=required):
                self.assertIn(required, consumer)
        self.assertNotIn("docker.sock", consumer)
        self.assertNotRegex(consumer, r"(?m)^\s*(?:eval|source)\s")

    def test_automatic_signed_upgrade_options_fail_before_docker_or_filesystem_mutation(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        source = consumer.read_text(encoding="utf-8")
        self.assertNotIn("stage-upgrade", source)
        self.assertNotIn("signed_release_upgrade.py", source)
        self.assertIn("automatic signed upgrades are unsupported", source)

        with tempfile.TemporaryDirectory(prefix="backupsheep-upgrade-refusal-") as directory:
            root = Path(directory)
            install_dir = root / "installation"
            install_dir.mkdir(mode=0o700)
            sentinel = install_dir / "operator-state"
            sentinel.write_bytes(b"must remain byte-identical\n")
            sentinel.chmod(0o600)
            docker_marker = root / "docker-was-called"
            fake_docker = root / "docker"
            fake_docker.write_text(
                '#!/bin/sh\n: > "$BACKUPSHEEP_DOCKER_CALLED"\nexit 99\n',
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            def snapshot():
                metadata = sentinel.stat()
                return (
                    sorted(str(path.relative_to(install_dir)) for path in install_dir.rglob("*")),
                    sentinel.read_bytes(),
                    metadata.st_ino,
                    metadata.st_nlink,
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_mtime_ns,
                )

            old_stage_arguments = [
                "--mode", "stage-upgrade",
                "--source-tag", "v1.0.0",
                "--source-commit", "a" * 40,
                "--target-tag", "v1.1.0",
                "--target-commit", "b" * 40,
                "--install-dir", str(install_dir),
                "--docker", str(fake_docker),
            ]
            rejected_forms = (
                old_stage_arguments,
                ["--mode", "upgrade", *old_stage_arguments[2:]],
                ["--upgrade", *old_stage_arguments[2:]],
            )
            expected = snapshot()
            environment = os.environ.copy()
            environment["BACKUPSHEEP_DOCKER_CALLED"] = str(docker_marker)
            for arguments in rejected_forms:
                with self.subTest(arguments=arguments[:2]):
                    result = subprocess.run(
                        [str(consumer), *arguments],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("automatic signed upgrades are unsupported", result.stderr)
                    self.assertFalse(docker_marker.exists())
                    self.assertFalse(Path(f"{install_dir}.backupsheep-mutation-lock").exists())
                    self.assertEqual(snapshot(), expected)

    def test_signed_consumer_attests_exact_clean_source_checkout_even_with_skip_worktree(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        with tempfile.TemporaryDirectory(prefix="backupsheep-consumer-source-") as directory:
            checkout = Path(directory) / "checkout"
            for relative in (
                "deploy/release/consume-signed-release.sh",
                "deploy/release/sigstore-trusted-root.json",
                "deploy/release/signed-release.compose.yml",
                "deploy/release-policy.json",
                "deploy/runtime/compose-json.awk",
                "scripts/release_transition.py",
            ):
                target = checkout / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
                target.chmod(0o700 if relative.endswith(".sh") else 0o600)
            checkout.chmod(0o700)
            subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.email", "security@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Security Test"], check=True)
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(["git", "-C", str(checkout), "commit", "--quiet", "-m", "fixture"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "remote", "add", "origin", "https://github.com/bilal414/backupsheep.git"],
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
            ).strip()
            checkout = checkout.resolve()
            command = 'source "$1"; INSTALL_DIR="$2"; SOURCE_COMMIT="$3"; GIT_BIN="$(command -v git)"; validate_source_checkout; validate_trusted_root "$2/deploy/release/sigstore-trusted-root.json"'
            accepted = subprocess.run(
                ["bash", "-c", command, "source-attestation", str(consumer), str(checkout), commit],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            policy = checkout / "deploy/release-policy.json"
            subprocess.run(
                ["git", "-C", str(checkout), "update-index", "--skip-worktree", "deploy/release-policy.json"],
                check=True,
            )
            policy.write_text(policy.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            refused = subprocess.run(
                ["bash", "-c", command, "source-attestation", str(consumer), str(checkout), commit],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("does not byte-match source commit", refused.stderr)

    def test_image_source_contract_is_one_atomic_durable_update_and_partial_candidate_retries(self):
        configure_body = self.installer.split("configure_image_source() {", 1)[1].split(
            "\n}\n\nattest_local_release_image()", 1
        )[0]
        self.assertEqual(configure_body.count("set_image_source_contract_atomically"), 1)
        self.assertNotIn('set_env_value "$key"', configure_body)
        contract_lines = [
            "BACKUPSHEEP_IMAGE_MODE|signed-release",
            "BACKUPSHEEP_RELEASE_TAG|v1.2.3",
            f"BACKUPSHEEP_RELEASE_SOURCE_COMMIT|{'a' * 40}",
            f"BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256|sha256:{'b' * 64}",
            f"BACKUPSHEEP_RELEASE_APP_IMAGE|ghcr.io/bilal414/backupsheep@sha256:{'c' * 64}",
            f"BACKUPSHEEP_RELEASE_POSTGRES_IMAGE|ghcr.io/bilal414/backupsheep-postgres@sha256:{'d' * 64}",
            f"BACKUPSHEEP_RELEASE_EGRESS_IMAGE|ghcr.io/bilal414/backupsheep-egress@sha256:{'e' * 64}",
            f"BACKUPSHEEP_IMAGE|ghcr.io/bilal414/backupsheep@sha256:{'c' * 64}",
            f"BACKUPSHEEP_POSTGRES_IMAGE|ghcr.io/bilal414/backupsheep-postgres@sha256:{'d' * 64}",
            f"BACKUPSHEEP_EGRESS_IMAGE|ghcr.io/bilal414/backupsheep-egress@sha256:{'e' * 64}",
        ]
        with tempfile.TemporaryDirectory(prefix="backupsheep-image-contract-") as directory:
            install_dir = Path(directory)
            install_dir.chmod(0o700)
            env_file = install_dir / ".env"
            original = "EXISTING='preserved'\n"
            env_file.write_text(original, encoding="utf-8")
            env_file.chmod(0o600)
            command = 'source "$1"; INSTALL_DIR="$2"; ENV_FILE="$2/.env"; reconcile_image_source_contract_candidate'
            for boundary in range(len(contract_lines) + 1):
                candidate = install_dir / ".env.image-source.new"
                candidate.write_text("\n".join(contract_lines[:boundary]), encoding="utf-8")
                candidate.chmod(0o600)
                result = subprocess.run(
                    ["bash", "-c", command, "image-contract-retry", str(INSTALLER), str(install_dir)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with self.subTest(boundary=boundary):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(env_file.read_text(encoding="utf-8"), original)
                    self.assertFalse(candidate.exists())
            contract = "\x1c".join(contract_lines) + "\x1c"
            applied = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; INSTALL_DIR="$2"; ENV_FILE="$2/.env"; set_image_source_contract_atomically "$3"',
                    "image-contract-apply",
                    str(INSTALLER),
                    str(install_dir),
                    contract,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            rendered = env_file.read_text(encoding="utf-8")
            self.assertIn("EXISTING='preserved'", rendered)
            for line in contract_lines:
                key, value = line.split("|", 1)
                self.assertEqual(rendered.count(f"{key}='{value}'"), 1)

    def test_signed_release_download_and_docker_clients_are_bounded_and_scrubbed(self):
        consumer = (ROOT / "deploy/release/consume-signed-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$CURL_BIN" --disable --fail', consumer)
        self.assertIn("/usr/bin/env -i LC_ALL=C", consumer)
        self.assertIn('--max-filesize "$maximum"', consumer)
        self.assertIn('run_bounded 310 "release asset download"', consumer)
        self.assertIn('run_bounded 600 "Cosign verifier pull"', consumer)
        self.assertIn('run_bounded 600 "${role} digest pull"', consumer)
        self.assertIn('run_bounded 180 "Cosign verification"', consumer)
        self.assertIn('kill -TERM -- "-$ACTIVE_PID"', consumer)
        self.assertIn('kill -KILL -- "-$ACTIVE_PID"', consumer)
        self.assertIn("DOCKER_ENV=(/usr/bin/env -i", consumer)
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY"):
            self.assertIn(f"--env {variable}=", consumer)
        for variable in (
            "COSIGN_REPOSITORY", "COSIGN_EXPERIMENTAL", "SIGSTORE_NO_CACHE",
            "HTTP_PROXY", "http_proxy", "FTP_PROXY", "ftp_proxy",
            "SSL_CERT_FILE", "DOCKER_CONFIG",
        ):
            self.assertIn(f"--env {variable}=", consumer)

    def test_signed_release_signal_handlers_force_interrupted_status(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        phases = ("release asset download", "Cosign verification", "app digest pull")
        for (signal_number, expected), phase in zip(
            ((signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143)), phases
        ):
            with tempfile.TemporaryDirectory(prefix="backupsheep-signal-tree-") as directory:
                descendant_file = Path(directory) / "descendant.pid"
                command = r'''
source "$1"
INSTALL_DIR="$4"
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
printf 'ready\n'
run_bounded_capture 30 "$2" sh -c 'printf "%s\n" "$$" > "$1"; printf captured; sleep 30' child "$3"
'''
                process = subprocess.Popen(
                    [
                        "bash",
                        "-c",
                        command,
                        "release-signal-test",
                        str(consumer),
                        phase,
                        str(descendant_file),
                        directory,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(process.stdout.readline(), "ready\n")
                for _ in range(50):
                    if descendant_file.exists():
                        break
                    time.sleep(0.02)
                self.assertTrue(descendant_file.exists())
                descendant_pid = int(descendant_file.read_text().strip())
                process.send_signal(signal_number)
                stdout, stderr = process.communicate(timeout=10)
                with self.subTest(signal=signal_number, phase=phase):
                    self.assertEqual(process.returncode, expected, (stdout, stderr))
                    with self.assertRaises(ProcessLookupError):
                        os.kill(descendant_pid, 0)

    def test_signed_release_watchdog_handles_fast_exit_and_kills_timeout_tree(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        fast = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; run_bounded 2 quick true; ! run_bounded 2 quick false',
                "release-watchdog-test",
                str(consumer),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(fast.returncode, 0, fast.stderr)
        with tempfile.TemporaryDirectory(prefix="backupsheep-timeout-tree-") as directory:
            descendant_file = Path(directory) / "descendant.pid"
            timed = subprocess.run(
                [
                    "bash",
                    "-c",
                    r'''source "$1"
run_bounded 1 timeout sh -c 'trap "" TERM; printf "%s\n" "$$" > "$1"; sleep 30' child "$2"
''',
                    "release-watchdog-test",
                    str(consumer),
                    str(descendant_file),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=12,
            )
            self.assertEqual(timed.returncode, 124, timed.stderr)
            descendant_pid = int(descendant_file.read_text().strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(descendant_pid, 0)

    def test_signed_release_residue_and_named_verifier_reconciliation_is_fail_closed(self):
        consumer = (ROOT / "deploy/release/consume-signed-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("validate_residue_dir", consumer)
        self.assertIn("release residue is still mounted by a Docker container", consumer)
        self.assertIn("(( count <= 8 ))", consumer)
        self.assertIn("--name \"$VERIFIER_NAME\"", consumer)
        self.assertIn("com.backupsheep.installation-path-sha256", consumer)
        self.assertIn("attest_verifier_container", consumer)
        self.assertIn("reconcile_evidence_refresh", consumer)
        self.assertIn('chmod 0755 "$VERIFIER_DIR"', consumer)
        self.assertIn('expected_mode="755"', consumer)
        self.assertIn('--workdir /', consumer)
        self.assertIn("'[\"/ko-app/cosign\"]|null|/|null||null|0'", consumer)
        self.assertNotIn('$(file_links "$path")" == "2"', consumer)
        self.assertNotIn('$(file_links "$evidence")" == "2"', consumer)
        self.assertIn('run_bounded 30 "durable release evidence sync"', consumer)
        self.assertGreaterEqual(consumer.count("durable_sync"), 4)
        create_block = consumer[consumer.index("cosign() {"):consumer.index("verify_signatures() {")]
        self.assertLess(
            create_block.index("VERIFIER_CREATE_UNCERTAIN=true"),
            create_block.index('run_bounded 30 "Cosign verifier creation"'),
        )
        self.assertIn("RECOVERY_VERIFIER_DIR", consumer)
        self.assertNotIn("quiesce_verifier_creation_residue", consumer)
        self.assertIn('size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 ))', consumer)
        self.assertIn("installation path contains Docker mount or filter metacharacters", consumer)
        self.assertIn("--install-dir cannot contain a comma", self.installer)
        command = r'''
source "$1"
docker_client() {
  if [[ "$1" == ps ]]; then
    printf '%064d\n' 1
  elif [[ "$1" == inspect ]]; then
    printf '/unrelated/source\n'
  else
    return 1
  fi
}
containers_mounting_path /wanted/source
docker_client() {
  if [[ "$1" == ps ]]; then
    printf '%064d\n' 1
  elif [[ "$1" == inspect ]]; then
    printf '/wanted/source\n'
  else
    return 1
  fi
}
if containers_mounting_path /wanted/source; then exit 1; else test "$?" -eq 10; fi
docker_client() {
  if [[ "$1" == ps ]]; then
    printf '%064d\n' 1
  elif [[ "$1" == inspect ]]; then
    printf '/wanted\n'
  else
    return 1
  fi
}
if containers_mounting_path /wanted/source; then exit 1; else test "$?" -eq 10; fi
docker_client() {
  if [[ "$1" == ps ]]; then
    printf '%064d\n' 1
  elif [[ "$1" == inspect ]]; then
    printf '/wanted/source/nested/file\n'
  else
    return 1
  fi
}
if containers_mounting_path /wanted/source; then exit 1; else test "$?" -eq 10; fi
'''
        result = subprocess.run(
            ["bash", "-c", command, "release-mount-test", str(ROOT / "deploy/release/consume-signed-release.sh")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for blocked_call in ("ps", "inspect"):
            timeout_command = rf'''
source "$1"
docker_client() {{
  if [[ "$1" == ps ]]; then
    {'sleep 30' if blocked_call == 'ps' else "printf '%064d\\n' 1"}
  elif [[ "$1" == inspect ]]; then
    {'sleep 30' if blocked_call == 'inspect' else 'return 1'}
  fi
}}
if containers_mounting_path /wanted/source 1; then exit 1; else test "$?" -eq 124; fi
'''
            timeout_result = subprocess.run(
                [
                    "bash",
                    "-c",
                    timeout_command,
                    "release-mount-timeout-test",
                    str(ROOT / "deploy/release/consume-signed-release.sh"),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            with self.subTest(blocked_call=blocked_call):
                self.assertEqual(timeout_result.returncode, 0, timeout_result.stderr)
        self.assertLess(
            consumer.index("reconcile_verifier_orphan\n    cleanup_residues"),
            consumer.index('STAGING_DIR="$(mktemp'),
        )

        with tempfile.TemporaryDirectory(prefix="backupsheep-apfs-links-") as directory:
            root = Path(directory)
            residue = root / ".release-evidence.download.ABCDEFGH"
            evidence = root / ".release-evidence"
            residue.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            for name in (
                "backupsheep-release-descriptor-v2.txt",
                "backupsheep-release-descriptor-v2.sigstore.json",
                "release-manifest.json",
                "sigstore-trusted-root.json",
                "signature-verification.json",
            ):
                path = residue / name
                path.write_text("x\n", encoding="utf-8")
                path.chmod(0o600)
            for name in (
                "backupsheep-release-descriptor-v2.txt",
                "backupsheep-release-descriptor-v2.sigstore.json",
                "release-manifest.json",
                "sigstore-trusted-root.json",
                "signature-verification.json",
            ):
                path = evidence / name
                if name == "sigstore-trusted-root.json":
                    path.write_bytes(
                        (ROOT / "deploy/release/sigstore-trusted-root.json").read_bytes()
                    )
                else:
                    path.write_text("x\n", encoding="utf-8")
                path.chmod(0o600)
            receipt = evidence / "local-images.txt"
            receipt.write_text(
                "".join(
                    f"{role}_image_id=sha256:{index * 64}\n"
                    for index, role in zip(
                        "123456",
                        (
                            "app", "postgres", "egress", "rabbitmq",
                            "rabbitmq_upgrade", "cosign",
                        ),
                    )
                ),
                encoding="utf-8",
            )
            receipt.chmod(0o600)
            portable_links = subprocess.run(
                [
                    "bash",
                    "-c",
                    r'''source "$1"
file_links() {
  if [[ -d "$1" ]]; then printf '7\n';
  else stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"; fi
}
validate_residue_dir "$2"
validate_persisted_evidence "$3"
''',
                    "apfs-link-test",
                    str(ROOT / "deploy/release/consume-signed-release.sh"),
                    str(residue),
                    str(evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(portable_links.returncode, 0, portable_links.stderr)

    def test_signed_release_shell_descriptor_parser_rejects_adversarial_lines(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        tag = "v1.2.3-rc.1"
        commit = "a" * 40
        with tempfile.TemporaryDirectory(prefix="backupsheep-release-parser-") as directory:
            root = Path(directory)
            manifest = root / "release-manifest.json"
            manifest.write_bytes(b'{"test":true}\n')
            manifest.chmod(0o600)
            manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            descriptor = (
                "BACKUPSHEEP-SIGNED-RELEASE-V2\n"
                f"release_tag={tag}\n"
                f"source_commit={commit}\n"
                f"release_manifest_sha256=sha256:{manifest_digest}\n"
                f"app_image=ghcr.io/bilal414/backupsheep@sha256:{'1' * 64}\n"
                f"postgres_image=ghcr.io/bilal414/backupsheep-postgres@sha256:{'2' * 64}\n"
                f"egress_image=ghcr.io/bilal414/backupsheep-egress@sha256:{'3' * 64}\n"
                f"rabbitmq_image=ghcr.io/bilal414/backupsheep-rabbitmq@sha256:{'4' * 64}\n"
                f"rabbitmq_upgrade_image=ghcr.io/bilal414/backupsheep-rabbitmq-upgrade@sha256:{'5' * 64}\n"
                "release_verifier_image=ghcr.io/bilal414/backupsheep-release-verifier@sha256:ba8edf9b99437ffc62650133972365eb381b39b46f208d33c82f8949b159cd5e\n"
                "release_verifier_runtime_contract_version=1\n"
                "release_verifier_linux_amd64_manifest=sha256:29c25a1a2bcbe8190166f65e0914fbd4c904968be5a615f59421dc8fd4526f06\n"
                "release_verifier_linux_amd64_config=sha256:6feeb7c97d6b7b709f2dc6b33723de442205437694fd3679461d78635745349d\n"
                "release_verifier_linux_arm64_manifest=sha256:2d0bfa77e828bff3c198039763f05f44017e6c2cd75572fce8f61431a95b927d\n"
                "release_verifier_linux_arm64_config=sha256:9a6ceeac0bc63631bd168417839d56e01a2ee157411daef235df13e0c8d04c01\n"
                "trusted_root_sha256=sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66\n"
            )
            descriptor_path = root / "descriptor.txt"
            command = (
                'source "$1"; validate_descriptor "$2" "$3" "$4" "$5"'
            )
            cases = (
                (descriptor, True),
                (descriptor.replace("SIGNED-RELEASE-V2", "SIGNED-RELEASE-V1", 1), False),
                (descriptor.replace("release_tag=", "source_commit=", 1), False),
                (descriptor.replace("ghcr.io/bilal414/backupsheep@", "ghcr.io/attacker/backupsheep@", 1), False),
                (descriptor.replace("release_verifier_runtime_contract_version=1", "release_verifier_runtime_contract_version=2", 1), False),
                (descriptor + "app_image=duplicate\n", False),
                (descriptor.rstrip("\n"), False),
                (descriptor.replace("\n", "\r\n", 1), False),
            )
            for payload, accepted in cases:
                descriptor_path.write_bytes(payload.encode("ascii"))
                descriptor_path.chmod(0o600)
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        command,
                        "release-parser-test",
                        str(consumer),
                        str(descriptor_path),
                        tag,
                        commit,
                        str(manifest),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with self.subTest(payload=payload[:80]):
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_signed_release_local_image_receipt_has_exact_ordered_six_line_grammar(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        keys = (
            "app_image_id",
            "postgres_image_id",
            "egress_image_id",
            "rabbitmq_image_id",
            "rabbitmq_upgrade_image_id",
            "cosign_image_id",
        )
        canonical = "".join(
            f"{key}=sha256:{index:064x}\n" for index, key in enumerate(keys, 1)
        )
        cases = (
            (canonical, True),
            (canonical.replace(keys[1], keys[0], 1), False),
            (
                canonical.splitlines(keepends=True)[1]
                + canonical.splitlines(keepends=True)[0]
                + "".join(canonical.splitlines(keepends=True)[2:]),
                False,
            ),
            (canonical + f"extra_image_id=sha256:{7:064x}\n", False),
            (canonical.rstrip("\n"), False),
            (canonical.replace("sha256:", "sha256:\x01", 1), False),
        )
        with tempfile.TemporaryDirectory(prefix="backupsheep-image-receipt-") as directory:
            receipt = Path(directory) / "local-images.txt"
            for payload, accepted in cases:
                receipt.write_bytes(payload.encode("ascii"))
                receipt.chmod(0o600)
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; validate_local_image_receipt "$2"',
                        "release-receipt-test",
                        str(consumer),
                        str(receipt),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with self.subTest(payload=repr(payload[:100])):
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_signed_release_daemon_platform_is_linux_and_scanned_arch_only(self):
        consumer = ROOT / "deploy/release/consume-signed-release.sh"
        command = r'''
source "$1"
MOCK_PLATFORM="$2"
INSTALL_DIR="$3"
docker_client() {
    if [[ "$1" == version ]]; then
        printf '%s\n' "$MOCK_PLATFORM"
    else
        printf '%s\n' 'daemon-test-id'
    fi
}
attest_docker_daemon_platform
'''
        with tempfile.TemporaryDirectory(prefix="backupsheep-platform-capture-") as directory:
            for platform, accepted in (
                ("linux|amd64", True),
                ("linux|arm64", True),
                ("linux|386", False),
                ("darwin|arm64", False),
                ("linux|x86_64", False),
            ):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        command,
                        "release-platform-test",
                        str(consumer),
                        platform,
                        directory,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                with self.subTest(platform=platform):
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

        source = consumer.read_text(encoding="utf-8")
        self.assertIn("persisted local image receipt conflicts with attested images", source)
        self.assertNotIn(
            'mv -f -- "$EVIDENCE_DIR/local-images.txt.new" "$EVIDENCE_DIR/local-images.txt"',
            source,
        )

    def test_signed_release_overlay_removes_all_release_builds_and_never_pulls(self):
        overlay = (ROOT / "deploy/release/signed-release.compose.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(overlay.count("build: !reset null"), 6)
        self.assertEqual(overlay.count("pull_policy: never"), 6)
        self.assertIn("signed-release.compose.yml", self.installer)
        self.assertIn("Signed-release Compose model contains a build definition", self.installer)

    def test_installer_validates_model_shaping_values_before_compose(self):
        model_validator = self.installer.index("validate_compose_model_settings")
        compose_validation = self.installer.index("compose config --quiet", model_validator)
        self.assertLess(
            self.installer.index("validate_compose_model_settings", model_validator + 1),
            compose_validation,
        )
        self.assertIn(
            "Signed-release Compose model contains an unsafe tmpfs mount option",
            self.installer,
        )
        invalid = (
            ("BACKUPSHEEP_TMPFS_SIZE", "256m,exec,suid,dev", "integer size"),
            ("POSTGRES_PIDS_LIMIT", "0", "reviewed resource range"),
            ("APP_CPU_LIMIT", "64.001", "canonical CPU value"),
            ("APP_MEMORY_LIMIT", "99999999g", "reviewed resource range"),
            ("BACKUPSHEEP_STOP_GRACE_PERIOD", "5m,exec", "canonical nonzero duration"),
        )
        with tempfile.TemporaryDirectory(prefix="backupsheep-model-settings-") as root:
            env_path = Path(root) / ".env"
            for key, value, expected in invalid:
                with self.subTest(key=key):
                    env_path.write_text(f"{key}='{value}'\n", encoding="utf-8")
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            'source "$1"; ENV_FILE="$2"; validate_compose_model_settings',
                            "installer-model-settings-test",
                            str(INSTALLER),
                            str(env_path),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)
            env_path.write_text(
                "BACKUPSHEEP_TMPFS_SIZE='256m'\nAPP_CPU_LIMIT='2.000'\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; ENV_FILE="$2"; validate_compose_model_settings',
                    "installer-model-settings-test",
                    str(INSTALLER),
                    str(env_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_signed_wrapper_binds_runtime_files_and_service_roles_to_source_commit(self):
        wrapper = (ROOT / "backupsheep-compose").read_text(encoding="utf-8")
        self.assertIn("validate_signed_release_source_checkout", wrapper)
        self.assertIn("signed-release checkout HEAD does not match its release receipt", wrapper)
        self.assertIn("https://github.com/bilal414/backupsheep.git", wrapper)
        for relative in (
            "backupsheep-compose",
            "docker-compose.yml",
            "deploy/release/signed-release.compose.yml",
            "deploy/rabbitmq/upgrade-4.2.9.compose.yml",
            "deploy/release-policy.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, wrapper)
        self.assertIn("does not byte-match its source commit", wrapper)
        self.assertIn("deployment overrides are outside the exact signed-release runtime model", wrapper)
        self.assertIn("signed-release Compose model service set or order changed", wrapper)
        self.assertIn("does not use its exact role image", wrapper)
        for forbidden in (
            "use_api_socket",
            "provider",
            "develop",
            "post_start",
            "pre_stop",
            "extends",
            "include",
            "devices",
            "device_cgroup_rules",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertIn(forbidden, wrapper)
        self.assertIn(
            "Signed-release mode rejects docker-compose.override.yml", self.installer
        )
        self.assertIn('"COMPOSE_MENU=false"', self.installer)

    def test_fresh_configuration_crash_boundaries_converge_without_legacy_classification(self):
        base_setup = r'''
source "$1"
INSTALL_DIR="$2"
INSTALL_REF="$3"
PROJECT_NAME=backupsheep
IMAGE_MODE=local-build
PUBLIC_HOST=localhost
APP_DOMAIN=localhost:8000
ENV_FILE="$2/.env"
DOCKER_BIN=mock_docker
mock_docker() {
    if [[ "$1" == volume && "$2" == ls ]]; then return 0; fi
    return 64
}
'''
        finish = r'''
reconcile_installer_temp_residues
reconcile_fresh_env_candidate
create_or_migrate_configuration
validate_runtime_configuration
'''

        def new_installation():
            temporary = tempfile.TemporaryDirectory(prefix="backupsheep-fresh-resume-")
            install_dir = Path(temporary.name)
            install_dir.chmod(0o700)
            sample = install_dir / ".env_sample"
            shutil.copyfile(SAMPLE_ENV, sample)
            sample.chmod(0o600)
            return temporary, install_dir

        def run(install_dir, body):
            return subprocess.run(
                [
                    "bash",
                    "-c",
                    base_setup + body,
                    "fresh-resume-test",
                    str(INSTALLER),
                    str(install_dir),
                    COMMIT,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

        temporary, install_dir = new_installation()
        try:
            candidate = install_dir / ".env.fresh.new"
            candidate.write_bytes(b"")
            candidate.chmod(0o600)
            resumed = run(install_dir, finish)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertIn(
                "BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE='complete'",
                (install_dir / ".env").read_text(encoding="utf-8"),
            )
        finally:
            temporary.cleanup()

        # Exercise every mutating call in the current fresh-install path.  These
        # bounds intentionally fail if the implementation adds a later mutation
        # without extending the crash matrix.
        for function_name, boundaries in (
            ("write_secret_file", range(1, 23)),
            ("set_env_value", range(1, 24)),
        ):
            for boundary in boundaries:
                with self.subTest(function=function_name, boundary=boundary):
                    temporary, install_dir = new_installation()
                    try:
                        staged = run(install_dir, "create_fresh_env_atomically\n")
                        self.assertEqual(staged.returncode, 0, staged.stderr)
                        pending = (install_dir / ".env").read_text(encoding="utf-8")
                        self.assertIn(
                            "BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE='pending-fresh'",
                            pending,
                        )
                        crash = rf'''
reconcile_installer_temp_residues
reconcile_fresh_env_candidate
definition="$(declare -f {function_name})"
eval "${{definition/{function_name}/original_{function_name}}}"
boundary_count=0
{function_name}() {{
    original_{function_name} "$@"
    boundary_count=$((boundary_count + 1))
    if [[ "$boundary_count" -eq {boundary} ]]; then kill -KILL "$$"; fi
}}
create_or_migrate_configuration
exit 97
'''
                        interrupted = run(install_dir, crash)
                        self.assertEqual(interrupted.returncode, -signal.SIGKILL, interrupted.stderr)
                        resumed = run(install_dir, finish)
                        self.assertEqual(resumed.returncode, 0, resumed.stderr)
                        completed = (install_dir / ".env").read_text(encoding="utf-8")
                        self.assertIn(
                            "BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE='complete'",
                            completed,
                        )
                        self.assertFalse(list(install_dir.glob(".env-update.*")))
                        self.assertFalse(list(install_dir.glob(".env-artifact-policy.*")))
                    finally:
                        temporary.cleanup()

        # The related RabbitMQ/Celery generation fields are one atomic contract.
        # Interrupt immediately before and after each of its two publications in
        # a true first invocation; no partially promoted generation may appear.
        for phase in ("before", "after"):
            for boundary in (1, 2):
                with self.subTest(function="set_env_values_atomically", phase=phase, boundary=boundary):
                    temporary, install_dir = new_installation()
                    try:
                        crash = rf'''
reconcile_installer_temp_residues
reconcile_fresh_env_candidate
definition="$(declare -f set_env_values_atomically)"
eval "${{definition/set_env_values_atomically/original_set_env_values_atomically}}"
boundary_count=0
set_env_values_atomically() {{
    boundary_count=$((boundary_count + 1))
    if [[ "{phase}" == before && "$boundary_count" -eq {boundary} ]]; then kill -KILL "$$"; fi
    original_set_env_values_atomically "$@"
    if [[ "{phase}" == after && "$boundary_count" -eq {boundary} ]]; then kill -KILL "$$"; fi
}}
create_or_migrate_configuration
exit 97
'''
                        interrupted = run(install_dir, crash)
                        self.assertEqual(interrupted.returncode, -signal.SIGKILL, interrupted.stderr)
                        resumed = run(install_dir, finish)
                        self.assertEqual(resumed.returncode, 0, resumed.stderr)
                        completed = (install_dir / ".env").read_text(encoding="utf-8")
                        self.assertIn(
                            "BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE='complete'",
                            completed,
                        )
                        self.assertFalse(list(install_dir.glob(".env-update.*")))
                    finally:
                        temporary.cleanup()

        configuration_body = self.installer.split(
            "if [[ \"$FRESH_CONFIG_PENDING\" == true ]]; then", 2
        )[-1].split("FRESH_CONFIG_PENDING=false", 1)[0]
        self.assertLess(
            configuration_body.index('sync || die "Could not durably stage'),
            configuration_body.index(
                "set_env_value BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE complete"
            ),
        )


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

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def run_installer_functions(self, body, *, check=True):
        if (
            "create_or_migrate_configuration" in body
            or "configure_artifact_key_policy" in body
        ):
            configured = self.env_file.read_text(encoding="utf-8")
            match = re.search(
                r"^BACKUPSHEEP_INSTALLATION_ID='([0-9a-f]{64})'$",
                configured,
                re.MULTILINE,
            )
            if match is None:
                configured = configured.replace(
                    "BACKUPSHEEP_INSTALLATION_ID=''",
                    f"BACKUPSHEEP_INSTALLATION_ID='{'a' * 64}'",
                    1,
                )
                self.env_file.write_text(configured, encoding="utf-8")
                self.env_file.chmod(0o600)
                installation_id = "a" * 64
            else:
                installation_id = match.group(1)
            secret_dir = self.temp_dir / ".secrets"
            secret_dir.mkdir(mode=0o700, exist_ok=True)
            for lane, marker in (("database", "1"), ("files", "2")):
                key_id = f"lfk-{marker * 32}"
                keyring = secret_dir / f"artifact_local_file_{lane}_keyring"
                if not keyring.exists():
                    keyring.write_text(
                        "BACKUPSHEEP-ARTIFACT-KEYRING-V1\n"
                        f"installation={installation_id}\n"
                        f"lane={lane}\n"
                        f"active={key_id}\n"
                        f"key={key_id}:{marker * 64}\n",
                        encoding="ascii",
                    )
                    keyring.chmod(0o444)
        command = f"""
source "$1"
INSTALL_DIR="$2"
INSTALL_REF="$3"
PUBLIC_HOST=localhost
APP_DOMAIN=localhost:8000
INSTALL_WAS_PRESENT=true
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
        database_keyring = secret_dir / "artifact_local_file_database_keyring"
        files_keyring = secret_dir / "artifact_local_file_files_keyring"
        self.assertEqual(stat.S_IMODE(database_keyring.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(files_keyring.stat().st_mode), 0o444)
        self.assertNotEqual(database_keyring.read_bytes(), files_keyring.read_bytes())
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

    def test_artifact_lane_keyrings_require_distinct_ids_and_material(self):
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        key_id = "lfk-11111111111111111111111111111111"
        for lane in ("database", "files"):
            path = secret_dir / f"artifact_local_file_{lane}_keyring"
            path.write_text(
                "BACKUPSHEEP-ARTIFACT-KEYRING-V1\n"
                f"installation={'a' * 64}\n"
                f"lane={lane}\n"
                f"active={key_id}\n"
                f"key={key_id}:{'1' * 64}\n",
                encoding="ascii",
            )
            path.chmod(0o444)
        result = self.run_installer_functions(
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "validate_distinct_artifact_keyrings",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("share a key identity or root key", result.stderr)

    def test_installer_keyring_parser_requires_active_key_first(self):
        self.env_file.write_text(
            self.env_file.read_text(encoding="utf-8").replace(
                "BACKUPSHEEP_INSTALLATION_ID=''",
                f"BACKUPSHEEP_INSTALLATION_ID='{'a' * 64}'",
                1,
            ),
            encoding="utf-8",
        )
        self.env_file.chmod(0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        keyring = secret_dir / "artifact_local_file_database_keyring"
        keyring.write_text(
            "BACKUPSHEEP-ARTIFACT-KEYRING-V1\n"
            f"installation={'a' * 64}\n"
            "lane=database\n"
            "active=lfk-22222222222222222222222222222222\n"
            f"key=lfk-11111111111111111111111111111111:{'1' * 64}\n"
            f"key=lfk-22222222222222222222222222222222:{'2' * 64}\n",
            encoding="ascii",
        )
        keyring.chmod(0o444)

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'validate_artifact_keyring_content '
            '"$INSTALL_DIR/.secrets/artifact_local_file_database_keyring" database',
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active artifact key must be first", result.stderr)

    def test_fresh_artifact_keyrings_are_random_distinct_and_rerun_exact(self):
        shutil.copyfile(SAMPLE_ENV, self.env_file)
        os.chmod(self.env_file, 0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        body = (
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=false\n"
            f"set_env_value BACKUPSHEEP_INSTALLATION_ID {'a' * 64}\n"
            "set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION 3-pending-fresh\n"
            "configure_artifact_keyrings false\n"
            "validate_secret_dir"
        )
        self.run_installer_functions(body)

        before = {}
        identities = set()
        material = set()
        for lane in ("database", "files"):
            path = secret_dir / f"artifact_local_file_{lane}_keyring"
            before[lane] = path.read_bytes()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(path.stat().st_nlink, 1)
            lines = path.read_text(encoding="ascii").splitlines()
            self.assertEqual(
                lines[:3],
                [
                    "BACKUPSHEEP-ARTIFACT-KEYRING-V1",
                    f"installation={'a' * 64}",
                    f"lane={lane}",
                ],
            )
            self.assertRegex(lines[3], r"^active=lfk-[0-9a-f]{32}$")
            key_id, key_hex = lines[4].removeprefix("key=").split(":", 1)
            self.assertEqual(lines[3], f"active={key_id}")
            self.assertRegex(key_hex, r"^[0-9a-f]{64}$")
            identities.add(key_id)
            material.add(key_hex)
        self.assertEqual(len(identities), 2)
        self.assertEqual(len(material), 2)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "configure_artifact_keyrings false\n"
            "validate_secret_dir"
        )
        self.assertEqual(
            before,
            {
                lane: (secret_dir / f"artifact_local_file_{lane}_keyring").read_bytes()
                for lane in ("database", "files")
            },
        )

    def test_legacy_artifact_provider_transition_is_explicit_current_and_lossless(self):
        installation_id = "a" * 64
        configured = self.env_file.read_text(encoding="utf-8")
        configured = configured.replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='aws-kms'",
            1,
        )
        configured += (
            "BACKUPSHEEP_ARTIFACT_CHUNK_SIZE='8388608'\n"
            "AWS_ENDPOINT_URL_KMS='https://retired.example.invalid'\n"
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)

        refused = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=false\n"
            "configure_artifact_key_policy",
            check=False,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("--migrate-artifact-key-provider-empty", refused.stderr)
        self.assertIn(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='aws-kms'",
            self.env_file.read_text(encoding="utf-8"),
        )

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy"
        )
        pending = self.env_file.read_text(encoding="utf-8")
        expected_pending = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{installation_id}|local-file|generation=1-pending-empty"
            ).encode("ascii")
        ).hexdigest()
        self.assertIn("BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'", pending)
        self.assertIn(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION='1-pending-empty'",
            pending,
        )
        self.assertIn(
            f"BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS='{expected_pending}'",
            pending,
        )
        self.assertEqual(pending.count("BACKUPSHEEP_ARTIFACT_CHUNK_SIZE="), 1)
        self.assertIn("BACKUPSHEEP_ARTIFACT_CHUNK_SIZE='8388608'", pending)
        self.assertNotIn("AWS_ENDPOINT_URL_KMS", pending)
        rollback_path = self.temp_dir / ".secrets" / "artifact_provider_transition_rollback"
        self.assertTrue(rollback_path.is_file())
        self.assertEqual(stat.S_IMODE(rollback_path.stat().st_mode), 0o400)
        self.assertIn(
            b"AWS_ENDPOINT_URL_KMS='https://retired.example.invalid'",
            rollback_path.read_bytes(),
        )

        legacy_names = (
            "artifact_kms_database_aws_credentials",
            "artifact_kms_files_aws_credentials",
        )
        secret_dir = self.temp_dir / ".secrets"
        for name in legacy_names:
            path = secret_dir / name
            path.write_text("retained-rollback-evidence\n", encoding="ascii")
            path.chmod(0o444)
        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "seal_artifact_key_provider_migration"
        )
        sealed = self.env_file.read_text(encoding="utf-8")
        expected_final = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{installation_id}|local-file|generation=1"
            ).encode("ascii")
        ).hexdigest()
        self.assertIn(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION='1'",
            sealed,
        )
        self.assertIn(
            f"BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS='{expected_final}'",
            sealed,
        )
        self.assertIn("BACKUPSHEEP_ARTIFACT_CHUNK_SIZE='8388608'", sealed)
        for name in legacy_names:
            self.assertTrue((secret_dir / name).exists())
        self.assertTrue(rollback_path.exists())

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "complete_artifact_key_provider_migration"
        )
        for name in legacy_names:
            self.assertFalse((secret_dir / name).exists())
        self.assertFalse(rollback_path.exists())

    def test_local_development_transition_preserves_root_without_logging_it(self):
        installation_id = "c" * 64
        root_key = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
        configured = self.env_file.read_text(encoding="utf-8")
        configured = configured.replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-development'",
            1,
        )
        configured += (
            f"BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY='{root_key}'\n"
            "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID='legacy-local-key'\n"
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)
        body = (
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy"
        )

        first = self.run_installer_functions(body)
        self.assertNotIn(root_key, first.stdout + first.stderr)
        rollback = self.temp_dir / ".secrets" / "artifact_provider_transition_rollback"
        original = rollback.read_bytes()
        self.assertIn(root_key.encode("ascii"), original)
        self.assertEqual(stat.S_IMODE(rollback.stat().st_mode), 0o400)
        pending = self.env_file.read_text(encoding="utf-8")
        self.assertNotIn(root_key, pending)
        self.assertRegex(
            pending,
            r"BACKUPSHEEP_ARTIFACT_PROVIDER_ROLLBACK_SHA256='[0-9a-f]{64}'",
        )

        resumed = self.run_installer_functions(body)
        self.assertNotIn(root_key, resumed.stdout + resumed.stderr)
        self.assertEqual(rollback.read_bytes(), original)

    def test_legacy_kms_endpoint_rollback_rejects_duplicate_or_malformed_keys(self):
        installation_id = "8" * 64
        base = self.env_file.read_text(encoding="utf-8").replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='aws-kms'",
            1,
        )
        cases = (
            (
                "duplicate",
                "AWS_ENDPOINT_URL_KMS='https://one.invalid'\n"
                "AWS_ENDPOINT_URL_KMS='https://two.invalid'\n",
                "cannot be preserved safely",
            ),
            (
                "malformed",
                " AWS_ENDPOINT_URL_KMS='https://space.invalid'\n",
                "is malformed",
            ),
        )
        for name, endpoint_lines, expected_error in cases:
            with self.subTest(name=name):
                rollback = (
                    self.temp_dir
                    / ".secrets"
                    / "artifact_provider_transition_rollback"
                )
                rollback.unlink(missing_ok=True)
                self.env_file.write_text(base + endpoint_lines, encoding="utf-8")
                self.env_file.chmod(0o600)
                before = self.env_file.read_bytes()

                result = self.run_installer_functions(
                    'ENV_FILE="$INSTALL_DIR/.env"\n'
                    'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
                    "ENV_WAS_PRESENT=true\n"
                    "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
                    "configure_artifact_key_policy",
                    check=False,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)
                self.assertEqual(self.env_file.read_bytes(), before)
                self.assertFalse(rollback.exists())

    def test_blank_legacy_artifact_provider_can_only_enter_pending_empty_state(self):
        installation_id = "b" * 64
        configured = self.env_file.read_text(encoding="utf-8")
        configured = configured.replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER=''",
            1,
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy"
        )
        pending = self.env_file.read_text(encoding="utf-8")
        self.assertIn("BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'", pending)
        self.assertIn(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION='1-pending-empty'",
            pending,
        )

    def test_pre_feature_env_with_no_artifact_lines_has_exact_empty_rollback(self):
        configured = "\n".join(
            line
            for line in self.env_file.read_text(encoding="utf-8").splitlines()
            if not line.startswith("BACKUPSHEEP_ARTIFACT_")
        ) + "\n"
        configured = configured.replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{'d' * 64}'",
            1,
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)

        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy"
        )
        rollback = self.temp_dir / ".secrets" / "artifact_provider_transition_rollback"
        self.assertEqual(
            rollback.read_text(encoding="ascii"),
            "BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1\n"
            f"installation={'d' * 64}\n",
        )

    def test_stale_valid_artifact_provider_rollback_does_not_replace_current_policy(self):
        installation_id = "e" * 64
        configured = self.env_file.read_text(encoding="utf-8").replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-development'",
            1,
        )
        configured += "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID='current-key'\n"
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)
        (self.temp_dir / ".secrets").mkdir(mode=0o700)
        rollback = self.temp_dir / ".secrets" / "artifact_provider_transition_rollback"
        rollback.write_text(
            "BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1\n"
            f"installation={installation_id}\n"
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-development'\n"
            "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID='stale-key'\n",
            encoding="ascii",
        )
        rollback.chmod(0o400)
        before = self.env_file.read_bytes()

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy",
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not exactly match", result.stderr)
        self.assertEqual(self.env_file.read_bytes(), before)

    def test_foreign_installation_artifact_provider_rollback_is_refused_unchanged(self):
        installation_id = "f" * 64
        configured = self.env_file.read_text(encoding="utf-8").replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        ).replace(
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER=''",
            1,
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)
        (self.temp_dir / ".secrets").mkdir(mode=0o700)
        rollback = self.temp_dir / ".secrets" / "artifact_provider_transition_rollback"
        rollback.write_text(
            "BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1\n"
            f"installation={'0' * 64}\n",
            encoding="ascii",
        )
        rollback.chmod(0o400)
        before = self.env_file.read_bytes()

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true\n"
            "configure_artifact_key_policy",
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rollback is malformed", result.stderr)
        self.assertEqual(self.env_file.read_bytes(), before)

    def test_artifact_provider_completion_follows_fresh_database_proof(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        start_core = installer.split("start_core() {", 1)[1].split("\n}", 1)[0]
        main = installer.split("main() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(
            start_core.index("wait_for_database_seal"),
            start_core.index("seal_artifact_key_provider_migration"),
        )
        self.assertLess(
            start_core.index("seal_artifact_key_provider_migration"),
            start_core.index("validate_runtime_configuration"),
        )
        self.assertNotIn("complete_artifact_key_provider_migration", start_core)
        self.assertLess(main.index("start_core"), main.index("complete_artifact_key_provider_migration"))
        self.assertLess(main.index("start_operations"), main.index("complete_artifact_key_provider_migration"))

    def test_stale_legacy_artifact_credential_requires_transition_rollback(self):
        installation_id = "9" * 64
        configured = self.env_file.read_text(encoding="utf-8").replace(
            "BACKUPSHEEP_INSTALLATION_ID=''",
            f"BACKUPSHEEP_INSTALLATION_ID='{installation_id}'",
            1,
        )
        self.env_file.write_text(configured, encoding="utf-8")
        self.env_file.chmod(0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        credentials = []
        for name in (
            "artifact_kms_database_aws_credentials",
            "artifact_kms_files_aws_credentials",
        ):
            credential = secret_dir / name
            credential.write_text("retired-credential\n", encoding="ascii")
            credential.chmod(0o444)
            credentials.append(credential)

        result = self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "validate_legacy_artifact_provider_secret_state",
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without its protected transition rollback", result.stderr)
        self.assertTrue(all(credential.exists() for credential in credentials))

    def test_artifact_keyring_rotation_requires_exact_witness_and_is_replay_safe(self):
        shutil.copyfile(SAMPLE_ENV, self.env_file)
        os.chmod(self.env_file, 0o600)
        secret_dir = self.temp_dir / ".secrets"
        secret_dir.mkdir(mode=0o700)
        self.run_installer_functions(
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=false\n"
            f"set_env_value BACKUPSHEEP_INSTALLATION_ID {'a' * 64}\n"
            "set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION 3-pending-fresh\n"
            "configure_artifact_keyrings false\n"
            "set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION 3"
        )
        database = secret_dir / "artifact_local_file_database_keyring"
        files = secret_dir / "artifact_local_file_files_keyring"
        old_database = database.read_bytes()
        old_files = files.read_bytes()
        expected = database.read_text(encoding="ascii").splitlines()[3].split("=", 1)[1]
        rotate_body = (
            'ENV_FILE="$INSTALL_DIR/.env"\n'
            'SECRETS_DIR="$INSTALL_DIR/.secrets"\n'
            "ENV_WAS_PRESENT=true\n"
            "PROJECT_NAME=backupsheep\n"
            "ARTIFACT_LOCAL_FILE_ROTATE_LANE=database\n"
            f"ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID={expected}\n"
            "mock_docker() { [[ \"$1\" == ps ]] && return 0; return 64; }\n"
            "configure_artifact_keyrings true"
        )
        self.run_installer_functions(rotate_body)

        rotated = database.read_bytes()
        lines = rotated.decode("ascii").splitlines()
        self.assertNotEqual(rotated, old_database)
        self.assertEqual(sum(line.startswith("key=") for line in lines), 2)
        self.assertEqual(lines[5], old_database.decode("ascii").splitlines()[4])
        self.assertEqual(files.read_bytes(), old_files)

        replay = self.run_installer_functions(rotate_body, check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("refusing stale or repeated rotation", replay.stderr)
        self.assertEqual(database.read_bytes(), rotated)
        self.assertEqual(files.read_bytes(), old_files)

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
        self.env_file.write_text(
            "\n".join(
                line
                for line in self.env_file.read_text(encoding="utf-8").splitlines()
                if not line.startswith("COMPOSE_REMOVE_ORPHANS=")
            )
            + "\n",
            encoding="utf-8",
        )
        self.env_file.chmod(0o600)

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
INSTALL_DIR="$3"
ENV_FILE="$3/.env"
PROJECT_NAME=backupsheep
DOCKER_BIN="$2"
INSTALL_PARENT_IDENTITY="$(directory_inode_identity "$(dirname -- "$INSTALL_DIR")")"
INSTALL_PARENT_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$(dirname -- "$INSTALL_DIR")")"
INSTALL_ROOT_IDENTITY="$(directory_inode_identity "$INSTALL_DIR")"
INSTALL_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$INSTALL_DIR")"
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
                str(self.temp_dir),
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
