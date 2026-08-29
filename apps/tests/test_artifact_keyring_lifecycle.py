"""Operator lifecycle tests for bounded local-file artifact keyrings."""

import fcntl
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from backupsheep.artifact_crypto import LocalFileKeyProvider
from backupsheep.artifact_crypto.providers.local_file import canonical_keyring_bytes
from scripts import manage_artifact_keyring as lifecycle

INSTALLATION_ID = "a" * 64


class ArtifactKeyringLifecycleTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / "database.keyring"

    def tearDown(self):
        self.temporary.cleanup()

    def _interrupt_lifecycle(
        self,
        path: Path,
        *,
        operation: str,
        phase: str,
        expected_active_key_id: str = "",
    ) -> subprocess.CompletedProcess[str]:
        program = r'''
import os
import signal
import sys
from pathlib import Path

from scripts import manage_artifact_keyring as lifecycle

path = Path(sys.argv[1])
operation = sys.argv[2]
phase = sys.argv[3]
expected_active_key_id = sys.argv[4]

if phase == "after-write":
    original_write = lifecycle._write_temporary
    def write_then_kill(*args, **kwargs):
        original_write(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    lifecycle._write_temporary = write_then_kill
elif phase == "after-link":
    original_link = os.link
    def link_then_kill(*args, **kwargs):
        original_link(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    os.link = link_then_kill
elif phase == "after-unlink":
    original_unlink = Path.unlink
    def unlink_then_kill(subject, *args, **kwargs):
        result = original_unlink(subject, *args, **kwargs)
        if subject != path:
            os.kill(os.getpid(), signal.SIGKILL)
        return result
    Path.unlink = unlink_then_kill
elif phase == "after-replace":
    original_replace = os.replace
    def replace_then_kill(*args, **kwargs):
        original_replace(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    os.replace = replace_then_kill
else:
    raise AssertionError("unknown interruption phase")

if operation == "create":
    lifecycle.create(path, "database", "a" * 64)
elif operation == "rotate":
    lifecycle.rotate(
        path,
        "database",
        "a" * 64,
        expected_active_key_id,
    )
else:
    raise AssertionError("unknown lifecycle operation")
'''
        repository_root = Path(lifecycle.__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                program,
                str(path),
                operation,
                phase,
                expected_active_key_id,
            ],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        return result

    def test_create_is_no_clobber_and_rerun_preserves_exact_bytes(self):
        outcome = lifecycle.create(self.path, "database", INSTALLATION_ID)
        original = self.path.read_bytes()

        self.assertEqual(outcome["lane"], "database")
        self.assertEqual(outcome["key_count"], 1)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o400)
        self.assertEqual(self.path.stat().st_nlink, 1)
        with self.assertRaises(lifecycle.KeyringLifecycleError):
            lifecycle.create(self.path, "database", INSTALLATION_ID)
        self.assertEqual(self.path.read_bytes(), original)

    def test_create_sigkill_publication_boundaries_converge_without_key_residue(self):
        for phase in ("after-write", "after-link"):
            with self.subTest(phase=phase):
                case_root = self.root / phase
                case_root.mkdir(mode=0o700)
                path = case_root / "database.keyring"
                self._interrupt_lifecycle(path, operation="create", phase=phase)

                outcome = lifecycle.create(path, "database", INSTALLATION_ID)

                self.assertEqual(outcome["key_count"], 1)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(
                    list(case_root.glob(".database.keyring.*.tmp")),
                    [],
                )

        case_root = self.root / "after-unlink"
        case_root.mkdir(mode=0o700)
        path = case_root / "database.keyring"
        self._interrupt_lifecycle(path, operation="create", phase="after-unlink")

        inspected = lifecycle.inspect(path, "database", INSTALLATION_ID)

        self.assertEqual(inspected["key_count"], 1)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(list(case_root.glob(".database.keyring.*.tmp")), [])
        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "refusing to overwrite",
        ):
            lifecycle.create(path, "database", INSTALLATION_ID)

    def test_rotation_sigkill_boundaries_are_single_step_and_residue_free(self):
        before_replace_root = self.root / "rotation-before-replace"
        before_replace_root.mkdir(mode=0o700)
        before_replace_path = before_replace_root / "database.keyring"
        created = lifecycle.create(
            before_replace_path,
            "database",
            INSTALLATION_ID,
        )
        original_active = str(created["active_key_id"])
        self._interrupt_lifecycle(
            before_replace_path,
            operation="rotate",
            phase="after-write",
            expected_active_key_id=original_active,
        )
        self.assertEqual(
            lifecycle.inspect(
                before_replace_path,
                "database",
                INSTALLATION_ID,
            )["active_key_id"],
            original_active,
        )

        rotated = lifecycle.rotate(
            before_replace_path,
            "database",
            INSTALLATION_ID,
            original_active,
        )

        self.assertNotEqual(rotated["active_key_id"], original_active)
        self.assertEqual(rotated["key_count"], 2)
        self.assertEqual(
            list(before_replace_root.glob(".database.keyring.*.tmp")),
            [],
        )

        after_replace_root = self.root / "rotation-after-replace"
        after_replace_root.mkdir(mode=0o700)
        after_replace_path = after_replace_root / "database.keyring"
        created = lifecycle.create(after_replace_path, "database", INSTALLATION_ID)
        original_active = str(created["active_key_id"])
        self._interrupt_lifecycle(
            after_replace_path,
            operation="rotate",
            phase="after-replace",
            expected_active_key_id=original_active,
        )

        inspected = lifecycle.inspect(
            after_replace_path,
            "database",
            INSTALLATION_ID,
        )
        self.assertNotEqual(inspected["active_key_id"], original_active)
        self.assertEqual(inspected["key_count"], 2)
        self.assertEqual(
            list(after_replace_root.glob(".database.keyring.*.tmp")),
            [],
        )
        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "expected active key ID does not match",
        ):
            lifecycle.rotate(
                after_replace_path,
                "database",
                INSTALLATION_ID,
                original_active,
            )

    def test_residue_recovery_refuses_unrelated_hard_link(self):
        created = lifecycle.create(self.path, "database", INSTALLATION_ID)
        candidate = self.root / f".{self.path.name}.{'0' * 24}.tmp"
        candidate.write_bytes(b"untrusted residue")
        candidate.chmod(0o400)
        decoy = self.root / "unrelated-hard-link"
        os.link(candidate, decoy)

        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "unsafe or ambiguous identity",
        ):
            lifecycle.rotate(
                self.path,
                "database",
                INSTALLATION_ID,
                str(created["active_key_id"]),
            )

        self.assertTrue(candidate.is_file())
        self.assertTrue(decoy.is_file())
        self.assertEqual(candidate.stat().st_nlink, 2)

    def test_linked_recovery_preserves_foreign_lane_residue_for_review(self):
        key_id = "lfk-11111111111111111111111111111111"
        candidate = self.root / f".{self.path.name}.{'1' * 24}.tmp"
        candidate.write_bytes(
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="files",
                active_key_id=key_id,
                keys=[(key_id, "22" * 32)],
            )
        )
        candidate.chmod(0o400)
        os.link(candidate, self.path)
        original = candidate.read_bytes()

        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "failed strict validation",
        ):
            lifecycle.create(self.path, "database", INSTALLATION_ID)

        self.assertEqual(candidate.read_bytes(), original)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(candidate.stat().st_ino, self.path.stat().st_ino)
        self.assertEqual(candidate.stat().st_nlink, 2)

    def test_rotate_prepends_new_active_and_retains_every_legacy_key(self):
        created = lifecycle.create(self.path, "database", INSTALLATION_ID)
        original = self.path.read_bytes()
        rotated = lifecycle.rotate(
            self.path,
            "database",
            INSTALLATION_ID,
            str(created["active_key_id"]),
        )

        self.assertEqual(rotated["key_count"], 2)
        self.assertEqual(rotated["retained_key_ids"], [created["active_key_id"]])
        self.assertNotEqual(self.path.read_bytes(), original)
        provider = LocalFileKeyProvider(
            self.path,
            lane="database",
            installation_id=INSTALLATION_ID,
        )
        try:
            self.assertEqual(provider.active_key_id, rotated["active_key_id"])
            self.assertEqual(provider.key_ids[1], created["active_key_id"])
        finally:
            provider.destroy()

        current = self.path.read_bytes()
        with self.assertRaises(lifecycle.KeyringLifecycleError):
            lifecycle.rotate(
                self.path,
                "database",
                INSTALLATION_ID,
                str(created["active_key_id"]),
            )
        self.assertEqual(self.path.read_bytes(), current)

    def test_rotation_never_evicts_when_keyring_is_full(self):
        entries = [
            (f"lfk-{index:032x}", f"{index + 1:064x}")
            for index in range(8)
        ]
        self.path.write_bytes(
            canonical_keyring_bytes(
                installation_id=INSTALLATION_ID,
                lane="database",
                active_key_id=entries[0][0],
                keys=entries,
            )
        )
        self.path.chmod(0o400)
        original = self.path.read_bytes()

        with self.assertRaisesRegex(lifecycle.KeyringLifecycleError, "full"):
            lifecycle.rotate(
                self.path,
                "database",
                INSTALLATION_ID,
                entries[0][0],
            )
        self.assertEqual(self.path.read_bytes(), original)

    def test_direct_rotation_refuses_installer_managed_mode_0444_keyring(self):
        created = lifecycle.create(self.path, "database", INSTALLATION_ID)
        original = self.path.read_bytes()
        self.path.chmod(0o444)

        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "installer-managed mode-0444",
        ):
            lifecycle.rotate(
                self.path,
                "database",
                INSTALLATION_ID,
                str(created["active_key_id"]),
            )
        self.assertEqual(self.path.read_bytes(), original)

        inspected = lifecycle.inspect(self.path, "database", INSTALLATION_ID)
        self.assertEqual(inspected["active_key_id"], created["active_key_id"])

    def test_rotation_rejects_same_size_tamper_with_restored_mtime(self):
        created = lifecycle.create(self.path, "database", INSTALLATION_ID)
        original = self.path.read_bytes()
        original_stat = self.path.stat()
        write_temporary = lifecycle._write_temporary

        def tamper_after_candidate(*args, **kwargs):
            temporary = write_temporary(*args, **kwargs)
            tampered = bytearray(self.path.read_bytes())
            index = len(tampered) - 2
            tampered[index] = ord("0") if tampered[index] != ord("0") else ord("1")
            self.path.chmod(0o600)
            self.path.write_bytes(tampered)
            self.path.chmod(0o400)
            os.utime(
                self.path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
            self.assertEqual(self.path.stat().st_size, original_stat.st_size)
            self.assertEqual(self.path.stat().st_mtime_ns, original_stat.st_mtime_ns)
            return temporary

        with mock.patch.object(
            lifecycle,
            "_write_temporary",
            side_effect=tamper_after_candidate,
        ):
            with self.assertRaisesRegex(
                lifecycle.KeyringLifecycleError,
                "changed concurrently",
            ):
                lifecycle.rotate(
                    self.path,
                    "database",
                    INSTALLATION_ID,
                    str(created["active_key_id"]),
                )

        self.assertNotEqual(self.path.read_bytes(), original)
        self.assertEqual(self.path.stat().st_size, original_stat.st_size)
        self.assertEqual(self.path.stat().st_mtime_ns, original_stat.st_mtime_ns)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o400)

    def test_mutation_refuses_unsafe_metadata_links_and_parent_lock(self):
        lifecycle.create(self.path, "database", INSTALLATION_ID)
        self.path.chmod(0o600)
        with self.assertRaises(lifecycle.KeyringLifecycleError):
            lifecycle.rotate(
                self.path,
                "database",
                INSTALLATION_ID,
                "lfk-00000000000000000000000000000000",
            )
        self.path.chmod(0o400)
        os.link(self.path, self.root / "second-link")
        with self.assertRaises(lifecycle.KeyringLifecycleError):
            lifecycle.inspect(self.path, "database", INSTALLATION_ID)

        other = self.root / "files.keyring"
        descriptor = os.open(self.root, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(
                lifecycle.KeyringLifecycleError,
                "another keyring mutation",
            ):
                lifecycle.create(other, "files", INSTALLATION_ID)
        finally:
            os.close(descriptor)

    def test_lifecycle_refuses_a_symlinked_ancestor_before_creation(self):
        real_ancestor = self.root / "real-ancestor"
        real_ancestor.mkdir(mode=0o700)
        protected_parent = real_ancestor / "protected"
        protected_parent.mkdir(mode=0o700)
        linked_ancestor = self.root / "linked-ancestor"
        linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
        destination = linked_ancestor / "protected" / "database.keyring"

        with self.assertRaisesRegex(
            lifecycle.KeyringLifecycleError,
            "unsafe or unavailable ancestor",
        ):
            lifecycle.create(destination, "database", INSTALLATION_ID)
        self.assertFalse((protected_parent / "database.keyring").exists())

    def test_cli_reports_only_metadata_and_never_root_key_material(self):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = lifecycle.main(
                [
                    "create",
                    "--path",
                    str(self.path),
                    "--lane",
                    "database",
                    "--installation-id",
                    INSTALLATION_ID,
                ]
            )
        payload = json.loads(output.getvalue())
        on_disk_key_hex = self.path.read_text(encoding="ascii").split(":", 1)[1].strip()

        self.assertEqual(result, 0)
        self.assertEqual(payload["key_count"], 1)
        self.assertNotIn(on_disk_key_hex, output.getvalue() + errors.getvalue())

    def test_cli_derives_installation_bound_sealed_policy_witness(self):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = lifecycle.main(
                [
                    "policy-witness",
                    "--installation-id",
                    INSTALLATION_ID,
                    "--generation",
                    "1",
                ]
            )
        payload = json.loads(output.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(payload["generation"], "1")
        self.assertEqual(payload["provider"], "local-file")
        self.assertRegex(payload["witness"], r"^[0-9a-f]{64}$")
        self.assertEqual(errors.getvalue(), "")

    def test_cli_pins_repository_imports_from_unrelated_working_directory(self):
        unrelated = self.root / "unrelated"
        unrelated.mkdir(mode=0o700)
        hostile = self.root / "hostile-pythonpath"
        hostile.mkdir(mode=0o700)
        (hostile / "argparse.py").write_text(
            "raise RuntimeError('hostile argparse imported')\n",
            encoding="utf-8",
        )
        hostile_package = hostile / "backupsheep"
        hostile_package.mkdir(mode=0o700)
        (hostile_package / "__init__.py").write_text(
            "raise RuntimeError('hostile backupsheep imported')\n",
            encoding="utf-8",
        )

        script = Path(lifecycle.__file__).resolve()
        for pythonpath in ("", f"{hostile}{os.pathsep}{unrelated}"):
            environment = os.environ.copy()
            environment["PYTHONPATH"] = pythonpath
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=unrelated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            with self.subTest(pythonpath=pythonpath):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("policy-witness", result.stdout)
                self.assertNotIn("hostile", result.stdout + result.stderr)
