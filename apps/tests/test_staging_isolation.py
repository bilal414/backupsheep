"""Adversarial tests for the private-plaintext/ciphertext-transfer boundary."""

import os
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from backupsheep import staging
from backupsheep.artifact_crypto import ArtifactContext, encrypt_file


INSTALLATION_ID = "a" * 64
BACKUP_UUID = "11111111-2222-4333-8444-555555555555"
HANDOFF_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class StagingIsolationTests(SimpleTestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)
        self.transfer = self.base / "transfer"
        self.restore_transfer = self.base / "restore-transfer"
        self.private = self.base / "private"
        self.transfer.mkdir(mode=0o700)
        self.restore_transfer.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        os.chmod(self.transfer, staging.ROOT_MODE)
        os.chmod(self.restore_transfer, staging.ROOT_MODE)
        os.chmod(self.private, staging.PRIVATE_MODE)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.identities = {
            role: (self.uid, self.gid) for role in staging.ROLE_IDENTITIES
        }
        self.environment = mock.patch.dict(
            os.environ,
            {
                "DJANGO_SERVER": "test",
                "BACKUPSHEEP_RUNTIME_ROLE": "database",
                "BACKUPSHEEP_INSTALLATION_ID": INSTALLATION_ID,
                "BACKUPSHEEP_PLAINTEXT_ROOT": str(self.private),
                "BACKUPSHEEP_CIPHERTEXT_TRANSFER_ROOT": str(self.transfer),
                "BACKUPSHEEP_RESTORE_CIPHERTEXT_TRANSFER_ROOT": str(
                    self.restore_transfer
                ),
                "BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES": "0",
                "BACKUPSHEEP_PRIVATE_MIN_FREE_INODES": "0",
                "BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES": "0",
                "BACKUPSHEEP_TRANSFER_MIN_FREE_INODES": "0",
                "BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES": "0",
                "BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES": "0",
            },
            clear=False,
        )
        self.patches = [
            self.environment,
            mock.patch.object(staging, "ROOT_UID", self.uid),
            mock.patch.object(staging, "TRANSFER_WRITER_GID", self.gid),
            mock.patch.object(staging, "TRANSFER_READER_GID", self.gid),
            mock.patch.object(staging, "RESTORE_WRITER_GID", self.gid),
            mock.patch.object(staging, "RESTORE_DATABASE_READER_GID", self.gid),
            mock.patch.object(staging, "RESTORE_FILES_READER_GID", self.gid),
            mock.patch.object(
                staging,
                "RESTORE_READER_GIDS",
                {"database": self.gid, "files": self.gid},
            ),
            mock.patch.object(staging, "SSH_TRUST_READER_GID", self.gid),
            mock.patch.object(staging, "ROLE_IDENTITIES", self.identities),
            mock.patch.object(os, "getgroups", return_value=[self.gid]),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def _fence_with_private_candidate(self, name="archive.bse1"):
        fence = staging.create_ciphertext_fence(BACKUP_UUID)
        candidate = fence.path / name
        candidate.write_bytes(b"BSE1complete-test-envelope")
        os.chmod(candidate, staging.PRIVATE_FILE_MODE)
        return fence, candidate

    def _restore_fence_with_private_candidate(self, name="restore.bse1"):
        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        fence = staging.create_restore_ciphertext_fence(
            HANDOFF_UUID,
            backup_uuid=BACKUP_UUID,
            target_lane="database",
        )
        candidate = fence.path / name
        candidate.write_bytes(b"BSE1complete-restore-envelope")
        os.chmod(candidate, staging.PRIVATE_FILE_MODE)
        return fence, candidate

    def test_plaintext_root_requires_exact_private_owner_and_mode(self):
        self.assertEqual(staging.private_plaintext_root(), self.private)
        os.chmod(self.private, 0o750)
        with self.assertRaisesRegex(
            staging.StagingIsolationError, "not private"
        ):
            staging.private_plaintext_root()

    def test_storage_private_root_uses_the_same_exact_boundary(self):
        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        self.assertEqual(staging.private_storage_root(), self.private)
        os.chmod(self.private, 0o750)
        with self.assertRaisesRegex(staging.StagingIsolationError, "not private"):
            staging.private_storage_root()

    def test_capacity_reserve_and_requested_headroom_fail_closed(self):
        filesystem = SimpleNamespace(f_bavail=100, f_frsize=1024, f_favail=20)
        os.environ["BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES"] = str(50 * 1024)
        os.environ["BACKUPSHEEP_PRIVATE_MIN_FREE_INODES"] = "10"
        with mock.patch.object(os, "fstatvfs", return_value=filesystem):
            self.assertEqual(
                staging.require_private_capacity(
                    required_bytes=50 * 1024,
                    required_inodes=10,
                ),
                self.private,
            )
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "insufficient free bytes"
            ):
                staging.require_private_capacity(required_bytes=50 * 1024 + 1)
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "insufficient free inodes"
            ):
                staging.require_private_capacity(required_inodes=11)

    def test_transfer_capacity_rejects_invalid_or_exhausted_configuration(self):
        filesystem = SimpleNamespace(f_bavail=1, f_frsize=4096, f_favail=1)
        os.environ["BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES"] = "4096"
        os.environ["BACKUPSHEEP_TRANSFER_MIN_FREE_INODES"] = "1"
        with mock.patch.object(os, "fstatvfs", return_value=filesystem):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "insufficient free bytes"
            ):
                staging.require_transfer_capacity(required_bytes=1)
        os.environ["BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES"] = "1GiB"
        with self.assertRaisesRegex(
            staging.StagingIsolationError, "non-negative integer"
        ):
            staging.require_transfer_capacity()

    def test_production_capacity_reserves_cannot_disable_the_safety_floor(self):
        os.environ["DJANGO_SERVER"] = "prod"
        os.environ["BACKUPSHEEP_PLAINTEXT_ROOT"] = str(self.private)
        os.environ["BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES"] = str(
            staging.PRODUCTION_MIN_FREE_BYTES - 1
        )
        os.environ["BACKUPSHEEP_PRIVATE_MIN_FREE_INODES"] = str(
            staging.PRODUCTION_MIN_FREE_INODES
        )
        with mock.patch.object(staging, "PLAINTEXT_ROOT", self.private):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "below the production safety floor"
            ):
                staging.require_private_capacity()

    def test_publish_is_the_only_private_to_group_readable_transition(self):
        fence, candidate = self._fence_with_private_candidate()
        self.assertEqual(candidate.stat().st_mode & 0o7777, 0o600)

        with mock.patch.object(staging, "_validate_bse1_path") as validate:
            published = staging.publish_ciphertext(BACKUP_UUID, candidate.name)

        self.assertEqual(published, candidate)
        self.assertEqual(candidate.stat().st_mode & 0o7777, 0o640)
        validate.assert_called_once_with(candidate, fence)

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        with mock.patch.object(staging, "_validate_bse1_path"):
            with staging.open_ciphertext(BACKUP_UUID, candidate.name) as source:
                self.assertEqual(source.read(), b"BSE1complete-test-envelope")

    def test_real_bse1_envelope_can_cross_only_after_validation(self):
        fence = staging.create_ciphertext_fence(BACKUP_UUID)
        source = self.private / "source.zip"
        source.write_bytes(b"private backup payload" * 4096)
        os.chmod(source, 0o600)
        destination = fence.path / "archive.bse1"
        context = ArtifactContext(
            installation_id=INSTALLATION_ID,
            account_id="account-17",
            node_id="node-29",
            backup_id=BACKUP_UUID,
            backup_model="apps.coredatabasebackup",
            lane="database",
        )
        encrypt_file(
            source,
            destination,
            data_key=bytes(range(32)),
            context=context,
            envelope_id=BACKUP_UUID,
            chunk_size=64 * 1024,
            trusted_source_root=self.private,
            trusted_destination_root=fence.path,
        )
        self.assertEqual(destination.stat().st_mode & 0o7777, 0o600)
        staging.publish_ciphertext(BACKUP_UUID, destination.name)
        self.assertEqual(destination.stat().st_mode & 0o7777, 0o640)

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        with staging.open_ciphertext(BACKUP_UUID, destination.name) as ciphertext:
            self.assertEqual(ciphertext.read(4), b"BSE1")

    def test_unpublished_or_mutable_candidate_is_not_readable_by_storage_api(self):
        _fence, candidate = self._fence_with_private_candidate()
        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        with mock.patch.object(staging, "_validate_bse1_path"):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "metadata is unsafe"
            ):
                staging.open_ciphertext(BACKUP_UUID, candidate.name)

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "database"
        os.chmod(candidate, 0o660)
        with mock.patch.object(staging, "_validate_bse1_path"):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "private, single-link"
            ):
                staging.publish_ciphertext(BACKUP_UUID, candidate.name)

    def test_symlink_and_hardlink_candidates_fail_closed(self):
        fence = staging.create_ciphertext_fence(BACKUP_UUID)
        outside = self.base / "outside.bse1"
        outside.write_bytes(b"BSE1outside")
        os.chmod(outside, 0o600)
        symlink = fence.path / "symlink.bse1"
        symlink.symlink_to(outside)
        with mock.patch.object(staging, "_validate_bse1_path"):
            with self.assertRaises(staging.StagingIsolationError):
                staging.publish_ciphertext(BACKUP_UUID, symlink.name)

        hardlink = fence.path / "hardlink.bse1"
        os.link(outside, hardlink)
        with mock.patch.object(staging, "_validate_bse1_path"):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "single-link"
            ):
                staging.publish_ciphertext(BACKUP_UUID, hardlink.name)

    def test_cross_lane_reuse_and_cleanup_are_refused(self):
        fence, candidate = self._fence_with_private_candidate()
        with mock.patch.object(staging, "_validate_bse1_path"):
            staging.publish_ciphertext(BACKUP_UUID, candidate.name)

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "files"
        with self.assertRaisesRegex(staging.StagingIsolationError, "different source lane"):
            staging.create_ciphertext_fence(BACKUP_UUID)
        with self.assertRaisesRegex(staging.StagingIsolationError, "different source lane"):
            staging.cleanup_ciphertext_fence(BACKUP_UUID)
        self.assertTrue(fence.path.exists())

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        with self.assertRaisesRegex(staging.StagingIsolationError, "not allowed"):
            staging.cleanup_ciphertext_fence(BACKUP_UUID)
        self.assertTrue(fence.path.exists())

    def test_cleanup_requires_exact_owned_inventory_before_mutating(self):
        fence, candidate = self._fence_with_private_candidate()
        with mock.patch.object(staging, "_validate_bse1_path"):
            staging.publish_ciphertext(BACKUP_UUID, candidate.name)
        unexpected = fence.path / "plaintext.zip"
        unexpected.write_bytes(b"secret")
        os.chmod(unexpected, 0o600)

        with mock.patch.object(staging, "_validate_bse1_path"):
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "artifact name is invalid"
            ):
                staging.cleanup_ciphertext_fence(BACKUP_UUID)
        self.assertTrue(candidate.exists())
        self.assertTrue(unexpected.exists())

        unexpected.unlink()
        with mock.patch.object(staging, "_validate_bse1_path"):
            staging.cleanup_ciphertext_fence(BACKUP_UUID)
        self.assertFalse(fence.path.exists())

    def test_source_can_discard_complete_unpublished_bse1_after_crash(self):
        fence, candidate = self._fence_with_private_candidate()
        self.assertEqual(candidate.stat().st_mode & 0o7777, 0o600)
        with mock.patch.object(staging, "_validate_bse1_path") as validate:
            self.assertTrue(staging.cleanup_ciphertext_fence(BACKUP_UUID))
        validate.assert_called_once_with(candidate, fence)
        self.assertFalse(fence.path.exists())
        self.assertFalse(staging.cleanup_ciphertext_fence(BACKUP_UUID))

    def test_wrong_installation_or_noncanonical_uuid_cannot_cross_fence(self):
        self._fence_with_private_candidate()
        with self.assertRaises(staging.StagingIsolationError):
            staging.create_ciphertext_fence(f"{{{uuid.UUID(BACKUP_UUID)}}}")
        with self.assertRaisesRegex(staging.StagingIsolationError, "inconsistent"):
            staging.publish_ciphertext(
                BACKUP_UUID,
                "archive.bse1",
                installation_id="b" * 64,
            )

    def test_transfer_root_must_remain_root_owned_setgid_and_sticky(self):
        os.chmod(self.transfer, 0o2770)
        with self.assertRaisesRegex(
            staging.StagingIsolationError, "unsafe ownership or permissions"
        ):
            staging.create_ciphertext_fence(BACKUP_UUID)

    def test_reverse_handoff_is_storage_written_and_target_lane_read_only(self):
        fence, candidate = self._restore_fence_with_private_candidate()
        with mock.patch.object(staging, "_validate_bse1_path") as validate:
            published = staging.publish_restore_ciphertext(
                HANDOFF_UUID,
                candidate.name,
                backup_uuid=BACKUP_UUID,
                target_lane="database",
            )
        self.assertEqual(published, candidate)
        self.assertEqual(candidate.stat().st_mode & 0o7777, 0o640)
        validate.assert_called_once_with(candidate, fence)

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "files"
        with self.assertRaisesRegex(staging.StagingIsolationError, "does not own"):
            staging.open_restore_ciphertext(
                HANDOFF_UUID,
                candidate.name,
                backup_uuid=BACKUP_UUID,
                target_lane="database",
            )

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "database"
        with mock.patch.object(staging, "_validate_bse1_path"):
            with staging.open_restore_ciphertext(
                HANDOFF_UUID,
                candidate.name,
                backup_uuid=BACKUP_UUID,
                target_lane="database",
            ) as source:
                self.assertEqual(source.read(), b"BSE1complete-restore-envelope")
        with self.assertRaisesRegex(staging.StagingIsolationError, "not allowed"):
            staging.cleanup_restore_ciphertext_fence(
                HANDOFF_UUID,
                backup_uuid=BACKUP_UUID,
                target_lane="database",
            )

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        with mock.patch.object(staging, "_validate_bse1_path"):
            self.assertTrue(
                staging.cleanup_restore_ciphertext_fence(
                    HANDOFF_UUID,
                    backup_uuid=BACKUP_UUID,
                    target_lane="database",
                )
            )
        self.assertFalse(
            staging.cleanup_restore_ciphertext_fence(
                HANDOFF_UUID,
                backup_uuid=BACKUP_UUID,
                target_lane="database",
            )
        )

    def test_real_bse1_restore_envelope_crosses_reverse_handoff(self):
        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        fence = staging.create_restore_ciphertext_fence(
            HANDOFF_UUID,
            backup_uuid=BACKUP_UUID,
            target_lane="files",
        )
        source = self.private / "provider-object.bse1"
        plaintext = self.private / "source.zip"
        plaintext.write_bytes(b"private restore payload" * 4096)
        os.chmod(plaintext, 0o600)
        context = ArtifactContext(
            installation_id=INSTALLATION_ID,
            account_id="account-17",
            node_id="node-29",
            backup_id=BACKUP_UUID,
            backup_model="apps.corewebsitebackup",
            lane="files",
        )
        encrypt_file(
            plaintext,
            source,
            data_key=bytes(range(32)),
            context=context,
            envelope_id=BACKUP_UUID,
            chunk_size=64 * 1024,
            trusted_source_root=self.private,
            trusted_destination_root=self.private,
        )
        destination = fence.path / "restore.bse1"
        destination.write_bytes(source.read_bytes())
        os.chmod(destination, 0o600)
        staging.publish_restore_ciphertext(
            HANDOFF_UUID,
            destination.name,
            backup_uuid=BACKUP_UUID,
            target_lane="files",
        )

        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "files"
        with staging.open_restore_ciphertext(
            HANDOFF_UUID,
            destination.name,
            backup_uuid=BACKUP_UUID,
            target_lane="files",
        ) as ciphertext:
            self.assertEqual(ciphertext.read(4), b"BSE1")

    def test_restore_transfer_capacity_and_binding_fail_closed(self):
        os.environ["BACKUPSHEEP_RUNTIME_ROLE"] = "storage"
        filesystem = SimpleNamespace(f_bavail=8, f_frsize=1024, f_favail=4)
        os.environ["BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES"] = "4096"
        os.environ["BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES"] = "2"
        with mock.patch.object(os, "fstatvfs", return_value=filesystem):
            self.assertEqual(
                staging.require_restore_transfer_capacity(
                    required_bytes=4096,
                    required_inodes=2,
                ),
                self.restore_transfer,
            )
            with self.assertRaisesRegex(
                staging.StagingIsolationError, "insufficient free bytes"
            ):
                staging.require_restore_transfer_capacity(required_bytes=4097)

        self._restore_fence_with_private_candidate()
        with self.assertRaisesRegex(staging.StagingIsolationError, "inconsistent"):
            staging.publish_restore_ciphertext(
                HANDOFF_UUID,
                "restore.bse1",
                backup_uuid="22222222-3333-4444-8555-666666666666",
                target_lane="database",
            )
