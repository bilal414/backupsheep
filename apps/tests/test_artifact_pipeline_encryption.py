"""Adversarial integration tests for the BSE1 backup/upload/restore pipeline."""

import base64
import hashlib
import os
import shutil
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock, skipIf

from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone

from apps._tasks.artifact_encryption import (
    ArtifactPipelineError,
    _new_envelope_id,
    _configured_provider,
    cleanup_terminal_restore_ciphertext_handoff,
    cleanup_terminal_source_ciphertext,
    ensure_destination_ciphertext_ledger,
    materialize_local_restore_ciphertext_handoff,
    restore_ciphertext_handoff_identity,
    restore_encryption_plan,
    seal_or_validate_source_artifact,
    storage_upload_artifact,
)
from apps._tasks.integration.restore_common import (
    RestoreError,
    _destination_ledger_exists,
    fetch_backup_zip,
)
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupEncryptionEnvelope,
    CoreWebsiteBackup,
    CoreWebsiteRestore,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.management.commands.docker_preflight import (
    _assert_artifact_encryption_boundary,
    _assert_artifact_keyring_database_state,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


INSTALLATION_ID = "a" * 64
LOCAL_KEY = base64.b64encode(bytes(range(32))).decode("ascii")

skip_on_darwin_without_anonymous_staging = skipIf(
    sys.platform == "darwin",
    "Darwin does not provide Linux O_TMPFILE/linkat secure anonymous staging.",
)


@override_settings(
    DJANGO_SERVER="test",
    BACKUPSHEEP_INSTALLATION_ID=INSTALLATION_ID,
    BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="bse1",
    BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
    BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=False,
    BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-development",
    BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY=LOCAL_KEY,
    BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID="test-local-v1",
    BACKUPSHEEP_ARTIFACT_CHUNK_SIZE=64 * 1024,
)
class ArtifactPipelineEncryptionTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        node = factories.make_website_node(self.account, self.member)
        self.backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=str(uuid.uuid4()),
            status=UtilBackup.Status.DOWNLOAD_IN_PROGRESS,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        self.backup.initialize_execution(
            celery_task_id=f"source-{self.backup.pk}",
            attempt_no=1,
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "private"
        self.fence = Path(self.temporary.name) / "transfer" / self.backup.uuid_str
        self.root.mkdir()
        self.fence.mkdir(parents=True)
        self.archive = self.root / f"{self.backup.uuid_str}.zip"

    def _write_zip(self, payload=b"authenticated backup payload"):
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data/backup.txt", payload)

    @staticmethod
    def _verify_zip(path):
        with zipfile.ZipFile(path, "r") as archive:
            if archive.testzip() is not None:
                raise ValueError("invalid zip")

    def _publish(self, _backup_uuid, artifact_name, *, installation_id=None):
        self.assertEqual(installation_id, INSTALLATION_ID)
        path = self.fence / artifact_name
        # This unit test runs in one UID. The cross-UID staging suite separately
        # proves the production publisher's group-readable 0640 handoff.
        os.chmod(path, 0o600)
        return path

    def _source_boundary(self):
        fence = SimpleNamespace(path=self.fence)
        return (
            mock.patch(
                "backupsheep.staging.private_plaintext_root",
                return_value=self.root,
            ),
            mock.patch(
                "backupsheep.staging.create_ciphertext_fence",
                return_value=fence,
            ),
            mock.patch(
                "backupsheep.staging.publish_ciphertext",
                side_effect=self._publish,
            ),
            mock.patch(
                "backupsheep.staging.require_transfer_capacity",
                return_value=self.fence.parent,
            ),
        )

    def _seal(self):
        self._write_zip()
        patches = self._source_boundary()
        with patches[0], patches[1], patches[2], patches[3]:
            artifact = seal_or_validate_source_artifact(
                self.backup,
                self.archive,
                zip_verifier=self._verify_zip,
            )
        return artifact, self.fence / f"{artifact.encryption_envelope.uuid}.bse1"

    def _local_destination(self, source_artifact, ciphertext):
        local_root = Path(self.temporary.name) / "local-storage"
        local_root.mkdir(exist_ok=True)
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="local"),
            name="encrypted-local",
            added_by=self.member,
        )
        CoreStorageLocal.objects.create(storage=storage, path=str(local_root))
        remote = local_root / source_artifact.object_key
        shutil.copyfile(ciphertext, remote)
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=self.backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=str(remote),
            metadata={
                "unit_test_destination": {
                    "phase": "committed",
                    "storage_file_id": str(remote),
                    "object_key": str(remote),
                    "sha256": source_artifact.checksum_value,
                    "size_bytes": source_artifact.byte_count,
                }
            },
        )
        destination = self.backup.record_artifact_integrity(
            role="destination",
            object_key=str(remote),
            byte_count=source_artifact.byte_count,
            storage=storage,
            checksum_algorithm="sha256",
            checksum_value=source_artifact.checksum_value,
            verified_at=timezone.now(),
            metadata={"storage_metadata_key": "unit_test_destination"},
        )
        return point, destination, remote, local_root

    def test_random_envelope_identity_retries_a_backup_uuid_collision(self):
        expected = uuid.UUID("77777777-6666-4555-8444-333333333333")
        with mock.patch(
            "apps._tasks.artifact_encryption.uuid.uuid4",
            side_effect=[uuid.UUID(self.backup.uuid_str), expected],
        ):
            self.assertEqual(_new_envelope_id(self.backup.uuid_str), expected)

    @skip_on_darwin_without_anonymous_staging
    def test_source_validates_zip_before_key_provider_and_activates_atomically(self):
        self.archive.write_bytes(b"not-a-zip")
        provider = mock.Mock()
        with mock.patch(
            "backupsheep.staging.private_plaintext_root", return_value=self.root
        ), mock.patch(
            "apps._tasks.artifact_encryption._configured_provider", provider
        ):
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                seal_or_validate_source_artifact(
                    self.backup,
                    self.archive,
                    zip_verifier=self._verify_zip,
                )
        provider.assert_not_called()
        self.assertFalse(CoreBackupEncryptionEnvelope.objects.exists())

        self.archive.unlink()
        artifact, ciphertext = self._seal()
        envelope = CoreBackupEncryptionEnvelope.objects.get()
        self.assertEqual(artifact.artifact_format, CoreBackupArtifact.Format.BSE1)
        self.assertEqual(artifact.encryption_envelope, envelope)
        self.assertEqual(envelope.status, envelope.Status.ACTIVE)
        self.assertNotEqual(envelope.uuid, uuid.UUID(self.backup.uuid_str))
        self.assertEqual(envelope.format_version, 2)
        self.assertEqual(artifact.object_key, f"{envelope.uuid}.bse1")
        self.assertFalse(self.archive.exists())
        self.assertEqual(stat_mode(ciphertext), 0o600)
        self.assertEqual(ciphertext.read_bytes()[:4], b"BSE1")

    def test_key_provider_failure_never_publishes_or_activates_plaintext(self):
        self._write_zip()
        patches = self._source_boundary()
        with patches[0], patches[1], patches[2] as publisher, patches[3], mock.patch(
            "apps._tasks.artifact_encryption.seal_file",
            side_effect=RuntimeError("key provider unavailable"),
        ):
            with self.assertRaises(RuntimeError):
                seal_or_validate_source_artifact(
                    self.backup,
                    self.archive,
                    zip_verifier=self._verify_zip,
                )
        publisher.assert_not_called()
        self.assertTrue(self.archive.exists())
        self.assertFalse(CoreBackupEncryptionEnvelope.objects.exists())
        self.assertFalse(any(self.fence.glob("*.bse1")))

    @skip_on_darwin_without_anonymous_staging
    def test_storage_copies_and_verifies_ciphertext_before_adapter_reads_it(self):
        source_artifact, ciphertext = self._seal()
        storage_root = Path(self.temporary.name) / "storage-private"
        storage_root.mkdir()

        with mock.patch(
            "backupsheep.staging.require_private_capacity", return_value=storage_root
        ), mock.patch(
            "backupsheep.staging.open_ciphertext",
            side_effect=lambda *_args, **_kwargs: open(ciphertext, "rb"),
        ) as opener:
            with storage_upload_artifact(
                self.backup,
                legacy_verifier=mock.Mock(side_effect=AssertionError("legacy")),
            ) as observed:
                snapshot = storage_root / source_artifact.object_key
                self.assertEqual(observed.pk, source_artifact.pk)
                self.assertEqual(snapshot.read_bytes(), ciphertext.read_bytes())
                self.assertNotEqual(os.stat(snapshot).st_ino, os.stat(ciphertext).st_ino)
                self.assertEqual(stat_mode(snapshot), 0o600)
            self.assertFalse(snapshot.exists())
        opener.assert_called_once_with(
            self.backup.uuid_str,
            f"{source_artifact.encryption_envelope.uuid}.bse1",
            source_lane="files",
            installation_id=INSTALLATION_ID,
        )

        tampered = Path(self.temporary.name) / "tampered.bse1"
        tampered.write_bytes(ciphertext.read_bytes() + b"attacker")
        with mock.patch(
            "backupsheep.staging.require_private_capacity", return_value=storage_root
        ), mock.patch(
            "backupsheep.staging.open_ciphertext",
            side_effect=lambda *_args, **_kwargs: open(tampered, "rb"),
        ):
            with self.assertRaises(ArtifactPipelineError):
                with storage_upload_artifact(
                    self.backup,
                    legacy_verifier=mock.Mock(),
                ):
                    self.fail("tampered ciphertext reached an adapter")

    @skip_on_darwin_without_anonymous_staging
    def test_restore_authenticates_bse1_and_never_falls_back_for_missing_ledger(self):
        source_artifact, ciphertext = self._seal()
        point, destination, remote, local_root = self._local_destination(
            source_artifact, ciphertext
        )
        restore_root = self.root / "restore"
        restore_root.mkdir()
        output = restore_root / "restored.zip"
        restore = CoreWebsiteRestore.objects.create(
            backup=self.backup,
            storage_point=point,
            name="Encrypted local restore",
            params={},
        )
        plan = restore_encryption_plan(point)
        handoff = restore_ciphertext_handoff_identity(restore, plan)
        restore.execution_metadata = {
            "local_restore_ciphertext_handoff": {
                **handoff,
                "status": "ready",
                "ready_at": timezone.now().isoformat(),
            }
        }
        restore.save(update_fields=["execution_metadata", "modified"])
        with override_settings(LOCAL_STORAGE_ROOT=str(local_root)), mock.patch(
            "backupsheep.staging.private_plaintext_root",
            return_value=self.root,
        ), mock.patch(
            "backupsheep.staging.require_private_capacity",
            return_value=self.root,
        ), mock.patch(
            "backupsheep.staging.open_restore_ciphertext",
            side_effect=lambda *_args, **_kwargs: open(remote, "rb"),
        ):
            self.assertIsNotNone(restore_encryption_plan(point))
            fetch_backup_zip(point, output, restore=restore)
        with zipfile.ZipFile(output) as restored:
            self.assertEqual(
                restored.read("data/backup.txt"), b"authenticated backup payload"
            )

        output.unlink()
        payload = bytearray(remote.read_bytes())
        payload[-1] ^= 1
        remote.write_bytes(payload)
        forged_checksum = hashlib.sha256(payload).hexdigest()
        CoreBackupArtifact.objects.filter(
            pk__in=(source_artifact.pk, destination.pk)
        ).update(checksum_value=forged_checksum)
        with override_settings(LOCAL_STORAGE_ROOT=str(local_root)), mock.patch(
            "backupsheep.staging.private_plaintext_root",
            return_value=self.root,
        ), mock.patch(
            "backupsheep.staging.require_private_capacity",
            return_value=self.root,
        ), mock.patch(
            "backupsheep.staging.open_restore_ciphertext",
            side_effect=lambda *_args, **_kwargs: open(remote, "rb"),
        ):
            with self.assertRaises(RestoreError):
                fetch_backup_zip(point, output, restore=restore)
        self.assertFalse(output.exists())

        destination.delete()
        point.generate_download_url = mock.Mock(return_value="https://attacker.invalid")
        with override_settings(LOCAL_STORAGE_ROOT=str(local_root)):
            with self.assertRaises(RestoreError):
                fetch_backup_zip(point, output, restore=restore)
        point.generate_download_url.assert_not_called()

    @skip_on_darwin_without_anonymous_staging
    def test_encrypted_local_artifact_has_no_direct_zip_download_bypass(self):
        source_artifact, ciphertext = self._seal()
        point, _destination, _remote, local_root = self._local_destination(
            source_artifact, ciphertext
        )
        self.assertFalse(point.direct_download_permitted())
        with self.assertRaises(RuntimeError):
            point.generate_download_url()

        self.client.force_login(self.user)
        with override_settings(LOCAL_STORAGE_ROOT=str(local_root)):
            response = self.client.get(f"/api/v1/storage/local/file/{point.pk}/")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["artifact_format"], "bse1")

    @skip_on_darwin_without_anonymous_staging
    def test_local_restore_uses_storage_owned_reverse_ciphertext_handoff(self):
        source_artifact, ciphertext = self._seal()
        point, _destination, remote, local_root = self._local_destination(
            source_artifact, ciphertext
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=self.backup,
            storage_point=point,
            name="Reverse handoff",
            params={},
        )
        reverse_fence = Path(self.temporary.name) / "restore-transfer"
        reverse_fence.mkdir()

        def publish(_handoff_uuid, artifact_name, **_kwargs):
            path = reverse_fence / artifact_name
            # Cross-UID publication permissions are exercised by the staging
            # kernel harness; this in-process fixture remains owner-private.
            os.chmod(path, 0o600)
            return path

        with override_settings(LOCAL_STORAGE_ROOT=str(local_root)), mock.patch(
            "backupsheep.staging.require_restore_transfer_capacity",
            return_value=reverse_fence.parent,
        ), mock.patch(
            "backupsheep.staging.cleanup_restore_ciphertext_fence",
            return_value=False,
        ), mock.patch(
            "backupsheep.staging.create_restore_ciphertext_fence",
            return_value=SimpleNamespace(path=reverse_fence),
        ), mock.patch(
            "backupsheep.staging.publish_restore_ciphertext",
            side_effect=publish,
        ):
            self.assertTrue(
                materialize_local_restore_ciphertext_handoff(
                    restore,
                    task_id="storage-stage-1",
                )
            )
        restored_ciphertext = (
            reverse_fence / f"{source_artifact.encryption_envelope.uuid}.bse1"
        )
        self.assertEqual(restored_ciphertext.read_bytes(), remote.read_bytes())
        restore.refresh_from_db()
        self.assertEqual(
            restore.execution_metadata["local_restore_ciphertext_handoff"]["status"],
            "ready",
        )

        restore.status = restore.Status.COMPLETE
        restore.save(update_fields=["status", "modified"])
        with mock.patch(
            "backupsheep.staging.cleanup_restore_ciphertext_fence",
            return_value=True,
        ) as cleanup:
            self.assertTrue(cleanup_terminal_restore_ciphertext_handoff(restore))
        cleanup.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(
            restore.execution_metadata["local_restore_ciphertext_handoff"]["status"],
            "cleanup_complete",
        )

    @skip_on_darwin_without_anonymous_staging
    def test_local_restore_never_reads_backups_mount_and_rejects_handoff_drift(self):
        source_artifact, ciphertext = self._seal()
        point, _destination, _remote, _local_root = self._local_destination(
            source_artifact, ciphertext
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=self.backup,
            storage_point=point,
            name="Isolated local restore",
            params={},
        )
        plan = restore_encryption_plan(point)
        expected = restore_ciphertext_handoff_identity(restore, plan)
        restore.execution_metadata = {
            "local_restore_ciphertext_handoff": {
                **expected,
                "status": "ready",
                "ready_at": timezone.now().isoformat(),
            }
        }
        restore.save(update_fields=["execution_metadata", "modified"])
        attacker_handoff = Path(self.temporary.name) / "attacker-handoff.bse1"
        attacker_handoff.write_bytes(ciphertext.read_bytes() + b"drift")
        output = self.root / "must-not-exist.zip"

        with mock.patch(
            "backupsheep.staging.require_private_capacity",
            return_value=self.root,
        ), mock.patch(
            "backupsheep.staging.open_restore_ciphertext",
            side_effect=lambda *_args, **_kwargs: open(attacker_handoff, "rb"),
        ), mock.patch(
            "apps._tasks.integration.restore_common._local_source_path",
            side_effect=AssertionError("source lane attempted to open /backups"),
        ) as local_source, mock.patch(
            "apps._tasks.integration.restore_common.unseal_downloaded_artifact"
        ) as unseal:
            with self.assertRaises(RestoreError):
                fetch_backup_zip(point, output, restore=restore)
        local_source.assert_not_called()
        unseal.assert_not_called()
        self.assertFalse(output.exists())

    @skip_on_darwin_without_anonymous_staging
    def test_destination_evidence_is_automatically_bound_to_active_envelope(self):
        source_artifact, ciphertext = self._seal()
        point, destination, _remote, _local_root = self._local_destination(
            source_artifact, ciphertext
        )
        self.assertEqual(destination.artifact_format, CoreBackupArtifact.Format.BSE1)
        self.assertEqual(
            destination.encryption_envelope_id,
            source_artifact.encryption_envelope_id,
        )
        ensure_destination_ciphertext_ledger(self.backup, point, source_artifact)

    @skip_on_darwin_without_anonymous_staging
    def test_destination_gate_never_synthesizes_or_adopts_same_storage_evidence(self):
        source_artifact, ciphertext = self._seal()
        point, destination, _remote, _local_root = self._local_destination(
            source_artifact, ciphertext
        )
        initial_count = self.backup.artifact_records.count()

        destination.verified_at = None
        destination.save(update_fields=["verified_at", "modified"])
        with self.assertRaisesRegex(ArtifactPipelineError, "exactly one verified"):
            ensure_destination_ciphertext_ledger(
                self.backup,
                point,
                source_artifact,
            )
        destination.refresh_from_db()
        self.assertIsNone(destination.verified_at)
        self.assertEqual(self.backup.artifact_records.count(), initial_count)

        destination.verified_at = timezone.now()
        destination.object_key = "other-object-on-the-same-storage"
        destination.save(
            update_fields=["verified_at", "object_key", "modified"]
        )
        self.assertFalse(_destination_ledger_exists(point))
        with self.assertRaisesRegex(ArtifactPipelineError, "exactly one verified"):
            ensure_destination_ciphertext_ledger(
                self.backup,
                point,
                source_artifact,
            )
        with self.assertRaisesRegex(ArtifactPipelineError, "exactly one verified"):
            restore_encryption_plan(point)

    @skip_on_darwin_without_anonymous_staging
    def test_duplicate_exact_destination_records_are_ambiguous(self):
        source_artifact, ciphertext = self._seal()
        point, destination, _remote, _local_root = self._local_destination(
            source_artifact, ciphertext
        )
        CoreBackupArtifact.objects.create(
            backup_content_type=destination.backup_content_type,
            backup_object_id=destination.backup_object_id,
            storage=destination.storage,
            role=CoreBackupArtifact.Role.ARCHIVE,
            artifact_format=CoreBackupArtifact.Format.BSE1,
            encryption_envelope=destination.encryption_envelope,
            idempotency_key=f"duplicate-{uuid.uuid4().hex}",
            object_key=destination.object_key,
            byte_count=destination.byte_count,
            checksum_algorithm="sha256",
            checksum_value=destination.checksum_value,
            verified_at=timezone.now(),
            metadata=dict(destination.metadata),
        )

        with self.assertRaisesRegex(ArtifactPipelineError, "exactly one verified"):
            ensure_destination_ciphertext_ledger(
                self.backup,
                point,
                source_artifact,
            )
        with self.assertRaisesRegex(ArtifactPipelineError, "exactly one verified"):
            restore_encryption_plan(point)

    @skip_on_darwin_without_anonymous_staging
    def test_restore_binds_selected_object_version_and_etag(self):
        source_artifact, ciphertext = self._seal()
        point, destination, _remote, _local_root = self._local_destination(
            source_artifact, ciphertext
        )
        state = dict(point.metadata["unit_test_destination"])
        state.update({"etag": '"etag-v7"', "version_id": "version-7"})
        point.metadata = {"unit_test_destination": state}
        point.save(update_fields=["metadata", "modified"])
        destination.etag = '"etag-v7"'
        destination.version_id = "version-7"
        destination.save(update_fields=["etag", "version_id", "modified"])
        CoreBackupArtifact.objects.create(
            backup_content_type=destination.backup_content_type,
            backup_object_id=destination.backup_object_id,
            storage=destination.storage,
            role=CoreBackupArtifact.Role.ARCHIVE,
            artifact_format=CoreBackupArtifact.Format.BSE1,
            encryption_envelope=destination.encryption_envelope,
            idempotency_key=f"decoy-{uuid.uuid4().hex}",
            object_key="different-object-on-the-same-storage",
            byte_count=destination.byte_count,
            checksum_algorithm="sha256",
            checksum_value=destination.checksum_value,
            etag='"decoy-etag"',
            version_id="decoy-version",
            verified_at=timezone.now(),
            metadata=dict(destination.metadata),
        )

        ensure_destination_ciphertext_ledger(self.backup, point, source_artifact)
        self.assertEqual(restore_encryption_plan(point).artifact.pk, destination.pk)

        state["version_id"] = "attacker-version"
        point.metadata = {"unit_test_destination": state}
        point.save(update_fields=["metadata", "modified"])
        with self.assertRaisesRegex(ArtifactPipelineError, "provider version"):
            ensure_destination_ciphertext_ledger(
                self.backup,
                point,
                source_artifact,
            )
        with self.assertRaisesRegex(ArtifactPipelineError, "provider version"):
            restore_encryption_plan(point)

    def test_dispatch_inventory_requires_verification_for_every_adapter(self):
        from apps._tasks.integration.storage.tasks import (
            _STORAGE_ADAPTER_INVENTORY,
        )

        self.assertEqual(
            set(_STORAGE_ADAPTER_INVENTORY),
            {
                "alibaba",
                "aws_s3",
                "azure",
                "backblaze_b2",
                "cloudflare",
                "do_spaces",
                "dropbox",
                "exoscale",
                "filebase",
                "google_cloud",
                "google_drive",
                "ibm",
                "idrive",
                "ionos",
                "leviia",
                "linode",
                "local",
                "onedrive",
                "oracle",
                "pcloud",
                "rackcorp",
                "scaleway",
                "tencent",
                "upcloud",
                "vultr",
                "wasabi",
            },
        )
        self.assertTrue(
            all(
                callable(adapter)
                and (
                    verification.endswith("sha256")
                    or verification == "verified-s3-object"
                )
                for adapter, verification in _STORAGE_ADAPTER_INVENTORY.values()
            )
        )

    @skip_on_darwin_without_anonymous_staging
    def test_source_fence_cleanup_requires_terminal_db_state_and_is_idempotent(self):
        source_artifact, _ciphertext = self._seal()
        with mock.patch("backupsheep.staging.cleanup_ciphertext_fence") as cleanup:
            with self.assertRaises(ArtifactPipelineError):
                cleanup_terminal_source_ciphertext(
                    self.backup,
                    expected_lane="files",
                )
        cleanup.assert_not_called()

        self.backup.status = UtilBackup.Status.COMPLETE
        self.backup.save(update_fields=["status", "modified"])
        self.backup.finalize_execution(terminal_phase="complete")
        with mock.patch(
            "backupsheep.staging.cleanup_ciphertext_fence", return_value=True
        ) as cleanup:
            self.assertTrue(
                cleanup_terminal_source_ciphertext(
                    self.backup,
                    expected_lane="files",
                )
            )
        cleanup.assert_called_once_with(
            self.backup.uuid_str,
            installation_id=INSTALLATION_ID,
        )
        execution = self.backup.get_execution_state(create=False)
        witness = execution.metadata["artifact_ciphertext_cleanup"]
        self.assertEqual(witness["status"], "complete")
        self.assertEqual(
            witness["envelope_id"], str(source_artifact.encryption_envelope.uuid)
        )

        # Simulate deletion succeeding immediately before the database witness.
        metadata = dict(execution.metadata)
        metadata.pop("artifact_ciphertext_cleanup")
        execution.metadata = metadata
        execution.save(update_fields=["metadata", "modified"])
        with mock.patch(
            "backupsheep.staging.cleanup_ciphertext_fence", return_value=False
        ) as cleanup:
            self.assertFalse(
                cleanup_terminal_source_ciphertext(
                    self.backup,
                    expected_lane="files",
                )
            )
        cleanup.assert_called_once()

        # A replay after the witness cannot require another filesystem mutation.
        with mock.patch("backupsheep.staging.cleanup_ciphertext_fence") as cleanup:
            self.assertFalse(
                cleanup_terminal_source_ciphertext(
                    self.backup,
                    expected_lane="files",
                )
            )
        cleanup.assert_not_called()
        with self.assertRaises(ArtifactPipelineError):
            cleanup_terminal_source_ciphertext(
                self.backup,
                expected_lane="database",
            )


def stat_mode(path):
    return os.stat(path, follow_symlinks=False).st_mode & 0o7777


class ArtifactPreflightPolicyTests(BaseTestCase):
    def test_local_file_provider_requires_sealed_installation_witness(self):
        witness = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{INSTALLATION_ID}|local-file|generation=1"
            ).encode("ascii")
        ).hexdigest()
        provider = mock.Mock()
        settings_values = {
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER": "local-file",
            "BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH": "/exact/keyring",
            "BACKUPSHEEP_INSTALLATION_ID": INSTALLATION_ID,
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION": "",
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS": "",
        }
        with mock.patch.dict(
            os.environ,
            {"BACKUPSHEEP_RUNTIME_ROLE": "files"},
        ), mock.patch(
            "apps._tasks.artifact_encryption.LocalFileKeyProvider",
            return_value=provider,
        ) as provider_class:
            with override_settings(**settings_values):
                with self.assertRaisesRegex(ArtifactPipelineError, "not sealed"):
                    with _configured_provider():
                        pass
            provider_class.assert_not_called()

            sealed_values = {
                **settings_values,
                "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION": "1",
                "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS": witness,
            }
            with override_settings(**sealed_values):
                with _configured_provider() as configured:
                    self.assertIs(configured, provider)
        provider.destroy.assert_called_once_with()

    def test_docker_preflight_requires_local_file_bse1_without_legacy(self):
        installation_id = "a" * 64
        witness = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{installation_id}|local-file|generation=1"
            ).encode("ascii")
        ).hexdigest()
        runtime = SimpleNamespace(
            BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="legacy-only",
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-development",
            BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
            BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH="",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION="",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS="",
            BACKUPSHEEP_INSTALLATION_ID=installation_id,
        )
        with self.assertRaises(CommandError):
            _assert_artifact_encryption_boundary(
                environment={}, runtime_settings=runtime
            )

        runtime.BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE = "bse1"
        runtime.BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE = True
        runtime.BACKUPSHEEP_ARTIFACT_KEY_PROVIDER = "local-file"
        runtime.BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE = False
        runtime.BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION = "1"
        runtime.BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS = witness
        _assert_artifact_encryption_boundary(
            environment={"BACKUPSHEEP_RUNTIME_ROLE": "app"},
            runtime_settings=runtime,
        )

    def test_docker_preflight_accepts_only_the_exact_source_lane_keyring(self):
        installation_id = "a" * 64
        witness = hashlib.sha256(
            (
                "BackupSheep/artifact-key-provider/v1|"
                f"{installation_id}|local-file|generation=1"
            ).encode("ascii")
        ).hexdigest()
        expected = "/run/secrets/artifact_local_file_database_keyring"
        runtime = SimpleNamespace(
            BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="bse1",
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=True,
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-file",
            BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=False,
            BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=expected,
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION="1",
            BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS=witness,
            BACKUPSHEEP_INSTALLATION_ID=installation_id,
        )

        def exists(path):
            return str(path) == expected

        with mock.patch.object(Path, "exists", autospec=True, side_effect=exists), mock.patch.object(
            Path,
            "is_symlink",
            autospec=True,
            return_value=False,
        ):
            _assert_artifact_encryption_boundary(
                environment={"BACKUPSHEEP_RUNTIME_ROLE": "database"},
                runtime_settings=runtime,
            )
            runtime.BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH = (
                "/run/secrets/artifact_local_file_files_keyring"
            )
            with self.assertRaisesRegex(CommandError, "exact lane"):
                _assert_artifact_encryption_boundary(
                    environment={"BACKUPSHEEP_RUNTIME_ROLE": "database"},
                    runtime_settings=runtime,
                )

    def test_source_preflight_rejects_stale_keyring_missing_database_wrap_key(self):
        cursor = mock.Mock()
        cursor.fetchall.return_value = [
            ("lfk-22222222222222222222222222222222",)
        ]
        runtime = SimpleNamespace(
            BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=(
                "/run/secrets/artifact_local_file_database_keyring"
            ),
            BACKUPSHEEP_INSTALLATION_ID="a" * 64,
        )
        provider = mock.Mock()
        provider.key_ids = ("lfk-11111111111111111111111111111111",)
        with mock.patch(
            "backupsheep.artifact_crypto.providers.LocalFileKeyProvider",
            return_value=provider,
        ):
            with self.assertRaisesRegex(CommandError, "database-referenced"):
                _assert_artifact_keyring_database_state(
                    cursor=cursor,
                    environment={"BACKUPSHEEP_RUNTIME_ROLE": "database"},
                    runtime_settings=runtime,
                )
        provider.destroy.assert_called_once_with()

        cursor.fetchall.return_value = [
            ("lfk-11111111111111111111111111111111",)
        ]
        provider.reset_mock()
        with mock.patch(
            "backupsheep.artifact_crypto.providers.LocalFileKeyProvider",
            return_value=provider,
        ):
            _assert_artifact_keyring_database_state(
                cursor=cursor,
                environment={"BACKUPSHEEP_RUNTIME_ROLE": "database"},
                runtime_settings=runtime,
            )
        provider.destroy.assert_called_once_with()
        cursor.execute.assert_called_with(
            mock.ANY,
            ["local-file", "retired"],
        )
