"""Durability and backward-compatibility tests for encryption ledgers."""

import hashlib
import uuid

from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupEncryptionEnvelope,
    CoreBackupExecution,
    CoreBackupKeyWrap,
    CoreDigitalOceanBackup,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.artifact_crypto import ArtifactContext


class ArtifactEncryptionModelTests(BaseTestCase):
    def _force_encryption_constraints(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SET CONSTRAINTS backup_envelope_state_consistency, "
                "backup_key_wrap_state_consistency, "
                "backup_artifact_encryption_consistency IMMEDIATE"
            )
            cursor.execute(
                "SET CONSTRAINTS backup_envelope_state_consistency, "
                "backup_key_wrap_state_consistency, "
                "backup_artifact_encryption_consistency DEFERRED"
            )

    def _context(self, backup):
        backup_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"backupsheep-test:{backup._meta.label_lower}:{backup.pk}",
        )
        return ArtifactContext(
            installation_id="a" * 64,
            account_id=str(self.account.pk),
            node_id=str(backup.digitalocean.node_id),
            backup_id=str(backup_id),
            backup_model="apps.coredigitaloceanbackup",
            lane="files",
        )

    def _backup(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id=f"task-{node.pk}",
            attempt_no=1,
        )
        execution = backup.initialize_execution(
            celery_task_id=backup.celery_task_id,
            attempt_no=1,
        )
        artifact = backup.record_artifact_integrity(
            role=CoreBackupArtifact.Role.SOURCE,
            object_key=f"local/{backup.uuid_str}.zip",
            byte_count=123,
            checksum_algorithm="sha256",
            checksum_value="1" * 64,
            verified_at=timezone.now(),
        )
        return backup, execution, artifact

    def _envelope(self, execution, backup, **overrides):
        context = self._context(backup)
        values = {
            "execution": execution,
            "context_canonical_json": context.canonical_bytes().decode("ascii"),
            "context_sha256": context.sha256,
            "header_sha256": "3" * 64,
            "plaintext_byte_count": 123,
            "plaintext_sha256": "4" * 64,
            "ciphertext_byte_count": 456,
            "status": CoreBackupEncryptionEnvelope.Status.PENDING,
        }
        values.update(overrides)
        return CoreBackupEncryptionEnvelope.objects.create(**values)

    def _key_wrap(self, envelope, **overrides):
        wrapped = overrides.pop("wrapped_data_key", b"provider-wrapped-data-key")
        values = {
            "envelope": envelope,
            "generation": 1,
            "provider": CoreBackupKeyWrap.Provider.LOCAL_FILE,
            "wrapping_key_id": "lfk-11111111111111111111111111111111",
            "wrapped_data_key": wrapped,
            "wrapped_key_sha256": hashlib.sha256(wrapped).hexdigest(),
            "status": CoreBackupKeyWrap.Status.PENDING,
        }
        values.update(overrides)
        return CoreBackupKeyWrap.objects.create(**values)

    def test_existing_artifacts_remain_explicit_legacy_zip_records(self):
        _backup, _execution, artifact = self._backup()

        self.assertEqual(artifact.artifact_format, CoreBackupArtifact.Format.LEGACY_ZIP)
        self.assertIsNone(artifact.encryption_envelope_id)
        artifact.full_clean()

    def test_bse1_artifact_links_execution_envelope_and_active_key_wrap(self):
        backup, execution, artifact = self._backup()
        envelope = self._envelope(execution, backup)
        key_wrap = self._key_wrap(envelope)
        envelope.full_clean()
        key_wrap.full_clean()

        envelope.activate_with_key_wrap(key_wrap, artifacts=[artifact])
        artifact.refresh_from_db()

        self.assertEqual(envelope.get_active_key_wrap(), key_wrap)
        self.assertEqual(list(envelope.artifacts.all()), [artifact])
        context, active_wrap = artifact.validate_encrypted_restore_state()
        self.assertEqual(context, self._context(backup))
        self.assertEqual(active_wrap, key_wrap)

    def test_artifact_format_constraint_fails_closed_in_both_directions(self):
        backup, execution, artifact = self._backup()
        envelope = self._envelope(execution, backup)

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupArtifact.objects.filter(pk=artifact.pk).update(
                artifact_format=CoreBackupArtifact.Format.BSE1,
                encryption_envelope=None,
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupArtifact.objects.filter(pk=artifact.pk).update(
                artifact_format=CoreBackupArtifact.Format.LEGACY_ZIP,
                encryption_envelope=envelope,
            )

    def test_artifact_rejects_an_envelope_owned_by_a_different_backup(self):
        first, first_execution, _first_artifact = self._backup()
        envelope = self._envelope(first_execution, first)
        key_wrap = self._key_wrap(envelope)
        envelope.activate_with_key_wrap(key_wrap)
        _second, _second_execution, second_artifact = self._backup()
        second_artifact.artifact_format = CoreBackupArtifact.Format.BSE1
        second_artifact.encryption_envelope = envelope

        with self.assertRaises(ValidationError):
            second_artifact.full_clean()

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupArtifact.objects.filter(pk=second_artifact.pk).update(
                artifact_format=CoreBackupArtifact.Format.BSE1,
                encryption_envelope=envelope,
            )
            self._force_encryption_constraints()

    def test_envelope_and_key_wrap_validate_hashes_and_activation_witnesses(self):
        backup, execution, _artifact = self._backup()
        context = self._context(backup)
        envelope = CoreBackupEncryptionEnvelope(
            execution=execution,
            context_canonical_json=context.canonical_bytes().decode("ascii"),
            context_sha256="not-a-digest",
            header_sha256="3" * 64,
            plaintext_sha256="4" * 64,
            ciphertext_byte_count=1,
            status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
        )
        with self.assertRaises(ValidationError) as envelope_error:
            envelope.full_clean()
        self.assertIn("context_sha256", envelope_error.exception.message_dict)
        self.assertIn("sealed_at", envelope_error.exception.message_dict)

        envelope = self._envelope(execution, backup)
        key_wrap = CoreBackupKeyWrap(
            envelope=envelope,
            provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
            wrapping_key_id="key",
            wrapped_data_key=b"wrapped",
            wrapped_key_sha256="0" * 64,
            status=CoreBackupKeyWrap.Status.ACTIVE,
        )
        with self.assertRaises(ValidationError) as key_error:
            key_wrap.full_clean()
        self.assertIn("wrapped_key_sha256", key_error.exception.message_dict)
        self.assertIn("activated_at", key_error.exception.message_dict)

    def test_only_one_active_key_wrap_generation_is_allowed(self):
        backup, execution, _artifact = self._backup()
        envelope = self._envelope(execution, backup)
        key_wrap = self._key_wrap(envelope)
        envelope.activate_with_key_wrap(key_wrap)

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._key_wrap(
                envelope,
                generation=2,
                status=CoreBackupKeyWrap.Status.ACTIVE,
                activated_at=timezone.now(),
            )

        retired = self._key_wrap(
            envelope,
            generation=2,
            status=CoreBackupKeyWrap.Status.RETIRED,
            activated_at=None,
            retired_at=timezone.now(),
        )
        retired.full_clean()

    def test_database_rejects_incomplete_publication_states(self):
        backup, execution, artifact = self._backup()
        envelope = self._envelope(execution, backup)

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupEncryptionEnvelope.objects.filter(pk=envelope.pk).update(
                status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
                sealed_at=timezone.now(),
            )
            self._force_encryption_constraints()

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupArtifact.objects.filter(pk=artifact.pk).update(
                artifact_format=CoreBackupArtifact.Format.BSE1,
                encryption_envelope=envelope,
            )
            self._force_encryption_constraints()

    def test_durable_context_and_execution_identity_are_database_immutable(self):
        backup, execution, _artifact = self._backup()
        envelope = self._envelope(execution, backup)

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupEncryptionEnvelope.objects.filter(pk=envelope.pk).update(
                context_canonical_json="{}"
            )

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupExecution.objects.filter(pk=execution.pk).update(
                backup_object_id=execution.backup_object_id + 1
            )

    def test_publication_witnesses_cannot_be_changed_by_status_dance(self):
        backup, execution, _artifact = self._backup()
        envelope = self._envelope(execution, backup)
        key_wrap = self._key_wrap(envelope)
        envelope.activate_with_key_wrap(key_wrap)

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupKeyWrap.objects.filter(pk=key_wrap.pk).update(
                status=CoreBackupKeyWrap.Status.PENDING
            )
            CoreBackupEncryptionEnvelope.objects.filter(pk=envelope.pk).update(
                status=CoreBackupEncryptionEnvelope.Status.PENDING
            )
            CoreBackupEncryptionEnvelope.objects.filter(pk=envelope.pk).update(
                header_sha256="5" * 64
            )

        replacement = b"different-provider-wrapped-key"
        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreBackupKeyWrap.objects.filter(pk=key_wrap.pk).update(
                status=CoreBackupKeyWrap.Status.PENDING
            )
            CoreBackupEncryptionEnvelope.objects.filter(pk=envelope.pk).update(
                status=CoreBackupEncryptionEnvelope.Status.PENDING
            )
            CoreBackupKeyWrap.objects.filter(pk=key_wrap.pk).update(
                wrapped_data_key=replacement,
                wrapped_key_sha256=hashlib.sha256(replacement).hexdigest(),
            )

    def test_backup_deletion_cascades_envelope_wraps_and_encrypted_artifacts(self):
        backup, execution, artifact = self._backup()
        envelope = self._envelope(execution, backup)
        key_wrap = self._key_wrap(envelope)
        envelope.activate_with_key_wrap(key_wrap, artifacts=[artifact])
        ids = (execution.pk, envelope.pk, key_wrap.pk, artifact.pk)

        backup.delete()

        self.assertFalse(CoreBackupExecution.objects.filter(pk=ids[0]).exists())
        self.assertFalse(
            CoreBackupEncryptionEnvelope.objects.filter(pk=ids[1]).exists()
        )
        self.assertFalse(CoreBackupKeyWrap.objects.filter(pk=ids[2]).exists())
        self.assertFalse(CoreBackupArtifact.objects.filter(pk=ids[3]).exists())
