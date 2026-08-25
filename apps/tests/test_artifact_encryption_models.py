"""Durability and backward-compatibility tests for encryption ledgers."""

import hashlib

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
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


class ArtifactEncryptionModelTests(BaseTestCase):
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

    def _envelope(self, execution, **overrides):
        values = {
            "execution": execution,
            "context_sha256": "2" * 64,
            "header_sha256": "3" * 64,
            "plaintext_byte_count": 123,
            "plaintext_sha256": "4" * 64,
            "ciphertext_byte_count": 456,
            "status": CoreBackupEncryptionEnvelope.Status.ACTIVE,
            "sealed_at": timezone.now(),
        }
        values.update(overrides)
        return CoreBackupEncryptionEnvelope.objects.create(**values)

    def _key_wrap(self, envelope, **overrides):
        wrapped = overrides.pop("wrapped_data_key", b"provider-wrapped-data-key")
        values = {
            "envelope": envelope,
            "generation": 1,
            "provider": CoreBackupKeyWrap.Provider.AWS_KMS,
            "wrapping_key_id": "arn:aws:kms:us-east-1:123:key/example",
            "wrapped_data_key": wrapped,
            "wrapped_key_sha256": hashlib.sha256(wrapped).hexdigest(),
            "status": CoreBackupKeyWrap.Status.ACTIVE,
            "activated_at": timezone.now(),
        }
        values.update(overrides)
        return CoreBackupKeyWrap.objects.create(**values)

    def test_existing_artifacts_remain_explicit_legacy_zip_records(self):
        _backup, _execution, artifact = self._backup()

        self.assertEqual(artifact.artifact_format, CoreBackupArtifact.Format.LEGACY_ZIP)
        self.assertIsNone(artifact.encryption_envelope_id)
        artifact.full_clean()

    def test_bse1_artifact_links_execution_envelope_and_active_key_wrap(self):
        _backup, execution, artifact = self._backup()
        envelope = self._envelope(execution)
        key_wrap = self._key_wrap(envelope)
        envelope.full_clean()
        key_wrap.full_clean()

        artifact.artifact_format = CoreBackupArtifact.Format.BSE1
        artifact.encryption_envelope = envelope
        artifact.full_clean()
        artifact.save(
            update_fields=["artifact_format", "encryption_envelope", "modified"]
        )

        self.assertEqual(envelope.get_active_key_wrap(), key_wrap)
        self.assertEqual(list(envelope.artifacts.all()), [artifact])

    def test_artifact_format_constraint_fails_closed_in_both_directions(self):
        _backup, execution, artifact = self._backup()
        envelope = self._envelope(execution)

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
        _first, first_execution, _first_artifact = self._backup()
        envelope = self._envelope(first_execution)
        _second, _second_execution, second_artifact = self._backup()
        second_artifact.artifact_format = CoreBackupArtifact.Format.BSE1
        second_artifact.encryption_envelope = envelope

        with self.assertRaises(ValidationError):
            second_artifact.full_clean()

    def test_envelope_and_key_wrap_validate_hashes_and_activation_witnesses(self):
        _backup, execution, _artifact = self._backup()
        envelope = CoreBackupEncryptionEnvelope(
            execution=execution,
            context_sha256="not-a-digest",
            header_sha256="3" * 64,
            plaintext_sha256="4" * 64,
            status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
        )
        with self.assertRaises(ValidationError) as envelope_error:
            envelope.full_clean()
        self.assertIn("context_sha256", envelope_error.exception.message_dict)
        self.assertIn("sealed_at", envelope_error.exception.message_dict)

        envelope = self._envelope(execution)
        key_wrap = CoreBackupKeyWrap(
            envelope=envelope,
            provider=CoreBackupKeyWrap.Provider.AWS_KMS,
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
        _backup, execution, _artifact = self._backup()
        envelope = self._envelope(execution)
        self._key_wrap(envelope)

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._key_wrap(envelope, generation=2)

        retired = self._key_wrap(
            envelope,
            generation=2,
            status=CoreBackupKeyWrap.Status.RETIRED,
            activated_at=None,
            retired_at=timezone.now(),
        )
        retired.full_clean()

    def test_backup_deletion_cascades_envelope_wraps_and_encrypted_artifacts(self):
        backup, execution, artifact = self._backup()
        envelope = self._envelope(execution)
        key_wrap = self._key_wrap(envelope)
        artifact.artifact_format = CoreBackupArtifact.Format.BSE1
        artifact.encryption_envelope = envelope
        artifact.save(
            update_fields=["artifact_format", "encryption_envelope", "modified"]
        )
        ids = (execution.pk, envelope.pk, key_wrap.pk, artifact.pk)

        backup.delete()

        self.assertFalse(CoreBackupExecution.objects.filter(pk=ids[0]).exists())
        self.assertFalse(
            CoreBackupEncryptionEnvelope.objects.filter(pk=ids[1]).exists()
        )
        self.assertFalse(CoreBackupKeyWrap.objects.filter(pk=ids[2]).exists())
        self.assertFalse(CoreBackupArtifact.objects.filter(pk=ids[3]).exists())
