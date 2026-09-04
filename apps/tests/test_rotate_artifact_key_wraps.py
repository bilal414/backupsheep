"""Safety tests for resumable local-file data-key rewrapping."""

import hashlib
import io
import uuid
from contextlib import nullcontext
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone

from apps.management.commands import rotate_artifact_key_wraps as rotation
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupEncryptionEnvelope,
    CoreBackupKeyWrap,
    CoreDigitalOceanBackup,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.artifact_crypto import ArtifactContext, WrappedDataKey


SOURCE_KEY = "lfk-11111111111111111111111111111111"
DESTINATION_KEY = "lfk-22222222222222222222222222222222"
INSTALLATION_ID = "a" * 64
THIRD_KEY = "lfk-33333333333333333333333333333333"


@override_settings(
    BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="bse1",
    BACKUPSHEEP_ARTIFACT_KEY_PROVIDER="local-file",
    BACKUPSHEEP_INSTALLATION_ID=INSTALLATION_ID,
)
class ArtifactKeyWrapRotationTests(BaseTestCase):
    def _active_envelope(self, *, wrapping_key=SOURCE_KEY):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id=f"rotation-{node.pk}",
            attempt_no=1,
        )
        execution = backup.initialize_execution(
            celery_task_id=backup.celery_task_id,
            attempt_no=1,
        )
        artifact = backup.record_artifact_integrity(
            role=CoreBackupArtifact.Role.SOURCE,
            object_key=f"local/{backup.uuid_str}.bse1",
            byte_count=456,
            checksum_algorithm="sha256",
            checksum_value="1" * 64,
            verified_at=timezone.now(),
        )
        context = ArtifactContext(
            installation_id=INSTALLATION_ID,
            account_id=str(self.account.pk),
            node_id=str(backup.digitalocean.node_id),
            backup_id=str(uuid.uuid4()),
            backup_model="apps.coredigitaloceanbackup",
            lane="files",
        )
        envelope = CoreBackupEncryptionEnvelope.objects.create(
            execution=execution,
            context_canonical_json=context.canonical_bytes().decode("ascii"),
            context_sha256=context.sha256,
            header_sha256="3" * 64,
            plaintext_byte_count=123,
            plaintext_sha256="4" * 64,
            ciphertext_byte_count=456,
        )
        wrapped = b"source-provider-wrapped-data-key"
        key_wrap = CoreBackupKeyWrap.objects.create(
            envelope=envelope,
            generation=1,
            provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
            wrapping_key_id=wrapping_key,
            wrapped_data_key=wrapped,
            wrapped_key_sha256=hashlib.sha256(wrapped).hexdigest(),
        )
        envelope.activate_with_key_wrap(key_wrap, artifacts=[artifact])
        return envelope, key_wrap

    def _arguments(self, *, apply=False):
        values = {
            "expected_source_key_id": SOURCE_KEY,
            "installation_id_witness": INSTALLATION_ID,
            "lane": "files",
            "limit": 100,
            "apply": apply,
        }
        return values

    def test_default_plan_is_read_only_after_validating_keyring(self):
        envelope, original = self._active_envelope()
        output = io.StringIO()
        provider = self.mock_provider(b"unused")
        with mock.patch.object(
            rotation,
            "_configured_provider",
            return_value=nullcontext(provider),
        ):
            call_command("rotate_artifact_key_wraps", stdout=output, **self._arguments())
        self.assertIn("no keyring or database mutation", output.getvalue())
        envelope.refresh_from_db()
        original.refresh_from_db()
        self.assertEqual(envelope.get_active_key_wrap().pk, original.pk)
        self.assertEqual(envelope.key_wraps.count(), 1)

    def test_plan_filters_candidates_to_the_explicit_credential_lane(self):
        self._active_envelope()
        output = io.StringIO()
        arguments = self._arguments()
        arguments["lane"] = "database"
        provider = self.mock_provider(b"unused", lane="database")
        with mock.patch.object(
            rotation,
            "_configured_provider",
            return_value=nullcontext(provider),
        ):
            call_command("rotate_artifact_key_wraps", stdout=output, **arguments)
        self.assertIn(
            f"lane=database source={SOURCE_KEY} destination={DESTINATION_KEY} "
            "selected=0",
            output.getvalue(),
        )

    def test_shared_provider_factory_context_is_entered_and_closed(self):
        provider = mock.Mock()
        provider.name = "local-file"
        provider.enterprise_eligible = True
        provider.lane = "files"
        manager = mock.MagicMock()
        manager.__enter__.return_value = provider
        with mock.patch(
            "apps._tasks.artifact_encryption._configured_provider",
            return_value=manager,
        ) as provider_factory:
            with rotation._configured_provider(lane="files") as observed:
                self.assertIs(observed, provider)
        provider_factory.assert_called_once_with()
        manager.__enter__.assert_called_once_with()
        manager.__exit__.assert_called_once()

    def test_successful_rotation_is_atomic_and_preserves_retired_witness(self):
        envelope, original = self._active_envelope()
        provider = self.mock_provider(b"destination-wrapped-key")
        result = rotation._rotate_one(
            envelope.pk,
            provider=provider,
            source_key=SOURCE_KEY,
            destination_key=DESTINATION_KEY,
            installation_id=INSTALLATION_ID,
            expected_lane="files",
        )
        self.assertEqual(result, "rotated")
        original.refresh_from_db()
        replacement = envelope.get_active_key_wrap()
        self.assertEqual(original.status, CoreBackupKeyWrap.Status.RETIRED)
        self.assertIsNotNone(original.retired_at)
        self.assertEqual(replacement.generation, 2)
        self.assertEqual(replacement.wrapping_key_id, DESTINATION_KEY)
        self.assertEqual(
            replacement.wrapped_key_sha256,
            hashlib.sha256(b"destination-wrapped-key").hexdigest(),
        )
        provider.rewrap_data_key.assert_called_once()

    def test_apply_command_uses_provider_once_and_is_resumable(self):
        envelope, _original = self._active_envelope()
        provider = self.mock_provider(b"command-destination-wrap")
        output = io.StringIO()
        with mock.patch.object(
            rotation,
            "_configured_provider",
            side_effect=lambda **_kwargs: nullcontext(provider),
        ) as provider_factory:
            call_command(
                "rotate_artifact_key_wraps",
                stdout=output,
                **self._arguments(apply=True),
            )
        provider_factory.assert_called_once_with(lane="files")
        self.assertIn("rotated=1", output.getvalue())
        self.assertEqual(
            envelope.get_active_key_wrap().wrapping_key_id,
            DESTINATION_KEY,
        )

        output = io.StringIO()
        with mock.patch.object(
            rotation,
            "_configured_provider",
            side_effect=lambda **_kwargs: nullcontext(provider),
        ):
            call_command(
                "rotate_artifact_key_wraps",
                stdout=output,
                **self._arguments(apply=True),
            )
        self.assertIn("rotated=0", output.getvalue())
        provider.rewrap_data_key.assert_called_once()

    def test_provider_failure_rolls_back_without_pending_or_retired_state(self):
        envelope, original = self._active_envelope()
        provider = self.mock_provider(b"unused")
        provider.rewrap_data_key.side_effect = RuntimeError("keyring unavailable")
        with self.assertRaisesRegex(CommandError, "no database state changed"):
            rotation._rotate_one(
                envelope.pk,
                provider=provider,
                source_key=SOURCE_KEY,
                destination_key=DESTINATION_KEY,
                installation_id=INSTALLATION_ID,
                expected_lane="files",
            )
        original.refresh_from_db()
        self.assertEqual(original.status, CoreBackupKeyWrap.Status.ACTIVE)
        self.assertIsNone(original.retired_at)
        self.assertEqual(envelope.key_wraps.count(), 1)

    def test_unexpected_source_key_and_wrong_installation_fail_closed(self):
        envelope, _original = self._active_envelope(wrapping_key=THIRD_KEY)
        provider = self.mock_provider(b"unused")
        with self.assertRaisesRegex(CommandError, "unexpected wrapping key"):
            rotation._rotate_one(
                envelope.pk,
                provider=provider,
                source_key=SOURCE_KEY,
                destination_key=DESTINATION_KEY,
                installation_id=INSTALLATION_ID,
                expected_lane="files",
            )
        provider.rewrap_data_key.assert_not_called()

        with self.assertRaisesRegex(CommandError, "installation identity"):
            rotation._validated_rotation_scope(
                source_key=SOURCE_KEY,
                witness="b" * 64,
                lane="files",
            )

    @staticmethod
    def mock_provider(ciphertext, *, lane="files"):
        provider = mock.Mock()
        provider.name = "local-file"
        provider.enterprise_eligible = True
        provider.lane = lane
        provider.active_key_id = DESTINATION_KEY
        provider.key_ids = (DESTINATION_KEY, SOURCE_KEY)
        provider.rewrap_data_key.return_value = WrappedDataKey(
            provider_name="local-file",
            wrapping_key_id=DESTINATION_KEY,
            ciphertext=ciphertext,
        )
        return provider
