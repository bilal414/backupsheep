"""Durable, provider-independent backup execution state and recovery fencing."""

import os
import shutil
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest import mock

from django.db import close_old_connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.execution import (
    durable_execution_lease,
    verify_and_commit_source_artifact,
)
from apps._tasks.integration.backup._archive import create_python_zip
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupExecution,
    CoreDigitalOceanBackup,
)
from apps.console.connection.models import CoreIntegration
from apps.console.utils.models import BackupExecutionLeaseLostError, UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class BackupExecutionStateTests(BaseTestCase):
    def _backup(self, status=UtilBackup.Status.IN_PROGRESS, task_id="backup-task-1"):
        node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=status,
            celery_task_id=task_id,
            attempt_no=1,
        )
        return node, backup

    def test_legacy_backup_lazily_gets_backward_compatible_defaults(self):
        _node, backup = self._backup()

        self.assertEqual(CoreBackupExecution.objects.count(), 0)
        state = backup.get_execution_state(create=True)

        self.assertIsNotNone(state.correlation_id)
        self.assertEqual(state.attempt_count, 0)
        self.assertEqual(state.delivery_count, 0)
        self.assertEqual(state.claim_count, 0)
        self.assertEqual(state.lease_owner, "")
        self.assertIsNone(state.lease_token)
        self.assertIsNone(state.lease_expires_at)
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.NONE,
        )
        self.assertEqual(state.reconciliation_metadata, {})
        self.assertEqual(state.provider_metadata, {})
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)

    def test_initialize_preserves_correlation_and_tracks_attempts_and_redelivery(self):
        _node, backup = self._backup()

        first = backup.initialize_execution(
            celery_task_id="task-a", attempt_no=1, task_name="backup_digitalocean"
        )
        correlation_id = first.correlation_id
        second = backup.initialize_execution(
            celery_task_id="task-a", attempt_no=3, task_name="backup_digitalocean"
        )

        self.assertEqual(second.correlation_id, correlation_id)
        self.assertEqual(second.celery_task_id, "task-a")
        self.assertEqual(second.task_name, "backup_digitalocean")
        self.assertEqual(second.attempt_count, 3)
        self.assertEqual(second.delivery_count, 2)
        self.assertEqual(CoreBackupExecution.objects.count(), 1)

    def test_live_lease_blocks_duplicate_delivery_including_same_task_id(self):
        _node, backup = self._backup()
        now = timezone.now()

        first = backup.claim_execution(
            lease_owner="task-a", phase="create", lease_seconds=300, now=now
        )

        self.assertIsNotNone(first)
        self.assertIsNone(
            backup.claim_execution(
                lease_owner="task-b", phase="create", lease_seconds=300, now=now
            )
        )
        self.assertIsNone(
            backup.claim_execution(
                lease_owner="task-a", phase="create", lease_seconds=300, now=now
            )
        )
        state = backup.get_execution_state()
        self.assertEqual(state.claim_count, 1)
        self.assertEqual(state.lease_token, first.lease_token)

    def test_stale_takeover_fences_old_worker_and_marks_reconciliation(self):
        _node, backup = self._backup()
        started = timezone.now()
        first = backup.claim_execution(
            lease_owner="worker-a",
            phase="upload",
            lease_seconds=60,
            now=started,
        )
        first_token = first.lease_token

        takeover_at = started + timedelta(seconds=61)
        replacement = backup.claim_execution(
            lease_owner="worker-b",
            phase="recovery",
            lease_seconds=120,
            now=takeover_at,
            increment_attempt=True,
        )

        self.assertIsNotNone(replacement)
        self.assertNotEqual(replacement.lease_token, first_token)
        self.assertEqual(
            replacement.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertEqual(
            replacement.reconciliation_reason, "stale_execution_lease"
        )
        self.assertEqual(replacement.attempt_count, 1)
        self.assertEqual(
            replacement.reconciliation_metadata["stale_lease_takeovers"][-1][
                "previous_owner"
            ],
            "worker-a",
        )

        self.assertIsNone(
            backup.heartbeat_execution(
                lease_owner="worker-a",
                lease_token=first_token,
                lease_seconds=60,
                now=takeover_at + timedelta(seconds=1),
            )
        )
        self.assertIsNone(
            backup.release_execution(
                lease_owner="worker-a",
                lease_token=first_token,
                phase="upload",
                now=takeover_at + timedelta(seconds=1),
            )
        )

        heartbeat = backup.heartbeat_execution(
            lease_owner="worker-b",
            lease_token=replacement.lease_token,
            lease_seconds=120,
            progress_completed=512,
            progress_total=1024,
            progress_unit="bytes",
            now=takeover_at + timedelta(seconds=1),
        )
        self.assertEqual(heartbeat.progress_completed, 512)
        self.assertEqual(heartbeat.progress_total, 1024)
        self.assertEqual(heartbeat.progress_unit, "bytes")
        reconciling = backup.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.IN_PROGRESS,
            reason="adopting provider operation",
            metadata={"match_count": 1},
            lease_owner="worker-b",
            lease_token=replacement.lease_token,
            now=takeover_at + timedelta(seconds=2),
        )
        self.assertEqual(
            reconciling.reconciliation_state,
            CoreBackupExecution.ReconciliationState.IN_PROGRESS,
        )
        resolved = backup.set_reconciliation_state(
            reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
            reason="provider operation adopted",
            lease_owner="worker-b",
            lease_token=replacement.lease_token,
            now=takeover_at + timedelta(seconds=3),
        )
        self.assertEqual(
            resolved.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(resolved.reconciliation_metadata["match_count"], 1)

    def test_retry_deadline_and_terminal_status_prevent_claim(self):
        _node, backup = self._backup()
        retry_at = timezone.now() + timedelta(minutes=5)
        backup.record_execution_error(
            code="PROVIDER_RATE_LIMIT",
            message="retry later",
            retry_at=retry_at,
        )

        self.assertIsNone(
            backup.claim_execution(
                lease_owner="worker-a", phase="poll", lease_seconds=60
            )
        )

        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        self.assertIsNone(
            backup.claim_execution(
                lease_owner="worker-a",
                phase="poll",
                lease_seconds=60,
                respect_retry_at=False,
            )
        )

    def test_raw_provider_exception_text_is_never_persisted(self):
        _node, backup = self._backup()
        secret = "Bearer live-provider-token password=database-secret"

        state = backup.record_execution_error(
            code="UNMAPPED_PROVIDER_FAILURE",
            message=f"request failed: {secret}",
        )

        self.assertNotIn(secret, state.last_error_message)
        self.assertNotIn("provider-token", state.last_error_message)
        self.assertEqual(
            state.last_error_message,
            "Backup execution encountered an error. Review secured diagnostics using the correlation ID.",
        )

    def test_retryable_error_contract_persists_safe_retry_status(self):
        _node, backup = self._backup()
        retry_at = timezone.now() + timedelta(minutes=15)

        state = backup.record_execution_error(
            code="STORAGE_TRANSIENT_FAILURE",
            message="provider response with secret-token-canary",
            retryable=True,
            retry_at=retry_at,
        )

        self.assertTrue(state.metadata["retryable"])
        self.assertEqual(state.next_retry_at, retry_at)
        self.assertNotIn("secret-token-canary", state.last_error_message)

    def test_durable_local_lease_blocks_duplicate_delivery_and_releases(self):
        _node, backup = self._backup()

        with durable_execution_lease(
            backup, phase="source_dispatch", task_id="delivery-a"
        ) as first:
            self.assertTrue(first.acquired)
            with durable_execution_lease(
                backup, phase="source_dispatch", task_id="delivery-b"
            ) as duplicate:
                self.assertFalse(duplicate.acquired)
            first.ensure_owned()

        state = backup.get_execution_state()
        self.assertFalse(state.lease_is_active())
        self.assertIsNone(state.lease_token)

    def test_fenced_progress_can_publish_and_clear_a_safe_ui_stage(self):
        _node, backup = self._backup()

        with durable_execution_lease(
            backup, phase="source_dispatch", task_id="website-stage"
        ) as execution:
            execution.progress(
                10000,
                None,
                unit="files",
                metadata_updates={"public_stage": "website_enumerating"},
            )
            state = backup.get_execution_state()
            self.assertEqual(state.progress_completed, 10000)
            self.assertEqual(state.progress_unit, "files")
            self.assertEqual(
                state.metadata["public_stage"],
                "website_enumerating",
            )

            execution.progress(
                12000,
                12000,
                unit="files",
                metadata_updates={"public_stage": None},
            )
            state = backup.get_execution_state()
            self.assertNotIn("public_stage", state.metadata)

    def test_stale_worker_direct_save_is_fenced_after_takeover(self):
        _node, backup = self._backup()
        expired_at = timezone.now() - timedelta(minutes=2)
        first = backup.claim_execution(
            lease_owner="worker-a",
            phase="source_dispatch",
            lease_seconds=30,
            now=expired_at,
        )
        backup.bind_execution_fence("worker-a", first.lease_token)

        replacement = backup.claim_execution(
            lease_owner="worker-b",
            phase="source_recovery",
            lease_seconds=120,
        )
        self.assertIsNotNone(replacement)
        self.assertNotEqual(first.lease_token, replacement.lease_token)

        backup.status = UtilBackup.Status.FAILED
        with self.assertRaises(BackupExecutionLeaseLostError):
            backup.save(update_fields=["status", "modified"])

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)
        state = backup.get_execution_state()
        self.assertEqual(state.lease_owner, "worker-b")
        self.assertEqual(state.lease_token, replacement.lease_token)

    def test_archive_publication_is_atomic_and_fence_checked(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        source = os.path.join(root, "source")
        os.makedirs(source)
        with open(os.path.join(source, "database.sql"), "w") as dump:
            dump.write("SELECT 1;")
        archive_path = os.path.join(root, "backup.zip")
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("previous.txt", "committed")

        def reject_stale_worker():
            raise BackupExecutionLeaseLostError("stale worker")

        with self.assertRaises(BackupExecutionLeaseLostError):
            create_python_zip(
                source,
                archive_path,
                required_suffix=".sql",
                before_publish=reject_stale_worker,
            )

        with zipfile.ZipFile(archive_path) as archive:
            self.assertEqual(archive.namelist(), ["previous.txt"])
            self.assertEqual(archive.read("previous.txt"), b"committed")
        self.assertFalse(
            any(name.endswith(".partial.zip") for name in os.listdir(root))
        )

    def test_source_archive_commit_detects_corruption_before_upload(self):
        _node, backup = self._backup()
        backup.uuid = f"source-artifact-{backup.pk}"
        backup.save(update_fields=["uuid", "modified"])
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        storage = os.path.join(root, "_storage")
        os.makedirs(storage)
        archive_path = os.path.join(storage, f"{backup.uuid}.zip")
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("database.sql", "SELECT 1;")

        with override_settings(BASE_DIR=root):
            artifact = verify_and_commit_source_artifact(backup)
            self.assertEqual(artifact.checksum_algorithm, "sha256")
            self.assertGreater(artifact.byte_count, 0)
            self.assertTrue(
                os.path.isfile(
                    os.path.join(storage, f"{backup.uuid}.manifest.json")
                )
            )

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("database.sql", "SELECT 2;")
            with self.assertRaisesRegex(ValueError, "committed identity"):
                verify_and_commit_source_artifact(backup)

    def test_truncated_source_archive_is_never_committed(self):
        _node, backup = self._backup()
        backup.uuid = f"invalid-source-{backup.pk}"
        backup.save(update_fields=["uuid", "modified"])
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        storage = os.path.join(root, "_storage")
        os.makedirs(storage)
        with open(os.path.join(storage, f"{backup.uuid}.zip"), "wb") as archive:
            archive.write(b"not-a-zip")

        with override_settings(BASE_DIR=root):
            with self.assertRaisesRegex(ValueError, "valid ZIP"):
                verify_and_commit_source_artifact(backup)
        self.assertFalse(backup.artifact_records.filter(role="source").exists())

    def test_provider_and_storage_integrity_metadata_are_idempotent(self):
        _node, backup = self._backup()
        state = backup.claim_execution(
            lease_owner="worker-a", phase="create", lease_seconds=300
        )
        backup.record_provider_reference(
            operation_id="operation-1",
            resource_id="snapshot-1",
            idempotency_key="backup-marker-1",
            provider_status="accepted",
            metadata={"http_status": 202},
            lease_owner="worker-a",
            lease_token=state.lease_token,
        )

        verified_at = timezone.now()
        first = backup.record_artifact_integrity(
            role=CoreBackupArtifact.Role.ARCHIVE,
            object_key="backups/one.zip",
            byte_count=100,
            checksum_algorithm="sha256",
            checksum_value="a" * 64,
            etag="etag-1",
            version_id="version-1",
            verified_at=verified_at,
            metadata={"verification": "head_object"},
        )
        second = backup.record_artifact_integrity(
            role=CoreBackupArtifact.Role.ARCHIVE,
            object_key="backups/one.zip",
            byte_count=125,
            checksum_algorithm="sha256",
            checksum_value="b" * 64,
            etag="etag-2",
            version_id="version-2",
            verified_at=verified_at,
        )

        state.refresh_from_db()
        self.assertEqual(state.provider_operation_id, "operation-1")
        self.assertEqual(state.provider_resource_id, "snapshot-1")
        self.assertEqual(state.provider_idempotency_key, "backup-marker-1")
        self.assertEqual(state.provider_status, "accepted")
        self.assertEqual(state.provider_metadata, {"http_status": 202})
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(CoreBackupArtifact.objects.count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.byte_count, 125)
        self.assertEqual(second.etag, "etag-2")
        self.assertEqual(second.version_id, "version-2")
        self.assertEqual(second.checksum_value, "b" * 64)
        self.assertEqual(second.verified_at, verified_at)
        self.assertEqual(second.metadata, {"verification": "head_object"})

    def test_deleting_backup_cascades_execution_and_artifact_ledgers(self):
        _node, backup = self._backup()
        state = backup.initialize_execution(celery_task_id="task-a", attempt_no=1)
        artifact = backup.record_artifact_integrity(
            role=CoreBackupArtifact.Role.SOURCE,
            object_key="local/source.zip",
            byte_count=10,
            checksum_algorithm="sha256",
            checksum_value="c" * 64,
            verified_at=timezone.now(),
        )
        state.refresh_from_db()
        self.assertEqual(state.artifact_bytes, 10)
        self.assertEqual(state.artifact_checksum_algorithm, "sha256")
        self.assertEqual(state.artifact_checksum, "c" * 64)
        self.assertIsNotNone(state.artifact_verified_at)

        backup.delete()

        self.assertFalse(CoreBackupExecution.objects.filter(pk=state.pk).exists())
        self.assertFalse(CoreBackupArtifact.objects.filter(pk=artifact.pk).exists())

    def test_provider_unknown_outcome_stays_leased_and_reconcilable(self):
        _node, backup = self._backup()
        create = mock.Mock(side_effect=TimeoutError("provider response was lost"))

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            self.assertIsNone(
                helper_tasks.run_provider_create(backup, "create-task", create)
            )
        send_task.assert_called_once()

        state = backup.get_execution_state()
        self.assertTrue(state.lease_is_active())
        self.assertEqual(state.phase, "create")
        self.assertEqual(state.last_error_code, "PROVIDER_CREATE_OUTCOME_UNKNOWN")
        self.assertEqual(
            state.reconciliation_reason, "provider_create_outcome_unknown"
        )
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertIsNone(
            helper_tasks.run_provider_create(backup, "create-task", mock.Mock())
        )


@override_settings(BACKUP_RECOVERY_STALE_SECONDS=900, BACKUP_RECOVERY_BATCH_SIZE=100)
class DurableRecoverySweepTests(BaseTestCase):
    def _backup(self, task_id):
        node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id=task_id,
        )
        return node, backup

    def test_expired_lease_is_recovered_even_when_backup_row_is_recent(self):
        _node, backup = self._backup("expired-task")
        old = timezone.now() - timedelta(hours=1)
        claim = backup.claim_execution(
            lease_owner="dead-worker",
            phase="create",
            lease_seconds=60,
            now=old,
        )
        self.assertLess(claim.lease_expires_at, timezone.now())

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_called_once()
        self.assertEqual(send_task.call_args.args[0], "backup_digitalocean")
        self.assertEqual(send_task.call_args.kwargs["task_id"], "expired-task")
        state = backup.get_execution_state()
        self.assertEqual(state.phase, "recovery")
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )

    def test_live_lease_blocks_recovery_even_when_backup_row_is_old(self):
        _node, backup = self._backup("live-task")
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=2)
        )
        backup.claim_execution(
            lease_owner="healthy-worker", phase="create", lease_seconds=3600
        )

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_not_called()

    def test_two_sweeps_publish_only_one_recovery_delivery(self):
        _node, backup = self._backup("lost-task")
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=2)
        )

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_called_once()
        state = backup.get_execution_state()
        self.assertEqual(state.phase, "recovery")
        self.assertTrue(state.lease_is_active())

    def test_live_legacy_json_lease_blocks_new_execution_claim(self):
        _node, backup = self._backup("legacy-task")
        backup.metadata = {
            "_backup_control": {
                "create_task_id": "legacy-worker",
                "create_lease_until": timezone.now().timestamp() + 300,
            }
        }
        backup.save(update_fields=["metadata", "modified"])

        self.assertIsNone(
            helper_tasks._claim_provider_create(backup, "new-worker")
        )
        self.assertEqual(CoreBackupExecution.objects.count(), 0)


class ConcurrentBackupExecutionClaimTests(TransactionTestCase):
    """PostgreSQL row locking must choose exactly one concurrent claimant."""

    def setUp(self):
        super().setUp()
        # TransactionTestCase flushes migration-seeded reference rows. Recreate
        # only the provider this isolated concurrency fixture needs instead of
        # serializing the entire database, which conflicts when multiple
        # TransactionTestCase classes run in one suite.
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={"name": "DigitalOcean", "type": CoreIntegration.Type.CLOUD},
        )
        self.account, self.member, _user = factories.make_account()
        node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        self.backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="concurrent-claim",
            attempt_no=1,
        )

    def test_two_workers_cannot_claim_the_same_backup(self):
        barrier = Barrier(2)
        now = timezone.now()

        def claim(owner):
            close_old_connections()
            try:
                backup = CoreDigitalOceanBackup.objects.get(pk=self.backup.pk)
                barrier.wait(timeout=5)
                state = backup.claim_execution(
                    lease_owner=owner,
                    phase="create",
                    lease_seconds=120,
                    now=now,
                )
                return str(state.lease_token) if state else None
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            tokens = list(executor.map(claim, ("worker-a", "worker-b")))

        self.assertEqual(sum(token is not None for token in tokens), 1)
        self.assertEqual(CoreBackupExecution.objects.count(), 1)
        state = CoreBackupExecution.objects.get()
        self.assertEqual(state.claim_count, 1)
        self.assertIn(state.lease_owner, {"worker-a", "worker-b"})
