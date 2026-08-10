import time
from datetime import timedelta
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from apps._tasks.helper import tasks as helper_tasks
from apps.console.backup.models import CoreBackupExecution, CoreDigitalOceanBackup
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


@override_settings(
    BACKUP_RECOVERY_STALE_SECONDS=1,
    BACKUP_RECOVERY_BATCH_SIZE=100,
    BACKUP_POLL_INTERVAL=120,
)
class CloudPollRecoveryHandoffTests(BaseTestCase):
    def _backup(self):
        node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="original-create-task",
            unique_id="provider-snapshot-123",
        )
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )
        return node, backup

    @staticmethod
    def _recovery_id(backup):
        return f"recover-poll-{backup.__class__.__name__}-{backup.pk}"

    def test_recovery_reservation_is_consumed_by_exact_poll_delivery(self):
        node, backup = self._backup()
        recovery_id = self._recovery_id(backup)

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_called_once_with(
            "poll_cloud_backup",
            task_id=recovery_id,
            args=[node.id, backup.id, mock.ANY, 120, 86400],
        )
        backup.refresh_from_db()
        control = backup.metadata["_backup_control"]
        state = backup.get_execution_state(create=False)
        self.assertEqual(state.lease_owner, recovery_id)
        self.assertTrue(state.lease_is_active())
        self.assertEqual(control["poll_handoff_task_id"], recovery_id)
        self.assertEqual(
            control["poll_handoff_lease_token"], str(state.lease_token)
        )
        state.reconciliation_state = CoreBackupExecution.ReconciliationState.REQUIRED
        state.reconciliation_reason = "stale_worker_recovered"
        state.save(
            update_fields=[
                "reconciliation_state",
                "reconciliation_reason",
                "modified",
            ]
        )

        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            return_value=UtilBackup.Status.COMPLETE,
        ) as poll_status, mock.patch.object(
            CoreNode, "notify_backup_success"
        ) as notify:
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id, time.time() - 30, 120, 86400],
                task_id=recovery_id,
            )

        poll_status.assert_called_once()
        notify.assert_called_once()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        control = backup.metadata["_backup_control"]
        self.assertNotIn("poll_handoff_task_id", control)
        self.assertNotIn("poll_handoff_lease_token", control)
        state.refresh_from_db()
        self.assertFalse(state.lease_owner)
        self.assertIsNone(state.lease_token)
        self.assertIsNotNone(state.finished_at)
        self.assertEqual(state.phase, "complete")
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(state.reconciliation_reason, "backup_finalized")

    def test_two_sweeps_publish_only_one_reserved_poller(self):
        _node, backup = self._backup()

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_called_once()
        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertTrue(state.lease_is_active())
        self.assertEqual(
            backup.metadata["_backup_control"]["poll_handoff_task_id"],
            self._recovery_id(backup),
        )

    def test_duplicate_same_task_delivery_cannot_poll_concurrently(self):
        node, backup = self._backup()
        recovery_id = self._recovery_id(backup)
        with mock.patch.object(helper_tasks.current_app, "send_task"):
            helper_tasks.resume_in_progress_backups.apply()

        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            return_value=UtilBackup.Status.IN_PROGRESS,
        ) as poll_status, mock.patch.object(
            helper_tasks.poll_cloud_backup, "apply_async"
        ) as schedule_next:
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id, time.time(), 120, 86400],
                task_id=recovery_id,
            )
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id, time.time(), 120, 86400],
                task_id=recovery_id,
            )

        poll_status.assert_called_once()
        schedule_next.assert_called_once()
        backup.refresh_from_db()
        self.assertNotIn(
            "poll_handoff_task_id", backup.metadata["_backup_control"]
        )
        self.assertTrue(backup.get_execution_state().lease_is_active())

    def test_lost_recovery_publish_is_retried_after_fenced_lease_expiry(self):
        _node, backup = self._backup()
        recovery_id = self._recovery_id(backup)

        with mock.patch.object(
            helper_tasks.current_app,
            "send_task",
            side_effect=RuntimeError(
                "amqp://broker-user:SUPER-SECRET@10.0.0.8/vhost"
            ),
        ) as failed_publish, mock.patch.object(
            helper_tasks, "capture_exception"
        ) as capture:
            helper_tasks.resume_in_progress_backups.apply()

        failed_publish.assert_called_once()
        capture.assert_called_once()
        backup.refresh_from_db()
        old_state = backup.get_execution_state(create=False)
        old_token = old_state.lease_token
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )
        old_state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        old_state.save(update_fields=["lease_expires_at", "modified"])
        metadata = dict(backup.metadata or {})
        control = dict(metadata.get("_backup_control") or {})
        control["poll_lease_until"] = time.time() - 1
        metadata["_backup_control"] = control
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            metadata=metadata,
            modified=timezone.now() - timedelta(hours=1),
        )

        with mock.patch.object(helper_tasks.current_app, "send_task") as retry:
            helper_tasks.resume_in_progress_backups.apply()

        retry.assert_called_once()
        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertEqual(state.lease_owner, recovery_id)
        self.assertNotEqual(state.lease_token, old_token)
        self.assertTrue(state.lease_is_active())
        self.assertEqual(
            backup.metadata["_backup_control"]["poll_handoff_lease_token"],
            str(state.lease_token),
        )
        self.assertEqual(
            state.reconciliation_reason, "stale_execution_lease"
        )

    def test_terminal_redelivery_repairs_split_commit_exactly_once(self):
        node, backup = self._backup()
        state = backup.claim_execution(
            lease_owner="worker-that-crashed-after-provider-completion",
            phase="poll",
            lease_seconds=300,
        )
        self.assertIsNotNone(state)
        original_finished_at = timezone.now() - timedelta(seconds=5)
        state.finished_at = original_finished_at
        state.reconciliation_state = CoreBackupExecution.ReconciliationState.REQUIRED
        state.reconciliation_reason = "stale_execution_lease"
        state.save(
            update_fields=[
                "finished_at",
                "reconciliation_state",
                "reconciliation_reason",
                "modified",
            ]
        )
        metadata = dict(backup.metadata or {})
        metadata["_backup_control"] = {
            "poll_task_id": state.lease_owner,
            "poll_lease_token": str(state.lease_token),
            "poll_lease_until": state.lease_expires_at.timestamp(),
        }
        backup.metadata = metadata
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["metadata", "status", "modified"])

        with mock.patch.object(
            CoreDigitalOceanBackup, "poll_status"
        ) as poll_status, mock.patch.object(
            CoreNode, "notify_backup_success"
        ) as notify:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        poll_status.assert_not_called()
        notify.assert_called_once()
        backup.refresh_from_db()
        state.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(state.phase, "complete")
        self.assertEqual(state.finished_at, original_finished_at)
        self.assertFalse(state.lease_owner)
        self.assertIsNone(state.lease_token)
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(state.reconciliation_reason, "backup_finalized")
        control = backup.metadata["_backup_control"]
        self.assertTrue(control["success_notified"])
        self.assertNotIn("poll_task_id", control)
        self.assertNotIn("poll_lease_token", control)
