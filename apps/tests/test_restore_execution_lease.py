"""Crash/redelivery tests for generic restore execution fencing."""

import uuid
from datetime import timedelta
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from apps._tasks.integration import restore as restore_tasks
from apps._tasks.integration.restore_common import RestoreError
from apps._tasks.integration.restore_lease import (
    DurableRestoreLease,
    RestoreLeaseBusy,
)
from apps.console.backup.models import (
    CoreCloudRestore,
    CoreDigitalOceanBackup,
    CoreWebsiteBackup,
    CoreWebsiteRestore,
    RestoreExecutionLeaseLostError,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


@override_settings(
    RESTORE_WORKER_LEASE_SECONDS=90,
    RESTORE_WORKER_HEARTBEAT_SECONDS=30,
)
class RestoreExecutionLeaseTests(BaseTestCase):
    def _restore(self):
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"restore-lease-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=backup,
            name="restore-copy",
            params={"delete": False},
        )
        return node, backup, restore

    def _cloud_restore(self):
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            uuid=f"cloud-restore-{uuid.uuid4().hex}",
            unique_id="snapshot-source",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="cloud-restore-copy",
        )
        return node, backup, restore

    @staticmethod
    def _stop_without_release(lease):
        lease._stop.set()
        if lease._thread:
            lease._thread.join(timeout=2)

    def test_duplicate_restore_delivery_is_blocked_by_live_lease(self):
        _node, _backup, restore = self._restore()
        first = DurableRestoreLease(
            restore, phase="website_restore", task_id="delivery-a"
        )
        first.claim()
        self.addCleanup(first.release)

        duplicate = DurableRestoreLease(
            restore, phase="website_restore", task_id="delivery-b"
        )
        with self.assertRaises(RestoreLeaseBusy):
            duplicate.claim()

        restore.refresh_from_db()
        self.assertEqual(restore.attempt_count, 1)

    def test_expired_restore_takeover_fences_old_worker_save(self):
        _node, _backup, restore = self._restore()
        crashed = DurableRestoreLease(
            restore, phase="database_restore", task_id="crashed"
        )
        stale = crashed.claim()
        self._stop_without_release(crashed)
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )

        replacement = DurableRestoreLease(
            restore, phase="database_restore", task_id="replacement"
        )
        current = replacement.claim()
        self.addCleanup(replacement.release)

        stale.status = stale.Status.COMPLETE
        with self.assertRaises(RestoreExecutionLeaseLostError):
            stale.save(update_fields=["status", "modified"])

        current.execution_phase = "validated"
        current.save(update_fields=["execution_phase", "modified"])
        crashed.release()
        current.refresh_from_db()
        self.assertEqual(current.execution_phase, "validated")

    def test_task_never_persists_secret_bearing_restore_exception(self):
        node, backup, restore = self._restore()
        canary = "Bearer live-token password=database-secret"

        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=RestoreError(f"download failed: {canary}"),
        ):
            restore_tasks.restore_website_backup.apply(
                args=[node.id, backup.id, restore.id]
            )

        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.FAILED)
        self.assertNotIn(canary, restore.error)
        self.assertNotIn("live-token", restore.error)
        self.assertEqual(restore.last_error_code, "RESTORE_SOURCE_UNAVAILABLE")

    def test_structured_provider_rate_limit_is_retryable_and_preserves_backoff(self):
        error = RestoreError("provider-body=secret-canary")
        error.code = "PROVIDER_RATE_LIMITED"
        error.retryable = True
        error.retry_after = 37

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "RATE_LIMITED")
        self.assertTrue(retryable)
        self.assertEqual(restore_tasks._restore_retry_delay(error), 37)
        self.assertNotIn("secret-canary", message)

    def test_cloud_provider_rate_limit_and_outage_codes_are_retryable(self):
        for provider_code in ("PROVIDER_RATE_LIMIT", "PROVIDER_TRANSIENT_OUTAGE"):
            with self.subTest(provider_code=provider_code):
                error = RestoreError("secret provider response")
                error.code = provider_code
                code, message, retryable = restore_tasks._restore_error_outcome(error)
                self.assertTrue(retryable)
                self.assertNotIn("secret", message)
                self.assertIn(code, {"RATE_LIMITED", "RESTORE_TRANSIENT_FAILURE"})

    def test_provider_request_failure_is_terminal_without_explicit_retry_contract(self):
        error = RestoreError("provider rejected request with secret details")
        error.code = "PROVIDER_REQUEST_FAILED"

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "PROVIDER_FAILED")
        self.assertFalse(retryable)
        self.assertNotIn("secret", message)

    def test_cloud_failure_preserves_manual_review_phase(self):
        node, backup, restore = self._cloud_restore()
        restore.operation_phase = restore.OperationPhase.MANUAL_REVIEW
        restore.save(update_fields=["operation_phase", "modified"])

        with mock.patch.object(restore_tasks, "notify_restore_failed"):
            restore_tasks._mark_cloud_restore_failed(
                node,
                backup,
                restore,
                "PROVIDER_DUPLICATE_MATCH",
                "Multiple exact targets require manual review.",
            )

        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.FAILED)
        self.assertEqual(
            restore.operation_phase,
            restore.OperationPhase.MANUAL_REVIEW,
        )
        self.assertEqual(restore.execution_phase, "manual_review")

    @override_settings(RESTORE_CREATE_RECONCILIATION_MAX_ATTEMPTS=1)
    def test_unresolved_cloud_create_is_bounded_and_enters_manual_review(self):
        node, backup, restore = self._cloud_restore()

        with mock.patch.object(restore_tasks, "notify_restore_failed"), \
                mock.patch.object(
                    restore_tasks.restore_cloud_backup,
                    "apply_async",
                ) as enqueue:
            scheduled = restore_tasks._defer_cloud_restore_reconciliation(
                node,
                backup,
                restore,
            )

        self.assertFalse(scheduled)
        enqueue.assert_not_called()
        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.FAILED)
        self.assertEqual(
            restore.operation_phase,
            restore.OperationPhase.MANUAL_REVIEW,
        )
        self.assertEqual(
            restore.last_error_code,
            "PROVIDER_RECONCILIATION_EXHAUSTED",
        )

    def test_structured_provider_auth_failure_is_terminal_and_redacted(self):
        error = RestoreError("Authorization: Bearer secret-canary")
        error.code = "PROVIDER_AUTH_FAILED"
        error.retryable = False

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "PROVIDER_AUTH_FAILED")
        self.assertFalse(retryable)
        self.assertNotIn("secret-canary", message)

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_recovery_sweep_requeues_expired_restore_once(self):
        node, backup, restore = self._restore()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            lease_owner="crashed-worker",
            lease_token=uuid.uuid4(),
            lease_expires_at=timezone.now() - timedelta(seconds=1),
        )

        with mock.patch.object(restore_tasks.current_app, "send_task") as send_task:
            restore_tasks.resume_in_progress_restores.run()
            restore_tasks.resume_in_progress_restores.run()

        send_task.assert_called_once_with(
            "restore_website_backup",
            task_id=(
                f"recover-restore-{CoreWebsiteRestore.__name__}-{restore.pk}"
            ),
            args=[node.id, backup.id, restore.id],
        )
        restore.refresh_from_db()
        self.assertGreater(restore.next_retry_at, timezone.now())
        self.assertEqual(
            restore.execution_metadata["recovery_dispatch_count"], 1
        )

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_recovery_sweep_does_not_requeue_live_restore(self):
        _node, _backup, restore = self._restore()
        live = DurableRestoreLease(
            restore, phase="website_restore", task_id="healthy-worker"
        )
        live.claim()
        self.addCleanup(live.release)
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )

        with mock.patch.object(restore_tasks.current_app, "send_task") as send_task:
            restore_tasks.resume_in_progress_restores.run()

        send_task.assert_not_called()
