"""Crash/redelivery tests for generic restore execution fencing."""

import hashlib
import uuid
from datetime import datetime, timedelta
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from apps._tasks.integration import restore as restore_tasks
from apps._tasks.integration.restore_common import RestoreError
from apps._tasks.integration.restore_lease import (
    DurableRestoreLease,
    RestoreLeaseBusy,
)
from apps.api.v1.backup import serializers as backup_serializers
from apps.api.v1.node.serializers import CoreCloudRestoreSerializer
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

    def test_materialized_duplicate_delivery_is_acknowledged_without_retry_chain(self):
        node, backup, restore = self._restore()
        first = DurableRestoreLease(
            restore, phase="website_restore", task_id="delivery-a"
        )
        first.claim()
        self.addCleanup(first.release)
        duplicate_task = mock.Mock()
        duplicate_task.request.id = "delivery-b"
        duplicate_task.request.hostname = "files@test"
        engine = mock.Mock()

        result = restore_tasks._run_materialized_restore(
            duplicate_task,
            node=node,
            backup=backup,
            restore=restore,
            engine=engine,
            phase="website_restore",
        )

        self.assertIsNone(result)
        duplicate_task.retry.assert_not_called()
        engine.assert_not_called()

    def test_long_restore_completion_does_not_rewind_renewed_lease(self):
        node, backup, restore = self._restore()
        stale_heartbeat = timezone.now() - timedelta(hours=1)
        renewed_heartbeat = timezone.now()

        def long_running_engine(_backup, leased_restore):
            # Model the task-local instance left behind while the heartbeat thread
            # renews the authoritative row during a long transfer.
            leased_restore.heartbeat_at = stale_heartbeat
            leased_restore.lease_expires_at = stale_heartbeat
            CoreWebsiteRestore.objects.filter(pk=leased_restore.pk).update(
                heartbeat_at=renewed_heartbeat,
                lease_expires_at=renewed_heartbeat + timedelta(seconds=90),
            )

        with mock.patch(
            "apps._tasks.integration.restore_website.restore_website",
            side_effect=long_running_engine,
        ), mock.patch.object(
            restore_tasks, "notify_restore_started"
        ), mock.patch.object(
            restore_tasks, "notify_restore_completed"
        ) as completed:
            result = restore_tasks.restore_website_backup.apply(
                args=[node.id, backup.id, restore.id]
            )

        self.assertTrue(result.successful(), result.result)
        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.COMPLETE)
        self.assertEqual(restore.execution_phase, "complete")
        self.assertEqual(restore.heartbeat_at, renewed_heartbeat)
        self.assertIn(
            "completed_notification_enqueued_at",
            restore.execution_metadata,
        )
        completed.assert_called_once_with(node, backup, mock.ANY)

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

    def test_expired_restore_takeover_records_previous_work_suffix(self):
        _node, _backup, restore = self._restore()
        crashed = DurableRestoreLease(
            restore, phase="database_restore", task_id="crashed"
        )
        stale = crashed.claim()
        previous_work_suffix = hashlib.sha256(
            f"{stale.lease_owner}|{stale.lease_token}".encode("utf-8")
        ).hexdigest()[:16]
        self._stop_without_release(crashed)
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )

        replacement = DurableRestoreLease(
            restore, phase="database_restore", task_id="replacement"
        )
        current = replacement.claim()
        self.addCleanup(replacement.release)

        takeover = current.execution_metadata["stale_lease_takeovers"][-1]
        self.assertEqual(takeover["previous_work_suffix"], previous_work_suffix)

    def test_cloud_restore_root_task_id_survives_poll_recovery_takeover(self):
        _node, _backup, restore = self._cloud_restore()
        restore.celery_task_id = "root-restore-request"
        restore.save(update_fields=["celery_task_id", "modified"])

        first = DurableRestoreLease(
            restore, phase="provider_create", task_id="root-restore-request"
        )
        initial = first.claim()
        self._stop_without_release(first)
        CoreCloudRestore.objects.filter(pk=restore.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )

        recovery = DurableRestoreLease(
            restore, phase="provider_poll", task_id="poll-recovery-delivery"
        )
        current = recovery.claim()
        self.addCleanup(recovery.release)

        self.assertEqual(initial.celery_task_id, "root-restore-request")
        self.assertEqual(current.celery_task_id, "root-restore-request")
        self.assertEqual(current.attempt_count, initial.attempt_count + 1)
        self.assertIn("poll-recovery-delivery", current.lease_owner)

    def test_successful_cloud_poll_clears_stale_public_error_rollups(self):
        node, _backup, restore = self._cloud_restore()
        restore.resource_id = "provider-target"
        restore.celery_task_id = "root-restore-request"
        restore.params = {
            "witness": "preserve-me",
            "_bs_last_error_code": "PROVIDER_MALFORMED_RESPONSE",
            "_bs_last_error_category": "manual_review",
        }
        restore.error = "stale safe failure"
        restore.last_error_code = "PROVIDER_MALFORMED_RESPONSE"
        restore.status = restore.Status.IN_PROGRESS
        restore.operation_phase = restore.OperationPhase.POLLING
        restore.save()

        with mock.patch.object(
            CoreCloudRestore,
            "poll_status",
            return_value=CoreCloudRestore.Status.COMPLETE,
        ), mock.patch.object(restore_tasks, "notify_restore_completed"):
            restore_tasks.poll_cloud_restore.apply(args=[node.id, restore.id])

        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.COMPLETE)
        self.assertEqual(restore.operation_phase, restore.OperationPhase.COMPLETE)
        self.assertEqual(restore.params, {"witness": "preserve-me"})
        self.assertEqual(restore.last_error_code, "")
        self.assertIsNone(restore.error)
        data = CoreCloudRestoreSerializer(restore).data
        self.assertIsNone(data["error"])
        self.assertIsNone(data["execution_status"]["last_error_code"])

    def test_healthy_in_progress_poll_clears_stale_public_error_rollups(self):
        node, _backup, restore = self._cloud_restore()
        restore.resource_id = "provider-target"
        restore.params = {
            "witness": "preserve-me",
            "_bs_last_error_code": "PROVIDER_TRANSIENT_OUTAGE",
            "_bs_last_error_category": "provider",
        }
        restore.status = restore.Status.IN_PROGRESS
        restore.operation_phase = restore.OperationPhase.POLLING
        restore.error = "The provider is temporarily unavailable."
        restore.last_error_code = "RESTORE_TRANSIENT_FAILURE"
        restore.save()

        transient = RestoreError("provider outage")
        transient.code = "PROVIDER_TRANSIENT_OUTAGE"
        transient.retryable = True
        with mock.patch.object(
            CoreCloudRestore,
            "poll_status",
            side_effect=[transient, CoreCloudRestore.Status.IN_PROGRESS],
        ), mock.patch.object(restore_tasks.poll_cloud_restore, "apply_async"):
            restore_tasks.poll_cloud_restore.apply(args=[node.id, restore.id])
            restore.refresh_from_db()
            self.assertEqual(
                restore.last_error_code,
                "RESTORE_TRANSIENT_FAILURE",
            )
            self.assertIsNotNone(restore.error)
            CoreCloudRestore.objects.filter(pk=restore.pk).update(
                next_retry_at=timezone.now() - timedelta(seconds=1)
            )

            restore_tasks.poll_cloud_restore.apply(args=[node.id, restore.id])

        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.IN_PROGRESS)
        self.assertEqual(restore.operation_phase, restore.OperationPhase.POLLING)
        self.assertEqual(restore.params, {"witness": "preserve-me"})
        self.assertEqual(restore.last_error_code, "")
        self.assertIsNone(restore.error)
        data = CoreCloudRestoreSerializer(restore).data
        self.assertIsNone(data["error"])
        self.assertIsNone(data["execution_status"]["last_error_code"])

    def test_in_progress_poll_preserves_error_written_by_current_reconciliation(self):
        node, _backup, restore = self._cloud_restore()
        restore.resource_id = "provider-target"
        restore.params = {
            "witness": "preserve-me",
            "_bs_last_error_code": "PROVIDER_TRANSIENT_OUTAGE",
            "_bs_last_error_category": "retryable",
        }
        restore.status = restore.Status.IN_PROGRESS
        restore.operation_phase = restore.OperationPhase.POLLING
        restore.error = "stale safe failure"
        restore.last_error_code = "PROVIDER_TRANSIENT_OUTAGE"
        restore.save()

        def current_reconciliation(row):
            params = dict(row.params or {})
            params["_bs_last_error_code"] = "PROVIDER_NOT_FOUND"
            params["_bs_last_error_category"] = "reconciliation_wait"
            row.params = params
            row.last_error_code = "PROVIDER_NOT_FOUND"
            row.error = "The provider target is not visible yet."
            row.operation_phase = row.OperationPhase.RECONCILING
            row.next_retry_at = timezone.now() + timedelta(seconds=60)
            row.save()
            return row.Status.IN_PROGRESS

        with mock.patch.object(
            CoreCloudRestore,
            "poll_status",
            autospec=True,
            side_effect=current_reconciliation,
        ), mock.patch.object(
            restore_tasks.poll_cloud_restore, "apply_async"
        ) as requeue:
            restore_tasks.poll_cloud_restore.apply(args=[node.id, restore.id])

        restore.refresh_from_db()
        self.assertEqual(restore.status, restore.Status.IN_PROGRESS)
        self.assertEqual(
            restore.operation_phase,
            restore.OperationPhase.RECONCILING,
        )
        self.assertEqual(restore.execution_phase, "provider_reconciling")
        self.assertEqual(restore.last_error_code, "PROVIDER_NOT_FOUND")
        self.assertEqual(
            restore.params["_bs_last_error_category"],
            "reconciliation_wait",
        )
        self.assertEqual(restore.params["witness"], "preserve-me")
        self.assertGreater(requeue.call_args.kwargs["countdown"], 0)
        self.assertLessEqual(requeue.call_args.kwargs["countdown"], 60)

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

    def test_archive_rehydration_has_a_safe_retryable_outcome(self):
        error = RestoreError("provider-body=secret-canary")
        error.code = "RESTORE_ARCHIVE_NOT_READY"
        error.retryable = True
        error.retry_after = 120

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "RESTORE_ARCHIVE_NOT_READY")
        self.assertTrue(retryable)
        self.assertIn("restoring this archive", message)
        self.assertNotIn("secret-canary", message)
        self.assertEqual(restore_tasks._restore_retry_delay(error), 120)
        self.assertEqual(backup_serializers._safe_error_code(code), code)
        self.assertIn(
            "restoring this archive",
            backup_serializers._safe_error_message(code),
        )

    def test_target_name_collision_is_terminal_and_public_safe(self):
        error = RestoreError("destination listing contained secret-canary")
        error.code = "RESTORE_TARGET_NAME_COLLISION"
        error.retryable = False

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "RESTORE_TARGET_NAME_COLLISION")
        self.assertFalse(retryable)
        self.assertIn("cannot preserve distinct", message)
        self.assertIn("No website data was uploaded or published", message)
        self.assertNotIn("secret-canary", message)
        self.assertEqual(backup_serializers._safe_error_code(code), code)
        self.assertIn(
            "cannot preserve distinct",
            backup_serializers._safe_error_message(code),
        )

    @override_settings(RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120)
    def test_archive_rehydration_reserves_one_retry_with_extended_budget(self):
        class RetrySignal(Exception):
            pass

        node, backup, restore = self._restore()
        task = mock.Mock()
        task.request.id = "archive-delivery"
        task.request.hostname = "files@test"
        task.retry.side_effect = RetrySignal()
        error = RestoreError("provider-body=secret-canary")
        error.code = "RESTORE_ARCHIVE_NOT_READY"
        error.retryable = True
        error.retry_after = 120

        with mock.patch.object(
            restore_tasks, "notify_restore_started"
        ), mock.patch.object(restore_tasks, "capture_exception"):
            with self.assertRaises(RetrySignal):
                restore_tasks._run_materialized_restore(
                    task,
                    node=node,
                    backup=backup,
                    restore=restore,
                    engine=mock.Mock(side_effect=error),
                    phase="website_restore",
                )

        task.retry.assert_called_once_with(countdown=120, max_retries=2880)
        restore.refresh_from_db()
        self.assertEqual(
            restore.last_error_code,
            "RESTORE_ARCHIVE_NOT_READY",
        )
        self.assertEqual(restore.execution_phase, "retrying")
        self.assertGreater(restore.next_retry_at, timezone.now())
        reservation = restore.execution_metadata[
            restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL
        ]
        self.assertGreater(
            datetime.fromisoformat(reservation),
            restore.next_retry_at,
        )
        self.assertFalse(restore.lease_owner)

    def test_provider_request_failure_is_terminal_without_explicit_retry_contract(self):
        error = RestoreError("provider rejected request with secret details")
        error.code = "PROVIDER_REQUEST_FAILED"

        code, message, retryable = restore_tasks._restore_error_outcome(error)

        self.assertEqual(code, "PROVIDER_FAILED")
        self.assertFalse(retryable)
        self.assertNotIn("secret", message)

    def test_ambiguous_restore_state_requires_reconciliation(self):
        for detail in (
            "PostgreSQL target ownership is ambiguous; no changes were retried.",
            "restore checkpoint and PostgreSQL marker disagree.",
            "fork target name collision: existing database is not BackupSheep-owned.",
        ):
            with self.subTest(detail=detail):
                code, message, retryable = restore_tasks._restore_error_outcome(
                    RestoreError(detail)
                )

                self.assertEqual(code, "RESTORE_RECONCILIATION_REQUIRED")
                self.assertFalse(retryable)
                self.assertIn("automatic destination writes were stopped", message)
                self.assertEqual(backup_serializers._safe_error_code(code), code)
                self.assertNotIn(detail, message)

    def test_remote_cleanup_outcomes_are_safe_and_classified(self):
        retryable = RestoreError("remote-body=secret-canary")
        retryable.code = "RESTORE_TRANSIENT_FAILURE"
        retryable.retryable = True
        code, message, should_retry = restore_tasks._restore_error_outcome(retryable)
        self.assertEqual(code, "RESTORE_TRANSIENT_FAILURE")
        self.assertTrue(should_retry)
        self.assertNotIn("secret-canary", message)

        manual = RestoreError("remote-body=secret-canary")
        manual.code = "RESTORE_RECONCILIATION_REQUIRED"
        code, message, should_retry = restore_tasks._restore_error_outcome(manual)
        self.assertEqual(code, "RESTORE_RECONCILIATION_REQUIRED")
        self.assertFalse(should_retry)
        self.assertNotIn("secret-canary", message)

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
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_recovery_sweep_respects_orderly_retry_reservation(self):
        _node, _backup, restore = self._restore()
        now = timezone.now()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            next_retry_at=now - timedelta(seconds=1),
            execution_metadata={
                restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL: (
                    now + timedelta(seconds=120)
                ).isoformat()
            },
        )

        with mock.patch.object(restore_tasks.current_app, "send_task") as send_task:
            restore_tasks.resume_in_progress_restores.run()

        send_task.assert_not_called()
        restore.refresh_from_db()
        self.assertIn(
            restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL,
            restore.execution_metadata,
        )

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_recovery_sweep_reclaims_expired_orderly_retry_reservation(self):
        node, backup, restore = self._restore()
        now = timezone.now()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            next_retry_at=now - timedelta(seconds=1),
            execution_metadata={
                restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL: (
                    now - timedelta(seconds=1)
                ).isoformat()
            },
        )

        with mock.patch.object(restore_tasks.current_app, "send_task") as send_task:
            restore_tasks.resume_in_progress_restores.run()

        send_task.assert_called_once_with(
            "restore_website_backup",
            task_id=(
                f"recover-restore-{CoreWebsiteRestore.__name__}-{restore.pk}"
            ),
            args=[node.id, backup.id, restore.id],
        )
        restore.refresh_from_db()
        self.assertNotIn(
            restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL,
            restore.execution_metadata,
        )
        self.assertEqual(
            restore.execution_metadata["recovery_dispatch_count"],
            1,
        )

    def test_due_retry_claim_consumes_orderly_retry_reservation(self):
        _node, _backup, restore = self._restore()
        now = timezone.now()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            next_retry_at=now - timedelta(seconds=1),
            execution_metadata={
                restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL: (
                    now + timedelta(seconds=120)
                ).isoformat()
            },
        )
        restore.refresh_from_db()
        retry = DurableRestoreLease(
            restore,
            phase="website_restore",
            task_id="archive-delivery",
        )
        claimed = retry.claim()
        self.addCleanup(retry.release)

        self.assertNotIn(
            restore_tasks.SCHEDULED_RETRY_RESERVED_UNTIL,
            claimed.execution_metadata,
        )
        self.assertIsNone(claimed.next_retry_at)

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_recovery_delivery_consumes_exact_dispatch_reservation(self):
        node, backup, restore = self._restore()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            lease_owner="crashed-worker",
            lease_token=uuid.uuid4(),
            lease_expires_at=timezone.now() - timedelta(seconds=1),
        )

        with mock.patch.object(restore_tasks.current_app, "send_task"):
            restore_tasks.resume_in_progress_restores.run()

        restore.refresh_from_db()
        reservation = restore.next_retry_at
        recovery_task_id = (
            f"recover-restore-{CoreWebsiteRestore.__name__}-{restore.pk}"
        )
        recovery = DurableRestoreLease(
            restore,
            phase="website_restore",
            task_id=recovery_task_id,
        )
        claimed = recovery.claim()
        self.addCleanup(recovery.release)

        self.assertEqual(claimed.attempt_count, 1)
        self.assertIsNone(claimed.next_retry_at)
        self.assertEqual(
            claimed.execution_metadata["recovery_claimed_task_id"],
            recovery_task_id,
        )
        self.assertIn("recovery_claimed_at", claimed.execution_metadata)
        self.assertNotIn(
            "recovery_dispatch_reserved_until", claimed.execution_metadata
        )
        self.assertGreater(reservation, timezone.now())

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_ordinary_delivery_cannot_consume_recovery_reservation(self):
        _node, _backup, restore = self._restore()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            lease_owner="crashed-worker",
            lease_token=uuid.uuid4(),
            lease_expires_at=timezone.now() - timedelta(seconds=1),
        )

        with mock.patch.object(restore_tasks.current_app, "send_task"):
            restore_tasks.resume_in_progress_restores.run()

        restore.refresh_from_db()
        ordinary = DurableRestoreLease(
            restore,
            phase="website_restore",
            task_id="ordinary-redelivery",
        )
        with self.assertRaises(RestoreLeaseBusy):
            ordinary.claim()

    @override_settings(
        RESTORE_RECOVERY_STALE_SECONDS=1,
        RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS=120,
        RESTORE_RECOVERY_BATCH_SIZE=10,
    )
    def test_consumed_recovery_reservation_does_not_bypass_later_backoff(self):
        _node, _backup, restore = self._restore()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            status=restore.Status.IN_PROGRESS,
            lease_owner="crashed-worker",
            lease_token=uuid.uuid4(),
            lease_expires_at=timezone.now() - timedelta(seconds=1),
        )

        with mock.patch.object(restore_tasks.current_app, "send_task"):
            restore_tasks.resume_in_progress_restores.run()

        restore.refresh_from_db()
        recovery_task_id = (
            f"recover-restore-{CoreWebsiteRestore.__name__}-{restore.pk}"
        )
        recovery = DurableRestoreLease(
            restore,
            phase="website_restore",
            task_id=recovery_task_id,
        )
        recovery.claim()
        recovery.release()
        CoreWebsiteRestore.objects.filter(pk=restore.pk).update(
            next_retry_at=timezone.now() + timedelta(seconds=60)
        )
        restore.refresh_from_db()

        delayed_recovery = DurableRestoreLease(
            restore,
            phase="website_restore",
            task_id=recovery_task_id,
        )
        with self.assertRaises(RestoreLeaseBusy):
            delayed_recovery.claim()

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
