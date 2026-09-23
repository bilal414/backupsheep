"""Task-boundary tests for provider create retry and reconciliation policy."""

from unittest import mock

from django.utils import timezone

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.digitalocean import backup_digitalocean
from apps.console.backup.models import CoreBackupExecution
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreDigitalOcean, CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class ProviderCreateTaskPolicyTests(BaseTestCase):
    def _backup(self, task_id="provider-create-task"):
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
        )
        backup = node.digitalocean.backups.create(
            celery_task_id=task_id,
            uuid="provider-create-policy",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        backup.initialize_execution(
            celery_task_id=task_id,
            attempt_no=1,
            task_name="backup_digitalocean",
        )
        return node, backup

    def test_lost_response_retains_fence_and_schedules_same_task_after_expiry(self):
        node, backup = self._backup()

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                mock.Mock(side_effect=TimeoutError("secret provider response")),
            )

        self.assertIsNone(result)
        state = backup.get_execution_state(create=False)
        self.assertTrue(state.lease_is_active())
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertEqual(state.last_error_code, "PROVIDER_CREATE_OUTCOME_UNKNOWN")
        send_task.assert_called_once()
        self.assertEqual(send_task.call_args.args[0], node.backup_task_name())
        self.assertEqual(
            send_task.call_args.kwargs["task_id"],
            backup.celery_task_id,
        )
        self.assertGreaterEqual(send_task.call_args.kwargs["countdown"], 60)

    def test_real_provider_task_defers_ambiguous_create_without_celery_retry(self):
        node, _backup = self._backup(task_id="old-complete-row")
        _backup.status = UtilBackup.Status.COMPLETE
        _backup.save(update_fields=["status", "modified"])
        task_id = "digitalocean-lost-response-task"

        with mock.patch.object(CoreConnection, "validate", return_value=True), \
                mock.patch.object(CoreNode, "validate", return_value=True), \
                mock.patch.object(
                    CoreDigitalOcean,
                    "create_snapshot",
                    side_effect=TimeoutError("secret provider response"),
                ) as create, \
                mock.patch.object(helper_tasks.current_app, "send_task") as resume, \
                mock.patch.object(
                    helper_tasks.poll_cloud_backup,
                    "apply_async",
                ) as poll:
            result = backup_digitalocean.apply(
                kwargs={
                    "node_id": node.id,
                    "schedule_id": None,
                    "storage_ids": None,
                    "notes": None,
                },
                task_id=task_id,
                throw=True,
            )

        self.assertTrue(result.successful())
        create.assert_called_once()
        poll.assert_not_called()
        resume.assert_called_once()
        backup = node.digitalocean.backups.exclude(pk=_backup.pk).get()
        state = backup.get_execution_state(create=False)
        self.assertIn(backup.status, UtilBackup.ACTIVE_STATUSES)
        self.assertEqual(state.last_error_code, "PROVIDER_CREATE_OUTCOME_UNKNOWN")
        self.assertEqual(resume.call_args.kwargs["task_id"], task_id)

    def test_success_without_provider_reference_is_never_treated_as_success(self):
        _node, backup = self._backup()

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                mock.Mock(return_value=None),
            )

        self.assertIsNone(result)
        state = backup.get_execution_state(create=False)
        self.assertTrue(state.lease_is_active())
        self.assertEqual(state.last_error_code, "PROVIDER_CREATE_OUTCOME_UNKNOWN")
        send_task.assert_called_once()

    def test_definite_rate_limit_releases_fence_and_schedules_stable_retry(self):
        _node, backup = self._backup()
        error = RuntimeError("secret throttling body")
        error.error_code = "PROVIDER_RATE_LIMIT"
        error.retryable = True
        error.unknown_outcome = False

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                mock.Mock(side_effect=error),
            )

        self.assertIsNone(result)
        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertFalse(state.lease_is_active())
        self.assertEqual(state.last_error_code, "PROVIDER_RATE_LIMIT")
        self.assertGreater(state.next_retry_at, timezone.now())
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        send_task.assert_called_once()

    def test_manual_review_failure_stops_without_scheduling_another_create(self):
        node, backup = self._backup()

        def fail_closed(claimed):
            claimed.status = UtilBackup.Status.FAILED
            claimed.save(update_fields=["status", "modified"])
            state = claimed.get_execution_state(create=False)
            state.last_error_code = "PROVIDER_DUPLICATE_MATCH"
            state.reconciliation_state = (
                CoreBackupExecution.ReconciliationState.MANUAL_REVIEW
            )
            state.save(
                update_fields=[
                    "last_error_code",
                    "reconciliation_state",
                    "modified",
                ]
            )
            error = RuntimeError("secret duplicate response")
            error.error_code = "PROVIDER_DUPLICATE_MATCH"
            raise error

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task, \
                mock.patch.object(
                    type(node),
                    "notify_backup_fail",
                ) as notify:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                fail_closed,
            )

        self.assertIsNone(result)
        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertEqual(backup.status, UtilBackup.Status.FAILED)
        self.assertFalse(state.lease_is_active())
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )
        send_task.assert_not_called()
        notify.assert_called_once()

    def test_successful_reference_releases_create_lease(self):
        _node, backup = self._backup()

        def succeed(claimed):
            claimed.unique_id = "provider-snapshot-id"
            claimed.save(update_fields=["unique_id", "modified"])

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            result = helper_tasks.run_provider_create(
                backup,
                backup.celery_task_id,
                succeed,
            )

        self.assertIsNotNone(result)
        state = backup.get_execution_state(create=False)
        self.assertFalse(state.lease_is_active())
        send_task.assert_not_called()
