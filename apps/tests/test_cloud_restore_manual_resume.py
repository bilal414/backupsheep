"""Contract tests for safe, read-only native cloud restore resumption."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest import mock

from django.db import close_old_connections
from django.template.loader import get_template
from django.test import SimpleTestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.integration import restore as restore_tasks
from apps.api.v1.node.views import CoreNodeView
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreIntegration
from apps.console.log.models import CoreLog
from apps.tests import factories


class ManualCloudRestoreResumeApiTests(TransactionTestCase):
    def setUp(self):
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={
                "name": "DigitalOcean",
                "type": CoreIntegration.Type.CLOUD,
            },
        )
        self.account, self.member, self.user = factories.make_account()
        self.node = factories.make_cloud_node(self.account, self.member)

    def _restore(self, node=None, **overrides):
        values = {
            "node": node or self.node,
            "backup_id": 91,
            "name": "existing-provider-target",
            "params": {
                "region": "us-east-2",
                "witness": "preserve-me",
                "_bs_last_error_code": "PROVIDER_OWNERSHIP_MISMATCH",
                "_bs_last_error_category": "manual_review",
            },
            "resource_id": "provider-target-91",
            "provider_job_id": "provider-job-91",
            "restore_marker": "restore-marker-91",
            "request_fingerprint": "a" * 64,
            "status": CoreCloudRestore.Status.FAILED,
            "operation_phase": CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
            "execution_phase": "manual_review",
            "error": "safe old error",
            "last_error_code": "PROVIDER_OWNERSHIP_MISMATCH",
            "next_retry_at": timezone.now(),
            "celery_task_id": "root-restore-request-91",
            "execution_metadata": {
                "provider_witness": {"account_id": "123456789012"},
                "opaque_control": "preserve-me",
            },
        }
        values.update(overrides)
        return CoreCloudRestore.objects.create(**values)

    def _post(self, node, restore_id, user=None):
        request = APIRequestFactory().post(
            f"/api/v1/nodes/{node.id}/resume_restore/",
            {"restore_id": restore_id},
            format="json",
        )
        force_authenticate(request, user=user or self.user)
        view = CoreNodeView.as_view({"post": "resume_restore"})
        return view(request, pk=node.id)

    def test_resume_preserves_provider_witness_and_dispatches_only_poll(self):
        restore = self._restore()
        original = {
            "correlation_id": restore.correlation_id,
            "celery_task_id": restore.celery_task_id,
            "resource_id": restore.resource_id,
            "provider_job_id": restore.provider_job_id,
            "restore_marker": restore.restore_marker,
            "request_fingerprint": restore.request_fingerprint,
            "params": {"region": "us-east-2", "witness": "preserve-me"},
        }

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll, mock.patch.object(
            self.node.digitalocean, "restore_snapshot"
        ) as provider_create:
            response = self._post(self.node, restore.id)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["manual_resume_enqueued"], True)
        self.assertEqual(response.data["resume_sequence"], 1)
        provider_create.assert_not_called()
        poll.assert_called_once_with(
            task_id=f"cloud-restore-resume-{restore.id}-1",
            args=[self.node.id, restore.id],
        )

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.POLLING
        )
        self.assertEqual(restore.execution_phase, "provider_polling")
        self.assertIsNone(restore.error)
        self.assertEqual(restore.last_error_code, "")
        self.assertIsNone(restore.next_retry_at)
        self.assertEqual(restore.correlation_id, original["correlation_id"])
        self.assertEqual(restore.celery_task_id, original["celery_task_id"])
        self.assertEqual(restore.resource_id, original["resource_id"])
        self.assertEqual(restore.provider_job_id, original["provider_job_id"])
        self.assertEqual(restore.restore_marker, original["restore_marker"])
        self.assertEqual(
            restore.request_fingerprint, original["request_fingerprint"]
        )
        self.assertEqual(restore.params, original["params"])
        self.assertIsNone(response.data["error"])
        self.assertIsNone(response.data["execution_status"]["last_error_code"])
        self.assertEqual(restore.execution_metadata["opaque_control"], "preserve-me")
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(
            restore.execution_metadata["manual_resume_history"][0]["sequence"], 1
        )
        self.assertEqual(
            restore.execution_metadata["root_celery_task_id"],
            original["celery_task_id"],
        )

        log = CoreLog.objects.get(
            account=self.account,
            type=CoreLog.Type.RESTORE,
            data__action="restore_resume_verification",
        )
        self.assertEqual(log.data["restore_id"], restore.id)
        self.assertNotIn("provider-target-91", log.data)

    def test_active_repeat_is_idempotent_and_does_not_enqueue_again(self):
        restore = self._restore()
        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll:
            first = self._post(self.node, restore.id)
            replay = self._post(self.node, restore.id)

        self.assertEqual(first.status_code, 202)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["idempotent_replay"], True)
        self.assertEqual(replay.data["code"], "restore_resume_already_active")
        poll.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(len(restore.execution_metadata["manual_resume_history"]), 1)
        self.assertEqual(
            CoreLog.objects.filter(
                account=self.account,
                type=CoreLog.Type.RESTORE,
                data__action="restore_resume_verification",
            ).count(),
            1,
        )

    def test_broker_ack_loss_returns_recovery_state_and_repeat_is_harmless(self):
        restore = self._restore()
        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async",
            side_effect=RuntimeError("broker secret must not escape"),
        ) as poll:
            response = self._post(self.node, restore.id)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["code"], "restore_resume_saved_for_recovery")
        self.assertNotIn("broker secret", str(response.data))
        poll.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_phase, "provider_polling")

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as replay_poll:
            replay = self._post(self.node, restore.id)
        self.assertEqual(replay.status_code, 200)
        replay_poll.assert_not_called()

    def test_broker_ack_loss_serializes_rapid_complete_row_and_resume_sequence(self):
        restore = self._restore()

        def publish_then_complete(*_args, **kwargs):
            restore_tasks.poll_cloud_restore.apply(args=kwargs["args"])
            raise RuntimeError("broker acknowledgement was lost")

        with mock.patch.object(
            CoreCloudRestore,
            "poll_status",
            return_value=CoreCloudRestore.Status.COMPLETE,
        ), mock.patch.object(restore_tasks, "notify_restore_completed"), mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async",
            side_effect=publish_then_complete,
        ):
            response = self._post(self.node, restore.id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], restore.id)
        self.assertEqual(response.data["status"], CoreCloudRestore.Status.COMPLETE)
        self.assertEqual(response.data["execution_status"]["status"], "complete")
        self.assertEqual(response.data["resume_sequence"], 1)
        self.assertEqual(response.data["code"], "restore_resume_reconciled")
        self.assertFalse(response.data["manual_resume_enqueued"])

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.COMPLETE)
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)

    def test_broker_ack_loss_serializes_rapid_failed_row_and_resume_sequence(self):
        restore = self._restore()

        def publish_then_fail(*_args, **kwargs):
            restore_tasks.poll_cloud_restore.apply(args=kwargs["args"])
            raise RuntimeError("broker acknowledgement was lost")

        with mock.patch.object(
            CoreCloudRestore,
            "poll_status",
            return_value=CoreCloudRestore.Status.FAILED,
        ), mock.patch.object(restore_tasks, "notify_restore_failed"), mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async",
            side_effect=publish_then_fail,
        ):
            response = self._post(self.node, restore.id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], restore.id)
        self.assertEqual(response.data["status"], CoreCloudRestore.Status.FAILED)
        self.assertEqual(response.data["execution_status"]["status"], "failed")
        self.assertEqual(response.data["resume_sequence"], 1)
        self.assertEqual(response.data["code"], "restore_resume_reconciled")
        self.assertFalse(response.data["manual_resume_enqueued"])

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)

    def test_cross_account_restore_id_is_not_visible_or_resumable(self):
        other_account, other_member, _other_user = factories.make_account()
        foreign_node = factories.make_cloud_node(other_account, other_member)
        foreign_restore = self._restore(node=foreign_node)

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll:
            response = self._post(self.node, foreign_restore.id)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data["code"], "restore_not_found")
        poll.assert_not_called()
        foreign_restore.refresh_from_db()
        self.assertEqual(foreign_restore.status, CoreCloudRestore.Status.FAILED)

    def test_complete_and_missing_pointer_fail_closed_with_stable_codes(self):
        complete = self._restore(status=CoreCloudRestore.Status.COMPLETE)
        missing = self._restore(
            resource_id="",
            provider_job_id="",
            name="missing-pointer",
        )

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll:
            complete_response = self._post(self.node, complete.id)
            missing_response = self._post(self.node, missing.id)

        self.assertEqual(complete_response.status_code, 409)
        self.assertEqual(complete_response.data["code"], "restore_already_complete")
        self.assertEqual(missing_response.status_code, 409)
        self.assertEqual(
            missing_response.data["code"], "restore_provider_pointer_missing"
        )
        poll.assert_not_called()
        missing.refresh_from_db()
        self.assertEqual(missing.status, CoreCloudRestore.Status.FAILED)

    def test_two_concurrent_clicks_have_one_transition_and_one_publish(self):
        restore = self._restore()
        barrier = Barrier(2)

        def submit(_value):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return self._post(self.node, restore.id)
            finally:
                close_old_connections()

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll:
            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(submit, (1, 2)))

        self.assertEqual(sorted(response.status_code for response in responses), [200, 202])
        poll.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(len(restore.execution_metadata["manual_resume_history"]), 1)


class ManualCloudRestoreResumeTemplateTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.template_path = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "detail.html"
        )
        cls.source = cls.template_path.read_text(encoding="utf-8")

    def test_template_compiles_and_exposes_safe_resume_control(self):
        get_template("console/node/detail.html")
        for marker in (
            "Resume verification",
            "nativeRestoreCanResume",
            "resumeNativeCloudRestore",
            "/resume_restore/",
            "existing provider target",
            "No new resource was created.",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_resume_ui_posts_only_restore_id_and_accepts_recovery_statuses(self):
        resume_block = self.source.split("async resumeNativeCloudRestore(item)", 1)[1].split(
            "clearRestorePoll()", 1
        )[0]
        self.assertIn("body: JSON.stringify({restore_id: restoreId})", resume_block)
        self.assertIn("response.status !== 200 && response.status !== 202", resume_block)
        self.assertIn("await this.getNativeCloudRestores(false)", resume_block)
        self.assertIn("this.startNativeRestorePolling()", resume_block)
        self.assertNotIn("/restore_backup/", resume_block)
        self.assertNotIn("restore_snapshot", resume_block)

    def test_another_copy_is_hidden_when_an_exact_target_can_be_resumed(self):
        self.assertIn(
            "nativeRestoreStatusIsTerminal(nativeRestoreStatus) && !nativeRestoreCanResume(nativeRestoreStatus)",
            self.source,
        )
        self.assertIn(
            "status === '4' || status === 'failed'",
            self.source,
        )
        self.assertIn("String(item.resource_id || item.provider_job_id || '').trim()", self.source)

    def test_duplicate_name_polling_stays_on_the_tracked_restore_id(self):
        polling_block = self.source.split(
            "async getNativeCloudRestores(showErrors = false, allowNameRecovery = false)",
            1,
        )[1].split("async startNativeCloudRestore()", 1)[0]
        tracked_branch = polling_block.split("if (trackedId !== null)", 1)[1].split(
            "else if (allowNameRecovery)", 1
        )[0]
        self.assertIn(
            "records.find(item => this.nativeRestoreId(item.id) === trackedId)",
            tracked_branch,
        )
        self.assertNotIn("item.name", tracked_branch)
        self.assertIn("else if (allowNameRecovery)", polling_block)
        self.assertIn(
            "const matches = records.filter(item => String(item.name || '').trim() === targetName)",
            polling_block,
        )
