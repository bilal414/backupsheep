"""Shared durable reconciliation-state regressions for provider poll outcomes."""

import json
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from apps.api.v1.backup.website.serializers import CoreWebsiteBackupSerializer
from apps.console.backup.models import (
    CoreBackupExecution,
    CoreDigitalOceanBackup,
    CoreWebsiteBackup,
    _provider_failed,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class ProviderReconciliationStateTests(BaseTestCase):
    def _cloud_backup(self, *, status=UtilBackup.Status.IN_PROGRESS):
        node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=status,
            unique_id="provider-resource-owned-by-test",
            celery_task_id=f"poll-{uuid4().hex}",
        )
        return node, backup

    def test_provider_reconciliation_error_reopens_resolved_execution(self):
        _node, backup = self._cloud_backup()
        state = backup.get_execution_state(create=True)
        state.reconciliation_state = state.ReconciliationState.RESOLVED
        state.reconciliation_reason = "provider_reconciled"
        state.save(update_fields=["reconciliation_state", "reconciliation_reason"])

        result = _provider_failed(
            backup,
            provider="oracle",
            state="durable_pointer_mismatch",
            code="PROVIDER_RECONCILIATION_REQUIRED",
        )

        self.assertEqual(result, UtilBackup.Status.FAILED)
        state.refresh_from_db()
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertEqual(
            state.reconciliation_reason, "provider_reconciliation_required"
        )
        self.assertEqual(
            state.reconciliation_metadata,
            {
                "source": "provider_outcome",
                "error_code": "PROVIDER_RECONCILIATION_REQUIRED",
            },
        )
        self.assertEqual(state.provider_metadata["provider"], "oracle")
        self.assertEqual(state.provider_metadata["operation"], "poll")

    def test_provider_reconciliation_survives_terminal_finalization(self):
        _node, backup = self._cloud_backup()
        _provider_failed(
            backup,
            provider="oracle",
            state="durable_pointer_mismatch",
            code="PROVIDER_RECONCILIATION_REQUIRED",
        )
        backup.status = UtilBackup.Status.FAILED
        backup.save(update_fields=["status", "modified"])

        backup.finalize_execution(terminal_phase="failed")

        state = backup.get_execution_state(create=False)
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.REQUIRED,
        )
        self.assertEqual(
            state.reconciliation_reason, "provider_reconciliation_required"
        )
        self.assertEqual(state.phase, "failed")
        self.assertIsNotNone(state.finished_at)

    def test_later_successful_finalization_can_resolve_reconciliation(self):
        _node, backup = self._cloud_backup()
        _provider_failed(
            backup,
            provider="oracle",
            state="durable_pointer_mismatch",
            code="PROVIDER_RECONCILIATION_REQUIRED",
        )
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])

        backup.finalize_execution(terminal_phase="complete")

        state = backup.get_execution_state(create=False)
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(state.reconciliation_reason, "backup_finalized")

    def test_manual_review_and_fencing_are_preserved(self):
        _node, backup = self._cloud_backup()
        state = backup.get_execution_state(create=True)
        state.reconciliation_state = state.ReconciliationState.MANUAL_REVIEW
        state.reconciliation_reason = "provider_ownership_mismatch"
        state.save(update_fields=["reconciliation_state", "reconciliation_reason"])

        saved = backup.record_execution_error(
            code="PROVIDER_RECONCILIATION_REQUIRED",
            message="provider response contains bearer-secret-canary",
        )
        self.assertEqual(
            saved.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )
        self.assertEqual(
            saved.reconciliation_reason, "provider_reconciliation_required"
        )
        self.assertNotIn("bearer-secret-canary", saved.last_error_message)

        claimed = backup.claim_execution(
            lease_owner="poll-worker",
            phase="poll",
            lease_seconds=120,
        )
        stale = backup.record_execution_error(
            code="PROVIDER_RECONCILIATION_REQUIRED",
            lease_owner="stale-worker",
            lease_token=uuid4(),
        )
        self.assertIsNone(stale)
        claimed.refresh_from_db()
        self.assertEqual(
            claimed.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )
        self.assertEqual(claimed.lease_owner, "poll-worker")

    def test_normal_retry_and_terminal_finalization_semantics_remain_unchanged(self):
        _node, backup = self._cloud_backup()
        state = backup.get_execution_state(create=True)
        state.reconciliation_state = state.ReconciliationState.RESOLVED
        state.reconciliation_reason = "provider_reconciled"
        state.save(update_fields=["reconciliation_state", "reconciliation_reason"])
        retry_at = timezone.now() + timedelta(minutes=5)

        retry = backup.record_execution_error(
            code="PROVIDER_RATE_LIMIT",
            retryable=True,
            retry_at=retry_at,
        )
        self.assertEqual(
            retry.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(retry.next_retry_at, retry_at)

        retry.reconciliation_state = retry.ReconciliationState.REQUIRED
        retry.reconciliation_reason = "stale_execution_lease"
        retry.last_error_code = "PROVIDER_TIMEOUT"
        retry.save(
            update_fields=[
                "reconciliation_state",
                "reconciliation_reason",
                "last_error_code",
                "modified",
            ]
        )
        backup.status = UtilBackup.Status.FAILED
        backup.save(update_fields=["status", "modified"])
        backup.finalize_execution(terminal_phase="failed")

        retry.refresh_from_db()
        self.assertEqual(
            retry.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )
        self.assertEqual(retry.reconciliation_reason, "backup_finalized")
        self.assertIsNone(retry.next_retry_at)

    def test_api_and_ui_expose_only_the_safe_reconciliation_contract(self):
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            name="reconciliation-status",
            uuid=f"status-{uuid4().hex}",
            status=UtilBackup.Status.FAILED,
            type=UtilBackup.Type.ON_DEMAND,
        )
        content_type = ContentType.objects.get_for_model(
            backup, for_concrete_model=False
        )
        CoreBackupExecution.objects.create(
            backup_content_type=content_type,
            backup_object_id=backup.pk,
            phase="failed",
            reconciliation_state=CoreBackupExecution.ReconciliationState.REQUIRED,
            reconciliation_reason="provider_reconciliation_required",
            reconciliation_metadata={"response_body": "provider-secret-canary"},
            last_error_code="PROVIDER_RECONCILIATION_REQUIRED",
            last_error_message="Bearer provider-secret-canary",
            provider_metadata={"response_body": "provider-secret-canary"},
        )

        payload = CoreWebsiteBackupSerializer(
            CoreWebsiteBackup.objects.get(pk=backup.pk)
        ).data
        execution = payload["execution_status"]
        self.assertEqual(
            execution["reconciliation"],
            {
                "state": "required",
                "reason": "provider_reconciliation_required",
            },
        )
        self.assertEqual(
            execution["last_error_code"], "PROVIDER_RECONCILIATION_REQUIRED"
        )
        self.assertEqual(
            execution["last_error_message"],
            UtilBackup.EXECUTION_ERROR_MESSAGES[
                "PROVIDER_RECONCILIATION_REQUIRED"
            ],
        )
        self.assertNotIn("reconciliation_metadata", execution)
        self.assertNotIn("provider_metadata", execution)
        self.assertNotIn("provider-secret-canary", json.dumps(payload))

        template = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "detail.html"
        ).read_text(encoding="utf-8")
        self.assertIn("manualReviewErrorPattern", template)
        self.assertIn("RECONCILIATION_REQUIRED", template)
        self.assertIn("Recovery:", template)
        self.assertNotIn("reconciliation_metadata", template)
