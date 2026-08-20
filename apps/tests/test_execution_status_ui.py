"""Focused contract checks for the durable execution status dashboard UI."""

from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase


class ExecutionStatusUiTemplateTests(SimpleTestCase):
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

    def test_node_detail_template_compiles(self):
        get_template("console/node/detail.html")

    def test_backup_and_restore_statuses_expose_operator_contract(self):
        for label in (
            "Queued",
            "Actively running",
            "Waiting for provider",
            "Scheduled retry",
            "Recovering / reconciling",
            "Manual review required",
            "Terminal failure",
            "Partially complete",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.source)

        for marker in (
            "data-execution-status-card",
            "payload.execution_status",
            "/api/v1/backups/${encodeURIComponent(this.integrationCode)}",
            "Next retry:",
            "Progress",
            "Provider:",
            "Recovery:",
            "Technical details",
            "Correlation ID",
            'role="progressbar"',
            'role="status"',
            'aria-live="polite"',
            'aria-label="Copy backup correlation ID"',
            'aria-label="Copy restore correlation ID"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_pending_backup_is_visibly_queued_and_keeps_polling(self):
        category = self.source.split(
            "function categoryFor({status, phase, providerStatus, reconciliationState, errorCode, retryAt})",
            1,
        )[1].split("function toneClasses", 1)[0]

        self.assertIn(
            "if (status === 'pending' || phase === 'pending')",
            category,
        )
        self.assertIn(
            "return {key: 'queued', label: 'Queued', tone: 'sky'};",
            category,
        )
        self.assertIn(
            "const shouldPoll = !['complete', 'terminal_failure', 'manual_review'].includes(category.key);",
            self.source,
        )

    def test_legacy_and_malformed_payloads_keep_existing_status_fallback(self):
        # These guards are intentionally close to the client-side parser so a
        # legacy deployment or a partial response cannot blank the server badge
        # or throw during polling.
        for guard in (
            "if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;",
            "const restoreItems = Array.isArray(json)",
            "this.restoreExecutionStatus = this.executionStatusView(this.restoreStatus);",
            "server-rendered legacy status badge",
            "this.schedule(30000);",
            "legacyRestoreStatusLabel",
        ):
            with self.subTest(guard=guard):
                self.assertIn(guard, self.source)

    def test_status_ui_never_reads_or_renders_private_execution_fields(self):
        # The UI consumes only the redacted execution_status contract.  These
        # names are canaries for accidentally wiring raw coordination/provider
        # metadata into an x-text, title, or technical-details element.
        for private_field in (
            "provider_metadata",
            "lease_owner",
            "lease_token",
            "lease_expires_at",
            "worker_name",
            "internal_path",
            "restoreStatus.error",
            "restoreItem.error",
            "last_error_message",
        ):
            with self.subTest(private_field=private_field):
                self.assertNotIn(private_field, self.source)

        self.assertIn("safeErrorMessage", self.source)
        self.assertIn("last_error_code", self.source)
        self.assertIn("Review secured diagnostics using the correlation ID", self.source)

    def test_intermediate_archive_phases_are_not_treated_as_terminal(self):
        complete_set = self.source.split(
            "const completeStatuses = new Set([", 1
        )[1].split("]);", 1)[0]
        self.assertNotIn("upload_complete", complete_set)
        self.assertNotIn("download_complete", complete_set)
        self.assertIn("partial_some_destinations_failed", self.source)
        self.assertIn("partialStatuses.has(status)", self.source)
        self.assertIn(
            ":aria-valuenow=\"view && view.progressDeterminate ? view.progressCompleted : null\"",
            self.source,
        )

    def test_source_ready_label_and_diagnostics_do_not_offer_a_dead_log_action(self):
        self.assertIn("Source archive ready", self.source)
        self.assertIn(
            "Diagnostics: use the correlation ID under Technical details.",
            self.source,
        )
        self.assertNotIn("downloadTransferLog", self.source)
        self.assertNotIn("Log File", self.source)

    def test_polled_terminal_backup_replaces_cancel_with_terminal_actions(self):
        self.assertIn(
            "loaded ? Boolean(view && view.category === 'complete')",
            self.source,
        )
        self.assertIn(
            "loaded ? Boolean(view && view.shouldPoll)",
            self.source,
        )
        self.assertIn(
            'x-data="executionStatusCard"',
            self.source,
        )
        self.assertIn(
            "openNativeCloudRestoreModal('{{ backup.id }}', '{{ backup.uuid }}', '3')",
            self.source,
        )

    def test_recent_restore_history_exposes_phase_and_safe_diagnostics(self):
        for marker in (
            'x-show="restoreExecutionSummary(restoreItem)"',
            "restoreExecutionErrorMessage(item)",
            "restoreExecutionCorrelationId(item)",
            "restoreExecutionErrorCode(item)",
            'aria-label="Copy historical restore correlation ID"',
            "The restore state is ambiguous, so automatic destination writes were stopped.",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_archive_rehydration_has_specific_safe_guidance(self):
        self.assertIn("RESTORE_ARCHIVE_NOT_READY", self.source)
        self.assertIn(
            "The storage provider is restoring this archive; the restore will resume automatically when it is ready.",
            self.source,
        )

    def test_restore_created_and_retry_labels_share_browser_timezone_formatter(self):
        self.assertIn("function dateTimeLabel(value)", self.source)
        self.assertIn("const retryAtLabel = dateTimeLabel(retryAt);", self.source)
        self.assertIn(
            "window.BackupSheepExecutionStatus.dateTimeLabel(item.created)",
            self.source,
        )

        created_label = self.source.split("restoreCreatedLabel(item)", 1)[1].split(
            "safeLegacyRestoreError(item)", 1
        )[0]
        self.assertIn("item.created_display", created_label)
