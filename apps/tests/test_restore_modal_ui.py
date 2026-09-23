"""Focused UI contract tests for logical website and database restores."""

from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase


class LogicalRestoreModalUiTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        template_path = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "_recovery_dialogs.html"
        )
        cls.modal = template_path.read_text(encoding="utf-8")
        cls.detail = (template_path.parent / "detail.html").read_text(
            encoding="utf-8"
        )
        cls.schedule_dialog = (
            template_path.parent / "_schedule_dialog.html"
        ).read_text(encoding="utf-8")
        cls.overview = (
            template_path.parent / "_detail_overview.html"
        ).read_text(encoding="utf-8")
        cls.styles = (
            template_path.parents[3] / "_static" / "console" / "css" / "styles.css"
        ).read_text(encoding="utf-8")

    def test_restore_modal_template_compiles(self):
        get_template("console/node/detail.html")
        get_template("console/node/_recovery_dialogs.html")

    def test_website_restore_retains_overwrite_and_delete_warning(self):
        notice = self.modal.rsplit("{% if object.type == 3 %}", 1)[1].split(
            "{% endif %}", 1
        )[0]
        website_notice = notice.split("{% else %}", 1)[0]

        self.assertIn("This overwrites matching website files", website_notice)
        self.assertIn(
            "Files absent from the recovery point remain in place unless you enable the destructive mirror option below.",
            website_notice,
        )
        self.assertIn("Also delete files absent from this recovery point", self.modal)
        self.assertIn("Permanent and off by default", self.modal)

    def test_database_restore_explains_safe_fork_without_source_overwrite_claim(self):
        notice = self.modal.rsplit("{% if object.type == 3 %}", 1)[1].split(
            "{% endif %}", 1
        )[0]
        database_notice = notice.split("{% else %}", 1)[1]

        self.assertIn("Safe fork:", database_notice)
        self.assertIn("the restore creates a separate database", database_notice)
        self.assertIn("the source database remains unchanged", database_notice)
        self.assertNotIn("overwrites", database_notice.lower())
        self.assertNotIn("deleted", database_notice.lower())

    def test_download_actions_require_a_completed_exportable_copy(self):
        self.assertIn(
            ".filter(point => point.status === 3 && point.storage_file_id && point.direct_download_permitted === true)",
            self.modal,
        )
        self.assertIn("No direct browser export is available", self.modal)
        self.assertIn("controlled export workflow", self.modal)

    def test_restore_acceptance_copy_does_not_claim_execution_started(self):
        self.assertIn("Recovery request recorded", self.modal)
        self.assertIn("does not claim that recovery completed", self.modal)
        self.assertNotIn("Recovery operation started", self.modal)
        recorded_panel = self.modal.split("!loading && restoreStarted", 1)[1]
        self.assertNotIn("animate-spin", recorded_panel.split("</div>", 2)[0])
        self.assertNotIn("details: 'Restore started.'", self.detail)

    def test_recovery_requests_are_bounded_reconciled_and_always_unlock(self):
        self.assertIn("async requestWithTimeout", self.detail)
        self.assertIn("controller.abort()", self.detail)
        self.assertIn("data.request_id = this.logicalRestoreRequestId()", self.detail)
        self.assertIn("this.logicalRestoreRecoveryId(item) === this.restoreRequestId", self.detail)
        self.assertIn("heading: 'Restore request recovered'", self.detail)
        start_restore = self.detail.split("async startRestore(", 1)[1].split(
            "openBackupTransferModal", 1
        )[0]
        storage_points = self.detail.split(
            "async getBackupStoragePoints(", 1
        )[1].split("async downloadDirTree", 1)[0]
        self.assertIn("finally", start_restore)
        self.assertIn("this.loading = false", start_restore)
        self.assertIn("finally", storage_points)
        self.assertIn("this.loading = false", storage_points)

    def test_uncertain_restore_submission_fails_closed_until_reconciled(self):
        self.assertIn("restoreSubmissionUncertain", self.modal)
        self.assertIn("Check durable ledger", self.modal)
        self.assertIn("Retry same request safely", self.modal)
        self.assertIn("restoreReconciliationLoading", self.modal)
        self.assertIn("Do not create a different restore", self.modal)
        start_restore = self.detail.split("async startRestore(", 1)[1].split(
            "openBackupTransferModal", 1
        )[0]
        self.assertIn("const outcomeMayBeUnknown", start_restore)
        self.assertIn("outcomeMayBeUnknown", start_restore)
        self.assertIn("this.restoreSubmissionUncertain = outcomeMayBeUnknown", start_restore)
        self.assertNotIn(
            "const recovered = await this.reconcileRestoreSubmission(false)",
            start_restore,
        )

    def test_restore_request_identity_is_persisted_and_matched_exactly(self):
        self.assertIn("window.sessionStorage.getItem(storageKey)", self.detail)
        self.assertIn("window.sessionStorage.setItem(storageKey, requestId)", self.detail)
        self.assertIn("nativeRestoreRandomUUID", self.detail)
        match = self.detail.split("logicalRestoreRequestMatch(records)", 1)[1].split(
            "adoptLogicalRestoreRequest", 1
        )[0]
        self.assertIn("this.logicalRestoreRecoveryId(item) === this.restoreRequestId", match)
        self.assertIn(
            "String(item.storage_point) === String(this.restoreSubmissionStoragePointId)",
            match,
        )
        self.assertIn(
            "String(item.backup) === String(this.restoreSubmissionBackupId)",
            match,
        )
        self.assertNotIn("knownRestoreIds", self.detail)

    def test_restore_start_requires_a_fresh_durable_ledger(self):
        self.assertIn("restoreLedgerReady", self.modal)
        self.assertIn("Restore ledger unavailable", self.modal)
        self.assertIn("An unavailable ledger is never treated as an empty ledger", self.modal)
        start_restore = self.detail.split("async startRestore(", 1)[1].split(
            "openBackupTransferModal", 1
        )[0]
        self.assertIn("!this.restoreLedgerReady", start_restore)
        self.assertIn("const currentLedger = await this.getBackupRestores(false)", start_restore)
        self.assertIn("if (!Array.isArray(currentLedger))", start_restore)
        self.assertIn("No second restore was submitted", start_restore)

    def test_server_errors_are_treated_as_unknown_restore_outcomes(self):
        start_restore = self.detail.split("async startRestore(", 1)[1].split(
            "openBackupTransferModal", 1
        )[0]
        self.assertIn("const definitiveClientRejection", start_restore)
        self.assertIn("response.status >= 400 && response.status < 500", start_restore)
        self.assertIn("![408, 425, 429].includes(response.status)", start_restore)
        self.assertIn("responseError.outcomeUnknown = !definitiveClientRejection", start_restore)

    def test_high_impact_dialogs_share_keyboard_modal_lifecycle(self):
        focusable_helper = self.detail.split(
            "dialogFocusableElements(container)", 1
        )[1].split("focusDialogFirstControl(refName)", 1)[0]
        focus_trap = self.detail.split("trapFocus(event, container)", 1)[1].split(
            "async requestWithTimeout", 1
        )[0]
        self.assertIn("'summary'", focusable_helper)
        self.assertIn("active === container", focus_trap)
        self.assertIn("event.shiftKey ? last : first", focus_trap)
        self.assertIn("this.focusDialogFirstControl(refName)", self.detail)
        for dialog in (
            "backupDialog",
            "pauseDialog",
            "resumeDialog",
            "nativeRestoreDialog",
            "transferDialog",
            "deleteNodeDialog",
            "deleteBackupDialog",
            "modifyDialog",
            "incrementalResetDialog",
        ):
            with self.subTest(dialog=dialog):
                self.assertIn(f'x-ref="{dialog}"', self.detail)
                self.assertIn(
                    f"trapFocus($event, $refs.{dialog})",
                    self.detail,
                )

        transfer_open = self.detail.split("openBackupTransferModal(storagePoint)", 1)[1].split(
            "closeBackupTransferModal()", 1
        )[0]
        self.assertIn("this.prepareDialog('transferDialog')", transfer_open)
        self.assertNotIn("dialog.focus()", transfer_open)

    def test_restore_ledger_responses_are_bound_to_one_modal_context(self):
        open_restore = self.detail.split(
            "openBackupRestoreModal(backupID, BackupUUID)", 1
        )[1].split("closeRestoreModal()", 1)[0]
        close_restore = self.detail.split("closeRestoreModal()", 1)[1].split(
            "hasActiveLogicalRestore()", 1
        )[0]
        ledger = self.detail.split("async getBackupRestores(", 1)[1].split(
            "async reloadRestoreLedger()", 1
        )[0]

        self.assertIn("this.cancelRestoreLedgerRequest()", open_restore)
        self.assertIn("++this.restoreContextGeneration", open_restore)
        self.assertIn(
            "this.getBackupRestores(true, backupID, restoreGeneration)",
            open_restore,
        )
        self.assertIn("this.restoreContextGeneration += 1", close_restore)
        self.assertIn("this.cancelRestoreLedgerRequest()", close_restore)
        self.assertIn("backupID = this.backup.id", ledger)
        self.assertIn("generation = this.restoreContextGeneration", ledger)
        self.assertIn("this.restoreContextMatches(backupID, generation)", ledger)
        self.assertIn("signal: controller.signal", ledger)
        self.assertIn("this.restoreLedgerController !== controller", ledger)
        self.assertIn("this.restoreLedgerController === controller", ledger)

    def test_destination_copy_responses_are_bound_to_backup_and_dialog_context(self):
        storage_points = self.detail.split(
            "async getBackupStoragePoints(", 1
        )[1].split("async downloadDirTree", 1)[0]
        for marker in (
            "backupID",
            "generation = this.backupStorageContextGeneration",
            "purpose = this.openBackupRestore ? 'restore' : 'download'",
            "this.backupStorageContextMatches(backupID, generation, purpose)",
            "this.backupStorageController !== controller",
            "this.backupStorageController === controller",
            "signal: controller.signal",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, storage_points)

        for opener, closer, purpose in (
            (
                "openBackupDownloadModal(backupID, BackupUUID)",
                "closeBackupDownloadModal()",
                "'download'",
            ),
            (
                "openBackupRestoreModal(backupID, BackupUUID)",
                "closeRestoreModal()",
                "'restore'",
            ),
        ):
            with self.subTest(opener=opener):
                block = self.detail.split(opener, 1)[1].split(closer, 1)[0]
                self.assertIn("this.cancelBackupStoragePointRequest()", block)
                self.assertIn("++this.backupStorageContextGeneration", block)
                self.assertIn(purpose, block)

    def test_logical_restore_ledger_uses_source_wide_lane_and_gates_point_resume(self):
        ledger = self.detail.split("async getBackupRestores(", 1)[1].split(
            "async reloadRestoreLedger()", 1
        )[0]
        self.assertIn("/restores/?scope=source", ledger)
        self.assertIn("const activeRestore = this.activeLogicalRestore()", ledger)
        self.assertIn(
            "this.restoreStatus = activeRestore || trackedRestore || currentPointRestore",
            ledger,
        )
        resume_predicate = self.detail.split("databaseRestoreCanResume(item)", 1)[1].split(
            "},", 1
        )[0]
        self.assertIn("this.logicalRestoreBelongsToSelectedPoint(item)", resume_predicate)
        self.assertIn("source-wide recovery lane", self.modal)

    def test_direct_download_affordance_requires_server_eligibility(self):
        self.assertIn("point.direct_download_permitted === true", self.modal)
        self.assertIn("No direct browser export is available", self.modal)
        self.assertIn("enterprise-protected copies, if present", self.modal)
        download = self.detail.split("async downloadBackup(storagePoint, type)", 1)[1].split(
            "async downloadTransferLog", 1
        )[0]
        self.assertIn("storagePoint.direct_download_permitted !== true", download)

    def test_download_navigation_revalidates_server_targets_in_the_browser(self):
        validator = self.detail.split(
            "validatedBrowserDownloadTarget(value)", 1
        )[1].split("applyNodeSummary(summary)", 1)[0]
        for marker in (
            "value.trim() !== value",
            "value.startsWith('/')",
            "localDownloadPath.test(value)",
            "parsed = new URL(value)",
            "parsed.protocol !== 'https:'",
            "parsed.username || parsed.password",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, validator)

        download = self.detail.split(
            "async downloadBackup(storagePoint, type)", 1
        )[1].split("async downloadTransferLog", 1)[0]
        validation = "const url = this.validatedBrowserDownloadTarget(data.url);"
        self.assertIn(validation, download)
        self.assertLess(download.index(validation), download.index("navigator.clipboard.writeText(url)"))
        self.assertLess(download.index(validation), download.index("window.location.assign(url)"))
        self.assertNotIn("const url = data.url;", download)

        directory_tree = self.detail.split(
            "async downloadDirTree(backup_id)", 1
        )[1].split("async downloadBackup(storagePoint, type)", 1)[0]
        self.assertIn(
            "window.location.assign(this.validatedBrowserDownloadTarget(json.url));",
            directory_tree,
        )

    def test_native_restore_async_work_is_bounded_and_context_isolated(self):
        native_get = self.detail.split("async getNativeCloudRestores(", 1)[1].split(
            "async startNativeCloudRestore(exactRetry = false)", 1
        )[0]
        native_start = self.detail.split("async startNativeCloudRestore(exactRetry = false)", 1)[1].split(
            "async resumeNativeCloudRestore(item)", 1
        )[0]
        native_resume = self.detail.split("async resumeNativeCloudRestore(item)", 1)[1].split(
            "async resumeDatabaseRestore(item)", 1
        )[0]
        for block in (native_get, native_start, native_resume):
            self.assertIn("this.requestWithTimeout", block)
            self.assertIn("nativeRestoreContextMatches", block)
        self.assertIn("signal: controller.signal", native_get)
        self.assertIn("nativeRestoreLedgerController !== controller", native_get)
        self.assertIn("nativeRestoreLedgerController === controller", native_get)
        self.assertIn("Restore status response was not a list.", native_get)
        self.assertIn("nativeRestoreSubmitting || this.nativeRestoreResumeSubmitting", self.detail)

    def test_policy_delete_requires_named_confirmation_and_busy_lock(self):
        self.assertIn("openScheduleDeleteModal", self.overview)
        self.assertIn("Delete protection policy?", self.schedule_dialog)
        self.assertIn("scheduleDelete.name", self.schedule_dialog)
        self.assertIn("Existing recovery points are not deleted", self.schedule_dialog)
        self.assertIn(':disabled="loading"', self.schedule_dialog)
        self.assertIn("if (this.loading || !this.scheduleDelete.id) return", self.detail)

    def test_small_metadata_token_uses_darker_aa_color(self):
        self.assertIn("--color-ink-500: #596765;", self.styles)

    def test_policy_copy_does_not_overstate_offline_air_gap(self):
        self.assertIn(
            "Require a selected immutable protected copy",
            self.schedule_dialog,
        )
        self.assertIn("Object Lock Compliance", self.schedule_dialog)
        self.assertIn("does not by itself evidence offline", self.schedule_dialog)
        self.assertNotIn(
            "Require a selected air-gapped copy",
            self.schedule_dialog,
        )

    def test_source_deletion_is_described_as_an_async_request(self):
        self.assertIn("This requests deletion", self.detail)
        self.assertIn("Destination cleanup is asynchronous", self.detail)
        self.assertIn("retention-locked", self.detail)
        self.assertIn("Request source deletion", self.detail)
