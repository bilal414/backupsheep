"""Focused contract tests for the native cloud restore dashboard flow.

These tests intentionally inspect the template contract instead of making provider
calls.  The API is durable/idempotent; the browser must submit only the supported
fields and recover the same restore record after a reload or lost response.
"""

from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase


class NativeCloudRestoreUiTemplateTests(SimpleTestCase):
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

    def test_template_compiles_and_renders_native_restore_surface(self):
        # Compilation catches invalid Django conditionals/filters.  The source
        # assertions below cover the Alpine render contract without provider I/O.
        get_template("console/node/detail.html")
        for marker in (
            'x-show="openNativeCloudRestore"',
            'id="native-restore-modal-title"',
            "Restore safely",
            "Recent native restores",
            'role="dialog"',
            'aria-live="polite"',
            ):
                with self.subTest(marker=marker):
                    self.assertIn(marker, self.source)
        self.assertNotIn("object.oracle.metadata._bs_", self.source)
        self.assertIn("object.oracle.native_restore_compartment_id", self.source)

    def test_restore_action_is_available_only_for_terminal_native_backups(self):
        self.assertIn(
            "{% elif object.type == 1 or object.type == 2 or is_vultr_managed_database %}",
            self.source,
        )
        self.assertIn(
            "openNativeCloudRestoreModal('{{ backup.id }}', '{{ backup.uuid|default_if_none:''|escapejs }}', '3')",
            self.source,
        )
        self.assertIn(
            "loaded ? Boolean(view && view.category === 'complete')",
            self.source,
        )
        self.assertIn("String(backupStatus) !== '3' ||", self.source)
        self.assertIn("this.nativeRestoreStarted ||", self.source)

    def test_post_contract_is_explicit_and_uses_provider_minimal_fields(self):
        self.assertIn(
            "`/api/v1/nodes/${encodeURIComponent(this.node_id || nativeRestoreConfig.nodeId)}/restore_backup/`",
            self.source,
        )
        self.assertIn("backup_id: Number(this.nativeRestore.backupId)", self.source)
        self.assertIn("confirm: true", self.source)
        self.assertIn("request_id: this.nativeRestoreRequestId()", self.source)
        self.assertIn("recovery_id: this.nativeRestoreRecoveryId()", self.source)
        self.assertIn("params.destination_bucket_name = targetName", self.source)
        self.assertIn("params.target_table_name = targetName", self.source)
        self.assertIn("if (response.status !== 200 && response.status !== 201)", self.source)
        self.assertIn("idempotent_replay", self.source)

    def test_request_id_is_stable_for_retries_but_changes_for_a_new_target(self):
        self.assertIn("if (this.nativeRestore.requestId && this.nativeRestore.requestTargetName === targetName)", self.source)
        self.assertIn("window.crypto.randomUUID()", self.source)
        self.assertIn("this.nativeRestore.requestTargetName = targetName", self.source)
        self.assertIn("if (this.nativeRestore.recoveryId && this.nativeRestore.recoveryTargetName === targetName)", self.source)
        self.assertIn("this.nativeRestore.recoveryTargetName = targetName", self.source)
        self.assertGreaterEqual(self.source.count("requestId: null"), 2)
        self.assertGreaterEqual(self.source.count("recoveryId: null"), 2)
        self.assertIn("requestId: pendingRequest ? pendingRequest.request_id : null", self.source)
        self.assertIn("recoveryId: pendingRequest ? pendingRequest.recovery_id : null", self.source)
        # A fetch failure reconciles the existing durable row; it does not call
        # openNativeCloudRestoreModal or reset requestId before the next attempt.
        retry_block = self.source.split("async startNativeCloudRestore(exactRetry = false)", 1)[1].split(
            "clearRestorePoll()", 1
        )[0]
        self.assertIn("await this.getNativeCloudRestores(", retry_block)
        self.assertIn("backupId", retry_block)
        self.assertIn("generation", retry_block)
        self.assertNotIn("requestId = null", retry_block)

    def test_reload_recovery_and_polling_use_node_restore_list(self):
        self.assertIn(
            "`/api/v1/nodes/${encodeURIComponent(this.node_id || nativeRestoreConfig.nodeId)}/restores/`",
            self.source,
        )
        self.assertIn(
            "String(this.nativeRestoreBackupId(item)) === String(backupId)",
            self.source,
        )
        self.assertIn(
            "item.backup_id !== undefined ? item.backup_id : item.backup",
            self.source,
        )
        self.assertIn("adoptNativeRestoreTargetIfPresent()", self.source)
        self.assertIn("startNativeRestorePolling()", self.source)
        self.assertIn("clearNativeRestorePoll()", self.source)
        self.assertIn("this.nativeRestoreStatusIsTerminal(this.nativeRestoreStatus)", self.source)
        self.assertIn("A lost response can still mean the API created the durable", self.source)

    def test_existing_backup_promotes_latest_restore_but_lost_post_stays_exact(self):
        restore_block = self.source.split(
            "async getNativeCloudRestores(",
            1,
        )[1].split("async reconcileNativeRestoreSubmission", 1)[0]
        self.assertIn("const recoveringAcceptedRequest = Boolean(", restore_block)
        self.assertIn(
            "const pendingRequest = this.nativeRestorePendingRequestBody",
            restore_block,
        )
        self.assertIn("String(pendingRequest.recovery_id || '').trim()", restore_block)
        self.assertIn("String(pendingRequest.name || '').trim()", restore_block)
        self.assertIn(
            "String((item.execution_status || {}).recovery_id || '').trim() === recoveryId",
            restore_block,
        )
        self.assertIn("String(item.name || '').trim() === targetName", restore_block)
        self.assertIn("matches.length === 1 ? matches[0] : null", restore_block)
        self.assertNotIn("correlation_id", restore_block)
        self.assertIn("else if (!this.nativeRestoreSubmissionUncertain)", restore_block)
        self.assertIn("exact = records.reduce((latest, item) =>", restore_block)
        self.assertIn("return itemId > latestId ? item : latest", restore_block)
        self.assertIn("the newest durable attempt instead of pinning", restore_block)

    def test_unknown_submission_is_locked_to_exact_request_until_reconciled(self):
        start_block = self.source.split(
            "async startNativeCloudRestore(exactRetry = false)",
            1,
        )[1].split("async resumeNativeCloudRestore(item)", 1)[0]
        submit_guard = self.source.split("nativeRestoreCanSubmit() {", 1)[1].split(
            "nativeRestoreCanRetryExact() {", 1
        )[0]
        close_block = self.source.split(
            "closeNativeCloudRestoreModal() {",
            1,
        )[1].split("cancelNativeRestoreLedgerRequest() {", 1)[0]

        for marker in (
            "nativeRestoreSubmissionUncertain: false",
            "nativeRestorePendingRequestBody: null",
            "nativeRestoreReconciliationLoading: false",
            "Restore outcome not yet confirmed",
            "Check durable ledger",
            "Retry exact request",
            "reconcileNativeRestoreSubmission(true)",
            "retryNativeRestoreSubmission()",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

        self.assertIn("this.nativeRestoreSubmissionUncertain", submit_guard)
        self.assertIn("this.nativeRestoreReconciliationLoading", submit_guard)
        self.assertIn("this.nativeRestoreSubmissionUncertain", close_block)
        self.assertIn("this.nativeRestoreReconciliationLoading", close_block)
        self.assertIn(':disabled="!nativeRestoreCanReconcileExact()"', self.source)
        self.assertIn("let acceptedResponseSeen = false", start_block)
        self.assertIn(
            "acceptedResponseSeen = response.status === 200 || response.status === 201",
            start_block,
        )
        self.assertIn("malformedAcceptedResponse.outcomeUnknown = acceptedResponseSeen", start_block)
        self.assertIn("this.persistNativeRestorePendingRequest(requestBody)", start_block)
        self.assertIn("? this.nativeRestorePendingRequestBody", start_block)
        self.assertIn("this.nativeRestoreSubmissionUncertain = outcomeMayBeUnknown", start_block)
        self.assertIn("if (!outcomeMayBeUnknown) this.clearNativeRestorePendingRequest()", start_block)
        self.assertIn("responseRecoveryId !== String(requestBody.recovery_id || '').trim()", start_block)
        self.assertIn(
            "String(this.nativeRestoreBackupId(json)) !== String(requestBody.backup_id)",
            start_block,
        )
        self.assertIn(
            "String(json.name || '').trim() !== String(requestBody.name || '').trim()",
            start_block,
        )
        self.assertIn(
            ':disabled="nativeRestoreSubmissionUncertain || nativeRestoreSubmitting || nativeRestoreReconciliationLoading"',
            self.source,
        )

    def test_unknown_submission_survives_reload_before_any_network_request(self):
        persistence_block = self.source.split(
            "nativeRestoreSubmissionStorageKey(backupId) {",
            1,
        )[1].split("nativeRestoreDestinationBucketValid() {", 1)[0]
        open_block = self.source.split(
            "openNativeCloudRestoreModal(backupId, backupUuid, backupStatus) {",
            1,
        )[1].split("closeNativeCloudRestoreModal() {", 1)[0]
        start_block = self.source.split(
            "async startNativeCloudRestore(exactRetry = false)",
            1,
        )[1].split("async resumeNativeCloudRestore(item)", 1)[0]

        for marker in (
            "backupsheep.native-restore.pending.v1",
            "window.sessionStorage.getItem(storageKey)",
            "window.sessionStorage.setItem(storageKey, serialized)",
            "window.sessionStorage.removeItem(storageKey)",
            "nativeRestorePendingRequestValid(requestBody, backupId)",
            "return {requestBody: null, storageKey, blocked: true}",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, persistence_block)

        self.assertIn("const pendingState = this.loadNativeRestorePendingRequest(backupId)", open_block)
        self.assertIn("this.nativeRestoreSubmissionUncertain = Boolean(pendingRequest || pendingBlocked)", open_block)
        self.assertIn("requestId: pendingRequest ? pendingRequest.request_id : null", open_block)
        self.assertIn("recoveryId: pendingRequest ? pendingRequest.recovery_id : null", open_block)
        self.assertIn("destinationBucketName: pendingRequest && this.nativeRestoreResourceKind === 'aws_s3'", open_block)
        self.assertIn("!pendingBlocked", open_block)
        self.assertIn("if (pendingBlocked)", open_block)
        self.assertIn("else if (pendingRequest)", open_block)
        self.assertIn(
            "if (!this.nativeRestorePendingRequestValid(",
            self.source.split("async reconcileNativeRestoreSubmission", 1)[1].split(
                "retryNativeRestoreSubmission()",
                1,
            )[0],
        )

        persist_index = start_block.index("this.persistNativeRestorePendingRequest(requestBody)")
        network_index = start_block.index("this.requestWithTimeout(url")
        self.assertLess(persist_index, network_index)
        self.assertIn("No restore request was submitted", start_block)
        self.assertIn("this.nativeRestoreSubmissionUncertain = outcomeMayBeUnknown", start_block)
        self.assertIn("if (!outcomeMayBeUnknown) this.clearNativeRestorePendingRequest()", start_block)

    def test_terminal_restore_can_start_another_unique_copy(self):
        self.assertIn("Restore another copy", self.source)
        self.assertIn("prepareAnotherNativeCloudRestore()", self.source)
        self.assertIn("nextNativeRestoreName()", self.source)
        self.assertIn("for (let sequence = 2; sequence <= 999; sequence += 1)", self.source)
        self.assertIn("base.slice(0, 63 - suffix.length)", self.source)
        self.assertIn("if (!existing.has(candidate)) return candidate", self.source)
        self.assertIn("this.nativeRestore.requestId = null", self.source)
        self.assertIn("this.nativeRestore.requestTargetName = ''", self.source)
        self.assertIn("this.nativeRestore.confirm = false", self.source)
        self.assertIn("this.nativeRestoreStarted = false", self.source)

    def test_status_categories_are_distinct_and_diagnostics_are_surfaceable(self):
        for category in (
            "queued",
            "running",
            "adopting",
            "retry",
            "manual_review",
            "failed",
            "complete",
        ):
            with self.subTest(category=category):
                self.assertIn(f"return '{category}'", self.source)
        for label in (
            "Queued",
            "Running",
            "Adopting provider resource",
            "Retry scheduled",
            "Manual review required",
            "Failed",
            "Complete",
            "Provider resource ID:",
            "Provider job ID:",
            "Correlation ID",
            "Error code:",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.source)

        error_block = self.source.split("nativeRestoreStatusError(item)", 1)[1].split(
            "nativeRestoreStatusIsTerminal(item)", 1
        )[0]
        self.assertIn("view.errorMessage", error_block)
        self.assertNotIn("item.error", error_block)
        self.assertIn("QUOTA_EXCEEDED", self.source)

    def test_hidden_native_restore_details_guard_null_status(self):
        guarded_expressions = (
            "nativeRestoreStatus && nativeRestoreStatus.execution_status ? nativeRestoreStatus.execution_status.provider_status : ''",
            "nativeRestoreStatus ? nativeRestoreStatus.resource_id : ''",
            "nativeRestoreStatus ? nativeRestoreStatus.provider_job_id : ''",
            "nativeRestoreStatus && nativeRestoreStatus.execution_status ? nativeRestoreStatus.execution_status.next_retry_at : ''",
            "nativeRestoreStatus && nativeRestoreStatus.execution_status ? nativeRestoreStatus.execution_status.last_error_code : ''",
        )
        for expression in guarded_expressions:
            with self.subTest(expression=expression):
                self.assertIn(f'x-text="{expression}"', self.source)

        for unsafe_expression in (
            'x-text="nativeRestoreStatus.execution_status.provider_status"',
            'x-text="nativeRestoreStatus.resource_id"',
            'x-text="nativeRestoreStatus.provider_job_id"',
            'x-text="nativeRestoreStatus.execution_status.next_retry_at"',
            'x-text="nativeRestoreStatus.execution_status.last_error_code"',
        ):
            with self.subTest(unsafe_expression=unsafe_expression):
                self.assertNotIn(unsafe_expression, self.source)

    def test_in_progress_reconciliation_does_not_stop_browser_polling(self):
        shared_category = self.source.split(
            "function categoryFor({status, phase, providerStatus, reconciliationState, errorCode, retryAt})",
            1,
        )[1].split("function toneClasses", 1)[0]
        self.assertIn("const terminalFailure", shared_category)
        self.assertIn(
            "terminalFailure && errorCode && manualReviewErrorPattern.test(errorCode)",
            shared_category,
        )
        self.assertNotIn(
            "(errorCode && manualReviewErrorPattern.test(errorCode))",
            shared_category,
        )

        native_category = self.source.split(
            "nativeRestoreStatusCategory(item)", 1
        )[1].split("nativeRestoreStatusLabel(item)", 1)[0]
        self.assertIn("const terminalFailure", native_category)
        self.assertIn("(terminalFailure && /UNKNOWN|AMBIGUOUS", native_category)

        terminal_check = self.source.split(
            "nativeRestoreStatusIsTerminal(item)", 1
        )[1].split("nativeRestoreId(value)", 1)[0]
        self.assertIn("execution.status", terminal_check)
        self.assertIn("raw.operation_phase", terminal_check)
        self.assertNotIn("this.nativeRestoreStatusCategory(item)", terminal_check)

    def test_vultr_managed_database_uses_native_restore_contract(self):
        self.assertIn(
            "object.type == 1 or object.type == 2 or is_vultr_managed_database",
            self.source,
        )
        self.assertIn(
            "{% elif is_vultr_managed_database %}vultr_database",
            self.source,
        )
        self.assertIn(
            "{% elif is_vultr_managed_database %}managed database cluster",
            self.source,
        )
        self.assertIn(
            "const backupApiCode = '{% if is_vultr_managed_database %}vultr_database",
            self.source,
        )
        self.assertIn(
            "object.type == 4 and not is_vultr_managed_database",
            self.source,
        )

    def test_safe_defaults_and_no_arbitrary_provider_json(self):
        self.assertIn("nativeRestoreDefaultName(backupUuid)", self.source)
        self.assertIn("nativeRestoreConfig.sourceName", self.source)
        self.assertIn("replace(/[^a-z0-9]/g, '')", self.source)
        self.assertIn(".slice(0, 63)", self.source)
        self.assertIn("<strong class=\"font-semibold\">Safe fork:</strong>", self.source)
        self.assertIn("In-place restore is not available from this screen.", self.source)
        modal = self.source.split("<!-- Native cloud restore modal -->", 1)[1].split(
            "<!-- Transfer backup modal -->", 1
        )[0]
        self.assertNotIn("<textarea", modal)
        self.assertNotIn("JSON.parse", modal)
        self.assertIn("params,", self.source)

    def test_aws_resource_labels_and_s3_dynamodb_mapping_are_explicit(self):
        for label in (
            "S3 bucket",
            "DynamoDB table",
            "EBS volume",
            "EC2 instance",
            "RDS database",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.source)
        for kind in ("aws_s3", "aws_dynamodb", "aws_volume", "aws_instance", "aws_rds"):
            with self.subTest(kind=kind):
                self.assertIn(kind, self.source)
        self.assertIn("Existing destination S3 bucket", self.source)
        self.assertIn("has versioning enabled", self.source)
        self.assertIn('pattern="[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"', self.source)
