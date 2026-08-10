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

    def test_restore_action_is_available_only_for_terminal_native_backups(self):
        self.assertIn("{% elif object.type == 1 or object.type == 2 %}", self.source)
        self.assertIn(
            "openNativeCloudRestoreModal('{{ backup.id }}', '{{ backup.uuid }}', '{{ backup.status }}')",
            self.source,
        )
        self.assertIn("{% if backup.status == 3 %}", self.source)
        self.assertIn("if (String(backupStatus) !== '3') return;", self.source)
        self.assertIn("this.nativeRestoreStarted ||", self.source)

    def test_post_contract_is_explicit_and_uses_provider_minimal_fields(self):
        self.assertIn(
            "`/api/v1/nodes/${encodeURIComponent(this.node_id || nativeRestoreConfig.nodeId)}/restore_backup/`",
            self.source,
        )
        self.assertIn("backup_id: Number(this.nativeRestore.backupId)", self.source)
        self.assertIn("confirm: true", self.source)
        self.assertIn("request_id: this.nativeRestoreRequestId()", self.source)
        self.assertIn("params.destination_bucket_name = targetName", self.source)
        self.assertIn("params.target_table_name = targetName", self.source)
        self.assertIn("if (response.status !== 200 && response.status !== 201)", self.source)
        self.assertIn("idempotent_replay", self.source)

    def test_request_id_is_stable_for_retries_but_changes_for_a_new_target(self):
        self.assertIn("if (this.nativeRestore.requestId && this.nativeRestore.requestTargetName === targetName)", self.source)
        self.assertIn("window.crypto.randomUUID()", self.source)
        self.assertIn("this.nativeRestore.requestTargetName = targetName", self.source)
        self.assertGreaterEqual(self.source.count("requestId: null"), 3)
        # A fetch failure reconciles the existing durable row; it does not call
        # openNativeCloudRestoreModal or reset requestId before the next attempt.
        retry_block = self.source.split("async startNativeCloudRestore()", 1)[1].split(
            "clearRestorePoll()", 1
        )[0]
        self.assertIn("await this.getNativeCloudRestores(false)", retry_block)
        self.assertNotIn("requestId = null", retry_block)

    def test_reload_recovery_and_polling_use_node_restore_list(self):
        self.assertIn(
            "`/api/v1/nodes/${encodeURIComponent(this.node_id || nativeRestoreConfig.nodeId)}/restores/`",
            self.source,
        )
        self.assertIn("String(item.backup_id) === String(this.nativeRestore.backupId)", self.source)
        self.assertIn("adoptNativeRestoreTargetIfPresent()", self.source)
        self.assertIn("startNativeRestorePolling()", self.source)
        self.assertIn("clearNativeRestorePoll()", self.source)
        self.assertIn("this.nativeRestoreStatusIsTerminal(this.nativeRestoreStatus)", self.source)
        self.assertIn("A lost response can still mean the API created the durable", self.source)

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
