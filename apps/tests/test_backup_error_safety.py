from unittest import mock

from django.test import SimpleTestCase

from apps._tasks.integration.backup.errors import safe_backup_failure
from apps._tasks.exceptions import NodeBackupFailedError
from apps.api.v1.utils.api_helpers import get_error
from apps.console.vultr import record_provider_result


class BackupErrorSafetyTests(SimpleTestCase):
    def test_secret_bearing_provider_error_is_never_returned(self):
        canary = "Bearer live-token password=database-secret host=db.internal"

        failure = safe_backup_failure(
            RuntimeError(f"export command failed: {canary}"),
            stage="database_backup",
        )

        self.assertEqual(failure.code, "SOURCE_EXPORT_FAILED")
        self.assertNotIn(canary, failure.detail)
        self.assertNotIn("live-token", failure.detail)
        self.assertNotIn("db.internal", failure.detail)
        self.assertTrue(failure.retryable)

    def test_timeout_and_disk_full_are_distinguishable(self):
        timeout = safe_backup_failure(TimeoutError("secret timeout URL"))
        disk = safe_backup_failure(OSError("No space left on device /private/path"))

        self.assertEqual(timeout.code, "BACKUP_TIMEOUT")
        self.assertTrue(timeout.retryable)
        self.assertEqual(disk.code, "WORKER_DISK_FULL")
        self.assertTrue(disk.retryable)
        self.assertNotIn("/private/path", disk.detail)

    def test_legacy_provider_error_helper_never_returns_exception_text(self):
        canary = (
            "https://api.example.invalid/object?X-Amz-Credential=secret-canary "
            "Authorization=Bearer provider-token"
        )

        detail = get_error(RuntimeError(canary))

        self.assertNotIn("secret-canary", detail)
        self.assertNotIn("provider-token", detail)
        self.assertNotIn("api.example.invalid", detail)
        self.assertIn("provider operation failed", detail.lower())

    def test_vultr_result_metadata_never_persists_exception_text(self):
        canary = "Authorization=Bearer provider-token signed-url=secret-canary"

        metadata = record_provider_result(
            {},
            classification="transient_provider_error",
            status_code=503,
            error=RuntimeError(canary),
        )

        serialized = str(metadata)
        self.assertNotIn("provider-token", serialized)
        self.assertNotIn("secret-canary", serialized)
        self.assertEqual(
            metadata["vultr_last_result"]["classification"],
            "transient_provider_error",
        )
        self.assertIn("retry", metadata["vultr_last_result"]["message"].lower())

    def test_node_backup_failure_never_persists_diagnostic_text(self):
        canary = "password=db-secret signed-url=https://secret.invalid/object"
        account = mock.Mock()
        node = mock.Mock()
        node.id = 42
        node.name = "source"
        node.connection.id = 7
        node.connection.name = "connection"
        node.connection.account = account

        error = NodeBackupFailedError(
            node,
            backup_uuid="safe-backup-id",
            attempt_no=1,
            backup_type=1,
            message=f"mysqldump failed: {canary}",
        )

        logged = account.create_log.call_args.args[0]
        self.assertNotIn("db-secret", str(logged))
        self.assertNotIn("secret.invalid", str(logged))
        self.assertNotIn("db-secret", str(error.detail))
        self.assertNotIn("secret.invalid", str(error.detail))
        self.assertEqual(logged["error_code"], error.error_code)
        self.assertEqual(logged["message"], error.public_message)
