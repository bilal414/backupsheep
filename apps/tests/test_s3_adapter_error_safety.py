from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError
from django.test import SimpleTestCase

from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadOutcomePending,
    S3UploadReconciliationRequired,
)
from apps.tests.test_s3_compatible_storage_adapters import (
    ADAPTERS,
    _stored_backup,
)


CANARY = "provider-body-secret-canary-7f6a"
PRIVATE_URL = "https://provider.invalid/private-response"
ADAPTER_PATHS = tuple(
    Path(__file__).resolve().parents[1]
    / "_tasks"
    / "integration"
    / "storage"
    / f"{spec.module}.py"
    for spec in ADAPTERS
)


def _client_error(code, status, *, retry_after=None):
    headers = {
        "x-amz-request-id": CANARY,
        "content-location": PRIVATE_URL,
    }
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return ClientError(
        {
            "Error": {"Code": code, "Message": CANARY},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "HTTPHeaders": headers,
            },
        },
        "PutObject",
    )


class S3CompatibleAdapterErrorSafetyTests(SimpleTestCase):
    def _invoke(self, spec, failure):
        module_name = f"apps._tasks.integration.storage.{spec.module}"
        module = __import__(module_name, fromlist=[spec.function])
        point, _provider = _stored_backup(spec)
        with mock.patch(f"{module_name}.boto3.client"), mock.patch(
            f"{module_name}.bs_decrypt", return_value="secret"
        ), mock.patch(f"{module_name}.upload_verified_s3", side_effect=failure):
            with self.assertRaises(Exception) as raised:
                getattr(module, spec.function)(point)
        return raised.exception, failure

    def test_all_adapters_redact_auth_response_bodies_and_preserve_cause(self):
        for spec in ADAPTERS:
            with self.subTest(provider=spec.module):
                wrapped, original = self._invoke(
                    spec, _client_error("AccessDenied", 403)
                )
                public_text = str(wrapped)
                self.assertNotIn(CANARY, public_text)
                self.assertNotIn(PRIVATE_URL, public_text)
                self.assertEqual(wrapped.error_code, "STORAGE_AUTH_FAILED")
                self.assertEqual(wrapped.code, "STORAGE_AUTH_FAILED")
                self.assertFalse(wrapped.retryable)
                self.assertIsNone(wrapped.retry_after)
                self.assertIs(wrapped.__cause__, original)

    def test_rate_limit_exposes_bounded_retry_hint_without_provider_text(self):
        for spec in ADAPTERS:
            with self.subTest(provider=spec.module):
                wrapped, _original = self._invoke(
                    spec,
                    _client_error("SlowDown", 429, retry_after="17"),
                )
                self.assertNotIn(CANARY, str(wrapped))
                self.assertEqual(wrapped.error_code, "STORAGE_RATE_LIMITED")
                self.assertEqual(wrapped.code, "STORAGE_RATE_LIMITED")
                self.assertTrue(wrapped.retryable)
                self.assertEqual(wrapped.retry_after, 17)

    def test_timeout_integrity_and_reconciliation_have_distinct_codes(self):
        cases = (
            (
                TimeoutError(CANARY),
                "STORAGE_TIMEOUT",
                True,
            ),
            (
                S3ObjectIntegrityError(CANARY),
                "STORAGE_INTEGRITY_FAILED",
                False,
            ),
            (
                S3UploadReconciliationRequired(CANARY),
                "STORAGE_RECONCILIATION_REQUIRED",
                False,
            ),
        )
        for failure, expected_code, expected_retryable in cases:
            for spec in ADAPTERS:
                with self.subTest(provider=spec.module, code=expected_code):
                    wrapped, original = self._invoke(spec, failure)
                    self.assertNotIn(CANARY, str(wrapped))
                    self.assertEqual(wrapped.error_code, expected_code)
                    self.assertEqual(wrapped.code, expected_code)
                    self.assertEqual(wrapped.retryable, expected_retryable)
                    self.assertIs(wrapped.__cause__, original)

    def test_vultr_preserves_retryable_outcome_pending_contract(self):
        from apps._tasks.integration.storage.vultr import _safe_s3_failure

        pending = S3UploadOutcomePending(CANARY, retry_after=23)

        failure = _safe_s3_failure(pending)

        self.assertNotIn(CANARY, failure.message)
        self.assertEqual(failure.code, "STORAGE_RECONCILIATION_PENDING")
        self.assertTrue(failure.retryable)
        self.assertEqual(failure.retry_after, 23)

    def test_task_classifies_pending_as_retry_and_conflicts_as_manual_review(self):
        from apps._tasks.integration.storage.tasks import _storage_error_outcome

        point = SimpleNamespace(
            Status=SimpleNamespace(
                UPLOAD_RETRY="upload_retry",
                STORAGE_VALIDATION_FAILED="storage_validation_failed",
            )
        )
        pending = S3UploadOutcomePending("zero new uploads are visible yet")

        code, _message, status, retryable = _storage_error_outcome(pending, point)

        self.assertEqual(code, "STORAGE_RECONCILIATION_PENDING")
        self.assertEqual(status, point.Status.UPLOAD_RETRY)
        self.assertTrue(retryable)

        for message in (
            "multiple new uploads matched the baseline",
            "the new upload has a foreign owner identity",
        ):
            with self.subTest(message=message):
                conflict = S3UploadReconciliationRequired(message)
                code, _message, status, retryable = _storage_error_outcome(
                    conflict, point
                )
                self.assertEqual(code, "STORAGE_RECONCILIATION_REQUIRED")
                self.assertEqual(status, point.Status.STORAGE_VALIDATION_FAILED)
                self.assertFalse(retryable)

    def test_bad_provider_request_is_fail_closed_as_malformed_response(self):
        for spec in ADAPTERS:
            with self.subTest(provider=spec.module):
                wrapped, _original = self._invoke(
                    spec, _client_error("InvalidRequest", 400)
                )
                self.assertNotIn(CANARY, str(wrapped))
                self.assertEqual(wrapped.error_code, "PROVIDER_MALFORMED_RESPONSE")
                self.assertFalse(wrapped.retryable)

    def test_filebase_quota_and_spaces_bucket_codes_remain_typed_but_safe(self):
        filebase = next(spec for spec in ADAPTERS if spec.module == "filebase")
        wrapped, _original = self._invoke(
            filebase, _client_error("QuotaExceeded", 507)
        )
        self.assertEqual(wrapped.__class__.__name__, "StorageFilebaseQuotaExceededError")
        self.assertEqual(wrapped.error_code, "STORAGE_QUOTA_EXCEEDED")
        self.assertNotIn(CANARY, str(wrapped))

        spaces = next(spec for spec in ADAPTERS if spec.module == "do_spaces")
        wrapped, _original = self._invoke(spaces, _client_error("NoSuchBucket", 404))
        self.assertEqual(wrapped.__class__.__name__, "NodeDigitalOceanSpacesNoSuchBucketError")
        self.assertEqual(wrapped.error_code, "STORAGE_DESTINATION_NOT_FOUND")
        self.assertNotIn(CANARY, str(wrapped))

    def test_legacy_delete_helpers_require_backup_marker_and_use_exact_version(self):
        for module_suffix, function_name, relation in (
            ("do_spaces", "storage_do_spaces_delete", "storage_do_spaces"),
            ("wasabi", "storage_wasabi_delete", "storage_wasabi"),
        ):
            with self.subTest(provider=module_suffix):
                module_name = f"apps._tasks.integration.storage.{module_suffix}"
                module = __import__(module_name, fromlist=[function_name])
                provider = SimpleNamespace(
                    access_key=b"encrypted-access",
                    secret_key=b"encrypted-secret",
                    bucket_name="test-bucket",
                    region=SimpleNamespace(endpoint="region.example"),
                )
                backup = SimpleNamespace(
                    id=42,
                    storage_byo=SimpleNamespace(**{relation: provider}),
                    storage_file_id="owned/backup.zip",
                )
                node = SimpleNamespace(
                    type=module.CoreNode.Type.WEBSITE,
                    connection=SimpleNamespace(
                        account=SimpleNamespace(
                            get_encryption_key=lambda: b"encryption-key"
                        )
                    ),
                )
                client = mock.Mock()
                client.head_object.return_value = {
                    "VersionId": "v-42",
                    "Metadata": {"backupsheep-backup-id": "42"},
                }
                with mock.patch.object(
                    module.CoreWebsiteBackup.objects, "get", return_value=backup
                ), mock.patch.object(module, "_s3_client", return_value=client):
                    getattr(module, function_name)(node, "backup-uuid")
                client.head_object.assert_called_once_with(
                    Bucket="test-bucket", Key="owned/backup.zip"
                )
                client.delete_object.assert_called_once_with(
                    Bucket="test-bucket", Key="owned/backup.zip", VersionId="v-42"
                )

    def test_adapter_sources_do_not_format_caught_exception_text(self):
        for path in ADAPTER_PATHS:
            with self.subTest(path=path.name):
                source = path.read_text()
                self.assertNotIn("str(error)", source)
                self.assertNotIn("f\"{error}", source)
