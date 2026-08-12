import hashlib
import io
import os
import shutil
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError
from django.test import SimpleTestCase

from apps._tasks.integration import restore_common


class _ArtifactQuery:
    def __init__(self, records=()):
        self.records = list(records)

    def filter(self, **_kwargs):
        return self

    def exclude(self, **_kwargs):
        return self

    def exists(self):
        return bool(self.records)

    def values_list(self, field, flat=False):
        return [getattr(record, field, None) for record in self.records]

    def __iter__(self):
        return iter(self.records)


PROVIDERS = (
    ("do_spaces", "do_spaces_s3_object", "do_spaces", "DigitalOcean Spaces"),
    ("upcloud", "upcloud_s3_object", "upcloud", "UpCloud Object Storage"),
    ("oracle", "oracle_s3_object", "oracle", "Oracle Object Storage"),
    ("vultr", "vultr_s3_object", "vultr", "Vultr Object Storage"),
)


class S3CompatibleRestoreIntegrityTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="backupsheep-s3-restore-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.payload = b"PK\x03\x04" + (b"authenticated exact restore\n" * 17)
        self.checksum = hashlib.sha256(self.payload).hexdigest()

    @staticmethod
    def _provider_config(provider):
        values = {
            "do_spaces": SimpleNamespace(
                bucket_name="spaces-bucket",
                region=SimpleNamespace(endpoint="nyc3.digitaloceanspaces.com"),
            ),
            "upcloud": SimpleNamespace(
                bucket_name="upcloud-bucket",
                endpoint="safe1.upcloudobjects.com",
            ),
            "oracle": SimpleNamespace(
                bucket_name="oracle-bucket",
                namespace="objectnamespace",
                region=SimpleNamespace(code="us-ashburn-1"),
            ),
            "vultr": SimpleNamespace(
                bucket_name="vultr-bucket",
                endpoint="ewr1.vultrobjects.com",
            ),
        }
        return values[provider]

    def _point(self, provider, *, version_id="version-1", records=()):
        config = self._provider_config(provider)
        key = f"backups/{provider}/exact.zip"
        backup_id = 417
        state = {
            "phase": "committed",
            "bucket": config.bucket_name,
            "object_key": key,
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
            "checksum_algorithm": "sha256",
            "ownership_marker": str(backup_id),
            "etag": '"etag-committed"',
            "version_id": version_id,
        }
        storage = SimpleNamespace(
            type=SimpleNamespace(code=provider),
            account=SimpleNamespace(get_encryption_key=lambda: b"encryption-key"),
            **{f"storage_{provider}": config},
        )
        backup = SimpleNamespace(
            id=backup_id,
            artifact_records=_ArtifactQuery(records),
        )
        point = SimpleNamespace(
            backup=backup,
            backup_id=backup_id,
            storage=storage,
            storage_id=23,
            storage_file_id=key,
            metadata={
                {
                    "do_spaces": "do_spaces_s3_object",
                    "upcloud": "upcloud_s3_object",
                    "oracle": "oracle_s3_object",
                    "vultr": "vultr_s3_object",
                }[provider]: state
            },
            committed_version_id=mock.Mock(return_value=version_id),
            generate_download_url=mock.Mock(return_value="https://legacy.invalid/object"),
            save=mock.Mock(),
        )
        return point, config, key, state

    def _head(self, point, state, **overrides):
        head = {
            "ContentLength": len(self.payload),
            "ETag": state["etag"],
            "VersionId": state["version_id"],
            "Metadata": {
                "backupsheep-backup-id": state["ownership_marker"],
                "backupsheep-sha256": self.checksum,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }
        head.update(overrides)
        return head

    @staticmethod
    def _client_patch(stack, module, client):
        return stack.enter_context(
            mock.patch(
                f"apps._tasks.integration.storage.{module}._s3_client",
                return_value=client,
            )
        )

    def _run_success(self, provider):
        point, config, key, state = self._point(provider)
        head = self._head(point, state)
        client = mock.Mock(name=f"{provider}-client")
        client.head_object.side_effect = [dict(head), dict(head)]
        client.get_object.return_value = {**head, "Body": io.BytesIO(self.payload)}
        destination = os.path.join(self.tmp, f"{provider}.zip")

        with ExitStack() as stack:
            factory = self._client_patch(stack, provider, client)
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), self.payload)
        point.generate_download_url.assert_not_called()
        request = {"Bucket": config.bucket_name, "Key": key, "VersionId": "version-1"}
        client.head_object.assert_called_with(**request)
        client.get_object.assert_called_once_with(**request)
        self.assertEqual(client.head_object.call_count, 2)
        if provider == "vultr":
            factory.assert_called_once_with(point.storage, b"encryption-key")
        else:
            factory.assert_called_once_with(
                getattr(point.storage, f"storage_{provider}"),
                b"encryption-key",
            )

    def test_successful_exact_download_for_all_required_providers(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                self._run_success(provider)

    def test_bucket_drift_is_rejected_before_object_access_for_all_providers(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, config, _key, _state = self._point(provider)
                config.bucket_name = "mutated-bucket"
                client = mock.Mock(name=f"{provider}-client")
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-bucket-drift.zip"),
                        )

                self.assertEqual(raised.exception.code, "PROVIDER_STATE_CONFLICT")
                client.head_object.assert_not_called()
                client.get_object.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_committed_legacy_state_binds_bucket_after_exact_read_only_head(self):
        point, config, _key, state = self._point("vultr")
        state.pop("bucket")
        client = mock.Mock(name="vultr-client")
        head = self._head(point, state)
        client.head_object.side_effect = [dict(head), dict(head)]
        client.get_object.return_value = {**head, "Body": io.BytesIO(self.payload)}
        destination = os.path.join(self.tmp, "vultr-legacy-no-bucket.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), self.payload)
        self.assertEqual(point.metadata["vultr_s3_object"]["bucket"], config.bucket_name)
        point.save.assert_called_once_with(update_fields=["metadata", "modified"])
        point.generate_download_url.assert_not_called()

    def test_legacy_bucket_is_not_bound_when_exact_head_is_missing_or_mismatched(self):
        for outcome in ("missing", "mismatched"):
            with self.subTest(outcome=outcome):
                point, _config, _key, state = self._point("vultr")
                state.pop("bucket")
                client = mock.Mock(name=f"vultr-{outcome}-client")
                if outcome == "missing":
                    client.head_object.side_effect = ClientError(
                        {"Error": {"Code": "NoSuchKey", "Message": "missing"}},
                        "HeadObject",
                    )
                else:
                    client.head_object.return_value = self._head(
                        point,
                        state,
                        Metadata={
                            "backupsheep-backup-id": "foreign-backup",
                            "backupsheep-sha256": self.checksum,
                            "backupsheep-bytes": str(len(self.payload)),
                        },
                    )

                with mock.patch(
                    "apps._tasks.integration.storage.vultr._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError):
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"vultr-legacy-{outcome}.zip"),
                        )

                self.assertNotIn("bucket", point.metadata["vultr_s3_object"])
                point.save.assert_not_called()
                client.get_object.assert_not_called()
                client.put_object.assert_not_called()
                client.create_multipart_upload.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_aws_legacy_state_binds_bucket_after_exact_authenticated_head(self):
        key = "backups/aws/exact.zip"
        state = {
            "phase": "committed",
            "object_key": key,
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
            "ownership_marker": "417",
            "etag": '"etag-committed"',
            "version_id": "version-1",
        }
        head = {
            "ContentLength": len(self.payload),
            "ETag": state["etag"],
            "VersionId": state["version_id"],
        }
        client = mock.Mock(name="aws-client")
        client.head_object.side_effect = [dict(head), dict(head)]
        client.get_object.return_value = {**head, "Body": io.BytesIO(self.payload)}
        storage_config = SimpleNamespace(
            _connection_values=mock.Mock(
                return_value={
                    "bucket_name": "legacy-aws-bucket",
                    "expected_bucket_owner": "123456789012",
                }
            ),
            _s3_client=mock.Mock(return_value=client),
            expected_bucket_owner_kwargs=mock.Mock(
                return_value={"ExpectedBucketOwner": "123456789012"}
            ),
        )
        point = SimpleNamespace(
            metadata={"aws_s3_object": state},
            storage=SimpleNamespace(storage_aws_s3=storage_config),
            storage_file_id=key,
            storage_id=23,
            backup=SimpleNamespace(artifact_records=_ArtifactQuery()),
            committed_version_id=mock.Mock(return_value="version-1"),
            verify_s3_head_ownership=mock.Mock(),
            save=mock.Mock(),
        )

        restore_common._aws_s3_download(
            point,
            os.path.join(self.tmp, "aws-legacy-no-bucket.zip"),
            {"size_bytes": len(self.payload), "sha256": self.checksum},
        )

        self.assertEqual(
            point.metadata["aws_s3_object"]["bucket"], "legacy-aws-bucket"
        )
        point.save.assert_called_once_with(update_fields=["metadata", "modified"])
        client.get_object.assert_called_once()

    def test_aws_exact_restore_rejects_bucket_drift_before_client_creation(self):
        storage_config = SimpleNamespace(
            _connection_values=mock.Mock(
                return_value={
                    "bucket_name": "mutated-bucket",
                    "expected_bucket_owner": "123456789012",
                }
            ),
            _s3_client=mock.Mock(),
        )
        point = SimpleNamespace(
            metadata={
                "aws_s3_object": {
                    "phase": "committed",
                    "bucket": "committed-bucket",
                }
            },
            storage=SimpleNamespace(storage_aws_s3=storage_config),
            storage_file_id="backups/aws/exact.zip",
        )

        with self.assertRaises(restore_common.RestoreError) as raised:
            restore_common._aws_s3_download(
                point,
                os.path.join(self.tmp, "aws-bucket-drift.zip"),
                {"size_bytes": len(self.payload), "sha256": self.checksum},
            )

        self.assertEqual(raised.exception.code, "PROVIDER_STATE_CONFLICT")
        storage_config._s3_client.assert_not_called()

    def test_version_drift_is_rejected_before_get_for_all_providers(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, _config, _key, state = self._point(provider)
                client = mock.Mock(name=f"{provider}-client")
                client.head_object.return_value = self._head(
                    point,
                    state,
                    VersionId="version-2",
                )
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-version-drift.zip"),
                        )
                self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
                self.assertIn("committed", str(raised.exception))
                client.get_object.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_etag_drift_is_rejected_before_get_for_all_providers(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, _config, _key, state = self._point(provider)
                client = mock.Mock(name=f"{provider}-client")
                client.head_object.return_value = self._head(
                    point,
                    state,
                    ETag='"etag-different"',
                )
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-etag-drift.zip"),
                        )
                self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
                client.get_object.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_ownership_marker_mismatch_is_rejected_without_legacy_fallback(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, _config, _key, state = self._point(provider)
                client = mock.Mock(name=f"{provider}-client")
                client.head_object.return_value = self._head(
                    point,
                    state,
                    Metadata={
                        "backupsheep-backup-id": "different-backup",
                        "backupsheep-sha256": self.checksum,
                        "backupsheep-bytes": str(len(self.payload)),
                    },
                )
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-ownership.zip"),
                        )
                self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
                client.get_object.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_404_is_classified_redacted_and_never_falls_back(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, _config, _key, _state = self._point(provider)
                client = mock.Mock(name=f"{provider}-client")
                client.head_object.side_effect = ClientError(
                    {
                        "Error": {"Code": "NoSuchKey", "Message": "secret-body"},
                        "ResponseMetadata": {"HTTPStatusCode": 404},
                    },
                    "HeadObject",
                )
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-404.zip"),
                        )
                self.assertEqual(raised.exception.code, "PROVIDER_NOT_FOUND")
                self.assertNotIn("secret-body", str(raised.exception))
                client.get_object.assert_not_called()
                point.generate_download_url.assert_not_called()

    def test_timeout_auth_rate_limit_and_transient_failures_are_safe(self):
        failures = (
            (TimeoutError("credential-canary"), "PROVIDER_TIMEOUT", True),
            (
                ClientError(
                    {
                        "Error": {"Code": "AccessDenied", "Message": "body-canary"},
                        "ResponseMetadata": {"HTTPStatusCode": 403},
                    },
                    "HeadObject",
                ),
                "PROVIDER_AUTH_FAILED",
                False,
            ),
            (
                ClientError(
                    {
                        "Error": {"Code": "SlowDown", "Message": "body-canary"},
                        "ResponseMetadata": {
                            "HTTPStatusCode": 429,
                            "HTTPHeaders": {"retry-after": "12"},
                        },
                    },
                    "HeadObject",
                ),
                "PROVIDER_RATE_LIMITED",
                True,
            ),
            (ConnectionError("connection-canary"), "PROVIDER_TRANSIENT_FAILURE", True),
        )
        for provider, _state_key, _module, _label in PROVIDERS:
            for error, code, retryable in failures:
                with self.subTest(provider=provider, code=code):
                    point, _config, _key, _state = self._point(provider)
                    client = mock.Mock(name=f"{provider}-client")
                    client.head_object.side_effect = error
                    with mock.patch(
                        f"apps._tasks.integration.storage.{provider}._s3_client",
                        return_value=client,
                    ):
                        with self.assertRaises(restore_common.RestoreError) as raised:
                            restore_common.fetch_backup_zip(
                                point,
                                os.path.join(self.tmp, f"{provider}-{code}.zip"),
                            )
                    self.assertEqual(raised.exception.code, code)
                    self.assertEqual(raised.exception.retryable, retryable)
                    self.assertNotIn("canary", str(raised.exception))
                    point.generate_download_url.assert_not_called()

    def test_destination_ledger_without_provider_state_cannot_use_legacy_url(self):
        record = SimpleNamespace(
            storage_id=23,
            role="destination",
            object_key="backups/do_spaces/exact.zip",
            byte_count=len(self.payload),
            checksum_algorithm="sha256",
            checksum_value=self.checksum,
            etag='"etag-committed"',
            version_id="version-1",
            verified_at=object(),
        )
        point, _config, _key, _state = self._point("do_spaces", records=[record])
        point.metadata = {}

        with self.assertRaises(restore_common.RestoreError) as raised:
            restore_common.fetch_backup_zip(
                point,
                os.path.join(self.tmp, "missing-provider-state.zip"),
            )

        self.assertEqual(raised.exception.code, "MISSING_PROVIDER_STATE")
        point.generate_download_url.assert_not_called()
