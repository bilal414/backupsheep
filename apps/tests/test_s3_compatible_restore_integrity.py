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

from apps._tasks.artifact_encryption import StorageArtifactIdentity
from apps._tasks.integration import restore_common
from apps.console.backup.models import CoreWebsiteBackupStoragePoints


BSE_ENVELOPE_UUID = "23cc9ced-eb5a-4b3a-959a-6c4f72fa1337"
BSE_IDENTITY = StorageArtifactIdentity(
    identifier=BSE_ENVELOPE_UUID,
    filename=f"{BSE_ENVELOPE_UUID}.bse1",
    artifact_format="bse1",
    ownership_marker=f"bse2:{BSE_ENVELOPE_UUID}",
    content_type="application/octet-stream",
)


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

    def _point(self, provider, *, version_id="version-1", records=(), bse=False):
        config = self._provider_config(provider)
        key = (
            f"backups/{provider}/{BSE_IDENTITY.filename}"
            if bse
            else f"backups/{provider}/exact.zip"
        )
        backup_id = 417
        state = {
            "phase": "committed",
            "bucket": config.bucket_name,
            "object_key": key,
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
            "checksum_algorithm": "sha256",
            "ownership_marker": (
                BSE_IDENTITY.ownership_marker if bse else str(backup_id)
            ),
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
            uuid_str="exact",
            artifact_records=_ArtifactQuery(records),
        )
        if bse:
            backup.uuid_str = "c05995a5-b5ca-498c-9e54-47708063e46a"
            backup.get_execution_state = mock.Mock()
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
        marker_key = (
            "backupsheep-artifact-id"
            if str(state["ownership_marker"]).startswith("bse2:")
            else "backupsheep-backup-id"
        )
        head = {
            "ContentLength": len(self.payload),
            "ETag": state["etag"],
            "VersionId": state["version_id"],
            "Metadata": {
                marker_key: state["ownership_marker"],
                "backupsheep-sha256": self.checksum,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }
        head.update(overrides)
        return head

    @staticmethod
    def _bse_context(point):
        active = SimpleNamespace(
            envelope=SimpleNamespace(uuid=BSE_ENVELOPE_UUID),
        )
        stack = ExitStack()
        stack.enter_context(
            mock.patch(
                "apps._tasks.artifact_encryption._load_active_source_state",
                return_value=active,
            )
        )
        stack.enter_context(
            mock.patch.object(
                restore_common,
                "restore_encryption_plan",
                return_value=None,
            )
        )
        return stack

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

    def test_bse_exact_restore_uses_opaque_marker_and_key_for_all_providers(self):
        for provider, _state_key, _module, _label in PROVIDERS:
            with self.subTest(provider=provider):
                point, config, key, state = self._point(provider, bse=True)
                head = self._head(point, state)
                client = mock.Mock(name=f"{provider}-bse-client")
                client.head_object.side_effect = [dict(head), dict(head)]
                client.get_object.return_value = {
                    **head,
                    "Body": io.BytesIO(self.payload),
                }
                destination = os.path.join(self.tmp, f"{provider}-bse.zip")

                with self._bse_context(point) as stack:
                    self._client_patch(stack, provider, client)
                    restore_common.fetch_backup_zip(point, destination)

                request = {
                    "Bucket": config.bucket_name,
                    "Key": key,
                    "VersionId": "version-1",
                }
                client.get_object.assert_called_once_with(**request)
                self.assertEqual(
                    head["Metadata"]["backupsheep-artifact-id"],
                    BSE_IDENTITY.ownership_marker,
                )
                self.assertNotIn("backupsheep-backup-id", head["Metadata"])
                self.assertNotIn(str(point.backup_id), key)
                self.assertFalse(key.endswith(".zip"))

    def test_bse_restore_rejects_ambiguous_legacy_marker_before_get(self):
        point, _config, _key, state = self._point("do_spaces", bse=True)
        head = self._head(point, state)
        head["Metadata"]["backupsheep-backup-id"] = str(point.backup_id)
        client = mock.Mock(name="do-spaces-ambiguous-bse-client")
        client.head_object.return_value = head

        with self._bse_context(point) as stack:
            self._client_patch(stack, "do_spaces", client)
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(
                    point,
                    os.path.join(self.tmp, "ambiguous-bse.zip"),
                )

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        client.get_object.assert_not_called()

    def test_aws_bse_restore_uses_only_committed_opaque_identity(self):
        key = f"backups/{BSE_IDENTITY.filename}"
        state = {
            "phase": "committed",
            "bucket": "aws-bse-bucket",
            "object_key": key,
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
            "ownership_marker": BSE_IDENTITY.ownership_marker,
            "etag": '"etag-committed"',
            "version_id": "version-1",
        }
        head = {
            "ContentLength": len(self.payload),
            "ETag": state["etag"],
            "VersionId": state["version_id"],
            "Metadata": {
                "backupsheep-artifact-id": BSE_IDENTITY.ownership_marker,
                "backupsheep-sha256": self.checksum,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }
        client = mock.Mock(name="aws-bse-client")
        client.head_object.side_effect = [dict(head), dict(head)]
        client.get_object.return_value = {
            **head,
            "Body": io.BytesIO(self.payload),
        }
        storage_config = SimpleNamespace(
            _connection_values=mock.Mock(
                return_value={
                    "bucket_name": "aws-bse-bucket",
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
            backup_id=417,
            backup=SimpleNamespace(
                id=417,
                uuid_str="c05995a5-b5ca-498c-9e54-47708063e46a",
                artifact_records=_ArtifactQuery(),
                get_execution_state=mock.Mock(),
            ),
            committed_version_id=mock.Mock(return_value="version-1"),
            committed_integrity_identity=mock.Mock(
                return_value={
                    "size_bytes": len(self.payload),
                    "sha256": self.checksum,
                }
            ),
        )
        point.verify_s3_head_ownership = lambda value: (
            CoreWebsiteBackupStoragePoints.verify_s3_head_ownership(point, value)
        )
        destination = os.path.join(self.tmp, "aws-bse.zip")

        with self._bse_context(point):
            restore_common._aws_s3_download(
                point,
                destination,
                {"size_bytes": len(self.payload), "sha256": self.checksum},
            )

        request = {
            "Bucket": "aws-bse-bucket",
            "Key": key,
            "ExpectedBucketOwner": "123456789012",
            "VersionId": "version-1",
        }
        client.get_object.assert_called_once_with(**request)
        self.assertEqual(client.head_object.call_count, 2)
        visible = repr({"key": key, "metadata": head["Metadata"]})
        self.assertNotIn(point.backup.uuid_str, visible)
        self.assertNotIn(str(point.backup_id), visible)
        self.assertNotIn(".zip", visible)

    def test_vultr_multipart_zero_length_head_still_requires_exact_get_stream(self):
        point, config, key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        zero_length_head = self._head(point, state, ContentLength=0)
        exact_get = self._head(point, state)
        client = mock.Mock(name="vultr-zero-length-head-client")
        client.head_object.side_effect = [
            dict(zero_length_head),
            dict(zero_length_head),
        ]
        client.get_object.return_value = {
            **exact_get,
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-zero-length-head.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), self.payload)
        request = {"Bucket": config.bucket_name, "Key": key, "VersionId": "version-1"}
        client.get_object.assert_called_once_with(**request)
        self.assertEqual(client.head_object.call_count, 2)

    def test_vultr_archive_rehydration_defers_before_get(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        client = mock.Mock(name="vultr-archive-client")
        client.head_object.return_value = self._head(
            point,
            state,
            ContentLength=0,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="true"',
        )

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(
                    point,
                    os.path.join(self.tmp, "vultr-archive.zip"),
                )

        self.assertEqual(raised.exception.code, "RESTORE_ARCHIVE_NOT_READY")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(raised.exception.retry_after, 120)
        client.get_object.assert_not_called()

    def test_vultr_rehydrated_archive_downloads_exact_object(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        zero_length_head = self._head(
            point,
            state,
            ContentLength=0,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )
        exact_get = self._head(
            point,
            state,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )
        client = mock.Mock(name="vultr-rehydrated-archive-client")
        client.head_object.side_effect = [
            dict(zero_length_head),
            dict(zero_length_head),
        ]
        client.get_object.return_value = {
            **exact_get,
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-rehydrated-archive.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), self.payload)
        client.get_object.assert_called_once()

    def test_vultr_rehydrated_archive_accepts_stable_transport_etag_change(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        rehydrated_etag = '"fedcba9876543210fedcba9876543210-1025"'
        rehydrated_head = self._head(
            point,
            state,
            ETag=rehydrated_etag,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )
        client = mock.Mock(name="vultr-rehydrated-etag-client")
        client.head_object.side_effect = [
            dict(rehydrated_head),
            dict(rehydrated_head),
        ]
        client.get_object.return_value = {
            **rehydrated_head,
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-rehydrated-etag.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), self.payload)
        client.get_object.assert_called_once()

    def test_vultr_archive_etag_change_still_defers_while_rehydrating(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        client = mock.Mock(name="vultr-rehydrating-etag-client")
        client.head_object.return_value = self._head(
            point,
            state,
            ContentLength=0,
            ETag='"fedcba9876543210fedcba9876543210-1025"',
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="true"',
        )

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(
                    point,
                    os.path.join(self.tmp, "vultr-rehydrating-etag.zip"),
                )

        self.assertEqual(raised.exception.code, "RESTORE_ARCHIVE_NOT_READY")
        client.get_object.assert_not_called()

    def test_vultr_archive_etag_change_requires_multipart_commit_identity(self):
        point, _config, _key, state = self._point("vultr")
        client = mock.Mock(name="vultr-single-part-etag-client")
        client.head_object.return_value = self._head(
            point,
            state,
            ETag='"fedcba9876543210fedcba9876543210-1025"',
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(
                    point,
                    os.path.join(self.tmp, "vultr-single-part-etag.zip"),
                )

        self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
        client.get_object.assert_not_called()

    def test_vultr_rehydrated_transport_etag_must_match_get(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        rehydrated_etag = '"fedcba9876543210fedcba9876543210-1025"'
        rehydrated_head = self._head(
            point,
            state,
            ETag=rehydrated_etag,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )
        client = mock.Mock(name="vultr-rehydrated-get-drift-client")
        client.head_object.return_value = dict(rehydrated_head)
        client.get_object.return_value = {
            **rehydrated_head,
            "ETag": '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1025"',
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-rehydrated-get-drift.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, destination)

        self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
        self.assertFalse(os.path.exists(destination))

    def test_vultr_rehydrated_transport_etag_must_match_final_head(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        rehydrated_etag = '"fedcba9876543210fedcba9876543210-1025"'
        rehydrated_head = self._head(
            point,
            state,
            ETag=rehydrated_etag,
            StorageClass="VULTR_ARCHIVE",
            Restore='ongoing-request="false"',
        )
        final_drift = {
            **rehydrated_head,
            "ETag": '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1025"',
        }
        client = mock.Mock(name="vultr-rehydrated-final-drift-client")
        client.head_object.side_effect = [
            dict(rehydrated_head),
            final_drift,
        ]
        client.get_object.return_value = {
            **rehydrated_head,
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-rehydrated-final-drift.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, destination)

        self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
        self.assertFalse(os.path.exists(destination))

    def test_zero_length_head_exception_is_vultr_multipart_only(self):
        cases = (
            ("do_spaces", '"0123456789abcdef0123456789abcdef-2"'),
            ("upcloud", '"0123456789abcdef0123456789abcdef-2"'),
            ("oracle", '"0123456789abcdef0123456789abcdef-2"'),
            ("vultr", '"etag-committed"'),
        )
        for provider, etag in cases:
            with self.subTest(provider=provider, etag=etag):
                point, _config, _key, state = self._point(provider)
                state["etag"] = etag
                client = mock.Mock(name=f"{provider}-zero-length-head-client")
                client.head_object.return_value = self._head(
                    point,
                    state,
                    ContentLength=0,
                )
                with mock.patch(
                    f"apps._tasks.integration.storage.{provider}._s3_client",
                    return_value=client,
                ):
                    with self.assertRaises(restore_common.RestoreError) as raised:
                        restore_common.fetch_backup_zip(
                            point,
                            os.path.join(self.tmp, f"{provider}-zero-length-head.zip"),
                        )

                self.assertEqual(raised.exception.code, "INTEGRITY_MISMATCH")
                client.get_object.assert_not_called()

    def test_vultr_zero_length_get_is_rejected_after_accepted_multipart_head(self):
        point, _config, _key, state = self._point("vultr")
        state["etag"] = '"0123456789abcdef0123456789abcdef-7881"'
        zero_length = self._head(point, state, ContentLength=0)
        client = mock.Mock(name="vultr-zero-length-get-client")
        client.head_object.return_value = dict(zero_length)
        client.get_object.return_value = {
            **zero_length,
            "Body": io.BytesIO(self.payload),
        }
        destination = os.path.join(self.tmp, "vultr-zero-length-get.zip")

        with mock.patch(
            "apps._tasks.integration.storage.vultr._s3_client",
            return_value=client,
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, destination)

        self.assertEqual(raised.exception.code, "INTEGRITY_MISMATCH")
        self.assertFalse(os.path.exists(destination))

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
            backup=SimpleNamespace(
                id=417,
                uuid_str="exact",
                artifact_records=_ArtifactQuery(),
            ),
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
            backup=SimpleNamespace(id=417, uuid_str="exact"),
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
