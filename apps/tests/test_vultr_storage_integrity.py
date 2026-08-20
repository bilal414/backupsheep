import hashlib
import io
import os
import uuid
from datetime import timedelta
from unittest import mock

from botocore.exceptions import ClientError
from django.test import override_settings
from django.utils import timezone

from apps._tasks.exceptions import StorageVultrUploadFailedError
from apps._tasks.integration.storage.vultr import (
    VULTR_OBJECT_METADATA_KEY,
    storage_vultr,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreWebsiteBackup, CoreWebsiteBackupStoragePoints
from apps.console.storage.models import CoreStorage, CoreStorageType, CoreStorageVultr
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def _not_found(operation="HeadObject"):
    return ClientError({"Error": {"Code": "404"}}, operation)


class VultrStorageIntegrityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="vultr"),
            name="vultr-storage",
            added_by=self.member,
        )
        CoreStorageVultr.objects.create(
            storage=self.storage,
            access_key=bs_encrypt("access", self.account.get_encryption_key()),
            secret_key=bs_encrypt("secret", self.account.get_encryption_key()),
            bucket_name="test-bucket",
            endpoint="ewr1.vultrobjects.com",
            prefix="backups",
        )
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        self.point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=self.storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        self.local_zip = f"_storage/{backup.uuid}.zip"
        self._write_payload(b"vultr object integrity test\n")
        self.addCleanup(
            lambda: os.path.exists(self.local_zip) and os.remove(self.local_zip)
        )

    def _write_payload(self, payload):
        self.payload = payload
        self.sha256 = hashlib.sha256(payload).hexdigest()
        os.makedirs("_storage", exist_ok=True)
        with open(self.local_zip, "wb") as file_obj:
            file_obj.write(payload)

    def _head(self, *, sha256=None, etag='"multipart-etag-2"', version_id="version-1"):
        return {
            "ContentLength": len(self.payload),
            "ETag": etag,
            "VersionId": version_id,
            "Metadata": {
                "backupsheep-backup-id": str(self.point.backup_id),
                "backupsheep-sha256": sha256 or self.sha256,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }

    def _client(self, *heads):
        client = mock.MagicMock()
        client.head_object.side_effect = list(heads)
        client.put_object.return_value = {"ETag": '"put-etag"'}
        return client

    def _run(self, client):
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client",
            return_value=client,
        ) as boto3_client:
            storage_vultr(self.point)
        return boto3_client

    def test_upload_notification_never_exposes_provider_exception_text(self):
        node = self.point.backup.website.node
        canary = "provider-secret-canary-upload"
        error = RuntimeError(f"provider body contains {canary}")
        with mock.patch.object(self.account.__class__, "create_log") as create_log, mock.patch(
            "apps._tasks.helper.tasks.send_postmark_email"
        ) as send_email:
            node.notify_upload_fail(error, self.point.backup, self.storage)

        data = create_log.call_args.kwargs["data"]
        self.assertEqual(data["error_code"], "STORAGE_UPLOAD_FAILED")
        self.assertNotIn(canary, repr(data))
        self.assertNotIn(canary, repr(send_email.delay.call_args))

    def test_upload_notification_uses_explicit_safe_classification(self):
        node = self.point.backup.website.node
        canary = "provider-secret-canary-transient"
        error = RuntimeError(f"provider body contains {canary}")
        with mock.patch.object(self.account.__class__, "create_log") as create_log, mock.patch(
            "apps._tasks.helper.tasks.send_postmark_email"
        ) as send_email:
            node.notify_upload_fail(
                error,
                self.point.backup,
                self.storage,
                error_code="STORAGE_TRANSIENT_FAILURE",
            )

        data = create_log.call_args.kwargs["data"]
        self.assertEqual(data["error_code"], "STORAGE_TRANSIENT_FAILURE")
        self.assertNotIn(canary, repr(data))
        self.assertNotIn(canary, repr(send_email.delay.call_args))

    def test_upload_notification_tolerates_legacy_safe_message(self):
        node = self.point.backup.website.node
        with mock.patch("apps.console.node.models.capture_exception") as capture:
            node.notify_upload_fail(
                "The storage upload could not be completed.",
                self.point.backup,
                self.storage,
            )

        capture.assert_not_called()

    def test_upload_persists_size_checksum_etag_and_version_id(self):
        client = self._client(_not_found(), self._head())
        boto3_client = self._run(client)

        self.point.refresh_from_db()
        state = self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        self.assertEqual(state["bucket"], "test-bucket")
        self.assertEqual(state["object_key"], self.point.storage_file_id)
        self.assertEqual(state["sha256"], self.sha256)
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["etag"], '"multipart-etag-2"')
        self.assertEqual(state["version_id"], "version-1")
        self.assertEqual(state["phase"], "committed")
        client.put_object.assert_called_once()
        upload_metadata = client.put_object.call_args.kwargs["Metadata"]
        self.assertEqual(upload_metadata["backupsheep-sha256"], self.sha256)
        self.assertEqual(upload_metadata["backupsheep-bytes"], str(len(self.payload)))

        config = boto3_client.call_args.kwargs["config"]
        self.assertEqual(config.connect_timeout, 10)
        self.assertEqual(config.read_timeout, 60)
        self.assertEqual(config.retries["max_attempts"], 5)

    def test_unavailable_version_id_is_persisted_canonically(self):
        client = self._client(_not_found(), self._head(version_id=None))

        self._run(client)

        self.point.refresh_from_db()
        state = self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        self.assertEqual(state["version_id"], "")
        self.assertIn("version_id", state)

    def test_multipart_etag_is_identity_metadata_not_content_checksum(self):
        client = self._client(_not_found(), self._head(etag='"abc-7"'))
        self._run(client)
        self.point.refresh_from_db()
        state = self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        self.assertEqual(state["etag"], '"abc-7"')
        self.assertNotEqual(state["etag"].strip('"'), state["sha256"])

    def test_lost_put_response_adopts_verified_object_without_second_upload(self):
        client = self._client(_not_found(), self._head())
        client.put_object.side_effect = ConnectionError("response lost")
        self._run(client)

        client.put_object.assert_called_once()
        self.point.refresh_from_db()
        self.assertEqual(self.point.status, self.point.Status.UPLOAD_COMPLETE)

    def test_verified_resume_streams_body_if_provider_drops_custom_metadata(self):
        key = "backups/existing.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {
                "bucket": "test-bucket",
                "phase": "committed",
                "object_key": key,
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": str(self.point.backup_id),
                "version_id": "version-1",
            }
        }
        self.point.save()
        head = self._head()
        head["Metadata"] = {"backupsheep-backup-id": str(self.point.backup_id)}
        client = self._client(head)
        client.get_object.return_value = {"Body": io.BytesIO(self.payload)}
        self._run(client)

        client.put_object.assert_not_called()
        client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key=key, VersionId="version-1"
        )

    def test_resume_rejects_local_artifact_changed_after_upload_started(self):
        original_sha = self.sha256
        original_size = len(self.payload)
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {
                "bucket": "test-bucket",
                "object_key": "backups/in-progress.zip",
                "sha256": original_sha,
                "size_bytes": original_size,
                "phase": "uploading",
            }
        }
        self.point.save(update_fields=["metadata", "modified"])
        self._write_payload(b"different bytes with the same retry identity")
        client = mock.MagicMock()

        with self.assertRaises(StorageVultrUploadFailedError) as raised:
            self._run(client)

        self.assertIn("changed after this upload", str(raised.exception))
        client.head_object.assert_not_called()
        client.put_object.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_worker_crash_resumes_persisted_multipart_upload(self):
        self._write_payload((b"a" * (5 * 1024 * 1024)) + (b"b" * 1024))
        client = self._client(_not_found(), _not_found(), self._head())
        client.list_multipart_uploads.return_value = {
            "Uploads": [],
            "IsTruncated": False,
        }
        client.create_multipart_upload.return_value = {"UploadId": "upload-1"}
        client.list_parts.side_effect = [
            {"Parts": [], "IsTruncated": False},
            {
                "Parts": [
                    {
                        "PartNumber": 1,
                        "ETag": '"part-1"',
                        "Size": 5 * 1024 * 1024,
                    }
                ],
                "IsTruncated": False,
            },
            {
                "Parts": [
                    {
                        "PartNumber": 1,
                        "ETag": '"part-1"',
                        "Size": 5 * 1024 * 1024,
                    },
                    {
                        "PartNumber": 2,
                        "ETag": '"part-2"',
                        "Size": 1024,
                    },
                ],
                "IsTruncated": False,
            },
        ]
        client.upload_part.side_effect = [
            {"ETag": '"part-1"'},
            ConnectionError("worker lost"),
            {"ETag": '"part-2"'},
        ]

        with self.assertRaises(StorageVultrUploadFailedError):
            self._run(client)
        self.point.refresh_from_db()
        self.assertEqual(
            self.point.metadata[VULTR_OBJECT_METADATA_KEY]["multipart"]["upload_id"],
            "upload-1",
        )

        self._run(client)
        client.create_multipart_upload.assert_called_once()
        client.complete_multipart_upload.assert_called_once()
        self.point.refresh_from_db()
        self.assertEqual(self.point.status, self.point.Status.UPLOAD_COMPLETE)
        self.assertNotIn(
            "multipart", self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        )

    @override_settings(S3_MULTIPART_THRESHOLD_BYTES=1)
    def test_duplicate_unfinished_uploads_stop_automatic_recreation(self):
        client = self._client(_not_found())
        client.create_multipart_upload.side_effect = TimeoutError("response lost")
        key = f"backups/{self.point.backup.uuid}.zip"
        initiated = timezone.now()
        identity = {
            "Owner": {"ID": "owner-1"},
            "Initiator": {"ID": "initiator-1"},
            "StorageClass": "STANDARD",
        }
        client.list_multipart_uploads.side_effect = [
            {
                "Uploads": [
                    {
                        "Key": key,
                        "UploadId": "stale",
                        "Initiated": initiated - timedelta(days=1),
                        **identity,
                    }
                ],
                "IsTruncated": False,
            },
            {
                "Uploads": [
                    {
                        "Key": key,
                        "UploadId": "stale",
                        "Initiated": initiated - timedelta(days=1),
                        **identity,
                    },
                    {
                        "Key": key,
                        "UploadId": "one",
                        "Initiated": initiated,
                        **identity,
                    },
                    {
                        "Key": key,
                        "UploadId": "two",
                        "Initiated": initiated,
                        **identity,
                    },
                ],
                "IsTruncated": False,
            },
        ]
        with self.assertRaises(StorageVultrUploadFailedError) as raised:
            self._run(client)
        self.assertIn("Multiple unfinished uploads", str(raised.exception))
        client.upload_part.assert_not_called()

    def test_versioned_object_download_uses_persisted_version_id(self):
        self.point.storage_file_id = "backups/versioned.zip"
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {"version_id": "version-7"}
        }
        self.point.save()
        client = mock.MagicMock()
        client.generate_presigned_url.return_value = "https://example.invalid/object"
        with mock.patch("boto3.client", return_value=client):
            self.assertEqual(
                self.point.generate_download_url(),
                "https://example.invalid/object",
            )
        self.assertEqual(
            client.generate_presigned_url.call_args.kwargs["Params"]["VersionId"],
            "version-7",
        )
