import hashlib
import io
import os
import uuid
from unittest import mock

from botocore.exceptions import ClientError

from apps._tasks.integration.storage.vultr import (
    VULTR_OBJECT_METADATA_KEY,
    storage_vultr,
)
from apps._tasks.exceptions import StorageVultrUploadFailedError
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreWebsiteBackup, CoreWebsiteBackupStoragePoints
from apps.console.storage.models import CoreStorage, CoreStorageType, CoreStorageVultr
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def _not_found():
    return ClientError({"Error": {"Code": "404"}}, "HeadObject")


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
        self.payload = b"vultr object integrity test\n"
        self.sha256 = hashlib.sha256(self.payload).hexdigest()
        os.makedirs("_storage", exist_ok=True)
        self.local_zip = f"_storage/{backup.uuid}.zip"
        with open(self.local_zip, "wb") as file_obj:
            file_obj.write(self.payload)
        self.addCleanup(lambda: os.path.exists(self.local_zip) and os.remove(self.local_zip))

    def _head(self, *, sha256=None, etag='"multipart-etag-2"', version_id="version-1"):
        return {
            "ContentLength": len(self.payload),
            "ETag": etag,
            "VersionId": version_id,
            "Metadata": {"backupsheep-sha256": sha256 or self.sha256},
        }

    def _client(self, *heads):
        client = mock.MagicMock()
        client.head_object.side_effect = list(heads)
        return client

    def test_upload_persists_size_checksum_etag_and_version_id(self):
        client = self._client(_not_found(), self._head())
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ) as boto3_client:
            storage_vultr(self.point)

        self.point.refresh_from_db()
        metadata = self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        self.assertEqual(metadata["object_key"], self.point.storage_file_id)
        self.assertEqual(metadata["sha256"], self.sha256)
        self.assertEqual(metadata["size_bytes"], len(self.payload))
        self.assertEqual(metadata["etag"], '"multipart-etag-2"')
        self.assertEqual(metadata["version_id"], "version-1")
        client.upload_fileobj.assert_called_once()
        extra_args = client.upload_fileobj.call_args.kwargs["ExtraArgs"]
        self.assertEqual(extra_args["Metadata"]["backupsheep-sha256"], self.sha256)

        config = boto3_client.call_args.kwargs["config"]
        self.assertEqual(config.connect_timeout, 10)
        self.assertEqual(config.read_timeout, 60)
        self.assertEqual(config.retries["max_attempts"], 5)

    def test_multipart_etag_is_persisted_but_not_used_as_checksum(self):
        client = self._client(_not_found(), self._head(etag='"abc-7"'))
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            storage_vultr(self.point)

        self.point.refresh_from_db()
        metadata = self.point.metadata[VULTR_OBJECT_METADATA_KEY]
        self.assertEqual(metadata["etag"], '"abc-7"')
        self.assertEqual(metadata["sha256"], self.sha256)
        self.assertNotEqual(metadata["etag"].strip('"'), metadata["sha256"])

    def test_checksum_mismatch_reuploads_same_deterministic_key(self):
        self.point.storage_file_id = "backups/old-key.zip"
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {
                "object_key": "backups/old-key.zip",
                "sha256": "wrong",
                "size_bytes": len(self.payload),
                "etag": '"old"',
                "version_id": "old-version",
            }
        }
        self.point.save()
        client = self._client(
            self._head(sha256="wrong", etag='"old"', version_id="old-version"),
            self._head(),
        )
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            storage_vultr(self.point)

        client.upload_fileobj.assert_called_once()
        self.assertEqual(client.upload_fileobj.call_args.args[2], "backups/old-key.zip")
        self.point.refresh_from_db()
        self.assertEqual(
            self.point.metadata[VULTR_OBJECT_METADATA_KEY]["sha256"], self.sha256
        )

    def test_head_not_found_then_upload_retry_succeeds(self):
        client = self._client(_not_found(), _not_found(), self._head())
        client.upload_fileobj.side_effect = [ConnectionError("temporary"), None]
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            with self.assertRaises(StorageVultrUploadFailedError):
                storage_vultr(self.point)
            storage_vultr(self.point)

        self.assertEqual(client.upload_fileobj.call_count, 2)
        self.point.refresh_from_db()
        self.assertEqual(self.point.status, self.point.Status.UPLOAD_COMPLETE)

    def test_verified_resume_streams_body_when_provider_omits_custom_metadata(self):
        key = "backups/body-verified.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {
                "object_key": key,
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "etag": '"multipart-etag-2"',
                "version_id": "version-1",
            }
        }
        self.point.save()
        head = self._head()
        head["Metadata"] = {}
        client = self._client(head)
        client.get_object.return_value = {"Body": io.BytesIO(self.payload)}
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            storage_vultr(self.point)

        client.upload_fileobj.assert_not_called()
        client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key=key, VersionId="version-1"
        )

    def test_worker_crash_after_upload_adopts_existing_object_without_duplicate_upload(self):
        client = self._client(_not_found(), self._head(), self._head())
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ), mock.patch.object(
            self.point, "save", side_effect=[RuntimeError("worker crashed"), None]
        ):
            with self.assertRaises(Exception):
                storage_vultr(self.point)

        # The worker crashed after the provider accepted the upload. The retry
        # must use the deterministic key's existing object and avoid another PUT.
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            storage_vultr(self.point)

        client.upload_fileobj.assert_called_once()
        self.point.refresh_from_db()
        self.assertEqual(self.point.status, self.point.Status.UPLOAD_COMPLETE)

    def test_existing_verified_object_is_resumed_without_upload(self):
        key = "backups/existing.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {
                "object_key": key,
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "etag": '"multipart-etag-2"',
                "version_id": "version-1",
            }
        }
        self.point.save()
        client = self._client(self._head())
        with mock.patch(
            "apps._tasks.integration.storage.vultr.boto3.client", return_value=client
        ):
            storage_vultr(self.point)

        client.upload_fileobj.assert_not_called()
        client.head_object.assert_called_once_with(
            Bucket="test-bucket", Key=key, VersionId="version-1"
        )

    def test_versioned_object_download_uses_persisted_version_id(self):
        self.point.storage_file_id = "backups/versioned.zip"
        self.point.metadata = {
            VULTR_OBJECT_METADATA_KEY: {"version_id": "version-7"}
        }
        self.point.save()
        client = mock.MagicMock()
        client.generate_presigned_url.return_value = "https://example.invalid/object"
        with mock.patch(
            "boto3.client", return_value=client
        ):
            self.assertEqual(
                self.point.generate_download_url(), "https://example.invalid/object"
            )
        self.assertEqual(
            client.generate_presigned_url.call_args.kwargs["Params"]["VersionId"],
            "version-7",
        )
