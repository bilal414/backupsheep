import os
import tempfile
import uuid
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from apps._tasks.integration.storage.aws_s3 import storage_aws_s3
from apps._tasks.integration.storage.local import storage_local
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreWebsiteBackup, CoreWebsiteBackupStoragePoints
from apps.console.storage.models import CoreStorage, CoreStorageAWSS3, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def make_local_storage(account, member, *, path=None, no_delete=None):
    storage = CoreStorage.objects.create(
        account=account, type=CoreStorageType.objects.get(code="local"),
        name="local-store", added_by=member,
    )
    CoreStorageLocal.objects.create(storage=storage, path=path, no_delete=no_delete)
    return storage


def make_website_backup_point(member, storage, *, status, storage_file_id=None):
    node = factories.make_website_node(storage.account, member)
    backup = CoreWebsiteBackup.objects.create(
        website=node.website, uuid=f"t{uuid.uuid4().hex}",
        status=UtilBackup.Status.COMPLETE, attempt_no=1,
        type=UtilBackup.Type.ON_DEMAND,
    )
    return CoreWebsiteBackupStoragePoints.objects.create(
        backup=backup, storage=storage, status=status,
        storage_file_id=storage_file_id,
    )


class StorageValidateTests(BaseTestCase):
    def test_validate_dispatches_to_provider(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        with mock.patch.object(CoreStorageAWSS3, "validate", return_value=True) as m:
            self.assertTrue(storage.validate())
            m.assert_called_once()
        with mock.patch.object(CoreStorageAWSS3, "validate", return_value=False):
            self.assertFalse(storage.validate())

    def test_aws_s3_validate_success(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        client = mock.MagicMock()
        client.put_object.return_value = {"ETag": "abc"}
        client.get_object.return_value = {"ETag": "abc"}
        client.delete_object.return_value = {"ResponseMetadata": {"HTTPStatusCode": 204}}
        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(storage.storage_aws_s3.validate())
        client.put_object.assert_called_once()
        client.delete_object.assert_called_once()  # cleanup of the test object

    def test_aws_s3_validate_failure_when_upload_has_no_etag(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        client = mock.MagicMock()
        client.put_object.return_value = {}  # no ETag -> failure
        with mock.patch("boto3.client", return_value=client):
            self.assertFalse(storage.storage_aws_s3.validate())

    def test_aws_s3_object_lock_validation_does_not_create_a_test_object(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        aws_s3 = storage.storage_aws_s3
        aws_s3.object_lock_mode = CoreStorageAWSS3.ObjectLockMode.COMPLIANCE
        aws_s3.object_lock_retain_days = 30
        aws_s3.expected_bucket_owner = "123456789012"
        aws_s3.save()
        client = mock.MagicMock()
        client.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }

        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(aws_s3.validate())

        client.get_object_lock_configuration.assert_called_once_with(
            Bucket="test-bucket", ExpectedBucketOwner="123456789012"
        )
        client.head_bucket.assert_called_once_with(
            Bucket="test-bucket", ExpectedBucketOwner="123456789012"
        )
        client.put_object.assert_not_called()

    def test_storage_defaults_active_and_is_account_scoped(self):
        storage = factories.make_storage(self.account, self.member)
        self.assertEqual(storage.status, CoreStorage.Status.ACTIVE)
        self.assertEqual(storage.account, self.account)


class S3ImmutabilityTests(BaseTestCase):
    def _protected_storage(self, *, air_gapped=False):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        storage.is_air_gapped = air_gapped
        storage.save()
        aws_s3 = storage.storage_aws_s3
        key = self.account.get_encryption_key()
        aws_s3.access_key = bs_encrypt("access", key)
        aws_s3.secret_key = bs_encrypt("secret", key)
        aws_s3.object_lock_mode = CoreStorageAWSS3.ObjectLockMode.COMPLIANCE
        aws_s3.object_lock_retain_days = 30
        aws_s3.expected_bucket_owner = "123456789012"
        aws_s3.save()
        return storage

    def test_upload_sets_object_lock_headers_and_records_object_version(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        local_zip = f"_storage/{point.backup.uuid}.zip"
        os.makedirs("_storage", exist_ok=True)
        with open(local_zip, "wb") as fh:
            fh.write(b"immutable-backup")
        self.addCleanup(lambda: os.path.exists(local_zip) and os.remove(local_zip))

        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-1",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() + timedelta(days=30),
        }
        with mock.patch(
            "apps._tasks.integration.storage.aws_s3.boto3.client", return_value=client
        ):
            storage_aws_s3(point)

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertEqual(point.metadata["s3_object_lock"]["version_id"], "version-1")
        upload_args = client.upload_fileobj.call_args.kwargs["ExtraArgs"]
        self.assertEqual(upload_args["ObjectLockMode"], "COMPLIANCE")
        self.assertEqual(upload_args["ChecksumAlgorithm"], "SHA256")
        self.assertEqual(upload_args["ExpectedBucketOwner"], "123456789012")

    def test_active_object_lock_defers_deletion_and_keeps_parent_backup_complete(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="protected.zip",
        )
        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-1",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() + timedelta(days=1),
        }

        with mock.patch("boto3.client", return_value=client):
            self.assertFalse(point.backup.soft_delete())

        point.refresh_from_db()
        point.backup.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertEqual(point.backup.status, UtilBackup.Status.COMPLETE)
        client.delete_object.assert_not_called()

    def test_expired_object_lock_deletes_the_exact_s3_version(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="expired.zip",
        )
        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-expired",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() - timedelta(days=1),
        }

        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(point.soft_delete())

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED)
        client.delete_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="expired.zip",
            VersionId="version-expired",
            ExpectedBucketOwner="123456789012",
        )

    def test_lifecycle_sync_merges_customer_rule(self):
        storage = self._protected_storage()
        aws_s3 = storage.storage_aws_s3
        aws_s3.prefix = "backupsheep"
        aws_s3.lifecycle_transition_days = 45
        aws_s3.lifecycle_storage_class = CoreStorageAWSS3.LifecycleStorageClass.DEEP_ARCHIVE
        aws_s3.save()
        customer_rule = {"ID": "customer-rule", "Status": "Enabled", "Filter": {"Prefix": "other/"}}
        client = mock.MagicMock()
        client.get_bucket_lifecycle_configuration.return_value = {
            "Rules": [customer_rule, {"ID": aws_s3.lifecycle_rule_id(), "Status": "Disabled"}]
        }

        with mock.patch("boto3.client", return_value=client):
            aws_s3.sync_lifecycle_configuration()

        rules = client.put_bucket_lifecycle_configuration.call_args.kwargs[
            "LifecycleConfiguration"
        ]["Rules"]
        self.assertIn(customer_rule, rules)
        managed_rule = next(rule for rule in rules if rule["ID"] == aws_s3.lifecycle_rule_id())
        self.assertEqual(managed_rule["Filter"], {"Prefix": "backupsheep/"})
        self.assertEqual(managed_rule["Transitions"][0]["Days"], 45)


class StorageCostSummaryTests(BaseTestCase):
    def test_cost_summary_groups_recorded_bytes_by_destination_and_source(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        storage.storage_cost_usd_per_gib_month = Decimal("0.020000")
        storage.retrieval_cost_usd_per_gib = Decimal("0.010000")
        storage.save()
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="cost.zip",
        )
        point.backup.size = 2 * 1024 ** 3
        point.backup.save()

        summary = CoreStorage.cost_summary_for_account(self.account)

        self.assertEqual(summary["stored_bytes"], 2 * 1024 ** 3)
        self.assertEqual(summary["destinations"][0]["stored_bytes"], 2 * 1024 ** 3)
        self.assertEqual(summary["sources"][0]["source_id"], point.backup.website.node_id)
        self.assertEqual(summary["estimated_monthly_storage_usd"], 0.04)
        self.assertEqual(summary["estimated_full_retrieval_usd"], 0.02)

        self.client.force_login(self.user)
        response = self.client.get("/api/v1/storage/costs/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["estimated_monthly_storage_usd"], 0.04)


class LocalStorageModelTests(BaseTestCase):
    def test_validate_roundtrip_at_root(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            self.assertTrue(CoreStorageLocal().validate({"path": None, "no_delete": None}))

    def test_validate_roundtrip_with_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            self.assertTrue(CoreStorageLocal().validate({"path": "server1"}))
            target_dir = os.path.join(os.path.realpath(tmp), "server1")
            self.assertTrue(os.path.isdir(target_dir))
            # the write/read test file is cleaned up afterwards
            self.assertEqual(os.listdir(target_dir), [])

    def test_validate_via_storage_dispatch_chain(self):
        storage = make_local_storage(self.account, self.member, path="server1")
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            self.assertTrue(storage.validate())

    def test_path_traversal_rejected(self):
        local = CoreStorageLocal()
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            for bad in ("../etc", "..", "a/../../b", "/etc"):
                with self.assertRaises(ValueError, msg=bad):
                    local.resolve_path(bad)
                with self.assertRaises(ValueError, msg=bad):
                    local.validate({"path": bad})

    def test_resolve_path_stays_in_root(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            local = CoreStorageLocal(path="server1/backups")
            self.assertEqual(
                local.resolve_path(),
                os.path.join(os.path.realpath(tmp), "server1", "backups"),
            )


class LocalStorageUploadTests(BaseTestCase):
    def _fake_point(self, storage, backup_uuid):
        return SimpleNamespace(
            backup=SimpleNamespace(
                uuid=backup_uuid, uuid_str=backup_uuid,
                attempt_no=1, type=UtilBackup.Type.ON_DEMAND,
            ),
            storage=storage,
            storage_file_id=None,
            status=None,
            Status=CoreWebsiteBackupStoragePoints.Status,
            save=lambda: None,
        )

    def test_upload_copies_zip_and_sets_storage_file_id(self):
        payload = b"local-storage-test" * 100
        backup_uuid = f"t{uuid.uuid4().hex}"
        local_zip = f"_storage/{backup_uuid}.zip"
        with open(local_zip, "wb") as fh:
            fh.write(payload)
        self.addCleanup(lambda: os.path.exists(local_zip) and os.remove(local_zip))

        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            storage = make_local_storage(self.account, self.member, path="server1")
            point = self._fake_point(storage, backup_uuid)
            storage_local(point)

            target = os.path.join(os.path.realpath(tmp), "server1", f"{backup_uuid}.zip")
            self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
            self.assertEqual(point.storage_file_id, target)
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), payload)

    def test_upload_missing_source_marks_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            storage = make_local_storage(self.account, self.member)
            point = self._fake_point(storage, f"t{uuid.uuid4().hex}")
            storage_local(point)
            self.assertEqual(
                point.status,
                CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED_FILE_NOT_FOUND,
            )
            self.assertIsNone(point.storage_file_id)


class LocalStorageDeleteTests(BaseTestCase):
    def test_soft_delete_removes_file(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            target = os.path.join(tmp, "backup.zip")
            with open(target, "wb") as fh:
                fh.write(b"zip-bytes")
            storage = make_local_storage(self.account, self.member)
            point = make_website_backup_point(
                self.member, storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
                storage_file_id=target,
            )
            point.soft_delete()
            point.refresh_from_db()
            self.assertFalse(os.path.exists(target))
            self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED)

    def test_soft_delete_honors_no_delete(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            target = os.path.join(tmp, "backup.zip")
            with open(target, "wb") as fh:
                fh.write(b"zip-bytes")
            storage = make_local_storage(self.account, self.member, no_delete=True)
            point = make_website_backup_point(
                self.member, storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
                storage_file_id=target,
            )
            point.soft_delete()
            point.refresh_from_db()
            # the file is kept; only BackupSheep's record of it is closed out
            self.assertTrue(os.path.exists(target))
            self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED)

    def test_soft_delete_refuses_path_outside_root(self):
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as other, \
                override_settings(LOCAL_STORAGE_ROOT=tmp), \
                mock.patch("apps.console.backup.models.capture_exception"):
            target = os.path.join(other, "backup.zip")
            with open(target, "wb") as fh:
                fh.write(b"zip-bytes")
            storage = make_local_storage(self.account, self.member)
            point = make_website_backup_point(
                self.member, storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
                storage_file_id=target,
            )
            point.soft_delete()
            point.refresh_from_db()
            # never unlink files outside the storage root
            self.assertTrue(os.path.exists(target))
            self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_FAILED)

    def test_generate_download_url_returns_streaming_path(self):
        storage = make_local_storage(self.account, self.member)
        point = make_website_backup_point(
            self.member, storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="/backups/x.zip",
        )
        self.assertEqual(
            point.generate_download_url(),
            f"/api/v1/storage/local/file/{point.id}/",
        )


class LocalStorageDownloadViewTests(BaseTestCase):
    def _make_point_with_file(self, account, member, root, payload):
        storage = make_local_storage(account, member)
        backup_uuid = f"t{uuid.uuid4().hex}"
        target = os.path.join(root, f"{backup_uuid}.zip")
        with open(target, "wb") as fh:
            fh.write(payload)
        return make_website_backup_point(
            member, storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=target,
        )

    def test_download_streams_file_for_owner(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            payload = b"zip-bytes" * 100
            point = self._make_point_with_file(self.account, self.member, tmp, payload)
            self.client.force_login(self.user)
            r = self.client.get(f"/api/v1/storage/local/file/{point.id}/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(b"".join(r.streaming_content), payload)
            self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_download_404_for_other_account(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            other_account, other_member, _ = factories.make_account()
            point = self._make_point_with_file(other_account, other_member, tmp, b"zip-bytes")
            self.client.force_login(self.user)
            r = self.client.get(f"/api/v1/storage/local/file/{point.id}/")
            self.assertEqual(r.status_code, 404)
