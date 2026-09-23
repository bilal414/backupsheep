import os
import base64
import hashlib
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from botocore.exceptions import ClientError

from apps._tasks.integration.storage.aws_s3 import storage_aws_s3
from apps._tasks.integration.storage.local import storage_local
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.connection.models import CoreDoSpacesRegion
from apps.console.node.models import (
    CoreBasecamp,
    CoreDatabase,
    CoreNode,
)
from apps.console.storage.models import (
    CoreStorage,
    CoreStorageAWSS3,
    CoreStorageDoSpaces,
    CoreStorageLocal,
    CoreStorageType,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.download_urls import UnsafeBrowserDownloadTarget


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


def make_category_backup_point(member, storage, *, category, size, status=None):
    connection = factories.make_connection(
        storage.account,
        member,
        code=category,
        name=f"{category}-{uuid.uuid4().hex[:8]}",
    )
    node = CoreNode.objects.create(
        connection=connection,
        type=(
            CoreNode.Type.DATABASE
            if category == "database"
            else CoreNode.Type.SAAS
        ),
        name=f"{category}-source",
        added_by=member,
    )
    suffix = uuid.uuid4().hex
    if category == "database":
        source = CoreDatabase.objects.create(node=node, name="database-source")
        backup_model = CoreDatabaseBackup
        point_model = CoreDatabaseBackupStoragePoints
        source_field = "database"
    elif category == "basecamp":
        source = CoreBasecamp.objects.create(node=node, name="basecamp-source")
        backup_model = CoreBasecampBackup
        point_model = CoreBasecampBackupStoragePoints
        source_field = "basecamp"
    else:
        raise ValueError(f"Unsupported category: {category}")

    backup = backup_model.objects.create(
        **{source_field: source},
        uuid=f"storage-summary-{category}-{suffix}",
        status=UtilBackup.Status.COMPLETE,
        type=UtilBackup.Type.ON_DEMAND,
        size=size,
    )
    return point_model.objects.create(
        backup=backup,
        storage=storage,
        status=status or point_model.Status.UPLOAD_COMPLETE,
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

    def test_do_spaces_validation_probes_are_unique(self):
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="do_spaces"),
            name="spaces-store",
            added_by=self.member,
        )
        spaces = CoreStorageDoSpaces.objects.create(
            storage=storage,
            region=CoreDoSpacesRegion.objects.get(code="nyc3"),
            access_key=bs_encrypt("access", self.account.get_encryption_key()),
            secret_key=bs_encrypt("secret", self.account.get_encryption_key()),
            bucket_name="test-bucket",
            prefix="probe",
            no_delete=False,
        )
        client = mock.MagicMock()
        client.put_object.return_value = {"ETag": "abc"}
        client.get_object.return_value = {"ETag": "abc"}
        client.delete_object.return_value = {"ResponseMetadata": {"HTTPStatusCode": 204}}

        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(spaces.validate())
            self.assertTrue(spaces.validate())

        keys = [call.kwargs["Key"] for call in client.put_object.call_args_list]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])
        self.assertTrue(all(key.startswith("probe/") for key in keys))

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

        payload = b"immutable-backup"
        digest = hashlib.sha256(payload)
        client = mock.MagicMock()
        client.head_object.side_effect = [
            ClientError({"Error": {"Code": "404"}}, "HeadObject"),
            {
            "ContentLength": len(payload),
            "VersionId": "version-1",
            "ETag": '"etag-1"',
            "Metadata": {
                "backupsheep-backup-id": str(point.backup_id),
                "backupsheep-sha256": digest.hexdigest(),
                "backupsheep-bytes": str(len(payload)),
            },
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() + timedelta(days=30),
            },
        ]
        with mock.patch(
            "apps._tasks.integration.storage.aws_s3.boto3.client", return_value=client
        ):
            storage_aws_s3(point)

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertEqual(point.metadata["s3_object_lock"]["version_id"], "version-1")
        upload_args = client.put_object.call_args.kwargs
        self.assertEqual(upload_args["ObjectLockMode"], "COMPLIANCE")
        self.assertEqual(
            upload_args["ChecksumSHA256"],
            base64.b64encode(digest.digest()).decode("ascii"),
        )
        self.assertEqual(upload_args["ExpectedBucketOwner"], "123456789012")
        self.assertEqual(
            point.metadata["aws_s3_object"]["sha256"], digest.hexdigest()
        )

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
            "Metadata": {
                "backupsheep-backup-id": str(point.backup_id),
            },
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

    def test_category_usage_is_completed_account_scoped_and_fixed_query_count(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        website_point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        )
        website_point.backup.size = 100
        website_point.backup.save(update_fields=["size", "modified"])
        make_category_backup_point(
            self.member, storage, category="database", size=200
        )
        make_category_backup_point(
            self.member, storage, category="basecamp", size=400
        )

        failed_point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED,
        )
        failed_point.backup.size = 500
        failed_point.backup.save(update_fields=["size", "modified"])

        other_account, other_member, _other_user = factories.make_account()
        other_storage = factories.make_storage(
            other_account, other_member, code="aws_s3"
        )
        other_point = make_website_backup_point(
            other_member,
            other_storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        )
        other_point.backup.size = 600
        other_point.backup.save(update_fields=["size", "modified"])

        # The storage lookup plus one grouped query for each of website, database,
        # and Basecamp stays constant as destinations grow.
        with CaptureQueriesContext(connection) as captured:
            summary = CoreStorage.cost_summary_for_account(self.account)
        self.assertLessEqual(len(captured), 4)

        destination = next(
            item
            for item in summary["destinations"]
            if item["storage_id"] == storage.id
        )
        self.assertEqual(destination["categories"]["website"], {
            "source_count": 1,
            "backup_count": 1,
            "stored_bytes": 100,
        })
        self.assertEqual(destination["categories"]["database"], {
            "source_count": 1,
            "backup_count": 1,
            "stored_bytes": 200,
        })
        self.assertEqual(destination["categories"]["saas"], {
            "source_count": 1,
            "backup_count": 1,
            "stored_bytes": 400,
        })
        self.assertEqual(destination["stored_bytes"], 700)
        self.assertEqual(
            sum(
                category["stored_bytes"]
                for category in destination["categories"].values()
            ),
            destination["stored_bytes"],
        )
        self.assertNotIn(
            other_storage.id,
            {item["storage_id"] for item in summary["destinations"]},
        )

        self.client.force_login(self.user)
        response = self.client.get(
            reverse(
                "console:setup:integration_storage_open",
                args=[storage.type.code],
            )
        )
        self.assertEqual(response.status_code, 200)
        storage_row = next(
            item
            for item in response.context["page"].object_list
            if item.id == storage.id
        )
        self.assertEqual(storage_row.stats_website_count, 1)
        self.assertEqual(storage_row.stats_website_backup_count, 1)
        self.assertEqual(storage_row.stats_website_size, 100)
        self.assertEqual(storage_row.stats_database_count, 1)
        self.assertEqual(storage_row.stats_database_backup_count, 1)
        self.assertEqual(storage_row.stats_database_size, 200)
        self.assertEqual(storage_row.stats_saas_count, 1)
        self.assertEqual(storage_row.stats_saas_backup_count, 1)
        self.assertEqual(storage_row.stats_saas_size, 400)


class LocalStorageModelTests(BaseTestCase):
    def test_validate_roundtrip_at_root(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            self.assertTrue(CoreStorageLocal(path=None).probe_filesystem())

    def test_validate_roundtrip_with_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            self.assertTrue(CoreStorageLocal(path="server1").probe_filesystem())
            target_dir = os.path.join(os.path.realpath(tmp), "server1")
            self.assertTrue(os.path.isdir(target_dir))
            # the write/read test file is cleaned up afterwards
            self.assertEqual(os.listdir(target_dir), [])

    def test_concurrent_validation_probes_do_not_collide(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            local = CoreStorageLocal(path="concurrent")
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _unused: local.probe_filesystem(), range(8)))

            self.assertEqual(results, [True] * 8)
            self.assertEqual(os.listdir(os.path.join(tmp, "concurrent")), [])

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
            storage = make_local_storage(self.account, self.member)
            point = make_website_backup_point(
                self.member, storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            )
            payload = b"zip-bytes"
            target = os.path.join(tmp, f"{point.backup.uuid_str}.zip")
            with open(target, "wb") as fh:
                fh.write(payload)
            point.storage_file_id = target
            point.metadata = {
                "local_object": {
                    "object_key": os.path.basename(target),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                    "checksum_algorithm": "sha256",
                }
            }
            point.save()
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
            self.assertFalse(point.soft_delete())
            point.refresh_from_db()
            # Protected copies remain visibly restorable and are not reported as
            # deleted while the bytes still exist.
            self.assertTrue(os.path.exists(target))
            self.assertEqual(
                point.status,
                CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            )
            self.assertIn("deletion_protection", point.metadata)

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
            f"/api/v1/storage/local/file/website/{point.id}/",
        )
        self.assertEqual(
            point.generate_browser_download_target(),
            f"/api/v1/storage/local/file/website/{point.id}/",
        )

    def test_browser_download_target_rejects_unsafe_provider_output(self):
        storage = make_local_storage(self.account, self.member)
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="/backups/x.zip",
        )
        with mock.patch.object(
            point,
            "generate_download_url",
            return_value="javascript:alert(document.domain)",
        ):
            with self.assertRaises(UnsafeBrowserDownloadTarget):
                point.generate_browser_download_target()


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

    def _make_family_point_with_file(
        self,
        family,
        account,
        member,
        root,
        payload,
        *,
        backup_status=UtilBackup.Status.COMPLETE,
    ):
        storage = make_local_storage(account, member)
        target = os.path.join(root, f"{family}-{uuid.uuid4().hex}.zip")
        with open(target, "wb") as fh:
            fh.write(payload)
        if family == "website":
            point = make_website_backup_point(
                member,
                storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
                storage_file_id=target,
            )
        else:
            point = make_category_backup_point(
                member,
                storage,
                category=family,
                size=len(payload),
            )
            point.storage_file_id = target
            point.save(update_fields=["storage_file_id", "modified"])
        point.backup.status = backup_status
        point.backup.save(update_fields=["status", "modified"])
        return point

    def test_download_streams_file_for_owner(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            payload = b"zip-bytes" * 100
            point = self._make_point_with_file(self.account, self.member, tmp, payload)
            self.client.force_login(self.user)
            r = self.client.get(f"/api/v1/storage/local/file/website/{point.id}/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(b"".join(r.streaming_content), payload)
            self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_download_404_for_other_account(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(LOCAL_STORAGE_ROOT=tmp):
            other_account, other_member, _ = factories.make_account()
            point = self._make_point_with_file(other_account, other_member, tmp, b"zip-bytes")
            self.client.force_login(self.user)
            r = self.client.get(f"/api/v1/storage/local/file/website/{point.id}/")
            self.assertEqual(r.status_code, 404)

    def test_family_routes_require_complete_parent_for_every_backup_family(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(
            LOCAL_STORAGE_ROOT=tmp,
            BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
        ):
            self.client.force_login(self.user)
            for family in ("website", "database", "basecamp"):
                with self.subTest(family=family):
                    payload = f"{family}-bytes".encode()
                    point = self._make_family_point_with_file(
                        family,
                        self.account,
                        self.member,
                        tmp,
                        payload,
                        backup_status=UtilBackup.Status.IN_PROGRESS,
                    )
                    url = f"/api/v1/storage/local/file/{family}/{point.id}/"
                    self.assertEqual(self.client.get(url).status_code, 404)

                    point.backup.status = UtilBackup.Status.COMPLETE
                    point.backup.save(update_fields=["status", "modified"])
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(b"".join(response.streaming_content), payload)

    def test_family_qualified_routes_prevent_cross_table_id_collisions(self):
        with tempfile.TemporaryDirectory() as tmp, override_settings(
            LOCAL_STORAGE_ROOT=tmp,
            BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
            BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
        ):
            website = self._make_family_point_with_file(
                "website", self.account, self.member, tmp, b"website-bytes"
            )
            database = self._make_family_point_with_file(
                "database", self.account, self.member, tmp, b"database-bytes"
            )
            if database.id != website.id:
                database_backup = database.backup
                database_storage = database.storage
                database_path = database.storage_file_id
                database.delete()
                database = CoreDatabaseBackupStoragePoints.objects.create(
                    id=website.id,
                    backup=database_backup,
                    storage=database_storage,
                    status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
                    storage_file_id=database_path,
                )
            self.assertEqual(database.id, website.id)

            self.client.force_login(self.user)
            website_response = self.client.get(
                f"/api/v1/storage/local/file/website/{website.id}/"
            )
            database_response = self.client.get(
                f"/api/v1/storage/local/file/database/{database.id}/"
            )
            self.assertEqual(website_response.status_code, 200)
            self.assertEqual(database_response.status_code, 200)
            self.assertEqual(
                b"".join(website_response.streaming_content), b"website-bytes"
            )
            self.assertEqual(
                b"".join(database_response.streaming_content), b"database-bytes"
            )
            self.assertEqual(
                self.client.get(
                    f"/api/v1/storage/local/file/{website.id}/"
                ).status_code,
                404,
            )


class S3ImmutabilityFollowupTests(BaseTestCase):
    """Regression tests for deferred-deletion retries and async lifecycle sync."""

    def _protected_storage(self, *, air_gapped=False, no_delete=None):
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
        aws_s3.no_delete = no_delete
        aws_s3.save()
        return storage

    def test_legal_hold_defers_deletion(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member, storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="legal-hold.zip",
        )
        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-1",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockLegalHoldStatus": "ON",
            "ObjectLockRetainUntilDate": timezone.now() - timedelta(days=1),
        }

        with mock.patch("boto3.client", return_value=client):
            self.assertFalse(point.soft_delete())

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertIn("deletion_protection", point.metadata)
        client.delete_object.assert_not_called()

    def test_missing_version_id_defers_when_object_lock_configured(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member, storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="no-version.zip",
        )
        client = mock.MagicMock()
        client.head_object.return_value = {
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() - timedelta(days=1),
        }

        with mock.patch("boto3.client", return_value=client):
            self.assertFalse(point.soft_delete())

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertIn("deletion_protection", point.metadata)
        client.delete_object.assert_not_called()

    def test_missing_object_is_marked_deleted_even_with_object_lock_configured(self):
        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member,
            storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="already-gone.zip",
        )
        client = mock.MagicMock()
        client.head_object.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}},
            "HeadObject",
        )

        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(point.soft_delete())

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED)
        client.delete_object.assert_not_called()

    def test_retry_task_deletes_once_retention_has_expired(self):
        from apps._tasks.helper.maintenance import retry_protected_storage_deletes

        storage = self._protected_storage()
        point = make_website_backup_point(
            self.member, storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="retry.zip",
        )
        point.metadata = {
            "deletion_protection": {
                "reason": "S3 Object Lock retention is active",
                "deferred_at": (timezone.now() - timedelta(days=31)).isoformat(),
                "retain_until": (timezone.now() - timedelta(days=1)).isoformat(),
            }
        }
        point.save()
        client = mock.MagicMock()
        client.head_object.return_value = {
            "VersionId": "version-expired",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": timezone.now() - timedelta(days=1),
            "Metadata": {
                "backupsheep-backup-id": str(point.backup_id),
            },
        }

        with mock.patch("boto3.client", return_value=client):
            retry_protected_storage_deletes.apply()

        point.refresh_from_db()
        self.assertEqual(point.status, CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED)
        client.delete_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="retry.zip",
            VersionId="version-expired",
            ExpectedBucketOwner="123456789012",
        )

    def test_retry_task_skips_permanently_protected_destinations(self):
        from apps._tasks.helper.maintenance import retry_protected_storage_deletes

        deferred_metadata = {
            "deletion_protection": {
                "reason": "destination deletion protection is enabled",
                "deferred_at": timezone.now().isoformat(),
                "retain_until": None,
            }
        }
        air_gapped_storage = self._protected_storage(air_gapped=True)
        air_gapped_point = make_website_backup_point(
            self.member, air_gapped_storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="air-gapped.zip",
        )
        air_gapped_point.metadata = deferred_metadata
        air_gapped_point.save()

        no_delete_storage = self._protected_storage(no_delete=True)
        no_delete_point = make_website_backup_point(
            self.member, no_delete_storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="no-delete.zip",
        )
        no_delete_point.metadata = deferred_metadata
        no_delete_point.save()

        with mock.patch("boto3.client") as boto_client:
            retry_protected_storage_deletes.apply()

        boto_client.assert_not_called()
        air_gapped_point.refresh_from_db()
        no_delete_point.refresh_from_db()
        self.assertEqual(air_gapped_point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)
        self.assertEqual(no_delete_point.status, CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE)

    def test_sync_lifecycle_endpoint_queues_task(self):
        storage = self._protected_storage()
        self.client.force_login(self.user)
        with mock.patch(
            "apps.api.v1.storage.aws_s3.views.storage_aws_s3_sync_lifecycle.apply_async"
        ) as dispatch:
            response = self.client.post(
                f"/api/v1/storage/aws_s3/{storage.id}/sync_lifecycle/"
            )

        self.assertEqual(response.status_code, 202)
        dispatch.assert_called_once_with(args=[storage.storage_aws_s3.id])

    def test_serializer_validation_error_is_a_clean_400(self):
        from apps.api.v1.storage.aws_s3.serializers import CoreStorageAWSS3WriteSerializer
        from apps.console.connection.models import CoreAWSRegion

        aws_s3 = self._protected_storage().storage_aws_s3
        region_id = aws_s3.region_id or CoreAWSRegion.objects.first().id
        serializer = CoreStorageAWSS3WriteSerializer(
            instance=aws_s3,
            data={
                "access_key": "access",
                "secret_key": "secret",
                "bucket_name": "test-bucket",
                "region": region_id,
                # mode without retention days -> invalid combination
                "object_lock_mode": CoreStorageAWSS3.ObjectLockMode.COMPLIANCE,
                "object_lock_retain_days": None,
            },
            context={"encryption_key": self.account.get_encryption_key()},
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("configured together", str(serializer.errors))

    def test_serializer_never_exposes_provider_exception_text(self):
        from apps.api.v1.storage.aws_s3.serializers import CoreStorageAWSS3WriteSerializer
        from apps.console.connection.models import CoreAWSRegion

        canary = "aws-provider-secret-canary"
        aws_s3 = self._protected_storage().storage_aws_s3
        region_id = aws_s3.region_id or CoreAWSRegion.objects.first().id
        serializer = CoreStorageAWSS3WriteSerializer(
            instance=aws_s3,
            data={
                "access_key": "access",
                "secret_key": "secret",
                "bucket_name": "test-bucket",
                "region": region_id,
            },
            context={"encryption_key": self.account.get_encryption_key()},
        )

        with mock.patch.object(
            CoreStorageAWSS3, "validate", side_effect=ValueError(canary)
        ):
            self.assertFalse(serializer.is_valid())
        self.assertNotIn(canary, str(serializer.errors))
        self.assertIn("Unable to authenticate", str(serializer.errors))
