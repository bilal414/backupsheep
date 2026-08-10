import hashlib
import uuid
from types import SimpleNamespace
from unittest import mock

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.storage.models import (
    CoreStorageAzure,
    CoreStorage,
    CoreStorageDropbox,
    CoreStorageGoogleCloud,
    CoreStorageGoogleDrive,
    CoreStorageOneDrive,
    CoreStoragePCloud,
    CoreStorageType,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class StorageDeleteOwnershipTests(BaseTestCase):
    payload = b"verified backup bytes"

    def _storage(self, code):
        return CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code=code),
            name=f"{code}-delete-test",
            added_by=self.member,
        )

    def _point(self, storage, *, storage_file_id, state_key, state):
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        state = {
            **state,
            "sha256": hashlib.sha256(self.payload).hexdigest(),
            "size_bytes": len(self.payload),
        }
        return CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=storage_file_id,
            metadata={state_key: state},
        )

    def test_dropbox_deletes_only_the_committed_revision(self):
        storage = self._storage("dropbox")
        key = self.account.get_encryption_key()
        CoreStorageDropbox.objects.create(
            storage=storage,
            access_token=bs_encrypt("access", key),
            refresh_token=bs_encrypt("refresh", key),
            token_type="bearer",
            no_delete=False,
        )
        provider_id = "id:owned"
        path = "/BackupSheep/site/backup.zip"
        point = self._point(
            storage,
            storage_file_id=provider_id,
            state_key="dropbox_object",
            state={
                "provider_id": provider_id,
                "path": path,
                "revision": "rev-1",
                "version_id": "rev-1",
                "content_hash": "dropbox-hash",
            },
        )
        point.metadata["dropbox_object"]["ownership_marker"] = (
            f"backupsheep:{point.backup.uuid_str}"
        )
        point.save(update_fields=["metadata", "modified"])

        client = mock.MagicMock()
        client.files_get_metadata.return_value = SimpleNamespace(
            id=provider_id,
            path_display=path.lower(),
            path_lower=path.lower(),
            name="backup.zip",
            size=len(self.payload),
            rev="rev-1",
            content_hash="dropbox-hash",
        )
        with mock.patch("apps.console.backup.models.dropbox.Dropbox", return_value=client):
            self.assertTrue(point.soft_delete())

        client.files_delete_v2.assert_called_once_with(path.lower(), parent_rev="rev-1")
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_COMPLETED)

    def test_dropbox_revision_drift_fails_closed(self):
        storage = self._storage("dropbox")
        key = self.account.get_encryption_key()
        CoreStorageDropbox.objects.create(
            storage=storage,
            access_token=bs_encrypt("access", key),
            refresh_token=bs_encrypt("refresh", key),
            token_type="bearer",
            no_delete=False,
        )
        provider_id = "id:owned"
        point = self._point(
            storage,
            storage_file_id=provider_id,
            state_key="dropbox_object",
            state={
                "provider_id": provider_id,
                "path": "/site/backup.zip",
                "revision": "rev-1",
                "version_id": "rev-1",
                "content_hash": "dropbox-hash",
            },
        )
        point.metadata["dropbox_object"]["ownership_marker"] = (
            f"backupsheep:{point.backup.uuid_str}"
        )
        point.save(update_fields=["metadata", "modified"])
        client = mock.MagicMock()
        client.files_get_metadata.return_value = SimpleNamespace(
            id=provider_id,
            path_display="/site/backup.zip",
            size=len(self.payload),
            rev="foreign-revision",
            content_hash="dropbox-hash",
        )

        with mock.patch("apps.console.backup.models.dropbox.Dropbox", return_value=client):
            self.assertFalse(point.soft_delete())

        client.files_delete_v2.assert_not_called()
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_FAILED)

    def test_pcloud_verifies_file_id_checksum_and_path_before_delete(self):
        storage = self._storage("pcloud")
        CoreStoragePCloud.objects.create(
            storage=storage,
            access_token=bs_encrypt(
                "pcloud-token", self.account.get_encryption_key()
            ),
            token_type="bearer",
            hostname="api.pcloud.com",
        )
        point = self._point(
            storage,
            storage_file_id="pc-1",
            state_key="pcloud_object",
            state={
                "provider_id": "pc-1",
                "fileid": "pc-1",
                "folder": "/site",
                "path": "placeholder",
                "provider_hash": "provider-hash",
            },
        )
        expected_path = f"/site/{point.backup.uuid_str}.zip"
        point.metadata["pcloud_object"].update(
            {
                "path": expected_path,
                "ownership_marker": f"backupsheep:{point.backup.uuid_str}",
            }
        )
        point.save(update_fields=["metadata", "modified"])
        candidate = {
            "fileid": "pc-1",
            "name": f"{point.backup.uuid_str}.zip",
            "path": expected_path,
            "size": len(self.payload),
            "hash": "provider-hash",
        }

        def request_json(_config, _token, method, operation, **_kwargs):
            if operation == "stat":
                return {"metadata": candidate}
            if operation == "checksumfile":
                return {"sha256": hashlib.sha256(self.payload).hexdigest()}
            if operation == "deletefile" and method == "POST":
                return {"result": 0}
            raise AssertionError((method, operation))

        with mock.patch(
            "apps._tasks.integration.storage.pcloud._request_json",
            side_effect=request_json,
        ) as provider_request:
            self.assertTrue(point.soft_delete())

        self.assertEqual(
            provider_request.call_args_list[-1].args[3], "deletefile"
        )
        self.assertEqual(
            provider_request.call_args_list[-1].kwargs["data"], {"fileid": "pc-1"}
        )

    def test_google_drive_rechecks_markers_and_exact_version_before_delete(self):
        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=False,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-1",
            state_key="google_drive_upload",
            state={
                "phase": "committed",
                "provider_id": "drive-file-1",
                "parent_id": "node-folder",
                "version_id": "7",
                "revision": "head-7",
            },
        )
        node_slug = point.backup.node.name_slug
        remote = {
            "id": "drive-file-1",
            "name": f"{point.backup.uuid_str}.zip",
            "mimeType": "application/zip",
            "parents": ["node-folder"],
            "trashed": False,
            "size": str(len(self.payload)),
            "version": "7",
            "headRevisionId": "head-7",
            "appProperties": {
                "backupsheep_namespace": "backupsheep-v1",
                "backupsheep_role": "backup",
                "backupsheep_backup_uuid": point.backup.uuid_str,
                "backupsheep_sha256": hashlib.sha256(self.payload).hexdigest(),
                "backupsheep_bytes": str(len(self.payload)),
                "backupsheep_node_slug": node_slug,
            },
        }
        client = mock.MagicMock()
        response = SimpleNamespace(status_code=204)
        with mock.patch.object(
            CoreStorageGoogleDrive, "get_client", return_value=client
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._get_file",
            return_value=remote,
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._call",
            return_value=response,
        ) as provider_call:
            self.assertTrue(point.soft_delete())

        self.assertEqual(provider_call.call_args.args[1], "delete")
        self.assertIn("drive-file-1", provider_call.call_args.args[2])

        point.refresh_from_db()
        delete_state = point.metadata["google_drive_upload"]["delete"]
        self.assertEqual(delete_state["phase"], "complete")
        self.assertTrue(delete_state["witness_sha256"])
        self.assertEqual(point.status, point.Status.DELETE_COMPLETED)

    def test_google_drive_lost_delete_response_is_not_replayed(self):
        from apps._tasks.integration.storage.google_drive import (
            GoogleDriveUploadFailure,
        )

        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=False,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-lost",
            state_key="google_drive_upload",
            state={
                "phase": "committed",
                "provider_id": "drive-file-lost",
                "parent_id": "node-folder",
                "version_id": "11",
                "revision": "head-11",
            },
        )
        remote = self._google_drive_remote(point, version="11", revision="head-11")
        client = mock.MagicMock()
        with mock.patch.object(
            CoreStorageGoogleDrive, "get_client", return_value=client
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._get_file",
            return_value=remote,
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._call",
            side_effect=GoogleDriveUploadFailure("PROVIDER_TIMEOUT"),
        ) as provider_call:
            self.assertFalse(point.soft_delete())
            point.refresh_from_db()
            self.assertEqual(point.status, point.Status.DELETE_REQUESTED)
            self.assertEqual(
                point.metadata["google_drive_upload"]["delete"]["phase"],
                "ambiguous",
            )

            # Provider still reports the exact object.  The second worker must
            # stop for reconciliation instead of sending a duplicate DELETE.
            self.assertFalse(point.soft_delete())

        self.assertEqual(provider_call.call_count, 1)
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_REQUESTED)
        self.assertEqual(
            point.last_error_code, "STORAGE_DELETE_RECONCILIATION_REQUIRED"
        )

    def test_google_drive_lost_delete_response_adopts_confirmed_absence(self):
        from apps._tasks.integration.storage.google_drive import (
            GoogleDriveUploadFailure,
        )

        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=False,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-adopt",
            state_key="google_drive_upload",
            state={
                "phase": "committed",
                "provider_id": "drive-file-adopt",
                "parent_id": "node-folder",
                "version_id": "12",
                "revision": "head-12",
            },
        )
        remote = self._google_drive_remote(point, version="12", revision="head-12")
        client = mock.MagicMock()
        with mock.patch.object(
            CoreStorageGoogleDrive, "get_client", return_value=client
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._get_file",
            side_effect=[remote, None],
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._call",
            side_effect=GoogleDriveUploadFailure("PROVIDER_TIMEOUT"),
        ) as provider_call:
            self.assertFalse(point.soft_delete())
            point.refresh_from_db()
            self.assertTrue(point.soft_delete())

        self.assertEqual(provider_call.call_count, 1)
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_COMPLETED)
        self.assertEqual(
            point.metadata["google_drive_upload"]["delete"]["phase"],
            "complete",
        )

    def test_google_drive_unproven_404_fails_without_delete(self):
        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=False,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-missing",
            state_key="google_drive_upload",
            state={
                "phase": "committed",
                "provider_id": "drive-file-missing",
                "parent_id": "node-folder",
                "version_id": "13",
                "revision": "head-13",
            },
        )
        with mock.patch.object(
            CoreStorageGoogleDrive, "get_client", return_value=mock.MagicMock()
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._get_file",
            return_value=None,
        ), mock.patch(
            "apps._tasks.integration.storage.google_drive._call",
        ) as provider_call:
            self.assertFalse(point.soft_delete())

        provider_call.assert_not_called()
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_FAILED)
        self.assertEqual(point.last_error_code, "PROVIDER_NOT_FOUND")

    def test_google_drive_cross_tenant_storage_fails_before_provider_contact(self):
        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=False,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-foreign-account",
            state_key="google_drive_upload",
            state={
                "phase": "committed",
                "provider_id": "drive-file-foreign-account",
                "parent_id": "node-folder",
                "version_id": "14",
                "revision": "head-14",
            },
        )
        other_account, _, _ = factories.make_account()
        CoreStorage.objects.filter(pk=storage.pk).update(account=other_account)
        point.refresh_from_db()

        with mock.patch.object(CoreStorageGoogleDrive, "get_client") as client:
            self.assertFalse(point.soft_delete())

        client.assert_not_called()
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_FAILED)

    def _google_drive_remote(self, point, *, version, revision):
        return {
            "id": point.storage_file_id,
            "name": f"{point.backup.uuid_str}.zip",
            "mimeType": "application/zip",
            "parents": ["node-folder"],
            "trashed": False,
            "size": str(len(self.payload)),
            "version": version,
            "headRevisionId": revision,
            "appProperties": {
                "backupsheep_namespace": "backupsheep-v1",
                "backupsheep_role": "backup",
                "backupsheep_backup_uuid": point.backup.uuid_str,
                "backupsheep_sha256": hashlib.sha256(self.payload).hexdigest(),
                "backupsheep_bytes": str(len(self.payload)),
                "backupsheep_node_slug": point.backup.node.name_slug,
            },
        }

    def test_onedrive_uses_provider_id_and_if_match(self):
        storage = self._storage("onedrive")
        CoreStorageOneDrive.objects.create(
            storage=storage,
            token_type="bearer",
            scope="Files.ReadWrite",
            drive_id="drive-1",
        )
        target_path = "backupsheep/site/backup.zip"
        point = self._point(
            storage,
            storage_file_id=target_path,
            state_key="onedrive_upload",
            state={
                "phase": "committed",
                "provider_path": target_path,
                "provider_id": "item-1",
                "etag": '"etag-1"',
                "revision": '"ctag-1"',
                "version_id": '"ctag-1"',
                "session_fingerprint": "a" * 64,
            },
        )
        remote = {
            "id": "item-1",
            "name": "backup.zip",
            "size": len(self.payload),
            "eTag": '"etag-1"',
            "cTag": '"ctag-1"',
        }
        response = SimpleNamespace(status_code=204)
        with mock.patch(
            "apps._tasks.integration.storage.onedrive._get_item_by_id",
            return_value=remote,
        ), mock.patch(
            "apps._tasks.integration.storage.onedrive._client_headers",
            return_value={"Authorization": "Bearer redacted"},
        ), mock.patch(
            "apps._tasks.integration.storage.onedrive._request",
            return_value=response,
        ) as provider_request:
            self.assertTrue(point.soft_delete())

        self.assertEqual(provider_request.call_args.args[0], "delete")
        self.assertIn("/items/item-1", provider_request.call_args.args[1])
        self.assertEqual(
            provider_request.call_args.kwargs["headers"]["If-Match"], '"etag-1"'
        )

    def test_onedrive_business_item_can_use_persisted_session_proof(self):
        from apps._tasks.integration.storage.onedrive import (
            OneDriveOwnershipFailure,
            _validate_item,
        )

        item = {
            "id": "business-item",
            "name": "backup.zip",
            "size": len(self.payload),
            # Microsoft Graph does not expose description for every drive type.
            "description": None,
        }
        with self.assertRaises(OneDriveOwnershipFailure):
            _validate_item(
                item,
                target_path="backupsheep/site/backup.zip",
                marker="marker",
            )
        self.assertIs(
            _validate_item(
                item,
                target_path="backupsheep/site/backup.zip",
                marker="marker",
                allow_missing_marker=True,
            ),
            item,
        )

    def test_google_cloud_deletes_only_committed_generation_with_preconditions(self):
        from apps._tasks.integration.storage import google_cloud

        storage = self._storage("google_cloud")
        CoreStorageGoogleCloud.objects.create(
            storage=storage,
            service_key=bs_encrypt("{}", self.account.get_encryption_key()),
            bucket_name="unit-test-bucket",
            prefix="backups",
            no_delete=False,
        )
        object_key = "backups/site/owned.zip"
        point = self._point(
            storage,
            storage_file_id=object_key,
            state_key=google_cloud.STATE_KEY,
            state={
                "phase": "committed",
                "object_key": object_key,
                "generation": "7",
                "version_id": "7",
                "etag": '"gcs-etag-7"',
                "metageneration": "3",
            },
        )
        markers = google_cloud._marker_values(
            point.backup.uuid_str,
            point.committed_integrity_identity(),
        )
        point.metadata[google_cloud.STATE_KEY]["ownership_marker"] = markers
        point.save(update_fields=["metadata", "modified"])

        blob = mock.MagicMock()
        blob.name = object_key
        blob.metadata = markers
        blob.size = len(self.payload)
        blob.generation = "7"
        blob.etag = '"gcs-etag-7"'
        blob.metageneration = "3"
        bucket = mock.MagicMock()
        bucket.blob.return_value = blob
        client = mock.MagicMock()
        client.bucket.return_value = bucket
        with mock.patch.object(
            CoreStorageGoogleCloud, "get_credentials", return_value=object()
        ), mock.patch.object(google_cloud.gc_storage, "Client", return_value=client):
            self.assertTrue(point.soft_delete())

        bucket.blob.assert_called_once_with(object_key, generation=7)
        self.assertEqual(blob.delete.call_args.kwargs["if_generation_match"], 7)
        self.assertEqual(blob.delete.call_args.kwargs["if_metageneration_match"], 3)
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_COMPLETED)

    def test_google_cloud_version_drift_fails_closed(self):
        from apps._tasks.integration.storage import google_cloud

        storage = self._storage("google_cloud")
        CoreStorageGoogleCloud.objects.create(
            storage=storage,
            service_key=bs_encrypt("{}", self.account.get_encryption_key()),
            bucket_name="unit-test-bucket",
            no_delete=False,
        )
        object_key = "backups/site/owned.zip"
        point = self._point(
            storage,
            storage_file_id=object_key,
            state_key=google_cloud.STATE_KEY,
            state={
                "phase": "committed",
                "object_key": object_key,
                "generation": "7",
                "version_id": "7",
                "etag": '"gcs-etag-7"',
                "metageneration": "3",
            },
        )
        markers = google_cloud._marker_values(
            point.backup.uuid_str,
            point.committed_integrity_identity(),
        )
        point.metadata[google_cloud.STATE_KEY]["ownership_marker"] = markers
        point.save(update_fields=["metadata", "modified"])
        blob = mock.MagicMock(
            name=object_key,
            metadata=markers,
            size=len(self.payload),
            generation="7",
            etag='"foreign-etag"',
            metageneration="3",
        )
        # MagicMock's constructor reserves ``name``; assign provider fields after.
        blob.name = object_key
        blob.metadata = markers
        blob.size = len(self.payload)
        blob.generation = "7"
        blob.etag = '"foreign-etag"'
        blob.metageneration = "3"
        client = mock.MagicMock()
        client.bucket.return_value.blob.return_value = blob
        with mock.patch.object(
            CoreStorageGoogleCloud, "get_credentials", return_value=object()
        ), mock.patch.object(google_cloud.gc_storage, "Client", return_value=client):
            self.assertFalse(point.soft_delete())
        blob.delete.assert_not_called()

    def test_azure_deletes_exact_version_with_etag_precondition(self):
        from azure.core import MatchConditions
        from apps._tasks.integration.storage import azure

        storage = self._storage("azure")
        CoreStorageAzure.objects.create(
            storage=storage,
            connection_string=bs_encrypt(
                "DefaultEndpointsProtocol=https", self.account.get_encryption_key()
            ),
            bucket_name="unit-test-container",
            prefix="backups",
            no_delete=False,
        )
        object_key = "backups/site/owned.zip"
        point = self._point(
            storage,
            storage_file_id=object_key,
            state_key=azure.STATE_KEY,
            state={
                "phase": "committed",
                "object_key": object_key,
                "version_id": "version-9",
                "etag": '"azure-etag-9"',
            },
        )
        markers = azure._marker_values(
            point.backup.uuid_str,
            point.committed_integrity_identity(),
        )
        point.metadata[azure.STATE_KEY]["ownership_marker"] = markers
        point.save(update_fields=["metadata", "modified"])
        properties = SimpleNamespace(
            metadata=markers,
            size=len(self.payload),
            version_id="version-9",
            etag='"azure-etag-9"',
        )
        blob = mock.MagicMock()
        blob.get_blob_properties.return_value = properties
        service = mock.MagicMock()
        service.get_blob_client.return_value = blob
        with mock.patch.object(CoreStorageAzure, "get_client", return_value=service):
            self.assertTrue(point.soft_delete())

        service.get_blob_client.assert_called_once_with(
            container="unit-test-container",
            blob=object_key,
            version_id="version-9",
        )
        self.assertEqual(blob.delete_blob.call_args.kwargs["etag"], '"azure-etag-9"')
        self.assertEqual(
            blob.delete_blob.call_args.kwargs["match_condition"],
            MatchConditions.IfNotModified,
        )
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.DELETE_COMPLETED)

    def test_provider_no_delete_defers_without_contacting_provider(self):
        storage = self._storage("google_drive")
        CoreStorageGoogleDrive.objects.create(
            storage=storage,
            email_address="backup@example.test",
            no_delete=True,
        )
        point = self._point(
            storage,
            storage_file_id="drive-file-1",
            state_key="google_drive_upload",
            state={"provider_id": "drive-file-1"},
        )
        with mock.patch.object(CoreStorageGoogleDrive, "get_client") as client:
            self.assertFalse(point.soft_delete())

        client.assert_not_called()
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertIn("deletion_protection", point.metadata)
