"""Focused exact-identity restore tests for non-S3 storage providers."""

import hashlib
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, override_settings

from apps._tasks.integration import restore_common
from apps._tasks.integration.storage import azure, google_cloud, google_drive, pcloud


PAYLOAD = b"BackupSheep exact restore payload\n"
SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
BACKUP_UUID = "restore-exact-123"
NODE_SLUG = "restore-node"


class _Artifacts:
    def filter(self, **_filters):
        return self

    def exists(self):
        return False

    def __iter__(self):
        return iter(())


class _CommittedLedger:
    def filter(self, **_filters):
        return self

    def exists(self):
        return True

    def __iter__(self):
        return iter(())


class _Response:
    def __init__(
        self,
        status_code=200,
        *,
        chunks=None,
        payload=None,
        body_error=None,
        headers=None,
    ):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self._chunks = list(chunks or [])
        self._payload = payload
        self._body_error = body_error
        self.closed = False

    def json(self):
        if isinstance(self._payload, BaseException):
            raise self._payload
        return self._payload

    def iter_content(self, chunk_size=1):
        del chunk_size
        if self._body_error:
            raise self._body_error
        return iter(self._chunks)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("provider response body is intentionally not exposed")

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return False


class _GoogleClient:
    def __init__(self, item, payload=PAYLOAD):
        self.item = item
        self.payload = payload
        self.calls = []
        self.responses = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if "alt=media" in url:
            return _Response(chunks=[self.payload[:8], self.payload[8:]])
        return _Response(payload=dict(self.item))


class _GCSRestoreBlob:
    def __init__(self, key, state, markers, payload=PAYLOAD):
        self.name = key
        self.size = len(payload)
        self.generation = state["generation"]
        self.metageneration = state["metageneration"]
        self.etag = state["etag"]
        self.metadata = dict(markers)
        self.payload = payload
        self.reload_calls = []
        self.download_calls = []
        self.download_write_sizes = []
        self.drift_after_stream = False

    def reload(self, **kwargs):
        self.reload_calls.append(dict(kwargs))
        if self.drift_after_stream and len(self.reload_calls) > 1:
            self.etag = '"gcs-etag-drifted"'

    def download_to_file(self, stream, **kwargs):
        self.download_calls.append(dict(kwargs))
        for offset in range(0, len(self.payload), 7):
            chunk = self.payload[offset : offset + 7]
            self.download_write_sizes.append(len(chunk))
            stream.write(chunk)

    def open(self, *_args, **_kwargs):
        raise AssertionError("restore must not use Blob.open")

    def download_as_bytes(self, **_kwargs):
        raise AssertionError("restore must never buffer a GCS object")


class _GCSRestoreBucket:
    def __init__(self, blob):
        self._blob = blob
        self.blob_calls = []

    def blob(self, key, **kwargs):
        self.blob_calls.append((key, dict(kwargs)))
        return self._blob


class _GCSRestoreClient:
    def __init__(self, bucket):
        self._bucket = bucket
        self.bucket_calls = []

    def bucket(self, name):
        self.bucket_calls.append(name)
        return self._bucket


class _AzureRestoreDownloader:
    def __init__(self, payload):
        self.payload = payload
        self.chunk_calls = 0

    def chunks(self):
        self.chunk_calls += 1
        for offset in range(0, len(self.payload), 6):
            yield self.payload[offset : offset + 6]

    def readall(self):
        raise AssertionError("restore must never call Azure readall")


class _AzureRestoreBlob:
    def __init__(self, state, markers, payload=PAYLOAD):
        self.state = state
        self.markers = markers
        self.payload = payload
        self.property_calls = []
        self.download_calls = []
        self.downloader = _AzureRestoreDownloader(payload)
        self.drift_after_stream = False

    def get_blob_properties(self, **kwargs):
        self.property_calls.append(dict(kwargs))
        etag = self.state["etag"]
        if self.drift_after_stream and len(self.property_calls) > 1:
            etag = '"azure-etag-drifted"'
        return SimpleNamespace(
            size=len(self.payload),
            etag=etag,
            version_id=self.state["version_id"],
            metadata=dict(self.markers),
        )

    def download_blob(self, **kwargs):
        self.download_calls.append(dict(kwargs))
        return self.downloader


class _AzureRestoreService:
    def __init__(self, blob):
        self._blob = blob
        self.calls = []

    def get_blob_client(self, **kwargs):
        self.calls.append(dict(kwargs))
        return self._blob


class ExactRestoreFixtures:
    def _point(self, provider, state, *, storage_file_id=None, config=None):
        backup = SimpleNamespace(
            uuid_str=BACKUP_UUID,
            uuid=BACKUP_UUID,
            node=SimpleNamespace(name_slug=NODE_SLUG),
            artifact_records=_Artifacts(),
        )
        account = SimpleNamespace(get_encryption_key=lambda: b"unit-test-key")
        storage = SimpleNamespace(
            type=SimpleNamespace(code=provider),
            account=account,
            storage_azure=None,
            storage_dropbox=None,
            storage_google_cloud=None,
            storage_pcloud=None,
            storage_google_drive=None,
            storage_onedrive=None,
        )
        setattr(storage, f"storage_{provider}", config or SimpleNamespace())
        point = SimpleNamespace(
            backup=backup,
            storage=storage,
            storage_id=41,
            storage_file_id=storage_file_id or state.get("provider_id") or state.get("provider_path"),
            metadata={restore_common.PROVIDER_STATE_KEYS[provider]: state},
            generate_download_url=mock.Mock(return_value="https://legacy.invalid/view"),
        )
        return point

    @staticmethod
    def _base_state(provider, **overrides):
        state = {
            "provider": provider,
            "phase": "committed",
            "provider_id": f"{provider}-file-id",
            "sha256": SHA256,
            "size_bytes": len(PAYLOAD),
            "checksum_algorithm": "sha256",
        }
        state.update(overrides)
        return state


@override_settings(MS_GRAPH_ENDPOINT="https://graph.example.test/v1.0")
class NonS3RestoreDownloadTests(ExactRestoreFixtures, SimpleTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _destination(self, name="restore.zip"):
        return os.path.join(self.temp_dir.name, name)

    def _dropbox_point(self, **overrides):
        state = self._base_state(
            "dropbox",
            provider_id="id:dropbox-file",
            path=f"/{BACKUP_UUID}.zip",
            ownership_marker=f"backupsheep:{BACKUP_UUID}",
            revision="rev-1",
            version_id="rev-1",
            content_hash="dropbox-hash",
            **overrides,
        )
        config = SimpleNamespace(access_token=b"encrypted-access", refresh_token=None)
        return self._point("dropbox", state, config=config), state

    @staticmethod
    def _dropbox_metadata(state):
        return SimpleNamespace(
            id=state["provider_id"],
            path_display=state["path"],
            path_lower=state["path"].lower(),
            size=state["size_bytes"],
            rev=state["revision"],
            content_hash=state["content_hash"],
        )

    def _google_cloud_point(self):
        object_key = f"backups/{NODE_SLUG}/{BACKUP_UUID}.zip"
        state = self._base_state("google_cloud")
        state.pop("provider_id")
        state.update(
            {
                "object_key": object_key,
                "generation": "17",
                "metageneration": "3",
                "version_id": "17",
                "etag": '"gcs-etag-17"',
            }
        )
        markers = google_cloud._marker_values(BACKUP_UUID, state)
        state["ownership_marker"] = dict(markers)
        blob = _GCSRestoreBlob(object_key, state, markers)
        bucket = _GCSRestoreBucket(blob)
        client = _GCSRestoreClient(bucket)
        config = SimpleNamespace(
            prefix="backups",
            bucket_name="restore-bucket",
            get_credentials=mock.Mock(return_value=object()),
        )
        point = self._point(
            "google_cloud",
            state,
            storage_file_id=object_key,
            config=config,
        )
        return point, state, blob, bucket, client

    def _azure_point(self):
        object_key = f"backups/{NODE_SLUG}/{BACKUP_UUID}.zip"
        state = self._base_state("azure")
        state.pop("provider_id")
        state.update(
            {
                "object_key": object_key,
                "version_id": "azure-version-19",
                "etag": '"azure-etag-19"',
            }
        )
        markers = azure._marker_values(BACKUP_UUID, state)
        state["ownership_marker"] = dict(markers)
        blob = _AzureRestoreBlob(state, markers)
        service = _AzureRestoreService(blob)
        config = SimpleNamespace(
            prefix="backups",
            bucket_name="restore-container",
            get_client=mock.Mock(return_value=service),
        )
        point = self._point(
            "azure",
            state,
            storage_file_id=object_key,
            config=config,
        )
        return point, state, blob, service

    def test_dropbox_streams_exact_id_and_revision_without_legacy_link(self):
        point, state = self._dropbox_point()
        metadata = self._dropbox_metadata(state)
        client = mock.Mock()
        client.files_get_metadata.side_effect = [metadata, metadata]
        client.files_download.return_value = (
            metadata,
            _Response(chunks=[PAYLOAD[:3], PAYLOAD[3:]]),
        )

        with mock.patch("dropbox.Dropbox", return_value=client), mock.patch(
            "apps._tasks.integration.restore_common.bs_decrypt", return_value="token"
        ):
            restore_common.fetch_backup_zip(point, self._destination())

        client.files_download.assert_called_once_with(
            state["provider_id"], rev=state["revision"]
        )
        point.generate_download_url.assert_not_called()
        with open(self._destination(), "rb") as stream:
            self.assertEqual(stream.read(), PAYLOAD)

    def test_dropbox_revision_drift_fails_before_provider_bytes_are_read(self):
        point, state = self._dropbox_point()
        drifted = self._dropbox_metadata(state)
        drifted.rev = "rev-2"
        client = mock.Mock()
        client.files_get_metadata.return_value = drifted

        with mock.patch("dropbox.Dropbox", return_value=client), mock.patch(
            "apps._tasks.integration.restore_common.bs_decrypt", return_value="token"
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("revision", str(raised.exception).lower())
        client.files_download.assert_not_called()
        self.assertFalse(os.path.exists(self._destination()))

    def test_dropbox_stream_timeout_is_safe_and_atomic(self):
        point, state = self._dropbox_point()
        metadata = self._dropbox_metadata(state)
        client = mock.Mock()
        client.files_get_metadata.return_value = metadata
        client.files_download.return_value = (
            metadata,
            _Response(body_error=TimeoutError("Bearer dropbox-secret")),
        )

        with mock.patch("dropbox.Dropbox", return_value=client), mock.patch(
            "apps._tasks.integration.restore_common.bs_decrypt", return_value="token"
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("deadline", str(raised.exception).lower())
        self.assertNotIn("dropbox-secret", str(raised.exception))
        self.assertFalse(os.path.exists(self._destination()))

    def test_dropbox_lost_metadata_response_is_safe(self):
        point, _state = self._dropbox_point()
        client = mock.Mock()
        client.files_get_metadata.side_effect = TimeoutError("provider-body=secret")

        with mock.patch("dropbox.Dropbox", return_value=client), mock.patch(
            "apps._tasks.integration.restore_common.bs_decrypt", return_value="token"
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("deadline", str(raised.exception).lower())
        self.assertNotIn("provider-body", str(raised.exception))
        self.assertFalse(os.path.exists(self._destination()))

    def test_dropbox_ownership_marker_mismatch_fails_closed(self):
        point, state = self._dropbox_point()
        state["ownership_marker"] = "backupsheep:another-backup"
        metadata = self._dropbox_metadata(state)
        client = mock.Mock()
        client.files_get_metadata.return_value = metadata

        with mock.patch("dropbox.Dropbox", return_value=client), mock.patch(
            "apps._tasks.integration.restore_common.bs_decrypt", return_value="token"
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("ownership", str(raised.exception).lower())
        client.files_download.assert_not_called()

    def test_onedrive_404_is_classified_without_provider_body(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-item-id",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="etag-1",
            revision="ctag-1",
        )
        config = SimpleNamespace(
            drive_id="drive-1",
            get_client=mock.Mock(return_value={"Authorization": "Bearer live-token"}),
        )
        point = self._point("onedrive", state, storage_file_id=state["provider_path"], config=config)

        with mock.patch.object(
            restore_common.requests,
            "get",
            return_value=_Response(status_code=404, payload={"error": "secret provider body"}),
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("not found", str(raised.exception).lower())
        self.assertNotIn("secret provider body", str(raised.exception))
        self.assertFalse(os.path.exists(self._destination()))

    def test_ambiguous_provider_state_is_rejected_before_authentication(self):
        point, _state = self._dropbox_point(file_id="different-dropbox-id")
        with self.assertRaises(restore_common.RestoreError) as raised:
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("ambiguous", str(raised.exception).lower())
        point.generate_download_url.assert_not_called()

    def test_pcloud_uses_exact_file_id_and_adapter_verification(self):
        state = self._base_state(
            "pcloud",
            provider_id="9001",
            file_id="9001",
            fileid="9001",
            path=f"/{NODE_SLUG}/{BACKUP_UUID}.zip",
            ownership_marker=f"backupsheep:{BACKUP_UUID}",
        )
        config = SimpleNamespace(
            hostname="api.pcloud.com",
            get_access_token=mock.Mock(return_value="pcloud-token"),
        )
        point = self._point("pcloud", state, storage_file_id=state["path"], config=config)
        candidate = {
            "fileid": "9001",
            "path": state["path"],
            "name": f"{BACKUP_UUID}.zip",
            "size": len(PAYLOAD),
        }

        def request_json(_config, _token, _method, operation, *, data=None, **_kwargs):
            if operation == "stat":
                return {"metadata": dict(candidate)}
            if operation == "getfilelink":
                return {"hosts": ["api.pcloud.com"], "path": "/download/9001"}
            raise AssertionError(operation)

        stream = _Response(chunks=[PAYLOAD])
        with mock.patch.object(pcloud, "_request_json", side_effect=request_json) as request, mock.patch.object(
            pcloud, "_verify_candidate", return_value=candidate
        ) as verify, mock.patch.object(
            restore_common.requests, "get", return_value=stream
        ) as get:
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertGreaterEqual(verify.call_count, 1)
        self.assertEqual(verify.call_args.args[2]["fileid"], "9001")
        self.assertTrue(any(call.kwargs.get("data", {}).get("fileid") == "9001" for call in request.call_args_list))
        self.assertIn("/download/9001", get.call_args.args[0])
        self.assertEqual(get.call_args.kwargs["timeout"], restore_common.DOWNLOAD_TIMEOUT)

    def test_google_cloud_streams_only_the_committed_generation(self):
        point, state, blob, bucket, client = self._google_cloud_point()

        with mock.patch.object(
            google_cloud.gc_storage, "Client", return_value=client
        ):
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(
            bucket.blob_calls,
            [
                (
                    state["object_key"],
                    {
                        "generation": 17,
                        "chunk_size": restore_common.CHUNK_SIZE,
                    },
                )
            ],
        )
        self.assertEqual(len(blob.reload_calls), 2)
        self.assertTrue(
            all(call["if_generation_match"] == 17 for call in blob.reload_calls)
        )
        self.assertEqual(blob.download_calls[0]["if_generation_match"], 17)
        self.assertEqual(blob.download_calls[0]["if_metageneration_match"], 3)
        self.assertFalse(blob.download_calls[0]["single_shot_download"])
        self.assertIsNone(blob.download_calls[0]["checksum"])
        self.assertGreater(len(blob.download_write_sizes), 1)
        point.generate_download_url.assert_not_called()
        with open(self._destination(), "rb") as stream:
            self.assertEqual(stream.read(), PAYLOAD)

    def test_google_cloud_post_stream_generation_drift_is_not_published(self):
        point, _state, blob, _bucket, client = self._google_cloud_point()
        blob.drift_after_stream = True
        destination = self._destination()
        with open(destination, "wb") as stream:
            stream.write(b"previous-gcs-restore")

        with mock.patch.object(
            google_cloud.gc_storage, "Client", return_value=client
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, destination)

        self.assertIn("generation", str(raised.exception).lower())
        with open(destination, "rb") as stream:
            self.assertEqual(stream.read(), b"previous-gcs-restore")

    def test_azure_streams_only_the_committed_version_with_etag_guard(self):
        point, state, blob, service = self._azure_point()

        restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(
            service.calls,
            [
                {
                    "container": "restore-container",
                    "blob": state["object_key"],
                    "version_id": state["version_id"],
                }
            ],
        )
        self.assertEqual(len(blob.property_calls), 2)
        self.assertEqual(blob.download_calls[0]["etag"], state["etag"])
        self.assertEqual(
            str(blob.download_calls[0]["match_condition"]),
            str(azure.MatchConditions.IfNotModified),
        )
        self.assertEqual(blob.downloader.chunk_calls, 1)
        point.generate_download_url.assert_not_called()
        with open(self._destination(), "rb") as stream:
            self.assertEqual(stream.read(), PAYLOAD)

    def test_azure_post_stream_version_drift_is_not_published(self):
        point, _state, blob, _service = self._azure_point()
        blob.drift_after_stream = True
        destination = self._destination()
        with open(destination, "wb") as stream:
            stream.write(b"previous-azure-restore")

        with self.assertRaises(restore_common.RestoreError) as raised:
            restore_common.fetch_backup_zip(point, destination)

        self.assertIn("version", str(raised.exception).lower())
        with open(destination, "rb") as stream:
            self.assertEqual(stream.read(), b"previous-azure-restore")

    def test_google_drive_rechecks_app_properties_version_and_revision(self):
        state = self._base_state(
            "google_drive",
            provider_id="gdrive-file-id",
            object_key="gdrive-file-id",
            provider_path=f"BackupSheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            parent_id="gdrive-node-folder",
            version_id="7",
            revision="head-revision-7",
            md5_checksum="md5-placeholder",
        )
        markers = google_drive._marker_values(
            BACKUP_UUID, state, role="backup", node_slug=NODE_SLUG
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "mimeType": google_drive.ZIP_MIME,
            "parents": [state["parent_id"]],
            "trashed": False,
            "size": len(PAYLOAD),
            "version": "7",
            "headRevisionId": "head-revision-7",
            "md5Checksum": "md5-placeholder",
            "appProperties": markers,
        }
        client = _GoogleClient(item)
        config = SimpleNamespace(get_client=mock.Mock(return_value=client))
        point = self._point("google_drive", state, config=config)

        restore_common.fetch_backup_zip(point, self._destination())

        urls = [call[0] for call in client.calls]
        self.assertTrue(any("alt=media" in url for url in urls))
        self.assertTrue(all("webViewLink" not in url for url in urls))
        self.assertTrue(all(call[1].get("timeout") == restore_common.DOWNLOAD_TIMEOUT for call in client.calls))
        point.generate_download_url.assert_not_called()

    def test_google_drive_version_drift_fails_before_media_read(self):
        state = self._base_state(
            "google_drive",
            provider_id="gdrive-file-id",
            object_key="gdrive-file-id",
            provider_path=f"BackupSheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            parent_id="gdrive-node-folder",
            version_id="7",
            revision="head-revision-7",
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "mimeType": google_drive.ZIP_MIME,
            "parents": [state["parent_id"]],
            "trashed": False,
            "size": len(PAYLOAD),
            "version": "8",
            "headRevisionId": "head-revision-8",
            "appProperties": google_drive._marker_values(
                BACKUP_UUID, state, role="backup", node_slug=NODE_SLUG
            ),
        }
        client = _GoogleClient(item)
        config = SimpleNamespace(get_client=mock.Mock(return_value=client))
        point = self._point("google_drive", state, config=config)

        with self.assertRaises(restore_common.RestoreError) as raised:
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("version", str(raised.exception).lower())
        self.assertFalse(any("alt=media" in call[0] for call in client.calls))

    def test_google_drive_post_stream_drift_does_not_publish_staged_bytes(self):
        state = self._base_state(
            "google_drive",
            provider_id="gdrive-file-id",
            object_key="gdrive-file-id",
            provider_path=f"BackupSheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            parent_id="gdrive-node-folder",
            version_id="7",
            revision="head-revision-7",
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "mimeType": google_drive.ZIP_MIME,
            "parents": [state["parent_id"]],
            "trashed": False,
            "size": len(PAYLOAD),
            "version": "7",
            "headRevisionId": "head-revision-7",
            "appProperties": google_drive._marker_values(
                BACKUP_UUID, state, role="backup", node_slug=NODE_SLUG
            ),
        }
        client = _GoogleClient(item)
        original_get = client.get

        def drift_after_media(url, **kwargs):
            if "alt=media" in url:
                item["version"] = "8"
                item["headRevisionId"] = "head-revision-8"
            return original_get(url, **kwargs)

        client.get = drift_after_media
        config = SimpleNamespace(get_client=mock.Mock(return_value=client))
        point = self._point("google_drive", state, config=config)
        destination = self._destination()
        with open(destination, "wb") as stream:
            stream.write(b"pre-existing-safe-restore")

        with self.assertRaises(restore_common.RestoreError):
            restore_common.fetch_backup_zip(point, destination)

        with open(destination, "rb") as stream:
            self.assertEqual(stream.read(), b"pre-existing-safe-restore")

    def test_onedrive_addresses_item_id_and_sends_if_match(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-item-id",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="etag-1",
            revision="ctag-1",
            version_id="ctag-1",
        )
        marker = (
            f"BackupSheep backup uuid={BACKUP_UUID};"
            f"sha256={SHA256};bytes={len(PAYLOAD)}"
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "description": marker,
            "size": len(PAYLOAD),
            "eTag": "etag-1",
            "cTag": "ctag-1",
            "parentReference": {"driveId": "drive-1"},
            "file": {},
        }
        config = SimpleNamespace(
            drive_id="drive-1",
            get_client=mock.Mock(return_value={"Authorization": "Bearer unit-secret"}),
        )
        point = self._point("onedrive", state, storage_file_id=state["provider_path"], config=config)
        metadata = _Response(payload=item)
        stream = _Response(chunks=[PAYLOAD])

        with mock.patch.object(restore_common.requests, "get", side_effect=[metadata, stream, _Response(payload=item)]) as get:
            restore_common.fetch_backup_zip(point, self._destination())

        content_call = get.call_args_list[1]
        self.assertIn(f"/items/{state['provider_id']}/content", content_call.args[0])
        self.assertEqual(content_call.kwargs["headers"]["If-Match"], state["etag"])

    def test_onedrive_business_accepts_missing_description_with_session_proof(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-business-item",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="business-etag-1",
            revision="business-ctag-1",
            version_id="business-ctag-1",
            session_fingerprint="a" * 64,
            ownership_proof="session_and_verified_content",
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "description": None,
            "size": len(PAYLOAD),
            "eTag": state["etag"],
            "cTag": state["revision"],
            "parentReference": {"driveId": "business-drive"},
            "file": {},
        }
        config = SimpleNamespace(
            drive_id="business-drive",
            get_client=mock.Mock(
                return_value={"Authorization": "Bearer business-secret"}
            ),
        )
        point = self._point(
            "onedrive",
            state,
            storage_file_id=state["provider_path"],
            config=config,
        )

        with mock.patch.object(
            restore_common.requests,
            "get",
            side_effect=[
                _Response(payload=item),
                _Response(chunks=[PAYLOAD]),
                _Response(payload=item),
            ],
        ) as get:
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(get.call_count, 3)
        self.assertIn("/content", get.call_args_list[1].args[0])
        with open(self._destination(), "rb") as stream:
            self.assertEqual(stream.read(), PAYLOAD)

    def test_onedrive_business_rejects_missing_description_without_session_proof(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-business-item",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="business-etag-1",
            revision="business-ctag-1",
            session_fingerprint="not-a-sha256-proof",
            ownership_proof="session_and_verified_content",
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "description": None,
            "size": len(PAYLOAD),
            "eTag": state["etag"],
            "cTag": state["revision"],
            "parentReference": {"driveId": "business-drive"},
            "file": {},
        }
        config = SimpleNamespace(
            drive_id="business-drive",
            get_client=mock.Mock(return_value={"Authorization": "Bearer token"}),
        )
        point = self._point(
            "onedrive",
            state,
            storage_file_id=state["provider_path"],
            config=config,
        )

        with mock.patch.object(
            restore_common.requests,
            "get",
            return_value=_Response(payload=item),
        ) as get:
            with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(get.call_count, 1)

    def test_onedrive_business_wrong_description_overrides_valid_session_proof(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-business-item",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="business-etag-1",
            revision="business-ctag-1",
            session_fingerprint="b" * 64,
            ownership_proof="session_and_verified_content",
        )
        item = {
            "id": state["provider_id"],
            "name": f"{BACKUP_UUID}.zip",
            "description": "BackupSheep backup uuid=wrong-object",
            "size": len(PAYLOAD),
            "eTag": state["etag"],
            "cTag": state["revision"],
            "parentReference": {"driveId": "business-drive"},
            "file": {},
        }
        config = SimpleNamespace(
            drive_id="business-drive",
            get_client=mock.Mock(return_value={"Authorization": "Bearer token"}),
        )
        point = self._point(
            "onedrive",
            state,
            storage_file_id=state["provider_path"],
            config=config,
        )

        with mock.patch.object(
            restore_common.requests,
            "get",
            return_value=_Response(payload=item),
        ) as get:
            with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(get.call_count, 1)

    def test_onedrive_auth_404_and_provider_body_are_not_exposed(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-item-id",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="etag-1",
            revision="ctag-1",
        )
        config = SimpleNamespace(
            drive_id="drive-1",
            get_client=mock.Mock(return_value={"Authorization": "Bearer live-token"}),
        )
        point = self._point("onedrive", state, storage_file_id=state["provider_path"], config=config)

        with mock.patch.object(
            restore_common.requests,
            "get",
            return_value=_Response(status_code=401, payload={"error": "password=database-secret"}),
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("rejected", str(raised.exception).lower())
        self.assertNotIn("database-secret", str(raised.exception))
        self.assertNotIn("live-token", str(raised.exception))
        self.assertFalse(os.path.exists(self._destination()))

    def test_provider_state_normalization_does_not_mutate_persisted_metadata(self):
        point, state, _blob, _bucket, _client = self._google_cloud_point()
        original = dict(state)
        expected = {"size_bytes": len(PAYLOAD), "sha256": SHA256}

        normalized = restore_common._provider_state(
            point,
            "google_cloud",
            expected,
        )

        self.assertEqual(state, original)
        self.assertNotIn("provider_id", state)
        self.assertNotIn("provider_path", state)
        self.assertEqual(normalized["provider_id"], state["object_key"])
        self.assertEqual(normalized["provider_path"], state["object_key"])
        normalized["ownership_marker"]["backupsheep_sha256"] = "0" * 64
        self.assertEqual(state, original)

    def test_response_content_is_never_used_as_a_streaming_fallback(self):
        class ContentOnlyResponse:
            @property
            def content(self):
                raise AssertionError("response.content must not be accessed")

        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            restore_common._response_chunks(ContentOnlyResponse())

        self.assertEqual(raised.exception.code, "MALFORMED_PROVIDER_RESPONSE")
        self.assertFalse(raised.exception.retryable)

    def test_retry_metadata_is_bounded_and_status_aware(self):
        cases = (
            (429, "37", True, 37, "PROVIDER_RATE_LIMITED"),
            (503, "999999", True, 86400, "PROVIDER_TRANSIENT_FAILURE"),
            (404, "15", False, None, "PROVIDER_NOT_FOUND"),
            (401, "15", False, None, "PROVIDER_AUTH_FAILED"),
            (412, "15", False, None, "PROVIDER_VERSION_DRIFT"),
        )
        for status, retry_header, retryable, retry_after, code in cases:
            with self.subTest(status=status):
                response = _Response(
                    status_code=status,
                    headers={"Retry-After": retry_header},
                )
                with self.assertRaises(
                    restore_common._SafeProviderRestoreError
                ) as raised:
                    restore_common._check_provider_response(
                        response,
                        "Unit Provider",
                    )
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(raised.exception.provider_status, status)
                self.assertEqual(raised.exception.retryable, retryable)
                self.assertEqual(raised.exception.retry_after, retry_after)

    def test_timeout_is_retryable_without_leaking_exception_text(self):
        error = restore_common._safe_provider_failure(
            "Unit Provider",
            TimeoutError("Authorization=Bearer raw-secret"),
            retry_after="21",
        )

        self.assertEqual(error.code, "PROVIDER_TIMEOUT")
        self.assertTrue(error.retryable)
        self.assertEqual(error.retry_after, 21)
        self.assertIsNone(error.provider_status)
        self.assertNotIn("raw-secret", str(error))

    def test_permanent_identity_failure_cannot_become_retryable(self):
        error = restore_common._safe_provider_failure(
            "Unit Provider",
            SimpleNamespace(
                error_code="PROVIDER_OWNERSHIP_MISMATCH",
                provider_status=503,
                retry_after=45,
            ),
        )

        self.assertEqual(error.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertFalse(error.retryable)
        self.assertIsNone(error.retry_after)
        self.assertEqual(error.provider_status, 503)

    def test_committed_ledger_without_provider_state_fails_closed(self):
        state = self._base_state(
            "onedrive",
            provider_id="onedrive-item-id",
            object_key=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            provider_path=f"backupsheep/{NODE_SLUG}/{BACKUP_UUID}.zip",
            etag="etag-1",
            revision="ctag-1",
        )
        point = self._point("onedrive", state)
        point.metadata = {}
        point.backup.artifact_records = _CommittedLedger()

        with mock.patch.object(
            restore_common,
            "_expected_integrity",
            return_value={"size_bytes": len(PAYLOAD), "sha256": SHA256},
        ):
            with self.assertRaises(restore_common.RestoreError) as raised:
                restore_common.fetch_backup_zip(point, self._destination())

        self.assertIn("no provider identity", str(raised.exception))
        point.generate_download_url.assert_not_called()

    def test_legacy_without_ledger_keeps_explicit_url_fallback(self):
        point = self._point(
            "onedrive",
            {},
            storage_file_id="legacy-path",
            config=SimpleNamespace(),
        )
        point.metadata = {}
        response = _Response(chunks=[PAYLOAD])
        with mock.patch.object(restore_common.requests, "get", return_value=response) as get:
            restore_common.fetch_backup_zip(point, self._destination())

        point.generate_download_url.assert_called_once_with()
        self.assertEqual(get.call_args.kwargs["timeout"], restore_common.DOWNLOAD_TIMEOUT)
