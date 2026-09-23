"""Focused provider-boundary tests for Dropbox and pCloud storage adapters."""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from types import SimpleNamespace
from unittest import TestCase, mock

from apps._tasks.artifact_encryption import StorageArtifactIdentity
from apps._tasks.integration.storage import dropbox as dropbox_module
from apps._tasks.integration.storage import pcloud as pcloud_module
from apps.console.backup.models import CoreWebsiteBackupStoragePoints


class _Response:
    def __init__(self, payload=None, *, status_code=200, content=b""):
        self._payload = payload
        self.status_code = status_code
        self.content = content

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=1024 * 1024):
        for offset in range(0, len(self.content), max(1, chunk_size)):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        return None


class NotFoundError(Exception):
    """Name intentionally mirrors the SDK's not-found exception classification."""


class _DropboxResponse:
    def __init__(self, content):
        self.content = content

    def iter_content(self, chunk_size=1024 * 1024):
        for offset in range(0, len(self.content), max(1, chunk_size)):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        return None


class _DropboxFake:
    def __init__(self):
        self.objects = {}
        self.upload_calls = 0
        self.lost_upload_response = False
        self.duplicate_entries = None
        self.delete_calls = []

    @staticmethod
    def _metadata(path, object_id, content, *, rev="rev-1", content_hash="dbx-hash"):
        return {
            "id": object_id,
            "name": os.path.basename(path),
            "path_display": path,
            "path_lower": path.lower(),
            "size": len(content),
            "rev": rev,
            "content_hash": content_hash,
            "content": content,
        }

    def files_get_metadata(self, path):
        path = str(path)
        if path in self.objects:
            return dict(self.objects[path])
        for item in self.objects.values():
            if path == str(item["id"]):
                return dict(item)
        raise NotFoundError()

    def files_list_folder(self, path, recursive=False):
        entries = (
            list(self.duplicate_entries)
            if self.duplicate_entries is not None
            else list(self.objects.values())
        )
        return SimpleNamespace(entries=[dict(entry) for entry in entries], has_more=False)

    def files_upload(self, body, path, **kwargs):
        self.upload_calls += 1
        self.objects[path] = self._metadata(
            path,
            f"id:{uuid.uuid4().hex}",
            body,
        )
        if self.lost_upload_response:
            self.lost_upload_response = False
            raise TimeoutError("provider-body=dropbox-secret")
        return dict(self.objects[path])

    def files_download(self, provider_id_or_path):
        for item in self.objects.values():
            if provider_id_or_path in {item["id"], item["path_display"]}:
                return dict(item), _DropboxResponse(item["content"])
        raise NotFoundError()

    def files_delete_v2(self, path, *, parent_rev):
        self.delete_calls.append((path, parent_rev))
        self.objects.pop(path, None)
        return None


class _PCloudFake:
    def __init__(self):
        self.objects = {}
        self.upload_calls = 0
        self.lost_upload_response = False
        self.duplicate_entries = None
        self.calls = []
        self.last_upload_content_type = None

    def _object(self, path, content, file_id=None, *, provider_hash="pc-hash"):
        return {
            "fileid": file_id or str(uuid.uuid4().int % 10_000_000),
            "id": f"f{file_id or uuid.uuid4().int % 10_000_000}",
            "name": os.path.basename(path),
            "path": path,
            "size": len(content),
            "hash": provider_hash,
            "modified": "2026-08-09T00:00:00Z",
            "parentfolderid": 17,
            "content": content,
        }

    def _payload(self, operation, data):
        data = data or {}
        if operation == "createfolderifnotexists":
            return {"result": 0, "metadata": {"folderid": 17}}
        if operation == "stat":
            path = data.get("path")
            file_id = str(data.get("fileid") or "")
            object_data = self.objects.get(path)
            if object_data is None and file_id:
                object_data = next(
                    (
                        item
                        for item in self.objects.values()
                        if str(item["fileid"]) == file_id
                    ),
                    None,
                )
            if object_data is None:
                return {"result": 2009}
            return {"result": 0, "metadata": dict(object_data)}
        if operation == "listfolder":
            entries = (
                list(self.duplicate_entries)
                if self.duplicate_entries is not None
                else list(self.objects.values())
            )
            return {
                "result": 0,
                "metadata": {"contents": [dict(entry) for entry in entries]},
            }
        if operation == "checksumfile":
            file_id = str(data.get("fileid"))
            for item in self.objects.values():
                if str(item["fileid"]) == file_id:
                    return {
                        "result": 0,
                        "sha256": hashlib.sha256(item["content"]).hexdigest(),
                    }
            return {"result": 2009}
        if operation == "getfilelink":
            return {
                "result": 0,
                "hosts": ["c1.pcloud.com"],
                "path": "/download/test",
            }
        if operation == "deletefile":
            file_id = str(data.get("fileid") or "")
            path = next(
                (
                    key
                    for key, item in self.objects.items()
                    if str(item["fileid"]) == file_id
                ),
                None,
            )
            if path is None:
                return {"result": 2009}
            self.objects.pop(path)
            return {"result": 0}
        raise AssertionError(f"unexpected pCloud operation: {operation}")

    def get(self, url, *, params=None, **kwargs):
        self.calls.append(("GET", url, dict(params or {}), dict(kwargs)))
        operation = url.rsplit("/", 1)[-1]
        data = dict(params or {})
        return _Response(self._payload(operation, data))

    def post(self, url, *, data=None, files=None, **kwargs):
        self.calls.append(("POST", url, dict(data or {}), dict(kwargs)))
        operation = url.rsplit("/", 1)[-1]
        if operation != "uploadfile":
            return _Response(self._payload(operation, data))
        self.upload_calls += 1
        file_tuple = (files or {})["file"]
        filename, source, content_type = file_tuple
        self.last_upload_content_type = content_type
        content = source.read()
        folder = data["path"].rstrip("/")
        path = f"{folder}/{filename}" if folder else f"/{filename}"
        object_data = self._object(path, content)
        self.objects[path] = object_data
        if self.lost_upload_response:
            self.lost_upload_response = False
            raise TimeoutError("provider-body=pcloud-secret")
        return _Response({"result": 0, "metadata": [dict(object_data)]})


class _Account:
    id = 7

    def get_encryption_key(self):
        return "encryption-key"

    def create_storage_log(self, *args, **kwargs):
        return None


class _Backup:
    def __init__(self, identifier, events):
        self.uuid = identifier
        self.uuid_str = identifier
        self.attempt_no = 4
        self.type = "website"
        self.node = SimpleNamespace(name_slug="hardening-node")
        self.events = events

    def record_artifact_integrity(self, **kwargs):
        self.events.append(("artifact", dict(kwargs)))


class _DropboxConfig:
    access_token = b"encrypted-access"
    refresh_token = b"encrypted-refresh"


class _PCloudConfig:
    hostname = "api.pcloud.com"

    def get_access_token(self):
        return "pcloud-access-token"


class _Storage:
    def __init__(self, provider):
        self.id = 9
        self.name = f"{provider} storage"
        self.account = _Account()
        self.storage_dropbox = _DropboxConfig()
        self.storage_pcloud = _PCloudConfig()
        self.type = SimpleNamespace(id=10, code=provider, name=provider)
        self.is_air_gapped = False


class _Point:
    Status = CoreWebsiteBackupStoragePoints.Status

    def __init__(self, provider, identifier, events, *, lose_final_save=False):
        self.backup = _Backup(identifier, events)
        self.storage = _Storage(provider)
        self.storage_file_id = None
        self.metadata = {}
        self.status = self.Status.UPLOAD_IN_PROGRESS
        self.events = events
        self.lose_final_save = lose_final_save

    def save(self, *args, **kwargs):
        if self.status == self.Status.UPLOAD_COMPLETE and self.lose_final_save:
            self.lose_final_save = False
            raise OSError("database-body=secret-at-db.internal")
        self.events.append(("save", self.status, dict(self.metadata)))

    def committed_integrity_identity(self):
        state = next(
            (
                value
                for value in (self.metadata or {}).values()
                if isinstance(value, dict)
                and value.get("sha256")
                and value.get("size_bytes") is not None
            ),
            None,
        )
        if state is None:
            return None
        return {
            "sha256": str(state["sha256"]),
            "size_bytes": int(state["size_bytes"]),
        }


class DropboxPCloudHardeningTests(TestCase):
    def setUp(self):
        os.makedirs("_storage", exist_ok=True)
        self.identifier = f"provider-hardening-{uuid.uuid4().hex}"
        self.source = os.path.join("_storage", f"{self.identifier}.zip")
        self.payload = b"backup-payload-for-provider-hardening" * 8
        with open(self.source, "wb") as source:
            source.write(self.payload)
        self.addCleanup(lambda: os.path.exists(self.source) and os.remove(self.source))

    def _point(self, provider, *, lose_final_save=False):
        events = []
        return _Point(provider, self.identifier, events, lose_final_save=lose_final_save), events

    def _bse_identity(self):
        identifier = "12345678-1234-4abc-8def-1234567890ab"
        return StorageArtifactIdentity(
            identifier=identifier,
            filename=f"{identifier}.bse1",
            artifact_format="bse1",
            ownership_marker=f"bse2:{identifier}",
            content_type="application/octet-stream",
        )

    def _write_bse_fixture(self, artifact):
        path = os.path.join("_storage", artifact.filename)
        with open(path, "wb") as source:
            source.write(self.payload)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    @staticmethod
    def _assert_artifact_before_complete(test_case, events):
        artifact_index = next(index for index, event in enumerate(events) if event[0] == "artifact")
        complete_index = next(
            index
            for index, event in enumerate(events)
            if event[0] == "save" and event[1] == CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE
        )
        test_case.assertLess(artifact_index, complete_index)
        artifact = events[artifact_index][1]
        test_case.assertEqual(artifact["role"], "destination")
        test_case.assertEqual(artifact["byte_count"], len(test_case.payload))
        test_case.assertEqual(artifact["checksum_value"], hashlib.sha256(test_case.payload).hexdigest())

    def test_dropbox_lost_provider_response_is_adopted_without_duplicate_upload(self):
        point, events = self._point("dropbox")
        provider = _DropboxFake()
        provider.lost_upload_response = True
        with mock.patch.object(dropbox_module.dropbox, "Dropbox", return_value=provider), mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ):
            dropbox_module.storage_dropbox(point)
        self.assertEqual(provider.upload_calls, 1)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        state = point.metadata[dropbox_module.DROPBOX_METADATA_KEY]
        self.assertEqual(state["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["revision"], "rev-1")
        self._assert_artifact_before_complete(self, events)
        artifact = next(event[1] for event in events if event[0] == "artifact")
        self.assertEqual(artifact["object_key"], point.storage_file_id)

    def test_dropbox_encrypted_path_is_random_and_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        point, _events = self._point("dropbox")
        provider = _DropboxFake()
        with mock.patch.object(
            dropbox_module, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            dropbox_module.dropbox, "Dropbox", return_value=provider
        ), mock.patch.object(dropbox_module, "bs_decrypt", return_value="token"):
            dropbox_module.storage_dropbox(point)

        state = point.metadata[dropbox_module.DROPBOX_METADATA_KEY]
        self.assertEqual(state["path"], f"/{artifact.filename}")
        self.assertEqual(
            state["ownership_marker"], f"backupsheep:{artifact.identifier}"
        )
        remote = next(iter(provider.objects.values()))
        visible = repr(
            {
                "name": remote["name"],
                "path_display": remote["path_display"],
                "path_lower": remote["path_lower"],
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("hardening-node", visible)
        self.assertNotIn(".zip", visible)

    def test_dropbox_encrypted_delete_uses_opaque_path_and_provider_id(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        point, _events = self._point("dropbox")
        provider = _DropboxFake()
        with mock.patch.object(
            dropbox_module, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            dropbox_module.dropbox, "Dropbox", return_value=provider
        ), mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ), mock.patch(
            "apps.console.backup.models.bs_decrypt", return_value="token"
        ), mock.patch(
            "apps._tasks.artifact_encryption.storage_artifact_identity",
            return_value=artifact,
        ), mock.patch(
            "apps._tasks.artifact_encryption.validate_storage_object_key",
            return_value=artifact,
        ):
            dropbox_module.storage_dropbox(point)
            self.assertTrue(CoreWebsiteBackupStoragePoints.soft_delete(point))

        self.assertEqual(
            provider.delete_calls, [(f"/{artifact.filename}", "rev-1")]
        )
        visible = repr(provider.delete_calls)
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("hardening-node", visible)
        self.assertNotIn(".zip", visible)

    def test_dropbox_worker_crash_before_status_persistence_adopts_completed_object(self):
        point, _events = self._point("dropbox", lose_final_save=True)
        provider = _DropboxFake()
        with mock.patch.object(dropbox_module.dropbox, "Dropbox", return_value=provider), mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ):
            with self.assertRaises(dropbox_module.StorageDropboxSafeError):
                dropbox_module.storage_dropbox(point)
            os.remove(self.source)
            dropbox_module.storage_dropbox(point)
        self.assertEqual(provider.upload_calls, 1)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_dropbox_duplicate_matches_fail_closed_without_upload(self):
        point, _events = self._point("dropbox")
        provider = _DropboxFake()
        path = f"/{self.identifier}.zip"
        first = provider._metadata(path, "id:first", self.payload)
        second = provider._metadata(path, "id:second", self.payload, rev="rev-2")
        provider.objects[path] = first
        provider.duplicate_entries = [first, second]
        with mock.patch.object(dropbox_module.dropbox, "Dropbox", return_value=provider), mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ):
            with self.assertRaises(dropbox_module.StorageDropboxSafeError) as raised:
                dropbox_module.storage_dropbox(point)
        self.assertEqual(raised.exception.error_code, "DUPLICATE_MATCH")
        self.assertEqual(provider.upload_calls, 0)
        self.assertNotIn("provider-body", str(raised.exception))

    def test_dropbox_checksum_or_size_mismatch_never_overwrites_existing_object(self):
        point, _events = self._point("dropbox")
        provider = _DropboxFake()
        path = f"/{self.identifier}.zip"
        wrong = b"wrong-provider-content" * 2
        provider.objects[path] = provider._metadata(path, "id:wrong", wrong)
        original = dict(provider.objects[path])
        with mock.patch.object(dropbox_module.dropbox, "Dropbox", return_value=provider), mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ):
            with self.assertRaises(dropbox_module.StorageDropboxSafeError) as raised:
                dropbox_module.storage_dropbox(point)
        self.assertEqual(raised.exception.error_code, "INTEGRITY_MISMATCH")
        self.assertEqual(provider.upload_calls, 0)
        self.assertEqual(provider.objects[path]["content"], original["content"])

    def test_dropbox_timeout_is_bounded_and_safe(self):
        point, _events = self._point("dropbox")
        provider = _DropboxFake()
        original_upload = provider.files_upload

        def timeout(*args, **kwargs):
            provider.upload_calls += 1
            raise TimeoutError("response-body=dropbox-token")

        provider.files_upload = timeout
        with mock.patch.object(dropbox_module.dropbox, "Dropbox", return_value=provider) as client, mock.patch.object(
            dropbox_module, "bs_decrypt", return_value="token"
        ):
            with self.assertRaises(dropbox_module.StorageDropboxSafeError) as raised:
                dropbox_module.storage_dropbox(point)
        self.assertEqual(raised.exception.error_code, "TIMEOUT")
        self.assertNotIn("dropbox-token", str(raised.exception))
        self.assertNotIn("response-body", str(raised.exception))
        self.assertGreater(client.call_args.kwargs["timeout"], 0)
        provider.files_upload = original_upload

    def test_pcloud_lost_provider_response_is_adopted_without_duplicate_upload(self):
        point, events = self._point("pcloud")
        provider = _PCloudFake()
        provider.lost_upload_response = True
        with mock.patch.object(pcloud_module, "requests", provider):
            pcloud_module.storage_pcloud(point)
        self.assertEqual(provider.upload_calls, 1)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        state = point.metadata[pcloud_module.PCLOUD_METADATA_KEY]
        self.assertEqual(state["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["provider_id"], state["fileid"])
        self.assertEqual(state["version_id"], "pc-hash")
        for _method, url, parameters, kwargs in provider.calls:
            self.assertNotIn("pcloud-access-token", url)
            self.assertNotIn("access_token", parameters)
            self.assertEqual(
                kwargs["headers"]["Authorization"],
                "Bearer pcloud-access-token",
            )
            self.assertFalse(kwargs["allow_redirects"])
        self._assert_artifact_before_complete(self, events)

    def test_pcloud_encrypted_path_progress_and_mime_are_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        point, _events = self._point("pcloud")
        provider = _PCloudFake()
        with mock.patch.object(
            pcloud_module, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(pcloud_module, "requests", provider):
            pcloud_module.storage_pcloud(point)

        state = point.metadata[pcloud_module.PCLOUD_METADATA_KEY]
        self.assertEqual(state["folder"], "/")
        self.assertEqual(state["path"], f"/{artifact.filename}")
        self.assertEqual(
            state["progress_hash"], f"backupsheep-{artifact.identifier}"
        )
        self.assertEqual(provider.last_upload_content_type, "application/octet-stream")
        visible_calls = repr(
            [
                (method, url, parameters)
                for method, url, parameters, _kwargs in provider.calls
            ]
        )
        self.assertNotIn(self.identifier, visible_calls)
        self.assertNotIn("hardening-node", visible_calls)
        self.assertNotIn(".zip", visible_calls)

    def test_pcloud_encrypted_delete_uses_opaque_file_id(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        point, _events = self._point("pcloud")
        provider = _PCloudFake()
        with mock.patch.object(
            pcloud_module, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            pcloud_module, "requests", provider
        ), mock.patch(
            "apps._tasks.artifact_encryption.storage_artifact_identity",
            return_value=artifact,
        ), mock.patch(
            "apps._tasks.artifact_encryption.validate_storage_object_key",
            return_value=artifact,
        ):
            pcloud_module.storage_pcloud(point)
            self.assertTrue(CoreWebsiteBackupStoragePoints.soft_delete(point))

        delete_calls = [
            call for call in provider.calls if call[1].endswith("/deletefile")
        ]
        self.assertEqual(len(delete_calls), 1)
        visible = repr(delete_calls)
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("hardening-node", visible)
        self.assertNotIn(".zip", visible)

    def test_pcloud_endpoint_rejects_non_official_hosts_before_network(self):
        for hostname in (
            "api.pcloud.com.attacker.example",
            "attacker.example",
            "api.pcloud.com:443",
            "api.pcloud.com:invalid",
            "https://user@api.pcloud.com",
            "https://api.pcloud.com/redirect",
        ):
            with self.subTest(hostname=hostname):
                with self.assertRaises(pcloud_module.PCloudStorageAdapterError):
                    pcloud_module._request_json(
                        SimpleNamespace(hostname=hostname),
                        "pcloud-access-token",
                        "GET",
                        "stat",
                        data={"path": "/owned/file.zip"},
                    )

    def test_pcloud_worker_crash_before_status_persistence_adopts_completed_object(self):
        point, _events = self._point("pcloud", lose_final_save=True)
        provider = _PCloudFake()
        with mock.patch.object(pcloud_module, "requests", provider):
            with self.assertRaises(pcloud_module.StoragePCloudSafeError):
                pcloud_module.storage_pcloud(point)
            os.remove(self.source)
            pcloud_module.storage_pcloud(point)
        self.assertEqual(provider.upload_calls, 1)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_pcloud_duplicate_matches_fail_closed_without_upload(self):
        point, _events = self._point("pcloud")
        provider = _PCloudFake()
        folder = "/hardening-node"
        path = f"{folder}/{self.identifier}.zip"
        first = provider._object(path, self.payload, file_id="101")
        second = provider._object(path, self.payload, file_id="202")
        provider.objects[path] = first
        provider.duplicate_entries = [first, second]
        with mock.patch.object(pcloud_module, "requests", provider):
            with self.assertRaises(pcloud_module.StoragePCloudSafeError) as raised:
                pcloud_module.storage_pcloud(point)
        self.assertEqual(raised.exception.error_code, "DUPLICATE_MATCH")
        self.assertEqual(provider.upload_calls, 0)

    def test_pcloud_checksum_mismatch_never_overwrites_existing_object(self):
        point, _events = self._point("pcloud")
        provider = _PCloudFake()
        folder = "/hardening-node"
        path = f"{folder}/{self.identifier}.zip"
        wrong = b"wrong-pcloud-content" * 2
        provider.objects[path] = provider._object(path, wrong, file_id="303")
        original = dict(provider.objects[path])
        with mock.patch.object(pcloud_module, "requests", provider):
            with self.assertRaises(pcloud_module.StoragePCloudSafeError) as raised:
                pcloud_module.storage_pcloud(point)
        self.assertEqual(raised.exception.error_code, "INTEGRITY_MISMATCH")
        self.assertEqual(provider.upload_calls, 0)
        self.assertEqual(provider.objects[path]["content"], original["content"])

    def test_pcloud_timeout_is_bounded_and_safe(self):
        point, _events = self._point("pcloud")
        provider = _PCloudFake()
        original_post = provider.post

        def timeout(url, **kwargs):
            if url.endswith("/uploadfile"):
                provider.upload_calls += 1
                raise TimeoutError("response-body=pcloud-secret")
            return original_post(url, **kwargs)

        provider.post = timeout
        with mock.patch.object(pcloud_module, "requests", provider):
            with self.assertRaises(pcloud_module.StoragePCloudSafeError) as raised:
                pcloud_module.storage_pcloud(point)
        self.assertEqual(raised.exception.error_code, "TIMEOUT")
        self.assertNotIn("pcloud-secret", str(raised.exception))
        self.assertNotIn("response-body", str(raised.exception))
