"""Focused crash/reconciliation tests for the Google Drive and OneDrive adapters."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from types import SimpleNamespace
from unittest import mock

import requests as real_requests
from cryptography.fernet import Fernet
from django.test import SimpleTestCase

from apps._tasks.artifact_encryption import StorageArtifactIdentity
from apps._tasks.integration.storage import google_drive, onedrive
from apps.console.backup.models import CoreWebsiteBackupStoragePoints


class _Response:
    def __init__(self, status_code=200, payload=None, *, headers=None, content=b""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = dict(headers or {})
        self.content = content

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=1024 * 1024):
        if self.content:
            yield self.content


class _Artifact:
    def __init__(self, checksum, size):
        self.checksum_algorithm = "sha256"
        self.checksum_value = checksum
        self.byte_count = size


class _ArtifactQuery:
    def __init__(self, artifact):
        self.artifact = artifact

    def filter(self, **kwargs):
        return self

    def order_by(self, *args):
        return self

    def first(self):
        return self.artifact


class _Backup:
    def __init__(self, identifier, checksum, size):
        self.uuid = identifier
        self.uuid_str = identifier
        self.node = SimpleNamespace(name_slug="test-node")
        self.artifact_records = _ArtifactQuery(_Artifact(checksum, size))
        self.artifact_calls = []
        self.events = []

    def record_artifact_integrity(self, **kwargs):
        self.artifact_calls.append(dict(kwargs))
        self.events.append(("artifact", dict(kwargs)))
        return SimpleNamespace(**kwargs)


class _Status:
    UPLOAD_FAILED_FILE_NOT_FOUND = "file-not-found"
    UPLOAD_VALIDATION = "validation"
    UPLOAD_COMPLETE = "complete"


class _Point:
    Status = _Status

    def __init__(self, backup, storage):
        self.backup = backup
        self.storage = storage
        self.metadata = {}
        self.storage_file_id = None
        self.status = "ready"
        self.save_calls = []
        self.fail_complete_once = False
        self.fail_session_once = False
        self.fail_after_provider_acceptance = False
        self.persisted_metadata = None
        self.persisted_storage_file_id = None
        self.persisted_status = None

    def save(self):
        state = (self.metadata or {}).get(google_drive.STATE_KEY) or (self.metadata or {}).get(onedrive.STATE_KEY) or {}
        if self.fail_session_once and state.get("phase") == "session_created":
            self.fail_session_once = False
            raise OSError("database response lost at db.internal:5432")
        if self.fail_after_provider_acceptance and state.get("phase") == "uploading":
            self.fail_after_provider_acceptance = False
            raise OSError("database response lost at db.internal:5432")
        if self.fail_complete_once and self.status == self.Status.UPLOAD_COMPLETE:
            self.fail_complete_once = False
            raise OSError("database response lost at db.internal:5432")
        self.save_calls.append((self.status, json.loads(json.dumps(self.metadata or {}))))
        self.backup.events.append(("save", self.status))
        self.persisted_metadata = json.loads(json.dumps(self.metadata or {}))
        self.persisted_storage_file_id = self.storage_file_id
        self.persisted_status = self.status


class _Account:
    def __init__(self):
        self.id = 7
        self.key = Fernet.generate_key()

    def get_encryption_key(self):
        return self.key

    def create_storage_log(self, *args, **kwargs):
        return None


class _Storage:
    def __init__(self, *, google_client=None, graph=None):
        self.account = _Account()
        self._google_client = google_client
        self._graph = graph
        self.storage_google_drive = SimpleNamespace(get_client=lambda: google_client)
        self.storage_onedrive = SimpleNamespace(
            drive_id="drive-1",
            get_client=lambda: {"Authorization": "Bearer unit-test-token"},
        )


class _DriveClient:
    def __init__(self, payload):
        self.payload = payload
        self.objects = {}
        self.next_id = 1
        self.session_url = "https://www.googleapis.com/upload/session/unit-test"
        self.offset = 0
        self.resume_offset = 0
        self.duplicate_backup = False
        self.duplicate_identifier = None
        self.timeout_on_session = False
        self.upload_ranges = []
        self.posted_file_count = 0
        self.remote_override = None
        self.timeouts = []
        self.delete_calls = []

    @staticmethod
    def _query_value(query, pattern):
        match = re.search(pattern, query)
        return match.group(1) if match else None

    def _list(self, query):
        name = self._query_value(query, r"name = '([^']*)'")
        parent = self._query_value(query, r"'([^']+)' in parents")
        marker_query = "appProperties has" in query
        values = []
        for item in self.objects.values():
            props = item.get("appProperties") or {}
            if name is not None and item.get("name") != name:
                continue
            if parent and parent not in (item.get("parents") or []):
                continue
            if "mimeType = 'application/vnd.google-apps.folder'" in query and item.get("mimeType") != google_drive.FOLDER_MIME:
                continue
            if "mimeType = 'application/zip'" in query and item.get("mimeType") != google_drive.ZIP_MIME:
                continue
            if "mimeType = 'application/octet-stream'" in query and item.get("mimeType") != "application/octet-stream":
                continue
            if marker_query and props.get("backupsheep_namespace") != google_drive.NAMESPACE:
                continue
            values.append(dict(item))
        if self.duplicate_backup and "backupsheep_namespace" in query and "application/zip" in query:
            if not values:
                identifier = self.duplicate_identifier or "duplicate"
                parent_id = parent or "node-1"
                base = {
                    "id": "duplicate-1",
                    "name": f"{identifier}.zip",
                    "mimeType": google_drive.ZIP_MIME,
                    "parents": [parent_id],
                    "trashed": False,
                    "size": 0,
                    "appProperties": {
                        "backupsheep_namespace": google_drive.NAMESPACE,
                        "backupsheep_role": "backup",
                        "backupsheep_backup_uuid": identifier,
                        "backupsheep_sha256": "0" * 64,
                        "backupsheep_bytes": str(len(self.payload)),
                    },
                }
                values = [base, dict(base, id="duplicate-2")]
            else:
                values.extend(dict(item) for item in values)
        return values

    def get(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if "?alt=media" in url:
            file_id = url.split("/files/", 1)[1].split("?", 1)[0]
            item = self.objects.get(file_id)
            return _Response(200, content=(item or {}).get("content", b""))
        if url.rstrip("/").endswith("/files"):
            return _Response(200, {"files": self._list((kwargs.get("params") or {}).get("q", ""))})
        file_id = url.rsplit("/", 1)[-1]
        item = self.objects.get(file_id)
        return _Response(200 if item else 404, dict(item or {}))

    def post(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if "uploadType=resumable" in url:
            if self.timeout_on_session:
                raise real_requests.exceptions.Timeout("token=do-not-leak")
            return _Response(200, headers={"Location": self.session_url})
        metadata = json.loads(kwargs.get("data") or "{}")
        file_id = f"drive-{self.next_id}"
        self.next_id += 1
        parents = list(metadata.get("parents") or ["root"])
        item = {
            "id": file_id,
            "name": metadata["name"],
            "mimeType": metadata["mimeType"],
            "parents": parents,
            "trashed": False,
            "appProperties": dict(metadata.get("appProperties") or {}),
            "size": 0,
            "content": b"",
            "version": "1",
            "headRevisionId": "rev-1",
            "md5Checksum": "",
        }
        self.objects[file_id] = item
        self.posted_file_count += 1
        return _Response(200, {"id": file_id})

    def patch(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        return self.post(url, **kwargs)

    def put(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if url != self.session_url:
            raise AssertionError(f"unexpected Google URL: {url}")
        content_range = (kwargs.get("headers") or {}).get("Content-Range", "")
        if content_range.startswith("bytes */"):
            item = next((value for value in self.objects.values() if value.get("mimeType") != google_drive.FOLDER_MIME), None)
            if item and len(item.get("content", b"")) == self.payload.__len__():
                return _Response(200, dict(item))
            if self.resume_offset:
                if item and not item.get("content"):
                    item["content"] = self.payload[: self.resume_offset]
                    item["size"] = self.resume_offset
                return _Response(308, headers={"Range": f"bytes=0-{self.resume_offset - 1}"})
            return _Response(308)
        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
        if not match:
            raise AssertionError(content_range)
        start, end, _total = (int(value) for value in match.groups())
        self.upload_ranges.append((start, end))
        item = next(value for value in self.objects.values() if value.get("mimeType") != google_drive.FOLDER_MIME)
        data = kwargs.get("data") or b""
        current = bytearray(item.get("content", b""))
        if len(current) < start:
            current.extend(b"\x00" * (start - len(current)))
        current[start:end + 1] = data
        item["content"] = (
            self.remote_override
            if end + 1 >= len(self.payload) and self.remote_override is not None
            else bytes(current)
        )
        item["size"] = len(item["content"])
        item["version"] = "2"
        item["headRevisionId"] = "rev-2"
        if end + 1 < len(self.payload):
            return _Response(308, headers={"Range": f"bytes=0-{end}"})
        return _Response(200, dict(item))

    def delete(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        self.delete_calls.append(url)
        file_id = url.rsplit("/", 1)[-1]
        self.objects.pop(file_id, None)
        return _Response(204)


class _GraphClient:
    def __init__(self, payload):
        self.payload = payload
        self.item = None
        self.session_url = "https://upload.example.invalid/session?opaque=token-do-not-persist"
        self.offset = 0
        self.accepted = False
        self.duplicate = False
        self.timeout_on_create = False
        self.resume_offset = 0
        self.force_partial = False
        self.upload_ranges = []
        self.timeouts = []
        self.fail_session_persistence = False
        self.conflict_on_put = False
        self.create_payloads = []
        self.delete_calls = []

    def _item_payload(self):
        if not self.item:
            return _Response(404, {"error": {"code": "itemNotFound", "message": "secret body"}})
        item = dict(self.item)
        item["file"] = {}
        return _Response(200, item)

    def get(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if url == self.session_url:
            if self.item and len(self.item.get("content", b"")) == len(self.payload):
                return _Response(200, dict(self.item))
            offset = self.resume_offset or self.offset
            return _Response(202, {"nextExpectedRanges": [f"{offset}-"]})
        if url.endswith(":/content"):
            return _Response(200, content=(self.item or {}).get("content", b""))
        if self.duplicate:
            first = dict(self.item or {"id": "one", "name": "backup.zip", "description": "marker"})
            second = dict(first, id="two")
            return _Response(200, {"value": [first, second]})
        return self._item_payload()

    def post(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if self.timeout_on_create:
            raise real_requests.exceptions.Timeout("Authorization: Bearer secret")
        self.create_payloads.append(json.loads(kwargs.get("data") or "{}"))
        return _Response(200, {"uploadUrl": self.session_url})

    def put(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        if url != self.session_url:
            raise AssertionError(f"unexpected Graph URL: {url}")
        headers = kwargs.get("headers") or {}
        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", headers.get("Content-Range", ""))
        if not match:
            raise AssertionError(headers)
        start, end, total = (int(value) for value in match.groups())
        data = kwargs.get("data") or b""
        if self.conflict_on_put and not self.upload_ranges:
            self.item = {
                "id": "graph-item-1",
                "name": getattr(self, "name", "backup.zip"),
                "description": self.description,
                "size": total,
                "eTag": "etag-1",
                "cTag": "revision-1",
                "lastModifiedDateTime": "2026-08-09T00:00:00Z",
                "content": self.payload,
            }
            return _Response(409, {"error": {"code": "nameAlreadyExists", "message": "secret"}})
        accepted_end = end
        if self.force_partial and not self.upload_ranges:
            accepted_end = min(end, 4)
            self.force_partial = False
        self.upload_ranges.append((start, accepted_end))
        self.offset = accepted_end + 1
        self.accepted = True
        if self.offset < total:
            return _Response(202, {"nextExpectedRanges": [f"{self.offset}-"]})
        self.item = {
            "id": "graph-item-1",
            "name": getattr(self, "name", "backup.zip"),
            "description": self.description,
            "size": total,
            "eTag": "etag-1",
            "cTag": "revision-1",
            "lastModifiedDateTime": "2026-08-09T00:00:00Z",
            "content": self.payload,
        }
        return _Response(201, dict(self.item))

    def delete(self, url, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        self.delete_calls.append((url, dict(kwargs.get("headers") or {})))
        self.item = None
        return _Response(204)


class _AdapterFixtureMixin:
    def setUp(self):
        self.identifier = f"gdrive-onedrive-{uuid.uuid4().hex}"
        self.payload = (b"backup-payload-" * 1000) + b"!"
        self.path = os.path.join("_storage", f"{self.identifier}.zip")
        os.makedirs("_storage", exist_ok=True)
        with open(self.path, "wb") as source:
            source.write(self.payload)
        self.checksum = hashlib.sha256(self.payload).hexdigest()
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def _backup(self):
        return _Backup(self.identifier, self.checksum, len(self.payload))

    def _point(self, storage):
        return _Point(self._backup(), storage)

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


class GoogleDriveHardeningTests(_AdapterFixtureMixin, SimpleTestCase):
    def _client_and_point(self):
        client = _DriveClient(self.payload)
        storage = _Storage(google_client=client)
        point = self._point(storage)
        client.duplicate_identifier = point.backup.uuid_str
        return client, point

    def test_encrypted_file_name_folder_and_properties_are_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        client, point = self._client_and_point()

        with mock.patch.object(
            google_drive, "storage_artifact_identity", return_value=artifact
        ):
            google_drive.storage_google_drive(point)

        files = [
            item
            for item in client.objects.values()
            if item.get("mimeType") != google_drive.FOLDER_MIME
        ]
        self.assertEqual(len(files), 1)
        remote = files[0]
        self.assertEqual(client.posted_file_count, 2)  # fixed root plus artifact
        self.assertEqual(remote["name"], artifact.filename)
        self.assertEqual(remote["mimeType"], "application/octet-stream")
        self.assertEqual(
            remote["appProperties"],
            {
                "backupsheep_namespace": google_drive.NAMESPACE,
                "backupsheep_role": "backup",
                "backupsheep_sha256": self.checksum,
                "backupsheep_bytes": str(len(self.payload)),
                "backupsheep_artifact_id": artifact.ownership_marker,
            },
        )
        visible = repr(
            {
                "name": remote["name"],
                "mimeType": remote["mimeType"],
                "parents": remote["parents"],
                "appProperties": remote["appProperties"],
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)
        self.assertNotIn("backupsheep_backup_uuid", visible)

    def test_encrypted_delete_targets_only_the_opaque_provider_identity(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        client, point = self._client_and_point()

        point.backup.pk = 42
        point.backup.node.pk = 43
        point.backup.node.connection = SimpleNamespace(account_id=7)
        point.storage.pk = 9
        point.storage.account_id = 7
        point.committed_integrity_identity = lambda: {
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
        }

        with mock.patch.object(
            google_drive, "storage_artifact_identity", return_value=artifact
        ):
            google_drive.storage_google_drive(point)
            provider_id = point.storage_file_id
            self.assertTrue(
                google_drive.delete_google_drive_storage_point(point)
            )

        self.assertEqual(len(client.delete_calls), 1)
        self.assertTrue(client.delete_calls[0].endswith(f"/{provider_id}"))
        self.assertNotIn(provider_id, client.objects)
        delete_state = point.metadata[google_drive.STATE_KEY][
            google_drive.DELETE_STATE_KEY
        ]
        self.assertEqual(delete_state["phase"], "complete")
        visible = repr(
            {
                "name": artifact.filename,
                "provider_id": provider_id,
                "delete_call": client.delete_calls,
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)

    def test_lost_final_database_response_is_adopted_without_second_file(self):
        client, point = self._client_and_point()
        point.fail_complete_once = True
        with self.assertRaises(google_drive.GoogleDriveUploadFailure) as error:
            google_drive.storage_google_drive(point)
        self.assertNotIn("db.internal", str(error.exception))
        self.assertNotIn("token", str(error.exception).lower())
        self.assertEqual(client.posted_file_count, 3)  # root, node, one file

        os.remove(self.path)
        google_drive.storage_google_drive(point)

        self.assertEqual(client.posted_file_count, 3)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(len(point.backup.artifact_calls), 2)
        self.assertEqual(point.backup.artifact_calls[-1]["checksum_value"], self.checksum)
        self.assertIsNotNone(point.backup.artifact_calls[-1]["verified_at"])
        self.assertEqual(
            point.backup.artifact_calls[-1]["metadata"]["storage_metadata_key"],
            google_drive.STATE_KEY,
        )
        self.assertNotIn(client.session_url, json.dumps(point.metadata))
        artifact_index = next(i for i, event in enumerate(point.backup.events) if event[0] == "artifact")
        complete_index = max(i for i, event in enumerate(point.backup.events) if event == ("save", point.Status.UPLOAD_COMPLETE))
        self.assertLess(artifact_index, complete_index)
        self.assertTrue(all(timeout is not None for timeout in client.timeouts))

    def test_duplicate_owned_matches_fail_closed(self):
        client, point = self._client_and_point()
        client.duplicate_backup = True
        with self.assertRaises(google_drive.GoogleDriveReconciliationRequired) as error:
            google_drive.storage_google_drive(point)
        self.assertNotIn("response", str(error.exception).lower())
        self.assertEqual(client.posted_file_count, 2)  # no backup file was created
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_google_status_offset_is_used_without_resending_accepted_bytes(self):
        client, point = self._client_and_point()
        client.resume_offset = 5
        google_drive.storage_google_drive(point)
        self.assertEqual(client.upload_ranges[0][0], 5)
        self.assertEqual(point.metadata[google_drive.STATE_KEY]["size_bytes"], len(self.payload))
        self.assertEqual(point.metadata[google_drive.STATE_KEY]["checksum_algorithm"], "sha256")

    def test_lost_session_creation_response_reuses_single_placeholder_file(self):
        client, point = self._client_and_point()
        point.fail_session_once = True
        with self.assertRaises(google_drive.GoogleDriveUploadFailure):
            google_drive.storage_google_drive(point)
        point.metadata = point.persisted_metadata
        google_drive.storage_google_drive(point)
        self.assertEqual(client.posted_file_count, 3)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_remote_checksum_mismatch_blocks_completion_and_artifact(self):
        client, point = self._client_and_point()
        client.payload = b"x" * len(self.payload)
        client.remote_override = client.payload
        with self.assertRaises(google_drive.GoogleDriveIntegrityFailure):
            google_drive.storage_google_drive(point)
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertFalse(point.backup.artifact_calls)

    def test_local_source_mismatch_is_rejected_before_provider_write(self):
        with open(self.path, "ab") as source:
            source.write(b"tampered")
        client, point = self._client_and_point()
        with self.assertRaises(google_drive.GoogleDriveUploadFailure) as error:
            google_drive.storage_google_drive(point)
        self.assertEqual(error.exception.code, "SOURCE_ARTIFACT_INVALID")
        self.assertEqual(client.posted_file_count, 0)

    def test_google_timeout_is_bounded_and_redacted(self):
        client, point = self._client_and_point()
        client.timeout_on_session = True
        with self.assertRaises(google_drive.GoogleDriveUploadFailure) as error:
            google_drive.storage_google_drive(point)
        self.assertEqual(error.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("do-not-leak", str(error.exception))
        self.assertNotIn("https://", str(error.exception))

    def test_google_rate_limit_response_is_structured_without_body(self):
        response = _Response(
            403,
            {"error": {"errors": [{"reason": "rateLimitExceeded", "message": "secret"}]}},
        )
        with self.assertRaises(google_drive.GoogleDriveRateLimitFailure) as error:
            google_drive._raise_response(response, "unit-test")
        self.assertEqual(error.exception.code, "STORAGE_RATE_LIMITED")
        self.assertNotIn("secret", str(error.exception))


class OneDriveHardeningTests(_AdapterFixtureMixin, SimpleTestCase):
    def _client_and_point(self):
        graph = _GraphClient(self.payload)
        storage = _Storage(graph=graph)
        graph.name = f"{self.identifier}.zip"
        graph.description = onedrive._marker(self.identifier, {"sha256": self.checksum, "size_bytes": len(self.payload)})
        point = self._point(storage)
        return graph, storage, point

    def _run(self, graph, point):
        with mock.patch.object(onedrive.requests, "get", side_effect=graph.get), mock.patch.object(
            onedrive.requests, "post", side_effect=graph.post
        ), mock.patch.object(onedrive.requests, "put", side_effect=graph.put):
            return onedrive.storage_onedrive(point)

    def test_encrypted_path_and_description_are_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        graph, _storage, point = self._client_and_point()
        graph.name = artifact.filename
        graph.description = onedrive._marker(
            artifact,
            {"sha256": self.checksum, "size_bytes": len(self.payload)},
        )

        with mock.patch.object(
            onedrive, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            onedrive, "validate_storage_object_key", return_value=artifact
        ):
            self._run(graph, point)

        self.assertEqual(
            point.storage_file_id, f"backupsheep/{artifact.filename}"
        )
        self.assertEqual(graph.item["name"], artifact.filename)
        self.assertEqual(graph.item["description"], graph.description)
        self.assertEqual(
            graph.create_payloads[-1]["item"]["description"], graph.description
        )
        visible = repr(
            {
                "path": point.storage_file_id,
                "name": graph.item["name"],
                "description": graph.item["description"],
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn("backup uuid", visible)
        self.assertNotIn(".zip", visible)

    def test_encrypted_delete_targets_only_opaque_path_and_provider_id(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        graph, storage, point = self._client_and_point()
        graph.name = artifact.filename
        graph.description = onedrive._marker(
            artifact,
            {"sha256": self.checksum, "size_bytes": len(self.payload)},
        )
        storage.id = 9
        storage.name = "OneDrive storage"
        storage.type = SimpleNamespace(id=10, code="onedrive", name="OneDrive")
        storage.is_air_gapped = False
        point.Status = CoreWebsiteBackupStoragePoints.Status
        point.committed_integrity_identity = lambda: {
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
        }

        with mock.patch.object(
            onedrive, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            onedrive, "validate_storage_object_key", return_value=artifact
        ):
            self._run(graph, point)

        with mock.patch.object(
            onedrive.requests, "get", side_effect=graph.get
        ), mock.patch.object(
            onedrive.requests, "delete", side_effect=graph.delete
        ), mock.patch(
            "apps._tasks.artifact_encryption.storage_artifact_identity",
            return_value=artifact,
        ), mock.patch(
            "apps._tasks.artifact_encryption.validate_storage_object_key",
            return_value=artifact,
        ):
            self.assertTrue(CoreWebsiteBackupStoragePoints.soft_delete(point))

        self.assertEqual(len(graph.delete_calls), 1)
        url, headers = graph.delete_calls[0]
        self.assertIn("/items/graph-item-1", url)
        self.assertEqual(headers["If-Match"], "etag-1")
        visible = repr(
            {
                "path": f"backupsheep/{artifact.filename}",
                "url": url,
                "description": graph.description,
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)

    def test_lost_final_database_response_is_adopted_by_deterministic_path(self):
        graph, _storage, point = self._client_and_point()
        point.fail_complete_once = True
        with self.assertRaises(onedrive.OneDriveUploadFailure) as error:
            self._run(graph, point)
        self.assertNotIn("db.internal", str(error.exception))
        os.remove(self.path)
        self._run(graph, point)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(point.storage_file_id, f"backupsheep/test-node/{self.identifier}.zip")
        self.assertEqual(point.backup.artifact_calls[-1]["etag"], "etag-1")
        self.assertIsNotNone(point.backup.artifact_calls[-1]["verified_at"])
        self.assertEqual(
            point.backup.artifact_calls[-1]["metadata"]["storage_metadata_key"],
            onedrive.STATE_KEY,
        )
        self.assertNotIn(graph.session_url, json.dumps(point.metadata))
        artifact_index = next(i for i, event in enumerate(point.backup.events) if event[0] == "artifact")
        complete_index = max(i for i, event in enumerate(point.backup.events) if event == ("save", point.Status.UPLOAD_COMPLETE))
        self.assertLess(artifact_index, complete_index)
        self.assertTrue(all(timeout is not None for timeout in graph.timeouts))

    def test_duplicate_matches_fail_closed(self):
        graph, _storage, point = self._client_and_point()
        graph.duplicate = True
        with self.assertRaises(onedrive.OneDriveReconciliationRequired):
            self._run(graph, point)
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_worker_crash_after_provider_acceptance_resumes_from_next_expected_range(self):
        graph, _storage, point = self._client_and_point()
        graph.payload = self.payload
        graph.description = onedrive._marker(self.identifier, {"sha256": self.checksum, "size_bytes": len(self.payload)})
        graph.force_partial = True
        point.fail_after_provider_acceptance = True
        with self.assertRaises(onedrive.OneDriveUploadFailure) as error:
            self._run(graph, point)
        self.assertNotIn("db.internal", str(error.exception))
        # Recreate the last durable DB snapshot: the session URL persisted before
        # the provider accepted the first range, but the post-acceptance offset did not.
        point.metadata = point.persisted_metadata
        self._run(graph, point)
        self.assertGreaterEqual(len(graph.upload_ranges), 2)
        self.assertEqual(graph.upload_ranges[-1][0], graph.upload_ranges[0][1] + 1)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertNotIn(graph.session_url, json.dumps(point.metadata))

    def test_lost_session_creation_response_reconciles_owned_path_on_conflict(self):
        graph, _storage, point = self._client_and_point()
        point.fail_session_once = True
        graph.conflict_on_put = True
        with self.assertRaises(onedrive.OneDriveUploadFailure):
            self._run(graph, point)
        point.metadata = point.persisted_metadata
        self._run(graph, point)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(graph.upload_ranges, [])
        self.assertNotIn(graph.session_url, json.dumps(point.persisted_metadata))

    def test_checksum_mismatch_blocks_completion_and_artifact(self):
        graph, _storage, point = self._client_and_point()
        graph.payload = b"wrong-provider-bytes".ljust(len(self.payload), b"x")[: len(self.payload)]
        with self.assertRaises(onedrive.OneDriveIntegrityFailure):
            self._run(graph, point)
        self.assertFalse(point.backup.artifact_calls)
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_local_source_mismatch_is_rejected_before_provider_write(self):
        with open(self.path, "ab") as source:
            source.write(b"tampered")
        graph, _storage, point = self._client_and_point()
        with self.assertRaises(onedrive.OneDriveUploadFailure) as error:
            self._run(graph, point)
        self.assertEqual(error.exception.code, "SOURCE_ARTIFACT_INVALID")
        self.assertFalse(graph.upload_ranges)

    def test_timeout_and_session_url_are_safe(self):
        graph, _storage, point = self._client_and_point()
        graph.timeout_on_create = True
        with self.assertRaises(onedrive.OneDriveUploadFailure) as error:
            self._run(graph, point)
        self.assertEqual(error.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("Authorization", str(error.exception))
        self.assertNotIn("upload.example", str(error.exception))
