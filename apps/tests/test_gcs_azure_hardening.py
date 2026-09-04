"""Failure-injection coverage for the Google Cloud and Azure upload adapters."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import uuid
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.test import SimpleTestCase

from apps._tasks.artifact_encryption import StorageArtifactIdentity
from apps._tasks.integration.storage import azure, google_cloud
from apps._tasks.integration.storage import tasks as storage_tasks


class _ResponseNotFound(Exception):
    status_code = 404


class _Artifact:
    checksum_algorithm = "sha256"

    def __init__(self, checksum, size):
        self.checksum_value = checksum
        self.byte_count = size


class _Artifacts:
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
        self.attempt_no = 1
        self.type = "website"
        self.node = SimpleNamespace(name_slug="test-node")
        self.artifact_records = _Artifacts(_Artifact(checksum, size))
        self.artifact_calls = []

    def record_artifact_integrity(self, **kwargs):
        self.artifact_calls.append(dict(kwargs))
        return SimpleNamespace(**kwargs)


class _Status:
    UPLOAD_FAILED = "failed"
    UPLOAD_FAILED_FILE_NOT_FOUND = "file-not-found"
    UPLOAD_RETRY = "retry"
    UPLOAD_VALIDATION = "validation"
    STORAGE_VALIDATION_FAILED = "storage-validation-failed"
    UPLOAD_COMPLETE = "complete"


class _Point:
    Status = _Status

    def __init__(self, backup, storage):
        self.backup = backup
        self.storage = storage
        self.metadata = {}
        self.storage_file_id = None
        self.status = "ready"
        self.save_count = 0
        self.fail_complete_once = False

    def save(self):
        self.save_count += 1
        if self.fail_complete_once and self.status == self.Status.UPLOAD_COMPLETE:
            self.fail_complete_once = False
            raise OSError("db://backup-state?password=secret-canary")


class _Account:
    def __init__(self):
        self.key = Fernet.generate_key()

    def get_encryption_key(self):
        return self.key


class _GCSConfig:
    prefix = "backups"
    bucket_name = "unit-test-bucket"

    def get_credentials(self):
        return object()


class _GCSStorage:
    def __init__(self, client):
        self.account = _Account()
        self.storage_google_cloud = _GCSConfig()
        self.client = client


class _GCSBlob:
    def __init__(self, bucket, name, content=b"", metadata=None):
        self.bucket = bucket
        self.name = name
        self.content = content
        self.metadata = dict(metadata or {})
        self.content_type = "application/zip"
        self.chunk_size = 0
        self.size = len(content)
        self.etag = "\"gcs-etag-1\""
        self.generation = "gcs-generation-7"
        self.metageneration = "2"
        self.md5_hash = "md5-provider-value"
        self.crc32c = "crc32c-provider-value"
        self.upload_calls = 0
        self.always_lose_upload_response = False
        self.remote_content_override = None
        self.delete_calls = []

    def upload_from_filename(self, filename, **kwargs):
        self.upload_calls += 1
        if self.bucket.objects.get(self.name) is not None and kwargs.get("if_generation_match") == 0:
            raise RuntimeError("precondition failed with secret response")
        with open(filename, "rb") as source:
            self.content = source.read()
        self.size = len(self.content)
        self.bucket.objects[self.name] = self
        if self.always_lose_upload_response:
            raise TimeoutError("Authorization: Bearer secret-canary /tmp/private.zip")

    def open(self, *args, **kwargs):
        return io.BytesIO(
            self.remote_content_override
            if self.remote_content_override is not None
            else self.content
        )

    def reload(self, **kwargs):
        return None

    def delete(self, **kwargs):
        self.delete_calls.append(dict(kwargs))
        self.bucket.objects.pop(self.name, None)


class _GCSBucket:
    def __init__(self):
        self.objects = {}
        self.list_override = None
        self.upload_blob = None

    def list_blobs(self, prefix=None, **kwargs):
        if self.list_override is not None:
            return list(self.list_override)
        return [
            blob
            for key, blob in self.objects.items()
            if not prefix or key.startswith(prefix)
        ]

    def blob(self, key, **_kwargs):
        value = self.objects.get(key)
        if value is None and self.upload_blob is not None and self.upload_blob.name == key:
            value = self.upload_blob
        if value is None:
            value = _GCSBlob(self, key)
        self.upload_blob = value
        return value

    def get_blob(self, key, **kwargs):
        return self.objects.get(key)


class _GCSClient:
    def __init__(self, bucket):
        self._bucket = bucket

    def bucket(self, name):
        return self._bucket


class _AzureConfig:
    prefix = "backups"
    bucket_name = "unit-test-container"

    def __init__(self, service):
        self.service = service

    def get_client(self):
        return self.service


class _AzureStorage:
    def __init__(self, service):
        self.account = _Account()
        self.storage_azure = _AzureConfig(service)


class _Downloader:
    def __init__(self, content):
        self.content = content

    def chunks(self):
        for offset in range(0, len(self.content), 11):
            yield self.content[offset : offset + 11]


class _ReadIntoDownloader:
    def __init__(self, content):
        self.content = content

    def readinto(self, stream):
        return stream.write(self.content)


class _AzureBlobClient:
    def __init__(self):
        self.committed = None
        self.uncommitted = {}
        self.stage_calls = []
        self.commit_calls = 0
        self.lose_commit_response = False
        self.remote_content_override = None
        self.foreign_metadata = None
        self.content_settings = None
        self.delete_calls = []

    @property
    def properties(self):
        if self.committed is None:
            return None
        content = self.committed["content"]
        return SimpleNamespace(
            size=len(content),
            etag='"azure-etag-1"',
            version_id="azure-version-9",
            last_modified="2026-08-09T00:00:00Z",
            metadata=self.committed["metadata"],
            content_settings=SimpleNamespace(content_md5=b"md5-bytes"),
        )

    def get_blob_properties(self, **kwargs):
        if self.committed is None:
            raise _ResponseNotFound()
        props = self.properties
        if self.foreign_metadata is not None:
            props.metadata = dict(self.foreign_metadata)
        return props

    def get_block_list(self, **kwargs):
        values = [SimpleNamespace(id=key, size=len(value)) for key, value in self.uncommitted.items()]
        return ([], values)

    def stage_block(self, block_id, data, **kwargs):
        value = data.read() if hasattr(data, "read") else bytes(data)
        self.stage_calls.append((block_id, len(value)))
        self.uncommitted[str(block_id)] = value

    def commit_block_list(self, block_list, **kwargs):
        self.commit_calls += 1
        self.content_settings = kwargs.get("content_settings")
        content = b"".join(self.uncommitted[str(item.id)] for item in block_list)
        self.committed = {
            "content": content,
            "metadata": dict(kwargs.get("metadata") or {}),
        }
        self.uncommitted.clear()
        if self.lose_commit_response:
            raise TimeoutError("https://account.blob.core.windows.net/?sig=secret-canary")
        return self.properties

    def download_blob(self, **kwargs):
        content = self.remote_content_override
        if content is None:
            content = (self.committed or {}).get("content", b"")
        return _Downloader(content)

    def delete_blob(self, **kwargs):
        self.delete_calls.append(dict(kwargs))
        self.committed = None


class _AzureService:
    def __init__(self, blob_client):
        self.blob_client = blob_client
        self.requests = []

    def get_blob_client(self, **kwargs):
        self.requests.append(dict(kwargs))
        return self.blob_client


class _AdapterFixtureMixin:
    def setUp(self):
        self.identifier = f"gcs-azure-{uuid.uuid4().hex}"
        self.payload = (b"backup-payload-" * 500) + b"!"
        self.checksum = hashlib.sha256(self.payload).hexdigest()
        os.makedirs("_storage", exist_ok=True)
        self.path = os.path.join("_storage", f"{self.identifier}.zip")
        with open(self.path, "wb") as source:
            source.write(self.payload)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def _backup(self):
        return _Backup(self.identifier, self.checksum, len(self.payload))

    def _gcs_point(self, bucket=None):
        bucket = bucket or _GCSBucket()
        client = _GCSClient(bucket)
        storage = _GCSStorage(client)
        return bucket, client, _Point(self._backup(), storage)

    def _azure_point(self, blob_client=None):
        blob_client = blob_client or _AzureBlobClient()
        service = _AzureService(blob_client)
        storage = _AzureStorage(service)
        return blob_client, service, _Point(self._backup(), storage)

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


class GoogleCloudHardeningTests(_AdapterFixtureMixin, SimpleTestCase):
    def _run(self, point, client):
        with mock.patch.object(google_cloud.gc_storage, "Client", return_value=client):
            return google_cloud.storage_google_cloud(point)

    def test_encrypted_object_key_and_metadata_are_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        bucket, client, point = self._gcs_point()

        with mock.patch.object(
            google_cloud, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            google_cloud, "validate_storage_object_key", return_value=artifact
        ):
            self._run(point, client)

        key = f"backups/{artifact.filename}"
        remote = bucket.objects[key]
        self.assertEqual(point.storage_file_id, key)
        self.assertEqual(remote.content_type, "application/octet-stream")
        self.assertEqual(
            remote.metadata,
            {
                "backupsheep_namespace": google_cloud.NAMESPACE,
                "backupsheep_sha256": self.checksum,
                "backupsheep_bytes": str(len(self.payload)),
                "backupsheep_artifact_id": artifact.ownership_marker,
            },
        )
        visible = repr({"key": key, "metadata": remote.metadata})
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)
        self.assertNotIn("backupsheep_backup_uuid", visible)

    def test_encrypted_delete_uses_only_durable_opaque_identity(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        bucket, client, point = self._gcs_point()

        with mock.patch.object(
            google_cloud, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            google_cloud, "validate_storage_object_key", return_value=artifact
        ):
            self._run(point, client)
            state = point.metadata[google_cloud.STATE_KEY]
            # The production SDK exposes the immutable generation as a numeric
            # string.  Most upload-only fixtures use a descriptive sentinel.
            state["generation"] = "7"
            bucket.upload_blob.generation = "7"
            point.committed_integrity_identity = lambda: {
                "sha256": self.checksum,
                "size_bytes": len(self.payload),
            }
            point.committed_version_id = lambda: state["generation"]
            with mock.patch.object(
                google_cloud, "_storage_client", return_value=client
            ):
                self.assertTrue(
                    google_cloud.delete_owned_google_cloud_object(point)
                )

        key = f"backups/{artifact.filename}"
        deleted = bucket.upload_blob
        self.assertEqual(point.storage_file_id, key)
        self.assertNotIn(key, bucket.objects)
        self.assertEqual(len(deleted.delete_calls), 1)
        visible = repr(
            {
                "key": key,
                "marker": state["ownership_marker"],
                "delete": deleted.delete_calls,
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)

    def test_lost_upload_response_adopts_one_owned_object(self):
        bucket, client, point = self._gcs_point()
        key = f"backups/test-node/{self.identifier}.zip"
        blob = _GCSBlob(bucket, key)
        blob.always_lose_upload_response = True
        bucket.upload_blob = blob

        self._run(point, client)

        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(blob.upload_calls, 3)
        self.assertEqual(len(point.backup.artifact_calls), 1)
        self.assertEqual(point.metadata[google_cloud.STATE_KEY]["object_key"], key)

    def test_duplicate_exact_objects_fail_closed(self):
        bucket, client, point = self._gcs_point()
        key = f"backups/test-node/{self.identifier}.zip"
        first = _GCSBlob(bucket, key, self.payload, {
            "backupsheep_namespace": google_cloud.NAMESPACE,
            "backupsheep_backup_uuid": self.identifier,
            "backupsheep_sha256": self.checksum,
            "backupsheep_bytes": str(len(self.payload)),
        })
        bucket.list_override = [first, _GCSBlob(bucket, key, self.payload, first.metadata)]

        with self.assertRaises(google_cloud.GoogleCloudReconciliationRequired):
            self._run(point, client)
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertFalse(point.backup.artifact_calls)

    def test_ownership_mismatch_never_adopts_foreign_blob(self):
        bucket, client, point = self._gcs_point()
        key = f"backups/test-node/{self.identifier}.zip"
        foreign = _GCSBlob(bucket, key, self.payload, {"customer": "owned-by-someone-else"})
        bucket.objects[key] = foreign

        with self.assertRaises(google_cloud.GoogleCloudOwnershipFailure) as error:
            self._run(point, client)
        self.assertNotIn("customer", str(error.exception))
        self.assertFalse(point.backup.artifact_calls)

    def test_remote_checksum_mismatch_blocks_completion(self):
        bucket, client, point = self._gcs_point()
        key = f"backups/test-node/{self.identifier}.zip"
        blob = _GCSBlob(bucket, key, self.payload, {
            "backupsheep_namespace": google_cloud.NAMESPACE,
            "backupsheep_backup_uuid": self.identifier,
            "backupsheep_sha256": self.checksum,
            "backupsheep_bytes": str(len(self.payload)),
        })
        blob.remote_content_override = b"tampered".ljust(len(self.payload), b"x")[: len(self.payload)]
        bucket.objects[key] = blob

        with self.assertRaises(google_cloud.GoogleCloudIntegrityFailure):
            self._run(point, client)
        self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertFalse(point.backup.artifact_calls)

    def test_timeout_is_bounded_and_redacted(self):
        bucket, _client, point = self._gcs_point()
        with mock.patch.object(google_cloud.gc_storage, "Client", side_effect=TimeoutError("token-canary /tmp/secret")):
            with self.assertRaises(google_cloud.GoogleCloudUploadFailure) as error:
                google_cloud.storage_google_cloud(point)
        self.assertEqual(error.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("token-canary", str(error.exception))
        self.assertNotIn("/tmp/secret", str(error.exception))

    def test_worker_crash_before_complete_status_adopts_without_second_upload(self):
        bucket, client, point = self._gcs_point()
        point.fail_complete_once = True
        with self.assertRaises(google_cloud.GoogleCloudUploadFailure):
            self._run(point, client)
        point.fail_complete_once = False
        self._run(point, client)
        key = f"backups/test-node/{self.identifier}.zip"
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(bucket.objects[key].upload_calls, 1)
        self.assertEqual(point.backup.artifact_calls[-1]["version_id"], "gcs-generation-7")

    def test_provider_checksum_and_generation_are_persisted(self):
        bucket, client, point = self._gcs_point()
        self._run(point, client)
        state = point.metadata[google_cloud.STATE_KEY]
        self.assertEqual(state["sha256"], self.checksum)
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["provider_checksum"], "crc32c-provider-value")
        self.assertEqual(state["etag"], '"gcs-etag-1"')
        self.assertEqual(state["generation"], "gcs-generation-7")

    def test_resumable_session_state_is_encrypted_before_persistence(self):
        _bucket, _client, point = self._gcs_point()
        session_url = "https://storage.googleapis.com/upload/session?token=secret-canary"
        sealed = google_cloud._seal_session(point.storage, session_url, stored_backup=point)
        self.assertNotIn("secret-canary", repr(sealed))
        self.assertEqual(google_cloud._unseal_session(point.storage, sealed), session_url)

    def test_verification_fallback_streams_into_digest_without_buffering_api(self):
        bucket, _client, point = self._gcs_point()
        blob = _GCSBlob(bucket, "owned", self.payload)
        blob.open = None

        def download_to_file(stream, **_kwargs):
            for offset in range(0, len(self.payload), 13):
                stream.write(self.payload[offset : offset + 13])

        blob.download_to_file = mock.Mock(side_effect=download_to_file)
        identity = google_cloud._remote_stream_identity(blob, stored_backup=point)

        self.assertEqual(identity, {
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
        })
        blob.download_to_file.assert_called_once()

    def test_rate_limit_preserves_retry_after_without_provider_body(self):
        error = RuntimeError("Authorization: Bearer secret-canary")
        error.status_code = 429
        error.response = SimpleNamespace(headers={"Retry-After": "37"})
        failure = google_cloud._provider_failure(error)
        self.assertEqual(failure.code, "STORAGE_RATE_LIMITED")
        self.assertEqual(failure.retry_after, 37)
        self.assertNotIn("secret-canary", str(failure))

    def test_structured_provider_failures_map_to_distinct_storage_outcomes(self):
        _bucket, _client, point = self._gcs_point()
        cases = (
            (
                google_cloud.GoogleCloudUploadFailure(
                    "STORAGE_AUTH_FAILED", retryable=False, stored_backup=point
                ),
                "STORAGE_AUTH_FAILED",
                point.Status.UPLOAD_FAILED,
                False,
            ),
            (
                google_cloud.GoogleCloudUploadFailure(
                    "STORAGE_RATE_LIMITED", retryable=True, stored_backup=point
                ),
                "STORAGE_RATE_LIMITED",
                point.Status.UPLOAD_RETRY,
                True,
            ),
            (
                google_cloud.GoogleCloudUploadFailure(
                    "PROVIDER_TIMEOUT", retryable=True, stored_backup=point
                ),
                "STORAGE_TIMEOUT",
                point.Status.UPLOAD_RETRY,
                True,
            ),
        )
        for error, code, status, retryable in cases:
            with self.subTest(code=code):
                outcome = storage_tasks._storage_error_outcome(error, point)
                self.assertEqual(outcome[0], code)
                self.assertEqual(outcome[2], status)
                self.assertEqual(outcome[3], retryable)


class AzureHardeningTests(_AdapterFixtureMixin, SimpleTestCase):
    def _run(self, point):
        return azure.storage_azure(point)

    def test_encrypted_object_key_and_metadata_are_opaque(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        blob, service, point = self._azure_point()

        with mock.patch.object(
            azure, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            azure, "validate_storage_object_key", return_value=artifact
        ):
            self._run(point)

        key = f"backups/{artifact.filename}"
        self.assertEqual(service.requests[-1]["blob"], key)
        self.assertEqual(point.storage_file_id, key)
        self.assertEqual(
            blob.committed["metadata"],
            {
                "backupsheep_namespace": azure.NAMESPACE,
                "backupsheep_sha256": self.checksum,
                "backupsheep_bytes": str(len(self.payload)),
                "backupsheep_artifact_id": artifact.ownership_marker,
            },
        )
        self.assertEqual(
            blob.content_settings.content_type, "application/octet-stream"
        )
        visible = repr(
            {"key": service.requests[-1]["blob"], "metadata": blob.committed["metadata"]}
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)
        self.assertNotIn("backupsheep_backup_uuid", visible)

    def test_encrypted_delete_uses_only_durable_opaque_identity(self):
        artifact = self._bse_identity()
        self._write_bse_fixture(artifact)
        blob, _service, point = self._azure_point()

        with mock.patch.object(
            azure, "storage_artifact_identity", return_value=artifact
        ), mock.patch.object(
            azure, "validate_storage_object_key", return_value=artifact
        ):
            self._run(point)
            state = point.metadata[azure.STATE_KEY]
            point.committed_integrity_identity = lambda: {
                "sha256": self.checksum,
                "size_bytes": len(self.payload),
            }
            point.committed_version_id = lambda: state["version_id"]
            self.assertTrue(azure.delete_owned_azure_blob(point))

        key = f"backups/{artifact.filename}"
        self.assertEqual(point.storage_file_id, key)
        self.assertIsNone(blob.committed)
        self.assertEqual(len(blob.delete_calls), 1)
        visible = repr(
            {
                "key": key,
                "marker": state["ownership_marker"],
                "delete": blob.delete_calls,
            }
        )
        self.assertNotIn(self.identifier, visible)
        self.assertNotIn("test-node", visible)
        self.assertNotIn(".zip", visible)

    def test_lost_commit_response_adopts_owned_blob(self):
        blob, _service, point = self._azure_point()
        blob.lose_commit_response = True
        self._run(point)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertGreaterEqual(blob.commit_calls, 1)
        self.assertEqual(len(point.backup.artifact_calls), 1)

    def test_ownership_mismatch_never_adopts_foreign_blob(self):
        blob, _service, point = self._azure_point()
        blob.committed = {"content": self.payload, "metadata": {"customer": "foreign"}}
        with self.assertRaises(azure.AzureOwnershipFailure) as error:
            self._run(point)
        self.assertNotIn("foreign", str(error.exception))
        self.assertFalse(point.backup.artifact_calls)

    def test_uncommitted_unknown_block_fails_closed(self):
        blob, _service, point = self._azure_point()
        blob.uncommitted["foreign-block-id"] = self.payload
        with self.assertRaises(azure.AzureOwnershipFailure):
            self._run(point)
        self.assertFalse(blob.committed)

    def test_remote_checksum_mismatch_blocks_completion(self):
        blob, _service, point = self._azure_point()
        self._run(point)
        point.status = "ready"
        point.backup.artifact_calls.clear()
        blob.remote_content_override = b"wrong".ljust(len(self.payload), b"x")[: len(self.payload)]
        with self.assertRaises(azure.AzureIntegrityFailure):
            self._run(point)
        self.assertFalse(point.backup.artifact_calls)

    def test_timeout_is_bounded_and_redacted(self):
        blob, service, point = self._azure_point()
        service.get_blob_client = mock.Mock(side_effect=TimeoutError("SAS=secret-canary /srv/private"))
        with self.assertRaises(azure.AzureUploadFailure) as error:
            self._run(point)
        self.assertEqual(error.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("secret-canary", str(error.exception))
        self.assertNotIn("/srv/private", str(error.exception))

    def test_worker_crash_before_complete_status_adopts_without_second_commit(self):
        blob, _service, point = self._azure_point()
        point.fail_complete_once = True
        with self.assertRaises(azure.AzureUploadFailure):
            self._run(point)
        point.fail_complete_once = False
        self._run(point)
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
        self.assertEqual(blob.commit_calls, 1)

    def test_provider_etag_version_checksum_and_bytes_are_persisted(self):
        blob, _service, point = self._azure_point()
        self._run(point)
        state = point.metadata[azure.STATE_KEY]
        self.assertEqual(state["sha256"], self.checksum)
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["etag"], '"azure-etag-1"')
        self.assertEqual(state["version_id"], "azure-version-9")
        self.assertEqual(state["provider_checksum_algorithm"], "md5")
        self.assertEqual(point.backup.artifact_calls[-1]["version_id"], "azure-version-9")

    def test_block_state_is_deterministic_and_persisted(self):
        blob, _service, point = self._azure_point()
        self._run(point)
        state = point.metadata[azure.STATE_KEY]
        self.assertEqual(len(state["blocks"]), 1)
        self.assertEqual(state["blocks"][0]["id"], azure._block_id(self.identifier, 0))
        self.assertEqual(state["uploaded_bytes"], len(self.payload))
        self.assertEqual(len(blob.stage_calls), 1)

    def test_verification_fallback_uses_readinto_without_readall(self):
        blob, _service, point = self._azure_point()
        blob.download_blob = mock.Mock(return_value=_ReadIntoDownloader(self.payload))

        identity = azure._remote_stream_identity(blob, stored_backup=point)

        self.assertEqual(identity, {
            "sha256": self.checksum,
            "size_bytes": len(self.payload),
        })
        blob.download_blob.assert_called_once()

    def test_rate_limit_preserves_retry_after_without_provider_body(self):
        error = RuntimeError("SAS=secret-canary")
        error.status_code = 429
        error.response = SimpleNamespace(headers={"retry-after": "41"})
        failure = azure._provider_failure(error)
        self.assertEqual(failure.code, "STORAGE_RATE_LIMITED")
        self.assertEqual(failure.retry_after, 41)
        self.assertNotIn("secret-canary", str(failure))
