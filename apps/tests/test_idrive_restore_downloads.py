"""Focused exact authenticated restore tests for IDrive/S3-compatible storage."""

import hashlib
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError, ReadTimeoutError
from django.test import SimpleTestCase

from apps._tasks.integration import restore_common


PAYLOAD = b"BackupSheep IDrive exact restore payload\n"
SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
BUCKET = "bs-e2e-hetzner-object-storage"
OBJECT_KEY = "backups/restore-node/restore-exact-123.zip"
ETAG = '"idrive-etag-1"'
VERSION_ID = "idrive-version-1"


class _ArtifactQuery:
    def __init__(self, records):
        self.records = list(records)

    def filter(self, **filters):
        records = self.records
        for name, expected in filters.items():
            if name.endswith("__in"):
                field = name[:-4]
                records = [
                    record for record in records if getattr(record, field, None) in expected
                ]
            elif name.endswith("__isnull"):
                field = name[:-8]
                records = [
                    record
                    for record in records
                    if (getattr(record, field, None) is None) is expected
                ]
            else:
                records = [
                    record for record in records if getattr(record, name, None) == expected
                ]
        return _ArtifactQuery(records)

    def exclude(self, **filters):
        records = self.records
        for name, expected in filters.items():
            if name.endswith("__in"):
                field = name[:-4]
                records = [
                    record for record in records if getattr(record, field, None) not in expected
                ]
            else:
                records = [
                    record for record in records if getattr(record, name, None) != expected
                ]
        return _ArtifactQuery(records)

    def values_list(self, field, flat=False):
        values = [getattr(record, field, None) for record in self.records]
        return values if flat else [(value,) for value in values]

    def exists(self):
        return bool(self.records)

    def __iter__(self):
        return iter(self.records)


class _Body:
    def __init__(self, chunks, error=None):
        self.chunks = list(chunks)
        self.error = error
        self.closed = False

    def read(self, _size):
        if self.error is not None and len(self.chunks) == 1:
            chunk = self.chunks.pop(0)
            if chunk:
                return chunk
            raise self.error
        if self.chunks:
            return self.chunks.pop(0)
        return b""

    def close(self):
        self.closed = True


class _FakeClient:
    def __init__(self, heads, response):
        self.heads = list(heads)
        self.response = response
        self.head_calls = []
        self.get_calls = []

    def head_object(self, **kwargs):
        self.head_calls.append(dict(kwargs))
        result = self.heads.pop(0)
        if isinstance(result, BaseException):
            raise result
        return dict(result)

    def get_object(self, **kwargs):
        self.get_calls.append(dict(kwargs))
        if isinstance(self.response, BaseException):
            raise self.response
        return dict(self.response)


class IDriveRestoreFixtures:
    def _point(self, *, state=None, artifacts=None, key=OBJECT_KEY):
        artifacts = list(artifacts or [])
        backup = SimpleNamespace(
            id=77,
            uuid_str="restore-exact-123",
            uuid="restore-exact-123",
            node=SimpleNamespace(name_slug="restore-node"),
            artifact_records=_ArtifactQuery(artifacts),
        )
        encryption_key = object()
        account = SimpleNamespace(get_encryption_key=mock.Mock(return_value=encryption_key))
        idrive = SimpleNamespace(
            endpoint_url="https://fsn1.your-objectstorage.com",
            bucket_name=BUCKET,
            access_key=b"encrypted-access",
            secret_key=b"encrypted-secret",
        )
        storage = SimpleNamespace(
            type=SimpleNamespace(code="idrive"),
            account=account,
            storage_idrive=idrive,
        )
        metadata = {}
        if state is not None:
            metadata["idrive_s3_object"] = dict(state)
        point = SimpleNamespace(
            backup=backup,
            backup_id=backup.id,
            storage=storage,
            storage_id=19,
            storage_file_id=key,
            metadata=metadata,
            generate_download_url=mock.Mock(return_value="https://legacy.invalid/view"),
            verify_s3_head_ownership=mock.Mock(),
        )

        def committed_version_id():
            return str((state or {}).get("version_id") or "")

        point.committed_version_id = committed_version_id
        return point, encryption_key

    @staticmethod
    def _state(**overrides):
        state = {
            "phase": "committed",
            "object_key": OBJECT_KEY,
            "sha256": SHA256,
            "size_bytes": len(PAYLOAD),
            "checksum_algorithm": "sha256",
            "etag": ETAG,
            "version_id": VERSION_ID,
        }
        state.update(overrides)
        return state

    @staticmethod
    def _artifact(**overrides):
        values = {
            "storage_id": 19,
            "role": "destination",
            "object_key": OBJECT_KEY,
            "byte_count": len(PAYLOAD),
            "checksum_algorithm": "sha256",
            "checksum_value": SHA256,
            "etag": ETAG,
            "version_id": VERSION_ID,
            "verified_at": True,
            "storage": True,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def _head(**overrides):
        head = {
            "Bucket": BUCKET,
            "Key": OBJECT_KEY,
            "ContentLength": len(PAYLOAD),
            "ETag": ETAG,
            "VersionId": VERSION_ID,
            "Metadata": {
                "backupsheep-backup-id": "77",
                "backupsheep-bytes": str(len(PAYLOAD)),
                "backupsheep-sha256": SHA256,
            },
        }
        head.update(overrides)
        return head


class IDriveRestoreDownloadTests(IDriveRestoreFixtures, SimpleTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _destination(self, name="restore.zip"):
        return os.path.join(self.temp_dir.name, name)

    def _download(self, point, client, destination=None):
        destination = destination or self._destination()
        with mock.patch(
            "apps._tasks.integration.storage.idrive._s3_client", return_value=client
        ) as build_client:
            restore_common.fetch_backup_zip(point, destination)
        return build_client

    def test_committed_idrive_object_uses_exact_authenticated_version_and_atomic_stream(self):
        point, encryption_key = self._point(
            state=self._state(),
            artifacts=[self._artifact()],
        )
        head = self._head()
        body = _Body([PAYLOAD[:7], PAYLOAD[7:]])
        client = _FakeClient([head, head], {**head, "Body": body})

        build_client = self._download(point, client)

        with open(self._destination(), "rb") as restored:
            self.assertEqual(restored.read(), PAYLOAD)
        expected_request = {
            "Bucket": BUCKET,
            "Key": OBJECT_KEY,
            "VersionId": VERSION_ID,
        }
        self.assertEqual(client.head_calls, [expected_request, expected_request])
        self.assertEqual(client.get_calls, [expected_request])
        self.assertEqual(point.verify_s3_head_ownership.call_count, 3)
        point.generate_download_url.assert_not_called()
        build_client.assert_called_once_with(
            point.storage.storage_idrive,
            encryption_key,
        )
        self.assertTrue(body.closed)

    def test_post_download_mutation_does_not_publish_or_overwrite_existing_restore(self):
        point, _encryption_key = self._point(
            state=self._state(),
            artifacts=[self._artifact()],
        )
        destination = self._destination()
        with open(destination, "wb") as restored:
            restored.write(b"previous-safe-restore")
        body = _Body([PAYLOAD])
        initial = self._head()
        changed = self._head(ETag='"changed-after-stream"')
        client = _FakeClient([initial, changed], {**initial, "Body": body})

        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            self._download(point, client, destination)

        self.assertEqual(raised.exception.code, "PROVIDER_VERSION_DRIFT")
        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), b"previous-safe-restore")
        self.assertTrue(body.closed)
        self.assertFalse(
            any(name.endswith(".provider.partial") for name in os.listdir(self.temp_dir.name))
        )

    def test_committed_version_is_optional_but_is_never_invented(self):
        state = self._state(version_id=None)
        point, _encryption_key = self._point(
            state=state,
            artifacts=[self._artifact(version_id="")],
        )
        head = self._head(VersionId=None)
        body = _Body([PAYLOAD])
        client = _FakeClient([head, head], {**head, "Body": body})

        self._download(point, client)

        expected_request = {"Bucket": BUCKET, "Key": OBJECT_KEY}
        self.assertEqual(client.head_calls, [expected_request, expected_request])
        self.assertEqual(client.get_calls, [expected_request])

    def test_committed_object_key_mismatch_is_safe_and_never_uses_legacy_url(self):
        point, _encryption_key = self._point(
            state=self._state(object_key="backups/another-object.zip"),
            artifacts=[],
        )

        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            restore_common.fetch_backup_zip(point, self._destination())

        self.assertEqual(raised.exception.code, "PROVIDER_STATE_CONFLICT")
        point.generate_download_url.assert_not_called()

    def test_ownership_mismatch_from_head_is_safe(self):
        point, _encryption_key = self._point(
            state=self._state(),
            artifacts=[self._artifact()],
        )
        point.verify_s3_head_ownership.side_effect = RuntimeError(
            "ownership marker does not match"
        )
        head = self._head()
        client = _FakeClient([head], {**head, "Body": _Body([PAYLOAD])})

        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            self._download(point, client)

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertEqual(client.head_calls, [{"Bucket": BUCKET, "Key": OBJECT_KEY, "VersionId": VERSION_ID}])
        self.assertEqual(client.get_calls, [])

    def test_lost_response_is_timeout_safe_and_does_not_leave_partial_restore(self):
        point, _encryption_key = self._point(
            state=self._state(),
            artifacts=[self._artifact()],
        )
        destination = self._destination()
        with open(destination, "wb") as restored:
            restored.write(b"previous-safe-restore")
        body = _Body(
            [PAYLOAD[:5], b""],
            error=ReadTimeoutError(endpoint_url="https://provider.invalid"),
        )
        head = self._head()
        client = _FakeClient([head], {**head, "Body": body})

        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            self._download(point, client, destination)

        self.assertEqual(raised.exception.code, "PROVIDER_TIMEOUT")
        self.assertTrue(raised.exception.retryable)
        with open(destination, "rb") as restored:
            self.assertEqual(restored.read(), b"previous-safe-restore")
        self.assertTrue(body.closed)
        self.assertNotIn("provider.invalid", str(raised.exception))

    def test_provider_failures_are_classified_without_response_body_or_secret(self):
        cases = (
            (404, "NoSuchKey", "PROVIDER_NOT_FOUND", False),
            (403, "AccessDenied", "PROVIDER_AUTH_FAILED", False),
            (429, "SlowDown", "PROVIDER_RATE_LIMITED", True),
        )
        for status, code, expected_code, retryable in cases:
            with self.subTest(code=code):
                point, _encryption_key = self._point(
                    state=self._state(),
                    artifacts=[self._artifact()],
                )
                error = ClientError(
                    {
                        "Error": {"Code": code, "Message": "secret-provider-body"},
                        "ResponseMetadata": {"HTTPStatusCode": status},
                    },
                    "HeadObject",
                )
                client = _FakeClient([error], None)
                with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
                    self._download(point, client)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(raised.exception.retryable, retryable)
                self.assertNotIn("secret-provider-body", str(raised.exception))

    def test_committed_destination_without_idrive_state_never_uses_legacy_url(self):
        point, _encryption_key = self._point(
            state=None,
            artifacts=[self._artifact()],
        )
        with self.assertRaises(restore_common._SafeProviderRestoreError) as raised:
            restore_common.fetch_backup_zip(point, self._destination())
        self.assertEqual(raised.exception.code, "MISSING_PROVIDER_STATE")
        point.generate_download_url.assert_not_called()

    def test_pre_ledger_idrive_copy_keeps_explicit_legacy_path(self):
        point, _encryption_key = self._point(state=None, artifacts=[])
        point.storage_file_id = "legacy/restore.zip"
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock(return_value=False)
        response.iter_content.return_value = iter([PAYLOAD])
        response.status_code = 200
        response.headers = {}
        with mock.patch.object(restore_common.requests, "get", return_value=response):
            restore_common.fetch_backup_zip(point, self._destination())
        point.generate_download_url.assert_called_once_with()
