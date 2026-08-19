import base64
import hashlib
import os
import uuid
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError
from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from apps._tasks.integration.storage.s3_verified import (
    BACKUP_METADATA,
    MULTIPART_METADATA,
    S3ObjectIntegrityError,
    S3UploadInventoryFailure,
    S3UploadOutcomePending,
    S3UploadReconciliationRequired,
    _list_parts,
    _multipart_part_size,
    upload_verified_s3,
)


def _client_error(code, status):
    return ClientError(
        {
            "Error": {"Code": code, "Message": "provider details are redacted"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "CreateMultipartUpload",
    )


def _not_found():
    return ClientError({"Error": {"Code": "404"}}, "HeadObject")


def _multipart_upload_entry(
    key,
    upload_id,
    initiated,
    *,
    owner_id="canonical-owner-1",
    initiator_id="arn:aws:iam::123456789012:user/backupsheep",
):
    return {
        "UploadId": upload_id,
        "Key": key,
        "Initiated": initiated,
        "StorageClass": "STANDARD",
        "Owner": {"ID": owner_id, "DisplayName": "bucket-owner"},
        "Initiator": {"ID": initiator_id, "DisplayName": "backupsheep"},
    }


def _one_part_inventory_pages(size, *, etag='"part-etag"'):
    return [
        {"Parts": [], "IsTruncated": False},
        {
            "Parts": [
                {"PartNumber": 1, "ETag": etag, "Size": int(size)}
            ],
            "IsTruncated": False,
        },
    ]


class VerifiedS3ReconciliationTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        backup_id = f"backup-{uuid.uuid4().hex}"
        self.point = SimpleNamespace(
            backup=SimpleNamespace(
                uuid=backup_id,
                uuid_str=backup_id,
                attempt_no=1,
                type="on_demand",
                record_artifact_integrity=mock.Mock(),
            ),
            backup_id=42,
            storage=SimpleNamespace(),
            storage_file_id=None,
            metadata={},
            status=None,
            Status=SimpleNamespace(
                UPLOAD_VALIDATION="validating",
                UPLOAD_COMPLETE="complete",
            ),
            save=mock.Mock(),
        )
        os.makedirs("_storage", exist_ok=True)
        self.local_path = f"_storage/{backup_id}.zip"
        self.addCleanup(
            lambda: os.path.exists(self.local_path) and os.remove(self.local_path)
        )

    def _write(self, payload=b"verified s3 payload\n"):
        self.payload = payload
        self.sha256 = hashlib.sha256(payload).hexdigest()
        with open(self.local_path, "wb") as archive:
            archive.write(payload)

    def _head(self, *, version_id="version-1", backup_id="42"):
        return {
            "ContentLength": len(self.payload),
            "ETag": '"provider-etag"',
            "VersionId": version_id,
            "Metadata": {
                BACKUP_METADATA: backup_id,
                "backupsheep-sha256": self.sha256,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }

    def _upload(
        self,
        client,
        *,
        key="backups/object.zip",
        bucket="test-bucket",
    ):
        return upload_verified_s3(
            self.point,
            client=client,
            bucket=bucket,
            key=key,
            local_path=self.local_path,
        )

    def test_lost_put_response_adopts_only_marker_verified_object_once(self):
        self._write()
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._head()]
        client.put_object.side_effect = ConnectionError("response lost")

        state = self._upload(client)

        client.put_object.assert_called_once()
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(state["version_id"], "version-1")
        self.assertEqual(state["ownership_marker"], "42")
        metadata = client.put_object.call_args.kwargs["Metadata"]
        self.assertEqual(metadata[BACKUP_METADATA], "42")

    def test_lost_put_response_replays_head_only_until_object_is_visible(self):
        self._write()
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._head(),
        ]
        client.put_object.side_effect = ConnectionError("response lost")

        with self.assertRaises(S3UploadOutcomePending) as raised:
            self._upload(client)

        self.assertTrue(raised.exception.retryable)
        client.put_object.assert_called_once()
        pending_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(pending_state["phase"], "put_outcome_unknown")
        self.assertEqual(
            pending_state["put_intent"]["reconciliation_checks"], 1
        )

        state = self._upload(client)

        client.put_object.assert_called_once()
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(state["version_id"], "version-1")

    def test_worker_crash_at_put_boundary_replays_head_only(self):
        self._write()
        key = "backups/crashed-put.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "put_outcome_unknown",
                "put_intent": {
                    "complete": True,
                    "object_key": key,
                    "sha256": self.sha256,
                    "size_bytes": len(self.payload),
                    "ownership_marker": "42",
                    "operation_marker": "durable-put-operation",
                    "operation_started_at": timezone.now().isoformat(),
                    "reconciliation_checks": 0,
                },
            }
        }
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        client.put_object.assert_not_called()
        self.assertEqual(
            self.point.metadata["s3_object"]["put_intent"][
                "reconciliation_checks"
            ],
            1,
        )

    def test_definitive_put_rate_limit_allows_one_fresh_put_on_retry(self):
        self._write()
        key = "backups/rate-limited-put.zip"
        rate_limit = _client_error("SlowDown", 503)
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._head(),
        ]
        operation_markers = []

        def put_side_effect(**_kwargs):
            operation_markers.append(
                self.point.metadata["s3_object"]["put_intent"][
                    "operation_marker"
                ]
            )
            if len(operation_markers) == 1:
                raise rate_limit
            return {"ETag": '"put-etag"'}

        client.put_object.side_effect = put_side_effect

        with self.assertRaises(ClientError) as raised:
            self._upload(client, key=key)

        self.assertIs(raised.exception, rate_limit)
        client.put_object.assert_called_once()
        # A definitive rejection must not trigger a post-error adoption HEAD.
        client.head_object.assert_called_once()
        rejected_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(rejected_state["phase"], "put_rejected")
        self.assertNotIn("put_intent", rejected_state)
        self.assertEqual(
            rejected_state["put_rejection"]["kind"], "rate_limit"
        )

        state = self._upload(client, key=key)

        self.assertEqual(client.put_object.call_count, 2)
        self.assertNotEqual(operation_markers[0], operation_markers[1])
        self.assertEqual(state["phase"], "committed")

    def test_same_key_foreign_version_is_not_adopted_after_lost_response(self):
        self._write()
        foreign = self._head(version_id="foreign-version", backup_id="other-backup")
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), foreign]
        client.put_object.side_effect = ConnectionError("response lost")

        with self.assertRaises(S3ObjectIntegrityError):
            self._upload(client)

        client.put_object.assert_called_once()
        self.assertEqual(client.head_object.call_count, 2)

    def test_persisted_version_id_must_match_provider_head(self):
        self._write()
        key = "backups/exact-version.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "version_id": "owned-version",
                "ownership_marker": "42",
            }
        }
        client = mock.MagicMock()
        client.head_object.return_value = self._head(version_id="foreign-version")

        with self.assertRaises(S3ObjectIntegrityError):
            self._upload(client, key=key)

        client.put_object.assert_not_called()
        client.head_object.assert_called_once_with(
            Bucket="test-bucket", Key=key, VersionId="owned-version"
        )

    def test_bucket_binding_is_durable_and_drift_stops_before_provider_access(self):
        self._write()
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._head()]
        client.put_object.return_value = {"ETag": '"put-etag"'}

        state = self._upload(client)

        self.assertEqual(state["bucket"], "test-bucket")
        client.reset_mock()
        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, bucket="different-bucket")

        client.head_object.assert_not_called()
        client.put_object.assert_not_called()
        client.create_multipart_upload.assert_not_called()

    def test_committed_legacy_state_binds_bucket_after_exact_read_only_head(self):
        self._write()
        key = "backups/legacy-without-bucket.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "phase": "committed",
                "object_key": key,
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "etag": '"etag"',
                "version_id": "version-1",
            }
        }
        client = mock.MagicMock()
        client.head_object.return_value = self._head()

        state = self._upload(client, key=key)

        self.assertEqual(state["bucket"], "test-bucket")
        client.head_object.assert_called_once_with(
            Bucket="test-bucket",
            Key=key,
            VersionId="version-1",
        )
        client.put_object.assert_not_called()
        client.create_multipart_upload.assert_not_called()

    def test_legacy_bucket_adoption_missing_or_mismatched_object_never_mutates(self):
        self._write()
        key = "backups/legacy-unproven.zip"
        legacy_state = {
            "phase": "committed",
            "object_key": key,
            "sha256": self.sha256,
            "size_bytes": len(self.payload),
            "checksum_algorithm": "sha256",
            "ownership_marker": "42",
            "etag": '"etag"',
            "version_id": "version-1",
        }
        cases = (
            (_not_found(), S3UploadReconciliationRequired),
            (self._head(backup_id="different-backup"), S3ObjectIntegrityError),
        )
        for head_result, expected_exception in cases:
            with self.subTest(expected_exception=expected_exception.__name__):
                self.point.storage_file_id = key
                self.point.metadata = {"s3_object": deepcopy(legacy_state)}
                client = mock.MagicMock()
                if isinstance(head_result, Exception):
                    client.head_object.side_effect = head_result
                else:
                    client.head_object.return_value = head_result

                with self.assertRaises(expected_exception):
                    self._upload(client, key=key)

                self.assertNotIn("bucket", self.point.metadata["s3_object"])
                client.put_object.assert_not_called()
                client.create_multipart_upload.assert_not_called()

    def test_in_progress_legacy_state_without_bucket_cannot_probe_or_mutate(self):
        self._write()
        key = "backups/legacy-in-progress.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "phase": "uploading",
                "object_key": key,
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "version_id": "version-1",
            }
        }
        client = mock.MagicMock()

        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, key=key)

        client.head_object.assert_not_called()
        client.put_object.assert_not_called()
        client.create_multipart_upload.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_lost_create_adopts_one_new_upload_against_durable_baseline(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/multipart.zip"
        now = timezone.now()
        stale = _multipart_upload_entry(
            key,
            "stale-upload",
            now - timedelta(days=1),
        )
        accepted = _multipart_upload_entry(key, "accepted-upload", now)
        client = mock.MagicMock()
        persisted = []
        self.point.save.side_effect = lambda **_kwargs: persisted.append(
            deepcopy(self.point.metadata)
        )
        client.head_object.side_effect = [_not_found(), self._head()]
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [stale], "IsTruncated": False},
            {"Uploads": [stale, accepted], "IsTruncated": False},
        ]
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}
        client.create_multipart_upload.side_effect = ConnectionError("response lost")

        state = self._upload(client, key=key)

        self.assertEqual(state["phase"], "committed")
        self.assertNotIn("multipart", state)
        client.create_multipart_upload.assert_called_once()
        self.assertEqual(client.list_multipart_uploads.call_count, 2)
        client.upload_part.assert_called_once()
        self.assertEqual(
            client.upload_part.call_args.kwargs["UploadId"], "accepted-upload"
        )
        create_args = client.create_multipart_upload.call_args.kwargs
        self.assertEqual(create_args["Metadata"][BACKUP_METADATA], "42")
        self.assertIn(MULTIPART_METADATA, create_args["Metadata"])
        witness = state["multipart_reconciliation"]
        self.assertEqual(witness["upload_id"], "accepted-upload")
        self.assertEqual(witness["owner_id"], "canonical-owner-1")
        durable_baselines = [
            snapshot["s3_object"]["multipart"]["create_baseline"]
            for snapshot in persisted
            if snapshot["s3_object"].get("phase") == "multipart_baseline_ready"
        ]
        self.assertEqual(len(durable_baselines), 1)
        self.assertEqual(durable_baselines[0]["object_key"], key)
        self.assertEqual(
            durable_baselines[0]["preexisting_upload_ids"], ["stale-upload"]
        )
        self.assertTrue(durable_baselines[0]["operation_started_at"])

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_worker_replay_reconciles_durable_baseline_without_second_create(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/crashed-create.zip"
        now = timezone.now()
        stale = _multipart_upload_entry(key, "stale", now - timedelta(days=1))
        accepted = _multipart_upload_entry(key, "accepted", now)
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "creating_multipart",
                "multipart": {
                    "operation_marker": "durable-operation",
                    "create_baseline": {
                        "complete": True,
                        "object_key": key,
                        "operation_started_at": now.isoformat(),
                        "preexisting_upload_ids": ["stale"],
                        "owner_ids": ["canonical-owner-1"],
                        "initiator_ids": [
                            "arn:aws:iam::123456789012:user/backupsheep"
                        ],
                    },
                },
            }
        }
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._head()]
        client.list_multipart_uploads.return_value = {
            "Uploads": [stale, accepted],
            "IsTruncated": False,
        }
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_not_called()
        self.assertEqual(client.upload_part.call_args.kwargs["UploadId"], "accepted")
        self.assertEqual(state["multipart_reconciliation"]["upload_id"], "accepted")

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_definitive_rate_limit_allows_fresh_baseline_and_create_on_retry(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/rate-limited-create.zip"
        rate_limit = _client_error("SlowDown", 503)
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), _not_found(), self._head()]
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            {"Uploads": [], "IsTruncated": False},
        ]
        client.create_multipart_upload.side_effect = [
            rate_limit,
            {"UploadId": "retry-upload"},
        ]
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        with self.assertRaises(ClientError) as raised:
            self._upload(client, key=key)

        self.assertIs(raised.exception, rate_limit)
        client.create_multipart_upload.assert_called_once()
        # One list established the pre-create boundary; no post-rejection
        # adoption inventory was attempted.
        client.list_multipart_uploads.assert_called_once()
        rejected_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(rejected_state["phase"], "multipart_create_rejected")
        self.assertNotIn("create_baseline", rejected_state["multipart"])
        self.assertNotIn("operation_marker", rejected_state["multipart"])
        rejection = rejected_state["multipart_create_rejection"]
        self.assertEqual(rejection["result"], "definitive_rejection")
        self.assertEqual(rejection["kind"], "rate_limit")
        self.assertTrue(rejection["retryable"])
        self.assertEqual(rejection["create_baseline"]["object_key"], key)
        first_marker = rejection["operation_marker"]

        state = self._upload(client, key=key)

        self.assertEqual(client.create_multipart_upload.call_count, 2)
        self.assertEqual(client.list_multipart_uploads.call_count, 2)
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(
            client.upload_part.call_args.kwargs["UploadId"], "retry-upload"
        )
        second_marker = client.create_multipart_upload.call_args_list[1].kwargs[
            "Metadata"
        ][MULTIPART_METADATA]
        self.assertNotEqual(second_marker, first_marker)

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_malformed_success_without_upload_id_reconciles_as_unknown(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/malformed-success.zip"
        accepted = _multipart_upload_entry(key, "accepted-upload", timezone.now())
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._head()]
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            {"Uploads": [accepted], "IsTruncated": False},
        ]
        client.create_multipart_upload.return_value = {}
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        self.assertEqual(client.list_multipart_uploads.call_count, 2)
        self.assertEqual(
            client.upload_part.call_args.kwargs["UploadId"], "accepted-upload"
        )
        self.assertEqual(
            state["multipart_reconciliation"]["upload_id"], "accepted-upload"
        )
        self.assertNotIn("multipart_create_rejection", state)

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_malformed_success_with_initial_zero_match_reconciles_on_replay(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/malformed-eventual.zip"
        accepted = _multipart_upload_entry(key, "accepted-upload", timezone.now())
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._head(),
        ]
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            {"Uploads": [], "IsTruncated": False},
            {"Uploads": [accepted], "IsTruncated": False},
        ]
        client.create_multipart_upload.return_value = {}
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        pending_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(pending_state["phase"], "creating_multipart")
        self.assertNotIn("multipart_create_rejection", pending_state)
        client.create_multipart_upload.assert_called_once()

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(
            state["multipart_reconciliation"]["upload_id"], "accepted-upload"
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_lost_complete_response_replays_head_only_until_object_is_visible(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/lost-complete.zip"
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            _not_found(),
            self._head(),
        ]
        client.list_multipart_uploads.return_value = {
            "Uploads": [],
            "IsTruncated": False,
        }
        client.create_multipart_upload.return_value = {"UploadId": "upload-1"}
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}
        client.complete_multipart_upload.side_effect = ConnectionError(
            "response lost"
        )

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        pending_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(
            pending_state["phase"], "multipart_complete_outcome_unknown"
        )
        self.assertEqual(
            pending_state["multipart"]["complete_intent"]["upload_id"],
            "upload-1",
        )
        self.assertEqual(
            pending_state["multipart"]["complete_intent"][
                "reconciliation_checks"
            ],
            1,
        )
        self.assertEqual(
            pending_state["multipart"]["part_size_bytes"],
            5 * 1024 * 1024,
        )

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        client.complete_multipart_upload.assert_called_once()
        self.assertEqual(client.list_parts.call_count, 2)

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        client.complete_multipart_upload.assert_called_once()
        self.assertEqual(client.list_parts.call_count, 2)
        self.assertEqual(state["phase"], "committed")

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
        S3_MULTIPART_CHECKPOINT_PARTS=1,
        S3_MULTIPART_HASH_CHUNK_BYTES=64 * 1024,
    )
    def test_multipart_streams_file_slices_and_persists_only_bounded_progress(self):
        first = b"a" * (5 * 1024 * 1024)
        second = b"b" * (1024 * 1024)
        self._write(first + second)
        key = "backups/bounded-parts.zip"
        persisted = []
        self.point.save.side_effect = lambda **_kwargs: persisted.append(
            deepcopy(self.point.metadata)
        )
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._head()]
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
                        "Size": len(first),
                    },
                    {
                        "PartNumber": 2,
                        "ETag": '"part-2"',
                        "Size": len(second),
                    },
                ],
                "IsTruncated": False,
            },
        ]
        bodies = []
        self.point.ensure_upload_fence = mock.Mock()

        def upload_part(**kwargs):
            body = kwargs["Body"]
            self.assertNotIsInstance(body, (bytes, bytearray))
            digest = hashlib.sha256()
            total = 0
            maximum_read = 0
            while True:
                payload = body.read(64 * 1024)
                if not payload:
                    break
                digest.update(payload)
                total += len(payload)
                maximum_read = max(maximum_read, len(payload))
            body.seek(0)
            self.assertEqual(body.tell(), 0)
            bodies.append((len(body), total, maximum_read))
            self.assertEqual(
                kwargs["ChecksumSHA256"],
                base64.b64encode(digest.digest()).decode("ascii"),
            )
            return {"ETag": f'"part-{kwargs["PartNumber"]}"'}

        client.upload_part.side_effect = upload_part

        state = upload_verified_s3(
            self.point,
            client=client,
            bucket="test-bucket",
            key=key,
            local_path=self.local_path,
            supports_checksum=True,
        )

        self.assertEqual(state["phase"], "committed")
        self.assertEqual(self.point.ensure_upload_fence.call_count, 3)
        self.assertEqual(
            bodies,
            [
                (len(first), len(first), 64 * 1024),
                (len(second), len(second), 64 * 1024),
            ],
        )
        multipart_snapshots = [
            snapshot["s3_object"]["multipart"]
            for snapshot in persisted
            if snapshot["s3_object"].get("multipart")
        ]
        self.assertTrue(multipart_snapshots)
        self.assertTrue(
            all("parts" not in multipart for multipart in multipart_snapshots)
        )
        completion = next(
            multipart["complete_intent"]
            for multipart in multipart_snapshots
            if multipart.get("complete_intent")
        )
        self.assertEqual(completion["part_count"], 2)
        self.assertEqual(completion["uploaded_bytes"], len(self.payload))
        self.assertEqual(len(completion["part_inventory_sha256"]), 64)
        self.assertNotIn("parts", completion)
        self.assertEqual(
            client.complete_multipart_upload.call_args.kwargs["MultipartUpload"][
                "Parts"
            ],
            [
                {"PartNumber": 1, "ETag": '"part-1"'},
                {"PartNumber": 2, "ETag": '"part-2"'},
            ],
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_incomplete_final_part_inventory_stops_before_completion(self):
        self._write(b"a" * (5 * 1024 * 1024))
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.list_multipart_uploads.return_value = {
            "Uploads": [],
            "IsTruncated": False,
        }
        client.create_multipart_upload.return_value = {"UploadId": "upload-1"}
        client.list_parts.side_effect = [
            {"Parts": [], "IsTruncated": False},
            {"Parts": [], "IsTruncated": False},
        ]
        client.upload_part.return_value = {"ETag": '"part-1"'}

        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, key="backups/incomplete-inventory.zip")

        client.complete_multipart_upload.assert_not_called()
        multipart = self.point.metadata["s3_object"]["multipart"]
        self.assertNotIn("parts", multipart)
        self.assertEqual(multipart["progress"]["completed_parts"], 1)
        self.assertEqual(
            multipart["progress"]["uploaded_bytes"], len(self.payload)
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
        S3_MULTIPART_NO_PROGRESS_SECONDS=60,
        S3_MULTIPART_NO_PROGRESS_RETRY_AFTER_SECONDS=17,
    )
    def test_stalled_multipart_becomes_visible_retry_then_can_resume(self):
        first_size = 5 * 1024 * 1024
        second_size = 1024
        self._write((b"a" * first_size) + (b"b" * second_size))
        key = "backups/stalled-multipart.zip"
        old = (timezone.now() - timedelta(minutes=10)).isoformat()
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "uploading",
                "multipart": {
                    "upload_id": "upload-1",
                    "part_size_bytes": first_size,
                    "progress": {
                        "completed_parts": 1,
                        "total_parts": 2,
                        "uploaded_bytes": first_size,
                        "total_bytes": len(self.payload),
                        "last_progress_at": old,
                        "window_started_at": old,
                    },
                },
            }
        }
        part_one = {
            "Parts": [
                {"PartNumber": 1, "ETag": '"part-1"', "Size": first_size}
            ],
            "IsTruncated": False,
        }
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.list_parts.return_value = part_one

        with self.assertRaises(S3UploadOutcomePending) as raised:
            self._upload(client, key=key)

        self.assertEqual(raised.exception.retry_after, 17)
        stalled = self.point.metadata["s3_object"]
        self.assertEqual(stalled["phase"], "multipart_no_progress")
        self.assertEqual(
            stalled["multipart"]["progress"]["no_progress_count"], 1
        )
        client.upload_part.assert_not_called()
        client.complete_multipart_upload.assert_not_called()

        client.head_object.side_effect = [_not_found(), self._head()]
        client.list_parts.side_effect = [
            part_one,
            {
                "Parts": [
                    {
                        "PartNumber": 1,
                        "ETag": '"part-1"',
                        "Size": first_size,
                    },
                    {
                        "PartNumber": 2,
                        "ETag": '"part-2"',
                        "Size": second_size,
                    },
                ],
                "IsTruncated": False,
            },
        ]
        client.upload_part.return_value = {"ETag": '"part-2"'}

        state = self._upload(client, key=key)

        self.assertEqual(state["phase"], "committed")
        client.create_multipart_upload.assert_not_called()
        client.upload_part.assert_called_once()
        client.complete_multipart_upload.assert_called_once()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_worker_crash_at_complete_boundary_replays_head_only(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/crashed-complete.zip"
        now = timezone.now().isoformat()
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "multipart_complete_outcome_unknown",
                "multipart": {
                    "upload_id": "durable-upload",
                    "parts": [{"PartNumber": 1, "ETag": '"part-etag"'}],
                    "complete_intent": {
                        "complete": True,
                        "object_key": key,
                        "sha256": self.sha256,
                        "size_bytes": len(self.payload),
                        "ownership_marker": "42",
                        "operation_marker": "durable-complete-operation",
                        "operation_started_at": now,
                        "reconciliation_checks": 0,
                        "upload_id": "durable-upload",
                        "parts": [
                            {"PartNumber": 1, "ETag": '"part-etag"'}
                        ],
                    },
                },
            }
        }
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        client.create_multipart_upload.assert_not_called()
        client.list_parts.assert_not_called()
        client.upload_part.assert_not_called()
        client.complete_multipart_upload.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_missing_upload_after_crash_never_starts_second_multipart(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/missing-after-complete.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "uploading",
                "multipart": {
                    "upload_id": "possibly-completed-upload",
                    "parts": [{"PartNumber": 1, "ETag": '"part-etag"'}],
                },
            }
        }
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.list_parts.side_effect = _client_error("NoSuchUpload", 404)

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)

        client.create_multipart_upload.assert_not_called()
        client.upload_part.assert_not_called()
        client.complete_multipart_upload.assert_not_called()
        state = self.point.metadata["s3_object"]
        self.assertEqual(state["phase"], "multipart_complete_outcome_unknown")
        self.assertTrue(
            state["multipart"]["complete_intent"][
                "inferred_from_missing_upload"
            ]
        )

    @override_settings(S3_OUTCOME_RECONCILIATION_MAX_CHECKS=2)
    def test_put_outcome_exhaustion_fails_closed_without_second_put(self):
        self._write()
        key = "backups/put-exhausted.zip"
        self.point.storage_file_id = key
        self.point.metadata = {
            "s3_object": {
                "object_key": key,
                "bucket": "test-bucket",
                "sha256": self.sha256,
                "size_bytes": len(self.payload),
                "checksum_algorithm": "sha256",
                "ownership_marker": "42",
                "phase": "put_outcome_unknown",
                "put_intent": {
                    "complete": True,
                    "object_key": key,
                    "sha256": self.sha256,
                    "size_bytes": len(self.payload),
                    "ownership_marker": "42",
                    "operation_marker": "durable-put-operation",
                    "operation_started_at": timezone.now().isoformat(),
                    "reconciliation_checks": 0,
                },
            }
        }
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()

        with self.assertRaises(S3UploadOutcomePending):
            self._upload(client, key=key)
        with self.assertRaises(S3UploadReconciliationRequired) as raised:
            self._upload(client, key=key)

        self.assertNotIsInstance(raised.exception, S3UploadOutcomePending)
        client.put_object.assert_not_called()
        self.assertEqual(
            self.point.metadata["s3_object"]["phase"],
            "put_reconciliation_exhausted",
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_zero_new_upload_is_retryable_then_eventually_adopted_without_recreate(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/stale.zip"
        now = timezone.now()
        stale = _multipart_upload_entry(
            key,
            "stale-upload",
            now - timedelta(days=1),
        )
        accepted = _multipart_upload_entry(key, "eventually-visible", now)
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._head(),
        ]
        client.create_multipart_upload.side_effect = ConnectionError("response lost")
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [stale], "IsTruncated": False},
            {"Uploads": [stale], "IsTruncated": False},
            {"Uploads": [stale, accepted], "IsTruncated": False},
        ]
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        with self.assertRaises(S3UploadOutcomePending) as raised:
            self._upload(client, key=key)

        self.assertTrue(raised.exception.retryable)
        pending_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(pending_state["phase"], "creating_multipart")
        self.assertTrue(
            pending_state["multipart"]["create_baseline"]["complete"]
        )
        self.assertEqual(
            pending_state["multipart"]["create_baseline"][
                "reconciliation_checks"
            ],
            1,
        )
        self.assertNotIn("multipart_create_rejection", pending_state)
        client.create_multipart_upload.assert_called_once()

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(
            state["multipart_reconciliation"]["upload_id"],
            "eventually-visible",
        )
        client.upload_part.assert_called_once()
        client.complete_multipart_upload.assert_called_once()

    def _assert_inventory_retry_then_unique_adoption(
        self,
        inventory_failure,
        *,
        expected_retry_after=None,
    ):
        from apps._tasks.integration.storage.tasks import _storage_error_outcome

        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/inventory-eventual.zip"
        accepted = _multipart_upload_entry(key, "eventually-visible", timezone.now())
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._head(),
        ]
        client.create_multipart_upload.side_effect = ConnectionError("response lost")
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            inventory_failure,
            {"Uploads": [accepted], "IsTruncated": False},
        ]
        client.list_parts.side_effect = _one_part_inventory_pages(len(self.payload))
        client.upload_part.return_value = {"ETag": '"part-etag"'}

        with self.assertRaises(S3UploadOutcomePending) as raised:
            self._upload(client, key=key)

        if expected_retry_after is not None:
            self.assertEqual(raised.exception.retry_after, expected_retry_after)
        status_point = SimpleNamespace(
            Status=SimpleNamespace(
                UPLOAD_RETRY="upload_retry",
                STORAGE_VALIDATION_FAILED="storage_validation_failed",
            )
        )
        code, _message, status, retryable = _storage_error_outcome(
            raised.exception,
            status_point,
        )
        self.assertEqual(code, "STORAGE_RECONCILIATION_PENDING")
        self.assertEqual(status, status_point.Status.UPLOAD_RETRY)
        self.assertTrue(retryable)
        pending_state = deepcopy(self.point.metadata["s3_object"])
        self.assertEqual(pending_state["phase"], "creating_multipart")
        self.assertTrue(
            pending_state["multipart"]["create_baseline"]["complete"]
        )
        self.assertNotIn("multipart_create_rejection", pending_state)

        state = self._upload(client, key=key)

        client.create_multipart_upload.assert_called_once()
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(
            state["multipart_reconciliation"]["upload_id"],
            "eventually-visible",
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_rate_limit_during_post_create_inventory_retries_then_adopts(self):
        rate_limit = ClientError(
            {
                "Error": {"Code": "SlowDown", "Message": "redacted"},
                "ResponseMetadata": {
                    "HTTPStatusCode": 429,
                    "HTTPHeaders": {"retry-after": "19"},
                },
            },
            "ListMultipartUploads",
        )

        self._assert_inventory_retry_then_unique_adoption(
            rate_limit,
            expected_retry_after=19,
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_timeout_during_post_create_inventory_retries_then_adopts(self):
        self._assert_inventory_retry_then_unique_adoption(
            TimeoutError("inventory response lost")
        )

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_definitive_inventory_failures_remain_typed_and_preserve_baseline(self):
        from apps._tasks.integration.storage.tasks import _storage_error_outcome

        cases = (
            (
                _client_error("AccessDenied", 403),
                "STORAGE_AUTH_FAILED",
                "STORAGE_AUTH_FAILED",
            ),
            (
                _client_error("NoSuchBucket", 404),
                "STORAGE_DESTINATION_NOT_FOUND",
                "STORAGE_DESTINATION_NOT_FOUND",
            ),
            (
                object(),
                "PROVIDER_MALFORMED_RESPONSE",
                "STORAGE_RECONCILIATION_REQUIRED",
            ),
        )
        for inventory_result, exception_code, task_code in cases:
            with self.subTest(exception_code=exception_code):
                self._write(b"a" * (5 * 1024 * 1024))
                self.point.metadata = {}
                self.point.storage_file_id = None
                client = mock.MagicMock()
                client.head_object.side_effect = _not_found()
                client.create_multipart_upload.side_effect = ConnectionError(
                    "response lost"
                )
                client.list_multipart_uploads.side_effect = [
                    {"Uploads": [], "IsTruncated": False},
                    inventory_result,
                ]

                with self.assertRaises(S3UploadInventoryFailure) as raised:
                    self._upload(client, key=f"backups/{exception_code}.zip")

                self.assertEqual(raised.exception.error_code, exception_code)
                state = self.point.metadata["s3_object"]
                self.assertEqual(state["phase"], "creating_multipart")
                self.assertTrue(
                    state["multipart"]["create_baseline"]["complete"]
                )
                self.assertNotIn("multipart_create_rejection", state)
                client.create_multipart_upload.assert_called_once()
                status_point = SimpleNamespace(
                    Status=SimpleNamespace(
                        UPLOAD_FAILED="upload_failed",
                        UPLOAD_RETRY="upload_retry",
                        STORAGE_VALIDATION_FAILED="storage_validation_failed",
                    )
                )
                code, _message, _status, retryable = _storage_error_outcome(
                    raised.exception,
                    status_point,
                )
                self.assertEqual(code, task_code)
                self.assertFalse(retryable)

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_duplicate_same_key_multipart_uploads_stop_adoption(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/duplicate.zip"
        now = timezone.now()
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.create_multipart_upload.side_effect = TimeoutError("response lost")
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            {
                "Uploads": [
                    _multipart_upload_entry(key, "one", now),
                    _multipart_upload_entry(key, "two", now),
                ],
                "IsTruncated": False,
            },
        ]

        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, key=key)

        client.upload_part.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
        S3_RECONCILIATION_CLOCK_SKEW_SECONDS=30,
    )
    def test_new_id_with_old_initiated_time_is_not_adopted(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/old-candidate.zip"
        old_candidate = _multipart_upload_entry(
            key,
            "new-id-but-old-time",
            timezone.now() - timedelta(hours=1),
        )
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.create_multipart_upload.side_effect = ConnectionError("response lost")
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [], "IsTruncated": False},
            {"Uploads": [old_candidate], "IsTruncated": False},
        ]

        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, key=key)

        client.upload_part.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_new_upload_with_owner_mismatch_is_not_adopted(self):
        self._write(b"a" * (5 * 1024 * 1024))
        key = "backups/foreign-owner.zip"
        now = timezone.now()
        stale = _multipart_upload_entry(key, "stale", now - timedelta(days=1))
        foreign = _multipart_upload_entry(
            key,
            "foreign",
            now,
            owner_id="different-canonical-owner",
        )
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found()
        client.create_multipart_upload.side_effect = ConnectionError("response lost")
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [stale], "IsTruncated": False},
            {"Uploads": [stale, foreign], "IsTruncated": False},
        ]

        with self.assertRaises(S3UploadReconciliationRequired):
            self._upload(client, key=key)

        client.upload_part.assert_not_called()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_definitive_create_rejections_never_trigger_adoption_inventory(self):
        cases = (
            ("AccessDenied", 403),
            ("NoSuchBucket", 404),
            ("SlowDown", 503),
            ("OperationAborted", 409),
            ("InvalidRequest", 400),
        )
        for code, status in cases:
            with self.subTest(code=code):
                self._write(b"definitive rejection")
                self.point.metadata = {}
                self.point.storage_file_id = None
                self.point.save.reset_mock()
                client = mock.MagicMock()
                client.head_object.side_effect = _not_found()
                client.list_multipart_uploads.return_value = {
                    "Uploads": [],
                    "IsTruncated": False,
                }
                failure = _client_error(code, status)
                client.create_multipart_upload.side_effect = failure

                with self.assertRaises(ClientError) as raised:
                    self._upload(client, key=f"backups/{code}.zip")

                self.assertIs(raised.exception, failure)
                # The durable pre-create baseline is mandatory. A definitive
                # response must not trigger a second, adoption inventory.
                client.list_multipart_uploads.assert_called_once()

    @override_settings(
        S3_RECONCILIATION_MAX_PAGES=2,
        S3_RECONCILIATION_PAGE_SIZE=1,
    )
    def test_multipart_inventory_has_bounded_cursor_pagination(self):
        from apps._tasks.integration.storage.s3_verified import _list_exact_uploads

        client = mock.MagicMock()
        client.list_multipart_uploads.side_effect = [
            {
                "Uploads": [],
                "IsTruncated": True,
                "NextKeyMarker": "key-1",
                "NextUploadIdMarker": "upload-1",
            },
            {
                "Uploads": [],
                "IsTruncated": True,
                "NextKeyMarker": "key-2",
                "NextUploadIdMarker": "upload-2",
            },
        ]

        with self.assertRaises(S3UploadReconciliationRequired):
            _list_exact_uploads(client, "test-bucket", "backups/object.zip")

        self.assertEqual(client.list_multipart_uploads.call_count, 2)
        self.assertEqual(
            client.list_multipart_uploads.call_args_list[0].kwargs["MaxUploads"],
            1,
        )

    @override_settings(
        S3_MULTIPART_PART_SIZE_BYTES=8 * 1024 * 1024,
        S3_MULTIPART_TARGET_PARTS=8000,
        S3_RECONCILIATION_MAX_PARTS=10000,
    )
    def test_large_object_geometry_keeps_headroom_below_provider_part_limit(self):
        object_size = 107_421_554_763

        part_size = _multipart_part_size(object_size)

        self.assertGreaterEqual(part_size, 8 * 1024 * 1024)
        self.assertEqual(part_size % (1024 * 1024), 0)
        self.assertLessEqual(
            (object_size + part_size - 1) // part_size,
            8000,
        )

    @override_settings(
        S3_RECONCILIATION_MAX_PAGES=3,
        S3_RECONCILIATION_PAGE_SIZE=1000,
        S3_RECONCILIATION_MAX_PARTS=2000,
    )
    def test_part_inventory_resumes_past_the_1000_part_page(self):
        first_page = [
            {"PartNumber": number, "ETag": f'"etag-{number}"', "Size": 8}
            for number in range(1, 1001)
        ]
        client = mock.MagicMock()
        client.list_parts.side_effect = [
            {
                "Parts": first_page,
                "IsTruncated": True,
                "NextPartNumberMarker": 1000,
            },
            {
                "Parts": [
                    {"PartNumber": 1001, "ETag": '"etag-1001"', "Size": 8}
                ],
                "IsTruncated": False,
            },
        ]

        parts = _list_parts(
            client, "test-bucket", "backups/object.zip", "upload-1"
        )

        self.assertEqual(len(parts), 1001)
        self.assertEqual(parts[-1]["PartNumber"], 1001)
        self.assertEqual(
            client.list_parts.call_args_list[1].kwargs["PartNumberMarker"],
            1000,
        )

    def test_part_inventory_rejects_malformed_and_repeated_pages(self):
        malformed_pages = (
            {"Parts": {}, "IsTruncated": False},
            {"Parts": [{"ETag": '"missing-number"'}], "IsTruncated": False},
            {
                "Parts": [{"PartNumber": 1, "ETag": '"etag-1"'}],
                "IsTruncated": True,
            },
            {
                "Parts": [{"PartNumber": 1, "ETag": '"etag-1"'}],
                "IsTruncated": True,
                "NextPartNumberMarker": "not-a-number",
            },
        )
        for page in malformed_pages:
            with self.subTest(page=page):
                client = mock.MagicMock()
                client.list_parts.return_value = page
                with self.assertRaises(S3UploadReconciliationRequired):
                    _list_parts(
                        client,
                        "test-bucket",
                        "backups/object.zip",
                        "upload-1",
                    )

        client = mock.MagicMock()
        client.list_parts.side_effect = [
            {
                "Parts": [{"PartNumber": 1, "ETag": '"etag-1"'}],
                "IsTruncated": True,
                "NextPartNumberMarker": 1,
            },
            {
                "Parts": [{"PartNumber": 1, "ETag": '"etag-1-again"'}],
                "IsTruncated": False,
            },
        ]
        with self.assertRaises(S3UploadReconciliationRequired):
            _list_parts(
                client, "test-bucket", "backups/object.zip", "upload-1"
            )

    @override_settings(S3_RECONCILIATION_MAX_PARTS=1)
    def test_part_inventory_enforces_configured_item_bound(self):
        client = mock.MagicMock()
        client.list_parts.return_value = {
            "Parts": [
                {"PartNumber": 1, "ETag": '"etag-1"'},
                {"PartNumber": 2, "ETag": '"etag-2"'},
            ],
            "IsTruncated": False,
        }

        with self.assertRaises(S3UploadReconciliationRequired):
            _list_parts(
                client, "test-bucket", "backups/object.zip", "upload-1"
            )

    @override_settings(S3_RECONCILIATION_MAX_PAGES=1)
    def test_part_inventory_enforces_configured_page_bound(self):
        client = mock.MagicMock()
        client.list_parts.return_value = {
            "Parts": [{"PartNumber": 1, "ETag": '"etag-1"'}],
            "IsTruncated": True,
            "NextPartNumberMarker": 1,
        }

        with self.assertRaises(S3UploadReconciliationRequired):
            _list_parts(
                client, "test-bucket", "backups/object.zip", "upload-1"
            )
        client.list_parts.assert_called_once()
