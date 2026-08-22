"""Failure-injection tests for renewable, fenced storage-point ownership."""

import uuid
from datetime import timedelta
from unittest import mock

from botocore.exceptions import ClientError
from django.test import override_settings
from django.utils import timezone

from apps._tasks.helper.tasks import _local_upload_is_active
from apps._tasks.integration.storage.lease import (
    DurableStorageUploadLease,
    StorageCleanupNotEligible,
    StorageUploadLeaseBusy,
)
from apps._tasks.integration.storage.tasks import (
    _mark_storage_upload_started,
    storage_cleanup_owned_multipart,
    storage_sweep_owned_multipart_cleanup,
)
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    StoragePointLeaseLostError,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


@override_settings(
    BACKUP_STORAGE_LEASE_SECONDS=90,
    BACKUP_STORAGE_HEARTBEAT_SECONDS=30,
)
class StorageExecutionLeaseTests(BaseTestCase):
    def _point(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"lease-{uuid.uuid4().hex}",
            status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        return backup, point

    @staticmethod
    def _stop_without_release(lease):
        lease._stop.set()
        if lease._thread:
            lease._thread.join(timeout=2)

    def _owned_cleanup_point(self):
        _backup, point = self._point()
        key = f"cleanup-tests/{point.backup.uuid}.zip"
        operation_started_at = (
            timezone.now() - timedelta(hours=1)
        ).isoformat()
        point.status = point.Status.UPLOAD_FAILED
        point.storage_file_id = key
        point.last_error_code = "STORAGE_RETRIES_EXHAUSTED"
        point.last_error_message = "Automatic retries were exhausted."
        point.metadata = {
            "aws_s3_object": {
                "phase": "uploading",
                "account_id": str(point.storage.account_id),
                "storage_id": str(point.storage_id),
                "bucket": "cleanup-test-bucket",
                "expected_bucket_owner": "",
                "object_key": key,
                "ownership_marker": str(point.backup_id),
                "sha256": "a" * 64,
                "size_bytes": 10,
                "multipart": {
                    "upload_id": "owned-upload",
                    "operation_marker": "owned-operation",
                    "create_baseline": {
                        "complete": True,
                        "object_key": key,
                        "operation_started_at": operation_started_at,
                        "preexisting_upload_ids": [],
                        "owner_ids": ["owner-1"],
                        "initiator_ids": ["initiator-1"],
                    },
                    "creation_proof": {
                        "version": 1,
                        "result": "provider_response",
                        "upload_id": "owned-upload",
                        "operation_marker": "owned-operation",
                        "recorded_at": timezone.now().isoformat(),
                    },
                },
            }
        }
        point.save()
        return point, key, operation_started_at

    def test_live_lease_blocks_duplicate_delivery(self):
        _backup, point = self._point()
        first = DurableStorageUploadLease(point, task_id="delivery-a")
        first.claim()
        self.addCleanup(first.release)

        duplicate = DurableStorageUploadLease(point, task_id="delivery-b")
        with self.assertRaises(StorageUploadLeaseBusy):
            duplicate.claim()

        point.refresh_from_db()
        self.assertEqual(point.upload_attempt_count, 1)
        self.assertEqual(point.upload_lease_owner, first.owner)

    def test_source_ready_parent_moves_only_after_storage_claim_boundary(self):
        backup, point = self._point()
        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save(update_fields=["status", "modified"])

        lease = DurableStorageUploadLease(point, task_id="storage-claim")
        lease.claim()
        self.addCleanup(lease.release)
        self.assertTrue(_mark_storage_upload_started(backup))

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.UPLOAD_IN_PROGRESS)
        self.assertFalse(_mark_storage_upload_started(backup))

    def test_expired_takeover_fences_worker_that_resumes_after_crash(self):
        _backup, point = self._point()
        crashed = DurableStorageUploadLease(point, task_id="crashed-worker")
        stale_instance = crashed.claim()
        self._stop_without_release(crashed)
        point.__class__.objects.filter(pk=point.pk).update(
            upload_lease_expires_at=timezone.now() - timedelta(seconds=1)
        )

        replacement = DurableStorageUploadLease(point, task_id="replacement")
        replacement_point = replacement.claim()
        self.addCleanup(replacement.release)

        with self.assertRaises(StoragePointLeaseLostError):
            stale_instance.ensure_upload_fence()
        replacement_point.ensure_upload_fence()

        stale_instance.status = stale_instance.Status.UPLOAD_COMPLETE
        with self.assertRaises(StoragePointLeaseLostError):
            stale_instance.save(update_fields=["status", "modified"])

        replacement_point.status = replacement_point.Status.UPLOAD_VALIDATION
        replacement_point.save(update_fields=["status", "modified"])
        replacement.release()
        crashed.release()  # must not clear the replacement or its final state

        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.UPLOAD_VALIDATION)
        self.assertEqual(point.upload_lease_owner, "")
        self.assertIsNone(point.upload_lease_token)
        takeovers = point.metadata["_upload_execution"]["stale_lease_takeovers"]
        self.assertEqual(takeovers[-1]["previous_owner"], crashed.owner)

    def test_heartbeat_renews_only_the_current_fence(self):
        _backup, point = self._point()
        lease = DurableStorageUploadLease(point, task_id="heartbeat-worker")
        lease.claim()
        self._stop_without_release(lease)
        point.refresh_from_db()
        previous_expiry = point.upload_lease_expires_at

        self.assertTrue(lease._heartbeat_once())
        point.refresh_from_db()
        self.assertGreater(point.upload_lease_expires_at, previous_expiry)

        point.__class__.objects.filter(pk=point.pk).update(
            upload_lease_token=uuid.uuid4()
        )
        self.assertFalse(lease._heartbeat_once())

    def test_claim_binds_a_same_thread_heartbeat_checkpoint(self):
        _backup, point = self._point()
        lease = DurableStorageUploadLease(point, task_id="checkpoint-worker")
        claimed = lease.claim()
        self.addCleanup(lease.release)
        self._stop_without_release(lease)
        point.refresh_from_db()
        previous_expiry = point.upload_lease_expires_at

        lease._last_heartbeat_monotonic = 0
        claimed._renew_upload_lease()

        point.refresh_from_db()
        self.assertGreater(point.upload_lease_expires_at, previous_expiry)

    def test_fenced_save_cannot_regress_a_renewed_lease_deadline(self):
        _backup, point = self._point()
        lease = DurableStorageUploadLease(point, task_id="renewed-save-worker")
        claimed = lease.claim()
        self.addCleanup(lease.release)
        self._stop_without_release(lease)
        original_expiry = claimed.upload_lease_expires_at
        original_heartbeat = claimed.upload_heartbeat_at

        self.assertTrue(lease._heartbeat_once())
        point.refresh_from_db()
        renewed_expiry = point.upload_lease_expires_at
        renewed_heartbeat = point.upload_heartbeat_at
        self.assertGreater(renewed_expiry, original_expiry)

        # Simulate an adapter that still holds the model state from claim time and
        # performs an ordinary full save after the background heartbeat.
        claimed.upload_lease_expires_at = original_expiry
        claimed.upload_heartbeat_at = original_heartbeat
        claimed.metadata = {"phase": "validating"}
        claimed.save()

        point.refresh_from_db()
        self.assertEqual(point.upload_lease_expires_at, renewed_expiry)
        self.assertEqual(point.upload_heartbeat_at, renewed_heartbeat)
        self.assertEqual(point.metadata, {"phase": "validating"})

    def test_recovery_uses_lease_expiry_not_modified_timestamp(self):
        backup, point = self._point()
        lease = DurableStorageUploadLease(point, task_id="active-upload")
        lease.claim()
        self.addCleanup(lease.release)
        point.__class__.objects.filter(pk=point.pk).update(
            modified=timezone.now() - timedelta(days=10)
        )

        self.assertTrue(_local_upload_is_active(backup))

        self._stop_without_release(lease)
        point.__class__.objects.filter(pk=point.pk).update(
            upload_lease_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertFalse(_local_upload_is_active(backup))

    def test_cleanup_lease_preserves_terminal_customer_state(self):
        _backup, point = self._point()
        point.status = point.Status.UPLOAD_FAILED
        point.upload_attempt_count = 7
        point.celery_task_id = "upload-delivery"
        point.last_error_code = "STORAGE_AUTH_FAILED"
        point.last_error_message = "Safe customer-facing message."
        point.save()

        lease = DurableStorageUploadLease(
            point,
            task_id="cleanup-delivery",
            purpose="multipart_cleanup",
        )
        claimed = lease.claim()
        self.addCleanup(lease.release)

        self.assertEqual(claimed.status, point.Status.UPLOAD_FAILED)
        self.assertEqual(claimed.upload_attempt_count, 7)
        self.assertEqual(claimed.celery_task_id, "upload-delivery")
        self.assertEqual(claimed.last_error_code, "STORAGE_AUTH_FAILED")
        self.assertEqual(
            claimed.metadata["_multipart_cleanup_execution"]["phase"],
            "multipart_cleanup",
        )

    def test_cleanup_lease_rejects_nonterminal_upload(self):
        _backup, point = self._point()
        lease = DurableStorageUploadLease(
            point,
            task_id="cleanup-delivery",
            purpose="multipart_cleanup",
        )

        with self.assertRaises(StorageCleanupNotEligible):
            lease.claim()

    def test_cleanup_task_aborts_exact_upload_without_changing_terminal_state(self):
        point, key, initiated = self._owned_cleanup_point()
        client = mock.MagicMock()
        client.head_object.side_effect = ClientError(
            {"Error": {"Code": "404"}}, "HeadObject"
        )
        owned = {
            "Key": key,
            "UploadId": "owned-upload",
            "Initiated": initiated,
            "Owner": {"ID": "owner-1"},
            "Initiator": {"ID": "initiator-1"},
        }
        client.list_multipart_uploads.side_effect = [
            {"Uploads": [owned], "IsTruncated": False},
            {"Uploads": [], "IsTruncated": False},
        ]
        client.list_parts.return_value = {
            "Parts": [{"PartNumber": 1, "ETag": '"part"', "Size": 10}],
            "IsTruncated": False,
        }

        with mock.patch(
            "apps._tasks.integration.storage.tasks.multipart_cleanup_context",
            return_value={
                "client": client,
                "bucket": "cleanup-test-bucket",
                "metadata_key": "aws_s3_object",
                "expected_owner": None,
            },
        ):
            result = storage_cleanup_owned_multipart.run("website", point.pk)

        self.assertEqual(result, {"result": "aborted", "phase": "complete"})
        point.refresh_from_db()
        self.assertEqual(point.status, point.Status.UPLOAD_FAILED)
        self.assertEqual(point.upload_attempt_count, 0)
        self.assertEqual(point.last_error_code, "STORAGE_RETRIES_EXHAUSTED")
        self.assertEqual(point.upload_lease_owner, "")
        self.assertIsNone(point.upload_lease_token)
        self.assertEqual(
            point.metadata["aws_s3_object"]["multipart_cleanup"]["result"],
            "aborted",
        )
        client.abort_multipart_upload.assert_called_once_with(
            Bucket="cleanup-test-bucket",
            Key=key,
            UploadId="owned-upload",
        )

    @override_settings(
        S3_MULTIPART_CLEANUP_STALE_SECONDS=300,
        S3_MULTIPART_CLEANUP_BATCH_SIZE=10,
        S3_MULTIPART_CLEANUP_SCAN_LIMIT=100,
    )
    def test_stale_sweep_enqueues_only_terminal_owned_candidate(self):
        point, _key, _initiated = self._owned_cleanup_point()
        point.__class__.objects.filter(pk=point.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )
        _backup, active = self._point()
        active.metadata = point.metadata
        active.save(update_fields=["metadata", "modified"])

        with mock.patch.object(
            storage_cleanup_owned_multipart, "apply_async"
        ) as publish:
            result = storage_sweep_owned_multipart_cleanup.run()

        self.assertEqual(result["enqueued"], 1)
        publish.assert_called_once_with(args=["website", point.pk])
