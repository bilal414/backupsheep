"""Failure-injection tests for renewable, fenced storage-point ownership."""

import uuid
from datetime import timedelta

from django.test import override_settings
from django.utils import timezone

from apps._tasks.helper.tasks import _local_upload_is_active
from apps._tasks.integration.storage.lease import (
    DurableStorageUploadLease,
    StorageUploadLeaseBusy,
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
