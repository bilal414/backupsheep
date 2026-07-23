"""Duplicate-backup prevention.

CoreNode.backup_initiate must never let two DIFFERENT celery tasks start a backup
for the same node at the same time: a duplicated schedule fire or an overlapping
manual + scheduled trigger would otherwise create two paid snapshots at the
provider. The guard lives inside backup_initiate (node row lock + active-status
check, see UtilBackup.ACTIVE_STATUSES); these tests exercise it directly, through
the real celery tasks (provider calls mocked), and concurrently (threads).
"""
import threading
import uuid
from unittest import mock

from django.db import close_old_connections
from django.test import TransactionTestCase

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.digitalocean import backup_digitalocean
from apps._tasks.integration.website import backup_website
from apps.console.backup.models import CoreDigitalOceanBackup, CoreWebsiteBackup
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreDigitalOcean, CoreWebsite
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class BackupInitiateGuardTests(BaseTestCase):
    """Guard semantics of CoreNode.backup_initiate itself."""

    def _node(self):
        return factories.make_cloud_node(self.account, self.member, code="digitalocean")

    def _initiate(self, node, task_id, storage_ids=None):
        return node.backup_initiate(
            task_id, UtilBackup.Type.ON_DEMAND, 1, None, storage_ids, None
        )

    def test_first_backup_is_created(self):
        node = self._node()
        backup = self._initiate(node, "task-1")
        self.assertIsNotNone(backup)
        self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)

    def test_second_different_task_is_blocked_without_record(self):
        node = self._node()
        self._initiate(node, "task-1")
        self.assertIsNone(self._initiate(node, "task-2"))
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)

    def test_every_active_status_blocks(self):
        for status in UtilBackup.ACTIVE_STATUSES:
            node = self._node()
            CoreDigitalOceanBackup.objects.create(
                digitalocean=node.digitalocean, status=status, celery_task_id="other-task",
            )
            self.assertIsNone(self._initiate(node, "task-new"), status)
            self.assertEqual(node.digitalocean.backups.count(), 1, status)

    def test_retry_same_task_reuses_its_backup(self):
        # A celery retry re-runs the task with the SAME task id after
        # backup_retrying_reset marked the backup RETRYING; it must proceed.
        node = self._node()
        first = self._initiate(node, "task-1")
        first.status = UtilBackup.Status.RETRYING
        first.save()
        retry = self._initiate(node, "task-1")
        self.assertIsNotNone(retry)
        self.assertEqual(retry.id, first.id)
        self.assertEqual(retry.status, UtilBackup.Status.IN_PROGRESS)
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)

    def test_terminal_status_allows_new_backup(self):
        terminal = (
            UtilBackup.Status.COMPLETE,
            UtilBackup.Status.FAILED,
            UtilBackup.Status.TIMEOUT,
            UtilBackup.Status.CANCELLED,
            UtilBackup.Status.MAX_RETRY_FAILED,
            UtilBackup.Status.UPLOAD_FAILED,
        )
        for status in terminal:
            node = self._node()
            CoreDigitalOceanBackup.objects.create(
                digitalocean=node.digitalocean, status=status, celery_task_id="old-task",
            )
            self.assertIsNotNone(self._initiate(node, "task-new"), status)
            self.assertEqual(node.digitalocean.backups.count(), 2, status)

    def test_website_backup_in_transfer_status_blocks(self):
        # File-based backups hold DOWNLOAD/UPLOAD statuses while their task is
        # still running, so those must block a second dump too.
        node = factories.make_website_node(self.account, self.member)
        CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.DOWNLOAD_IN_PROGRESS,
            celery_task_id="other-task",
        )
        self.assertIsNone(self._initiate(node, "task-new", storage_ids=[]))
        self.assertEqual(node.website.backups.count(), 1)


class CloudTaskDuplicateTests(BaseTestCase):
    """The real backup_digitalocean task, with the provider API + poller mocked."""

    def _run_task(self, node, task_id=None):
        kwargs = {
            "node_id": node.id, "schedule_id": None, "storage_ids": None, "notes": None,
        }
        with mock.patch.object(CoreDigitalOcean, "create_snapshot") as snapshot, \
                mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as poll:
            backup_digitalocean.apply(kwargs=kwargs, task_id=task_id or uuid.uuid4().hex)
        return snapshot, poll

    def test_two_invocations_create_one_backup_and_one_snapshot(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        snapshot1, poll1 = self._run_task(node)
        snapshot2, poll2 = self._run_task(node)
        snapshot1.assert_called_once()
        poll1.assert_called_once()
        # Second (duplicate) invocation exited before touching the provider.
        snapshot2.assert_not_called()
        poll2.assert_not_called()
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)

    def test_retry_with_same_task_id_is_not_blocked(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        snapshot1, _ = self._run_task(node, task_id="retry-task-id")
        snapshot1.assert_called_once()
        # What the task's retry path does before re-queueing itself.
        backup = CoreDigitalOceanBackup.objects.get()
        backup.status = UtilBackup.Status.RETRYING
        backup.save()
        snapshot2, poll2 = self._run_task(node, task_id="retry-task-id")
        snapshot2.assert_called_once()
        poll2.assert_called_once()
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)

    def test_new_backup_allowed_after_previous_completes(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        self._run_task(node)
        backup = CoreDigitalOceanBackup.objects.get()
        backup.status = UtilBackup.Status.COMPLETE
        backup.save()
        snapshot2, poll2 = self._run_task(node)
        snapshot2.assert_called_once()
        poll2.assert_called_once()
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 2)


class WebsiteTaskDuplicateTests(BaseTestCase):
    """The real backup_website task, with connection validation + snapshot mocked."""

    def test_duplicate_invocation_exits_before_snapshot(self):
        node = factories.make_website_node(self.account, self.member)
        kwargs = {
            "node_id": node.id, "schedule_id": None, "storage_ids": [], "notes": None,
        }
        with mock.patch.object(CoreConnection, "validate", return_value=True), \
                mock.patch.object(CoreWebsite, "create_snapshot") as snapshot:
            backup_website.apply(kwargs=kwargs, task_id="w-task-1")
            snapshot.assert_called_once()
            snapshot.reset_mock()
            # First backup is still in flight -> second task must do nothing.
            backup_website.apply(kwargs=kwargs, task_id="w-task-2")
            snapshot.assert_not_called()
        self.assertEqual(CoreWebsiteBackup.objects.count(), 1)


class ConcurrentInitiateTests(TransactionTestCase):
    """Two threads initiating backups for the same node at the same time.

    The node row lock (select_for_update) serializes them, so exactly one backup
    record is created and exactly one caller gets it -- regardless of which
    thread wins the lock. Needs TransactionTestCase: threads use their own
    connections and can only see committed rows.
    """

    def test_concurrent_initiates_create_exactly_one_backup(self):
        account, member, _user = factories.make_account()
        node = factories.make_cloud_node(account, member, code="digitalocean")
        barrier = threading.Barrier(2)
        results = []

        def initiate(task_id):
            try:
                barrier.wait(timeout=10)
                results.append(
                    node.backup_initiate(
                        task_id, UtilBackup.Type.ON_DEMAND, 1, None, None, None
                    )
                )
            finally:
                close_old_connections()

        threads = [
            threading.Thread(target=initiate, args=("task-1",)),
            threading.Thread(target=initiate, args=("task-2",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "initiate deadlocked")

        self.assertEqual(len(results), 2)
        self.assertEqual(sum(1 for backup in results if backup is not None), 1)
        self.assertEqual(CoreDigitalOceanBackup.objects.count(), 1)
