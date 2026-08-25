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
from datetime import timedelta
from unittest import mock

from django.db import IntegrityError, close_old_connections, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.digitalocean import backup_digitalocean
from apps._tasks.integration.website import backup_website
from apps.console.backup.models import (
    CoreDigitalOceanBackup,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.connection.models import CoreConnection, CoreIntegration
from apps.console.node.models import CoreDigitalOcean, CoreNode, CoreWebsite
from apps.console.storage.models import CoreStorage
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

    def test_same_task_terminal_redelivery_is_a_noop(self):
        terminal_statuses = [
            status.value
            for status in UtilBackup.Status
            if status.value not in UtilBackup.ACTIVE_STATUSES
        ]
        for status in terminal_statuses:
            with self.subTest(status=status):
                node = self._node()
                backup = CoreDigitalOceanBackup.objects.create(
                    digitalocean=node.digitalocean,
                    status=status,
                    celery_task_id="terminal-task",
                )

                self.assertIsNone(self._initiate(node, "terminal-task"))
                backup.refresh_from_db()
                self.assertEqual(backup.status, status)
                self.assertEqual(node.digitalocean.backups.count(), 1)

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

    def test_same_task_reuses_persisted_local_upload_phase(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="persisted-upload-phase"
        )
        first = CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
            celery_task_id="task-1",
            metadata={"_backup_storage_ids": [storage.id]},
        )
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=first,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_IN_PROGRESS,
        )
        resumed = self._initiate(node, "task-1", storage_ids=[])
        self.assertEqual(resumed.id, first.id)
        self.assertEqual(resumed.status, UtilBackup.Status.UPLOAD_IN_PROGRESS)

    def test_website_source_selection_is_frozen_once_on_backup_creation(self):
        node = factories.make_website_node(self.account, self.member)
        website = node.website
        original_paths = [
            {"name": "public_html", "path": "public_html", "type": "directory"},
        ]
        original_excludes = [{"path": "public_html/cache", "type": "directory"}]
        website.all_paths = False
        website.paths = original_paths
        website.excludes = original_excludes
        website.save(update_fields=["all_paths", "paths", "excludes", "modified"])

        with mock.patch.object(
            CoreNode, "_reconcile_local_backup_destinations", return_value=True
        ):
            backup = self._initiate(node, "website-selection-task", storage_ids=[])

        self.assertFalse(backup.all_paths)
        self.assertEqual(backup.paths, original_paths)
        self.assertEqual(backup.excludes, original_excludes)

        website.all_paths = True
        website.paths = None
        website.excludes = None
        website.save(update_fields=["all_paths", "paths", "excludes", "modified"])
        backup.status = UtilBackup.Status.RETRYING
        backup.save(update_fields=["status", "modified"])

        with mock.patch.object(
            CoreNode, "_reconcile_local_backup_destinations", return_value=True
        ):
            resumed = self._initiate(
                node, "website-selection-task", storage_ids=[]
            )

        self.assertEqual(resumed.pk, backup.pk)
        self.assertFalse(resumed.all_paths)
        self.assertEqual(resumed.paths, original_paths)
        self.assertEqual(resumed.excludes, original_excludes)


class DestinationSetupRecoveryTests(BaseTestCase):
    def _storage(self, suffix):
        return factories.make_storage(
            self.account,
            self.member,
            bucket=f"destination-setup-{suffix}",
        )

    def _initiate(self, node, task_id, storage_ids):
        return node.backup_initiate(
            task_id,
            UtilBackup.Type.ON_DEMAND,
            1,
            None,
            storage_ids,
            None,
        )

    def test_crash_after_first_destination_resumes_remaining_selection(self):
        node = factories.make_website_node(self.account, self.member)
        first = self._storage("first")
        second = self._storage("second")

        with mock.patch.object(
            CoreStorage,
            "validate",
            side_effect=[True, RuntimeError("worker disappeared")],
        ):
            with self.assertRaisesRegex(RuntimeError, "worker disappeared"):
                self._initiate(node, "destination-crash-task", [first.id, second.id])

        backup = CoreWebsiteBackup.objects.get(
            celery_task_id="destination-crash-task"
        )
        self.assertEqual(
            set(backup.storage_points.values_list("id", flat=True)),
            {first.id},
        )
        self.assertEqual(
            backup.metadata["_backup_destination_setup"]["state"],
            "in_progress",
        )

        with mock.patch.object(CoreStorage, "validate", return_value=True) as validate:
            resumed = self._initiate(
                node,
                "destination-crash-task",
                [first.id, second.id],
            )

        self.assertEqual(resumed.pk, backup.pk)
        validate.assert_called_once()
        backup.refresh_from_db()
        self.assertEqual(
            set(backup.storage_points.values_list("id", flat=True)),
            {first.id, second.id},
        )
        setup = backup.metadata["_backup_destination_setup"]
        self.assertEqual(setup["state"], "complete")
        self.assertEqual(setup["requested_count"], 2)
        self.assertEqual(setup["accepted_count"], 2)
        self.assertEqual(setup["validation_failed_count"], 0)
        self.assertEqual(setup["unavailable_count"], 0)
        self.assertEqual(setup["error_code"], "")

    def test_live_destination_setup_lease_blocks_duplicate_delivery(self):
        from apps._tasks.execution import durable_execution_lease

        node = factories.make_website_node(self.account, self.member)
        storage = self._storage("leased")
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="destination-lease-task",
            metadata={"_backup_storage_ids": [storage.id]},
        )
        backup.initialize_execution(
            celery_task_id=backup.celery_task_id,
            task_name="backup_website",
        )

        with durable_execution_lease(
            backup,
            phase="destination_setup",
            task_id="original-delivery",
        ) as lease:
            self.assertTrue(lease.acquired)
            with mock.patch.object(CoreStorage, "validate") as validate:
                duplicate = self._initiate(
                    node,
                    "destination-lease-task",
                    [storage.id],
                )

        self.assertIsNone(duplicate)
        validate.assert_not_called()
        self.assertFalse(backup.storage_points.exists())

    def test_partial_validation_is_not_reported_as_complete(self):
        from apps._tasks.integration.storage.tasks import finalize_backup

        node = factories.make_website_node(self.account, self.member)
        accepted = self._storage("accepted")
        rejected = self._storage("rejected")
        with mock.patch.object(
            CoreStorage, "validate", side_effect=[True, False]
        ), mock.patch.object(CoreNode, "notify_storage_validation_fail"):
            backup = self._initiate(
                node,
                "destination-partial-task",
                [accepted.id, rejected.id],
            )

        point = backup.stored_website_backups.get()
        point.status = point.Status.UPLOAD_COMPLETE
        point.save(update_fields=["status", "modified"])
        with mock.patch(
            "apps._tasks.helper.tasks.delete_from_disk.apply_async"
        ):
            finalize_backup.apply(args=[node.id, backup.id])

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.PARTIAL)
        self.assertEqual(
            backup.metadata["storage_upload_summary"],
            {
                "uploaded": 1,
                "configured": 2,
                "accepted": 1,
                "failed": 1,
                "partial": True,
            },
        )

    def test_no_valid_destination_stops_before_source_snapshot(self):
        node = factories.make_website_node(self.account, self.member)
        storage = self._storage("invalid")
        kwargs = {
            "node_id": node.id,
            "schedule_id": None,
            "storage_ids": [storage.id],
            "notes": None,
        }
        with mock.patch.object(
            CoreStorage, "validate", return_value=False
        ), mock.patch.object(
            CoreNode, "notify_storage_validation_fail"
        ), mock.patch.object(
            CoreConnection, "validate", return_value=True
        ) as connection_validate, mock.patch.object(
            CoreWebsite, "create_snapshot"
        ) as snapshot:
            backup_website.apply(kwargs=kwargs, task_id="no-destination-task")

        snapshot.assert_not_called()
        connection_validate.assert_not_called()
        backup = CoreWebsiteBackup.objects.get(
            celery_task_id="no-destination-task"
        )
        self.assertEqual(
            backup.status,
            UtilBackup.Status.STORAGE_VALIDATION_FAILED,
        )
        self.assertEqual(
            backup.get_execution_state().last_error_code,
            "NO_VALID_STORAGE_DESTINATION",
        )

    def test_redelivery_cannot_replace_immutable_destination_selection(self):
        node = factories.make_website_node(self.account, self.member)
        original = self._storage("original")
        substituted = self._storage("substituted")

        with mock.patch.object(CoreStorage, "validate", return_value=True) as validate:
            first = self._initiate(
                node,
                "immutable-destination-task",
                [original.id],
            )
            second = self._initiate(
                node,
                "immutable-destination-task",
                [substituted.id],
            )

        self.assertEqual(first.pk, second.pk)
        validate.assert_called_once()
        first.refresh_from_db()
        self.assertEqual(first.metadata["_backup_storage_ids"], [original.id])
        self.assertEqual(
            set(first.storage_points.values_list("id", flat=True)),
            {original.id},
        )

    def test_database_constraint_prevents_duplicate_logical_destination(self):
        node = factories.make_website_node(self.account, self.member)
        storage = self._storage("unique")
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="unique-destination-task",
        )
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreWebsiteBackupStoragePoints.objects.create(
                backup=backup,
                storage=storage,
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED,
            )


class CloudTaskDuplicateTests(BaseTestCase):
    """The real backup_digitalocean task, with the provider API + poller mocked."""

    def _run_task(self, node, task_id=None):
        kwargs = {
            "node_id": node.id, "schedule_id": None, "storage_ids": None, "notes": None,
        }
        def accepted(backup):
            backup.action_id = f"provider-action-{backup.pk}"
            backup.save(update_fields=["action_id", "modified"])

        with mock.patch.object(
                CoreDigitalOcean,
                "create_snapshot",
                side_effect=accepted,
        ) as snapshot, \
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
        # The retry resumes polling the durable provider action and never emits
        # a second create request.
        snapshot2.assert_not_called()
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


class RecoverySweepTests(BaseTestCase):
    def test_provider_create_lease_blocks_a_second_creator(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="create-task-1",
        )

        claimed = helper_tasks._claim_provider_create(backup, "create-task-1")
        self.assertIsNotNone(claimed)
        self.assertIsNone(
            helper_tasks._claim_provider_create(backup, "create-task-2")
        )
        # A duplicate delivery can carry the same Celery id. The lease must
        # still be exclusive while the original provider request is in flight.
        self.assertIsNone(
            helper_tasks._claim_provider_create(backup, "create-task-1")
        )

        state = claimed.get_execution_state()
        helper_tasks._release_backup_lease(
            backup,
            "create-task-1",
            "create",
            lease_token=state.lease_token,
        )
        self.assertIsNotNone(
            helper_tasks._claim_provider_create(backup, "create-task-2")
        )

    def test_retry_reset_keeps_unknown_provider_create_lease(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="create-task-1",
        )

        self.assertIsNotNone(
            helper_tasks._claim_provider_create(backup, "create-task-1")
        )
        node.backup_retrying_reset("create-task-1")

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        self.assertIsNone(
            helper_tasks._claim_provider_create(backup, "create-task-1")
        )

    def test_provider_timeout_stays_recoverable_while_create_is_leased(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="create-task-1",
        )
        self.assertIsNotNone(
            helper_tasks._claim_provider_create(backup, "create-task-1")
        )

        node.backup_timeout_reset("create-task-1")

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)

    def test_stale_create_is_requeued_with_original_task_id(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="lost-create-task",
        )
        CoreDigitalOceanBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )
        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_backups.apply()

        send_task.assert_called_once()
        self.assertEqual(send_task.call_args.args[0], "backup_digitalocean")
        self.assertEqual(send_task.call_args.kwargs["task_id"], "lost-create-task")
        self.assertTrue(send_task.call_args.kwargs["kwargs"]["resume"])

    def test_recovery_uses_persisted_on_demand_storage_ids(self):
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            status=UtilBackup.Status.DOWNLOAD_IN_PROGRESS,
            celery_task_id="lost-local-task",
            metadata={"_backup_storage_ids": [101, 202]},
        )
        CoreWebsiteBackup.objects.filter(pk=backup.pk).update(
            modified=timezone.now() - timedelta(hours=1)
        )

        with mock.patch.object(helper_tasks.current_app, "send_task") as send_task:
            helper_tasks.resume_in_progress_files_backups.apply()

        send_task.assert_called_once()
        self.assertEqual(
            send_task.call_args.kwargs["kwargs"]["storage_ids"], [101, 202]
        )


class WebsiteTaskDuplicateTests(BaseTestCase):
    """The real backup_website task, with connection validation + snapshot mocked."""

    def test_duplicate_invocation_exits_before_snapshot(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(
            self.account, self.member, bucket="website-duplicate-guard"
        )
        kwargs = {
            "node_id": node.id,
            "schedule_id": None,
            "storage_ids": [storage.id],
            "notes": None,
        }
        with mock.patch.object(CoreStorage, "validate", return_value=True), \
                mock.patch.object(CoreConnection, "validate", return_value=True), \
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

    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={"name": "DigitalOcean", "type": CoreIntegration.Type.CLOUD},
        )

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

        # The provider-independent execution ledger uses the same PostgreSQL locking
        # guarantee: two broker deliveries racing for one backup elect exactly one
        # fenced lease owner.
        backup = CoreDigitalOceanBackup.objects.get()
        claim_barrier = threading.Barrier(2)
        claims = []
        errors = []

        def claim(owner):
            try:
                close_old_connections()
                candidate = CoreDigitalOceanBackup.objects.get(pk=backup.pk)
                claim_barrier.wait(timeout=10)
                state = candidate.claim_execution(
                    lease_owner=owner,
                    phase="create",
                    lease_seconds=300,
                )
                claims.append(state.lease_token if state is not None else None)
            except Exception as error:  # pragma: no cover - asserted below
                errors.append(error)
            finally:
                close_old_connections()

        claim_threads = [
            threading.Thread(target=claim, args=("delivery-a",)),
            threading.Thread(target=claim, args=("delivery-b",)),
        ]
        for thread in claim_threads:
            thread.start()
        for thread in claim_threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "execution claim deadlocked")

        self.assertEqual(errors, [])
        self.assertEqual(len(claims), 2)
        self.assertEqual(sum(token is not None for token in claims), 1)
        state = backup.get_execution_state()
        self.assertEqual(state.claim_count, 1)
        self.assertIn(state.lease_token, claims)
