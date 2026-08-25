from datetime import timedelta
from unittest import mock

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django_celery_beat.models import PeriodicTask

from apps._tasks.helper import tasks as helper_tasks
from apps.console.backup.models import CoreBackupRequest, CoreWebsiteBackup
from apps.console.node.models import CoreNode, CoreSchedule, CoreScheduleRun
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup
from apps.console.backup.models import CoreDigitalOceanBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.celery import app as celery_app
from backupsheep.scheduler import BackupDatabaseScheduler, BackupModelEntry


class RunScheduledBackupTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.node = factories.make_website_node(self.account, self.member)

    def test_active_schedule_dispatches_backup_task_and_records_run(self):
        schedule = factories.make_schedule(self.node, self.member)
        with mock.patch("apps._tasks.backup_dispatch.current_app") as capp:
            helper_tasks.run_scheduled_backup.apply(kwargs={"schedule_id": schedule.id})
        capp.send_task.assert_called_once()
        task_name = capp.send_task.call_args.args[0]
        kwargs = capp.send_task.call_args.kwargs["kwargs"]
        self.assertEqual(task_name, "backup_website")
        self.assertEqual(kwargs["node_id"], self.node.id)
        self.assertEqual(kwargs["schedule_id"], schedule.id)
        self.assertEqual(CoreScheduleRun.objects.filter(schedule=schedule).count(), 1)

    def test_inactive_schedule_does_not_dispatch(self):
        schedule = factories.make_schedule(self.node, self.member, status=CoreSchedule.Status.PAUSED)
        with mock.patch.object(helper_tasks, "current_app") as capp:
            helper_tasks.run_scheduled_backup.apply(kwargs={"schedule_id": schedule.id})
        capp.send_task.assert_not_called()
        self.assertEqual(CoreScheduleRun.objects.count(), 0)

    def test_backup_task_name_matches_integration(self):
        self.assertEqual(self.node.backup_task_name(), "backup_website")
        do_node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        self.assertEqual(do_node.backup_task_name(), "backup_digitalocean")

    def test_schedule_storage_ids_use_only_the_non_secret_through_table(self):
        storage = factories.make_storage(
            self.account, self.member, bucket="scheduled-through-only"
        )
        schedule = factories.make_schedule(
            self.node, self.member, storages=(storage,)
        )
        with CaptureQueriesContext(connection) as queries:
            storage_ids = schedule.storage_ids
        self.assertEqual(storage_ids, [storage.pk])
        sql = "\n".join(query["sql"] for query in queries.captured_queries)
        self.assertIn('"core_schedule_storage_points"', sql)
        self.assertNotIn('FROM "core_storage"', sql)


class CrashSafeBeatSchedulingTests(BaseTestCase):
    """The scheduler boundary is the durable occurrence/outbox boundary."""

    def _make_periodic_schedule(self, *, kind=CoreSchedule.Type.CRON):
        schedule = factories.make_schedule(self.node, self.member)
        schedule.type = kind
        if kind == CoreSchedule.Type.RATE:
            schedule.rate_unit = CoreSchedule.RateUnit.MINUTES
            schedule.rate_value = 1
        elif kind == CoreSchedule.Type.ONETIME:
            schedule.at_datetime = timezone.now() - timedelta(minutes=1)
        schedule.save()
        schedule.schedule_create()
        return schedule, PeriodicTask.objects.get(pk=schedule.celery_periodic_task_id)

    def setUp(self):
        super().setUp()
        self.node = factories.make_website_node(self.account, self.member)

    @staticmethod
    def _scheduler_and_entry(periodic_task):
        scheduler = BackupDatabaseScheduler.__new__(BackupDatabaseScheduler)
        scheduler.app = celery_app
        scheduler._schedule = {}
        scheduler._dirty = set()
        scheduler._heap = []
        scheduler._tasks_since_sync = 0
        entry = BackupModelEntry(
            PeriodicTask.objects.get(pk=periodic_task.pk), app=celery_app
        )
        scheduler._schedule[entry.name] = entry
        return scheduler, entry

    def test_two_beat_instances_create_one_request_and_one_stable_task_id(self):
        schedule, periodic_task = self._make_periodic_schedule()
        scheduler_a, entry_a = self._scheduler_and_entry(periodic_task)
        scheduler_b, entry_b = self._scheduler_and_entry(periodic_task)

        scheduler_a.reserve(entry_a)
        scheduler_b.reserve(entry_b)
        self.assertEqual(entry_a._bs_occurrence_id, entry_b._bs_occurrence_id)

        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ) as publish, self.captureOnCommitCallbacks(execute=True):
            scheduler_a.apply_entry(entry_a)
            scheduler_b.apply_entry(entry_b)

        requests = CoreBackupRequest.objects.filter(schedule=schedule)
        self.assertEqual(requests.count(), 1)
        self.assertEqual(CoreScheduleRun.objects.filter(schedule=schedule).count(), 1)
        self.assertGreaterEqual(publish.call_count, 1)
        self.assertEqual(publish.call_args.args[0], requests.get().pk)
        self.assertTrue(all(call.args[0] == requests.get().pk for call in publish.call_args_list))

    def test_distinct_celery_delivery_ids_share_one_explicit_occurrence(self):
        schedule, _ = self._make_periodic_schedule()

        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ) as publish:
            helper_tasks.run_scheduled_backup.apply(
                kwargs={
                    "schedule_id": schedule.id,
                    "occurrence_id": "periodic-occurrence-test-1",
                },
                task_id="beat-process-a-delivery-id",
            )
            helper_tasks.run_scheduled_backup.apply(
                kwargs={
                    "schedule_id": schedule.id,
                    "occurrence_id": "periodic-occurrence-test-1",
                },
                task_id="beat-process-b-delivery-id",
            )

        self.assertEqual(
            CoreBackupRequest.objects.filter(schedule=schedule).count(), 1
        )
        self.assertEqual(
            CoreScheduleRun.objects.filter(schedule=schedule).values_list(
                "request_id", flat=True
            ).get(),
            "periodic-occurrence-test-1",
        )
        self.assertGreaterEqual(publish.call_count, 1)

    def test_crash_after_outbox_commit_before_publish_is_recovered(self):
        schedule, periodic_task = self._make_periodic_schedule()
        scheduler, entry = self._scheduler_and_entry(periodic_task)
        scheduler.reserve(entry)

        # This is the process-crash boundary: the transaction committed the
        # outbox and schedule state, but no broker call has happened yet.
        result = scheduler._commit_occurrence(entry)
        self.assertEqual(result["kind"], "committed")
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 1)
        self.assertEqual(
            CoreScheduleRun.objects.filter(schedule=schedule).count(), 1
        )

        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ) as publish:
            helper_tasks.resume_pending_backup_requests.apply()
        self.assertEqual(publish.call_count, 1)
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 1)

    def test_ambiguous_broker_response_keeps_one_recoverable_request(self):
        schedule, periodic_task = self._make_periodic_schedule()
        scheduler_a, entry_a = self._scheduler_and_entry(periodic_task)
        scheduler_b, entry_b = self._scheduler_and_entry(periodic_task)
        scheduler_a.reserve(entry_a)
        scheduler_b.reserve(entry_b)

        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request",
            side_effect=TimeoutError("confirmation lost"),
        ) as publish, self.captureOnCommitCallbacks(execute=True):
            scheduler_a.apply_entry(entry_a)
            # The second delivery may arrive after the first publish response
            # was lost; it must still lose the database baseline race.
            scheduler_b.apply_entry(entry_b)

        request = CoreBackupRequest.objects.get(schedule=schedule)
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 1)
        self.assertEqual(CoreScheduleRun.objects.filter(schedule=schedule).count(), 1)
        self.assertEqual(request.status, CoreBackupRequest.Status.PENDING)
        self.assertEqual(publish.call_count, 1)

    def test_next_legitimate_rate_occurrence_gets_a_new_identity(self):
        schedule, periodic_task = self._make_periodic_schedule(
            kind=CoreSchedule.Type.RATE
        )
        first_scheduler, first_entry = self._scheduler_and_entry(periodic_task)
        first_scheduler.reserve(first_entry)
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ), self.captureOnCommitCallbacks(execute=True):
            first_scheduler.apply_entry(first_entry)
        first_request = CoreBackupRequest.objects.get(schedule=schedule)

        # Simulate the next minute having elapsed.  This is durable schedule
        # state, not a wall-clock dedupe window.
        periodic_task.refresh_from_db()
        periodic_task.last_run_at = timezone.now() - timedelta(minutes=2)
        periodic_task.save(update_fields=["last_run_at"])
        second_scheduler, second_entry = self._scheduler_and_entry(periodic_task)
        second_scheduler.reserve(second_entry)
        self.assertNotEqual(
            first_entry._bs_occurrence_id, second_entry._bs_occurrence_id
        )
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ), self.captureOnCommitCallbacks(execute=True):
            second_scheduler.apply_entry(second_entry)

        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 2)
        self.assertEqual(
            CoreScheduleRun.objects.filter(schedule=schedule).values_list(
                "request_id", flat=True
            ).distinct().count(),
            2,
        )
        self.assertNotEqual(
            first_request.task_id,
            CoreBackupRequest.objects.filter(schedule=schedule)
            .exclude(pk=first_request.pk)
            .get()
            .task_id,
        )

    def test_every_minute_schedule_is_not_suppressed_by_a_coarse_window(self):
        schedule, periodic_task = self._make_periodic_schedule()
        periodic_task.last_run_at = timezone.now() - timedelta(minutes=2)
        periodic_task.save(update_fields=["last_run_at"])
        first_scheduler, first_entry = self._scheduler_and_entry(periodic_task)
        self.assertTrue(first_entry.is_due()[0])
        first_scheduler.reserve(first_entry)
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ), self.captureOnCommitCallbacks(execute=True):
            first_scheduler.apply_entry(first_entry)

        periodic_task.refresh_from_db()
        periodic_task.last_run_at = timezone.now() - timedelta(minutes=2)
        periodic_task.save(update_fields=["last_run_at"])
        second_scheduler, second_entry = self._scheduler_and_entry(periodic_task)
        self.assertTrue(second_entry.is_due()[0])
        second_scheduler.reserve(second_entry)
        self.assertNotEqual(
            first_entry._bs_occurrence_id, second_entry._bs_occurrence_id
        )
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ), self.captureOnCommitCallbacks(execute=True):
            second_scheduler.apply_entry(second_entry)
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 2)

    def test_one_time_schedule_is_consumed_once_after_transactional_dispatch(self):
        schedule, periodic_task = self._make_periodic_schedule(
            kind=CoreSchedule.Type.ONETIME
        )
        scheduler, entry = self._scheduler_and_entry(periodic_task)
        self.assertTrue(entry.is_due()[0])
        scheduler.reserve(entry)
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ), self.captureOnCommitCallbacks(execute=True):
            scheduler.apply_entry(entry)

        periodic_task.refresh_from_db()
        self.assertEqual(periodic_task.total_run_count, 1)
        next_entry = BackupModelEntry(periodic_task, app=celery_app)
        self.assertFalse(next_entry.is_due()[0])
        periodic_task.refresh_from_db()
        self.assertFalse(periodic_task.enabled)
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 1)

    def test_invalid_occurrence_state_fails_closed_without_outbox(self):
        schedule, periodic_task = self._make_periodic_schedule()
        periodic_task.args = "[]"
        periodic_task.save(update_fields=["args"])
        scheduler, entry = self._scheduler_and_entry(periodic_task)
        scheduler.reserve(entry)
        with self.captureOnCommitCallbacks(execute=True):
            scheduler.apply_entry(entry)
        self.assertTrue(entry._bs_occurrence_error)
        self.assertFalse(CoreBackupRequest.objects.filter(schedule=schedule).exists())

    def test_legacy_message_without_occurrence_id_still_uses_delivery_id(self):
        schedule, _ = self._make_periodic_schedule()
        with mock.patch(
            "apps._tasks.backup_dispatch.publish_backup_request"
        ):
            helper_tasks.run_scheduled_backup.apply(
                kwargs={"schedule_id": schedule.id},
                task_id="legacy-delivery-id",
            )
        self.assertEqual(
            CoreScheduleRun.objects.filter(schedule=schedule)
            .values_list("request_id", flat=True)
            .get(),
            "legacy-delivery-id",
        )
        self.assertEqual(CoreBackupRequest.objects.filter(schedule=schedule).count(), 1)


class KeepLastRetentionTests(BaseTestCase):
    """keep_last is applied when a backup finalizes; exercise the real retention path in
    poll_cloud_backup (cloud snapshots) with the provider status check mocked."""

    def test_keep_last_soft_deletes_oldest_completed(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        schedule = factories.make_schedule(node, self.member, keep_last=2)

        # 3 already-complete backups for the schedule + the one we're polling now.
        olds = [
            CoreDigitalOceanBackup.objects.create(
                digitalocean=node.digitalocean, schedule=schedule,
                status=UtilBackup.Status.COMPLETE,
            )
            for _ in range(3)
        ]
        polling = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean, schedule=schedule,
            status=UtilBackup.Status.IN_PROGRESS, celery_task_id="poll-task-1",
        )

        soft_deleted = []
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.COMPLETE), \
             mock.patch.object(CoreDigitalOceanBackup, "soft_delete",
                               autospec=True, side_effect=lambda self: soft_deleted.append(self.id)), \
             mock.patch.object(CoreNode, "notify_backup_success"):
            helper_tasks.poll_cloud_backup.apply(args=[node.id, polling.id])

        # 4 completed, keep_last=2 -> 2 are soft-deleted, and the just-finalized
        # (newest) backup is never one of them.
        self.assertEqual(len(soft_deleted), 2)
        self.assertNotIn(polling.id, soft_deleted)
        self.assertTrue(set(soft_deleted).issubset({o.id for o in olds}))


class AirGappedCopyPolicyTests(BaseTestCase):
    def test_backup_is_not_started_when_required_air_gapped_copy_fails_validation(self):
        node = factories.make_website_node(self.account, self.member)
        air_gapped_storage = factories.make_storage(self.account, self.member, code="aws_s3")
        air_gapped_storage.is_air_gapped = True
        air_gapped_storage.save()
        schedule = factories.make_schedule(
            node, self.member, storages=(air_gapped_storage,)
        )
        schedule.require_air_gapped_copy = True
        schedule.save()

        with mock.patch.object(CoreStorage, "validate", return_value=False):
            result = node.backup_initiate(
                "air-gap-task",
                UtilBackup.Type.SCHEDULED,
                1,
                schedule.id,
                schedule.storage_ids,
                None,
                prepare_destinations=True,
            )

        self.assertIsNone(result)
        backup = CoreWebsiteBackup.objects.get(celery_task_id="air-gap-task")
        self.assertEqual(backup.status, UtilBackup.Status.STORAGE_VALIDATION_FAILED)
