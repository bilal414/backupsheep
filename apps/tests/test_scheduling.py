from unittest import mock

from apps._tasks.helper import tasks as helper_tasks
from apps.console.node.models import CoreNode, CoreSchedule, CoreScheduleRun
from apps.console.utils.models import UtilBackup
from apps.console.backup.models import CoreDigitalOceanBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class RunScheduledBackupTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.node = factories.make_website_node(self.account, self.member)

    def test_active_schedule_dispatches_backup_task_and_records_run(self):
        schedule = factories.make_schedule(self.node, self.member)
        with mock.patch.object(helper_tasks, "current_app") as capp:
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
