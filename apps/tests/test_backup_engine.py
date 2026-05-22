import os
import time
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase, override_settings

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.backup import website as W
from apps.console.backup.models import CoreDigitalOceanBackup
from apps.console.connection.models import CoreAuthWebsite
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class PollCloudBackupTests(BaseTestCase):
    """Orchestration of the async snapshot poller (provider status check mocked)."""

    def _backup(self, status=UtilBackup.Status.IN_PROGRESS):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean, status=status, celery_task_id="ct-1",
        )
        return node, backup

    def test_complete_finalizes_and_notifies(self):
        node, backup = self._backup()
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.COMPLETE), \
             mock.patch.object(CoreNode, "notify_backup_success") as notify:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        notify.assert_called_once()

    def test_failed_marks_failed_and_notifies(self):
        node, backup = self._backup()
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.FAILED), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.FAILED)
        notify.assert_called_once()

    def test_in_progress_requeues(self):
        node, backup = self._backup()
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.IN_PROGRESS), \
             mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as requeue:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
        requeue.assert_called_once()
        self.assertIn("countdown", requeue.call_args.kwargs)

    def test_timeout_marks_timeout(self):
        node, backup = self._backup()
        long_ago = time.time() - (86400 + 60)
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.IN_PROGRESS), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify:
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id, long_ago, 120, 86400])
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.TIMEOUT)
        notify.assert_called_once()

    def test_terminal_status_short_circuits(self):
        node, backup = self._backup(status=UtilBackup.Status.COMPLETE)
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status") as poll:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
        poll.assert_not_called()


class ProviderPollStatusResilienceTests(BaseTestCase):
    def test_poll_status_never_raises_on_api_error(self):
        # No auth_digitalocean is configured, so get_client() blows up inside poll_status;
        # the contract is to return IN_PROGRESS, never raise.
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean, status=UtilBackup.Status.IN_PROGRESS, action_id="A1",
        )
        self.assertEqual(backup.poll_status(), UtilBackup.Status.IN_PROGRESS)


class LftpScriptBuilderTests(TestCase):
    def _auth(self, proto, explicit=False, verify=True):
        return SimpleNamespace(protocol=proto, ftps_use_explicit_ssl=explicit, verify_ssl=verify)

    def test_password_in_script_not_argv_and_quoted(self):
        s = W._build_lftp_script(
            auth=self._auth(CoreAuthWebsite.Protocol.FTPS, explicit=True),
            host_url="ftp://h", port=21, username='u"x', password='pa"ss',
            ssh_key_path=None, parallel=2, transfer='get "f" -o "t"', mirror=False)
        self.assertIn('user "u\\"x" "pa\\"ss"', s)
        self.assertIn("set ftps:initial-prot P", s)

    def test_verify_ssl_flag_reflected(self):
        on = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.FTPS, verify=True),
                                  host_url="ftp://h", port=21, username="u", password="p",
                                  ssh_key_path=None, parallel=1, transfer="get a", mirror=False)
        off = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.FTPS, verify=False),
                                   host_url="ftp://h", port=21, username="u", password="p",
                                   ssh_key_path=None, parallel=1, transfer="get a", mirror=False)
        self.assertIn("set ssl:verify-certificate yes", on)
        self.assertIn("set ssl:verify-certificate no", off)

    def test_sftp_username_cannot_inject_via_connect_program(self):
        s = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.SFTP),
                                 host_url="sftp://h", port=22, username="u'; rm -rf /",
                                 password="p", ssh_key_path="_storage/ssh_x", parallel=4,
                                 transfer='mirror "." "t"', mirror=True)
        line = next(l for l in s.splitlines() if "connect-program" in l)
        # the dangerous chars are shell-quoted, so they are data, not commands/args
        self.assertNotIn("-l u'; rm -rf /", line)

    def test_plain_ftp_disables_tls(self):
        s = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.FTP),
                                 host_url="ftp://h", port=21, username="u", password="p",
                                 ssh_key_path=None, parallel=1, transfer="get a", mirror=False)
        self.assertIn("set ftp:ssl-allow false", s)


class CeleryRoutingTests(TestCase):
    def test_tasks_route_to_expected_queues(self):
        from backupsheep.celery import app

        def q(name):
            return app.amqp.router.route({}, name).get("queue").name

        self.assertEqual(q("backup_database"), "database")
        self.assertEqual(q("backup_website"), "files")
        self.assertEqual(q("backup_digitalocean"), "cloud")
        self.assertEqual(q("storage_upload"), "storage")
        self.assertEqual(q("finalize_backup"), "storage")
        self.assertEqual(q("delete_from_disk"), "storage")
        self.assertEqual(q("poll_cloud_backup"), "cloud")
        self.assertEqual(q("send_log_to_db"), "logs")

    def test_celery_imports_register_all_backup_tasks(self):
        # The worker imports settings.CELERY_IMPORTS at boot; importing them here must
        # register every backup engine + helper task (catches a module dropped from the
        # list, which would otherwise surface only as "unregistered task" at runtime).
        import importlib
        from django.conf import settings
        from backupsheep.celery import app

        for module in settings.CELERY_IMPORTS:
            importlib.import_module(module)
        for name in ["backup_website", "backup_database", "backup_digitalocean",
                     "backup_hetzner", "backup_aws", "storage_upload", "finalize_backup",
                     "delete_from_disk", "poll_cloud_backup", "delete_old_logs",
                     "run_scheduled_backup"]:
            self.assertIn(name, app.tasks)


class DiskCleanupTests(TestCase):
    def _storage(self, base):
        d = os.path.join(base, "_storage")
        os.makedirs(d)
        return d

    def test_delete_from_disk_removes_dir_and_zip_but_keeps_log(self):
        import tempfile
        base = tempfile.mkdtemp()
        st = self._storage(base)
        uid = "u1"
        os.makedirs(os.path.join(st, uid))
        open(os.path.join(st, f"{uid}.zip"), "w").close()
        open(os.path.join(st, f"{uid}.log"), "w").close()
        with override_settings(BASE_DIR=base):
            helper_tasks.delete_from_disk.apply(args=[uid, "both"])
        self.assertFalse(os.path.exists(os.path.join(st, uid)))
        self.assertFalse(os.path.exists(os.path.join(st, f"{uid}.zip")))
        self.assertTrue(os.path.exists(os.path.join(st, f"{uid}.log")))  # log retained

    def test_delete_from_disk_path_traversal_guard(self):
        import tempfile
        base = tempfile.mkdtemp()
        self._storage(base)
        os.makedirs(os.path.join(base, "secret"))
        with override_settings(BASE_DIR=base):
            helper_tasks.delete_from_disk.apply(args=["../secret", "dir"])
        self.assertTrue(os.path.exists(os.path.join(base, "secret")))  # not escaped

    def test_delete_old_logs_prunes_by_age(self):
        import tempfile
        base = tempfile.mkdtemp()
        st = self._storage(base)
        old, fresh = os.path.join(st, "old.log"), os.path.join(st, "fresh.log")
        open(old, "w").close()
        open(fresh, "w").close()
        forty_days = time.time() - 40 * 86400
        os.utime(old, (forty_days, forty_days))
        with override_settings(BASE_DIR=base):
            helper_tasks.delete_old_logs.apply(args=[30])
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh))
