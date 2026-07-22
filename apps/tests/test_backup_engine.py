import io
import json
import os
import shutil
import stat
import tempfile
import time
import uuid
import zipfile
from types import SimpleNamespace
from unittest import mock

from celery.exceptions import MaxRetriesExceededError, Retry
from django.conf import settings
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.exceptions import (
    IntegrationValidationError,
    NodeBackupFailedError,
    NodeConnectionErrorSFTP,
)
from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.backup import mariadb as MDB_ENGINE
from apps._tasks.integration.backup import mysql as MYSQL_ENGINE
from apps._tasks.integration.backup import postgresql as PG_ENGINE
from apps._tasks.integration.backup import website as W
from apps._tasks.integration.database import backup_database
from apps._tasks.integration.website import backup_website
from apps.api.v1.node.views import CoreNodeView
from apps.api.v1.utils.api_helpers import bs_encrypt, ensure_disk_space, zipdir
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDigitalOceanBackup,
    CoreWebsiteBackup,
)
from apps.console.connection.models import CoreAuthDatabase, CoreAuthWebsite, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode, CoreWebsite
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


def _cleanup_storage_artifacts(*paths):
    """addCleanup target: remove exactly the _storage artifacts a test caused to appear.

    The backup engine writes CWD-relative `_storage/...` paths, i.e. the repo's real
    _storage when tests run from the project root. Paths that already existed at
    registration time are left untouched so a test can never delete pre-existing data.
    """
    preexisting = {p for p in paths if os.path.exists(p)}

    def _cleanup():
        for p in paths:
            if p in preexisting:
                continue
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass

    return _cleanup


class WebsiteEngineBase(BaseTestCase):
    """Shared fixture for the merged website backup engine tests."""

    def _make_backup(self, *, incremental=False, backup_type=None,
                     use_private_key=False, use_public_key=False):
        """A real website node (FTP password auth, all_paths) + CoreWebsiteBackup row."""
        node = factories.make_website_node(self.account, self.member)
        auth = node.connection.auth_website
        auth.use_private_key = use_private_key
        auth.use_public_key = use_public_key
        auth.save()
        website = node.website
        website.backup_type = backup_type or CoreWebsite.BackupType.FULL
        website.incremental = incremental
        website.save()
        backup = CoreWebsiteBackup.objects.create(
            website=website, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.PENDING, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        # Prune the website_cache parent dir afterwards too, but only if this test run
        # created it and only once it is empty (never touches other nodes' caches).
        cache_parent = "_storage/website_cache"
        if not os.path.exists(cache_parent):
            def _prune_parent():
                try:
                    os.rmdir(cache_parent)
                except OSError:
                    pass
            self.addCleanup(_prune_parent)
        # Everything the engine may drop under _storage for this node/backup.
        self.addCleanup(_cleanup_storage_artifacts(
            f"_storage/{backup.uuid}.log",
            f"_storage/{backup.uuid}.zip",
            f"_storage/{backup.uuid}/",
            f"_storage/ssh_{backup.uuid}",
            f"_storage/website_cache/{node.uuid_str}/",
            f"_storage/website_cache/{node.uuid_str}.meta.json",
            f"_storage/website_cache/{node.uuid_str}.lock",
        ))
        return node, backup


class WebsiteSnapshotDispatchTests(WebsiteEngineBase):
    """snapshot_website routes between incremental-lftp, server-side tar and full-lftp."""

    def _run(self, backup):
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W, "_snapshot_lftp") as lftp, \
             mock.patch.object(W, "_snapshot_tar") as tar, \
             mock.patch.object(W, "_finalize_zip"), \
             mock.patch.object(W, "delete_from_disk"):
            W.snapshot_website(backup)
        return lftp, tar

    def test_incremental_routes_to_lftp_with_cache_dir(self):
        node, backup = self._make_backup(incremental=True)
        lftp, tar = self._run(backup)
        tar.assert_not_called()
        lftp.assert_called_once()
        self.assertIs(lftp.call_args.kwargs.get("incremental"), True)
        base_dir = lftp.call_args.kwargs.get("base_dir", "")
        self.assertIn("website_cache", base_dir)
        self.assertIn(node.uuid_str, base_dir)

    def test_full_v2_with_private_key_routes_to_tar(self):
        node, backup = self._make_backup(
            backup_type=CoreWebsite.BackupType.FULL_V2, use_private_key=True)
        lftp, tar = self._run(backup)
        lftp.assert_not_called()
        tar.assert_called_once()

    def test_default_routes_to_full_lftp(self):
        node, backup = self._make_backup()
        lftp, tar = self._run(backup)
        tar.assert_not_called()
        lftp.assert_called_once()
        self.assertIs(lftp.call_args.kwargs.get("incremental"), False)
        base_dir = lftp.call_args.kwargs.get("base_dir", "")
        self.assertIn(backup.uuid, base_dir)
        self.assertNotIn("website_cache", base_dir)

    def test_public_key_on_lftp_path_fails(self):
        # Managed public-key auth is SaaS-only; only the tar path may see key auth.
        node, backup = self._make_backup(use_public_key=True)
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run") as run, \
             mock.patch.object(W, "_finalize_zip"), \
             mock.patch.object(W, "delete_from_disk"):
            with self.assertRaises(NodeBackupFailedError):
                W.snapshot_website(backup)
        run.assert_not_called()


class WebsiteMirrorOptsTests(WebsiteEngineBase):
    """The lftp mirror line must switch between cache-incremental and full re-download."""

    def _capture_script(self, *, incremental):
        node, backup = self._make_backup(incremental=incremental)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        base_dir = os.path.join(tmp, "cache" if incremental else "full") + os.sep
        scripts = []

        def fake_run(cmd, **kwargs):
            if cmd == ["lftp"]:
                scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(W, "delete_from_disk"), \
             mock.patch.object(W, "_finalize_zip"):
            W._snapshot_lftp(backup, base_dir=base_dir, incremental=incremental)
        self.assertTrue(scripts, "expected _snapshot_lftp to invoke lftp")
        return scripts[0]

    def test_incremental_mirror_opts(self):
        s = self._capture_script(incremental=True)
        for opt in ("--continue", "--recursion=always", "--no-perms", "--no-umask",
                    "--delete", "--use-pget=1", "--parallel=3"):
            self.assertIn(opt, s)
        # incremental relies on lftp's size/mtime comparison, so no ignore flags
        self.assertNotIn("--ignore-time", s)
        self.assertNotIn("--ignore-size", s)

    def test_full_mirror_opts_unchanged(self):
        s = self._capture_script(incremental=False)
        self.assertIn("--ignore-time", s)
        self.assertIn("--ignore-size", s)
        self.assertNotIn("--delete", s)


class CacheFingerprintTests(TestCase):
    """_cache_fingerprint(website, auth, username) -> stable sha256 hex."""

    def _inputs(self):
        website = SimpleNamespace(
            all_paths=False,
            paths=[{"path": "public_html", "type": "directory"}],
            includes_regex=None, includes_glob=None,
            excludes_regex=None, excludes_glob=None,
        )
        # _cache_fingerprint reads host/port/get_protocol_display() off the auth object
        auth = SimpleNamespace(
            host="ftp.example.com", port=21,
            get_protocol_display=lambda: "FTP",
        )
        return website, auth, "site-user"

    def test_stable_for_same_inputs(self):
        website, auth, username = self._inputs()
        fp1 = W._cache_fingerprint(website, auth, username)
        fp2 = W._cache_fingerprint(website, auth, username)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)
        int(fp1, 16)  # valid hex

    def test_changes_when_paths_change(self):
        website, auth, username = self._inputs()
        fp1 = W._cache_fingerprint(website, auth, username)
        website.paths = [{"path": "other_dir", "type": "directory"}]
        self.assertNotEqual(fp1, W._cache_fingerprint(website, auth, username))

    def test_changes_when_host_changes(self):
        website, auth, username = self._inputs()
        fp1 = W._cache_fingerprint(website, auth, username)
        auth.host = "ftp.other-host.com"
        self.assertNotEqual(fp1, W._cache_fingerprint(website, auth, username))


class ResetIncrementalCacheTests(BaseTestCase):
    """POST reset_incremental wipes the node's local snapshot cache + meta file."""

    def test_reset_incremental_deletes_local_cache(self):
        node = factories.make_website_node(self.account, self.member)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        cache_dir = os.path.join(tmp, "_storage", "website_cache", node.uuid_str)
        os.makedirs(cache_dir)
        with open(os.path.join(cache_dir, "index.html"), "w") as fh:
            fh.write("<html></html>")
        meta_path = os.path.join(
            tmp, "_storage", "website_cache", f"{node.uuid_str}.meta.json")
        with open(meta_path, "w") as fh:
            json.dump({"fingerprint": "x"}, fh)

        request = APIRequestFactory().post(f"/api/v1/nodes/{node.id}/reset_incremental/")
        force_authenticate(request, user=self.user)
        view = CoreNodeView.as_view({"post": "reset_incremental"})
        with override_settings(BASE_DIR=tmp):
            resp = view(request, pk=node.id)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(os.path.exists(cache_dir))
        self.assertFalse(os.path.exists(meta_path))


class NormalizeSshKeyTests(TestCase):
    """_normalize_ssh_key: paramiko rewrites the key unencrypted when it can; for keys
    paramiko parses but cannot serialize (Ed25519 in paramiko 5.0.0) it must fall back
    to the system ssh-keygen -- and only when a passphrase was supplied."""

    def _key_file(self, contents="-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n"):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(contents)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def _paramiko_write_broken(self):
        """Patch the three key classes the way paramiko 5.0.0 behaves with an ed25519
        key: Ed25519 parses but write_private_key_file blows up; RSA/ECDSA can't parse."""
        parsed = mock.Mock()
        parsed.write_private_key_file.side_effect = AttributeError(
            "'Ed25519Key' object has no attribute 'private_key'")
        ed = mock.Mock()
        ed.from_private_key_file.return_value = parsed
        rsa = mock.Mock()
        rsa.from_private_key_file.side_effect = W.paramiko.SSHException("not an RSA key")
        ec = mock.Mock()
        ec.from_private_key_file.side_effect = W.paramiko.SSHException("not an ECDSA key")
        return (mock.patch("paramiko.Ed25519Key", ed),
                mock.patch("paramiko.RSAKey", rsa),
                mock.patch("paramiko.ECDSAKey", ec))

    def test_paramiko_write_failure_falls_back_to_ssh_keygen(self):
        path = self._key_file()
        ed, rsa, ec = self._paramiko_write_broken()
        with ed, rsa, ec, mock.patch.object(W.subprocess, "run") as run:
            run.return_value = SimpleNamespace(returncode=0, stdout="")
            W._normalize_ssh_key(path, "s3cret-passphrase")
        run.assert_called_once()
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["ssh-keygen", "-p", "-P", "s3cret-passphrase",
                                "-N", "", "-f", path])

    def test_paramiko_rewrite_success_runs_no_subprocess(self):
        # Real RSA key encrypted with a passphrase: paramiko rewrites it, no fallback.
        rsa_key = W.paramiko.RSAKey.generate(2048)
        path = self._key_file("")
        rsa_key.write_private_key_file(path, password="key-pass")
        with mock.patch.object(W.subprocess, "run") as run:
            W._normalize_ssh_key(path, "key-pass")
        run.assert_not_called()
        # The rewritten key now loads without a passphrase.
        W.paramiko.RSAKey.from_private_key_file(path)

    def test_no_passphrase_means_no_fallback(self):
        path = self._key_file()
        ed, rsa, ec = self._paramiko_write_broken()
        with ed, rsa, ec, mock.patch.object(W.subprocess, "run") as run:
            W._normalize_ssh_key(path, "")
        run.assert_not_called()


class GetSftpClientKeyTests(BaseTestCase):
    """get_sftp_client must load Ed25519/ECDSA user keys too (not only RSA) and must
    never leave the decrypted-key temp file behind when connecting fails."""

    def _auth(self):
        node = factories.make_website_node(
            self.account, self.member, host="sftp.example.com",
            protocol=CoreAuthWebsite.Protocol.SFTP)
        auth = node.connection.auth_website
        key = self.account.get_encryption_key()
        auth.port = 22
        auth.use_private_key = True
        auth.private_key = bs_encrypt("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n", key)
        auth.password = bs_encrypt("key-pass", key)  # the key's passphrase
        auth.save()
        return auth

    def _storage_listing(self):
        return set(os.listdir(os.path.join(settings.BASE_DIR, "_storage")))

    def test_ed25519_key_connects_when_rsa_cannot_parse(self):
        auth = self._auth()
        pkey = mock.Mock(name="pkey")
        ed = mock.Mock()
        ed.from_private_key_file.return_value = pkey
        rsa = mock.Mock()
        rsa.from_private_key_file.side_effect = W.paramiko.SSHException("not an RSA key")
        ec = mock.Mock()
        ec.from_private_key_file.side_effect = W.paramiko.SSHException("not an ECDSA key")
        ssh_client = mock.Mock(name="ssh")
        sftp = mock.Mock(name="sftp")
        ssh_client.open_sftp.return_value = sftp
        with mock.patch("paramiko.Ed25519Key", ed), \
             mock.patch("paramiko.RSAKey", rsa), \
             mock.patch("paramiko.ECDSAKey", ec), \
             mock.patch("paramiko.SSHClient", return_value=ssh_client):
            got_sftp, got_ssh, key_path = auth.get_sftp_client()
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        self.assertIs(got_sftp, sftp)
        self.assertIs(got_ssh, ssh_client)
        # Happy-path contract unchanged: the caller owns the temp key file.
        self.assertTrue(os.path.exists(key_path))
        ed.from_private_key_file.assert_called_once_with(key_path, password="key-pass")
        rsa.from_private_key_file.assert_not_called()
        ssh_client.connect.assert_called_once()
        self.assertIs(ssh_client.connect.call_args.kwargs.get("pkey"), pkey)

    def test_connect_failure_removes_temp_key(self):
        auth = self._auth()
        ed = mock.Mock()
        ed.from_private_key_file.return_value = mock.Mock(name="pkey")
        ssh_client = mock.Mock(name="ssh")
        ssh_client.connect.side_effect = Exception("boom")
        before = self._storage_listing()
        with mock.patch("paramiko.Ed25519Key", ed), \
             mock.patch("paramiko.SSHClient", return_value=ssh_client):
            with self.assertRaises(Exception) as ctx:
                auth.get_sftp_client()
        self.assertIn("boom", str(ctx.exception))
        self.assertEqual(self._storage_listing(), before)

    def test_unparseable_key_raises_and_removes_temp_key(self):
        auth = self._auth()
        ssh_client = mock.Mock(name="ssh")
        before = self._storage_listing()
        with mock.patch("paramiko.SSHClient", return_value=ssh_client):
            # Real key classes, garbage key contents -> nothing parses.
            with self.assertRaises(NodeConnectionErrorSFTP):
                auth.get_sftp_client()
        ssh_client.connect.assert_not_called()
        self.assertEqual(self._storage_listing(), before)


# ---------------------------------------------------------------------------
# Database backup engine tests (mysql.py / mariadb.py / postgresql.py rewrites)
# ---------------------------------------------------------------------------

DB_USER = "dbuser"
DB_PASS = "p@ssw0rdSecret"


def make_database_node(account, member, *, db_type, version, database_name="appdb",
                       host="db.example.com", port=3306, username=DB_USER,
                       password=DB_PASS, all_tables=True, tables=None,
                       databases=None, all_databases=False, use_private_key=False):
    """Database counterpart of factories.make_website_node: CoreConnection (code
    "database") + CoreAuthDatabase (bs_encrypt'ed credentials) + DATABASE node +
    CoreDatabase row. Credentials are encrypted with the account key so the engines'
    bs_decrypt calls succeed."""
    conn = factories.make_connection(account, member, code="database")
    key = account.get_encryption_key()
    CoreAuthDatabase.objects.create(
        connection=conn,
        host=host, port=port,
        database_name=database_name,
        username=bs_encrypt(username, key),
        password=bs_encrypt(password, key),
        type=db_type, version=version,
        include_stored_procedure=False,
        use_ssl=False,
        use_public_key=False,
        use_private_key=use_private_key,
    )
    if use_private_key:
        auth = conn.auth_database
        auth.ssh_host = host
        auth.ssh_port = 22
        auth.ssh_username = bs_encrypt("sshuser", key)
        auth.ssh_password = bs_encrypt("sshpw", key)
        auth.private_key = bs_encrypt(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n", key)
        auth.save()
    node = CoreNode.objects.create(connection=conn, type=CoreNode.Type.DATABASE,
                                   name="db", added_by=member)
    CoreDatabase.objects.create(
        node=node, name="db",
        all_tables=all_tables, tables=tables,
        databases=databases, all_databases=all_databases,
    )
    return node


def _recorded_run(calls, *, dump=b"", stderr=b"", returncode=0):
    """subprocess.run fake: records argv/kwargs, streams `dump` into the stdout file
    object, and stats the --defaults-extra-file while it still exists."""

    def fake_run(argv, **kwargs):
        call = {"argv": list(argv), "kwargs": kwargs}
        calls.append(call)
        defaults = next((a.split("=", 1)[1] for a in argv
                         if a.startswith("--defaults-extra-file=")), None)
        if defaults:
            call["defaults_mode"] = stat.S_IMODE(os.stat(defaults).st_mode)
        out = kwargs.get("stdout")
        if out is not None and dump:
            out.write(dump)
        return SimpleNamespace(returncode=returncode, stderr=stderr)

    return fake_run


class _FakeChannelStream:
    """Stand-in for a paramiko channel file: read/readlines plus
    .channel.recv_exit_status(). The engine calls _set_mode('rb') on stdout."""

    def __init__(self, data=b"", exit_status=0):
        self._buf = io.BytesIO(data)
        self.channel = SimpleNamespace(recv_exit_status=lambda: exit_status)

    def _set_mode(self, mode):
        pass

    def read(self, n=-1):
        return self._buf.read(n)

    def readlines(self):
        return self._buf.readlines()


class _FakeSFTP:
    """Records open()/write()/chmod() of the remote credentials file."""

    def __init__(self):
        self.files = {}
        self.chmods = []
        self.closed = False

    def open(self, name, mode):
        sftp = self

        class _FH:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def write(self, data):
                sftp.files[name] = sftp.files.get(name, "") + data

        return _FH()

    def chmod(self, name, mode):
        self.chmods.append((name, mode))

    def close(self):
        self.closed = True


class _FakeSSH:
    """paramiko.SSHClient stand-in. handler(command) -> (stdout, stderr, exit_status)."""

    def __init__(self, handler):
        self.handler = handler
        self.commands = []
        self.sftp = _FakeSFTP()
        self.closed = False

    def exec_command(self, command):
        self.commands.append(command)
        out, err, exit_status = self.handler(command)
        return (
            _FakeChannelStream(),
            _FakeChannelStream(out, exit_status),
            _FakeChannelStream(err),
        )

    def open_sftp(self):
        return self.sftp

    def close(self):
        self.closed = True


class DatabaseEngineBase(BaseTestCase):
    """Shared fixture: a database node + CoreDatabaseBackup row, with _storage
    artifact cleanup registered for everything the engines may drop."""

    def _make_backup(self, **kwargs):
        node = make_database_node(self.account, self.member, **kwargs)
        backup = CoreDatabaseBackup.objects.create(
            database=node.database, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.PENDING, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        self.addCleanup(_cleanup_storage_artifacts(
            f"_storage/{backup.uuid}.log",
            f"_storage/{backup.uuid}.zip",
            f"_storage/{backup.uuid}/",
            f"_storage/my_{backup.uuid}.cnf",
        ))
        return node, backup

    def _key_file(self):
        """A real temp key file under _storage, returned to the engine as the
        ssh_key_path half of get_ssh_client()."""
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        return key_path

    @staticmethod
    def _patch_check_connection():
        return mock.patch.object(
            CoreAuthDatabase, "check_connection", lambda *a, **k: None)

    def _read_log(self, backup):
        with open(f"_storage/{backup.uuid}.log") as fh:
            return fh.read()


class DatabaseSnapshotDispatchTests(BaseTestCase):
    """CoreDatabase.create_snapshot dispatches on auth_database.type."""

    def _run(self, db_type, version):
        node = make_database_node(self.account, self.member,
                                  db_type=db_type, version=version)
        backup = CoreDatabaseBackup.objects.create(
            database=node.database, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.PENDING, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        with mock.patch("apps._tasks.integration.backup.mysql.snapshot_mysql") as m_mysql, \
             mock.patch("apps._tasks.integration.backup.mariadb.snapshot_mariadb") as m_maria, \
             mock.patch("apps._tasks.integration.backup.postgresql.snapshot_postgresql") as m_pg, \
             mock.patch("apps._tasks.integration.storage.tasks.finalize_backup"):
            node.database.create_snapshot(backup)
        return m_mysql, m_maria, m_pg, backup

    def test_mysql_type_dispatches_to_snapshot_mysql(self):
        m_mysql, m_maria, m_pg, backup = self._run(
            CoreAuthDatabase.DatabaseType.MYSQL, "mysql_8_0")
        m_mysql.assert_called_once()
        self.assertIs(m_mysql.call_args.args[0], backup)
        m_maria.assert_not_called()
        m_pg.assert_not_called()

    def test_mariadb_type_dispatches_to_snapshot_mariadb(self):
        m_mysql, m_maria, m_pg, backup = self._run(
            CoreAuthDatabase.DatabaseType.MARIADB, "mariadb_10_11")
        m_maria.assert_called_once()
        self.assertIs(m_maria.call_args.args[0], backup)
        m_mysql.assert_not_called()
        m_pg.assert_not_called()

    def test_postgresql_type_dispatches_to_snapshot_postgresql(self):
        m_mysql, m_maria, m_pg, backup = self._run(
            CoreAuthDatabase.DatabaseType.POSTGRESQL, "postgres_16")
        m_pg.assert_called_once()
        self.assertIs(m_pg.call_args.args[0], backup)
        m_mysql.assert_not_called()
        m_maria.assert_not_called()

    def test_unsupported_type_raises(self):
        node = make_database_node(self.account, self.member,
                                  db_type=99, version="mysql_8_0")
        backup = CoreDatabaseBackup.objects.create(
            database=node.database, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.PENDING, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        with mock.patch("apps._tasks.integration.backup.mysql.snapshot_mysql") as m_mysql, \
             mock.patch("apps._tasks.integration.backup.mariadb.snapshot_mariadb") as m_maria, \
             mock.patch("apps._tasks.integration.backup.postgresql.snapshot_postgresql") as m_pg:
            with self.assertRaises(NodeBackupFailedError):
                node.database.create_snapshot(backup)
        m_mysql.assert_not_called()
        m_maria.assert_not_called()
        m_pg.assert_not_called()


class MysqlDirectEngineTests(DatabaseEngineBase):
    """snapshot_mysql in DIRECT mode: argv list, temp defaults file, exit-code checks."""

    DUMP = b"-- dump\nINSERT INTO t VALUES (1);\n"

    def _run_engine(self, backup, fake_run):
        with self._patch_check_connection(), \
             mock.patch.object(MYSQL_ENGINE.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"):
            MYSQL_ENGINE.snapshot_mysql(backup)

    def test_direct_success(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        self._run_engine(backup, _recorded_run(calls, dump=self.DUMP))

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

        # Zip exists and contains the dumped database bytes.
        zip_path = f"_storage/{backup.uuid}.zip"
        self.assertTrue(os.path.exists(zip_path))
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("appdb.sql", zf.namelist())
            self.assertEqual(zf.read("appdb.sql"), self.DUMP)

        # Exactly one subprocess, argv list with the defaults file first, mode 0600.
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]["argv"], calls[0]["kwargs"]
        self.assertTrue(argv[0].endswith("mysqldump"))
        self.assertEqual(argv[1], f"--defaults-extra-file=_storage/my_{backup.uuid}.cnf")
        self.assertIn("--column-statistics=0", argv)  # mysql_8
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertNotIn(DB_USER, " ".join(argv))
        self.assertFalse(kwargs.get("shell"))
        self.assertNotIn("env", kwargs)
        self.assertEqual(kwargs.get("timeout"), 12 * 3600)
        self.assertEqual(calls[0]["defaults_mode"], 0o600)

        # The credentials file is deleted afterwards.
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))

    def test_direct_failure_raises_and_cleans_up(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        with self.assertRaises(NodeBackupFailedError):
            self._run_engine(backup, _recorded_run(
                calls, dump=b"partial", stderr=b"mysqldump: boom", returncode=1))
        self.assertEqual(len(calls), 1)
        self.assertFalse(os.path.exists(f"_storage/{backup.uuid}.zip"))
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))

    def test_stderr_on_success_is_warning_not_fatal(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        self._run_engine(backup, _recorded_run(
            calls, dump=self.DUMP, stderr=b"mysqldump: [Warning] something odd"))
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)
        self.assertIn("WARNING:", self._read_log(backup))

    def test_empty_dump_is_a_failure(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        with self.assertRaises(NodeBackupFailedError):
            self._run_engine(backup, _recorded_run(calls, dump=b""))
        self.assertFalse(os.path.exists(f"_storage/{backup.uuid}.zip"))
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))

    def test_undecryptable_credentials_fail_before_subprocess(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(MYSQL_ENGINE, "bs_decrypt", return_value=None), \
             mock.patch.object(MYSQL_ENGINE.subprocess, "run", side_effect=_recorded_run(calls)), \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"):
            with self.assertRaises(NodeBackupFailedError):
                MYSQL_ENGINE.snapshot_mysql(backup)
        self.assertEqual(calls, [])

    def test_failure_message_and_log_redact_password(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        stderr = (b"mysqldump: Got error: 1045: Access denied for user "
                  b"(using password: " + DB_PASS.encode() + b")")
        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run_engine(backup, _recorded_run(
                calls, dump=b"x", stderr=stderr, returncode=1))
        self.assertNotIn(DB_PASS, str(ctx.exception))
        self.assertNotIn(DB_PASS, self._read_log(backup))


class MariadbDirectEngineTests(DatabaseEngineBase):
    """snapshot_mariadb direct mode: mariadb-appropriate flags."""

    def test_direct_success_flags(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB, version="mariadb_10_11")
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(MDB_ENGINE.subprocess, "run",
                               side_effect=_recorded_run(calls, dump=b"-- dump\n")), \
             mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)
        self.assertEqual(len(calls), 1)
        argv = calls[0]["argv"]
        self.assertTrue(argv[0].endswith("mysqldump"))
        self.assertEqual(argv[1], f"--defaults-extra-file=_storage/my_{backup.uuid}.cnf")
        self.assertIn("--compress", argv)
        self.assertFalse(any("column-statistics" in a for a in argv))
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))


class PostgresDirectEngineTests(DatabaseEngineBase):
    """snapshot_postgresql direct mode: PGPASSWORD in env, never on argv."""

    def test_direct_success_uses_pgpassword_env(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16", port=5432)
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(PG_ENGINE.subprocess, "run",
                               side_effect=_recorded_run(calls, dump=b"-- pg dump\n")), \
             mock.patch.object(PG_ENGINE, "delete_from_disk"):
            PG_ENGINE.snapshot_postgresql(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]["argv"], calls[0]["kwargs"]
        self.assertTrue(argv[0].endswith("pg_dump"))
        self.assertIn("-w", argv)
        self.assertIn("--clean", argv)
        self.assertIn("appdb", argv)
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertEqual(kwargs["env"]["PGPASSWORD"], DB_PASS)
        self.assertFalse(kwargs.get("shell"))

        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as zf:
            self.assertEqual(zf.read("appdb.sql"), b"-- pg dump\n")

    def test_undecryptable_credentials_fail_before_subprocess(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16", port=5432)
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(PG_ENGINE, "bs_decrypt", return_value=None), \
             mock.patch.object(PG_ENGINE.subprocess, "run", side_effect=_recorded_run(calls)), \
             mock.patch.object(PG_ENGINE, "delete_from_disk"):
            with self.assertRaises(NodeBackupFailedError):
                PG_ENGINE.snapshot_postgresql(backup)
        self.assertEqual(calls, [])


class MysqlSshEngineTests(DatabaseEngineBase):
    """snapshot_mysql over SSH: remote defaults file, exit-status checks, cleanup."""

    DUMP = b"-- dump\nINSERT INTO t VALUES (1);\n"

    def _ssh_backup(self):
        return self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0",
            use_private_key=True)

    def test_ssh_success_contract(self):
        node, backup = self._ssh_backup()
        ssh = _FakeSSH(lambda command: (self.DUMP, b"", 0))
        key_path = self._key_file()
        with self._patch_check_connection(), \
             mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, key_path)), \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"):
            MYSQL_ENGINE.snapshot_mysql(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

        remote_name = f"bs_{backup.uuid_str}.cnf"
        dump_cmds = [c for c in ssh.commands if c.startswith("mysqldump ")]
        self.assertEqual(len(dump_cmds), 1)
        self.assertIn(f"--defaults-extra-file={remote_name}", dump_cmds[0])
        self.assertIn("--column-statistics=0", dump_cmds[0])  # mysql_8 over SSH too
        self.assertNotIn(DB_PASS, dump_cmds[0])

        # Credentials file SFTP-uploaded with 0600, then removed best-effort.
        self.assertIn(remote_name, ssh.sftp.files)
        self.assertIn(f'password="{DB_PASS}"', ssh.sftp.files[remote_name])
        self.assertEqual(ssh.sftp.chmods, [(remote_name, 0o600)])
        self.assertIn(f"rm -f {remote_name}", ssh.commands)
        self.assertTrue(ssh.closed)

        # Local temp key removed by the engine.
        self.assertFalse(os.path.exists(key_path))

        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as zf:
            self.assertEqual(zf.read("appdb.sql"), self.DUMP)

    def test_ssh_nonzero_exit_raises_and_cleans_up(self):
        node, backup = self._ssh_backup()
        ssh = _FakeSSH(lambda command: (b"", b"mysqldump: access denied", 2))
        key_path = self._key_file()
        with self._patch_check_connection(), \
             mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, key_path)), \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"):
            with self.assertRaises(NodeBackupFailedError):
                MYSQL_ENGINE.snapshot_mysql(backup)

        self.assertFalse(os.path.exists(f"_storage/{backup.uuid}.zip"))
        self.assertIn(f"rm -f bs_{backup.uuid_str}.cnf", ssh.commands)
        self.assertTrue(ssh.closed)
        self.assertFalse(os.path.exists(key_path))


class PostgresSshEngineTests(DatabaseEngineBase):
    """snapshot_postgresql over SSH: all-databases enumeration filters templates."""

    def test_ssh_all_databases_filters_templates(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16", port=5432,
            all_tables=False, all_databases=True, use_private_key=True)

        def handler(command):
            if "-lqt" in command:
                return b"db_one\ntemplate0\ntemplate1\n   \n", b"", 0
            if "pg_dump" in command:
                return b"-- dump of db_one\n", b"", 0
            return b"", b"", 0  # rm -f

        ssh = _FakeSSH(handler)
        with self._patch_check_connection(), \
             mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, None)), \
             mock.patch.object(PG_ENGINE, "delete_from_disk"):
            PG_ENGINE.snapshot_postgresql(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

        remote_name = f"bs_{backup.uuid_str}.pgpass"
        work_cmds = [c for c in ssh.commands if not c.startswith("rm -f")]
        self.assertTrue(all(c.startswith(f"PGPASSFILE=~/{remote_name}")
                            for c in work_cmds))
        self.assertNotIn(DB_PASS, " ".join(work_cmds))

        dump_cmds = [c for c in work_cmds if " pg_dump " in c]
        self.assertEqual(len(dump_cmds), 1)
        self.assertIn("-d db_one", dump_cmds[0])
        self.assertNotIn("template0", " ".join(dump_cmds))
        self.assertNotIn("template1", " ".join(dump_cmds))

        # pgpass uploaded with 0600 and removed afterwards.
        self.assertEqual(ssh.sftp.chmods, [(remote_name, 0o600)])
        self.assertIn(f"db.example.com:5432:*:{DB_USER}:{DB_PASS}",
                      ssh.sftp.files[remote_name])
        self.assertIn(f"rm -f ~/{remote_name}", ssh.commands)
        self.assertTrue(ssh.closed)

        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as zf:
            self.assertEqual(zf.read("db_one.sql"), b"-- dump of db_one\n")


class ZipdirErrorPropagationTests(TestCase):
    """zipdir must propagate per-file errors instead of swallowing them."""

    def test_zipdir_raises_on_broken_symlink(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "ok.sql"), "w") as fh:
            fh.write("x")
        os.symlink(os.path.join(tmp, "missing-target"),
                   os.path.join(tmp, "broken.sql"))
        with zipfile.ZipFile(os.path.join(tmp, "out.zip"), "w") as zf:
            with self.assertRaises(OSError):
                zipdir(tmp + os.sep, zf)

    def test_zipdir_happy_path_still_works(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "a.sql"), "w") as fh:
            fh.write("select 1;")
        zip_path = os.path.join(tmp, "out.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zipdir(tmp + os.sep, zf)
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("a.sql", zf.namelist())


class AuthDatabaseGetSshClientTests(BaseTestCase):
    """CoreAuthDatabase.get_ssh_client tries Ed25519/RSA/ECDSA and never leaves the
    decrypted private key on disk when connecting fails."""

    def _auth(self):
        node = make_database_node(
            self.account, self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0",
            use_private_key=True)
        return node.connection.auth_database

    def _storage_listing(self):
        return set(os.listdir(os.path.join(settings.BASE_DIR, "_storage")))

    def test_falls_back_to_rsa_when_ed25519_cannot_parse(self):
        auth = self._auth()
        pkey = mock.Mock(name="pkey")
        ed = mock.Mock()
        ed.from_private_key_file.side_effect = Exception("not an Ed25519 key")
        rsa = mock.Mock()
        rsa.from_private_key_file.return_value = pkey
        ec = mock.Mock()
        ssh_client = mock.Mock(name="ssh")
        ssh_client.open_sftp.return_value = mock.Mock(name="sftp")
        with mock.patch("paramiko.Ed25519Key", ed), \
             mock.patch("paramiko.RSAKey", rsa), \
             mock.patch("paramiko.ECDSAKey", ec), \
             mock.patch("paramiko.SSHClient", return_value=ssh_client):
            ssh, key_path = auth.get_ssh_client()
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        self.assertIs(ssh, ssh_client)
        self.assertTrue(os.path.exists(key_path))
        rsa.from_private_key_file.assert_called_once_with(key_path, password="sshpw")
        ec.from_private_key_file.assert_not_called()
        ssh_client.connect.assert_called_once()
        self.assertIs(ssh_client.connect.call_args.kwargs.get("pkey"), pkey)

    def test_connect_failure_removes_temp_key(self):
        auth = self._auth()
        ed = mock.Mock()
        ed.from_private_key_file.return_value = mock.Mock(name="pkey")
        ssh_client = mock.Mock(name="ssh")
        ssh_client.connect.side_effect = Exception("boom")
        before = self._storage_listing()
        with mock.patch("paramiko.Ed25519Key", ed), \
             mock.patch("paramiko.SSHClient", return_value=ssh_client):
            with self.assertRaises(Exception) as ctx:
                auth.get_ssh_client()
        self.assertIn("boom", str(ctx.exception))
        self.assertEqual(self._storage_listing(), before)


class AuthDatabaseCheckConnectionSshTests(BaseTestCase):
    """check_connection's SSH body closes the client and removes the temp key
    (try/finally), even on the success path."""

    def test_ssh_check_connection_cleans_up_key(self):
        node = make_database_node(
            self.account, self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0",
            use_private_key=True)
        auth = node.connection.auth_database
        ssh = _FakeSSH(lambda command: (b"mysql  Ver 8.0\nServer version: 8.0.35\n",
                                        b"", 0))
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        with mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, key_path)):
            auth.check_connection()
        self.assertTrue(ssh.closed)
        self.assertFalse(os.path.exists(key_path))


class BackupTaskValidationOrderTests(BaseTestCase):
    """backup_initiate runs before connection validation: a validation failure
    leaves a backup row that walks IN_PROGRESS -> RETRYING -> MAX_RETRY_FAILED.
    (Previously validate ran first, so no row existed and the 4 silent retries
    left backup_retrying_reset/backup_max_retries_reached with nothing to mark.)
    """

    def _website_node(self):
        return factories.make_website_node(self.account, self.member)

    def _database_node(self):
        return make_database_node(
            self.account, self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")

    def test_website_validation_failure_creates_row_and_marks_retrying(self):
        node = self._website_node()
        with mock.patch.object(CoreConnection, "validate", return_value=False), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_website, "retry",
                               side_effect=Retry("retrying")) as retry:
            backup_website.apply(kwargs={"node_id": node.id, "storage_ids": []}, throw=False)
        backup = CoreWebsiteBackup.objects.get(website=node.website)
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        self.assertEqual(backup.type, UtilBackup.Type.ON_DEMAND)
        self.assertEqual(backup.attempt_no, 1)
        notify.assert_called_once()
        retry.assert_called_once()

    def test_website_validation_failure_max_retries_marks_row(self):
        node = self._website_node()
        with mock.patch.object(CoreConnection, "validate", return_value=False), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_website, "retry",
                               side_effect=MaxRetriesExceededError("maxed")):
            backup_website.apply(kwargs={"node_id": node.id, "storage_ids": []}, throw=False)
        backup = CoreWebsiteBackup.objects.get(website=node.website)
        self.assertEqual(backup.status, UtilBackup.Status.MAX_RETRY_FAILED)
        notify.assert_called_once()

    def test_database_validation_failure_creates_row_and_marks_retrying(self):
        node = self._database_node()
        with mock.patch.object(CoreConnection, "validate",
                               side_effect=IntegrationValidationError("nope")), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_database, "retry",
                               side_effect=Retry("retrying")) as retry:
            backup_database.apply(kwargs={"node_id": node.id, "storage_ids": []}, throw=False)
        backup = CoreDatabaseBackup.objects.get(database=node.database)
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        self.assertEqual(backup.type, UtilBackup.Type.ON_DEMAND)
        self.assertEqual(backup.attempt_no, 1)
        notify.assert_called_once()
        retry.assert_called_once()

    def test_database_validation_failure_max_retries_marks_row(self):
        node = self._database_node()
        with mock.patch.object(CoreConnection, "validate",
                               side_effect=IntegrationValidationError("nope")), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_database, "retry",
                               side_effect=MaxRetriesExceededError("maxed")):
            backup_database.apply(kwargs={"node_id": node.id, "storage_ids": []}, throw=False)
        backup = CoreDatabaseBackup.objects.get(database=node.database)
        self.assertEqual(backup.status, UtilBackup.Status.MAX_RETRY_FAILED)
        notify.assert_called_once()


# ---------------------------------------------------------------------------
# Hardening: lftp failure detection, disk-space preflight, manifest location
# ---------------------------------------------------------------------------


class LftpFailureDetectionTests(WebsiteEngineBase):
    """_snapshot_lftp must fail loudly when lftp reports failed transfers.

    Mechanism (verified empirically against lftp 4.9.2 in the worker image):
    a mirror/get with failed transfers exits non-zero -- even with the trailing
    `bye` -- and clean transfers (including empty dirs and no-op incremental
    re-mirrors) exit 0. The engine therefore checks proc.returncode.
    """

    def _run(self, backup, *, incremental, fake_run):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        base_dir = os.path.join(tmp, "cache" if incremental else "full") + os.sep
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(W, "delete_from_disk"), \
             mock.patch.object(W, "_finalize_zip") as finalize:
            W._snapshot_lftp(backup, base_dir=base_dir, incremental=incremental)
        return finalize

    @staticmethod
    def _failed_run(cmd, **kwargs):
        return SimpleNamespace(
            stdout="mirror: Access failed: Permission denied (secret.txt)\n",
            returncode=1,
        )

    def test_full_mirror_failed_transfer_raises_naming_files(self):
        node, backup = self._make_backup(incremental=False)
        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, incremental=False, fake_run=self._failed_run)
        # The error names the failed file so the user can fix perms or exclude it.
        self.assertIn("secret.txt", str(ctx.exception))
        self.assertIn("exit code 1", str(ctx.exception))

    def test_incremental_mirror_failed_transfer_raises(self):
        node, backup = self._make_backup(incremental=True)
        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, incremental=True, fake_run=self._failed_run)
        self.assertIn("secret.txt", str(ctx.exception))

    def test_failed_transfer_never_reaches_finalize(self):
        node, backup = self._make_backup(incremental=False)
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run", side_effect=self._failed_run), \
             mock.patch.object(W, "delete_from_disk") as cleanup, \
             mock.patch.object(W, "_finalize_zip") as finalize:
            tmp = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, tmp, True)
            with self.assertRaises(NodeBackupFailedError):
                W._snapshot_lftp(backup, base_dir=tmp + os.sep, incremental=False)
        finalize.assert_not_called()
        # The failure path schedules the (harmless) artifact cleanup.
        cleanup.apply_async.assert_called_once_with(args=[backup.uuid_str, "both"])

    def test_clean_mirror_exit_zero_succeeds(self):
        node, backup = self._make_backup(incremental=False)
        finalize = self._run(
            backup, incremental=False,
            fake_run=lambda cmd, **kwargs: SimpleNamespace(stdout="", returncode=0),
        )
        finalize.assert_called_once()

    def test_clean_incremental_mirror_exit_zero_succeeds(self):
        node, backup = self._make_backup(incremental=True)
        finalize = self._run(
            backup, incremental=True,
            fake_run=lambda cmd, **kwargs: SimpleNamespace(stdout="", returncode=0),
        )
        finalize.assert_called_once()

    def test_login_failure_still_raises_from_output_grep(self):
        node, backup = self._make_backup(incremental=False)

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(
                stdout="mirror: Login failed: Login incorrect\n", returncode=1)

        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, incremental=False, fake_run=fake_run)
        self.assertIn("Login failed", str(ctx.exception))

    def test_failure_output_tail_is_redacted(self):
        node, backup = self._make_backup(incremental=False)

        def fake_run(cmd, **kwargs):
            # lftp echoes credentials-free output, but the tail redaction must
            # still strip the username/password if they appear.
            return SimpleNamespace(
                stdout="mirror: Access failed: Permission denied (u/p/secret.txt)\n",
                returncode=1,
            )

        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run(backup, incremental=False, fake_run=fake_run)
        # factory credentials are u/p -- they must never land in the message.
        self.assertNotIn("(u/p/", str(ctx.exception))
        self.assertIn("secret.txt", str(ctx.exception))

    def test_file_source_get_uses_boolean_pget_flag(self):
        # lftp 4.9.2: `-P` is boolean for get/put; `-P 3` makes lftp fetch an
        # extra file literally named "3" and exit 1 (verified). The engine must
        # emit the bare flag or every file-source backup would now fail.
        node, backup = self._make_backup(incremental=False)
        website = node.website
        website.all_paths = False
        website.paths = [{"path": "index.html", "type": "file"}]
        website.save()
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(W, "delete_from_disk"), \
             mock.patch.object(W, "_finalize_zip"):
            W._snapshot_lftp(backup, base_dir=tmp + os.sep, incremental=False)
        self.assertEqual(len(scripts), 1)
        self.assertIn('get -P "index.html"', scripts[0])
        self.assertNotIn("-P 3", scripts[0])


class EnsureDiskSpaceHelperTests(TestCase):
    """ensure_disk_space: RuntimeError with need/have GB (2dp) when short."""

    def _usage(self, free):
        return SimpleNamespace(total=0, used=0, free=free)

    def test_raises_with_need_have_message_when_short(self):
        with mock.patch(
            "apps.api.v1.utils.api_helpers.shutil.disk_usage",
            return_value=self._usage(1 << 30),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                ensure_disk_space(2 << 30, what="website backup")
        self.assertEqual(
            str(ctx.exception),
            "Not enough free disk space for website backup: "
            "need ~2.00 GB, have ~1.00 GB free",
        )

    def test_passes_when_enough_free(self):
        with mock.patch(
            "apps.api.v1.utils.api_helpers.shutil.disk_usage",
            return_value=self._usage(3 << 30),
        ):
            self.assertIsNone(ensure_disk_space(2 << 30))

    def test_passes_when_exactly_enough_free(self):
        with mock.patch(
            "apps.api.v1.utils.api_helpers.shutil.disk_usage",
            return_value=self._usage(2 << 30),
        ):
            self.assertIsNone(ensure_disk_space(2 << 30))


class DiskSpacePreflightEngineTests(WebsiteEngineBase):
    """The engines run the preflight BEFORE any download/dump, with an estimate
    of max(multiplier * last COMPLETE backup size, 1 GiB)."""

    GB = 1 << 30

    def _usage(self, free):
        return SimpleNamespace(total=0, used=0, free=free)

    def _run_lftp(self, backup, *, incremental, free):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run") as run, \
             mock.patch.object(W, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(free),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                W._snapshot_lftp(
                    backup, base_dir=os.path.join(tmp, "w") + os.sep,
                    incremental=incremental,
                )
        run.assert_not_called()  # preflight fired before any lftp transfer
        return str(ctx.exception)

    def test_full_backup_estimate_is_2x_last_complete_backup(self):
        node, backup = self._make_backup(incremental=False)
        CoreWebsiteBackup.objects.create(
            website=node.website, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE, size=2 * self.GB, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        # The newer COMPLETE backup (5 GB) is the estimate basis, not the older.
        CoreWebsiteBackup.objects.create(
            website=node.website, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE, size=5 * self.GB, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        message = self._run_lftp(backup, incremental=False, free=9 * self.GB)
        self.assertIn("need ~10.00 GB", message)
        self.assertIn("have ~9.00 GB free", message)

    def test_incremental_backup_estimate_is_1_2x(self):
        node, backup = self._make_backup(incremental=True)
        CoreWebsiteBackup.objects.create(
            website=node.website, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE, size=5 * self.GB, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        message = self._run_lftp(backup, incremental=True, free=5 * self.GB)
        self.assertIn("need ~6.00 GB", message)

    def test_estimate_floors_at_1gb_without_history(self):
        node, backup = self._make_backup(incremental=False)
        message = self._run_lftp(backup, incremental=False, free=self.GB - 1)
        self.assertIn("need ~1.00 GB", message)

    def test_non_complete_backups_do_not_feed_the_estimate(self):
        node, backup = self._make_backup(incremental=False)
        CoreWebsiteBackup.objects.create(
            website=node.website, uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.FAILED, size=50 * self.GB, attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        message = self._run_lftp(backup, incremental=False, free=self.GB - 1)
        self.assertIn("need ~1.00 GB", message)

    def test_mysql_engine_preflight_blocks_before_dump(self):
        node, backup = DatabaseEngineBase._make_backup(
            self, db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        with DatabaseEngineBase._patch_check_connection(), \
             mock.patch.object(MYSQL_ENGINE.subprocess, "run") as run, \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(0),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                MYSQL_ENGINE.snapshot_mysql(backup)
        run.assert_not_called()
        self.assertIn("Not enough free disk space for database backup",
                      str(ctx.exception))

    def test_postgresql_engine_preflight_blocks_before_dump(self):
        node, backup = DatabaseEngineBase._make_backup(
            self, db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16", port=5432)
        with DatabaseEngineBase._patch_check_connection(), \
             mock.patch.object(PG_ENGINE.subprocess, "run") as run, \
             mock.patch.object(PG_ENGINE, "delete_from_disk"), \
             mock.patch(
                 "apps.api.v1.utils.api_helpers.shutil.disk_usage",
                 return_value=self._usage(0),
             ):
            with self.assertRaises(NodeBackupFailedError) as ctx:
                PG_ENGINE.snapshot_postgresql(backup)
        run.assert_not_called()
        self.assertIn("Not enough free disk space for database backup",
                      str(ctx.exception))


class FinalizeZipManifestTests(WebsiteEngineBase):
    """_finalize_zip writes the manifest to TOP-LEVEL _storage/{uuid}.files --
    never inside the zip -- so archives hold pure site content."""

    def _tree(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        os.makedirs(os.path.join(tmp, "sub"))
        with open(os.path.join(tmp, "index.html"), "w") as fh:
            fh.write("<h1>hi</h1>")
        with open(os.path.join(tmp, "sub", "world.txt"), "w") as fh:
            fh.write("world")
        return tmp

    def _finalize(self, backup, tmp, *, keep_dir):
        self.addCleanup(_cleanup_storage_artifacts(
            f"_storage/{backup.uuid}.files",
            f"_storage/{backup.uuid}.zip",
            f"_storage/{backup.uuid}.log",
        ))
        with mock.patch.object(W, "delete_from_disk") as cleanup:
            W._finalize_zip(backup, tmp + os.sep, keep_dir=keep_dir)
        return cleanup

    def test_manifest_lives_at_top_level_not_in_zip(self):
        node, backup = self._make_backup()
        tmp = self._tree()
        self._finalize(backup, tmp, keep_dir=False)

        manifest = f"_storage/{backup.uuid}.files"
        self.assertTrue(os.path.exists(manifest))
        with open(manifest) as fh:
            entries = set(fh.read().splitlines())
        self.assertEqual(entries, {"index.html", os.path.join("sub", "world.txt")})

        # The tree itself holds no manifest copy...
        self.assertFalse(os.path.exists(os.path.join(tmp, f"{backup.uuid}.files")))

        # ...and the zip is pure site content.
        zip_path = f"_storage/{backup.uuid}.zip"
        self.assertTrue(os.path.exists(zip_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            self.assertIn("index.html", names)
            self.assertIn(os.path.join("sub", "world.txt"), names)
            self.assertFalse(any(n.endswith(".files") for n in names))

        backup.refresh_from_db()
        self.assertEqual(backup.total_files, 2)
        self.assertEqual(backup.size, os.stat(zip_path).st_size)
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

    def test_full_mode_discards_working_dir_via_task(self):
        node, backup = self._make_backup()
        tmp = self._tree()
        cleanup = self._finalize(backup, tmp, keep_dir=False)
        cleanup.apply_async.assert_called_once_with(args=[backup.uuid_str, "dir"])

    def test_cache_mode_keeps_tree_and_schedules_no_cleanup(self):
        node, backup = self._make_backup()
        # The incremental cache directory with its mirrored tree.
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        cache = os.path.join(tmp, "cache")
        os.makedirs(os.path.join(cache, "sub"))
        with open(os.path.join(cache, "index.html"), "w") as fh:
            fh.write("<h1>hi</h1>")
        with open(os.path.join(cache, "sub", "world.txt"), "w") as fh:
            fh.write("world")
        cleanup = self._finalize(backup, cache, keep_dir=True)
        cleanup.apply_async.assert_not_called()
        # The cache tree is untouched for the next incremental run, and nothing
        # cache-local was planted: no {uuid}.files inside the cache.
        self.assertEqual(sorted(os.listdir(cache)), ["index.html", "sub"])
        self.assertTrue(os.path.exists(os.path.join(cache, "sub", "world.txt")))
