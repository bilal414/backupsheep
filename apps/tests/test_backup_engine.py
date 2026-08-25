import io
import ftplib
import json
import os
import shlex
import shutil
import ssl
import subprocess
import stat
import tempfile
import time
import uuid
import zipfile
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

import requests as raw_requests
from botocore.exceptions import ClientError
from celery.exceptions import MaxRetriesExceededError, Retry
from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.exceptions import (
    IntegrationValidationError,
    NodeBackupFailedError,
    NodeConnectionErrorWebsite,
    NodeConnectionErrorSFTP,
)
from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.backup import mariadb as MDB_ENGINE
from apps._tasks.integration.backup import mysql as MYSQL_ENGINE
from apps._tasks.integration.backup import _mysql_schema as MYSQL_SCHEMA
from apps._tasks.integration.backup import postgresql as PG_ENGINE
from apps._tasks.integration.backup import website as W
from apps._tasks.integration.backup._archive import ArchiveSourcePolicyError
from apps._tasks.integration.backup.errors import BackupStageError, safe_backup_failure
from apps._tasks.integration.database import backup_database
from apps._tasks.integration.website import backup_website
from apps.api.v1.backup.website.serializers import CoreWebsiteBackupSerializer
from apps.api.v1.node.views import CoreNodeView
from apps.api.v1.utils.api_helpers import (
    bs_encrypt,
    ensure_disk_space,
    FtpImplicitTlsSession,
    FtpSession,
    FtpTlsSession,
    ftp_tls_session_factory,
    zipdir,
)
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDigitalOceanBackup,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    _stop_legacy_backup_container,
)
from apps.console.connection.models import (
    CoreAuthDatabase,
    CoreAuthDigitalOcean,
    CoreAuthWebsite,
    CoreConnection,
)
from apps.console.node.models import (
    CoreDatabase,
    CoreNode,
    CoreWebsite,
    _clear_local_backup_artifacts,
    _resume_local_backup_owned,
)
from apps.console.storage.models import CoreStorage, CoreStorageLocal
from apps.console.utils.models import BackupExecutionLeaseLostError, UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class LegacyContainerStopSafetyTests(TestCase):
    def test_stop_uses_fixed_argv_for_a_canonical_backup_uuid(self):
        identifier = "12345678-1234-4234-8234-123456789abc"
        with mock.patch(
            "apps.console.backup.models.shutil.which", return_value="/usr/bin/docker"
        ), mock.patch("apps.console.backup.models.subprocess.run") as run:
            _stop_legacy_backup_container(f"{identifier}-storage")

        run.assert_called_once_with(
            ["/usr/bin/docker", "stop", f"{identifier}-storage"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )

    def test_stop_rejects_noncanonical_or_shell_shaped_names(self):
        for candidate in (
            "12345678123442348234123456789abc",
            "12345678-1234-4234-8234-123456789abc;id",
            "../../another-container",
            "",
        ):
            with self.subTest(candidate=candidate), mock.patch(
                "apps.console.backup.models.shutil.which"
            ) as which, mock.patch(
                "apps.console.backup.models.subprocess.run"
            ) as run:
                _stop_legacy_backup_container(candidate)
                which.assert_not_called()
                run.assert_not_called()

    def test_stop_is_a_noop_without_a_docker_client(self):
        with mock.patch(
            "apps.console.backup.models.shutil.which", return_value=None
        ), mock.patch("apps.console.backup.models.subprocess.run") as run:
            _stop_legacy_backup_container(
                "12345678-1234-4234-8234-123456789abc"
            )
        run.assert_not_called()


class PlainFtpSecureDefaultTests(TestCase):
    @override_settings(ALLOW_INSECURE_FTP=False)
    def test_connection_validation_rejects_plain_ftp_before_network_access(self):
        for protocol in (CoreAuthWebsite.Protocol.FTP, "1"):
            with self.subTest(protocol=protocol), mock.patch(
                "ftputil.FTPHost"
            ) as ftp_host, self.assertRaisesRegex(
                NodeConnectionErrorWebsite,
                "Plain FTP is disabled",
            ):
                CoreAuthWebsite().check_connection(
                    data={
                        "host": "ftp.example.test",
                        "port": 21,
                        "username": "user",
                        "password": "secret",
                        "protocol": protocol,
                    }
                )

            ftp_host.assert_not_called()

    @override_settings(ALLOW_INSECURE_FTP=False)
    def test_direct_plain_ftp_session_is_denied_before_connect(self):
        with mock.patch.object(ftplib.FTP, "connect") as connect, self.assertRaisesRegex(
            RuntimeError,
            "Plain FTP is disabled",
        ):
            FtpSession("ftp.example.test", "user", "secret", 21)

        connect.assert_not_called()

    def test_invalid_protocol_fails_closed_before_network_access(self):
        with mock.patch("ftputil.FTPHost") as ftp_host, self.assertRaisesRegex(
            NodeConnectionErrorWebsite,
            "missing or unsupported",
        ):
            CoreAuthWebsite().check_connection(
                data={
                    "host": "ftp.example.test",
                    "port": 21,
                    "username": "user",
                    "password": "secret",
                    "protocol": "invalid",
                }
            )

        ftp_host.assert_not_called()


class FtpsSessionSecurityTests(TestCase):
    def _session(self, *, verify_ssl, explicit):
        with mock.patch.object(ftplib.FTP_TLS, "connect"), mock.patch.object(
            ftplib.FTP_TLS, "login"
        ), mock.patch.object(ftplib.FTP_TLS, "prot_p"):
            return ftp_tls_session_factory(
                verify_ssl=verify_ssl,
                explicit=explicit,
            )("ftps.example.test", "user", "secret", 990)

    def test_verified_explicit_ftps_requires_certificate_and_hostname(self):
        session = self._session(verify_ssl=True, explicit=True)

        self.assertIsInstance(session, FtpTlsSession)
        self.assertEqual(session.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(session.context.check_hostname)

    def test_verified_implicit_ftps_requires_certificate_and_hostname(self):
        session = self._session(verify_ssl=True, explicit=False)

        self.assertIsInstance(session, FtpImplicitTlsSession)
        self.assertEqual(session.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(session.context.check_hostname)

    def test_certificate_verification_opt_out_still_uses_explicit_tls(self):
        session = self._session(verify_ssl=False, explicit=True)

        self.assertIsInstance(session, FtpTlsSession)
        self.assertEqual(session.context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(session.context.check_hostname)

    def test_certificate_verification_opt_out_still_uses_implicit_tls(self):
        session = self._session(verify_ssl=False, explicit=False)

        self.assertIsInstance(session, FtpImplicitTlsSession)
        self.assertEqual(session.context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(session.context.check_hostname)

    def test_implicit_ftps_wraps_control_socket_with_sni(self):
        session = object.__new__(FtpImplicitTlsSession)
        session._implicit_server_hostname = "implicit.example.test"
        session._sock = None
        session.context = mock.Mock()
        raw_socket = mock.sentinel.raw_socket
        wrapped_socket = mock.sentinel.wrapped_socket
        session.context.wrap_socket.return_value = wrapped_socket

        session.sock = raw_socket

        session.context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="implicit.example.test",
        )
        self.assertIs(session.sock, wrapped_socket)

    def test_connection_validation_honors_ftps_mode_and_verify_policy(self):
        with mock.patch(
            "apps.api.v1.utils.api_helpers.ftp_tls_session_factory",
            return_value=mock.sentinel.session_factory,
        ) as session_factory, mock.patch("ftputil.FTPHost") as ftp_host:
            CoreAuthWebsite().check_connection(
                data={
                    "host": "ftps.example.test",
                    "port": 990,
                    "username": "user",
                    "password": "secret",
                    "protocol": CoreAuthWebsite.Protocol.FTPS,
                    "verify_ssl": False,
                    "ftps_use_explicit_ssl": False,
                }
            )

        session_factory.assert_called_once_with(
            verify_ssl=False,
            explicit=False,
        )
        ftp_host.assert_called_once_with(
            "ftps.example.test",
            "user",
            "secret",
            port=990,
            session_factory=mock.sentinel.session_factory,
        )


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

    def test_provider_failure_code_survives_notification_correlation(self):
        node, backup = self._backup()
        execution = backup.record_execution_error(
            code="PROVIDER_OWNERSHIP_MISMATCH",
            message="provider response must never be persisted",
        )
        execution.reconciliation_state = execution.ReconciliationState.MANUAL_REVIEW
        execution.reconciliation_reason = "PROVIDER_OWNERSHIP_MISMATCH"
        execution.reconciliation_metadata = {"proof": "durable"}
        execution.save(
            update_fields=[
                "reconciliation_state",
                "reconciliation_reason",
                "reconciliation_metadata",
                "modified",
            ]
        )

        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            return_value=UtilBackup.Status.FAILED,
        ), mock.patch.object(
            backup.__class__, "record_execution_error", wraps=backup.record_execution_error
        ) as record_error, mock.patch(
            "apps.console.account.models.CoreAccount.create_log"
        ):
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        record_error.assert_not_called()
        backup.refresh_from_db()
        persisted = backup.get_execution_state(create=False)
        self.assertEqual(persisted.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertEqual(
            persisted.last_error_message,
            "Provider ownership verification failed.",
        )
        self.assertEqual(
            persisted.reconciliation_state,
            persisted.ReconciliationState.MANUAL_REVIEW,
        )
        self.assertEqual(persisted.reconciliation_metadata, {"proof": "durable"})

        with mock.patch.object(node, "notify_backup_fail") as notify:
            helper_tasks._notify_cloud_failure_once(
                node, backup, True, UtilBackup.Status.FAILED
            )
        notification_error = notify.call_args.args[0]
        self.assertEqual(
            notification_error.error_code, "PROVIDER_OWNERSHIP_MISMATCH"
        )
        contract = node._backup_notification_contract(notification_error)
        self.assertEqual(contract["code"], "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertIn("ownership", contract["remediation"].lower())

    def test_notification_lookup_failure_uses_generic_safe_contract(self):
        node, backup = self._backup()
        sensitive_lookup_detail = "provider-token=do-not-leak-or-persist"

        with mock.patch.object(
            backup,
            "get_execution_state",
            side_effect=RuntimeError(sensitive_lookup_detail),
        ), mock.patch.object(node, "notify_backup_fail") as notify:
            helper_tasks._notify_cloud_failure_once(
                node, backup, True, UtilBackup.Status.FAILED
            )

        notify.assert_called_once()
        notification_error = notify.call_args.args[0]
        contract = node._backup_notification_contract(notification_error)
        self.assertEqual(contract["code"], "SOURCE_EXPORT_FAILED")
        self.assertNotIn(sensitive_lookup_detail, str(notification_error))
        self.assertNotIn(sensitive_lookup_detail, str(contract))

    def test_in_progress_requeues(self):
        node, backup = self._backup()
        with mock.patch.object(CoreDigitalOceanBackup, "poll_status",
                               return_value=UtilBackup.Status.IN_PROGRESS), \
             mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as requeue:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])
        requeue.assert_called_once()
        self.assertIn("countdown", requeue.call_args.kwargs)

    def test_escaped_timeout_is_categorized_and_requeued(self):
        node, backup = self._backup()
        canary = "Bearer provider-token"
        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            side_effect=raw_requests.Timeout(canary),
        ), mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as requeue:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        execution = backup.execution_records.get()
        self.assertEqual(execution.last_error_code, "PROVIDER_TIMEOUT")
        self.assertNotIn(canary, execution.last_error_message)
        requeue.assert_called_once()

    def test_escaped_auth_failure_is_terminal_not_in_progress(self):
        node, backup = self._backup()
        error = ClientError(
            {
                "Error": {"Code": "AccessDenied", "Message": "secret body"},
                "ResponseMetadata": {"HTTPStatusCode": 403},
            },
            "DescribeSnapshots",
        )
        with mock.patch.object(
            CoreDigitalOceanBackup, "poll_status", side_effect=error
        ), mock.patch.object(CoreNode, "notify_backup_fail") as notify:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        backup.refresh_from_db()
        execution = backup.execution_records.get()
        self.assertEqual(backup.status, UtilBackup.Status.FAILED)
        self.assertEqual(execution.last_error_code, "PROVIDER_AUTH_FAILED")
        self.assertNotIn("secret body", execution.last_error_message)
        notify.assert_called_once()

    def test_rate_limit_retry_deadline_controls_next_poll(self):
        node, backup = self._backup()

        def rate_limited(instance):
            instance.record_execution_error(
                code="PROVIDER_RATE_LIMIT",
                retry_at=timezone.now() + timedelta(seconds=600),
            )
            return UtilBackup.Status.IN_PROGRESS

        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            autospec=True,
            side_effect=rate_limited,
        ), mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as requeue:
            helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        countdown = requeue.call_args.kwargs["countdown"]
        self.assertGreaterEqual(countdown, 598)
        self.assertLessEqual(countdown, 600)

    def test_second_poller_is_blocked_by_database_lease(self):
        node, backup = self._backup()
        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            return_value=UtilBackup.Status.IN_PROGRESS,
        ) as poll, mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async"):
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id], task_id="poll-task-1"
            )
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id], task_id="poll-task-2"
            )
        poll.assert_called_once()

    def test_scheduled_successor_can_claim_after_poll_eta(self):
        node, backup = self._backup()
        control = dict((backup.metadata or {}).get("_backup_control") or {})
        control.update({
            "poll_task_id": "poll-task-1",
            "poll_lease_until": time.time() + 300,
            "poll_next_run_at": time.time() - 1,
        })
        backup.metadata = {"_backup_control": control}
        backup.save(update_fields=["metadata", "modified"])

        with mock.patch.object(
            CoreDigitalOceanBackup,
            "poll_status",
            return_value=UtilBackup.Status.IN_PROGRESS,
        ) as poll, mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async"):
            helper_tasks.poll_cloud_backup.apply(
                args=[node.id, backup.id], task_id="poll-task-2"
            )

        poll.assert_called_once()

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

    def test_terminal_poll_repairs_stale_node_status(self):
        node, backup = self._backup(status=UtilBackup.Status.COMPLETE)
        node.status = CoreNode.Status.BACKUP_IN_PROGRESS
        node.save(update_fields=["status", "modified"])

        helper_tasks.poll_cloud_backup.apply(args=[node.id, backup.id])

        node.refresh_from_db()
        self.assertEqual(node.status, CoreNode.Status.ACTIVE)

    def test_terminal_poll_does_not_reset_node_with_another_active_backup(self):
        node, terminal_backup = self._backup(status=UtilBackup.Status.COMPLETE)
        CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            celery_task_id="another-task",
        )
        node.status = CoreNode.Status.BACKUP_IN_PROGRESS
        node.save(update_fields=["status", "modified"])

        helper_tasks.poll_cloud_backup.apply(args=[node.id, terminal_backup.id])

        node.refresh_from_db()
        self.assertEqual(node.status, CoreNode.Status.BACKUP_IN_PROGRESS)


class LocalFinalizerTests(BaseTestCase):
    def test_finalizer_keeps_terminal_state_and_cleans_after_notification_error(self):
        node = factories.make_website_node(self.account, self.member)
        storage = factories.make_storage(self.account, self.member, code="local")
        CoreStorageLocal.objects.create(storage=storage, path=None)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        )

        with mock.patch.object(
            CoreNode,
            "notify_backup_success",
            side_effect=RuntimeError("notification transport unavailable"),
        ), mock.patch(
            "apps._tasks.helper.tasks.delete_from_disk.apply_async"
        ) as cleanup:
            from apps._tasks.integration.storage.tasks import finalize_backup

            finalize_backup.apply(args=[node.id, backup.id])

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        cleanup.assert_called_once_with(args=[backup.uuid_str, "both"])


class ProviderPollStatusResilienceTests(BaseTestCase):
    def test_poll_status_missing_auth_is_terminal_and_categorized(self):
        # Missing local provider credentials are not a transient provider operation.
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean, status=UtilBackup.Status.IN_PROGRESS, action_id="A1",
        )
        self.assertEqual(backup.poll_status(), UtilBackup.Status.FAILED)
        self.assertEqual(
            backup.execution_records.get().last_error_code,
            "PROVIDER_AUTH_FAILED",
        )

    def test_digitalocean_persisted_snapshot_404_is_terminal(self):
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
            node_type=CoreNode.Type.VOLUME,
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            status=UtilBackup.Status.IN_PROGRESS,
            unique_id="snapshot-1",
        )
        CoreAuthDigitalOcean.objects.create(
            connection=node.connection,
            api_key=bs_encrypt(
                "test-token", self.account.get_encryption_key()
            ),
        )
        not_found = SimpleNamespace(
            status_code=404,
            json=lambda: {},
            close=lambda: None,
        )
        with mock.patch(
            "apps.console.connection.models.CoreAuthDigitalOcean.get_verified_client",
            return_value={},
        ), mock.patch(
            "apps.console.backup.models.requests.get",
            return_value=not_found,
        ):
            self.assertEqual(backup.poll_status(), UtilBackup.Status.FAILED)
        self.assertEqual(
            backup.execution_records.get().last_error_code,
            "PROVIDER_NOT_FOUND",
        )


class DigitalOceanSnapshotCreateTests(BaseTestCase):
    def test_volume_create_treats_null_snapshot_list_as_empty(self):
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
            node_type=CoreNode.Type.VOLUME,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=node.connection,
            api_key=bs_encrypt("test-token", self.account.get_encryption_key()),
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            uuid="null-safe-volume-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        empty_catalog = SimpleNamespace(
            status_code=200,
            json=lambda: {"snapshots": None, "meta": {"total": 0}},
            close=lambda: None,
        )
        source_volume = SimpleNamespace(
            status_code=200,
            json=lambda: {
                "volume": {"id": str(node.digitalocean.unique_id)}
            },
            close=lambda: None,
        )
        created_snapshot = SimpleNamespace(
            status_code=201,
            json=lambda: {
                "snapshot": {
                    "id": "volume-snapshot-1",
                    "name": backup.uuid_str,
                    "resource_id": str(node.digitalocean.unique_id),
                    "resource_type": "volume",
                    "min_disk_size": 1,
                }
            },
            close=lambda: None,
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.api.v1.connection.digitalocean.client.requests.request",
            return_value=empty_catalog,
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=source_volume
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=created_snapshot
        ):
            node.digitalocean.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "volume-snapshot-1")
        self.assertEqual(backup.size_gigabytes, 1)


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
        self.assertIn("set ftp:ssl-force true", on)
        self.assertIn("set ftp:ssl-force true", off)

    def test_sftp_username_cannot_inject_via_connect_program(self):
        s = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.SFTP),
                                 host_url="sftp://h", port=22, username="u'; rm -rf /",
                                 password="p", ssh_key_path="_storage/ssh_x", parallel=4,
                                 transfer='mirror "." "t"', mirror=True)
        line = next(l for l in s.splitlines() if "connect-program" in l)
        # the dangerous chars are shell-quoted, so they are data, not commands/args
        self.assertNotIn("-l u'; rm -rf /", line)

    def test_sftp_password_uses_shared_strict_known_hosts(self):
        s = W._build_lftp_script(
            auth=self._auth(CoreAuthWebsite.Protocol.SFTP),
            host_url="sftp://h",
            port=22,
            username="user",
            password="secret",
            ssh_key_path=None,
            parallel=2,
            transfer='mirror "." "t"',
            mirror=True,
        )
        line = next(l for l in s.splitlines() if "connect-program" in l)
        self.assertIn("StrictHostKeyChecking=yes", line)
        self.assertIn("UserKnownHostsFile=", line)
        self.assertIn(settings.SSH_KNOWN_HOSTS_PATH, line)
        self.assertIn('user "user" "secret"', s)

    @override_settings(ALLOW_INSECURE_FTP=False)
    def test_plain_ftp_is_denied_by_default(self):
        with self.assertRaisesRegex(NodeBackupFailedError, "Plain FTP is disabled"):
            W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.FTP),
                                 host_url="ftp://h", port=21, username="u", password="p",
                                 ssh_key_path=None, parallel=1, transfer="get a", mirror=False)

    @override_settings(ALLOW_INSECURE_FTP=True)
    def test_plain_ftp_explicit_opt_in_disables_tls(self):
        s = W._build_lftp_script(auth=self._auth(CoreAuthWebsite.Protocol.FTP),
                                 host_url="ftp://h", port=21, username="u", password="p",
                                 ssh_key_path=None, parallel=1, transfer="get a", mirror=False)
        self.assertIn("set ftp:ssl-allow false", s)
        self.assertIn("set ftp:ssl-force false", s)

    def test_serial_fallback_changes_only_parallel_mirror_controls(self):
        script = "\n".join(
            [
                "set net:connection-limit 3",
                'open -p 22 "sftp://host"',
                'mirror --parallel=3 "/deep-3" "/target-3"',
                "bye",
            ]
        )
        serial = W._serial_lftp_script(script)
        self.assertIn("set net:connection-limit 1", serial)
        self.assertIn('--parallel=1 "/deep-3" "/target-3"', serial)
        self.assertNotIn("--parallel=3", serial)

    def test_serial_fallback_leaves_file_and_serial_scripts_unchanged(self):
        file_script = "set net:connection-limit 3\nget -P source -o target\n"
        serial_script = (
            "set net:connection-limit 1\n"
            "mirror --parallel=1 source target\n"
        )
        self.assertEqual(W._serial_lftp_script(file_script), file_script)
        self.assertEqual(W._serial_lftp_script(serial_script), serial_script)

    def test_depth_assertion_requires_nonzero_exact_lftp_signature(self):
        exact = SimpleNamespace(
            returncode=-6,
            stdout=(
                "lftp: SMTask.cc:152: static void SMTask::Enter(SMTask*): "
                "Assertion `stack_ptr<SMTASK_MAX_DEPTH' failed."
            ),
        )
        self.assertTrue(W._lftp_depth_stack_exhausted(exact))
        self.assertFalse(
            W._lftp_depth_stack_exhausted(
                SimpleNamespace(returncode=0, stdout=exact.stdout)
            )
        )
        self.assertFalse(
            W._lftp_depth_stack_exhausted(
                SimpleNamespace(returncode=1, stdout="mirror: permission denied")
            )
        )


class RemoteTarCommandSafetyTests(TestCase):
    def test_leading_dash_sources_are_operands_not_tar_options(self):
        sources = [
            "--checkpoint=1",
            "--checkpoint-action=exec=touch /tmp/attacker-controlled",
        ]

        command = W._build_remote_tar_command(
            archive_path="/tmp/backupsheep/archive.tar",
            exclude_rules="--exclude='*.sock'",
            sources=sources,
        )
        arguments = shlex.split(command)
        operand_boundary = arguments.index("--")

        self.assertIn(
            "--file=/tmp/backupsheep/archive.tar",
            arguments[:operand_boundary],
        )
        self.assertEqual(arguments[operand_boundary + 1:], sources)


class CeleryRoutingTests(TestCase):
    def test_tasks_route_to_expected_queues(self):
        from backupsheep.celery import app

        def q(name):
            return app.amqp.router.route({}, name).get("queue").name

        self.assertEqual(q("backup_database"), "database")
        self.assertEqual(q("backup_website"), "files")
        self.assertEqual(q("backup_digitalocean"), "cloud")
        self.assertEqual(q("storage_upload"), "storage")
        self.assertEqual(q("storage_cleanup_owned_multipart"), "storage")
        self.assertEqual(q("storage_sweep_owned_multipart_cleanup"), "storage")
        self.assertEqual(q("finalize_backup"), "storage")
        self.assertEqual(q("delete_from_disk"), "storage")
        self.assertEqual(q("poll_cloud_backup"), "cloud")
        self.assertEqual(q("resume_in_progress_backups"), "default")
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
                     "backup_hetzner", "backup_aws", "storage_upload",
                     "storage_cleanup_owned_multipart",
                     "storage_sweep_owned_multipart_cleanup", "finalize_backup",
                     "delete_from_disk", "poll_cloud_backup", "delete_old_logs",
                     "run_scheduled_backup", "resume_in_progress_backups"]:
            self.assertIn(name, app.tasks)
        self.assertNotIn("send_to_firebase", app.tasks)


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
        open(os.path.join(st, f"{uid}.files"), "w").close()
        open(os.path.join(st, f"{uid}.members"), "w").close()
        staged = (
            f".{uid}.zip.0123456789abcdef0123456789abcdef.partial.zip"
        )
        open(os.path.join(st, staged), "w").close()
        foreign = ".other.zip.0123456789abcdef0123456789abcdef.partial.zip"
        open(os.path.join(st, foreign), "w").close()
        open(os.path.join(st, f"{uid}.log"), "w").close()
        with override_settings(BASE_DIR=base):
            helper_tasks.delete_from_disk.apply(args=[uid, "both"])
        self.assertFalse(os.path.exists(os.path.join(st, uid)))
        self.assertFalse(os.path.exists(os.path.join(st, f"{uid}.zip")))
        self.assertFalse(os.path.exists(os.path.join(st, f"{uid}.files")))
        self.assertFalse(os.path.exists(os.path.join(st, f"{uid}.members")))
        self.assertFalse(os.path.exists(os.path.join(st, staged)))
        self.assertTrue(os.path.exists(os.path.join(st, foreign)))
        self.assertTrue(os.path.exists(os.path.join(st, f"{uid}.log")))  # log retained

    def test_delete_from_disk_path_traversal_guard(self):
        import tempfile
        base = tempfile.mkdtemp()
        self._storage(base)
        os.makedirs(os.path.join(base, "secret"))
        with override_settings(BASE_DIR=base):
            helper_tasks.delete_from_disk.apply(args=["../secret", "dir"])
        self.assertTrue(os.path.exists(os.path.join(base, "secret")))  # not escaped

    def test_retry_cleanup_removes_only_exact_incomplete_generation(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        st = self._storage(base)
        uid = "retry-owned"
        backup = SimpleNamespace(uuid_str=uid)
        os.makedirs(os.path.join(st, uid))
        exact_files = (
            f"{uid}.zip",
            f"{uid}.manifest.json",
            f"{uid}.files",
            f"{uid}.members",
            f".{uid}.zip.0123456789abcdef0123456789abcdef.partial.zip",
            f".{uid}.files.0123456789abcdef0123456789abcdef.partial",
            f".{uid}.members.0123456789abcdef0123456789abcdef.partial",
        )
        for name in exact_files:
            open(os.path.join(st, name), "w").close()
        foreign = ".foreign.members.0123456789abcdef0123456789abcdef.partial"
        open(os.path.join(st, foreign), "w").close()

        with override_settings(BASE_DIR=base):
            _clear_local_backup_artifacts(backup)

        self.assertFalse(os.path.exists(os.path.join(st, uid)))
        for name in exact_files:
            self.assertFalse(os.path.exists(os.path.join(st, name)))
        self.assertTrue(os.path.exists(os.path.join(st, foreign)))

    def test_delete_from_disk_removes_one_fenced_restore_generation(self):
        import tempfile
        base = tempfile.mkdtemp()
        st = self._storage(base)
        prefix = "restore_backup-id_0123456789abcdef"
        os.makedirs(os.path.join(st, prefix))
        for name in (
            f"{prefix}.zip",
            f"{prefix}.manifest.json",
            f"{prefix}.sql",
            f".{prefix}.sql.0123456789abcdef0123456789abcdef.partial",
            f"my_{prefix}.cnf",
            f"ssh_{prefix}",
        ):
            open(os.path.join(st, name), "w").close()
        foreign_sql = ".restore_backup-id_foreign.sql.0123456789abcdef.partial"
        open(os.path.join(st, foreign_sql), "w").close()
        log_path = os.path.join(st, "restore_backup-id.log")
        open(log_path, "w").close()

        with override_settings(BASE_DIR=base):
            helper_tasks.delete_from_disk.apply(args=[prefix, "restore"])

        self.assertFalse(os.path.exists(os.path.join(st, prefix)))
        self.assertFalse(os.path.exists(os.path.join(st, f"{prefix}.zip")))
        self.assertFalse(
            os.path.exists(os.path.join(st, f"{prefix}.manifest.json"))
        )
        self.assertFalse(os.path.exists(os.path.join(st, f"{prefix}.sql")))
        self.assertFalse(
            os.path.exists(
                os.path.join(
                    st,
                    f".{prefix}.sql.0123456789abcdef0123456789abcdef.partial",
                )
            )
        )
        self.assertFalse(os.path.exists(os.path.join(st, f"my_{prefix}.cnf")))
        self.assertFalse(os.path.exists(os.path.join(st, f"ssh_{prefix}")))
        self.assertTrue(os.path.exists(os.path.join(st, foreign_sql)))
        self.assertTrue(os.path.exists(log_path))

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
        """A real website node (SFTP password auth, all_paths) + backup row."""
        node = factories.make_website_node(self.account, self.member)
        auth = node.connection.auth_website
        # Generic engine tests exercise backup behavior, not the explicit legacy
        # FTP opt-in. Keep their fixture on the secure production default so a
        # plaintext-FTP regression cannot be hidden by the test setup.
        auth.protocol = CoreAuthWebsite.Protocol.SFTP
        auth.port = 22
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
            f"_storage/{backup.uuid}.files",
            f"_storage/{backup.uuid}.members",
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

    def test_public_key_routes_to_lftp_when_managed_key_is_configured(self):
        node, backup = self._make_backup(use_public_key=True)
        lftp, tar = self._run(backup)
        tar.assert_not_called()
        lftp.assert_called_once()


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

    def test_mirror_uses_backup_path_snapshot_after_node_edit(self):
        node, backup = self._make_backup(incremental=False)
        backup.all_paths = False
        backup.paths = [{"path": "request-path", "type": "directory"}]
        backup.save(update_fields=["all_paths", "paths", "modified"])
        website = node.website
        website.all_paths = False
        website.paths = [{"path": "later-node-path", "type": "directory"}]
        website.save(update_fields=["all_paths", "paths", "modified"])
        scripts = []

        def fake_run(cmd, **kwargs):
            if cmd == ["lftp"]:
                scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        with mock.patch.object(
            CoreAuthWebsite, "check_connection", lambda *a, **k: None
        ), mock.patch.object(
            W.subprocess, "run", side_effect=fake_run
        ), mock.patch.object(
            W, "delete_from_disk"
        ), mock.patch.object(
            W, "_finalize_zip"
        ):
            W._snapshot_lftp(
                backup,
                base_dir=f"_storage/{backup.uuid}/",
                incremental=False,
            )

        self.assertEqual(len(scripts), 1)
        self.assertIn('"request-path"', scripts[0])
        self.assertNotIn("later-node-path", scripts[0])

    def test_sftp_private_key_path_is_absolute_for_lftp(self):
        node, backup = self._make_backup(use_private_key=True)
        auth = node.connection.auth_website
        auth.protocol = CoreAuthWebsite.Protocol.SFTP
        auth.private_key = bs_encrypt(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ndummy\n-----END OPENSSH PRIVATE KEY-----\n",
            self.account.get_encryption_key(),
        )
        auth.save()
        scripts = []

        def fake_run(cmd, **kwargs):
            if cmd == ["lftp"]:
                scripts.append(kwargs.get("input") or "")
            return SimpleNamespace(stdout="", returncode=0)

        with mock.patch.object(CoreAuthWebsite, "check_connection", lambda *a, **k: None), \
             mock.patch.object(W.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(W, "_normalize_ssh_key"), \
             mock.patch.object(W, "delete_from_disk"), \
             mock.patch.object(W, "_finalize_zip"):
            W._snapshot_lftp(backup, base_dir=f"_storage/{backup.uuid}/", incremental=False)

        line = next(line for line in scripts[0].splitlines() if "connect-program" in line)
        self.assertIn(os.path.abspath(f"_storage/ssh_{backup.uuid}"), line)


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

    def test_backup_snapshot_keeps_fingerprint_stable_after_node_path_edit(self):
        website, auth, username = self._inputs()
        backup = SimpleNamespace(
            all_paths=False,
            paths=[{"path": "request_path", "type": "directory"}],
        )
        fp1 = W._cache_fingerprint(
            website, auth, username, backup=backup
        )
        website.all_paths = True
        website.paths = None
        self.assertEqual(
            fp1,
            W._cache_fingerprint(website, auth, username, backup=backup),
        )

    def test_changes_when_host_changes(self):
        website, auth, username = self._inputs()
        fp1 = W._cache_fingerprint(website, auth, username)
        auth.host = "ftp.other-host.com"
        self.assertNotEqual(fp1, W._cache_fingerprint(website, auth, username))


class ResetIncrementalCacheTests(BaseTestCase):
    """The web role schedules cache deletion on the storage-worker boundary."""

    @mock.patch(
        "apps.api.v1.node.views.reset_incremental_cache.apply_async"
    )
    def test_reset_incremental_schedules_storage_task(self, apply_async):
        node = factories.make_website_node(self.account, self.member)
        request = APIRequestFactory().post(f"/api/v1/nodes/{node.id}/reset_incremental/")
        force_authenticate(request, user=self.user)
        view = CoreNodeView.as_view({"post": "reset_incremental"})
        resp = view(request, pk=node.id)
        self.assertEqual(resp.status_code, 200)
        apply_async.assert_called_once_with(args=[node.pk])

    def test_storage_task_deletes_only_requested_cache(self):
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

        with override_settings(BASE_DIR=tmp):
            helper_tasks.reset_incremental_cache.apply(args=[node.pk]).get()
        self.assertFalse(os.path.exists(cache_dir))
        self.assertFalse(os.path.exists(meta_path))
        self.assertTrue(os.path.isfile(
            os.path.join(tmp, "_storage", "website_cache", f"{node.uuid_str}.lock")
        ))

    def test_storage_task_holds_incremental_lock_around_deletion(self):
        node = factories.make_website_node(self.account, self.member)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        cache_dir = os.path.join(tmp, "_storage", "website_cache", node.uuid_str)
        os.makedirs(cache_dir)

        events = []
        real_flock = helper_tasks.fcntl.flock
        real_rmtree = helper_tasks.shutil.rmtree

        def observed_flock(file_obj, operation):
            events.append("lock" if operation == helper_tasks.fcntl.LOCK_EX else "unlock")
            return real_flock(file_obj, operation)

        def observed_rmtree(*args, **kwargs):
            events.append("delete")
            return real_rmtree(*args, **kwargs)

        with override_settings(BASE_DIR=tmp), mock.patch.object(
            helper_tasks.fcntl, "flock", side_effect=observed_flock
        ), mock.patch.object(
            helper_tasks.shutil, "rmtree", side_effect=observed_rmtree
        ):
            helper_tasks.reset_incremental_cache.apply(args=[node.pk]).get()

        self.assertEqual(events, ["lock", "delete", "unlock"])

    def test_storage_task_rejects_cache_root_symlink_outside_workdir(self):
        node = factories.make_website_node(self.account, self.member)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        storage_dir = os.path.join(tmp, "_storage")
        outside = os.path.join(tmp, "backup-storage")
        victim = os.path.join(outside, node.uuid_str)
        os.makedirs(victim)
        with open(os.path.join(victim, "must-survive"), "w") as handle:
            handle.write("sentinel")
        os.makedirs(storage_dir)
        os.symlink(outside, os.path.join(storage_dir, "website_cache"))

        with override_settings(BASE_DIR=tmp):
            helper_tasks.reset_incremental_cache.apply(args=[node.pk]).get()

        self.assertTrue(os.path.isfile(os.path.join(victim, "must-survive")))


class NormalizeSshKeyTests(TestCase):
    """Private-key normalization never puts passphrases in process arguments."""

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

    def test_materialize_restores_terminal_newline_and_owner_only_mode(self):
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        generated_path = os.path.join(tmp_dir, "generated_ed25519")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", generated_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with open(generated_path, encoding="utf-8") as source:
            key_without_newline = source.read().rstrip("\n")

        materialized_path = os.path.join(tmp_dir, "materialized_ed25519")
        W._materialize_ssh_private_key(materialized_path, key_without_newline)

        with open(materialized_path, "rb") as source:
            materialized = source.read()
        self.assertTrue(materialized.endswith(b"\n"))
        self.assertFalse(materialized.endswith(b"\n\n"))
        self.assertEqual(stat.S_IMODE(os.stat(materialized_path).st_mode), 0o600)
        parsed = subprocess.run(
            ["ssh-keygen", "-y", "-f", materialized_path],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_paramiko_write_failure_uses_in_process_crypto(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        encrypted = private_key.private_bytes(
            encoding=W.serialization.Encoding.PEM,
            format=W.serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=W.serialization.BestAvailableEncryption(
                b"s3cret-passphrase"
            ),
        )
        path = self._key_file(encrypted.decode("utf-8"))
        ed, rsa, ec = self._paramiko_write_broken()
        with ed, rsa, ec, mock.patch.object(W.subprocess, "run") as run:
            W._normalize_ssh_key(path, "s3cret-passphrase")
        run.assert_not_called()
        W.paramiko.Ed25519Key.from_private_key_file(path)

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

    def test_unencrypted_ed25519_key_is_not_round_tripped(self):
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        path = os.path.join(tmp_dir, "id_ed25519")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with open(path, "rb") as fh:
            original = fh.read()

        W._normalize_ssh_key(path, "")

        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), original)
        W.paramiko.Ed25519Key.from_private_key_file(path)


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
        self.assertNotIn("boom", str(ctx.exception))
        self.assertIn("validate", str(ctx.exception).lower())
        self.assertEqual(self._storage_listing(), before)

    def test_unparseable_key_raises_and_removes_temp_key(self):
        auth = self._auth()
        ssh_client = mock.Mock(name="ssh")
        before = self._storage_listing()
        with mock.patch("paramiko.SSHClient", return_value=ssh_client):
            # Real key classes, garbage key contents -> nothing parses.
            with self.assertRaises(Exception) as ctx:
                auth.get_sftp_client()
        self.assertNotIn("unexpected OpenSSH", str(ctx.exception))
        self.assertIn("validate", str(ctx.exception).lower())
        ssh_client.connect.assert_not_called()
        self.assertEqual(self._storage_listing(), before)


# ---------------------------------------------------------------------------
# Database backup engine tests (mysql.py / mariadb.py / postgresql.py rewrites)
# ---------------------------------------------------------------------------

DB_USER = "dbuser"
DB_PASS = "p@ssw0rdSecret"
MYSQL_SCHEMA_DEFAULTS = b"utf8mb4\tutf8mb4_unicode_ci\n"
MYSQL_SCHEMA_PREAMBLE = (
    b"ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
)


class MysqlSchemaMetadataTests(TestCase):
    def test_database_defaults_are_validated_and_rendered_as_digest_bound_sql(self):
        defaults = MYSQL_SCHEMA.parse_database_defaults(
            MYSQL_SCHEMA_DEFAULTS.decode("ascii")
        )

        self.assertEqual(
            defaults,
            {"character_set": "utf8mb4", "collation": "utf8mb4_unicode_ci"},
        )
        self.assertEqual(
            MYSQL_SCHEMA.database_defaults_preamble(defaults),
            MYSQL_SCHEMA_PREAMBLE,
        )

    def test_database_defaults_reject_sql_metacharacters_and_missing_rows(self):
        for output in (
            "",
            "utf8mb4\tutf8mb4_unicode_ci\nextra\trow\n",
            "utf8mb4\tutf8mb4_unicode_ci;DROP_DATABASE\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    MYSQL_SCHEMA.parse_database_defaults(output)


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
        if any(
            item.startswith("--execute=") and "DEFAULT_CHARACTER_SET_NAME" in item
            for item in argv
        ):
            return SimpleNamespace(
                returncode=0, stdout=MYSQL_SCHEMA_DEFAULTS, stderr=b""
            )
        out = kwargs.get("stdout")
        if out is not None and dump:
            # Match subprocess semantics: the child writes to the descriptor,
            # not through the parent's Python buffer.
            os.write(out.fileno(), dump)
        return SimpleNamespace(returncode=returncode, stderr=stderr)

    return fake_run


def _recorded_multi_database_run(calls, *, inventory=None):
    """Record direct client/dump calls for selected/all-database fixtures."""
    inventory = inventory or []

    def fake_run(argv, **kwargs):
        call = {"argv": list(argv), "kwargs": kwargs}
        calls.append(call)
        defaults = next(
            (
                item.split("=", 1)[1]
                for item in argv
                if item.startswith("--defaults-extra-file=")
            ),
            None,
        )
        if defaults:
            call["defaults_mode"] = stat.S_IMODE(os.stat(defaults).st_mode)
        if "--execute=SHOW DATABASES;" in argv:
            return SimpleNamespace(
                returncode=0,
                stdout=("\n".join(inventory) + "\n").encode(),
                stderr=b"",
            )
        if any(
            item.startswith("--execute=") and "DEFAULT_CHARACTER_SET_NAME" in item
            for item in argv
        ):
            return SimpleNamespace(
                returncode=0, stdout=MYSQL_SCHEMA_DEFAULTS, stderr=b""
            )
        database = argv[-1]
        os.write(
            kwargs["stdout"].fileno(), f"-- dump of {database}\n".encode()
        )
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

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

    def exec_command(self, command, **_kwargs):
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
             mock.patch(
                 "apps._tasks.execution.verify_and_commit_source_artifact",
                 return_value=SimpleNamespace(byte_count=0),
             ), \
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

    def test_mysql_defaults_file_has_exact_tls_mode(self):
        required = MYSQL_ENGINE._defaults_file_content(
            DB_USER, DB_PASS, "db.example.test", 3306, True
        )
        disabled = MYSQL_ENGINE._defaults_file_content(
            DB_USER, DB_PASS, "db.example.test", 3306, False
        )

        self.assertIn("ssl-mode=Required", required)
        self.assertNotIn("ssl-mode=Preferred", required)
        self.assertIn("ssl-mode=Disabled", disabled)

    def _run_engine(self, backup, fake_run):
        with self._patch_check_connection(), \
             mock.patch.object(MYSQL_ENGINE.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(MYSQL_ENGINE, "delete_from_disk"):
            MYSQL_ENGINE.snapshot_mysql(backup)

    def test_direct_success(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        node.connection.auth_database.include_stored_procedure = True
        node.connection.auth_database.save(update_fields=["include_stored_procedure"])
        calls = []
        self._run_engine(backup, _recorded_run(calls, dump=self.DUMP))

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)

        # Zip exists and contains the dumped database bytes.
        zip_path = f"_storage/{backup.uuid}.zip"
        self.assertTrue(os.path.exists(zip_path))
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("appdb.sql", zf.namelist())
            self.assertEqual(
                zf.read("appdb.sql"), MYSQL_SCHEMA_PREAMBLE + self.DUMP
            )

        # One metadata query plus one dump. Both use the same 0600 defaults file.
        self.assertEqual(len(calls), 2)
        defaults_call = next(
            call for call in calls if "--database=appdb" in call["argv"]
        )
        self.assertIn("DEFAULT_CHARACTER_SET_NAME", " ".join(defaults_call["argv"]))
        argv, kwargs = next(
            (call["argv"], call["kwargs"])
            for call in calls
            if call["argv"][0].endswith("mysqldump")
        )
        self.assertTrue(argv[0].endswith("mysqldump"))
        self.assertEqual(argv[1], f"--defaults-extra-file=_storage/my_{backup.uuid}.cnf")
        self.assertIn("--column-statistics=0", argv)  # mysql_8
        self.assertIn("--routines", argv)
        self.assertIn("--triggers", argv)
        self.assertIn("--events", argv)
        self.assertIn("--extended-insert", argv)
        self.assertNotIn("--skip-extended-insert", argv)
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertNotIn(DB_USER, " ".join(argv))
        self.assertFalse(kwargs.get("shell"))
        self.assertNotIn("env", kwargs)
        self.assertEqual(kwargs.get("timeout"), 12 * 3600)
        self.assertEqual(calls[0]["defaults_mode"], 0o600)
        self.assertEqual(backup.option_mysql, " ".join(argv[2:-1]))
        self.assertEqual(
            backup.metadata["logical_dump"],
            {
                "contract_version": 2,
                "engine": "mysql",
                "version": "mysql_8_0",
                "client": "mysqldump",
                "flags": argv[2:-1],
                "extended_insert": True,
                "max_allowed_packet_bytes": 512 * 1024 * 1024,
                "database_defaults": {
                    "appdb": {
                        "character_set": "utf8mb4",
                        "collation": "utf8mb4_unicode_ci",
                    }
                },
            },
        )

        # The credentials file is deleted afterwards.
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))

    def test_direct_selected_databases_dump_each_database(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL,
            version="mysql_8_0",
            database_name=None,
            all_tables=False,
            tables=[],
            databases=["analytics", "appdb"],
        )
        calls = []

        self._run_engine(
            backup,
            _recorded_multi_database_run(calls),
        )

        self.assertEqual(
            [
                call["argv"][-1]
                for call in calls
                if call["argv"][0].endswith("mysqldump")
            ],
            ["analytics", "appdb"],
        )
        self.assertTrue(all(call["defaults_mode"] == 0o600 for call in calls))
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["analytics.sql", "appdb.sql", "backupsheep.txt"],
            )

    def test_direct_all_databases_filters_system_schemas_before_dump(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL,
            version="mysql_8_0",
            database_name=None,
            all_tables=False,
            tables=[],
            databases=[],
            all_databases=True,
        )
        calls = []

        self._run_engine(
            backup,
            _recorded_multi_database_run(
                calls,
                inventory=[
                    "mysql",
                    "analytics",
                    "information_schema",
                    "appdb",
                    "performance_schema",
                    "sys",
                ],
            ),
        )

        self.assertEqual(len(calls), 5)
        self.assertTrue(calls[0]["argv"][0].endswith("mysql"))
        self.assertIn("--execute=SHOW DATABASES;", calls[0]["argv"])
        self.assertEqual(
            [
                call["argv"][-1]
                for call in calls
                if call["argv"][0].endswith("mysqldump")
            ],
            ["analytics", "appdb"],
        )
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["analytics.sql", "appdb.sql", "backupsheep.txt"],
            )

    def test_direct_failure_raises_and_cleans_up(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        calls = []
        with self.assertRaises(NodeBackupFailedError):
            self._run_engine(backup, _recorded_run(
                calls, dump=b"partial", stderr=b"mysqldump: boom", returncode=1))
        self.assertEqual(len(calls), 2)
        self.assertFalse(os.path.exists(f"_storage/{backup.uuid}.zip"))
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))

    def test_explicit_skip_opt_keeps_row_by_row_format_visible(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        node.database.option_skip_opt = True
        node.database.save(update_fields=["option_skip_opt"])
        calls = []

        self._run_engine(backup, _recorded_run(calls, dump=self.DUMP))

        backup.refresh_from_db()
        argv = next(
            call["argv"]
            for call in calls
            if call["argv"][0].endswith("mysqldump")
        )
        self.assertIn("--skip-opt", argv)
        self.assertIn("--quick", argv)
        self.assertLess(argv.index("--skip-opt"), argv.index("--quick"))
        self.assertNotIn("--extended-insert", argv)
        self.assertNotIn("--skip-extended-insert", argv)
        self.assertFalse(backup.metadata["logical_dump"]["extended_insert"])

    def test_event_privilege_failure_contract_is_stable_and_not_retryable(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0")
        node.connection.auth_database.include_stored_procedure = True
        node.connection.auth_database.save(update_fields=["include_stored_procedure"])
        canary = "password=event-secret host=db.internal"
        calls = []

        with self.assertRaises(NodeBackupFailedError) as ctx:
            self._run_engine(
                backup,
                _recorded_run(
                    calls,
                    dump=b"partial",
                    stderr=(
                        "mysqldump: Couldn't execute 'show events': Access denied "
                        f"for user 'backup' ({canary})"
                    ).encode(),
                    returncode=1,
                ),
            )

        self.assertEqual(ctx.exception.error_code, "DATABASE_EVENT_PRIVILEGE_REQUIRED")
        self.assertFalse(ctx.exception.retryable)
        self.assertIn("EVENT privilege", str(ctx.exception.detail))
        self.assertNotIn(canary, str(ctx.exception.detail))
        self.assertNotIn(canary, self._read_log(backup))

    def test_stale_worker_does_not_delete_successor_artifacts(self):
        _node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MYSQL, version="mysql_8_0"
        )
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(
                 MYSQL_ENGINE.subprocess,
                 "run",
                 side_effect=_recorded_run(calls, dump=self.DUMP),
             ), \
             mock.patch.object(
                 MYSQL_ENGINE,
                 "create_python_zip",
                 side_effect=BackupExecutionLeaseLostError("stale worker"),
             ), \
             mock.patch.object(
                 MYSQL_ENGINE.delete_from_disk, "apply_async"
             ) as cleanup:
            with self.assertRaises(BackupExecutionLeaseLostError):
                MYSQL_ENGINE.snapshot_mysql(backup)

        cleanup.assert_not_called()

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

    def test_mariadb_defaults_file_never_uses_mysql_ssl_mode(self):
        enabled = MDB_ENGINE._defaults_file_content(
            DB_USER, DB_PASS, "db.example.test", 3306, True
        )
        disabled = MDB_ENGINE._defaults_file_content(
            DB_USER, DB_PASS, "db.example.test", 3306, False
        )

        self.assertIn("ssl=1\n", enabled)
        self.assertNotIn("ssl-mode", enabled)
        self.assertNotIn("ssl-mode", disabled)

    def test_direct_success_flags(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB, version="mariadb_10_11")
        node.connection.auth_database.include_stored_procedure = True
        node.connection.auth_database.save(update_fields=["include_stored_procedure"])
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(MDB_ENGINE.subprocess, "run",
                               side_effect=_recorded_run(calls, dump=b"-- dump\n")), \
             mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)
        self.assertEqual(len(calls), 2)
        argv = next(
            call["argv"]
            for call in calls
            if call["argv"][0].endswith("mariadb-dump")
        )
        self.assertTrue(argv[0].endswith("mariadb-dump"))
        self.assertEqual(argv[1], f"--defaults-extra-file=_storage/my_{backup.uuid}.cnf")
        self.assertIn("--compress", argv)
        self.assertIn("--routines", argv)
        self.assertIn("--triggers", argv)
        self.assertIn("--events", argv)
        self.assertIn("--extended-insert", argv)
        self.assertNotIn("--skip-extended-insert", argv)
        self.assertFalse(any("column-statistics" in a for a in argv))
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertFalse(os.path.exists(f"_storage/my_{backup.uuid}.cnf"))
        self.assertEqual(backup.option_mariadb, " ".join(argv[2:-1]))
        self.assertEqual(
            backup.metadata["logical_dump"],
            {
                "contract_version": 2,
                "engine": "mariadb",
                "version": "mariadb_10_11",
                "client": "mariadb-dump",
                "flags": argv[2:-1],
                "extended_insert": True,
                "max_allowed_packet_bytes": 512 * 1024 * 1024,
                "database_defaults": {
                    "appdb": {
                        "character_set": "utf8mb4",
                        "collation": "utf8mb4_unicode_ci",
                    }
                },
            },
        )

    def test_direct_selected_databases_dump_each_database(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB,
            version="mariadb_11_8",
            database_name=None,
            all_tables=False,
            tables=[],
            databases=["analytics", "appdb"],
        )
        calls = []
        with self._patch_check_connection(), mock.patch.object(
            MDB_ENGINE.subprocess,
            "run",
            side_effect=_recorded_multi_database_run(calls),
        ), mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)

        self.assertEqual(
            [
                call["argv"][-1]
                for call in calls
                if call["argv"][0].endswith("mariadb-dump")
            ],
            ["analytics", "appdb"],
        )
        self.assertTrue(all(call["defaults_mode"] == 0o600 for call in calls))
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["analytics.sql", "appdb.sql", "backupsheep.txt"],
            )

    def test_direct_all_databases_filters_system_schemas_before_dump(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB,
            version="mariadb_11_8",
            database_name=None,
            all_tables=False,
            tables=[],
            databases=[],
            all_databases=True,
        )
        calls = []
        with self._patch_check_connection(), mock.patch.object(
            MDB_ENGINE.subprocess,
            "run",
            side_effect=_recorded_multi_database_run(
                calls,
                inventory=[
                    "mysql",
                    "analytics",
                    "information_schema",
                    "appdb",
                    "performance_schema",
                    "sys",
                ],
            ),
        ), mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)

        self.assertEqual(len(calls), 5)
        self.assertTrue(calls[0]["argv"][0].endswith("mariadb"))
        self.assertIn("--execute=SHOW DATABASES;", calls[0]["argv"])
        self.assertEqual(
            [
                call["argv"][-1]
                for call in calls
                if call["argv"][0].endswith("mariadb-dump")
            ],
            ["analytics", "appdb"],
        )
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["analytics.sql", "appdb.sql", "backupsheep.txt"],
            )

    def test_explicit_skip_opt_keeps_row_by_row_format_visible(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB,
            version="mariadb_10_11",
        )
        node.database.option_skip_opt = True
        node.database.save(update_fields=["option_skip_opt"])
        calls = []
        with self._patch_check_connection(), \
             mock.patch.object(
                 MDB_ENGINE.subprocess,
                 "run",
                 side_effect=_recorded_run(calls, dump=b"-- dump\n"),
             ), \
             mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)

        backup.refresh_from_db()
        argv = next(
            call["argv"]
            for call in calls
            if call["argv"][0].endswith("mariadb-dump")
        )
        self.assertIn("--skip-opt", argv)
        self.assertIn("--quick", argv)
        self.assertLess(argv.index("--skip-opt"), argv.index("--quick"))
        self.assertNotIn("--extended-insert", argv)
        self.assertNotIn("--skip-extended-insert", argv)
        self.assertFalse(backup.metadata["logical_dump"]["extended_insert"])


class MariadbSshEngineTests(DatabaseEngineBase):
    """MariaDB SSH mode uses MariaDB-native query and dump clients."""

    def test_ssh_success_uses_mariadb_dump(self):
        node, backup = self._make_backup(
            db_type=CoreAuthDatabase.DatabaseType.MARIADB,
            version="mariadb_11_8",
            use_private_key=True,
        )
        node.connection.auth_database.include_stored_procedure = True
        node.connection.auth_database.save(update_fields=["include_stored_procedure"])
        dump = b"/*M!999999\\- enable the sandbox mode */\nCREATE TABLE t (id int);\n"
        ssh = _FakeSSH(
            lambda command: (
                (MYSQL_SCHEMA_DEFAULTS if "DEFAULT_CHARACTER_SET_NAME" in command else dump),
                b"",
                0,
            )
        )
        key_path = self._key_file()
        with self._patch_check_connection(), \
             mock.patch.object(
                 CoreAuthDatabase,
                 "get_ssh_client",
                 return_value=(ssh, key_path),
             ), \
             mock.patch.object(MDB_ENGINE, "delete_from_disk"):
            MDB_ENGINE.snapshot_mariadb(backup)

        dump_commands = [
            command for command in ssh.commands
            if command.startswith("mariadb-dump ")
        ]
        self.assertEqual(len(dump_commands), 1)
        self.assertIn("--routines", dump_commands[0])
        self.assertIn("--triggers", dump_commands[0])
        self.assertIn("--events", dump_commands[0])
        self.assertIn("--extended-insert", dump_commands[0])
        self.assertNotIn("--skip-extended-insert", dump_commands[0])
        self.assertNotIn(DB_PASS, dump_commands[0])
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(
                archive.read("appdb.sql"), MYSQL_SCHEMA_PREAMBLE + dump
            )


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
        self.assertIn("--if-exists", argv)
        self.assertIn("appdb", argv)
        self.assertNotIn(DB_PASS, " ".join(argv))
        self.assertEqual(kwargs["env"]["PGPASSWORD"], DB_PASS)
        self.assertFalse(kwargs.get("shell"))
        self.assertEqual(
            backup.option_postgres,
            PG_ENGINE.DEFAULT_POSTGRES_OPTIONS,
        )

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
        node.connection.auth_database.include_stored_procedure = True
        node.connection.auth_database.save(update_fields=["include_stored_procedure"])
        ssh = _FakeSSH(
            lambda command: (
                (
                    MYSQL_SCHEMA_DEFAULTS
                    if "DEFAULT_CHARACTER_SET_NAME" in command
                    else self.DUMP
                ),
                b"",
                0,
            )
        )
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
        self.assertIn("--routines", dump_cmds[0])
        self.assertIn("--triggers", dump_cmds[0])
        self.assertIn("--events", dump_cmds[0])
        self.assertIn("--extended-insert", dump_cmds[0])
        self.assertNotIn("--skip-extended-insert", dump_cmds[0])
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
            self.assertEqual(
                zf.read("appdb.sql"), MYSQL_SCHEMA_PREAMBLE + self.DUMP
            )

    def test_ssh_nonzero_exit_raises_and_cleans_up(self):
        node, backup = self._ssh_backup()
        ssh = _FakeSSH(
            lambda command: (
                (MYSQL_SCHEMA_DEFAULTS, b"", 0)
                if "DEFAULT_CHARACTER_SET_NAME" in command
                else (b"", b"mysqldump: access denied", 2)
            )
        )
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
        self.assertIn("--clean", dump_cmds[0])
        self.assertIn("--if-exists", dump_cmds[0])
        self.assertNotIn("template0", " ".join(dump_cmds))
        self.assertNotIn("template1", " ".join(dump_cmds))
        self.assertEqual(
            backup.option_postgres,
            PG_ENGINE.DEFAULT_POSTGRES_OPTIONS,
        )

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
        self.assertNotIn("boom", str(ctx.exception))
        self.assertIn("validate", str(ctx.exception).lower())
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

        def handler(command):
            if command == "mysql --version":
                return b"mysql  Ver 8.0.36 for Linux (MySQL Community Server)\n", b"", 0
            if command == "mysqldump --version":
                return b"mysqldump  Ver 8.0.36 for Linux (MySQL Community Server)\n", b"", 0
            if "SELECT 1" in command:
                return b"1\n", b"", 0
            return b"mysql  Ver 8.0\nServer version: 8.0.35\n", b"", 0

        ssh = _FakeSSH(handler)
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))
        with mock.patch.object(CoreAuthDatabase, "get_ssh_client",
                               return_value=(ssh, key_path)):
            auth.check_connection()
        self.assertTrue(ssh.closed)
        self.assertFalse(os.path.exists(key_path))

    def test_postgresql_ssh_check_connection_does_not_build_mysql_tls_option(self):
        node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16",
            use_private_key=True,
        )
        auth = node.connection.auth_database

        def handler(command):
            if command == "pg_dump --version":
                return b"pg_dump (PostgreSQL) 16.10\n", b"", 0
            if "SELECT version();" in command:
                return (
                    b"PostgreSQL 16.10 on x86_64, compiled by gcc, 64-bit\n",
                    b"",
                    0,
                )
            self.fail(f"unexpected PostgreSQL validation command: {command}")

        ssh = _FakeSSH(handler)
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))

        with mock.patch.object(
            CoreAuthDatabase,
            "get_ssh_client",
            return_value=(ssh, key_path),
        ), mock.patch.object(
            CoreAuthDatabase,
            "_mysql_family_ssl_option",
            side_effect=AssertionError("MySQL TLS helper used for PostgreSQL"),
        ):
            auth.check_connection()

        self.assertTrue(ssh.closed)
        self.assertFalse(os.path.exists(key_path))

    def test_postgresql_ssh_object_listing_does_not_build_mysql_tls_option(self):
        node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16",
            use_private_key=True,
        )
        auth = node.connection.auth_database

        def handler(command):
            if "FROM pg_catalog.pg_tables" in command:
                return b"fixture_meta\nbig\n", b"", 0
            self.fail(f"unexpected PostgreSQL listing command: {command}")

        ssh = _FakeSSH(handler)
        fd, key_path = tempfile.mkstemp(dir="_storage", prefix="sshkey_")
        os.write(fd, b"fake-key")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(key_path) and os.remove(key_path))

        with mock.patch.object(auth, "check_connection"), mock.patch.object(
            CoreAuthDatabase,
            "get_ssh_client",
            return_value=(ssh, key_path),
        ), mock.patch.object(
            CoreAuthDatabase,
            "_mysql_family_ssl_option",
            side_effect=AssertionError("MySQL TLS helper used for PostgreSQL"),
        ):
            objects = auth.get_eligible_objects()

        self.assertEqual(
            objects,
            [{"name": "big"}, {"name": "fixture_meta"}],
        )
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

    def _storage(self, suffix):
        return factories.make_storage(
            self.account,
            self.member,
            bucket=f"validation-order-{suffix}",
        )

    def test_website_validation_failure_creates_row_and_marks_retrying(self):
        node = self._website_node()
        storage = self._storage("website-retry")
        with mock.patch.object(CoreStorage, "validate", return_value=True), \
             mock.patch.object(CoreConnection, "validate", return_value=False), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_website, "retry",
                               side_effect=Retry("retrying")) as retry:
            backup_website.apply(
                kwargs={"node_id": node.id, "storage_ids": [storage.id]},
                throw=False,
            )
        backup = CoreWebsiteBackup.objects.get(website=node.website)
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        self.assertEqual(backup.type, UtilBackup.Type.ON_DEMAND)
        self.assertEqual(backup.attempt_no, 1)
        notify.assert_called_once()
        retry.assert_called_once()

    def test_website_validation_failure_max_retries_marks_row(self):
        node = self._website_node()
        storage = self._storage("website-max")
        with mock.patch.object(CoreStorage, "validate", return_value=True), \
             mock.patch.object(CoreConnection, "validate", return_value=False), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_website, "retry",
                               side_effect=MaxRetriesExceededError("maxed")):
            backup_website.apply(
                kwargs={"node_id": node.id, "storage_ids": [storage.id]},
                throw=False,
            )
        backup = CoreWebsiteBackup.objects.get(website=node.website)
        self.assertEqual(backup.status, UtilBackup.Status.MAX_RETRY_FAILED)
        notify.assert_called_once()

    def test_website_terminal_archive_policy_stops_without_retry(self):
        node = self._website_node()
        storage = self._storage("website-archive-policy")
        failure = safe_backup_failure(
            ArchiveSourcePolicyError(
                "symlink", relative_path="private/customer/path"
            ),
            stage="website_backup",
        )
        terminal = NodeBackupFailedError(
            node,
            "archive-policy-test",
            1,
            UtilBackup.Type.ON_DEMAND,
            failure.detail,
            public_failure=failure,
        )

        with mock.patch.object(CoreStorage, "validate", return_value=True), \
             mock.patch.object(CoreConnection, "validate", return_value=True), \
             mock.patch.object(
                 CoreWebsite, "create_snapshot", side_effect=terminal
             ), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_website, "retry") as retry:
            backup_website.apply(
                kwargs={"node_id": node.id, "storage_ids": [storage.id]},
                throw=False,
            )

        backup = CoreWebsiteBackup.objects.get(website=node.website)
        contract = node._backup_notification_contract(terminal)
        self.assertEqual(terminal.error_code, "SOURCE_SPECIAL_FILE_UNSUPPORTED")
        self.assertFalse(terminal.retryable)
        self.assertEqual(contract["code"], "SOURCE_SPECIAL_FILE_UNSUPPORTED")
        self.assertFalse(contract["retryable"])
        self.assertIn("Remove or exclude", contract["remediation"])
        self.assertEqual(backup.status, UtilBackup.Status.MAX_RETRY_FAILED)
        self.assertEqual(backup.attempt_no, 1)
        notify.assert_called_once()
        retry.assert_not_called()

    def test_database_validation_failure_creates_row_and_marks_retrying(self):
        node = self._database_node()
        storage = self._storage("database-retry")
        with mock.patch.object(CoreStorage, "validate", return_value=True), \
             mock.patch.object(CoreConnection, "validate",
                               side_effect=IntegrationValidationError("nope")), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_database, "retry",
                               side_effect=Retry("retrying")) as retry:
            backup_database.apply(
                kwargs={"node_id": node.id, "storage_ids": [storage.id]},
                throw=False,
            )
        backup = CoreDatabaseBackup.objects.get(database=node.database)
        self.assertEqual(backup.status, UtilBackup.Status.RETRYING)
        self.assertEqual(backup.type, UtilBackup.Type.ON_DEMAND)
        self.assertEqual(backup.attempt_no, 1)
        notify.assert_called_once()
        retry.assert_called_once()

    def test_database_validation_failure_max_retries_marks_row(self):
        node = self._database_node()
        storage = self._storage("database-max")
        with mock.patch.object(CoreStorage, "validate", return_value=True), \
             mock.patch.object(CoreConnection, "validate",
                               side_effect=IntegrationValidationError("nope")), \
             mock.patch.object(CoreNode, "notify_backup_fail") as notify, \
             mock.patch.object(backup_database, "retry",
                               side_effect=MaxRetriesExceededError("maxed")):
            backup_database.apply(
                kwargs={"node_id": node.id, "storage_ids": [storage.id]},
                throw=False,
            )
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

    def test_deep_tree_stack_abort_retries_same_mirror_serially(self):
        node, backup = self._make_backup(incremental=False)
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(kwargs.get("input") or "")
            if len(scripts) == 1:
                return SimpleNamespace(
                    stdout=(
                        "lftp: SMTask.cc:152: static void SMTask::Enter(SMTask*): "
                        "Assertion `stack_ptr<SMTASK_MAX_DEPTH' failed.\n"
                    ),
                    returncode=-6,
                )
            return SimpleNamespace(stdout="", returncode=0)

        finalize = self._run(
            backup, incremental=False, fake_run=fake_run
        )
        finalize.assert_called_once()
        self.assertEqual(len(scripts), 2)
        self.assertIn("--parallel=3", scripts[0])
        self.assertIn("--parallel=1", scripts[1])
        self.assertIn("set net:connection-limit 1", scripts[1])
        with open(f"_storage/{backup.uuid}.log") as log:
            self.assertIn("serial directory traversal", log.read())

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
            entries = fh.read().splitlines()
        self.assertEqual(entries, ["index.html", "sub/world.txt"])

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

    def test_verified_enumeration_feeds_zip_once_and_keeps_empty_directories(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        os.makedirs(os.path.join(tmp, "empty-directory"))
        original_walk = os.walk

        with mock.patch.object(W.os, "walk", wraps=original_walk) as walk:
            self._finalize(backup, tmp, keep_dir=True)

        walk.assert_called_once()
        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertIn("empty-directory/", archive.namelist())
        with open(f"_storage/{backup.uuid}.files") as manifest:
            self.assertEqual(
                manifest.read().splitlines(),
                ["index.html", "sub/world.txt"],
            )
        member_prefix = f".{backup.uuid}.members."
        self.assertFalse(
            any(
                name.startswith(member_prefix) and name.endswith(".partial")
                for name in os.listdir("_storage")
            )
        )

    def test_member_list_preserves_unicode_spaces_and_quotes(self):
        _node, backup = self._make_backup()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        names = (
            "caf\u00e9 space.txt",
            "arabic-\u0645\u0631\u062d\u0628\u0627.txt",
            "quote-'\".txt",
        )
        for name in names:
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as source:
                source.write(name)

        self._finalize(backup, tmp, keep_dir=True)

        with zipfile.ZipFile(f"_storage/{backup.uuid}.zip") as archive:
            self.assertEqual(set(archive.namelist()), set(names))
            for name in names:
                self.assertEqual(archive.read(name).decode("utf-8"), name)

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

    def test_symlink_is_rejected_before_archive_or_manifest_publication(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        os.symlink("index.html", os.path.join(tmp, "site-link"))
        manifest = f"_storage/{backup.uuid}.files"
        self.addCleanup(
            _cleanup_storage_artifacts(
                manifest,
                f"_storage/{backup.uuid}.zip",
                f"_storage/{backup.uuid}.log",
            )
        )

        with mock.patch.object(W, "create_zip") as create:
            with self.assertRaises(ArchiveSourcePolicyError) as context:
                W._finalize_zip(backup, tmp, keep_dir=True)

        self.assertEqual(context.exception.kind, "symlink")
        self.assertEqual(context.exception.relative_path, "site-link")
        create.assert_not_called()
        self.assertFalse(os.path.exists(manifest))


class WebsiteMirrorCheckpointTests(WebsiteEngineBase):
    def _tree(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        os.makedirs(os.path.join(directory, "sub"))
        with open(os.path.join(directory, "index.html"), "w") as source:
            source.write("first")
        with open(os.path.join(directory, "sub", "world.txt"), "w") as source:
            source.write("second")
        return directory

    def _checkpoint_tree(self, backup):
        directory = os.path.abspath(f"_storage/{backup.uuid}")
        os.makedirs(os.path.join(directory, "sub"), exist_ok=True)
        with open(os.path.join(directory, "index.html"), "w") as source:
            source.write("first")
        with open(os.path.join(directory, "sub", "world.txt"), "w") as source:
            source.write("second")
        return directory

    def test_archive_failure_persists_exact_mirror_checkpoint(self):
        _node, backup = self._make_backup()
        directory = self._checkpoint_tree(backup)
        fingerprint = W._cache_fingerprint(
            backup.website,
            backup.website.node.connection.auth_website,
            "u",
        )

        with mock.patch.object(W, "create_zip", side_effect=RuntimeError("zip stopped")):
            with self.assertRaises(BackupStageError) as raised:
                W._finalize_zip(
                    backup,
                    directory,
                    keep_dir=True,
                    configuration_sha256=fingerprint,
                )
        self.assertEqual(raised.exception.stage, "website_archive")
        self.assertEqual(str(raised.exception), "website backup stage failed")
        self.assertEqual(str(raised.exception.error), "zip stopped")
        self.assertEqual(
            safe_backup_failure(raised.exception).code,
            "ARCHIVE_CREATION_FAILED",
        )

        backup.refresh_from_db()
        checkpoint = backup.metadata[W._WEBSITE_CHECKPOINT_KEY]
        self.assertEqual(checkpoint["phase"], "archive_building")
        self.assertEqual(checkpoint["identity"]["file_count"], 2)
        self.assertEqual(checkpoint["identity"]["directory_count"], 1)
        self.assertEqual(backup.total_files, 2)
        self.assertTrue(os.path.isfile(f"_storage/{backup.uuid}.members"))
        self.assertTrue(W.website_mirror_checkpoint_candidate(backup))

    def test_retry_revalidates_checkpoint_and_skips_second_lftp_transfer(self):
        node, backup = self._make_backup()
        directory = self._checkpoint_tree(backup)
        fingerprint = W._cache_fingerprint(
            backup.website,
            node.connection.auth_website,
            "u",
        )
        with mock.patch.object(W, "create_zip", side_effect=RuntimeError("zip stopped")):
            with self.assertRaises(RuntimeError):
                W._finalize_zip(
                    backup,
                    directory,
                    keep_dir=True,
                    configuration_sha256=fingerprint,
                )

        with mock.patch.object(
                 CoreAuthWebsite,
                 "check_connection",
                 side_effect=AssertionError("archive retry touched the source"),
             ) as check_connection, \
             mock.patch.object(
                 W,
                 "_preflight_website_capacity",
                 side_effect=AssertionError("archive retry requested mirror capacity"),
             ) as mirror_preflight, \
             mock.patch.object(W.subprocess, "run") as lftp, \
             mock.patch.object(W, "delete_from_disk"):
            W._snapshot_lftp(
                backup,
                base_dir=directory + os.sep,
                incremental=False,
            )

        lftp.assert_not_called()
        check_connection.assert_not_called()
        mirror_preflight.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)
        with open(f"_storage/{backup.uuid}.log") as run_log:
            self.assertIn("without another source transfer", run_log.read())

    def test_changed_checkpoint_workspace_forces_fresh_mirror(self):
        node, backup = self._make_backup()
        directory = self._checkpoint_tree(backup)
        fingerprint = W._cache_fingerprint(
            backup.website,
            node.connection.auth_website,
            "u",
        )
        with mock.patch.object(W, "create_zip", side_effect=RuntimeError("zip stopped")):
            with self.assertRaises(RuntimeError):
                W._finalize_zip(
                    backup,
                    directory,
                    keep_dir=True,
                    configuration_sha256=fingerprint,
                )
        with open(os.path.join(directory, "index.html"), "w") as source:
            source.write("changed after checkpoint")

        with mock.patch.object(
                 CoreAuthWebsite,
                 "check_connection",
             ) as check_connection, \
             mock.patch.object(
                 W.subprocess,
                 "run",
                 return_value=SimpleNamespace(stdout="", returncode=0),
             ) as lftp, \
             mock.patch.object(W, "_finalize_zip"), \
             mock.patch.object(W, "delete_from_disk"):
            W._snapshot_lftp(
                backup,
                base_dir=directory + os.sep,
                incremental=False,
            )

        lftp.assert_called_once()
        check_connection.assert_called_once_with()

    def test_inode_preflight_fails_before_work_when_capacity_is_short(self):
        with mock.patch.object(
            W.os,
            "statvfs",
            return_value=SimpleNamespace(f_files=100, f_favail=3),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Not enough free inodes for website backup",
            ):
                W._ensure_inode_capacity("_storage", 4, what="website backup")

    def test_resume_preserves_checkpoint_and_unbinds_progress_callback(self):
        node, backup = self._make_backup()
        checkpoint = mock.Mock(return_value=True)
        execution = SimpleNamespace(
            state=SimpleNamespace(progress_completed=12000),
            progress=mock.Mock(),
            ensure_owned=mock.Mock(),
        )

        def snapshot(current):
            self.assertIs(current, backup)
            self.assertIs(current._execution_progress_callback, execution.progress)
            self.assertEqual(current._execution_progress_floor, 12000)

        with mock.patch(
                 "apps.console.node.models._clear_local_backup_artifacts",
             ) as clear_artifacts, \
             mock.patch(
                 "apps._tasks.execution.verify_and_commit_source_artifact",
                 return_value=SimpleNamespace(byte_count=321),
             ), \
             mock.patch(
                 "apps._tasks.integration.storage.tasks.finalize_backup.apply_async",
             ) as finalize:
            _resume_local_backup_owned(
                backup,
                node,
                snapshot,
                "stored_website_backups",
                CoreWebsiteBackupStoragePoints.Status,
                execution,
                resume_source_checkpoint=checkpoint,
            )

        checkpoint.assert_called_once_with(backup)
        clear_artifacts.assert_not_called()
        execution.progress.assert_called_once_with(
            321,
            321,
            unit="bytes",
            metadata_updates={"public_stage": None},
        )
        finalize.assert_called_once_with(args=[node.id, backup.id])
        self.assertNotIn("_execution_progress_callback", backup.__dict__)
        self.assertNotIn("_execution_progress_floor", backup.__dict__)

    def test_source_ready_parent_waits_for_a_storage_worker_claim(self):
        node, backup = self._make_backup()
        storage = factories.make_storage(
            self.account,
            self.member,
            code="local",
            bucket=f"source-ready-{uuid.uuid4().hex[:12]}",
        )
        CoreStorageLocal.objects.create(storage=storage, path=None)
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        execution = SimpleNamespace(
            state=SimpleNamespace(progress_completed=0),
            progress=mock.Mock(),
            ensure_owned=mock.Mock(),
        )
        artifact = SimpleNamespace(byte_count=321)

        queued_upload = mock.Mock()
        with mock.patch(
            "apps._tasks.execution.verify_and_commit_source_artifact",
            return_value=artifact,
        ), mock.patch(
            "apps._tasks.integration.storage.tasks.storage_upload.s",
            return_value=queued_upload,
        ) as storage_signature:
            _resume_local_backup_owned(
                backup,
                node,
                mock.Mock(),
                "stored_website_backups",
                CoreWebsiteBackupStoragePoints.Status,
                execution,
            )

        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DOWNLOAD_COMPLETE)
        self.assertEqual(
            CoreWebsiteBackupSerializer(backup).data["execution_status"]["phase"],
            "source_ready",
        )
        point = CoreWebsiteBackupStoragePoints.objects.get(backup=backup)
        storage_signature.assert_called_once_with(node.id, backup.id, point.id)
        queued_upload.set.assert_called_once_with()
        queued_upload.set.return_value.apply_async.assert_called_once_with()

    def test_directory_symlink_is_rejected_before_archive_publication(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        os.symlink("sub", os.path.join(tmp, "linked-directory"))
        manifest = f"_storage/{backup.uuid}.files"
        self.addCleanup(
            _cleanup_storage_artifacts(
                manifest,
                f"_storage/{backup.uuid}.zip",
                f"_storage/{backup.uuid}.log",
            )
        )

        with mock.patch.object(W, "create_zip") as create:
            with self.assertRaises(ArchiveSourcePolicyError) as context:
                W._finalize_zip(backup, tmp, keep_dir=True)

        self.assertEqual(context.exception.kind, "symlink")
        self.assertEqual(context.exception.relative_path, "linked-directory")
        create.assert_not_called()
        self.assertFalse(os.path.exists(manifest))

    def test_fifo_is_rejected_before_archive_or_manifest_publication(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        os.mkfifo(os.path.join(tmp, "updates.pipe"))
        manifest = f"_storage/{backup.uuid}.files"
        self.addCleanup(
            _cleanup_storage_artifacts(
                manifest,
                f"_storage/{backup.uuid}.zip",
                f"_storage/{backup.uuid}.log",
            )
        )

        with mock.patch.object(W, "create_zip") as create:
            with self.assertRaises(ArchiveSourcePolicyError) as context:
                W._finalize_zip(backup, tmp, keep_dir=True)

        self.assertEqual(context.exception.kind, "special")
        self.assertEqual(context.exception.relative_path, "updates.pipe")
        create.assert_not_called()
        self.assertFalse(os.path.exists(manifest))

    def test_manifest_ambiguous_name_is_rejected_before_archive_publication(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        with open(os.path.join(tmp, "line\nbreak.txt"), "w") as source:
            source.write("not representable in the line manifest")
        manifest = f"_storage/{backup.uuid}.files"
        self.addCleanup(
            _cleanup_storage_artifacts(
                manifest,
                f"_storage/{backup.uuid}.zip",
                f"_storage/{backup.uuid}.log",
            )
        )

        with mock.patch.object(W, "create_zip") as create:
            with self.assertRaises(ArchiveSourcePolicyError) as context:
                W._finalize_zip(backup, tmp, keep_dir=True)

        self.assertEqual(context.exception.kind, "invalid_path")
        create.assert_not_called()
        self.assertFalse(os.path.exists(manifest))

    def test_manifest_control_character_is_rejected_before_archive_publication(self):
        _node, backup = self._make_backup()
        tmp = self._tree()
        with open(os.path.join(tmp, "tab\tname.txt"), "w") as source:
            source.write("not portable across supported website protocols")
        manifest = f"_storage/{backup.uuid}.files"
        self.addCleanup(
            _cleanup_storage_artifacts(
                manifest,
                f"_storage/{backup.uuid}.zip",
                f"_storage/{backup.uuid}.log",
            )
        )

        with mock.patch.object(W, "create_zip") as create:
            with self.assertRaises(ArchiveSourcePolicyError) as context:
                W._finalize_zip(backup, tmp, keep_dir=True)

        self.assertEqual(context.exception.kind, "invalid_path")
        create.assert_not_called()
        self.assertFalse(os.path.exists(manifest))
