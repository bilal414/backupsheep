import os
import socket
import stat
import tempfile
from unittest import mock

import paramiko
from django.contrib.auth.models import Group, Permission
from django.core import signing
from django.test import SimpleTestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.console.account.models import CoreAccountGroup
from apps.console.connection.ssh import SSHHostKeyScanError, scan_host_key
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


PREVIEW_URL = "/api/v1/utils/ssh-host-keys/preview/"
APPROVE_URL = "/api/v1/utils/ssh-host-keys/approve/"


class SSHHostKeyScannerTests(SimpleTestCase):
    def test_scanner_is_bounded_and_does_not_authenticate(self):
        raw_socket = mock.Mock()
        transport = mock.Mock()
        key = paramiko.RSAKey.generate(1024)
        transport.get_remote_server_key.return_value = key
        with mock.patch(
            "apps.console.connection.ssh.socket.create_connection",
            return_value=raw_socket,
        ) as create_connection, mock.patch(
            "apps.console.connection.ssh.paramiko.Transport",
            return_value=transport,
        ) as transport_class:
            result = scan_host_key("backup.example.test", 2222, timeout=7)

        self.assertIs(result, key)
        create_connection.assert_called_once_with(
            ("backup.example.test", 2222), timeout=7.0
        )
        raw_socket.settimeout.assert_called_once_with(7.0)
        transport_class.assert_called_once_with(raw_socket)
        transport.start_client.assert_called_once_with(timeout=7.0)
        transport.auth_none.assert_not_called()
        transport.auth_password.assert_not_called()
        transport.auth_publickey.assert_not_called()
        transport.close.assert_called_once_with()

    def test_scanner_timeout_is_typed_and_safe(self):
        with mock.patch(
            "apps.console.connection.ssh.socket.create_connection",
            side_effect=socket.timeout("credential=not-returned"),
        ):
            with self.assertRaises(SSHHostKeyScanError) as raised:
                scan_host_key("backup.example.test", 2222, timeout=7)
        self.assertEqual(raised.exception.code, "ssh_timeout")
        self.assertEqual(raised.exception.status_code, 504)
        self.assertNotIn("not-returned", str(raised.exception))


class SSHHostKeyApprovalAPITests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.known_hosts_path = os.path.join(self.tmpdir.name, "ssh_known_hosts")
        self.settings_override = override_settings(
            SSH_KNOWN_HOSTS_PATH=self.known_hosts_path,
            SSH_HOST_KEY_APPROVAL_TOKEN_MAX_AGE=600,
        )
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.host = "backup.example.test"
        self.port = 2222
        self.key = paramiko.RSAKey.generate(1024)
        self.other_key = paramiko.RSAKey.generate(1024)

    def _patch_scan(self, *keys):
        scanned = []
        for key in keys:
            scanned.append(key)

        def fake_scan(host, port):
            key = scanned.pop(0) if scanned else keys[-1]
            return self._scan_result(host, port, key)

        return mock.patch(
            "apps.api.v1.utils.ssh_host_keys.scan_remote_host_key",
            side_effect=fake_scan,
        )

    @staticmethod
    def _scan_result(host, port, key):
        from apps.api.v1.utils.ssh_host_keys import ScannedHostKey, _fingerprint

        return ScannedHostKey(
            host=host,
            port=port,
            key_type=key.get_name(),
            fingerprint=_fingerprint(key),
            key=key,
        )

    def _preview(self, patcher=None):
        patcher = patcher or self._patch_scan(self.key)
        with patcher:
            response = self.client.post(
                PREVIEW_URL,
                {"host": self.host, "port": self.port},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        return response.json()

    def _approve(self, preview, *, replace=False, patcher=None, fingerprint=None):
        patcher = patcher or self._patch_scan(self.key)
        with patcher:
            return self.client.post(
                APPROVE_URL,
                {
                    "approval_token": preview["approval_token"],
                    "fingerprint": fingerprint or preview["fingerprint"],
                    "replace": replace,
                },
                format="json",
            )

    def _write_known_key(self, key, host=None):
        known_hosts = paramiko.HostKeys()
        known_hosts.add(
            host or f"[{self.host}]:{self.port}", key.get_name(), key
        )
        known_hosts.save(self.known_hosts_path)
        os.chmod(self.known_hosts_path, 0o600)

    def test_authentication_and_node_changes_permission_are_required(self):
        anonymous = APIClient().post(
            PREVIEW_URL,
            {"host": self.host, "port": self.port},
            format="json",
        )
        self.assertIn(anonymous.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

        _account, restricted_member, restricted_user = factories.make_account(
            email="ssh-restricted@example.test"
        )
        restricted_member.memberships.filter(current=True, primary=True).update(
            current=False, primary=False
        )
        CoreMemberAccount.objects.create(
            member=restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        group = Group.objects.create(name="ssh-read-only")
        enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=group,
            name="SSH read only",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        enrollment.group.permissions.set(Permission.objects.filter(codename="backup_download"))
        restricted_client = APIClient()
        restricted_client.force_authenticate(user=restricted_user)
        denied = restricted_client.post(
            PREVIEW_URL,
            {"host": self.host, "port": self.port},
            format="json",
        )
        self.assertEqual(denied.status_code, status.HTTP_403_FORBIDDEN)

    def test_preview_returns_contract_and_account_user_bound_timestamp_token(self):
        preview = self._preview()
        self.assertEqual(
            set(preview),
            {
                "host",
                "port",
                "key_type",
                "fingerprint",
                "status",
                "approval_token",
                "replace_required",
            },
        )
        self.assertEqual(preview["host"], self.host)
        self.assertEqual(preview["port"], self.port)
        self.assertEqual(preview["key_type"], "ssh-rsa")
        self.assertTrue(preview["fingerprint"].startswith("SHA256:"))
        self.assertEqual(preview["status"], "unknown")
        self.assertFalse(preview["replace_required"])
        payload = signing.TimestampSigner(
            salt="backupsheep.ssh-host-key-approval.v1"
        ).unsign_object(preview["approval_token"], max_age=600)
        self.assertEqual(payload["account_id"], str(self.account.pk))
        self.assertEqual(payload["user_id"], str(self.user.pk))

    def test_tampered_and_expired_tokens_are_rejected_without_networking(self):
        preview = self._preview()
        tampered = self.client.post(
            APPROVE_URL,
            {
                "approval_token": preview["approval_token"] + "tampered",
                "fingerprint": preview["fingerprint"],
                "replace": False,
            },
            format="json",
        )
        self.assertEqual(tampered.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(tampered.json()["code"], "approval_invalid")

        with mock.patch.object(
            signing.TimestampSigner,
            "unsign_object",
            side_effect=signing.SignatureExpired("expired"),
        ):
            expired = self.client.post(
                APPROVE_URL,
                {
                    "approval_token": preview["approval_token"],
                    "fingerprint": preview["fingerprint"],
                    "replace": False,
                },
                format="json",
            )
        self.assertEqual(expired.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(expired.json()["code"], "approval_expired")

    def test_approval_token_cannot_be_used_by_another_member(self):
        preview = self._preview()
        _other_account, other_member, other_user = factories.make_account(
            email="ssh-other-member@example.test"
        )
        other_member.memberships.filter(current=True, primary=True).update(
            current=False, primary=False
        )
        CoreMemberAccount.objects.create(
            member=other_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        group = Group.objects.create(name="ssh-node-editor")
        enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=group,
            name="SSH node editor",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        enrollment.group.permissions.set(Permission.objects.filter(codename="node_changes"))
        other_user.groups.add(enrollment.group)
        other_client = APIClient()
        other_client.force_authenticate(user=other_user)
        response = other_client.post(
            APPROVE_URL,
            {
                "approval_token": preview["approval_token"],
                "fingerprint": preview["fingerprint"],
                "replace": False,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["code"], "approval_invalid")

    def test_approve_refetches_key_and_rejects_toctou_change(self):
        preview = self._preview(self._patch_scan(self.key))
        with self._patch_scan(self.other_key) as scan:
            response = self.client.post(
                APPROVE_URL,
                {
                    "approval_token": preview["approval_token"],
                    "fingerprint": preview["fingerprint"],
                    "replace": False,
                },
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "host_key_changed")
        self.assertFalse(os.path.exists(self.known_hosts_path))

    def test_unknown_approval_is_written_idempotently_with_atomic_0600_permissions(self):
        preview = self._preview()
        with mock.patch("apps.api.v1.utils.ssh_host_keys.os.replace", wraps=os.replace) as replace, \
             mock.patch("apps.api.v1.utils.ssh_host_keys.os.fsync", wraps=os.fsync) as fsync:
            first = self._approve(preview)
        self.assertEqual(first.status_code, status.HTTP_200_OK, first.content)
        self.assertEqual(
            set(first.json()),
            {"detail", "status", "host", "port", "key_type", "fingerprint"},
        )
        self.assertEqual(first.json()["status"], "approved")
        self.assertEqual(first.json()["host"], self.host)
        self.assertEqual(first.json()["port"], self.port)
        self.assertEqual(first.json()["key_type"], "ssh-rsa")
        self.assertGreaterEqual(replace.call_count, 1)
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertEqual(stat.S_IMODE(os.stat(self.known_hosts_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(f"{self.known_hosts_path}.lock").st_mode), 0o600)

        os.chmod(self.known_hosts_path, 0o644)
        with mock.patch("apps.api.v1.utils.ssh_host_keys.os.replace", wraps=os.replace) as repair_replace:
            second = self._approve(preview)
        self.assertEqual(second.status_code, status.HTTP_200_OK, second.content)
        self.assertEqual(second.json()["status"], "already_approved")
        self.assertEqual(repair_replace.call_count, 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.known_hosts_path).st_mode), 0o600)
        with open(self.known_hosts_path, "r", encoding="utf-8") as known_hosts:
            lines = [line for line in known_hosts if line.strip()]
        self.assertEqual(len(lines), 1)

    def test_changed_same_algorithm_requires_explicit_replacement(self):
        self._write_known_key(self.key)
        preview = self._preview(self._patch_scan(self.other_key))
        self.assertEqual(preview["status"], "changed")
        self.assertTrue(preview["replace_required"])

        refused = self._approve(preview, patcher=self._patch_scan(self.other_key))
        self.assertEqual(refused.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(refused.json()["code"], "host_key_changed")
        existing = paramiko.HostKeys(self.known_hosts_path)
        self.assertEqual(
            existing.lookup(f"[{self.host}]:{self.port}")["ssh-rsa"].get_base64(),
            self.key.get_base64(),
        )

        replaced = self._approve(
            preview, replace=True, patcher=self._patch_scan(self.other_key)
        )
        self.assertEqual(replaced.status_code, status.HTTP_200_OK, replaced.content)
        self.assertEqual(replaced.json()["status"], "approved")
        updated = paramiko.HostKeys(self.known_hosts_path)
        self.assertEqual(
            updated.lookup(f"[{self.host}]:{self.port}")["ssh-rsa"].get_base64(),
            self.other_key.get_base64(),
        )
        with open(self.known_hosts_path, "r", encoding="utf-8") as known_hosts:
            self.assertEqual(len([line for line in known_hosts if line.strip()]), 1)

    def test_audit_record_contains_fingerprint_but_never_key_material(self):
        preview = self._preview()
        response = self._approve(preview)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        log = CoreLog.objects.filter(
            account=self.account, type=CoreLog.Type.CONNECTION
        ).latest("created")
        self.assertEqual(log.data["action"], "ssh_host_key_approve")
        self.assertEqual(log.data["fingerprint"], preview["fingerprint"])
        self.assertNotIn("approval_token", log.data)
        self.assertNotIn(self.key.get_base64(), str(log.data))

    def test_scan_failures_return_typed_safe_errors(self):
        with mock.patch(
            "apps.api.v1.utils.ssh_host_keys.scan_remote_host_key",
            side_effect=RuntimeError("password=must-not-leak"),
        ):
            response = self.client.post(
                PREVIEW_URL,
                {"host": self.host, "port": self.port},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_502_BAD_GATEWAY)
        self.assertEqual(response.json()["code"], "ssh_scan_failed")
        self.assertNotIn("must-not-leak", response.content.decode())
