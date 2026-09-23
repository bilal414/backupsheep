import base64
import hashlib
import socket
import struct
from unittest import mock

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth.models import Group, Permission
from django.core import signing
from django.db import (
    DatabaseError,
    IntegrityError,
    connection as database_connection,
    transaction,
)
from django.test import SimpleTestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.console.account.models import CoreAccountGroup
from apps.console.connection.models import (
    CoreSSHHostKeyApproval,
    CoreSSHHostKeyApprovalEvent,
)
from apps.console.connection.ssh import (
    STRICT_AUTH_KEY_ALGORITHMS,
    STRICT_CIPHERS,
    STRICT_HOST_KEY_ALGORITHMS,
    STRICT_KEX_ALGORITHMS,
    STRICT_MACS,
    SSHHostKeyScanError,
    _strict_transport,
    scan_host_key,
    validate_ssh_public_key,
)
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


PREVIEW_URL = "/api/v1/utils/ssh-host-keys/preview/"
APPROVE_URL = "/api/v1/utils/ssh-host-keys/approve/"
REVOKE_URL = "/api/v1/utils/ssh-host-keys/revoke/"


def _wire_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ed25519_key():
    public_bytes = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    blob = _wire_string(b"ssh-ed25519") + _wire_string(public_bytes)
    return paramiko.PKey.from_type_string("ssh-ed25519", blob)


class SSHHostKeyScannerTests(SimpleTestCase):
    def test_transport_pins_exact_reviewed_algorithms_and_strict_kex(self):
        security = mock.Mock()
        transport = mock.Mock()
        transport.get_security_options.return_value = security
        transport._key_info = {
            algorithm: object() for algorithm in STRICT_AUTH_KEY_ALGORITHMS
        }
        raw_socket = object()
        disabled = {"keys": ["ssh-rsa"]}

        with mock.patch(
            "apps.console.connection.ssh.paramiko.Transport",
            return_value=transport,
        ) as transport_class:
            returned = _strict_transport(
                raw_socket,
                disabled_algorithms=disabled,
            )

        self.assertIs(returned, transport)
        transport_class.assert_called_once_with(
            raw_socket,
            disabled_algorithms=disabled,
            strict_kex=True,
        )
        self.assertEqual(security.kex, STRICT_KEX_ALGORITHMS)
        self.assertEqual(security.ciphers, STRICT_CIPHERS)
        self.assertEqual(security.digests, STRICT_MACS)
        self.assertEqual(security.key_types, STRICT_HOST_KEY_ALGORITHMS)
        self.assertEqual(security.compression, ("none",))
        self.assertEqual(transport._preferred_pubkeys, STRICT_AUTH_KEY_ALGORITHMS)

    def test_transport_fails_closed_when_library_algorithm_is_missing(self):
        transport = mock.Mock()
        transport.get_security_options.return_value = mock.Mock()
        transport._key_info = {
            algorithm: object()
            for algorithm in STRICT_AUTH_KEY_ALGORITHMS
            if algorithm != "ssh-ed25519"
        }
        with mock.patch(
            "apps.console.connection.ssh.paramiko.Transport",
            return_value=transport,
        ):
            with self.assertRaisesRegex(ValueError, "policy is unavailable"):
                _strict_transport(object())
        transport.close.assert_called_once_with()

    def test_public_key_strength_policy_is_exact(self):
        accepted = (
            ("ssh-ed25519", 256),
            ("ecdsa-sha2-nistp256", 256),
            ("ecdsa-sha2-nistp384", 384),
            ("ecdsa-sha2-nistp521", 521),
            ("ssh-rsa", 3072),
            ("ssh-rsa", 16384),
        )
        rejected = (
            ("ssh-rsa", 2048),
            ("ssh-rsa", 16385),
            ("ssh-dss", 1024),
            ("ecdsa-sha2-nistp256", 384),
            ("ecdsa-sha2-nistp384", 256),
            ("ecdsa-sha2-nistp521", 512),
        )
        for key_type, bits in accepted:
            with self.subTest(accepted=(key_type, bits)):
                validate_ssh_public_key(
                    mock.Mock(
                        get_name=mock.Mock(return_value=key_type),
                        get_bits=mock.Mock(return_value=bits),
                    )
                )
        for key_type, bits in rejected:
            with self.subTest(rejected=(key_type, bits)):
                with self.assertRaisesRegex(ValueError, "not permitted"):
                    validate_ssh_public_key(
                        mock.Mock(
                            get_name=mock.Mock(return_value=key_type),
                            get_bits=mock.Mock(return_value=bits),
                        )
                    )

    def test_scanner_is_bounded_strict_and_does_not_authenticate(self):
        raw_socket = mock.Mock()
        transport = mock.Mock()
        key = _ed25519_key()
        transport.get_remote_server_key.return_value = key
        transport.host_key_type = "ssh-ed25519"
        with mock.patch(
            "apps.console.connection.ssh.socket.create_connection",
            return_value=raw_socket,
        ) as create_connection, mock.patch(
            "apps.console.connection.ssh.strict_transport_factory",
            return_value=transport,
        ) as transport_factory:
            result = scan_host_key("backup.example.test", 2222, timeout=7)

        self.assertIs(result.key, key)
        self.assertEqual(result.wire_key_type, "ssh-ed25519")
        self.assertEqual(result.negotiated_host_key_algorithm, "ssh-ed25519")
        self.assertEqual(result.bits, 256)
        create_connection.assert_called_once_with(
            ("backup.example.test", 2222), timeout=7.0
        )
        raw_socket.settimeout.assert_called_once_with(7.0)
        transport_factory.assert_called_once_with(raw_socket)
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


@override_settings(SSH_HOST_KEY_APPROVAL_TOKEN_MAX_AGE=600)
class SSHHostKeyApprovalAPITests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.host = "backup.example.test"
        self.port = 2222
        self.key = _ed25519_key()
        self.other_key = _ed25519_key()

    @staticmethod
    def _scan_result(host, port, key):
        from apps.api.v1.utils.ssh_host_keys import ScannedHostKey, _fingerprint

        return ScannedHostKey(
            host=host,
            port=port,
            key_type=key.get_name(),
            negotiated_host_key_algorithm="ssh-ed25519",
            bits=key.get_bits(),
            fingerprint=_fingerprint(key),
            key=key,
        )

    def _patch_scan(self, *keys):
        scanned = list(keys)

        def fake_scan(host, port):
            key = scanned.pop(0) if scanned else keys[-1]
            return self._scan_result(host, port, key)

        return mock.patch(
            "apps.api.v1.utils.ssh_host_keys.scan_remote_host_key",
            side_effect=fake_scan,
        )

    def _preview(self, *, client=None, key=None):
        client = client or self.client
        key = key or self.key
        with self._patch_scan(key):
            response = client.post(
                PREVIEW_URL,
                {"host": self.host, "port": self.port},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        return response.json()

    def _approve(self, preview, *, client=None, key=None, replace=False, fingerprint=None):
        client = client or self.client
        key = key or self.key
        with self._patch_scan(key):
            return client.post(
                APPROVE_URL,
                {
                    "approval_token": preview["approval_token"],
                    "fingerprint": fingerprint or preview["fingerprint"],
                    "replace": replace,
                },
                format="json",
            )

    def test_authentication_and_integration_changes_permission_are_required(self):
        anonymous = APIClient().post(
            PREVIEW_URL,
            {"host": self.host, "port": self.port},
            format="json",
        )
        self.assertIn(
            anonymous.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )

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
        enrollment.group.permissions.set(
            Permission.objects.filter(codename="backup_download")
        )
        restricted_user.groups.add(group)
        restricted_client = APIClient()
        restricted_client.force_authenticate(user=restricted_user)
        denied = restricted_client.post(
            PREVIEW_URL,
            {"host": self.host, "port": self.port},
            format="json",
        )
        self.assertEqual(denied.status_code, status.HTTP_403_FORBIDDEN)

    def test_preview_returns_bound_versioned_exact_witness(self):
        preview = self._preview()
        self.assertEqual(
            set(preview),
            {
                "host",
                "port",
                "key_type",
                "negotiated_host_key_algorithm",
                "bits",
                "fingerprint",
                "status",
                "approval_token",
                "replace_required",
            },
        )
        self.assertEqual(preview["host"], self.host)
        self.assertEqual(preview["port"], self.port)
        self.assertEqual(preview["key_type"], "ssh-ed25519")
        self.assertEqual(preview["negotiated_host_key_algorithm"], "ssh-ed25519")
        self.assertEqual(preview["bits"], 256)
        self.assertTrue(preview["fingerprint"].startswith("SHA256:"))
        self.assertEqual(preview["status"], "unknown")
        self.assertFalse(preview["replace_required"])
        payload = signing.TimestampSigner(
            salt="backupsheep.ssh-host-key-approval.v2"
        ).unsign_object(preview["approval_token"], max_age=600)
        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["account_id"], str(self.account.pk))
        self.assertEqual(payload["user_id"], str(self.user.pk))
        self.assertRegex(payload["local_approval_witness"], r"^[0-9a-f]{64}$")

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
        group = Group.objects.create(name="ssh-integration-editor")
        enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=group,
            name="SSH integration editor",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        enrollment.group.permissions.set(
            Permission.objects.filter(codename="integration_changes")
        )
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
        preview = self._preview(key=self.key)
        response = self._approve(preview, key=self.other_key)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "host_key_changed")
        self.assertFalse(
            CoreSSHHostKeyApproval.objects.filter(
                account=self.account,
                normalized_host=self.host,
                port=self.port,
            ).exists()
        )

    def test_approval_is_account_scoped_idempotent_and_append_only_audited(self):
        first_preview = self._preview()
        first = self._approve(first_preview)
        self.assertEqual(first.status_code, status.HTTP_200_OK, first.content)
        self.assertEqual(first.json()["status"], "approved")
        self.assertEqual(first.json()["approval_generation"], 1)
        approval = CoreSSHHostKeyApproval.objects.get(
            account=self.account,
            normalized_host=self.host,
            port=self.port,
        )
        self.assertEqual(approval.public_key_base64, self.key.get_base64())
        event = CoreSSHHostKeyApprovalEvent.objects.get(
            approval_pk_snapshot=approval.pk,
            generation=1,
            action=CoreSSHHostKeyApprovalEvent.Action.APPROVE,
        )
        self.assertEqual(event.account_pk_snapshot, self.account.pk)
        self.assertEqual(event.actor_kind, CoreSSHHostKeyApprovalEvent.ActorKind.MEMBER)
        self.assertEqual(event.actor_member_pk_snapshot, self.member.pk)
        self.assertEqual(event.actor_user_pk_snapshot, self.user.pk)
        self.assertEqual(event.old_fingerprint, "")
        self.assertEqual(event.new_fingerprint, approval.fingerprint)

        second_preview = self._preview()
        self.assertEqual(second_preview["status"], "already_approved")
        second = self._approve(second_preview)
        self.assertEqual(second.status_code, status.HTTP_200_OK, second.content)
        self.assertEqual(second.json()["status"], "already_approved")
        self.assertEqual(
            CoreSSHHostKeyApprovalEvent.objects.filter(
                approval_pk_snapshot=approval.pk
            ).count(),
            1,
        )

        with transaction.atomic(), self.assertRaises(IntegrityError):
            event.delete()

    def test_same_endpoint_isolated_between_tenants(self):
        self._approve(self._preview(key=self.key), key=self.key)
        other_account, _other_member, other_user = factories.make_account(
            email="ssh-other-account@example.test"
        )
        other_client = APIClient()
        other_client.force_authenticate(user=other_user)
        other_preview = self._preview(client=other_client, key=self.other_key)
        other_approved = self._approve(
            other_preview,
            client=other_client,
            key=self.other_key,
        )
        self.assertEqual(other_approved.status_code, status.HTTP_200_OK)

        approvals = CoreSSHHostKeyApproval.objects.filter(
            normalized_host=self.host,
            port=self.port,
        ).order_by("account_id")
        self.assertEqual(approvals.count(), 2)
        first = approvals.get(account=self.account)
        second = approvals.get(account=other_account)
        self.assertNotEqual(first.public_key_base64, second.public_key_base64)
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(
            CoreSSHHostKeyApprovalEvent.objects.filter(
                account_pk_snapshot=self.account.pk
            ).count(),
            1,
        )
        self.assertEqual(
            CoreSSHHostKeyApprovalEvent.objects.filter(
                account_pk_snapshot=other_account.pk
            ).count(),
            1,
        )

    def test_changed_key_requires_replace_and_records_generation_transition(self):
        self._approve(self._preview(key=self.key), key=self.key)
        preview = self._preview(key=self.other_key)
        self.assertEqual(preview["status"], "changed")
        self.assertTrue(preview["replace_required"])

        refused = self._approve(preview, key=self.other_key)
        self.assertEqual(refused.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(refused.json()["code"], "host_key_changed")

        replaced = self._approve(preview, key=self.other_key, replace=True)
        self.assertEqual(replaced.status_code, status.HTTP_200_OK, replaced.content)
        self.assertEqual(replaced.json()["status"], "approved")
        self.assertEqual(replaced.json()["approval_generation"], 2)
        approval = CoreSSHHostKeyApproval.objects.get(
            account=self.account,
            normalized_host=self.host,
            port=self.port,
        )
        self.assertEqual(approval.public_key_base64, self.other_key.get_base64())
        replacement = CoreSSHHostKeyApprovalEvent.objects.get(
            approval_pk_snapshot=approval.pk,
            generation=2,
            action=CoreSSHHostKeyApprovalEvent.Action.REPLACE,
        )
        self.assertNotEqual(replacement.old_fingerprint, replacement.new_fingerprint)
        self.assertEqual(replacement.new_fingerprint, approval.fingerprint)

    def test_revoke_is_idempotent_and_records_application_actor_without_live_scan(self):
        approved = self._approve(self._preview(), key=self.key)
        approval = CoreSSHHostKeyApproval.objects.get(
            account=self.account,
            normalized_host=self.host,
            port=self.port,
        )
        with mock.patch(
            "apps.api.v1.utils.ssh_host_keys.scan_remote_host_key"
        ) as scan:
            revoked = self.client.post(
                REVOKE_URL,
                {"host": self.host, "port": self.port},
                format="json",
            )
        scan.assert_not_called()
        self.assertEqual(approved.status_code, status.HTTP_200_OK)
        self.assertEqual(revoked.status_code, status.HTTP_200_OK, revoked.content)
        self.assertEqual(revoked.json()["status"], "revoked")
        self.assertFalse(
            CoreSSHHostKeyApproval.objects.filter(pk=approval.pk).exists()
        )
        event = CoreSSHHostKeyApprovalEvent.objects.get(
            approval_pk_snapshot=approval.pk,
            generation=2,
            action=CoreSSHHostKeyApprovalEvent.Action.REVOKE,
        )
        self.assertEqual(event.account_pk_snapshot, self.account.pk)
        self.assertEqual(
            event.actor_kind, CoreSSHHostKeyApprovalEvent.ActorKind.APPLICATION
        )
        self.assertIsNone(event.actor_member_pk_snapshot)
        self.assertIsNone(event.actor_user_pk_snapshot)
        self.assertEqual(event.old_fingerprint, approval.fingerprint)
        self.assertEqual(event.new_fingerprint, "")

        again = self.client.post(
            REVOKE_URL,
            {"host": self.host, "port": self.port},
            format="json",
        )
        self.assertEqual(again.status_code, status.HTTP_200_OK)
        self.assertEqual(again.json()["status"], "already_revoked")
        self.assertEqual(
            CoreSSHHostKeyApprovalEvent.objects.filter(
                approval_pk_snapshot=approval.pk
            ).count(),
            2,
        )

    def test_audit_log_contains_fingerprint_but_never_key_material(self):
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


class SSHHostKeyApprovalDatabaseGuardTests(BaseTestCase):
    def _evidence(self, marker):
        raw = (str(marker).encode("ascii") + b"-approval-evidence").ljust(32, b"x")
        return {
            "public_key_base64": base64.b64encode(raw).decode("ascii"),
            "fingerprint": "SHA256:"
            + base64.b64encode(hashlib.sha256(raw).digest())
            .decode("ascii")
            .rstrip("="),
        }

    def _approval(self, marker, **overrides):
        values = {
            "account": self.account,
            "normalized_host": f"guard-{marker}.example.test",
            "port": 22,
            "wire_key_type": "ssh-ed25519",
            "negotiated_host_key_algorithm": "ssh-ed25519",
            "bits": 256,
            "approved_by_member_pk_snapshot": self.member.pk,
            "approved_by_user_pk_snapshot": self.user.pk,
            **self._evidence(marker),
        }
        values.update(overrides)
        return CoreSSHHostKeyApproval.objects.create(**values)

    def test_database_accepts_only_supported_exact_algorithm_evidence(self):
        accepted = (
            ("ed25519", "ssh-ed25519", "ssh-ed25519", 256),
            ("ecdsa256", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", 256),
            ("ecdsa384", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384", 384),
            ("ecdsa521", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521", 521),
            ("rsa256", "ssh-rsa", "rsa-sha2-256", 3072),
            ("rsa512", "ssh-rsa", "rsa-sha2-512", 16384),
        )
        for marker, wire_type, negotiated, bits in accepted:
            with self.subTest(marker=marker):
                approval = self._approval(
                    marker,
                    wire_key_type=wire_type,
                    negotiated_host_key_algorithm=negotiated,
                    bits=bits,
                )
                event = CoreSSHHostKeyApprovalEvent.objects.get(
                    approval_pk_snapshot=approval.pk,
                    generation=1,
                    action=CoreSSHHostKeyApprovalEvent.Action.APPROVE,
                )
                self.assertEqual(event.new_wire_key_type, wire_type)
                self.assertEqual(event.new_negotiated_host_key_algorithm, negotiated)
                self.assertEqual(event.new_bits, bits)

    def test_database_rejects_algorithm_downgrades_and_corrupted_tuples(self):
        rejected = (
            (
                "rsa-sha1",
                {
                    "wire_key_type": "ssh-rsa",
                    "negotiated_host_key_algorithm": "ssh-rsa",
                    "bits": 3072,
                },
            ),
            (
                "dss",
                {
                    "wire_key_type": "ssh-dss",
                    "negotiated_host_key_algorithm": "ssh-dss",
                    "bits": 1024,
                },
            ),
            (
                "weak-rsa",
                {
                    "wire_key_type": "ssh-rsa",
                    "negotiated_host_key_algorithm": "rsa-sha2-512",
                    "bits": 2048,
                },
            ),
            (
                "oversize-rsa",
                {
                    "wire_key_type": "ssh-rsa",
                    "negotiated_host_key_algorithm": "rsa-sha2-512",
                    "bits": 16385,
                },
            ),
            (
                "curve-mismatch",
                {
                    "wire_key_type": "ecdsa-sha2-nistp256",
                    "negotiated_host_key_algorithm": "ecdsa-sha2-nistp384",
                    "bits": 256,
                },
            ),
            (
                "curve-bits",
                {
                    "wire_key_type": "ecdsa-sha2-nistp384",
                    "negotiated_host_key_algorithm": "ecdsa-sha2-nistp384",
                    "bits": 256,
                },
            ),
            ("malformed-base64", {"public_key_base64": "not*valid*base64=="}),
            ("oversize-base64", {"public_key_base64": "A" * 16388}),
            ("malformed-fingerprint", {"fingerprint": "SHA256:not-a-digest"}),
        )
        for marker, overrides in rejected:
            with self.subTest(marker=marker):
                with self.assertRaises(IntegrityError), transaction.atomic():
                    self._approval(marker, **overrides)
                self.assertFalse(
                    CoreSSHHostKeyApproval.objects.filter(
                        normalized_host=f"guard-{marker}.example.test"
                    ).exists()
                )

    def test_database_rejects_direct_delete_even_with_forged_session_gucs(self):
        actorless = self._approval("actorless-revoke")
        with self.assertRaises(DatabaseError), transaction.atomic():
            actorless.delete()
        self.assertTrue(
            CoreSSHHostKeyApproval.objects.filter(pk=actorless.pk).exists()
        )

        forged = self._approval("forged-revoke")
        with self.assertRaises(DatabaseError), transaction.atomic():
            with database_connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config(%s, %s, true)",
                    ("backupsheep.ssh_revoke_member_pk", str(self.member.pk)),
                )
                cursor.execute(
                    "SELECT set_config(%s, %s, true)",
                    ("backupsheep.ssh_revoke_user_pk", str(self.user.pk)),
                )
            forged.delete()
        self.assertTrue(CoreSSHHostKeyApproval.objects.filter(pk=forged.pk).exists())
        self.assertFalse(
            CoreSSHHostKeyApprovalEvent.objects.filter(
                approval_pk_snapshot=forged.pk,
                action=CoreSSHHostKeyApprovalEvent.Action.REVOKE,
            ).exists()
        )

    def test_database_revoke_routine_records_only_authenticated_application(self):
        approval = self._approval("application-revoke")
        approval_pk = approval.pk
        with database_connection.cursor() as cursor:
            cursor.execute(
                "SELECT public.backupsheep_revoke_ssh_host_key_approval(%s, %s)",
                (approval.pk, self.account.pk),
            )
            self.assertEqual(cursor.fetchone(), (True,))

        event = CoreSSHHostKeyApprovalEvent.objects.get(
            approval_pk_snapshot=approval_pk,
            generation=2,
            action=CoreSSHHostKeyApprovalEvent.Action.REVOKE,
        )
        self.assertEqual(
            event.actor_kind,
            CoreSSHHostKeyApprovalEvent.ActorKind.APPLICATION,
        )
        self.assertIsNone(event.actor_member_pk_snapshot)
        self.assertIsNone(event.actor_user_pk_snapshot)

    def test_database_attributes_no_guc_account_cascade_to_system(self):
        approval = self._approval("system-cascade")
        approval_pk = approval.pk
        account_pk = self.account.pk
        self.account.delete()

        event = CoreSSHHostKeyApprovalEvent.objects.get(
            approval_pk_snapshot=approval_pk,
            account_pk_snapshot=account_pk,
            generation=2,
            action=CoreSSHHostKeyApprovalEvent.Action.REVOKE,
        )
        self.assertEqual(
            event.actor_kind,
            CoreSSHHostKeyApprovalEvent.ActorKind.SYSTEM,
        )
        self.assertIsNone(event.actor_member_pk_snapshot)
        self.assertIsNone(event.actor_user_pk_snapshot)
