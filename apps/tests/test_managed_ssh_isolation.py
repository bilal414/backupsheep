import base64
import hashlib
import json
import struct
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps._tasks.managed_ssh import (
    validate_managed_ssh_database_connection,
    validate_managed_ssh_files_connection,
)
from apps.api.v1.connection.website.serializers import CoreAuthWebsiteWriteSerializer
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.connection.managed_ssh import (
    ManagedSSHOperationError,
    create_managed_ssh_operation,
    managed_public_key_fingerprint,
    managed_public_key_for_lane,
    validate_operation_intent,
)
from apps.console.connection.models import (
    CoreAuthDatabase,
    CoreAuthWebsite,
    CoreConnection,
    CoreManagedSSHOperation,
    CoreSSHHostKeyApproval,
)
from apps.console.connection.ssh import managed_private_key_path
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _wire_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ed25519_public_key(marker: bytes, comment: str) -> tuple[str, bytes]:
    blob = _wire_string(b"ssh-ed25519") + _wire_string(marker * 32)
    return (
        "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {comment}",
        blob,
    )


DATABASE_MANAGED_PUBLIC_KEY, DATABASE_PUBLIC_BLOB = _ed25519_public_key(
    b"d", "database-lane"
)
FILES_MANAGED_PUBLIC_KEY, FILES_PUBLIC_BLOB = _ed25519_public_key(
    b"f", "files-lane"
)
HOST_PUBLIC_KEY, HOST_PUBLIC_BLOB = _ed25519_public_key(b"h", "host-key")
HOST_PUBLIC_KEY_BASE64 = HOST_PUBLIC_KEY.split()[1]
HOST_FINGERPRINT = "SHA256:" + base64.b64encode(
    hashlib.sha256(HOST_PUBLIC_BLOB).digest()
).decode("ascii").rstrip("=")


MANAGED_KEY_SETTINGS = {
    "SSH_MANAGED_PUBLIC_KEY": "",
    "SSH_MANAGED_DATABASE_PUBLIC_KEY": DATABASE_MANAGED_PUBLIC_KEY,
    "SSH_MANAGED_FILES_PUBLIC_KEY": FILES_MANAGED_PUBLIC_KEY,
    "SSH_MANAGED_LANE_ISOLATION_REQUIRED": True,
}


@override_settings(**MANAGED_KEY_SETTINGS)
class ManagedSSHIsolationTests(BaseTestCase):
    def _approve_host(self, host, port):
        return CoreSSHHostKeyApproval.objects.create(
            account=self.account,
            normalized_host=host,
            port=port,
            wire_key_type="ssh-ed25519",
            public_key_base64=HOST_PUBLIC_KEY_BASE64,
            fingerprint=HOST_FINGERPRINT,
            negotiated_host_key_algorithm="ssh-ed25519",
            bits=256,
            approved_by_member_pk_snapshot=self.member.pk,
            approved_by_user_pk_snapshot=self.user.pk,
        )

    def _database_connection(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
            name="managed database",
        )
        key = self.account.get_encryption_key()
        CoreAuthDatabase.objects.create(
            connection=connection,
            host="database.internal.test",
            port=5432,
            database_name="application",
            all_databases=False,
            username=bs_encrypt("database-user", key),
            password=bs_encrypt("database-password", key),
            type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version=CoreAuthDatabase.DatabaseVersion.POSTGRESQL_16,
            ssh_host="bastion.internal.test",
            ssh_port=22,
            ssh_username=bs_encrypt("ssh-user", key),
            ssh_password=None,
            private_key=None,
            use_public_key=True,
            use_private_key=False,
        )
        self._approve_host("bastion.internal.test", 22)
        return connection

    def _website_connection(self, *, name="managed website"):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="website",
            name=name,
        )
        key = self.account.get_encryption_key()
        CoreAuthWebsite.objects.create(
            connection=connection,
            host="website.internal.test",
            port=22,
            protocol=CoreAuthWebsite.Protocol.SFTP,
            username=bs_encrypt("website-user", key),
            password=None,
            private_key=None,
            use_public_key=True,
            use_private_key=False,
        )
        if not CoreSSHHostKeyApproval.objects.filter(
            account=self.account,
            normalized_host="website.internal.test",
            port=22,
        ).exists():
            self._approve_host("website.internal.test", 22)
        return connection

    def test_operation_reserves_exact_task_without_connection_secrets(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ) as send_task:
            with self.captureOnCommitCallbacks(execute=True):
                operation = create_managed_ssh_operation(
                    connection,
                    "validate",
                    requested_by_member=self.member,
                )

        connection.refresh_from_db()
        self.assertEqual(connection.status, CoreConnection.Status.PENDING)
        self.assertEqual(operation.source_lane, "database")
        self.assertEqual(
            operation.managed_public_key_fingerprint,
            hashlib.sha256(DATABASE_PUBLIC_BLOB).hexdigest(),
        )
        self.assertEqual(operation.status, CoreManagedSSHOperation.Status.PENDING)
        send_task.assert_called_once()
        task_name = send_task.call_args.args[0]
        task_kwargs = send_task.call_args.kwargs
        self.assertEqual(task_name, "validate_managed_ssh_database_connection")
        self.assertEqual(task_kwargs["args"], (operation.pk,))
        self.assertEqual(task_kwargs["task_id"], str(operation.celery_task_id))
        serialized_call = repr(send_task.call_args)
        self.assertNotIn("database-password", serialized_call)
        self.assertNotIn("ssh-user", serialized_call)
        self.assertNotIn("bastion.internal.test", serialized_call)

    def test_changed_connection_is_rejected_before_worker_network_access(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            operation = create_managed_ssh_operation(
                connection,
                "validate",
                requested_by_member=self.member,
            )
        auth = connection.auth_database
        auth.ssh_host = "attacker.example.test"
        auth.save(update_fields=("ssh_host",))

        operation = CoreManagedSSHOperation.objects.select_related(
            "connection__integration"
        ).get(pk=operation.pk)
        with self.assertRaisesRegex(
            ManagedSSHOperationError, "connection (?:generation )?changed"
        ):
            validate_operation_intent(operation)

    def test_database_worker_completes_validation_and_activates_connection(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            operation = create_managed_ssh_operation(
                connection,
                "validate",
                requested_by_member=self.member,
            )
        with mock.patch.object(
            CoreAuthDatabase, "check_connection", return_value=True
        ) as check_connection:
            validate_managed_ssh_database_connection.run(operation.pk)

        operation.refresh_from_db()
        connection.refresh_from_db()
        check_connection.assert_called_once_with(check_errors=True)
        self.assertEqual(operation.status, CoreManagedSSHOperation.Status.COMPLETE)
        self.assertEqual(operation.result_payload, {"valid": True})
        self.assertRegex(operation.result_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(operation.execution_witness_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(connection.status, CoreConnection.Status.ACTIVE)

    def test_pending_operation_is_not_reused_after_member_user_identity_changes(self):
        connection = self._website_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            first = create_managed_ssh_operation(
                connection,
                "validate",
                requested_by_member=self.member,
            )
            replacement_user = get_user_model().objects.create_user(
                username="replacement-managed-actor@example.test",
                email="replacement-managed-actor@example.test",
                password="x-Secret-123",
            )
            self.member.user = replacement_user
            self.member.save(update_fields=("user",))
            second = create_managed_ssh_operation(
                connection,
                "validate",
                requested_by_member=self.member,
            )

        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(first.requested_by_user_pk_snapshot, self.user.pk)
        self.assertEqual(second.requested_by_user_pk_snapshot, replacement_user.pk)
        self.assertEqual(
            second.request_actor_kind,
            CoreManagedSSHOperation.ActorKind.MEMBER,
        )
        self.assertEqual(second.request_source, "api")

    def test_wrong_worker_lane_fails_closed_without_using_key(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            operation = create_managed_ssh_operation(
                connection,
                "validate",
                requested_by_member=self.member,
            )
        with mock.patch.object(CoreAuthDatabase, "check_connection") as check:
            validate_managed_ssh_files_connection.run(operation.pk)

        operation.refresh_from_db()
        connection.refresh_from_db()
        check.assert_not_called()
        self.assertEqual(operation.status, CoreManagedSSHOperation.Status.FAILED)
        self.assertEqual(connection.status, CoreConnection.Status.SUSPENDED)
        self.assertEqual(operation.result_payload, {})
        self.assertNotIn("database.internal.test", repr(operation.error_payload))

    def test_website_public_key_serializer_never_opens_managed_key_in_web(self):
        serializer = CoreAuthWebsiteWriteSerializer(
            data={
                "host": "website.internal.test",
                "port": 22,
                "protocol": CoreAuthWebsite.Protocol.SFTP,
                "username": "website-user",
                "use_public_key": True,
                "use_private_key": False,
            },
            context={
                "encryption_key": self.account.get_encryption_key(),
                "request": SimpleNamespace(user=self.user),
            },
        )
        with mock.patch.object(CoreAuthWebsite, "check_connection") as check:
            self.assertTrue(serializer.is_valid(), serializer.errors)
        check.assert_not_called()

    def test_second_account_without_connections_blocks_worker_private_key_load(self):
        self._website_connection()
        factories.make_account(email="managed-key-second-tenant@example.test")

        with mock.patch("apps.console.connection.ssh.os.path.isfile") as is_file:
            with self.assertRaisesRegex(
                ManagedSSHOperationError, "single-account installation"
            ):
                managed_private_key_path(account_id=self.account.pk)
        is_file.assert_not_called()


@override_settings(**MANAGED_KEY_SETTINGS)
class ManagedSSHAPIContractTests(ManagedSSHIsolationTests):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def assert_private_no_store(self, response):
        directives = {
            directive.strip()
            for directive in response["Cache-Control"].split(",")
        }
        self.assertIn("private", directives)
        self.assertIn("no-store", directives)

    def test_managed_actions_are_post_only_and_status_is_scoped_no_store(self):
        connection = self._website_connection()
        validate_url = f"/api/v1/connections/website/{connection.pk}/validate/"
        objects_url = f"/api/v1/connections/website/{connection.pk}/objects/"

        self.assertEqual(
            self.client.get(validate_url).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.get(objects_url).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            with self.captureOnCommitCallbacks(execute=True):
                accepted = self.client.post(validate_url, {}, format="json")

        self.assertEqual(accepted.status_code, status.HTTP_202_ACCEPTED, accepted.content)
        self.assert_private_no_store(accepted)
        payload = accepted.json()
        self.assertEqual(payload["operation_status"], "pending")
        operation_url = (
            f"/api/v1/connections/website/{connection.pk}/"
            f"managed-ssh-operations/{payload['operation_id']}/"
        )
        observed = self.client.get(operation_url)
        self.assertEqual(observed.status_code, status.HTTP_200_OK, observed.content)
        self.assert_private_no_store(observed)

        other_connection = self._website_connection(name="another managed website")
        wrong_connection = self.client.get(
            f"/api/v1/connections/website/{other_connection.pk}/"
            f"managed-ssh-operations/{payload['operation_id']}/"
        )
        self.assertEqual(wrong_connection.status_code, status.HTTP_404_NOT_FOUND)
        self.assert_private_no_store(wrong_connection)

        invalid_uuid = self.client.get(
            f"/api/v1/connections/website/{connection.pk}/"
            "managed-ssh-operations/not-a-uuid/"
        )
        self.assertEqual(invalid_uuid.status_code, status.HTTP_404_NOT_FOUND)
        self.assert_private_no_store(invalid_uuid)

        other_account, other_member, _other_user = factories.make_account()
        other_tenant = factories.make_connection(
            other_account,
            other_member,
            code="website",
            name="other tenant",
        )
        hidden = self.client.get(
            f"/api/v1/connections/website/{other_tenant.pk}/"
            f"managed-ssh-operations/{payload['operation_id']}/"
        )
        self.assertEqual(hidden.status_code, status.HTTP_404_NOT_FOUND)

    def test_second_account_cannot_target_first_accounts_managed_ssh_principal(self):
        first_connection = self._website_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            first_operation = create_managed_ssh_operation(
                first_connection,
                "validate",
                requested_by_member=self.member,
            )

        other_account, other_member, other_user = factories.make_account()
        other_connection = factories.make_connection(
            other_account,
            other_member,
            code="website",
            name="cross-tenant managed principal",
        )
        other_key = other_account.get_encryption_key()
        CoreAuthWebsite.objects.create(
            connection=other_connection,
            host=first_connection.auth_website.host,
            port=first_connection.auth_website.port,
            protocol=CoreAuthWebsite.Protocol.SFTP,
            username=bs_encrypt("website-user", other_key),
            password=bs_encrypt("temporary-password", other_key),
            private_key=None,
            use_public_key=False,
            use_private_key=False,
        )

        first_operation.pk = None
        first_operation.uuid = uuid.uuid4()
        first_operation.celery_task_id = uuid.uuid4()
        first_operation.idempotency_key = "f" * 64
        with self.assertRaises(IntegrityError), transaction.atomic():
            first_operation.save(force_insert=True)

        with self.assertRaisesRegex(
            ManagedSSHOperationError, "single-account installation"
        ):
            create_managed_ssh_operation(
                other_connection,
                "validate",
                requested_by_member=other_member,
            )

        self.client.force_authenticate(user=other_user)
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ) as send_task, mock.patch.object(CoreAuthWebsite, "check_connection") as check:
            denied = self.client.post(
                "/api/v1/connections/website/",
                {
                    "name": "cross-tenant managed principal API attempt",
                    "location": other_connection.location_id,
                    "auth_website": {
                        "host": first_connection.auth_website.host,
                        "port": first_connection.auth_website.port,
                        "protocol": CoreAuthWebsite.Protocol.SFTP,
                        "username": "website-user",
                        "use_public_key": True,
                        "use_private_key": False,
                    },
                },
                format="json",
            )

        self.assertEqual(denied.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(denied.status_code, status.HTTP_202_ACCEPTED)
        self.assertNotIn("website.internal.test", json.dumps(denied.json()))
        send_task.assert_not_called()
        check.assert_not_called()
        self.assertEqual(
            CoreManagedSSHOperation.objects.filter(
                account=other_account,
            ).count(),
            0,
        )
        self.assertFalse(
            CoreConnection.objects.filter(
                account=other_account,
                name="cross-tenant managed principal API attempt",
            ).exists()
        )
        self.assertEqual(first_operation.account_id, self.account.pk)

    def test_partial_managed_key_update_launches_durable_validation(self):
        connection = self._website_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            response = self.client.patch(
                f"/api/v1/connections/website/{connection.pk}/",
                {"auth_website": {"info_name": "renamed without auth mode"}},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.assert_private_no_store(response)
        payload = response.json()
        self.assertEqual(payload["validation_status"], "pending")
        operation = CoreManagedSSHOperation.objects.get(
            uuid=payload["operation_id"],
            connection=connection,
            source_lane=CoreManagedSSHOperation.SourceLane.FILES,
        )
        self.assertEqual(operation.operation, CoreManagedSSHOperation.Operation.VALIDATE)
        connection.refresh_from_db()
        self.assertEqual(connection.status, CoreConnection.Status.PENDING)

    def test_direct_validation_failure_saves_pending_and_retry_updates_same_row(self):
        location = factories.make_location("direct-validation-location")
        payload = {
            "name": "direct validation failure",
            "location": location.pk,
            "auth_website": {
                "host": "ftps.internal.test",
                "port": 990,
                "protocol": CoreAuthWebsite.Protocol.FTPS,
                "username": "direct-user",
                "password": "direct-password",
                "ftps_use_explicit_ssl": False,
                "verify_ssl": True,
                "use_public_key": False,
                "use_private_key": False,
            },
        }
        with mock.patch.object(
            CoreAuthWebsite,
            "check_connection",
            side_effect=TimeoutError("password=must-not-leak"),
        ):
            created = self.client.post(
                "/api/v1/connections/website/", payload, format="json"
            )

        self.assertEqual(created.status_code, status.HTTP_201_CREATED, created.content)
        self.assert_private_no_store(created)
        first = created.json()
        self.assertEqual(first["validation_status"], "failed")
        self.assertIn("saved as pending", first["detail"].lower())
        self.assertNotIn("must-not-leak", json.dumps(first))
        connection = CoreConnection.objects.get(pk=first["id"])
        self.assertEqual(connection.status, CoreConnection.Status.PENDING)

        with mock.patch.object(
            CoreAuthWebsite,
            "check_connection",
            side_effect=TimeoutError("password=must-not-leak-again"),
        ):
            retried = self.client.patch(
                f"/api/v1/connections/website/{connection.pk}/",
                {"auth_website": {"info_name": "retry same row"}},
                format="json",
            )

        self.assertEqual(retried.status_code, status.HTTP_200_OK, retried.content)
        self.assertEqual(retried.json()["validation_status"], "failed")
        self.assertEqual(
            CoreConnection.objects.filter(
                account=self.account,
                integration__code="website",
                name="direct validation failure",
            ).count(),
            1,
        )


class ManagedSSHPublicKeyTests(SimpleTestCase):
    def test_fingerprint_uses_wire_blob_not_comment(self):
        expected = hashlib.sha256(DATABASE_PUBLIC_BLOB).hexdigest()
        self.assertEqual(
            managed_public_key_fingerprint(DATABASE_MANAGED_PUBLIC_KEY), expected
        )
        self.assertEqual(
            managed_public_key_fingerprint(
                DATABASE_MANAGED_PUBLIC_KEY.rsplit(" ", 1)[0]
            ),
            expected,
        )

    def test_outer_and_wire_key_types_must_match(self):
        mismatched = DATABASE_MANAGED_PUBLIC_KEY.replace("ssh-ed25519 ", "ssh-rsa ", 1)
        with self.assertRaisesRegex(ManagedSSHOperationError, "does not match"):
            managed_public_key_fingerprint(mismatched)

    @override_settings(**MANAGED_KEY_SETTINGS)
    def test_database_and_files_lanes_have_distinct_required_identities(self):
        self.assertNotEqual(
            managed_public_key_for_lane("database"),
            managed_public_key_for_lane("files"),
        )
        self.assertNotEqual(
            managed_public_key_fingerprint(source_lane="database"),
            managed_public_key_fingerprint(source_lane="files"),
        )

    @override_settings(
        SSH_MANAGED_DATABASE_PUBLIC_KEY=DATABASE_MANAGED_PUBLIC_KEY,
        SSH_MANAGED_FILES_PUBLIC_KEY=DATABASE_MANAGED_PUBLIC_KEY,
        SSH_MANAGED_LANE_ISOLATION_REQUIRED=True,
    )
    def test_reused_lane_identity_fails_closed(self):
        with self.assertRaisesRegex(ManagedSSHOperationError, "must be different"):
            managed_public_key_for_lane("database")

    def test_compose_mounts_only_each_lane_private_key_and_never_web(self):
        compose = (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
        app_block = compose.split("\n  app:\n", 1)[1].split(
            "\n  cloud-egress-guard:", 1
        )[0]
        database_block = compose.split("\n  worker-database:\n", 1)[1].split(
            "\n  files-egress-guard:", 1
        )[0]
        files_block = compose.split("\n  worker-files:\n", 1)[1].split(
            "\n  storage-egress-guard:", 1
        )[0]
        for token in (
            "ssh_managed_private_key",
            "ssh_managed_database_private_key",
            "ssh_managed_files_private_key",
        ):
            self.assertNotIn(f"- {token}", app_block)
        self.assertIn("- ssh_managed_database_private_key", database_block)
        self.assertNotIn("- ssh_managed_files_private_key", database_block)
        self.assertIn("- ssh_managed_files_private_key", files_block)
        self.assertNotIn("- ssh_managed_database_private_key", files_block)
        for block in (app_block, database_block, files_block):
            self.assertNotIn("ssh_trust:/var/lib/backupsheep/ssh-trust", block)
