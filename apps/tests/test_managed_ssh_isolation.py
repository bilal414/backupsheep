import base64
import hashlib
import struct
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, override_settings

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
    validate_operation_intent,
)
from apps.console.connection.models import (
    CoreAuthDatabase,
    CoreAuthWebsite,
    CoreConnection,
    CoreManagedSSHOperation,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


def _wire_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


_PUBLIC_BLOB = _wire_string(b"ssh-ed25519") + _wire_string(b"m" * 32)
MANAGED_PUBLIC_KEY = (
    "ssh-ed25519 " + base64.b64encode(_PUBLIC_BLOB).decode("ascii") + " test-key"
)


@override_settings(SSH_MANAGED_PUBLIC_KEY=MANAGED_PUBLIC_KEY)
class ManagedSSHIsolationTests(BaseTestCase):
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
        return connection

    def _website_connection(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="website",
            name="managed website",
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
        return connection

    def test_operation_reserves_exact_task_without_connection_secrets(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ) as send_task:
            with self.captureOnCommitCallbacks(execute=True):
                operation = create_managed_ssh_operation(connection, "validate")

        connection.refresh_from_db()
        self.assertEqual(connection.status, CoreConnection.Status.PENDING)
        self.assertEqual(operation.source_lane, "database")
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
            operation = create_managed_ssh_operation(connection, "validate")
        auth = connection.auth_database
        auth.ssh_host = "attacker.example.test"
        auth.save(update_fields=("ssh_host",))

        operation = CoreManagedSSHOperation.objects.select_related(
            "connection__integration"
        ).get(pk=operation.pk)
        with self.assertRaisesRegex(ManagedSSHOperationError, "connection changed"):
            validate_operation_intent(operation)

    def test_database_worker_completes_validation_and_activates_connection(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            operation = create_managed_ssh_operation(connection, "validate")
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

    def test_wrong_worker_lane_fails_closed_without_using_key(self):
        connection = self._database_connection()
        with mock.patch(
            "apps.console.connection.managed_ssh.current_app.send_task"
        ):
            operation = create_managed_ssh_operation(connection, "validate")
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
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch.object(CoreAuthWebsite, "check_connection") as check:
            self.assertTrue(serializer.is_valid(), serializer.errors)
        check.assert_not_called()


class ManagedSSHPublicKeyTests(SimpleTestCase):
    def test_fingerprint_uses_wire_blob_not_comment(self):
        expected = hashlib.sha256(_PUBLIC_BLOB).hexdigest()
        self.assertEqual(managed_public_key_fingerprint(MANAGED_PUBLIC_KEY), expected)
        self.assertEqual(
            managed_public_key_fingerprint(MANAGED_PUBLIC_KEY.rsplit(" ", 1)[0]),
            expected,
        )

    def test_outer_and_wire_key_types_must_match(self):
        mismatched = MANAGED_PUBLIC_KEY.replace("ssh-ed25519 ", "ssh-rsa ", 1)
        with self.assertRaisesRegex(ManagedSSHOperationError, "does not match"):
            managed_public_key_fingerprint(mismatched)

    def test_compose_does_not_mount_managed_private_key_into_web(self):
        compose = (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
        app_block = compose.split("\n  app:\n", 1)[1].split("\n  cloud-egress-guard:", 1)[0]
        database_block = compose.split("\n  worker-database:\n", 1)[1].split(
            "\n  files-egress-guard:", 1
        )[0]
        files_block = compose.split("\n  worker-files:\n", 1)[1].split(
            "\n  storage-egress-guard:", 1
        )[0]
        self.assertNotIn("- ssh_managed_private_key", app_block)
        self.assertIn("- ssh_managed_private_key", database_block)
        self.assertIn("- ssh_managed_private_key", files_block)
