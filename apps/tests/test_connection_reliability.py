import errno
import socket
from unittest import mock

import paramiko
from django.test import SimpleTestCase, override_settings

from apps.console.connection.reliability import (
    ClassifiedConnectionError,
    DatabaseClientCapabilityError,
    classify_connection_error,
)
from apps.console.connection.models import CoreAuthDatabase
from apps.console.connection.ssh import open_ssh_client
from apps.api.v1.utils.http import TimeoutSession, _retry_policy


class ConnectionErrorClassificationTests(SimpleTestCase):
    def test_dns_failure_has_stable_safe_contract(self):
        failure = classify_connection_error(socket.gaierror("secret.example"))
        self.assertEqual(failure.code, "DNS_FAILURE")
        self.assertEqual(failure.stage, "dns")
        self.assertTrue(failure.retryable)
        self.assertNotIn("secret.example", failure.detail)

    def test_timeout_is_retryable_and_does_not_echo_exception(self):
        failure = classify_connection_error(
            TimeoutError("password=do-not-return-this")
        )
        self.assertEqual(failure.code, "TCP_TIMEOUT")
        self.assertTrue(failure.retryable)
        self.assertNotIn("do-not-return-this", failure.detail)

    def test_refused_connection_is_distinct_from_authentication(self):
        refused = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        self.assertEqual(
            classify_connection_error(refused).code, "CONNECTION_REFUSED"
        )
        auth = paramiko.AuthenticationException("username and password")
        self.assertEqual(classify_connection_error(auth).code, "AUTH_FAILED")

    def test_changed_host_key_is_permanent(self):
        failure = classify_connection_error(
            paramiko.BadHostKeyException("server", mock.Mock(), mock.Mock())
        )
        self.assertEqual(failure.code, "HOST_KEY_CHANGED")
        self.assertFalse(failure.retryable)

    def test_database_client_capability_failure_has_safe_actionable_contract(self):
        failure = classify_connection_error(
            DatabaseClientCapabilityError(
                "mariadb", internal_detail="password=do-not-return-this"
            )
        )
        self.assertEqual(failure.code, "DATABASE_CLIENT_UNSUPPORTED")
        self.assertEqual(failure.stage, "worker_preflight")
        self.assertFalse(failure.retryable)
        self.assertIn("MariaDB", failure.detail)
        self.assertIn("mariadb-dump", failure.remediation)
        self.assertNotIn("do-not-return-this", str(failure.as_dict()))


class DatabaseClientCapabilityTests(SimpleTestCase):
    def _auth(self, database_type, version):
        return CoreAuthDatabase(
            type=database_type,
            version=version,
            database_name="appdb",
        )

    def test_engine_aware_dump_binary_selection(self):
        self.assertEqual(
            CoreAuthDatabase.mysql_family_dump_binary(
                CoreAuthDatabase.DatabaseType.MYSQL
            ),
            "mysqldump",
        )
        self.assertEqual(
            CoreAuthDatabase.mysql_family_dump_binary(
                CoreAuthDatabase.DatabaseType.MARIADB
            ),
            "mariadb-dump",
        )

    def test_local_mariadb_probe_uses_exact_sandbox_header_without_secret_argv(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MARIADB,
            CoreAuthDatabase.DatabaseVersion.MARIADB_10_11,
        )
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[-1] == "--version":
                return "mariadb Ver 15.1 Distrib 10.11.14-MariaDB"
            return "1"

        with mock.patch.object(auth, "bin_path", return_value="/usr/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove") as remove:
            auth._validate_mysql_family_client_capability(
                database_type=auth.type,
                version=auth.version,
                host="db.internal",
                port=3306,
                database_name="appdb",
                username="backup",
                password="super-secret",
                use_ssl=False,
            )

        self.assertEqual(calls[0], ["/usr/bin/mariadb", "--version"])
        self.assertEqual(calls[1], ["/usr/bin/mariadb-dump", "--version"])
        probe_argv = calls[2]
        self.assertEqual(probe_argv[0], "/usr/bin/mariadb")
        self.assertEqual(
            probe_argv[1],
            "--defaults-extra-file=/tmp/bs-capability.cnf",
        )
        self.assertIn(
            "/*M!999999\\- enable the sandbox mode */\nSELECT 1;",
            probe_argv,
        )
        self.assertNotIn("super-secret", " ".join(probe_argv))
        remove.assert_called_once_with("/tmp/bs-capability.cnf")

    def test_mariadb_rejects_mysql_client_before_database_mutation(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MARIADB,
            CoreAuthDatabase.DatabaseVersion.MARIADB_11_8,
        )
        with mock.patch.object(auth, "bin_path", return_value="/usr/bin/"), \
             mock.patch.object(
                 auth,
                 "_run_local_database_client_command",
                 return_value="mysql Ver 8.4.10 MySQL Community Server",
             ):
            with self.assertRaises(DatabaseClientCapabilityError):
                auth._validate_mysql_family_client_capability(
                    database_type=auth.type,
                    version=auth.version,
                    host="db.internal",
                    port=3306,
                    database_name="appdb",
                    username="backup",
                    password="secret",
                    use_ssl=False,
                )

    def test_missing_mariadb_binary_is_classified_before_credentials_file(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MARIADB,
            CoreAuthDatabase.DatabaseVersion.MARIADB_11_8,
        )
        with mock.patch.object(auth, "bin_path", return_value="/missing/"), \
             mock.patch.object(
                 auth,
                 "_run_local_database_client_command",
                 side_effect=FileNotFoundError("/missing/mariadb"),
             ), \
             mock.patch.object(
                 auth, "_install_local_database_credentials"
             ) as install_credentials:
            with self.assertRaises(DatabaseClientCapabilityError) as raised:
                auth._validate_mysql_family_client_capability(
                    database_type=auth.type,
                    version=auth.version,
                    host="db.internal",
                    port=3306,
                    database_name="appdb",
                    username="backup",
                    password="secret",
                    use_ssl=False,
                )
        install_credentials.assert_not_called()
        self.assertEqual(
            classify_connection_error(raised.exception).code,
            "DATABASE_CLIENT_UNSUPPORTED",
        )

    def test_mysql_rejects_client_older_than_configured_server_contract(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_run_local_database_client_command",
                 return_value="mysql Ver 8.0.36 MySQL Community Server",
             ):
            with self.assertRaises(DatabaseClientCapabilityError):
                auth._validate_mysql_family_client_capability(
                    database_type=auth.type,
                    version=auth.version,
                    host="db.internal",
                    port=3306,
                    database_name="appdb",
                    username="backup",
                    password="secret",
                    use_ssl=False,
                )

    def test_ssh_mariadb_probe_checks_both_binaries_and_exact_dump_contract(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MARIADB,
            CoreAuthDatabase.DatabaseVersion.MARIADB_11_8,
        )
        calls = []

        def run(_ssh, command):
            calls.append(command)
            if command.endswith("--version"):
                return "mariadb Ver 15.1 Distrib 10.11.14-MariaDB", ""
            return "1", ""

        with mock.patch.object(
            auth, "_run_remote_database_command", side_effect=run
        ):
            auth._validate_mysql_family_client_capability(
                database_type=auth.type,
                version=auth.version,
                host="127.0.0.1",
                port=3307,
                database_name="appdb",
                username="backup",
                password="secret",
                use_ssl=False,
                ssh=mock.sentinel.ssh,
                remote_credentials={
                    "mysql_option": '--defaults-extra-file="$HOME/.bs.cnf"'
                },
            )

        self.assertEqual(calls[:2], ["mariadb --version", "mariadb-dump --version"])
        self.assertIn("mariadb --defaults-extra-file=", calls[2])
        self.assertIn("enable the sandbox mode", calls[2])
        self.assertNotIn("secret", calls[2])


@override_settings(
    SSH_KNOWN_HOSTS_PATH="/tmp/backupsheep-test-known-hosts",
    SSH_CONNECT_TIMEOUT=7,
    SSH_BANNER_TIMEOUT=8,
    SSH_AUTH_TIMEOUT=9,
    SSH_KEEPALIVE_SECONDS=10,
)
class StrictSSHClientTests(SimpleTestCase):
    @mock.patch("apps.console.connection.ssh.configure_host_keys")
    @mock.patch("apps.console.connection.ssh.paramiko.SSHClient")
    def test_password_connect_is_bounded_and_disables_ambient_keys(
        self, client_class, configure_host_keys
    ):
        client = client_class.return_value
        transport = client.get_transport.return_value

        returned, temporary_key = open_ssh_client(
            host="example.invalid",
            port=2222,
            username="backup",
            password="not-returned",
        )

        self.assertIs(returned, client)
        self.assertIsNone(temporary_key)
        configure_host_keys.assert_called_once_with(client)
        client.connect.assert_called_once_with(
            hostname="example.invalid",
            port=2222,
            username="backup",
            timeout=7,
            banner_timeout=8,
            auth_timeout=9,
            allow_agent=False,
            look_for_keys=False,
            password="not-returned",
        )
        transport.set_keepalive.assert_called_once_with(10)

    @mock.patch("apps.console.connection.ssh.configure_host_keys")
    @mock.patch("apps.console.connection.ssh.paramiko.SSHClient")
    def test_raw_client_error_is_classified(self, client_class, configure_host_keys):
        client_class.return_value.connect.side_effect = socket.timeout(
            "credential fragment"
        )
        with self.assertRaises(ClassifiedConnectionError) as raised:
            open_ssh_client(
                host="example.invalid",
                port=22,
                username="backup",
                password="secret",
            )
        self.assertEqual(raised.exception.code, "TCP_TIMEOUT")
        self.assertNotIn("credential fragment", str(raised.exception))


@override_settings(
    PROVIDER_HTTP_CONNECT_TIMEOUT=3,
    PROVIDER_HTTP_READ_TIMEOUT=11,
    PROVIDER_HTTP_MAX_RETRIES=5,
)
class ProviderHTTPClientTests(SimpleTestCase):
    @mock.patch("apps.api.v1.utils.http._requests.Session.request")
    def test_default_timeout_is_applied(self, request):
        request.return_value = mock.Mock(status_code=200)
        TimeoutSession().get("https://provider.example.invalid/resource")
        self.assertEqual(request.call_args.kwargs["timeout"], (3.0, 11.0))

    @mock.patch("apps.api.v1.utils.http._requests.Session.request")
    def test_explicit_provider_timeout_is_preserved(self, request):
        request.return_value = mock.Mock(status_code=200)
        TimeoutSession().get(
            "https://provider.example.invalid/resource", timeout=(1, 2)
        )
        self.assertEqual(request.call_args.kwargs["timeout"], (1, 2))

    def test_retry_policy_honors_retry_after_only_for_idempotent_methods(self):
        policy = _retry_policy()
        self.assertEqual(policy.total, 5)
        self.assertTrue(policy.respect_retry_after_header)
        self.assertIn("GET", policy.allowed_methods)
        self.assertIn("PUT", policy.allowed_methods)
        self.assertNotIn("POST", policy.allowed_methods)
