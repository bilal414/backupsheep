import errno
import socket
from unittest import mock

import paramiko
from django.test import SimpleTestCase, override_settings

from apps.console.connection.reliability import (
    ClassifiedConnectionError,
    DatabaseClientCapabilityError,
    DatabaseEventPrivilegeError,
    DatabaseTLSRequiredError,
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

    def test_mysql_secure_transport_errors_are_typed_and_not_retryable(self):
        errors = (
            DatabaseTLSRequiredError(),
            RuntimeError(
                "ERROR 3159 (HY000): Connections using insecure transport are "
                "prohibited while --require_secure_transport=ON"
            ),
            RuntimeError(
                "Authentication plugin 'caching_sha2_password' reported error: "
                "Authentication requires secure connection"
            ),
        )
        for error in errors:
            with self.subTest(error=error.__class__.__name__):
                failure = classify_connection_error(error, stage="database")
                self.assertEqual(failure.code, "TLS_REQUIRED")
                self.assertEqual(failure.stage, "tls")
                self.assertFalse(failure.retryable)
                self.assertIn("Enable SSL/TLS", failure.remediation)

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

    def test_database_event_privilege_failure_has_safe_actionable_contract(self):
        failure = classify_connection_error(
            DatabaseEventPrivilegeError(
                internal_detail="password=do-not-return-this host=db.internal"
            )
        )

        self.assertEqual(failure.code, "DATABASE_EVENT_PRIVILEGE_REQUIRED")
        self.assertEqual(failure.stage, "authorization")
        self.assertFalse(failure.retryable)
        self.assertIn("EVENT privilege", failure.remediation)
        self.assertNotIn("do-not-return-this", str(failure.as_dict()))
        self.assertNotIn("db.internal", str(failure.as_dict()))


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

    @mock.patch(
        "apps.console.connection.models.os.path.exists", return_value=True
    )
    def test_unsaved_mysql_connection_selects_submitted_client_version(self, exists):
        auth = CoreAuthDatabase()

        self.assertEqual(
            auth.bin_path(
                version=CoreAuthDatabase.DatabaseVersion.MYSQL_8_4
            ),
            "/opt/mysql/bin/",
        )
        exists.assert_called_once_with("/opt/mysql/bin/mysqldump")

    def test_mysql_tls_switch_maps_to_required_or_disabled_without_fallback(self):
        self.assertEqual(
            CoreAuthDatabase._mysql_family_ssl_option(
                CoreAuthDatabase.DatabaseType.MYSQL, True
            ),
            "--ssl-mode=REQUIRED",
        )
        self.assertEqual(
            CoreAuthDatabase._mysql_family_ssl_option(
                CoreAuthDatabase.DatabaseType.MYSQL, False
            ),
            "--ssl-mode=DISABLED",
        )
        self.assertEqual(
            CoreAuthDatabase._mysql_family_ssl_option(
                CoreAuthDatabase.DatabaseType.MARIADB, True
            ),
            "--ssl",
        )

    @mock.patch("apps.console.connection.models.subprocess.run")
    def test_local_client_secure_transport_rejection_keeps_tls_contract(self, run):
        run.return_value = mock.Mock(
            returncode=1,
            stdout=b"",
            stderr=(
                b"ERROR 3159 (HY000): Connections using insecure transport are "
                b"prohibited while --require_secure_transport=ON"
            ),
        )

        with self.assertRaises(DatabaseTLSRequiredError):
            CoreAuthDatabase._run_local_database_client_command(
                ["mysql", "--execute", "SELECT 1"]
            )

    @mock.patch("apps.console.connection.models.subprocess.run")
    def test_local_client_wrong_password_keeps_auth_contract(self, run):
        run.return_value = mock.Mock(
            returncode=1,
            stdout=b"",
            stderr=b"ERROR 1045 (28000): Access denied for user 'backup'@'worker'",
        )

        with self.assertRaises(ClassifiedConnectionError) as context:
            CoreAuthDatabase._run_local_database_client_command(
                ["mysql", "--execute", "SELECT 1"]
            )

        self.assertEqual(context.exception.code, "AUTH_FAILED")

    @mock.patch("apps.console.connection.models.subprocess.run")
    def test_local_client_refused_host_keeps_tcp_contract(self, run):
        run.return_value = mock.Mock(
            returncode=1,
            stdout=b"",
            stderr=(
                b"ERROR 2003 (HY000): Can't connect to MySQL server on "
                b"'db.example.test:65000' (111)"
            ),
        )

        with self.assertRaises(ClassifiedConnectionError) as context:
            CoreAuthDatabase._run_local_database_client_command(
                ["mysql", "--execute", "SELECT 1"]
            )

        self.assertEqual(context.exception.code, "CONNECTION_REFUSED")

    def test_mysql_require_ssl_1045_is_distinguished_from_wrong_password(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        query_calls = []
        auth_failure = ClassifiedConnectionError(
            classify_connection_error(
                RuntimeError("ERROR 1045: Access denied for user 'backup'")
            )
        )

        def run(argv):
            if argv[-1] == "--version":
                return "mysql Ver 8.4.10 MySQL Community Server"
            query_calls.append(argv)
            if "--ssl-mode=DISABLED" in argv:
                raise auth_failure
            if "--ssl-mode=REQUIRED" in argv:
                return "1"
            self.fail(f"unexpected capability command: {argv}")

        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove"):
            with self.assertRaises(DatabaseTLSRequiredError):
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

        self.assertEqual(len(query_calls), 2)
        self.assertIn("--ssl-mode=DISABLED", query_calls[0])
        self.assertIn("--ssl-mode=REQUIRED", query_calls[1])

    def test_mysql_wrong_password_remains_auth_failed_after_tls_hint_probe(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        auth_failure = ClassifiedConnectionError(
            classify_connection_error(
                RuntimeError("ERROR 1045: Access denied for user 'backup'")
            )
        )

        def run(argv):
            if argv[-1] == "--version":
                return "mysql Ver 8.4.10 MySQL Community Server"
            raise auth_failure

        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove"):
            with self.assertRaises(ClassifiedConnectionError) as context:
                auth._validate_mysql_family_client_capability(
                    database_type=auth.type,
                    version=auth.version,
                    host="db.internal",
                    port=3306,
                    database_name="appdb",
                    username="backup",
                    password="wrong-secret",
                    use_ssl=False,
                )

        self.assertEqual(context.exception.code, "AUTH_FAILED")

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

    def test_local_full_object_probe_verifies_event_privilege(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[-1] == "--version":
                return "mysql Ver 8.4.10 MySQL Community Server"
            if argv[-1] == "SELECT 1;":
                return "1"
            return ""

        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove"):
            auth._validate_mysql_family_client_capability(
                database_type=auth.type,
                version=auth.version,
                host="db.internal",
                port=3306,
                database_name="appdb",
                username="backup",
                password="secret",
                use_ssl=False,
                include_database_objects=True,
            )

        event_calls = [call for call in calls if "SHOW EVENTS" in " ".join(call)]
        self.assertEqual(len(event_calls), 1)
        self.assertIn("SHOW EVENTS FROM `appdb`;", event_calls[0])
        self.assertNotIn("secret", " ".join(event_calls[0]))

    def test_ssh_full_object_probe_verifies_event_privilege(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MARIADB,
            CoreAuthDatabase.DatabaseVersion.MARIADB_11_8,
        )
        calls = []

        def run(_ssh, command):
            calls.append(command)
            if command.endswith("--version"):
                return "mariadb Ver 15.1 Distrib 10.11.14-MariaDB", ""
            if "SELECT 1" in command:
                return "1", ""
            return "", ""

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
                include_database_objects=True,
                ssh=mock.sentinel.ssh,
                remote_credentials={
                    "mysql_option": '--defaults-extra-file="$HOME/.bs.cnf"'
                },
            )

        event_calls = [command for command in calls if "SHOW EVENTS" in command]
        self.assertEqual(len(event_calls), 1)
        self.assertIn("SHOW EVENTS FROM `appdb`;", event_calls[0])
        self.assertNotIn("secret", event_calls[0])

    def test_event_probe_failure_uses_event_privilege_contract(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )

        def run(argv):
            if argv[-1] == "--version":
                return "mysql Ver 8.4.10 MySQL Community Server"
            if argv[-1] == "SELECT 1;":
                return "1"
            raise RuntimeError("Access denied password=event-secret host=db.internal")

        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove"):
            with self.assertRaises(DatabaseEventPrivilegeError) as raised:
                auth._validate_mysql_family_client_capability(
                    database_type=auth.type,
                    version=auth.version,
                    host="db.internal",
                    port=3306,
                    database_name="appdb",
                    username="backup",
                    password="event-secret",
                    use_ssl=False,
                    include_database_objects=True,
                )

        failure = classify_connection_error(raised.exception)
        self.assertEqual(failure.code, "DATABASE_EVENT_PRIVILEGE_REQUIRED")
        self.assertNotIn("event-secret", str(failure.as_dict()))

    def test_all_databases_event_probe_checks_each_non_system_database(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[-1] == "--version":
                return "mysql Ver 8.4.10 MySQL Community Server"
            if argv[-1] == "SELECT 1;":
                return "1"
            if argv[-1] == "SHOW DATABASES;":
                return "mysql\nanalytics\ninformation_schema\nappdb\n"
            return ""

        with mock.patch.object(auth, "bin_path", return_value="/opt/mysql/bin/"), \
             mock.patch.object(
                 auth,
                 "_install_local_database_credentials",
                 return_value="/tmp/bs-capability.cnf",
             ), \
             mock.patch.object(
                 auth, "_run_local_database_client_command", side_effect=run
             ), \
             mock.patch("apps.console.connection.models.os.remove"):
            auth._validate_mysql_family_client_capability(
                database_type=auth.type,
                version=auth.version,
                host="db.internal",
                port=3306,
                database_name=None,
                username="backup",
                password="secret",
                use_ssl=False,
                all_databases=True,
                include_database_objects=True,
            )

        event_sql = sorted(
            call[-1] for call in calls if "SHOW EVENTS" in " ".join(call)
        )
        self.assertEqual(
            event_sql,
            ["SHOW EVENTS FROM `analytics`;", "SHOW EVENTS FROM `appdb`;"],
        )

    def test_check_connection_passes_full_object_policy_to_capability_probe(self):
        auth = self._auth(
            CoreAuthDatabase.DatabaseType.MYSQL,
            CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
        )
        connection = mock.Mock()
        cursor = connection.cursor.return_value
        cursor.fetchall.return_value = []
        data = {
            "host": "db.internal",
            "port": 3306,
            "database_name": "appdb",
            "username": "backup",
            "password": "secret",
            "all_databases": False,
            "use_ssl": False,
            "type": CoreAuthDatabase.DatabaseType.MYSQL,
            "version": CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
            "include_stored_procedure": True,
            "use_public_key": False,
            "use_private_key": False,
        }

        with mock.patch.object(
            auth, "_validate_mysql_family_client_capability"
        ) as validate, mock.patch.object(
            auth, "_direct_mysql_connect", return_value=connection
        ):
            auth.check_connection(data=data)

        self.assertTrue(validate.call_args.kwargs["include_database_objects"])
        self.assertFalse(validate.call_args.kwargs["all_databases"])


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
