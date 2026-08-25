import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from backupsheep.database_identity import (
    IdentityConfiguration,
    ProvisioningError,
    _assert_supported_database_shape,
    _ensure_application_role,
    _connect,
    _read_secret,
)


class DatabaseIdentityConfigurationTests(TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="backupsheep-database-identity-"
        )
        self.secret_root = Path(self.temporary_directory.name)
        self.secrets = {
            "bootstrap": "b" * 32,
            "migrator": "m" * 32,
            "runtime": "r" * 32,
        }
        for name, value in self.secrets.items():
            path = self.secret_root / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o444)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def environment(self):
        return {
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION": "2",
            "BACKUPSHEEP_INSTALLATION_ID": "a" * 64,
            "DB_NAME": "backupsheep",
            "DB_HOST": "db",
            "DB_PORT": "5432",
            "DB_BOOTSTRAP_USER": "backupsheep_bootstrap",
            "DB_MIGRATOR_USER": "backupsheep_migrator",
            "DB_USER": "backupsheep_runtime",
            "DB_BOOTSTRAP_PASSWORD_FILE": str(self.secret_root / "bootstrap"),
            "DB_MIGRATOR_PASSWORD_FILE": str(self.secret_root / "migrator"),
            "DB_PASSWORD_FILE": str(self.secret_root / "runtime"),
        }

    def test_configuration_loads_three_distinct_file_backed_identities(self):
        config = IdentityConfiguration.from_environment(
            self.environment(), secret_root=self.secret_root
        )

        self.assertEqual(config.bootstrap_user, "backupsheep_bootstrap")
        self.assertEqual(config.migrator_user, "backupsheep_migrator")
        self.assertEqual(config.runtime_user, "backupsheep_runtime")
        self.assertEqual(config.bootstrap_password, self.secrets["bootstrap"])
        self.assertEqual(
            config.marker("runtime"),
            "backupsheep:database-identity-v2:" + "a" * 64 + ":runtime",
        )

    def test_configuration_rejects_role_or_credential_reuse(self):
        reused_role = self.environment()
        reused_role["DB_USER"] = reused_role["DB_MIGRATOR_USER"]
        with self.assertRaisesRegex(ProvisioningError, "roles must be distinct"):
            IdentityConfiguration.from_environment(
                reused_role, secret_root=self.secret_root
            )

        (self.secret_root / "runtime").chmod(0o644)
        (self.secret_root / "runtime").write_text(
            self.secrets["migrator"] + "\n", encoding="utf-8"
        )
        (self.secret_root / "runtime").chmod(0o444)
        with self.assertRaisesRegex(ProvisioningError, "credentials must be distinct"):
            IdentityConfiguration.from_environment(
                self.environment(), secret_root=self.secret_root
            )

    def test_configuration_rejects_a_redirected_bootstrap_endpoint(self):
        environment = self.environment()
        environment["DB_HOST"] = "attacker.example"
        with self.assertRaisesRegex(ProvisioningError, "stock internal service"):
            IdentityConfiguration.from_environment(
                environment, secret_root=self.secret_root
            )

        environment = self.environment()
        environment["DB_PORT"] = "15432"
        with self.assertRaisesRegex(ProvisioningError, "must be 5432"):
            IdentityConfiguration.from_environment(
                environment, secret_root=self.secret_root
            )

    def test_connection_ignores_ambient_libpq_routing(self):
        config = IdentityConfiguration.from_environment(
            self.environment(), secret_root=self.secret_root
        )
        sentinel = object()
        with mock.patch.dict(
            os.environ,
            {
                "PGHOSTADDR": "203.0.113.99",
                "PGSERVICEFILE": "/tmp/attacker-service",
            },
            clear=False,
        ), mock.patch(
            "backupsheep.database_identity.psycopg2.connect",
            return_value=sentinel,
        ) as connect:
            self.assertIs(_connect(config), sentinel)
            self.assertEqual(os.environ["PGHOSTADDR"], "203.0.113.99")
            self.assertEqual(os.environ["PGSERVICEFILE"], "/tmp/attacker-service")

        parameters = connect.call_args.kwargs
        self.assertEqual(parameters["host"], "db")
        self.assertEqual(parameters["port"], 5432)
        self.assertEqual(parameters["sslmode"], "disable")
        self.assertEqual(parameters["target_session_attrs"], "read-write")

    def test_secret_reader_rejects_links_writable_files_and_multiple_lines(self):
        outside = self.secret_root.parent / (self.secret_root.name + "-outside")
        outside.write_text("z" * 32 + "\n", encoding="utf-8")
        try:
            link = self.secret_root / "link"
            link.symlink_to(outside)
            with self.assertRaises(ProvisioningError):
                _read_secret(str(link), "linked", root=self.secret_root)

            writable = self.secret_root / "writable"
            writable.write_text("w" * 32 + "\n", encoding="utf-8")
            writable.chmod(0o666)
            with self.assertRaises(ProvisioningError):
                _read_secret(str(writable), "writable", root=self.secret_root)

            multiline = self.secret_root / "multiline"
            multiline.write_text("x" * 32 + "\n\n", encoding="utf-8")
            multiline.chmod(0o444)
            with self.assertRaisesRegex(ProvisioningError, "exactly one line"):
                _read_secret(str(multiline), "multiline", root=self.secret_root)

            hardlink = self.secret_root / "hardlink"
            os.link(self.secret_root / "bootstrap", hardlink)
            with self.assertRaisesRegex(ProvisioningError, "non-hard-linked"):
                _read_secret(str(hardlink), "hardlink", root=self.secret_root)
        finally:
            outside.unlink(missing_ok=True)


class ExistingDatabaseRoleSafetyTests(TestCase):
    class Cursor:
        def __init__(self, role_record):
            self.role_record = role_record
            self.query = ""

        def execute(self, query, parameters=None):
            self.query = str(query)

        def fetchone(self):
            return self.role_record

        def fetchall(self):
            return []

    def test_existing_unmarked_role_is_never_adopted(self):
        cursor = self.Cursor(
            (
                "backupsheep_runtime",
                False,
                False,
                False,
                False,
                False,
                True,
                "",
            )
        )
        with self.assertRaisesRegex(
            ProvisioningError, "without this installation's marker"
        ):
            _ensure_application_role(
                cursor,
                role_name="backupsheep_runtime",
                password="r" * 32,
                marker="backupsheep:database-identity-v2:" + "a" * 64 + ":runtime",
            )

    def test_existing_marked_role_with_elevated_attribute_is_rejected(self):
        marker = "backupsheep:database-identity-v2:" + "a" * 64 + ":runtime"
        cursor = self.Cursor(
            (
                "backupsheep_runtime",
                True,
                False,
                False,
                False,
                False,
                True,
                marker,
            )
        )
        with self.assertRaisesRegex(ProvisioningError, "unsafe attributes"):
            _ensure_application_role(
                cursor,
                role_name="backupsheep_runtime",
                password="r" * 32,
                marker=marker,
            )


class ExistingDatabaseShapeSafetyTests(TestCase):
    class Cursor:
        def __init__(self, matching_query, rows):
            self.matching_query = matching_query
            self.rows = rows
            self.query = ""

        def execute(self, query, parameters=None):
            self.query = str(query)

        def fetchall(self):
            if self.matching_query in self.query:
                return self.rows
            return []

    config = mock.Mock(migrator_user="backupsheep_migrator")

    def test_custom_schema_is_rejected_even_when_it_is_empty(self):
        cursor = self.Cursor("namespace.nspname <> 'public'", [("custom",)])

        with self.assertRaisesRegex(ProvisioningError, "schemas outside public"):
            _assert_supported_database_shape(cursor, self.config)

    def test_standalone_public_type_is_rejected(self):
        cursor = self.Cursor("database_type.typrelid = 0", [("custom_enum",)])

        with self.assertRaisesRegex(ProvisioningError, "standalone types"):
            _assert_supported_database_shape(cursor, self.config)
