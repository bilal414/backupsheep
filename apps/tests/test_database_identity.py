import os
import shutil
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
    main,
)
from backupsheep.database_lane_policy import LANES


class DatabaseIdentityConfigurationTests(TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="backupsheep-database-identity-"
        )
        self.secret_root = Path(self.temporary_directory.name)
        # Unique canaries stand in for generated credentials; they are never
        # usable outside this temporary test directory.
        self.canaries = {
            "bootstrap": "b" * 32,
            "migrator": "m" * 32,
            **{
                lane: chr(ord("c") + index) * 32
                for index, lane in enumerate(LANES)
            },
        }
        for name, value in self.canaries.items():
            path = self.secret_root / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o444)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def environment(self):
        return {
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION": "3",
            "BACKUPSHEEP_INSTALLATION_ID": "a" * 64,
            "DB_NAME": "backupsheep",
            "DB_HOST": "db",
            "DB_PORT": "5432",
            "DB_BOOTSTRAP_USER": "backupsheep_bootstrap",
            "DB_MIGRATOR_USER": "backupsheep_migrator",
            "DB_BOOTSTRAP_PASSWORD_FILE": str(self.secret_root / "bootstrap"),
            "DB_MIGRATOR_PASSWORD_FILE": str(self.secret_root / "migrator"),
            **{
                f"DB_{lane.upper()}_USER": f"backupsheep_{lane}"
                for lane in LANES
            },
            **{
                f"DB_{lane.upper()}_PASSWORD_FILE": str(self.secret_root / lane)
                for lane in LANES
            },
        }

    def test_configuration_loads_every_distinct_file_backed_lane_identity(self):
        config = IdentityConfiguration.from_environment(
            self.environment(), secret_root=self.secret_root
        )

        self.assertEqual(config.bootstrap_user, "backupsheep_bootstrap")
        self.assertEqual(config.migrator_user, "backupsheep_migrator")
        self.assertEqual(config.bootstrap_password, self.canaries["bootstrap"])
        self.assertEqual(
            dict(config.lane_users),
            {lane: f"backupsheep_{lane}" for lane in LANES},
        )
        self.assertEqual(dict(config.lane_passwords), {
            lane: self.canaries[lane] for lane in LANES
        })
        self.assertEqual(
            config.marker("storage"),
            "backupsheep:database-identity-v3:" + "a" * 64 + ":storage",
        )

    def test_configuration_rejects_role_or_credential_reuse(self):
        reused_role = self.environment()
        reused_role["DB_STORAGE_USER"] = reused_role["DB_MIGRATOR_USER"]
        with self.assertRaisesRegex(ProvisioningError, "must be distinct"):
            IdentityConfiguration.from_environment(
                reused_role, secret_root=self.secret_root
            )

        storage_canary = self.secret_root / "storage"
        storage_canary.unlink()
        shutil.copyfile(self.secret_root / "migrator", storage_canary)
        storage_canary.chmod(0o444)
        self.assertEqual(
            storage_canary.read_bytes(),
            (self.secret_root / "migrator").read_bytes(),
        )
        with self.assertRaisesRegex(ProvisioningError, "credential must be distinct"):
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
                "backupsheep_storage",
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
                role_name="backupsheep_storage",
                password="r" * 32,
                marker="backupsheep:database-identity-v3:" + "a" * 64 + ":storage",
            )

    def test_existing_marked_role_with_elevated_attribute_is_rejected(self):
        marker = "backupsheep:database-identity-v3:" + "a" * 64 + ":storage"
        cursor = self.Cursor(
            (
                "backupsheep_storage",
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
                role_name="backupsheep_storage",
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


class DatabaseIdentitySealCommandTests(TestCase):
    @mock.patch("backupsheep.database_lane_probe.run_probe")
    @mock.patch("backupsheep.database_identity.seal_database_identities")
    @mock.patch("backupsheep.database_identity._connect")
    @mock.patch("backupsheep.database_identity.IdentityConfiguration.from_environment")
    def test_seal_runs_adversarial_probe_after_closing_bootstrap_connection(
        self,
        configuration,
        connect,
        seal,
        run_probe,
    ):
        config = mock.Mock()
        configuration.return_value = config
        connection = mock.Mock()
        connect.return_value = connection

        self.assertEqual(main(["seal"]), 0)

        seal.assert_called_once_with(connection, config)
        connection.close.assert_called_once_with()
        run_probe.assert_called_once_with(config)

    @mock.patch(
        "backupsheep.database_lane_probe.run_probe",
        side_effect=RuntimeError("synthetic probe failure"),
    )
    @mock.patch("backupsheep.database_identity.seal_database_identities")
    @mock.patch("backupsheep.database_identity._connect")
    @mock.patch("backupsheep.database_identity.IdentityConfiguration.from_environment")
    def test_seal_fails_closed_when_adversarial_probe_fails(
        self,
        configuration,
        connect,
        _seal,
        _run_probe,
    ):
        configuration.return_value = mock.Mock()
        connect.return_value = mock.Mock()

        with mock.patch("builtins.print") as output:
            self.assertEqual(main(["seal"]), 1)

        rendered = " ".join(
            str(argument)
            for call in output.call_args_list
            for argument in call.args
        )
        self.assertIn("failed closed", rendered)
        self.assertNotIn("synthetic probe failure", rendered)
