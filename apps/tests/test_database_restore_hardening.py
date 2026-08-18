"""Focused safety tests for logical database restore policy and resumption."""

import errno
import hashlib
import os
import stat
import tempfile
import uuid
from collections import OrderedDict
from types import SimpleNamespace
from unittest import mock

from django.test import override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration import restore as restore_tasks
from apps._tasks.integration import restore_database as RD
from apps._tasks.integration.restore_common import RestoreError
from apps.api.v1.backup.database.views import (
    CoreDatabaseBackupView,
    _in_place_confirmation,
)
from apps.api.v1.backup import serializers as backup_serializers
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
)
from apps.console.connection.models import CoreAuthDatabase
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests.base import BaseTestCase
from apps.tests.test_backup_engine import make_database_node


class _FakeRestore:
    def __init__(self, *, mode="fork", metadata=None):
        self.pk = 91
        self.name = "database-restore"
        self.correlation_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
        self.params = {"mode": mode}
        self.execution_metadata = metadata or {}
        self.execution_phase = "pending"
        self.progress_completed = 0
        self.progress_total = None
        self.progress_unit = ""
        self.saves = []

    def save(self, update_fields=None):
        self.saves.append(tuple(update_fields or ()))


def _fake_backup(*, option_postgres=None):
    return SimpleNamespace(
        uuid=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        uuid_str="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        attempt_no=1,
        type="database",
        size=1,
        tables=None,
        all_tables=True,
        option_postgres=option_postgres,
    )


def _fake_auth(database_type=CoreAuthDatabase.DatabaseType.MYSQL):
    return SimpleNamespace(
        database_name="source_db",
        host="db.example.test",
        port=3306,
        use_ssl=False,
        use_public_key=False,
        use_private_key=False,
        type=database_type,
        bin_path=lambda: "/usr/bin/",
        check_connection=lambda: None,
    )


def _marker(restore, backup, source, target, digest, state):
    values = RD._marker_values(restore, backup, source, target, digest, state)
    return "\t".join(
        values[field]
        for field in (
            "marker_version",
            "correlation_id",
            "backup_uuid",
            "source_database",
            "target_database",
            "source_digest",
            "state",
        )
    ) + "\n"


class DatabaseRestorePolicyTests(BaseTestCase):
    def _backup_and_storage(self, *, all_databases=False):
        node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL,
            version="mysql_8_0",
            all_databases=all_databases,
        )
        backup = CoreDatabaseBackup.objects.create(
            database=node.database,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            all_tables=True,
            all_databases=all_databases,
        )
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="local"),
            name="restore-local",
            added_by=self.member,
        )
        CoreStorageLocal.objects.create(storage=storage, path="")
        stored = CoreDatabaseBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="/tmp/restore.zip",
        )
        return node, backup, stored

    def _post(self, backup, payload):
        view = CoreDatabaseBackupView.as_view({"post": "restore"})
        request = APIRequestFactory().post(
            f"/api/v1/backups/database/{backup.id}/restore/",
            payload,
            format="json",
        )
        force_authenticate(request, user=self.user)
        return view(request, pk=backup.id)

    def test_api_defaults_to_deterministic_fork_and_persists_policy(self):
        _node, backup, stored = self._backup_and_storage()
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ):
            response = self._post(
                backup,
                {"confirm": True, "storage_point_id": stored.id},
            )
        self.assertEqual(response.status_code, 201)
        restore = CoreDatabaseRestore.objects.get(backup=backup)
        self.assertEqual(restore.params["mode"], "fork")
        self.assertTrue(restore.params["mapping_locked"])
        mapping = restore.params["target_mapping"]
        self.assertEqual(set(mapping), {"appdb"})
        self.assertNotEqual(mapping["appdb"], "appdb")
        self.assertTrue(mapping["appdb"].startswith("bs_restore_"))
        self.assertEqual(restore.execution_metadata["source_to_target"], mapping)

    def test_in_place_requires_exact_source_to_target_confirmation(self):
        _node, backup, stored = self._backup_and_storage()
        mapping = {"appdb": "appdb"}
        bad = self._post(
            backup,
            {
                "confirm": True,
                "storage_point_id": stored.id,
                "mode": "in_place",
                "target_mapping": mapping,
                "target_confirmation": "IN_PLACE_RESTORE_TO:{\"appdb\":\"wrong\"}",
            },
        )
        self.assertEqual(bad.status_code, 400)
        self.assertFalse(CoreDatabaseRestore.objects.filter(backup=backup).exists())

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ):
            good = self._post(
                backup,
                {
                    "confirm": True,
                    "storage_point_id": stored.id,
                    "mode": "in_place",
                    "target_mapping": mapping,
                    "target_confirmation": _in_place_confirmation(mapping),
                },
            )
        self.assertEqual(good.status_code, 201)
        restore = CoreDatabaseRestore.objects.get(backup=backup)
        self.assertEqual(restore.params["mode"], "in_place")
        self.assertEqual(restore.params["target_mapping"], mapping)


class DatabaseRestorePermissionPreflightTests(BaseTestCase):
    def _auth(self, database_type):
        auth = _fake_auth(database_type)
        auth.username = "encrypted-user"
        auth.password = "encrypted-password"
        return auth

    def _fenced_restore(self):
        restore = _FakeRestore()
        restore._required_restore_lease_owner = "database-worker"
        restore._required_restore_lease_token = "fence-token"
        return restore

    def _mysql_preflight_result(self, grants):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL)
        try:
            with mock.patch.object(RD, "_mysql_query", return_value=grants), \
                 mock.patch.object(RD, "_write_log") as log:
                result = RD._preflight_database_restore_permissions(
                    SimpleNamespace(),
                    _fake_backup(),
                    self._fenced_restore(),
                    auth,
                    "dbuser",
                    "password-do-not-persist",
                    mode="fork",
                    mapping={"source_db": "bs_restore_target"},
                )
            return result, log.call_args_list, None
        except RestoreError as error:
            return None, log.call_args_list, error

    def test_postgresql_direct_preflight_allows_createdb_without_mutation(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        restore = _FakeRestore()
        with mock.patch.object(RD, "_postgres_query", return_value="1\n") as query, \
             mock.patch.object(RD, "_run_direct") as run:
            result = RD._preflight_database_restore_permissions(
                SimpleNamespace(),
                _fake_backup(),
                restore,
                auth,
                "dbuser",
                "db-password",
                mode="fork",
                mapping={"source_db": "bs_restore_target"},
            )

        self.assertEqual(result, {"createdb": True})
        run.assert_not_called()
        self.assertIn("rolcreatedb", query.call_args.args[6])
        self.assertIn("rolsuper", query.call_args.args[6])

    def test_postgresql_direct_preflight_denial_is_safe_and_terminal(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        error = None
        with mock.patch.object(RD, "_postgres_query", return_value="0\n"):
            with self.assertRaises(RestoreError) as raised:
                RD._preflight_database_restore_permissions(
                    SimpleNamespace(),
                    _fake_backup(),
                    self._fenced_restore(),
                    auth,
                    "dbuser",
                    "password-do-not-persist",
                    mode="fork",
                    mapping={"source_db": "bs_restore_target"},
                )
            error = raised.exception

        self.assertEqual(error.code, RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE)
        self.assertFalse(error.retryable)
        self.assertNotIn("password-do-not-persist", str(error))
        self.assertIn("CREATEDB", str(error))

    def test_postgresql_ssh_preflight_uses_remote_pgpass_and_no_target_command(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        auth.use_private_key = True
        ssh = mock.Mock()
        auth.get_ssh_client = mock.Mock(return_value=(ssh, None))
        ssh.open_sftp.return_value.listdir.return_value = []
        with mock.patch.object(RD, "_sftp_write") as write, \
             mock.patch.object(RD, "_sftp_remove") as remove, \
             mock.patch.object(RD, "_postgres_query", return_value="1\n") as query, \
             mock.patch.object(RD, "_run_direct") as run:
            result = RD._preflight_database_restore_permissions(
                SimpleNamespace(),
                _fake_backup(),
                self._fenced_restore(),
                auth,
                "dbuser",
                "db-password",
                mode="fork",
                mapping={"source_db": "bs_restore_target"},
            )

        self.assertEqual(result, {"createdb": True})
        write.assert_called_once()
        remove.assert_not_called()
        query.assert_called_once()
        self.assertIs(query.call_args.kwargs["ssh"], ssh)
        self.assertIsNotNone(query.call_args.kwargs["remote_pgpass"])
        run.assert_not_called()
        ssh.close.assert_called_once()

    def test_mysql_direct_preflight_requires_global_create_and_drop(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MYSQL)
        grants = "GRANT CREATE, DROP ON *.* TO 'backup'@'%';\n"
        with mock.patch.object(RD, "_mysql_query", return_value=grants) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            result = RD._preflight_database_restore_permissions(
                SimpleNamespace(),
                _fake_backup(),
                _FakeRestore(),
                auth,
                "dbuser",
                "db-password",
                mode="fork",
                mapping={"source_db": "bs_restore_target"},
            )

        self.assertEqual(result, {"create": True, "drop": True})
        self.assertEqual(query.call_args.args[4], "SHOW GRANTS;")
        run.assert_not_called()

    def test_mysql_scoped_grants_cover_exact_and_matching_wildcard_targets(self):
        exact_result, exact_logs, exact_error = self._mysql_preflight_result(
            "GRANT CREATE, DROP ON `bs_restore_target`.* TO 'fixture'@'%' "
            "IDENTIFIED BY 'grant-secret';\n"
        )
        self.assertEqual(exact_result, {"create": True, "drop": True})
        self.assertIsNone(exact_error)

        wildcard_result, wildcard_logs, wildcard_error = self._mysql_preflight_result(
            "GRANT CREATE, DROP ON `bs_restore_%`.* TO 'fixture'@'%';\n"
        )
        self.assertEqual(wildcard_result, {"create": True, "drop": True})
        self.assertIsNone(wildcard_error)

        unrelated_result, unrelated_logs, unrelated_error = self._mysql_preflight_result(
            "GRANT CREATE, DROP ON `other_%`.* TO 'fixture'@'%' "
            "IDENTIFIED BY 'grant-secret';\n"
        )
        self.assertIsNone(unrelated_result)
        self.assertEqual(
            unrelated_error.code,
            RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE,
        )

        missing_result, missing_logs, missing_error = self._mysql_preflight_result(
            "GRANT CREATE ON `bs_restore_target`.* TO 'fixture'@'%';\n"
        )
        self.assertIsNone(missing_result)
        self.assertEqual(
            missing_error.code,
            RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE,
        )
        for error in (unrelated_error, missing_error):
            self.assertNotIn("fixture", str(error))
            self.assertNotIn("grant-secret", str(error))
        for logs in (exact_logs, wildcard_logs, unrelated_logs, missing_logs):
            joined_logs = " ".join(str(item) for item in logs)
            self.assertNotIn("GRANT ", joined_logs)
            self.assertNotIn("grant-secret", joined_logs)

    def test_mysql_scoped_grants_must_cover_every_resolved_target(self):
        capabilities = RD._mysql_grant_capabilities(
            "GRANT CREATE, DROP ON `bs_restore_target`.* TO 'fixture'@'%';\n",
            ["bs_restore_target", "bs_restore_other"],
        )
        self.assertTrue(capabilities["bs_restore_target"]["create"])
        self.assertTrue(capabilities["bs_restore_target"]["drop"])
        self.assertFalse(capabilities["bs_restore_other"]["create"])
        self.assertFalse(capabilities["bs_restore_other"]["drop"])

    def test_mysql_ssh_preflight_denial_does_not_issue_create_or_drop(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.MARIADB)
        auth.use_public_key = True
        ssh = mock.Mock()
        auth.get_ssh_client = mock.Mock(return_value=(ssh, None))
        ssh.open_sftp.return_value.listdir.return_value = []
        with mock.patch.object(RD, "_sftp_write") as write, \
             mock.patch.object(RD, "_sftp_remove") as remove, \
             mock.patch.object(
                 RD,
                 "_mysql_query",
                 return_value="GRANT SELECT ON *.* TO 'backup'@'%';\n",
             ) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaises(RestoreError) as raised:
                RD._preflight_database_restore_permissions(
                    SimpleNamespace(),
                    _fake_backup(),
                    self._fenced_restore(),
                    auth,
                    "dbuser",
                    "db-password",
                    mode="fork",
                    mapping={"source_db": "bs_restore_target"},
                )

        self.assertEqual(
            raised.exception.code,
            RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE,
        )
        self.assertIn("CREATE", str(raised.exception))
        self.assertIn("DROP", str(raised.exception))
        query.assert_called_once()
        self.assertNotIn("CREATE DATABASE", query.call_args.args[4])
        self.assertNotIn("DROP DATABASE", query.call_args.args[4])
        write.assert_called_once()
        remove.assert_not_called()
        run.assert_not_called()
        ssh.close.assert_called_once()

    def test_in_place_mode_preserves_semantics_and_skips_fork_preflight(self):
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        with mock.patch.object(RD, "_postgres_query") as query, \
             mock.patch.object(RD, "_mysql_query") as mysql_query:
            result = RD._preflight_database_restore_permissions(
                SimpleNamespace(),
                _fake_backup(),
                _FakeRestore(mode="in_place"),
                auth,
                "dbuser",
                "db-password",
                mode="in_place",
                mapping={"source_db": "source_db"},
            )
        self.assertIsNone(result)
        query.assert_not_called()
        mysql_query.assert_not_called()

    def test_restore_database_stops_before_family_engine_when_preflight_denies(self):
        backup = _fake_backup()
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        auth.check_connection = mock.Mock()
        node = SimpleNamespace(
            id=1,
            name="db-node",
            connection=SimpleNamespace(
                id=1,
                name="db-connection",
                auth_database=auth,
                account=SimpleNamespace(
                    get_encryption_key=lambda: b"unused",
                    create_log=lambda data: None,
                ),
            ),
        )
        backup.database = SimpleNamespace(node=node)
        restore = _FakeRestore()
        restore.storage_point = SimpleNamespace(storage=SimpleNamespace(name="local"))
        targets = OrderedDict({"source_db": ["/tmp/source.sql"]})
        source_digests = {"source_db": []}

        with mock.patch.object(RD, "ensure_disk_space"), \
             mock.patch.object(RD, "fetch_backup_zip"), \
             mock.patch.object(RD, "extract_backup_zip"), \
             mock.patch.object(RD, "_validate_extracted_archive", return_value=(targets, source_digests)), \
             mock.patch.object(RD, "_load_or_create_mapping", return_value={"source_db": "bs_restore_target"}), \
             mock.patch.object(RD, "bs_decrypt", side_effect=["dbuser", "password"]), \
             mock.patch.object(RD, "_postgres_query", return_value="0\n") as privilege_query, \
             mock.patch.object(RD, "_run_direct") as run, \
             mock.patch.object(RD, "_restore_postgresql") as restore_engine, \
             mock.patch.object(RD, "delete_from_disk"):
            with self.assertRaises(RestoreError) as raised:
                RD.restore_database(backup, restore)

        self.assertEqual(raised.exception.code, RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE)
        privilege_query.assert_called_once()
        run.assert_not_called()
        restore_engine.assert_not_called()
        self.assertNotIn("password", str(raised.exception))

    def test_new_postgresql_fork_marker_is_importable_but_existing_importing_is_fail_closed(self):
        backup = _fake_backup()
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(tempfile.gettempdir(), "bs-postgres-restore.sql")
        sql = b"CREATE TABLE restored(id integer);\n"
        with open(sql_path, "wb") as output:
            output.write(sql)
        self.addCleanup(lambda: os.path.exists(sql_path) and os.remove(sql_path))
        source_digests = {
            "source_db": [{
                "file": os.path.basename(sql_path),
                "bytes": len(sql),
                "sha256": hashlib.sha256(sql).hexdigest(),
            }]
        }
        mapping = {"source_db": "bs_restore_new_target"}

        new_restore = self._fenced_restore()
        digest = RD._source_digest(source_digests, "source_db")
        complete = _marker(
            new_restore,
            backup,
            "source_db",
            mapping["source_db"],
            digest,
            "complete",
        )
        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=["", "", "1\n", "1\n", complete],
        ), mock.patch.object(RD, "_run_direct", return_value="") as run, \
             mock.patch.object(RD, "_verify_source_files"):
            RD._restore_postgresql(
                SimpleNamespace(),
                backup,
                new_restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                mapping,
                source_digests,
                "dbuser",
                "db-password",
            )
        self.assertEqual(run.call_count, 2)  # createdb, then the import

        existing_restore = self._fenced_restore()
        importing = _marker(
            existing_restore,
            backup,
            "source_db",
            mapping["source_db"],
            digest,
            "importing",
        )
        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=["1\n", "1\n", importing],
        ), mock.patch.object(RD, "_run_direct") as reimport:
            with self.assertRaisesRegex(RestoreError, "import outcome is ambiguous"):
                RD._restore_postgresql(
                    SimpleNamespace(),
                    backup,
                    existing_restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    mapping,
                    source_digests,
                    "dbuser",
                    "db-password",
                )
        reimport.assert_not_called()

    def test_postgresql_source_checksum_change_stops_before_target_mutation(self):
        backup = _fake_backup()
        restore = self._fenced_restore()
        auth = self._auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(tempfile.gettempdir(), "bs-postgres-changed.sql")
        sql = b"CREATE TABLE restored(id integer);\n"
        with open(sql_path, "wb") as output:
            output.write(sql)
        self.addCleanup(lambda: os.path.exists(sql_path) and os.remove(sql_path))
        source_digests = {
            "source_db": [
                {
                    "file": os.path.basename(sql_path),
                    "bytes": len(sql),
                    "sha256": "0" * 64,
                }
            ]
        }

        with mock.patch.object(RD, "_ensure_postgres_target") as ensure_target, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(
                RestoreError, "staged database dump changed after validation"
            ):
                RD._restore_postgresql(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": "bs_restore_owned"},
                    source_digests,
                    "dbuser",
                    "db-password",
                )

        ensure_target.assert_not_called()
        run.assert_not_called()

    def test_permission_error_classification_and_api_allowlist_are_public_safe(self):
        error = RD._database_restore_permission_error(
            CoreAuthDatabase.DatabaseType.POSTGRESQL
        )
        code, message, retryable = restore_tasks._restore_error_outcome(error)
        self.assertEqual(code, RD.DATABASE_RESTORE_PERMISSION_ERROR_CODE)
        self.assertFalse(retryable)
        self.assertIn("CREATEDB", message)
        self.assertNotIn("password", message.lower())
        self.assertEqual(backup_serializers._safe_error_code(code), code)
        self.assertIn("in-place", backup_serializers._safe_error_message(code))


class DatabaseRestoreEngineHardeningTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_archive_validation_happens_before_connection_or_client(self):
        backup = _fake_backup()
        auth = _fake_auth()
        restore = _FakeRestore()
        restore.storage_point = SimpleNamespace(storage=SimpleNamespace(name="local"))
        node = SimpleNamespace(
            id=1,
            name="db-node",
            connection=SimpleNamespace(
                id=1,
                name="db-connection",
                auth_database=auth,
                account=SimpleNamespace(
                    get_encryption_key=lambda: b"unused",
                    create_log=lambda data: None,
                ),
            ),
        )
        backup.database = SimpleNamespace(node=node)
        malformed_zip = os.path.join(self.tmp, "bad.zip")
        with open(malformed_zip, "wb") as output:
            output.write(b"not-a-zip")
        def fake_fetch(_stored, destination):
            with open(destination, "wb") as output:
                output.write(b"not-a-zip")
            return destination

        with mock.patch.object(RD, "fetch_backup_zip", side_effect=fake_fetch), \
             mock.patch.object(RD, "delete_from_disk"), \
             mock.patch.object(auth, "check_connection") as check, \
             mock.patch.object(RD.subprocess, "run") as run:
            with self.assertRaises(RestoreError):
                RD.restore_database(backup, restore)
        check.assert_not_called()
        run.assert_not_called()

    def test_mysql_collision_fails_closed_without_create_or_drop(self):
        backup = _fake_backup()
        restore = _FakeRestore()
        auth = _fake_auth()
        digest = "d" * 64
        with mock.patch.object(
            RD,
            "_mysql_query",
            side_effect=["1\n", ""],
        ) as query:
            with self.assertRaises(RestoreError):
                RD._ensure_mysql_target(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    "source_db",
                    "bs_restore_owned",
                    digest,
                    "dbuser",
                    "password",
                    in_place=False,
                    defaults_arg="--defaults-extra-file=/tmp/credentials",
                )
        self.assertEqual(query.call_count, 2)
        self.assertNotIn("CREATE DATABASE", " ".join(str(call) for call in query.call_args_list))

    def test_mysql_family_queries_use_the_authenticated_vendor_client(self):
        for database_type, client in (
            (CoreAuthDatabase.DatabaseType.MYSQL, "mysql"),
            (CoreAuthDatabase.DatabaseType.MARIADB, "mariadb"),
        ):
            with self.subTest(database_type=database_type, mode="direct"):
                auth = _fake_auth(database_type)
                with mock.patch.object(RD, "_run_direct", return_value="") as run:
                    RD._mysql_query(
                        SimpleNamespace(),
                        _fake_backup(),
                        auth,
                        "--defaults-extra-file=/tmp/credentials",
                        "SELECT 1;",
                        "dbuser",
                        "password",
                        "query database",
                    )
                self.assertEqual(run.call_args.args[2][0], f"/usr/bin/{client}")
                self.assertEqual(run.call_args.args[5], client.upper())

            with self.subTest(database_type=database_type, mode="ssh"):
                auth = _fake_auth(database_type)
                with mock.patch.object(RD, "_ssh_run", return_value="") as run:
                    RD._mysql_query(
                        SimpleNamespace(),
                        _fake_backup(),
                        auth,
                        "credentials.cnf",
                        "SELECT 1;",
                        "dbuser",
                        "password",
                        "query database",
                        ssh=SimpleNamespace(),
                    )
                self.assertTrue(run.call_args.args[3].startswith(f"{client} "))
                self.assertEqual(run.call_args.args[6], client.upper())

    def _mysql_partial_fixture(
        self,
        *,
        mode="fork",
        marker_source="source_db",
        marker_digest=None,
        marker_state="importing",
        checkpoint_status="importing",
        file_status="in_progress",
        with_checkpoint=True,
    ):
        """Build one exact-marker partial MySQL restore for crash tests."""
        backup = _fake_backup()
        auth = _fake_auth()
        target = "bs_restore_owned"
        sql = b"CREATE TABLE restored(id int);\n"
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(sql)
        specification = {
            "file": "source_db.sql",
            "bytes": len(sql),
            "sha256": hashlib.sha256(sql).hexdigest(),
        }
        source_digests = {"source_db": [specification]}
        digest = RD._source_digest(source_digests, "source_db")
        metadata = {
            "source_to_target": {"source_db": target},
            "source_digests": source_digests,
        }
        if with_checkpoint:
            metadata["target_checkpoints"] = {
                target: {
                    "source": "source_db",
                    "source_digest": digest,
                    "status": checkpoint_status,
                    "files": {
                        "source_db.sql": {
                            **specification,
                            "status": file_status,
                        }
                    },
                }
            }
        restore = _FakeRestore(mode=mode, metadata=metadata)
        marker = _marker(
            restore,
            backup,
            marker_source,
            target,
            marker_digest or digest,
            marker_state,
        )
        return backup, restore, auth, sql_path, source_digests, digest, target, marker

    def _run_mysql_owned_fork_resume(
        self,
        *,
        restore,
        backup,
        auth,
        sql_path,
        source_digests,
        target,
        marker,
    ):
        """Run one resume and return the mocked SQL/client calls."""
        calls = [
            "1\n",  # exact target exists
            marker,  # exact BackupSheep-owned importing marker
            marker,  # ownership re-read immediately before DROP DATABASE
            "",  # DROP DATABASE
            "",  # target is absent after DROP
            "",  # CREATE DATABASE plus exact importing marker
            "",  # marker completion update
            "1\n",  # final target exists
            _marker(restore, backup, "source_db", target, RD._source_digest(source_digests, "source_db"), "complete"),
        ]
        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=calls) as query, \
             mock.patch.object(RD, "_run_direct", return_value="") as run:
            RD._restore_mysql_family(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": target},
                source_digests,
                "dbuser",
                "password",
            )
        return query, run

    def test_mysql_crash_after_checkpoint_before_import_restarts_owned_fork(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture()
        restore.execution_phase = "database_importing_file"

        query, run = self._run_mysql_owned_fork_resume(
            restore=restore,
            backup=backup,
            auth=auth,
            sql_path=sql_path,
            source_digests=source_digests,
            target=target,
            marker=marker,
        )

        self.assertTrue(any("DROP DATABASE" in str(call) for call in query.call_args_list))
        self.assertEqual(run.call_count, 1)
        checkpoint = restore.execution_metadata["target_checkpoints"][target]
        self.assertEqual(checkpoint["status"], "complete")
        self.assertEqual(checkpoint["files"]["source_db.sql"]["status"], "complete")

    def test_mysql_crash_after_import_before_checkpoint_restarts_owned_fork(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture()
        # The durable state is identical whether the client had applied the
        # dump before the worker died or had not started it yet.  The exact
        # owned fork is discarded, so replay is safe in either case.
        restore.execution_phase = "database_importing"

        query, run = self._run_mysql_owned_fork_resume(
            restore=restore,
            backup=backup,
            auth=auth,
            sql_path=sql_path,
            source_digests=source_digests,
            target=target,
            marker=marker,
        )

        self.assertEqual(
            sum("DROP DATABASE" in str(call) for call in query.call_args_list),
            1,
        )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )

    def test_mysql_worker_crash_during_partial_import_leaves_replayable_checkpoint(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            _initial_marker,
        ) = self._mysql_partial_fixture(with_checkpoint=False)

        # First delivery creates the exact fork and durably records the file
        # boundary, then the worker dies while the client is importing SQL.
        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["", ""]), \
             mock.patch.object(RD, "_run_direct", side_effect=SystemExit("worker crash")):
            with self.assertRaises(SystemExit):
                RD._restore_mysql_family(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": target},
                    source_digests,
                    "dbuser",
                    "password",
                )

        interrupted = restore.execution_metadata["target_checkpoints"][target]
        self.assertEqual(interrupted["status"], "importing")
        self.assertEqual(interrupted["files"]["source_db.sql"]["status"], "in_progress")

        # The next delivery proves the marker, discards the disposable fork,
        # and replays the archive from the beginning.
        marker = _marker(
            restore,
            backup,
            "source_db",
            target,
            RD._source_digest(source_digests, "source_db"),
            "importing",
        )
        query, run = self._run_mysql_owned_fork_resume(
            restore=restore,
            backup=backup,
            auth=auth,
            sql_path=sql_path,
            source_digests=source_digests,
            target=target,
            marker=marker,
        )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )
        self.assertTrue(any("DROP DATABASE" in str(call) for call in query.call_args_list))

    def test_mariadb_partial_import_uses_the_same_owned_fork_convergence(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture()
        auth.type = CoreAuthDatabase.DatabaseType.MARIADB

        query, run = self._run_mysql_owned_fork_resume(
            restore=restore,
            backup=backup,
            auth=auth,
            sql_path=sql_path,
            source_digests=source_digests,
            target=target,
            marker=marker,
        )

        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[2][0], "/usr/bin/mariadb")
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )
        self.assertEqual(
            sum("DROP DATABASE" in str(call) for call in query.call_args_list),
            1,
        )

    def test_mysql_complete_marker_is_adopted_without_reimport(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            digest,
            target,
            _importing,
        ) = self._mysql_partial_fixture(
            marker_state="complete",
            with_checkpoint=False,
        )
        complete = _marker(restore, backup, "source_db", target, digest, "complete")

        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", complete]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            RD._restore_mysql_family(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": target},
                source_digests,
                "dbuser",
                "password",
            )

        run.assert_not_called()
        self.assertEqual(query.call_count, 2)
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )

    def test_mysql_duplicate_delivery_adopts_completed_fork_without_reimport(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            importing,
        ) = self._mysql_partial_fixture()

        # The first delivery converges the owned fork and commits its marker.
        self._run_mysql_owned_fork_resume(
            restore=restore,
            backup=backup,
            auth=auth,
            sql_path=sql_path,
            source_digests=source_digests,
            target=target,
            marker=importing,
        )
        complete = _marker(
            restore,
            backup,
            "source_db",
            target,
            RD._source_digest(source_digests, "source_db"),
            "complete",
        )

        # A duplicate delivery must adopt the exact completion witness rather
        # than dropping or replaying the already-complete fork.
        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", complete]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            RD._restore_mysql_family(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": target},
                source_digests,
                "dbuser",
                "password",
            )

        run.assert_not_called()
        self.assertEqual(query.call_count, 2)
        self.assertNotIn(
            "DROP DATABASE",
            " ".join(str(call) for call in query.call_args_list),
        )

    def test_mysql_ambiguous_checkpoint_is_manual_before_drop(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture()
        restore.execution_metadata["target_checkpoints"][target]["files"][
            "source_db.sql"
        ]["status"] = "unknown"

        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", marker]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(RestoreError, "unsupported state"):
                RD._restore_mysql_family(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": target},
                    source_digests,
                    "dbuser",
                    "password",
                )

        run.assert_not_called()
        self.assertNotIn(
            "DROP DATABASE",
            " ".join(str(call) for call in query.call_args_list),
        )

    def test_mysql_in_place_partial_import_remains_manual_review(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture(mode="in_place")

        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", marker]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(RestoreError, "in-place MySQL restore"):
                RD._restore_mysql_family(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": target},
                    source_digests,
                    "dbuser",
                    "password",
                )

        self.assertEqual(query.call_count, 2)
        run.assert_not_called()
        self.assertNotIn(
            "DROP DATABASE",
            " ".join(str(call) for call in query.call_args_list),
        )

    def test_mysql_marker_ownership_mismatch_blocks_drop_and_import(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            _marker_for_restore,
        ) = self._mysql_partial_fixture(marker_digest="e" * 64)
        foreign_marker = _marker(
            restore,
            backup,
            "different_source",
            target,
            "e" * 64,
            "importing",
        )

        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", foreign_marker]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(RestoreError, "marker does not belong"):
                RD._restore_mysql_family(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": target},
                    source_digests,
                    "dbuser",
                    "password",
                )

        self.assertEqual(query.call_count, 2)
        run.assert_not_called()
        self.assertNotIn(
            "DROP DATABASE",
            " ".join(str(call) for call in query.call_args_list),
        )

    def test_mysql_stale_worker_cannot_drop_owned_fork(self):
        (
            backup,
            restore,
            auth,
            sql_path,
            source_digests,
            _digest,
            target,
            marker,
        ) = self._mysql_partial_fixture()

        with mock.patch.object(
            RD,
            "_ensure_restore_fence",
            side_effect=[None, RD.RestoreLeaseLost("stale worker")],
        ) as fence, mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=["1\n", marker]) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaises(RD.RestoreLeaseLost):
                RD._restore_mysql_family(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": target},
                    source_digests,
                    "dbuser",
                    "password",
                )

        self.assertEqual(fence.call_count, 2)
        self.assertEqual(query.call_count, 2)
        run.assert_not_called()
        self.assertNotIn(
            "DROP DATABASE",
            " ".join(str(call) for call in query.call_args_list),
        )

    def test_mysql_marker_change_or_disappearance_blocks_fork_drop(self):
        for replacement_kind in ("disappeared", "completed"):
            with self.subTest(replacement_kind=replacement_kind):
                (
                    backup,
                    restore,
                    auth,
                    sql_path,
                    source_digests,
                    digest,
                    target,
                    importing,
                ) = self._mysql_partial_fixture()
                replacement = ""
                if replacement_kind == "completed":
                    replacement = _marker(
                        restore,
                        backup,
                        "source_db",
                        target,
                        digest,
                        "complete",
                    )

                with mock.patch.object(RD, "_write_local_defaults_file"), \
                     mock.patch.object(
                         RD,
                         "_mysql_query",
                         side_effect=["1\n", importing, replacement],
                     ) as query, \
                     mock.patch.object(RD, "_run_direct") as run:
                    with self.assertRaisesRegex(RestoreError, "changed before fork recreation"):
                        RD._restore_mysql_family(
                            SimpleNamespace(),
                            backup,
                            restore,
                            auth,
                            OrderedDict({"source_db": [sql_path]}),
                            {"source_db": target},
                            source_digests,
                            "dbuser",
                            "password",
                        )

                self.assertEqual(query.call_count, 3)
                run.assert_not_called()
                self.assertNotIn(
                    "DROP DATABASE",
                    " ".join(str(call) for call in query.call_args_list),
                )

    def test_mysql_interrupted_owned_fork_is_recreated_and_checkpointed(self):
        backup = _fake_backup()
        restore = _FakeRestore(
            metadata={
                "source_to_target": {"source_db": "bs_restore_owned"},
                "target_checkpoints": {
                    "bs_restore_owned": {
                        "source": "source_db",
                        "source_digest": "d" * 64,
                        "status": "importing",
                    }
                },
            }
        )
        auth = _fake_auth()
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"CREATE TABLE restored(id int);\n")
        marker = _marker(
            restore,
            backup,
            "source_db",
            "bs_restore_owned",
            RD._source_digest(
                {"source_db": [{"file": "source_db.sql", "bytes": 32, "sha256": "x" * 64}]},
                "source_db",
            ),
            "importing",
        )
        # Use the real source digest for the marker/checkpoint identity.
        source_digests = {
            "source_db": [{"file": "source_db.sql", "bytes": 31, "sha256": "x" * 64}]
        }
        digest = RD._source_digest(source_digests, "source_db")
        restore.execution_metadata["source_digests"] = source_digests
        restore.execution_metadata["target_checkpoints"]["bs_restore_owned"]["source_digest"] = digest
        marker = _marker(restore, backup, "source_db", "bs_restore_owned", digest, "importing")
        calls = [
            "1\n",  # existing target
            marker,  # exact owned importing marker
            marker,  # ownership re-read immediately before DROP DATABASE
            "",  # DROP DATABASE
            "",  # target does not exist after drop
            "",  # CREATE DATABASE + marker
            "",  # marker completion update
            "1\n",  # completion marker reconciliation: target exists
            _marker(restore, backup, "source_db", "bs_restore_owned", digest, "complete"),
        ]
        with mock.patch.object(RD, "_write_local_defaults_file"), \
             mock.patch.object(RD, "_mysql_query", side_effect=calls) as query, \
             mock.patch.object(RD, "_run_direct", return_value="") as run:
            RD._restore_mysql_family(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": "bs_restore_owned"},
                source_digests,
                "dbuser",
                "password",
            )
        self.assertTrue(any("DROP DATABASE" in str(call) for call in query.call_args_list))
        self.assertEqual(restore.execution_metadata["target_checkpoints"]["bs_restore_owned"]["status"], "complete")
        self.assertEqual(restore.progress_completed, 1)
        self.assertTrue(run.called)

    def test_postgresql_in_place_claims_target_when_marker_schema_is_absent(self):
        """An absent marker relation is safe evidence for the explicit claim."""
        backup = _fake_backup(option_postgres="-w --clean --if-exists")
        restore = _FakeRestore(mode="in_place")
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)

        with mock.patch.object(
            RD, "_postgres_query", side_effect=["1\n", "0\n", ""]
        ) as query:
            result = RD._ensure_postgres_target(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                "source_db",
                "source_db",
                "a" * 64,
                "dbuser",
                "password",
                in_place=True,
                pg_env={},
            )

        self.assertEqual(result["state"], "importing")
        self.assertEqual(query.call_count, 3)
        marker_lookup = query.call_args_list[1].args[6]
        self.assertIn("to_regclass", marker_lookup)
        self.assertNotIn("\\gset", marker_lookup)
        self.assertNotIn("\\if", marker_lookup)
        self.assertIn("CREATE SCHEMA", query.call_args_list[2].args[6])

    def test_postgresql_foreign_marker_blocks_in_place_without_mutation(self):
        backup = _fake_backup(option_postgres="-w --clean --if-exists")
        restore = _FakeRestore(mode="in_place")
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        foreign = RD._marker_values(
            restore,
            backup,
            "different_source",
            "source_db",
            "b" * 64,
            "importing",
        )
        foreign["correlation_id"] = str(uuid.uuid4())
        foreign_text = "\t".join(
            foreign[field]
            for field in (
                "marker_version",
                "correlation_id",
                "backup_uuid",
                "source_database",
                "target_database",
                "source_digest",
                "state",
            )
        ) + "\n"

        with mock.patch.object(
            RD, "_postgres_query", side_effect=["1\n", "1\n", foreign_text]
        ) as query, mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(RestoreError, "marker does not belong"):
                RD._ensure_postgres_target(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    "source_db",
                    "source_db",
                    "a" * 64,
                    "dbuser",
                    "password",
                    in_place=True,
                    pg_env={},
                )

        run.assert_not_called()
        self.assertEqual(query.call_count, 3)
        self.assertFalse(
            any("CREATE SCHEMA" in call.args[6] for call in query.call_args_list)
        )

    def test_postgresql_in_place_rejects_incompatible_dump_before_target_mutation(self):
        backup = _fake_backup(option_postgres="-w --clean")
        restore = _FakeRestore(mode="in_place")
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)

        with mock.patch.object(RD, "_postgres_query") as query, \
             mock.patch.object(RD, "_ensure_postgres_target") as ensure_target, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(
                RestoreError, "--clean and --if-exists.*no target was changed"
            ) as raised:
                RD._restore_postgresql(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": ["/tmp/source.sql"]}),
                    {"source_db": "source_db"},
                    {"source_db": []},
                    "dbuser",
                    "db-password",
                )

        query.assert_not_called()
        ensure_target.assert_not_called()
        run.assert_not_called()
        self.assertNotIn("db-password", str(raised.exception))

    def test_postgresql_in_place_compatible_dump_replays_crashed_transaction(self):
        backup = _fake_backup(option_postgres="-w --clean --if-exists")
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(self.tmp, "source_db.sql")
        sql = b"CREATE TABLE restored(id integer);\n"
        with open(sql_path, "wb") as output:
            output.write(sql)
        source_digests = {
            "source_db": [{
                "file": "source_db.sql",
                "bytes": len(sql),
                "sha256": hashlib.sha256(sql).hexdigest(),
            }]
        }
        digest = RD._source_digest(source_digests, "source_db")
        target = "source_db"
        restore = _FakeRestore(
            mode="in_place",
            metadata={
                "source_to_target": {"source_db": target},
                "source_digests": source_digests,
                "target_checkpoints": {
                    target: {
                        "source": "source_db",
                        "source_digest": digest,
                        "status": "importing",
                        "files": {
                            "source_db.sql": {
                                **source_digests["source_db"][0],
                                "status": "in_progress",
                            }
                        },
                    }
                },
            },
        )
        importing = _marker(restore, backup, "source_db", target, digest, "importing")
        complete = _marker(restore, backup, "source_db", target, digest, "complete")

        # The first delivery crashed after the atomic import rolled back.  The
        # retry sees the exact importing marker, replays the verified dump, and
        # adopts the completion marker in the same fenced workflow.
        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=["1\n", "1\n", importing, "1\n", "1\n", complete],
        ), mock.patch.object(RD, "_run_direct", return_value="") as run:
            RD._restore_postgresql(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": target},
                source_digests,
                "dbuser",
                "password",
            )

        self.assertEqual(run.call_count, 1)
        self.assertIn("--single-transaction", run.call_args.args[2])
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["transaction_replay_count"],
            1,
        )

    def test_postgresql_uses_one_stop_transaction_and_adopts_exact_marker(self):
        backup = _fake_backup()
        restore = _FakeRestore()
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"CREATE TABLE restored(id integer);\n")
        source_digests = {
            "source_db": [{"file": "source_db.sql", "bytes": 37, "sha256": "a" * 64}]
        }
        digest = RD._source_digest(source_digests, "source_db")
        marker = _marker(restore, backup, "source_db", "bs_restore_owned", digest, "complete")
        query_results = [
            "1\n",  # target exists
            "1\n",  # marker relation exists
            marker,  # exact marker; adoption must not import
        ]
        with mock.patch.object(RD, "_postgres_query", side_effect=query_results) as query, \
             mock.patch.object(RD, "_run_direct") as run:
            RD._restore_postgresql(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": "bs_restore_owned"},
                source_digests,
                "dbuser",
                "password",
            )
        run.assert_not_called()
        self.assertEqual(restore.progress_completed, 1)
        self.assertEqual(query.call_count, 3)
        checkpoint = restore.execution_metadata["target_checkpoints"][
            "bs_restore_owned"
        ]
        self.assertEqual(checkpoint["files"]["source_db.sql"]["status"], "complete")

    def test_postgresql_import_command_contains_on_error_stop_and_no_password_argv(self):
        backup = _fake_backup()
        restore = _FakeRestore()
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"CREATE TABLE restored(id integer);\n")
        source_digests = {
            "source_db": [{"file": "source_db.sql", "bytes": 37, "sha256": "a" * 64}]
        }
        digest = RD._source_digest(source_digests, "source_db")
        importing = _marker(restore, backup, "source_db", "bs_restore_owned", digest, "importing")
        complete = _marker(restore, backup, "source_db", "bs_restore_owned", digest, "complete")
        calls = []
        credential_evidence = []

        def fake_run(*args, **kwargs):
            argv = args[2] if len(args) >= 3 else args[0]
            calls.append((list(argv), kwargs))
            pgpass_path = (kwargs.get("env") or {}).get("PGPASSFILE")
            if pgpass_path and os.path.exists(pgpass_path):
                with open(pgpass_path) as pgpass:
                    content = pgpass.read()
                credential_evidence.append(
                    (content, stat.S_IMODE(os.stat(pgpass_path).st_mode))
                )
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=["", "", "1\n", "1\n", complete],
        ), \
             mock.patch.object(RD, "_run_direct", side_effect=fake_run):
            RD._restore_postgresql(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": "bs_restore_owned"},
                source_digests,
                "dbuser",
                "p@ss-secret",
            )
        import_calls = [call for call in calls if "--single-transaction" in call[0]]
        self.assertEqual(len(import_calls), 1)
        argv, kwargs = import_calls[0]
        self.assertIn("--set=ON_ERROR_STOP=1", argv)
        self.assertNotIn("p@ss-secret", " ".join(argv))
        self.assertNotIn("PGPASSWORD", kwargs["env"])
        self.assertIn("PGPASSFILE", kwargs["env"])
        self.assertEqual(credential_evidence[-1][1], 0o600)
        self.assertIn("p@ss-secret", credential_evidence[-1][0])

    def test_postgresql_interrupted_atomic_import_replays_and_completes(self):
        backup = _fake_backup()
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(self.tmp, "source_db.sql")
        sql = b"CREATE TABLE restored(id integer);\n"
        with open(sql_path, "wb") as output:
            output.write(sql)
        source_digests = {
            "source_db": [
                {
                    "file": "source_db.sql",
                    "bytes": len(sql),
                    "sha256": hashlib.sha256(sql).hexdigest(),
                }
            ]
        }
        digest = RD._source_digest(source_digests, "source_db")
        target = "bs_restore_owned"
        restore = _FakeRestore(
            metadata={
                "source_to_target": {"source_db": target},
                "source_digests": source_digests,
                "target_checkpoints": {
                    target: {
                        "source": "source_db",
                        "source_digest": digest,
                        "status": "importing",
                        "files": {
                            "source_db.sql": {
                                **source_digests["source_db"][0],
                                "status": "in_progress",
                            }
                        },
                    }
                },
            }
        )
        importing = _marker(
            restore, backup, "source_db", target, digest, "importing"
        )
        complete = _marker(
            restore, backup, "source_db", target, digest, "complete"
        )

        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=["1\n", "1\n", importing, "1\n", "1\n", complete],
        ), mock.patch.object(RD, "_run_direct", return_value="") as run:
            RD._restore_postgresql(
                SimpleNamespace(),
                backup,
                restore,
                auth,
                OrderedDict({"source_db": [sql_path]}),
                {"source_db": target},
                source_digests,
                "dbuser",
                "password",
            )

        self.assertEqual(run.call_count, 1)
        self.assertIn("--single-transaction", run.call_args.args[2])
        checkpoint = restore.execution_metadata["target_checkpoints"][target]
        self.assertEqual(checkpoint["status"], "complete")
        self.assertEqual(checkpoint["files"]["source_db.sql"]["status"], "complete")
        self.assertEqual(checkpoint["transaction_replay_count"], 1)
        self.assertEqual(restore.execution_phase, "database_complete")
        self.assertEqual(restore.progress_completed, 1)

    def test_postgresql_marker_queries_are_pure_sql_and_boolean_is_strict(self):
        exists_query = RD._postgres_marker_exists_query()
        row_query = RD._postgres_marker_query()

        self.assertIn("to_regclass", exists_query)
        self.assertIn("ORDER BY marker_key", row_query)
        self.assertNotIn("\\", exists_query)
        self.assertNotIn("\\", row_query)
        for value in ("t\n", "true\n", "1\n"):
            self.assertTrue(RD._postgres_relation_exists(value))
        for value in ("f\n", "false\n", "0\n"):
            self.assertFalse(RD._postgres_relation_exists(value))
        for value in ("", "yes\n", "1\n0\n", "t\textra\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    RestoreError, "marker relation lookup was malformed"
                ):
                    RD._postgres_relation_exists(value)

    def test_postgresql_marker_queries_pin_tab_delimited_wire_format(self):
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        remote = RD._postgres_command(
            auth,
            "dbuser",
            "target_db",
            "SELECT 1, 2;",
            tuples_only=True,
        )
        self.assertIn("--field-separator=", remote)
        self.assertIn("\t", remote)

        with mock.patch.object(
            RD, "_run_direct", return_value="one\ttwo\n"
        ) as run:
            result = RD._postgres_query_direct(
                SimpleNamespace(),
                _fake_backup(),
                auth,
                {},
                "dbuser",
                "target_db",
                "SELECT 1, 2;",
                "query marker",
            )

        self.assertEqual(result, "one\ttwo\n")
        self.assertIn("--field-separator=\t", run.call_args.args[2])

    def test_postgresql_combined_import_contains_source_and_marker_once(self):
        backup = _fake_backup()
        restore = _FakeRestore()
        sql_path = os.path.join(self.tmp, "source_db.sql")
        source_sql = b"CREATE TABLE restored(id integer);\n"
        with open(sql_path, "wb") as output:
            output.write(source_sql)
        marker = RD._marker_values(
            restore,
            backup,
            "source_db",
            "bs_restore_owned",
            "a" * 64,
            "importing",
        )

        combined = RD._build_combined_postgres_sql([sql_path], marker)
        self.addCleanup(lambda: os.path.exists(combined) and os.remove(combined))
        with open(combined, "rb") as input_file:
            payload = input_file.read()

        self.assertEqual(payload.count(source_sql), 1)
        self.assertEqual(payload.count(b"SET state='complete'"), 1)
        self.assertEqual(stat.S_IMODE(os.stat(combined).st_mode), 0o600)

    def test_postgresql_historical_clean_dump_is_repaired_before_strict_import(self):
        backup = _fake_backup(option_postgres="-w --clean")
        restore = _FakeRestore()
        sql_path = os.path.join(self.tmp, "source_db.sql")
        source_sql = (
            b"--\n-- PostgreSQL database dump\n--\n"
            b"-- Dumped from database version 16.15\n"
            b"-- Dumped by pg_dump version 16.15\n\n"
            b"SET statement_timeout = 0;\n"
            b"ALTER TABLE ONLY app.child DROP CONSTRAINT child_parent_fkey;\n"
            b"DROP TRIGGER child_guard ON app.child;\n"
            b"DROP INDEX app.child_parent_idx;\n"
            b"DROP VIEW app.child_view;\n"
            b"DROP TABLE app.child;\n"
            b"DROP SEQUENCE app.child_seq;\n"
            b"DROP FUNCTION app.guard();\n"
            b"DROP TYPE app.mood;\n"
            b"DROP SCHEMA app;\n"
            b"CREATE SCHEMA app;\n"
            b"CREATE TABLE app.child(id integer);\n"
            b"SELECT missing_function_for_strict_failure();\n"
            b"-- PostgreSQL database dump complete\n"
        )
        with open(sql_path, "wb") as output:
            output.write(source_sql)
        marker = RD._marker_values(
            restore,
            backup,
            "source_db",
            "bs_restore_owned",
            "a" * 64,
            "importing",
        )

        combined = RD._build_combined_postgres_sql(
            [sql_path], marker, historical_clean_compatibility=True
        )
        self.addCleanup(lambda: os.path.exists(combined) and os.remove(combined))
        with open(combined, "rb") as input_file:
            payload = input_file.read()

        for expected in (
            b"ALTER TABLE IF EXISTS ONLY app.child DROP CONSTRAINT IF EXISTS child_parent_fkey;",
            b"DROP TRIGGER IF EXISTS child_guard ON app.child;",
            b"DROP INDEX IF EXISTS app.child_parent_idx;",
            b"DROP VIEW IF EXISTS app.child_view;",
            b"DROP TABLE IF EXISTS app.child;",
            b"DROP SEQUENCE IF EXISTS app.child_seq;",
            b"DROP FUNCTION IF EXISTS app.guard();",
            b"DROP TYPE IF EXISTS app.mood;",
            b"DROP SCHEMA IF EXISTS app;",
        ):
            self.assertIn(expected, payload)
        self.assertIn(b"SELECT missing_function_for_strict_failure();", payload)
        self.assertEqual(payload.count(b"SET state='complete'"), 1)
        self.assertTrue(
            RD._postgres_historical_clean_compatibility_required(backup)
        )

    def test_postgresql_historical_clean_rejects_unsupported_drop_before_target(self):
        backup = _fake_backup(option_postgres="-w --clean")
        restore = _FakeRestore()
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.POSTGRESQL)
        sql_path = os.path.join(self.tmp, "source_db.sql")
        source_sql = (
            b"--\n-- PostgreSQL database dump\n--\n"
            b"-- Dumped by pg_dump version 16.15\n"
            b"DROP DATABASE production;\n"
            b"-- PostgreSQL database dump complete\n"
        )
        with open(sql_path, "wb") as output:
            output.write(source_sql)
        source_digests = {
            "source_db": [
                {
                    "file": "source_db.sql",
                    "bytes": len(source_sql),
                    "sha256": hashlib.sha256(source_sql).hexdigest(),
                }
            ]
        }

        with mock.patch.object(RD, "_ensure_postgres_target") as ensure_target, \
             mock.patch.object(RD, "_run_direct") as run:
            with self.assertRaisesRegex(
                RestoreError, "unsupported dump statement.*before.*target"
            ):
                RD._restore_postgresql(
                    SimpleNamespace(),
                    backup,
                    restore,
                    auth,
                    OrderedDict({"source_db": [sql_path]}),
                    {"source_db": "bs_restore_owned"},
                    source_digests,
                    "dbuser",
                    "db-password",
                )

        ensure_target.assert_not_called()
        run.assert_not_called()

    def test_archive_cannot_overwrite_restore_ownership_marker(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"DROP TABLE __backupsheep_restore_marker;\n")

        with self.assertRaises(RestoreError):
            RD._validate_extracted_archive(
                _fake_backup(), _fake_auth(), self.tmp
            )

    def test_mariadb_fork_accepts_exact_vendor_transaction_scaffolding(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        payload = (
            b"/*M!999999\\- enable the sandbox mode */\n"
            b"SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;\n"
            b"CREATE TABLE restored(id integer);\n"
            b"INSERT INTO restored VALUES (1);\n"
            b"COMMIT;\n"
            b"SET AUTOCOMMIT=@OLD_AUTOCOMMIT;\n"
        )
        with open(sql_path, "wb") as output:
            output.write(payload)
        auth = _fake_auth(CoreAuthDatabase.DatabaseType.MARIADB)

        targets, digests = RD._validate_extracted_archive(
            _fake_backup(), auth, self.tmp, mode="fork"
        )

        self.assertEqual(targets, {"source_db": [sql_path]})
        self.assertEqual(digests["source_db"][0]["bytes"], len(payload))
        self.assertEqual(
            digests["source_db"][0]["sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_mariadb_transaction_scaffolding_is_rejected_for_in_place_restore(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(
                b"SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;\n"
                b"CREATE TABLE restored(id integer);\n"
                b"COMMIT;\n"
                b"SET AUTOCOMMIT=@OLD_AUTOCOMMIT;\n"
            )

        with self.assertRaisesRegex(RestoreError, "unsafe client directive"):
            RD._validate_extracted_archive(
                _fake_backup(),
                _fake_auth(CoreAuthDatabase.DatabaseType.MARIADB),
                self.tmp,
                mode="in_place",
            )

    def test_mariadb_fork_rejects_unpaired_commit(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"CREATE TABLE restored(id integer);\nCOMMIT;\n")

        with self.assertRaisesRegex(RestoreError, "unsafe client directive"):
            RD._validate_extracted_archive(
                _fake_backup(),
                _fake_auth(CoreAuthDatabase.DatabaseType.MARIADB),
                self.tmp,
                mode="fork",
            )

    def test_mariadb_fork_rejects_incomplete_vendor_transaction_scaffolding(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(
                b"SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;\n"
                b"CREATE TABLE restored(id integer);\n"
                b"COMMIT;\n"
            )

        with self.assertRaisesRegex(RestoreError, "malformed vendor transaction"):
            RD._validate_extracted_archive(
                _fake_backup(),
                _fake_auth(CoreAuthDatabase.DatabaseType.MARIADB),
                self.tmp,
                mode="fork",
            )

    def test_client_stderr_is_not_returned_or_persisted(self):
        backup = _fake_backup()
        node = SimpleNamespace(
            id=1,
            name="db-node",
            connection=SimpleNamespace(
                id=1,
                name="db-connection",
                account=SimpleNamespace(create_log=lambda data: None),
            ),
        )
        with mock.patch.object(
            RD.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"password=TOP-SECRET"),
        ), mock.patch.object(RD, "_write_log") as log, mock.patch.object(RD, "capture_exception"):
            with self.assertRaises(NodeBackupFailedError) as context:
                RD._run_direct(
                    node,
                    backup,
                    ["mysql", "--defaults-extra-file=/tmp/credentials", "source_db"],
                    "dbuser",
                    "TOP-SECRET",
                    "MYSQL",
                    "import source database source_db",
                )
        self.assertNotIn("TOP-SECRET", str(context.exception))
        self.assertNotIn("TOP-SECRET", " ".join(str(call) for call in log.call_args_list))

    def test_remote_temporary_files_are_mode_0600_and_ssh_is_bounded(self):
        class Channel:
            def __init__(self):
                self.timeout = None

            def settimeout(self, value):
                self.timeout = value

            def recv_exit_status(self):
                return 0

        class RemoteFile:
            def __init__(self):
                self.content = ""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def write(self, content):
                self.content += content

        class SFTP:
            def __init__(self):
                self.channel = Channel()
                self.file = RemoteFile()
                self.chmods = []

            def get_channel(self):
                return self.channel

            def open(self, _name, _mode):
                return self.file

            def chmod(self, name, mode):
                self.chmods.append((name, mode))

            def close(self):
                pass

        class Stream:
            def __init__(self, data, channel):
                self.data = data
                self.channel = channel

            def read(self):
                return self.data

        class SSH:
            def __init__(self, sftp):
                self.sftp = sftp
                self.calls = []
                self.channel = Channel()

            def open_sftp(self):
                return self.sftp

            def exec_command(self, command, timeout=None):
                self.calls.append((command, timeout))
                return None, Stream(b"ok\n", self.channel), Stream(b"", self.channel)

        sftp = SFTP()
        ssh = SSH(sftp)
        RD._sftp_write(ssh, "bs-credentials", "password=TOP-SECRET\n")
        self.assertEqual(sftp.chmods, [("bs-credentials", 0o600)])
        backup = _fake_backup()
        with mock.patch.object(RD, "_write_log") as log:
            self.assertEqual(
                RD._ssh_run(
                    SimpleNamespace(),
                    backup,
                    ssh,
                    "mysql --defaults-extra-file=$HOME/bs-credentials",
                    "dbuser",
                    "TOP-SECRET",
                    "MYSQL",
                    "marker query",
                ),
                "ok\n",
            )
        self.assertEqual(ssh.calls[0][1], RD.COMMAND_TIMEOUT)
        self.assertNotIn("TOP-SECRET", ssh.calls[0][0])
        self.assertNotIn("TOP-SECRET", " ".join(str(call) for call in log.call_args_list))


class RemoteDatabaseRestoreTempCleanupTests(BaseTestCase):
    """Remote cleanup is exact, fenced, idempotent, and secret-safe."""

    @staticmethod
    def _restore(owner, token, correlation=None):
        restore = _FakeRestore()
        if correlation is not None:
            restore.correlation_id = uuid.UUID(correlation)
        restore._required_restore_lease_owner = owner
        restore._required_restore_lease_token = token
        return restore

    @staticmethod
    def _ssh(names=None, remove_error=None):
        inventory = list(names or [])
        sftp = mock.Mock()
        sftp.listdir.side_effect = lambda _path: list(inventory)

        def remove(remote_name):
            if remove_error is not None:
                raise remove_error
            if remote_name in inventory:
                inventory.remove(remote_name)

        sftp.remove.side_effect = remove
        ssh = mock.Mock()
        ssh.open_sftp.return_value = sftp
        return ssh, sftp

    def test_hard_kill_residue_is_removed_only_for_exact_restore_and_old_fence(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        previous = self._restore("worker-old", "fence-old")
        another_restore = self._restore(
            "worker-other", "fence-other", "99999999-8888-7777-6666-555555555555"
        )
        another_backup = _fake_backup()
        another_backup.uuid = uuid.UUID("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
        another_backup.uuid_str = str(another_backup.uuid)

        stale_pgpass = RD._remote_restore_temp_name(
            previous, backup, "postgres_credentials"
        )
        stale_postgres_sql = RD._remote_restore_temp_name(
            previous,
            backup,
            "postgres_sql",
            source="appdb",
            filename="__combined__",
        )
        stale_mysql_sql = RD._remote_restore_temp_name(
            previous,
            backup,
            "mysql_sql",
            source="appdb",
            filename="dump.sql",
        )
        current_pgpass = RD._remote_restore_temp_name(
            current, backup, "postgres_credentials"
        )
        current_mysql_sql = RD._remote_restore_temp_name(
            current,
            backup,
            "mysql_sql",
            source="appdb",
            filename="dump.sql",
        )
        other_correlation = RD._remote_restore_temp_name(
            another_restore, backup, "postgres_credentials"
        )
        other_backup = RD._remote_restore_temp_name(
            current, another_backup, "mysql_credentials"
        )
        legacy_name = f".backupsheep_restore_{backup.uuid_str}_old.pgpass"
        user_file = "customer-data.sql"
        ssh, sftp = self._ssh(
            [
                stale_pgpass,
                stale_postgres_sql,
                stale_mysql_sql,
                current_pgpass,
                current_mysql_sql,
                other_correlation,
                other_backup,
                legacy_name,
                user_file,
            ]
        )

        with mock.patch.object(
            RD, "_has_competing_live_restore", return_value=False
        ), mock.patch.object(RD, "_capture_safe") as capture:
            RD._cleanup_stale_remote_restore_artifacts(ssh, current, backup)

        self.assertEqual(
            sftp.remove.call_args_list,
            [
                mock.call(stale_pgpass),
                mock.call(stale_postgres_sql),
                mock.call(stale_mysql_sql),
            ],
        )
        self.assertEqual(sftp.listdir.call_args.args, (".",))
        capture.assert_not_called()

    def test_strict_legacy_names_are_removed_only_for_exact_backup(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        suffix = "0123456789abcdef"
        legacy_names = [
            f".backupsheep_restore_{backup.uuid_str}_{suffix}.pgpass",
            f".backupsheep_restore_preflight_{backup.uuid_str}_{suffix}.cnf",
            f".backupsheep_restore_{backup.uuid_str}_{suffix}_" + "a" * 12 + "_" + "b" * 8 + ".sql",
            f".backupsheep_restore_{backup.uuid_str}_{suffix}_" + "c" * 12 + ".sql",
        ]
        unrelated = [
            f".backupsheep_restore_{backup.uuid_str}_old.pgpass",
            ".backupsheep_restore_bbbbbbbb-cccc-dddd-eeee-ffffffffffff_"
            f"{suffix}.pgpass",
            "customer-data.sql",
        ]
        ssh, sftp = self._ssh(legacy_names + unrelated)

        with mock.patch.object(
            RD, "_has_competing_live_restore", return_value=False
        ):
            RD._cleanup_stale_remote_restore_artifacts(
                ssh, current, backup, include_current=True
            )

        self.assertEqual(
            sftp.remove.call_args_list,
            [mock.call(name) for name in legacy_names],
        )
        self.assertEqual(
            RD._remote_restore_artifact_inventory(ssh, current, backup), []
        )

    def test_current_worker_artifacts_are_excluded_even_when_they_are_stale(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        current_credentials = RD._remote_restore_temp_name(
            current, backup, "mysql_credentials"
        )
        current_sql = RD._remote_restore_temp_name(
            current,
            backup,
            "mysql_sql",
            source="appdb",
            filename="dump.sql",
        )
        ssh, sftp = self._ssh([current_credentials, current_sql])

        RD._cleanup_stale_remote_restore_artifacts(ssh, current, backup)

        sftp.remove.assert_not_called()

    def test_successful_worker_final_sweep_removes_current_fence_artifacts(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        current_credentials = RD._remote_restore_temp_name(
            current, backup, "postgres_credentials"
        )
        current_sql = RD._remote_restore_temp_name(
            current,
            backup,
            "postgres_sql",
            source="appdb",
            filename="__combined__",
        )
        another_restore = self._restore(
            "worker-other", "fence-other", "99999999-8888-7777-6666-555555555555"
        )
        other_correlation = RD._remote_restore_temp_name(
            another_restore, backup, "postgres_credentials"
        )
        ssh, sftp = self._ssh(
            [current_credentials, current_sql, other_correlation, "customer-data.sql"]
        )

        RD._cleanup_stale_remote_restore_artifacts(
            ssh, current, backup, include_current=True
        )

        self.assertEqual(
            sftp.remove.call_args_list,
            [mock.call(current_credentials), mock.call(current_sql)],
        )
        self.assertEqual(
            RD._remote_restore_artifact_inventory(ssh, current, backup), []
        )

    def test_failed_final_sweep_requires_manual_reconciliation_and_hides_details(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        current_sql = RD._remote_restore_temp_name(
            current,
            backup,
            "postgres_sql",
            source="appdb",
            filename="__combined__",
        )
        ssh, sftp = self._ssh(
            [current_sql],
            remove_error=TimeoutError("remote provider secret endpoint timed out"),
        )

        with mock.patch.object(RD, "_capture_safe") as capture:
            with self.assertRaises(RD.RemoteRestoreCleanupError) as raised:
                RD._cleanup_stale_remote_restore_artifacts(
                    ssh, current, backup, include_current=True
                )

        self.assertEqual(raised.exception.category, "SFTP_CLEANUP_TIMEOUT")
        self.assertEqual(raised.exception.code, "RESTORE_RECONCILIATION_REQUIRED")
        self.assertFalse(raised.exception.retryable)
        self.assertNotIn("provider secret endpoint", str(raised.exception))
        capture.assert_called_once_with("SFTP_CLEANUP_TIMEOUT")
        self.assertEqual(sftp.close.call_count, 3)

    def test_legacy_cleanup_refuses_when_a_competing_restore_is_live(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        legacy_name = f".backupsheep_restore_{backup.uuid_str}.pgpass"
        ssh, sftp = self._ssh([legacy_name])

        with mock.patch.object(
            RD, "_has_competing_live_restore", return_value=True
        ), mock.patch.object(RD, "_capture_safe") as capture:
            with self.assertRaises(RD.RemoteRestoreCleanupError) as raised:
                RD._cleanup_stale_remote_restore_artifacts(
                    ssh, current, backup, include_current=True
                )

        self.assertEqual(raised.exception.category, "SFTP_CLEANUP_COMPETING_RESTORE")
        self.assertEqual(raised.exception.code, "RESTORE_RECONCILIATION_REQUIRED")
        sftp.remove.assert_not_called()
        capture.assert_called_once_with("SFTP_CLEANUP_COMPETING_RESTORE")

    def test_lease_loss_after_open_is_checked_before_remove(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        name = RD._remote_restore_temp_name(current, backup, "mysql_credentials")
        ssh, sftp = self._ssh([name])

        with mock.patch.object(
            RD,
            "_ensure_restore_fence",
            side_effect=[None, RD.RestoreLeaseLost("lease expired")],
        ):
            with self.assertRaises(RD.RestoreLeaseLost):
                RD._sftp_remove(ssh, name, restore=current, backup=backup)

        ssh.open_sftp.assert_called_once()
        sftp.remove.assert_not_called()
        sftp.close.assert_called_once()

    def test_open_sftp_is_bounded_and_transport_timeout_is_restored(self):
        class Transport:
            channel_timeout = 3600

        class SSH:
            def __init__(self):
                self.transport = Transport()
                self.seen_timeout = None
                self.sftp = mock.Mock()

            def get_transport(self):
                return self.transport

            def open_sftp(self):
                self.seen_timeout = self.transport.channel_timeout
                return self.sftp

        ssh = SSH()
        self.assertIs(RD._open_sftp_bounded(ssh, 17), ssh.sftp)
        self.assertEqual(ssh.seen_timeout, 17)
        self.assertEqual(ssh.transport.channel_timeout, 3600)

    def test_upload_rejects_a_prior_fence_filename(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        previous = self._restore("worker-previous", "fence-previous")
        prior_name = RD._remote_restore_temp_name(
            previous,
            backup,
            "postgres_sql",
            source="appdb",
            filename="__combined__",
        )
        ssh, _sftp = self._ssh()

        with self.assertRaises(RestoreError):
            RD._sftp_put(
                ssh,
                "/tmp/verified.sql",
                prior_name,
                restore=current,
                backup=backup,
            )

        ssh.open_sftp.assert_not_called()

    def test_missing_remote_file_is_idempotent(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        name = RD._remote_restore_temp_name(
            current,
            backup,
            "postgres_credentials",
        )
        ssh, sftp = self._ssh(
            remove_error=FileNotFoundError(errno.ENOENT, "no such file")
        )
        with mock.patch.object(RD, "_capture_safe") as capture:
            self.assertTrue(
                RD._sftp_remove(ssh, name, restore=current, backup=backup)
            )
        capture.assert_not_called()
        sftp.close.assert_called_once()

    def test_cleanup_failures_are_classified_without_provider_details(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        cases = (
            (PermissionError(errno.EACCES, "permission denied"), "SFTP_CLEANUP_PERMISSION_DENIED"),
            (RuntimeError("authentication failed for remote host"), "SFTP_CLEANUP_AUTH_FAILED"),
            (RuntimeError("transport connection reset"), "SFTP_CLEANUP_TRANSPORT_FAILED"),
        )
        for error, code in cases:
            with self.subTest(code=code):
                ssh, sftp = self._ssh(remove_error=error)
                name = RD._remote_restore_temp_name(
                    current, backup, "mysql_credentials"
                )
                with mock.patch.object(RD, "_capture_safe") as capture:
                    with self.assertRaises(RD.RemoteRestoreCleanupError) as raised:
                        RD._sftp_remove(
                            ssh, name, restore=current, backup=backup
                        )
                self.assertEqual(raised.exception.category, code)
                self.assertEqual(
                    raised.exception.code,
                    "RESTORE_RECONCILIATION_REQUIRED",
                )
                self.assertFalse(raised.exception.retryable)
                capture.assert_called_once_with(code)
                sftp.close.assert_called_once()

    def test_listing_failure_is_classified_without_deleting_anything(self):
        backup = _fake_backup()
        current = self._restore("worker-current", "fence-current")
        ssh, sftp = self._ssh()
        sftp.listdir.side_effect = PermissionError(errno.EACCES, "permission denied")

        with mock.patch.object(RD, "_capture_safe") as capture:
            with self.assertRaises(RD.RemoteRestoreCleanupError) as raised:
                RD._cleanup_stale_remote_restore_artifacts(ssh, current, backup)

        capture.assert_called_once_with("SFTP_CLEANUP_PERMISSION_DENIED")
        self.assertEqual(raised.exception.code, "RESTORE_RECONCILIATION_REQUIRED")
        sftp.remove.assert_not_called()
        sftp.close.assert_called_once()

    def test_stale_worker_cannot_write_a_namespaced_temp_file(self):
        backup = _fake_backup()
        stale = self._restore("worker-stale", "fence-stale")
        name = RD._remote_restore_temp_name(stale, backup, "mysql_credentials")
        ssh, _sftp = self._ssh()

        with mock.patch.object(
            RD, "_ensure_restore_fence", side_effect=RD.RestoreLeaseLost
        ):
            with self.assertRaises(RD.RestoreLeaseLost):
                RD._sftp_write(
                    ssh,
                    name,
                    "password=redacted\n",
                    restore=stale,
                    backup=backup,
                )

        ssh.open_sftp.assert_not_called()

    def test_cleanup_requires_a_live_fence_before_listing_or_deleting(self):
        backup = _fake_backup()
        unfenced = _FakeRestore()
        ssh, sftp = self._ssh()

        with mock.patch.object(RD, "_capture_safe") as capture:
            with self.assertRaises(RD.RestoreLeaseLost):
                RD._cleanup_stale_remote_restore_artifacts(ssh, unfenced, backup)
            with self.assertRaises(RD.RestoreLeaseLost):
                RD._sftp_remove(
                    ssh,
                    RD._remote_restore_temp_name(
                        self._restore("worker", "fence"), backup, "mysql_credentials"
                    ),
                    restore=unfenced,
                    backup=backup,
                )

        capture.assert_not_called()
        sftp.listdir.assert_not_called()
        sftp.remove.assert_not_called()
