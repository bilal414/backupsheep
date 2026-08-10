"""Focused safety tests for logical database restore policy and resumption."""

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
from apps._tasks.integration import restore_database as RD
from apps._tasks.integration.restore_common import RestoreError
from apps.api.v1.backup.database.views import (
    CoreDatabaseBackupView,
    _in_place_confirmation,
)
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


def _fake_backup():
    return SimpleNamespace(
        uuid=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        uuid_str="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        attempt_no=1,
        type="database",
        size=1,
        tables=None,
        all_tables=True,
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
        self.assertEqual(query.call_count, 2)

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

        with mock.patch.object(RD, "_postgres_query", side_effect=["", "", "1\n", complete]), \
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

    def test_archive_cannot_overwrite_restore_ownership_marker(self):
        sql_path = os.path.join(self.tmp, "source_db.sql")
        with open(sql_path, "wb") as output:
            output.write(b"DROP TABLE __backupsheep_restore_marker;\n")

        with self.assertRaises(RestoreError):
            RD._validate_extracted_archive(
                _fake_backup(), _fake_auth(), self.tmp
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
