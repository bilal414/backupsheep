"""Crash-safety contract tests for website and logical database restores.

These tests deliberately model the failure boundary that matters for restore
operations: the remote side may have accepted a destructive action while the
worker lost its response, or a worker may lose its durable lease after a
checkpoint was committed.  A retry must either adopt an exact durable marker
or stop for manual review; it must never guess and repeat a destructive
operation.
"""

import hashlib
import os
import uuid
from collections import OrderedDict
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration import restore_database as RD
from apps._tasks.integration import restore_website as RW
from apps._tasks.integration.restore_common import RestoreError
from apps._tasks.integration.restore_lease import (
    DurableRestoreLease,
    RestoreLeaseLost,
)
from apps.console.backup.models import CoreDatabaseRestore, CoreWebsiteRestore
from apps.console.connection.models import CoreAuthDatabase
from apps.tests.test_restore import RestoreBackendBase


class LogicalRestoreCrashSafetyTests(RestoreBackendBase):
    """Exercise durable replay boundaries without contacting a real endpoint."""

    def _claim(self, restore, phase, task_id):
        lease = DurableRestoreLease(restore, phase=phase, task_id=task_id)
        bound = lease.claim()
        # If a test exits before simulating the crash, release its lease.  When
        # a takeover is simulated this cleanup is fenced by the old token and
        # therefore cannot clear the replacement worker's lease.
        self.addCleanup(lease.release)
        return lease, bound

    @staticmethod
    def _stop_lease_without_release(lease):
        lease._stop.set()
        if lease._thread:
            lease._thread.join(timeout=2)

    def _take_over(self, lease, restore, phase, task_id):
        self._stop_lease_without_release(lease)
        restore.__class__.objects.filter(pk=restore.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )
        return self._claim(restore, phase, task_id)

    def _website_record(self, backup):
        tree_root = os.path.join(self.tmp, f"website-source-{uuid.uuid4().hex}")
        site_root = os.path.join(tree_root, "public_html")
        os.makedirs(site_root)
        with open(os.path.join(site_root, "index.html"), "wb") as output:
            output.write(b"restore payload\n")
        records, manifest = RW._prepare_sources(
            tree_root,
            [{"path": "public_html", "type": "directory"}],
            backup,
        )
        return records[0], manifest

    @staticmethod
    def _website_call_args(backup, restore, record):
        node = backup.website.node
        auth = node.connection.auth_website
        website = node.website
        return (
            node,
            backup,
            restore,
            auth,
            record,
            website,
            f"ftp://{auth.host}",
            "restore-user",
            "restore-password",
            None,
        )

    def _database_restore(
        self,
        *,
        contents=b"CREATE TABLE restored(id int);\n",
        db_type=CoreAuthDatabase.DatabaseType.MYSQL,
        version=None,
    ):
        if version is None:
            version = (
                "postgres_16"
                if db_type == CoreAuthDatabase.DatabaseType.POSTGRESQL
                else "mysql_8_0"
            )
        node, backup = self._database_backup(
            db_type=db_type,
            version=version,
        )
        restore = CoreDatabaseRestore.objects.create(
            backup=backup,
            name="crash-safe-database-restore",
            params={"mode": "fork"},
        )
        # The filename is part of the immutable archive identity and must
        # match the name recorded in source_digests.
        sql_path = os.path.join(self.tmp, "appdb.sql")
        with open(sql_path, "wb") as output:
            output.write(contents)
        source_digests = {
            "appdb": [
                {
                    "file": "appdb.sql",
                    "bytes": len(contents),
                    "sha256": hashlib.sha256(contents).hexdigest(),
                }
            ]
        }
        mapping = {"appdb": "bs_restore_owned"}
        return node, backup, restore, sql_path, source_digests, mapping

    @staticmethod
    def _marker_text(values):
        return (
            "\t".join(
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
            )
            + "\n"
        )

    def test_website_lost_publish_response_is_checkpointed_and_not_replayed(self):
        """A lost publish response becomes manual review, never a second mv."""
        node, backup = self._website_backup(
            all_paths=False,
            paths=[{"path": "public_html", "type": "directory"}],
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=backup,
            name="crash-safe-website-restore",
            params={"delete": False},
        )
        lease, bound = self._claim(
            restore,
            "website_restore",
            f"website-lost-publish-{uuid.uuid4().hex}",
        )
        record, manifest = self._website_record(backup)
        RW._checkpoint(
            bound,
            phase="archive_validated",
            manifest=manifest,
            records=[
                {
                    **record,
                    "state": RW._state_for(
                        record,
                        "pending",
                        files_status="pending",
                        stage=RW._remote_stage_paths(bound, record),
                    ),
                }
            ],
            progress_total=1,
        )
        args = self._website_call_args(backup, bound, record)

        # The staging upload succeeds.  The following publish may have moved
        # the target remotely, but the worker loses the response before it can
        # commit the complete checkpoint.
        with mock.patch.object(
            RW,
            "_run_lftp",
            side_effect=[None, RuntimeError("lost publish response")],
        ) as transfer:
            with self.assertRaisesRegex(RuntimeError, "lost publish response"):
                RW._staged_restore_source(*args)

        restore.refresh_from_db()
        state = restore.execution_metadata["source_states"][record["fingerprint"]]
        self.assertEqual(restore.execution_phase, "website_publishing")
        self.assertEqual(state["status"], "publishing")
        self.assertEqual(transfer.call_count, 2)

        replacement_lease, replacement = self._take_over(
            lease,
            restore,
            "website_restore_replay",
            f"website-replay-{uuid.uuid4().hex}",
        )
        self.assertIsNotNone(replacement_lease)

        # The replay sees the durable publishing checkpoint and refuses to
        # issue any remote command, including a second destructive publish.
        with mock.patch.object(RW, "_run_lftp") as replay_transfer:
            with self.assertRaisesRegex(
                RestoreError, "publish outcome is ambiguous"
            ):
                RW._staged_restore_source(
                    *self._website_call_args(backup, replacement, record)
                )
        replay_transfer.assert_not_called()

    def test_stale_fenced_website_worker_cannot_publish_after_checkpoint(self):
        """A replacement lease fences the old worker before its publish call."""
        node, backup = self._website_backup(
            all_paths=False,
            paths=[{"path": "public_html", "type": "directory"}],
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=backup,
            name="stale-website-worker",
            params={"delete": False},
        )
        lease, bound = self._claim(
            restore,
            "website_restore",
            f"website-stale-{uuid.uuid4().hex}",
        )
        record, manifest = self._website_record(backup)
        stage = RW._remote_stage_paths(bound, record)
        RW._checkpoint(
            bound,
            phase="website_staged",
            manifest=manifest,
            records=[
                {
                    **record,
                    "state": RW._state_for(
                        record,
                        "staged",
                        files_status="staged",
                        stage=stage,
                    ),
                }
            ],
            progress_total=1,
        )

        _replacement_lease, _replacement = self._take_over(
            lease,
            restore,
            "website_replacement",
            f"website-replacement-{uuid.uuid4().hex}",
        )

        with mock.patch.object(RW, "_run_lftp") as stale_transfer:
            with self.assertRaises(RestoreLeaseLost):
                RW._staged_restore_source(
                    *self._website_call_args(backup, bound, record)
                )
        stale_transfer.assert_not_called()

        current = CoreWebsiteRestore.objects.get(pk=restore.pk)
        current_state = current.execution_metadata["source_states"][
            record["fingerprint"]
        ]
        self.assertEqual(current_state["status"], "staged")

    def test_database_lost_create_response_adopts_exact_marker_without_recreate(self):
        """A lost CREATE response is adopted only through an exact marker."""
        node, backup, restore, _sql_path, _digests, _mapping = self._database_restore()
        auth = node.connection.auth_database
        target = "bs_restore_owned"
        digest = "d" * 64
        expected = RD._marker_values(
            restore,
            backup,
            "appdb",
            target,
            digest,
            "importing",
        )
        lost_response = NodeBackupFailedError(None, message="lost create response")

        with mock.patch.object(
            RD,
            "_mysql_query",
            side_effect=["", lost_response, "1\n", self._marker_text(expected)],
        ) as query, mock.patch.object(RD, "_capture_safe"):
            adopted = RD._ensure_mysql_target(
                node,
                backup,
                restore,
                auth,
                "appdb",
                target,
                digest,
                "dbuser",
                "db-password",
                in_place=False,
                defaults_arg="--defaults-extra-file=/tmp/restore.cnf",
            )

        self.assertEqual(adopted["state"], "importing")
        self.assertEqual(query.call_count, 4)
        self.assertIn("CREATE DATABASE", query.call_args_list[1].args[4])

        # A redelivery now observes the existing exact marker.  It cannot
        # issue another CREATE or any destructive cleanup.
        with mock.patch.object(
            RD,
            "_mysql_query",
            side_effect=["1\n", self._marker_text(expected)],
        ) as replay_query:
            replayed = RD._ensure_mysql_target(
                node,
                backup,
                restore,
                auth,
                "appdb",
                target,
                digest,
                "dbuser",
                "db-password",
                in_place=False,
                defaults_arg="--defaults-extra-file=/tmp/restore.cnf",
            )
        self.assertEqual(replayed["state"], "importing")
        replay_sql = [call.args[4] for call in replay_query.call_args_list]
        self.assertFalse(any("CREATE DATABASE" in sql for sql in replay_sql))
        self.assertFalse(any("DROP DATABASE" in sql for sql in replay_sql))

    def test_database_worker_crash_after_file_checkpoint_does_not_reimport(self):
        """An interrupted SQL file is durable and retry stops before re-import."""
        node, backup, restore, sql_path, source_digests, mapping = self._database_restore()
        lease, bound = self._claim(
            restore,
            "database_restore",
            f"database-crash-{uuid.uuid4().hex}",
        )
        targets = OrderedDict({"appdb": [sql_path]})
        auth = node.connection.auth_database

        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            return_value={"state": "importing", "_new": True},
        ), mock.patch.object(
            RD,
            "_run_direct",
            side_effect=NodeBackupFailedError(None, message="worker crashed"),
        ), mock.patch.object(RD, "_capture_safe"):
            with self.assertRaises(NodeBackupFailedError):
                RD._restore_mysql_family(
                    node,
                    backup,
                    bound,
                    auth,
                    targets,
                    mapping,
                    source_digests,
                    "dbuser",
                    "db-password",
                )

        restore.refresh_from_db()
        target_checkpoint = restore.execution_metadata["target_checkpoints"][
            mapping["appdb"]
        ]
        self.assertEqual(target_checkpoint["status"], "importing")
        self.assertEqual(
            target_checkpoint["files"]["appdb.sql"]["status"],
            "in_progress",
        )

        _replacement_lease, replacement = self._take_over(
            lease,
            restore,
            "database_restore_retry",
            f"database-retry-{uuid.uuid4().hex}",
        )
        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            return_value={"state": "importing"},
        ), mock.patch.object(RD, "_run_direct") as reimport, mock.patch.object(
            RD, "_drop_mysql_owned_target"
        ) as drop_target:
            with self.assertRaisesRegex(
                RestoreError, "import outcome is ambiguous"
            ):
                RD._restore_mysql_family(
                    node,
                    backup,
                    replacement,
                    auth,
                    targets,
                    mapping,
                    source_digests,
                    "dbuser",
                    "db-password",
                )
        reimport.assert_not_called()
        drop_target.assert_not_called()

    def test_database_takeover_cleans_prior_and_current_local_generations(self):
        node, backup, restore, _sql_path, _digests, _mapping = self._database_restore()
        lease, bound = self._claim(
            restore,
            "database_restore",
            f"database-cleanup-crash-{uuid.uuid4().hex}",
        )
        stale_prefix = (
            f"restore_{backup.uuid_str}_{RD._restore_work_suffix(bound, backup)}"
        )
        _replacement_lease, replacement = self._take_over(
            lease,
            restore,
            "database_restore_retry",
            f"database-cleanup-retry-{uuid.uuid4().hex}",
        )
        current_prefix = (
            f"restore_{backup.uuid_str}_{RD._restore_work_suffix(replacement, backup)}"
        )

        with mock.patch.object(RD, "ensure_disk_space"), mock.patch.object(
            RD, "delete_from_disk"
        ) as cleanup:
            with self.assertRaisesRegex(RestoreError, "storage point"):
                RD.restore_database(backup, replacement)

        self.assertEqual(
            cleanup.apply_async.call_args_list,
            [
                mock.call(args=[stale_prefix, "restore"]),
                mock.call(args=[current_prefix, "restore"]),
            ],
        )

    def test_website_takeover_cleans_prior_and_current_local_generations(self):
        node, backup = self._website_backup(all_paths=True)
        restore = CoreWebsiteRestore.objects.create(
            backup=backup,
            name="crash-cleanup-website-restore",
            params={"delete": False},
        )
        lease, bound = self._claim(
            restore,
            "website_restore",
            f"website-cleanup-crash-{uuid.uuid4().hex}",
        )
        stale_prefix = (
            f"restore_{backup.uuid_str}_{RW._restore_work_suffix(bound, backup)}"
        )
        _replacement_lease, replacement = self._take_over(
            lease,
            restore,
            "website_restore_retry",
            f"website-cleanup-retry-{uuid.uuid4().hex}",
        )
        current_prefix = (
            f"restore_{backup.uuid_str}_{RW._restore_work_suffix(replacement, backup)}"
        )

        with mock.patch.object(RW, "ensure_disk_space"), mock.patch.object(
            RW, "delete_from_disk"
        ) as cleanup:
            with self.assertRaisesRegex(RestoreError, "storage point"):
                RW.restore_website(backup, replacement)

        self.assertEqual(
            cleanup.apply_async.call_args_list,
            [
                mock.call(args=[stale_prefix, "restore"]),
                mock.call(args=[current_prefix, "restore"]),
            ],
        )

    def test_postgresql_stale_lease_replays_rolled_back_atomic_import(self):
        """An importing marker proves a crashed PostgreSQL transaction rolled back."""
        node, backup, restore, sql_path, source_digests, mapping = self._database_restore(
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
        )
        target = mapping["appdb"]
        digest = RD._source_digest(source_digests, "appdb")
        lease, bound = self._claim(
            restore,
            "database_restore",
            f"postgres-crash-{uuid.uuid4().hex}",
        )
        RD._checkpoint(
            bound,
            phase="database_importing",
            mapping=mapping,
            source_digests=source_digests,
            checkpoints={
                target: {
                    "source": "appdb",
                    "source_digest": digest,
                    "status": "importing",
                    "files": {
                        "appdb.sql": {
                            **source_digests["appdb"][0],
                            "status": "in_progress",
                        }
                    },
                }
            },
            progress_total=1,
        )
        importing = RD._marker_values(
            bound, backup, "appdb", target, digest, "importing"
        )
        complete = RD._marker_values(
            bound, backup, "appdb", target, digest, "complete"
        )
        replacement_lease, replacement = self._take_over(
            lease,
            restore,
            "database_restore_retry",
            f"postgres-retry-{uuid.uuid4().hex}",
        )
        self.assertIsNotNone(replacement_lease)

        with mock.patch.object(
            RD,
            "_postgres_query",
            side_effect=[
                "1\n",
                "1\n",
                self._marker_text(importing),
                "1\n",
                "1\n",
                self._marker_text(complete),
            ],
        ), mock.patch.object(RD, "_run_direct", return_value="") as replay:
            RD._restore_postgresql(
                node,
                backup,
                replacement,
                node.connection.auth_database,
                OrderedDict({"appdb": [sql_path]}),
                mapping,
                source_digests,
                "dbuser",
                "db-password",
            )

        self.assertEqual(replay.call_count, 1)
        restore.refresh_from_db()
        checkpoint = restore.execution_metadata["target_checkpoints"][target]
        self.assertEqual(checkpoint["status"], "complete")
        self.assertEqual(checkpoint["files"]["appdb.sql"]["status"], "complete")
        self.assertEqual(checkpoint["transaction_replay_count"], 1)
        self.assertEqual(restore.execution_phase, "database_complete")
        self.assertEqual(restore.progress_completed, 1)

    def test_database_marker_mismatch_fails_closed_without_destructive_sql(self):
        """A target with another restore's marker is never overwritten."""
        node, backup, restore, _sql_path, _digests, _mapping = self._database_restore()
        auth = node.connection.auth_database
        target = "bs_restore_marker_mismatch"
        digest = "e" * 64
        wrong = RD._marker_values(
            restore,
            backup,
            "appdb",
            target,
            digest,
            "importing",
        )
        wrong["correlation_id"] = str(uuid.uuid4())

        with mock.patch.object(
            RD,
            "_mysql_query",
            side_effect=["1\n", self._marker_text(wrong)],
        ) as query:
            with self.assertRaisesRegex(
                RestoreError, "marker does not belong"
            ):
                RD._ensure_mysql_target(
                    node,
                    backup,
                    restore,
                    auth,
                    "appdb",
                    target,
                    digest,
                    "dbuser",
                    "db-password",
                    in_place=False,
                    defaults_arg="--defaults-extra-file=/tmp/restore.cnf",
                )

        sql = [call.args[4] for call in query.call_args_list]
        self.assertFalse(any("CREATE DATABASE" in statement for statement in sql))
        self.assertFalse(any("DROP DATABASE" in statement for statement in sql))

    def test_markerless_database_collision_is_classified_without_mutation(self):
        """A missing marker table is a collision, not a generic client failure."""
        node, backup, restore, _sql_path, _digests, _mapping = self._database_restore()
        auth = node.connection.auth_database
        target = "bs_restore_markerless_collision"
        digest = "e" * 64
        missing_marker = NodeBackupFailedError(
            None,
            message="marker table does not exist",
        )

        with mock.patch.object(
            RD,
            "_mysql_query",
            side_effect=["1\n", missing_marker, ""],
        ) as query:
            with self.assertRaisesRegex(RestoreError, "name collision"):
                RD._ensure_mysql_target(
                    node,
                    backup,
                    restore,
                    auth,
                    "appdb",
                    target,
                    digest,
                    "dbuser",
                    "db-password",
                    in_place=False,
                    defaults_arg="--defaults-extra-file=/tmp/restore.cnf",
                )

        sql = [call.args[4] for call in query.call_args_list]
        self.assertEqual(len(sql), 3)
        self.assertIn("information_schema.TABLES", sql[-1])
        self.assertIn(RD.MYSQL_MARKER_TABLE, sql[-1])
        self.assertFalse(any("CREATE DATABASE" in statement for statement in sql))
        self.assertFalse(any("DROP DATABASE" in statement for statement in sql))

    def test_completed_database_checkpoint_retry_skips_drop_and_import(self):
        """A completed owned target is adopted without replaying DDL."""
        node, backup, restore, sql_path, source_digests, mapping = self._database_restore()
        target = mapping["appdb"]
        digest = RD._source_digest(source_digests, "appdb")
        restore.execution_metadata = {
            "source_to_target": mapping,
            "source_digests": source_digests,
            "target_checkpoints": {
                target: {
                    "source": "appdb",
                    "source_digest": digest,
                    "status": "complete",
                }
            },
        }
        restore.save(update_fields=["execution_metadata", "modified"])
        targets = OrderedDict({"appdb": [sql_path]})

        with mock.patch.object(
            RD,
            "_ensure_mysql_target",
            return_value={"state": "complete"},
        ), mock.patch.object(RD, "_run_direct") as import_sql, mock.patch.object(
            RD, "_drop_mysql_owned_target"
        ) as drop_target, mock.patch.object(RD, "_write_local_defaults_file"):
            RD._restore_mysql_family(
                node,
                backup,
                restore,
                node.connection.auth_database,
                targets,
                mapping,
                source_digests,
                "dbuser",
                "db-password",
            )

        import_sql.assert_not_called()
        drop_target.assert_not_called()
        restore.refresh_from_db()
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][target]["status"],
            "complete",
        )
