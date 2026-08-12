"""Contract tests for bounded logical database restore verification resumes."""

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from unittest import mock

from django.db import close_old_connections
from django.template.loader import get_template
from django.test import SimpleTestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.backup.database.serializers import (
    CoreDatabaseRestoreSerializer,
    database_restore_verification_resume_mode,
)
from apps.api.v1.backup.database.views import CoreDatabaseBackupView
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseRestore,
)
from apps.console.connection.models import CoreAuthDatabase, CoreIntegration
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.test_backup_engine import make_database_node


class DatabaseRestoreResumeApiTests(TransactionTestCase):
    def setUp(self):
        CoreIntegration.objects.get_or_create(
            code="database",
            defaults={
                "name": "Database",
                "type": CoreIntegration.Type.DATABASE,
            },
        )
        self.account, self.member, self.user = factories.make_account()
        self.node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16",
        )
        self.backup = CoreDatabaseBackup.objects.create(
            database=self.node.database,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            all_tables=True,
        )

    @staticmethod
    def _source_digest(source, files):
        canonical = json.dumps(
            {source: sorted(files, key=lambda item: item["file"])},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _safe_restore(self, **overrides):
        source = "appdb"
        target = "bs_restore_existing"
        payload = b"CREATE TABLE t(id int);\n"
        file_spec = {
            "file": "appdb.sql",
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        digest = self._source_digest(source, [file_spec])
        mapping = {source: target}
        params = {
            "mode": "fork",
            "target_mapping": mapping,
            "mapping_locked": True,
            "source_backup_uuid": str(self.backup.uuid),
            "immutable_request": "preserve-me",
            "_bs_last_error_code": "RESTORE_TARGET_REJECTED",
        }
        metadata = {
            "mode": "fork",
            "mapping_state": "locked",
            "mapping_locked": True,
            "source_to_target": dict(mapping),
            "source_digests": {source: [dict(file_spec)]},
            "target_checkpoints": {
                target: {
                    "source": source,
                    "source_digest": digest,
                    "status": "importing",
                    "files": {
                        file_spec["file"]: {
                            **file_spec,
                            "status": "in_progress",
                        }
                    },
                }
            },
            "opaque_witness": {"value": "preserve-me"},
            "failed_notification_enqueued_at": timezone.now().isoformat(),
        }
        values = {
            "backup": self.backup,
            "name": "existing-fork-restore",
            "params": params,
            "execution_metadata": metadata,
            "execution_phase": "database_importing",
            "status": CoreDatabaseRestore.Status.FAILED,
            "error": "safe old error",
            "last_error_code": "RESTORE_TARGET_REJECTED",
            "next_retry_at": timezone.now(),
            "lease_owner": "stale-worker",
            "lease_token": uuid.uuid4(),
            "lease_expires_at": timezone.now() - timedelta(seconds=1),
            "heartbeat_at": timezone.now() - timedelta(seconds=2),
            "celery_task_id": "database-restore-root-1",
        }
        values.update(overrides)
        return CoreDatabaseRestore.objects.create(**values)

    def _post(self, restore_id, *, backup=None, user=None):
        backup = backup or self.backup
        request = APIRequestFactory().post(
            f"/api/v1/backups/database/{backup.id}/resume_restore/",
            {"restore_id": restore_id},
            format="json",
        )
        force_authenticate(request, user=user or self.user)
        view = CoreDatabaseBackupView.as_view({"post": "resume_restore"})
        return view(request, pk=backup.id)

    def test_safe_failed_fork_resumes_same_row_and_publishes_deterministic_task(self):
        restore = self._safe_restore()
        original_params = dict(restore.params)
        original_metadata = json.loads(json.dumps(restore.execution_metadata))
        original_mapping = dict(original_params["target_mapping"])

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            response = self._post(restore.id)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["manual_resume_enqueued"], True)
        self.assertEqual(response.data["resume_sequence"], 1)
        dispatch.assert_called_once_with(
            task_id=f"database-restore-resume-{restore.id}-1",
            kwargs={
                "node_id": self.node.id,
                "backup_id": self.backup.id,
                "restore_id": restore.id,
            },
        )

        restore.refresh_from_db()
        self.assertEqual(restore.id, response.data["id"])
        self.assertEqual(restore.backup_id, self.backup.id)
        self.assertEqual(restore.params["mode"], original_params["mode"])
        self.assertEqual(restore.params["target_mapping"], original_mapping)
        self.assertEqual(
            restore.execution_metadata["source_to_target"],
            original_metadata["source_to_target"],
        )
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"],
            original_metadata["target_checkpoints"],
        )
        self.assertEqual(
            restore.execution_metadata["opaque_witness"],
            original_metadata["opaque_witness"],
        )
        self.assertNotIn(
            "failed_notification_enqueued_at", restore.execution_metadata
        )
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_phase, "database_reconciling")
        self.assertIsNone(restore.error)
        self.assertEqual(restore.last_error_code, "")
        self.assertIsNone(restore.next_retry_at)
        self.assertEqual(restore.lease_owner, "")
        self.assertIsNone(restore.lease_token)
        self.assertIsNone(restore.lease_expires_at)
        self.assertIsNone(restore.heartbeat_at)
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(
            restore.execution_metadata["manual_resume_history"][0]["mode"],
            "logical_fork_reconciliation",
        )
        self.assertFalse(response.data["can_resume_verification"])

    def test_serializer_boolean_is_server_computed_and_safe_only(self):
        safe = self._safe_restore()
        row16_shape = self._safe_restore(execution_phase="failed")
        row16_metadata = dict(row16_shape.execution_metadata)
        # The engine persists the exact mapping/checkpoint witness but the
        # materialized wrapper may leave the older mapping_state hint absent.
        row16_metadata.pop("mapping_state", None)
        row16_shape.execution_metadata = row16_metadata
        row16_shape.save(update_fields=["execution_metadata", "modified"])
        unsafe = self._safe_restore(
            params={
                "mode": "in_place",
                "target_mapping": {"appdb": "appdb"},
                "mapping_locked": True,
                "source_backup_uuid": str(self.backup.uuid),
            },
            execution_metadata={
                "mode": "in_place",
                "mapping_state": "locked",
                "source_to_target": {"appdb": "appdb"},
                "target_checkpoints": {},
            },
        )

        self.assertEqual(
            database_restore_verification_resume_mode(safe),
            "logical_fork_reconciliation",
        )
        self.assertTrue(
            CoreDatabaseRestoreSerializer(safe).data["can_resume_verification"]
        )
        self.assertEqual(
            database_restore_verification_resume_mode(row16_shape),
            "logical_fork_reconciliation",
        )
        self.assertTrue(
            CoreDatabaseRestoreSerializer(row16_shape).data[
                "can_resume_verification"
            ]
        )
        self.assertFalse(
            CoreDatabaseRestoreSerializer(unsafe).data["can_resume_verification"]
        )

    def test_row16_failed_phase_resumes_only_with_exact_fork_checkpoint_proof(self):
        restore = self._safe_restore(execution_phase="failed")
        metadata = dict(restore.execution_metadata)
        metadata.pop("mapping_state", None)
        restore.execution_metadata = metadata
        restore.save(update_fields=["execution_metadata", "modified"])

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            response = self._post(restore.id)

        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.data["manual_resume_enqueued"])
        self.assertEqual(response.data["id"], restore.id)
        dispatch.assert_called_once_with(
            task_id=f"database-restore-resume-{restore.id}-1",
            kwargs={
                "node_id": self.node.id,
                "backup_id": self.backup.id,
                "restore_id": restore.id,
            },
        )

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_phase, "database_reconciling")
        self.assertEqual(
            restore.params["target_mapping"], {"appdb": "bs_restore_existing"}
        )
        self.assertEqual(
            restore.execution_metadata["source_to_target"],
            {"appdb": "bs_restore_existing"},
        )
        self.assertEqual(
            restore.execution_metadata["target_checkpoints"][
                "bs_restore_existing"
            ]["status"],
            "importing",
        )

        malformed = self._safe_restore(execution_phase="failed")
        malformed_metadata = dict(malformed.execution_metadata)
        malformed_metadata["target_checkpoints"] = {}
        malformed.execution_metadata = malformed_metadata
        malformed.save(update_fields=["execution_metadata", "modified"])
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as rejected_dispatch:
            rejected = self._post(malformed.id)
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.data["code"], "restore_resume_not_safe")
        rejected_dispatch.assert_not_called()

    def test_in_place_ambiguous_and_missing_mapping_are_rejected(self):
        in_place = self._safe_restore(
            params={
                "mode": "in_place",
                "target_mapping": {"appdb": "appdb"},
                "mapping_locked": True,
                "source_backup_uuid": str(self.backup.uuid),
            },
            execution_metadata={
                "mode": "in_place",
                "mapping_state": "locked",
                "source_to_target": {"appdb": "appdb"},
                "target_checkpoints": {},
            },
        )
        ambiguous = self._safe_restore()
        ambiguous_metadata = dict(ambiguous.execution_metadata)
        ambiguous_metadata["source_to_target"] = {"appdb": "foreign_target"}
        ambiguous.execution_metadata = ambiguous_metadata
        ambiguous.save(update_fields=["execution_metadata", "modified"])
        missing = self._safe_restore()
        missing_params = dict(missing.params)
        missing_params.pop("target_mapping")
        missing.params = missing_params
        missing.save(update_fields=["params", "modified"])

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            for restore in (in_place, ambiguous, missing):
                response = self._post(restore.id)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.data["code"], "restore_resume_not_safe")
        dispatch.assert_not_called()
        for restore in (in_place, ambiguous, missing):
            restore.refresh_from_db()
            self.assertEqual(restore.status, CoreDatabaseRestore.Status.FAILED)

    def test_complete_and_live_rows_are_not_resumed(self):
        complete = self._safe_restore(status=CoreDatabaseRestore.Status.COMPLETE)
        live = self._safe_restore(status=CoreDatabaseRestore.Status.IN_PROGRESS)

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            complete_response = self._post(complete.id)
            live_response = self._post(live.id)

        self.assertEqual(complete_response.status_code, 409)
        self.assertEqual(complete_response.data["code"], "restore_already_complete")
        self.assertEqual(live_response.status_code, 200)
        self.assertEqual(live_response.data["code"], "restore_resume_already_active")
        self.assertTrue(live_response.data["idempotent_replay"])
        dispatch.assert_not_called()

    def test_repeated_click_is_idempotent_and_publishes_once(self):
        restore = self._safe_restore()
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            first = self._post(restore.id)
            replay = self._post(restore.id)

        self.assertEqual(first.status_code, 202)
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.data["idempotent_replay"])
        self.assertEqual(replay.data["code"], "restore_resume_already_active")
        dispatch.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(len(restore.execution_metadata["manual_resume_history"]), 1)

    def test_two_concurrent_clicks_have_one_transition_and_one_publish(self):
        restore = self._safe_restore()
        barrier = Barrier(2)

        def submit(_value):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return self._post(restore.id)
            finally:
                close_old_connections()

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(submit, (1, 2)))

        self.assertEqual(
            sorted(response.status_code for response in responses),
            [200, 202],
        )
        dispatch.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_metadata["manual_resume_count"], 1)
        self.assertEqual(len(restore.execution_metadata["manual_resume_history"]), 1)

    def test_broker_error_is_redacted_and_durable_state_is_recoverable(self):
        restore = self._safe_restore()
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async",
            side_effect=RuntimeError("broker password must not escape"),
        ) as dispatch:
            response = self._post(restore.id)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["code"], "restore_resume_saved_for_recovery")
        self.assertNotIn("broker password", str(response.data))
        dispatch.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreDatabaseRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.execution_phase, "database_reconciling")

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as replay_dispatch:
            replay = self._post(restore.id)
        self.assertEqual(replay.status_code, 200)
        replay_dispatch.assert_not_called()

    def test_resume_limit_is_bounded(self):
        restore = self._safe_restore()
        metadata = dict(restore.execution_metadata)
        metadata["manual_resume_count"] = 1000
        restore.execution_metadata = metadata
        restore.save(update_fields=["execution_metadata", "modified"])
        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            response = self._post(restore.id)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "restore_manual_resume_limit_reached")
        dispatch.assert_not_called()

    def test_cross_account_restore_is_not_visible(self):
        other_account, other_member, other_user = factories.make_account()
        other_node = make_database_node(
            other_account,
            other_member,
            db_type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version="postgres_16",
        )
        other_backup = CoreDatabaseBackup.objects.create(
            database=other_node.database,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            all_tables=True,
        )
        restore = self._safe_restore(backup=other_backup)

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            response = self._post(restore.id, user=self.user)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data["code"], "restore_not_found")
        dispatch.assert_not_called()


class DatabaseRestoreResumeTemplateTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.template_path = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "detail.html"
        )
        cls.source = cls.template_path.read_text(encoding="utf-8")

    def test_template_compiles_and_exposes_database_resume_control(self):
        get_template("console/node/detail.html")
        for marker in (
            "databaseRestoreCanResume",
            "resumeDatabaseRestore",
            "item.can_resume_verification === true",
            'x-show="!loading && restoreList.length > 0"',
            "/resume_restore/",
            "No second restore was created.",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_database_resume_posts_only_restore_id_and_never_infers_provider_safety(self):
        resume_block = self.source.split("async resumeDatabaseRestore(item)", 1)[1].split(
            "},\n                clearRestorePoll()", 1
        )[0]
        predicate_block = self.source.split("databaseRestoreCanResume(item)", 1)[1].split(
            "},", 1
        )[0]
        self.assertIn("item.can_resume_verification === true", predicate_block)
        self.assertIn("body: JSON.stringify({restore_id: restoreId})", resume_block)
        self.assertIn("response.status !== 200 && response.status !== 202", resume_block)
        self.assertNotIn("resource_id", resume_block)
        self.assertNotIn("provider_job_id", resume_block)
        self.assertNotIn("status_display", predicate_block)
