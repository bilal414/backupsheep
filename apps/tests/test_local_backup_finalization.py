"""Regression coverage for provider-independent local backup finalization."""

import uuid
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from apps.api.v1.backup.website.serializers import CoreWebsiteBackupSerializer
from apps._tasks.integration.storage.tasks import finalize_backup
from apps.console.backup.models import (
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWordPressBackup,
    CoreWordPressBackupStoragePoints,
)
from apps.console.account.models import CoreAccount
from apps.console.node.models import (
    CoreBasecamp,
    CoreDatabase,
    CoreNode,
    CoreWebsite,
    CoreWordPress,
)
from apps.console.storage.models import CoreStorageLocal
from apps.console.utils.models import (
    BackupExecutionLeaseLostError,
    UtilBackup,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


class LocalBackupFinalizationTests(BaseTestCase):
    def _storage(self):
        storage = factories.make_storage(
            self.account,
            self.member,
            code="local",
            bucket=f"finalizer-{uuid.uuid4().hex[:12]}",
        )
        CoreStorageLocal.objects.create(storage=storage, path=None)
        return storage

    def _backup(self, kind, point_statuses):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="website" if kind == "website" else kind,
            name=f"{kind}-{uuid.uuid4().hex[:8]}",
        )
        node_type = {
            "website": CoreNode.Type.WEBSITE,
            "database": CoreNode.Type.DATABASE,
            "wordpress": CoreNode.Type.SAAS,
            "basecamp": CoreNode.Type.SAAS,
        }[kind]
        node = CoreNode.objects.create(
            connection=connection,
            type=node_type,
            name=f"{kind}-node",
            added_by=self.member,
        )
        suffix = uuid.uuid4().hex
        if kind == "website":
            source = CoreWebsite.objects.create(node=node, name="local-site")
            backup_model = CoreWebsiteBackup
            point_model = CoreWebsiteBackupStoragePoints
            backup = backup_model.objects.create(
                website=source,
                uuid=f"local-website-{suffix}",
                status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
                type=UtilBackup.Type.ON_DEMAND,
            )
        elif kind == "database":
            source = CoreDatabase.objects.create(node=node, name="local-database")
            backup_model = CoreDatabaseBackup
            point_model = CoreDatabaseBackupStoragePoints
            backup = backup_model.objects.create(
                database=source,
                uuid=f"local-database-{suffix}",
                status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
                type=UtilBackup.Type.ON_DEMAND,
            )
        elif kind == "wordpress":
            source = CoreWordPress.objects.create(node=node, name="local-wordpress")
            backup_model = CoreWordPressBackup
            point_model = CoreWordPressBackupStoragePoints
            backup = backup_model.objects.create(
                wordpress=source,
                uuid=f"local-wordpress-{suffix}",
                status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
                type=UtilBackup.Type.ON_DEMAND,
            )
        else:
            source = CoreBasecamp.objects.create(node=node, name="local-basecamp")
            backup_model = CoreBasecampBackup
            point_model = CoreBasecampBackupStoragePoints
            backup = backup_model.objects.create(
                basecamp=source,
                uuid=f"local-basecamp-{suffix}",
                status=UtilBackup.Status.UPLOAD_IN_PROGRESS,
                type=UtilBackup.Type.ON_DEMAND,
            )

        backup.metadata = {
            "_backup_destination_setup": {
                "requested_count": len(point_statuses),
            }
        }
        backup.save(update_fields=["metadata", "modified"])
        for point_status in point_statuses:
            point_model.objects.create(
                backup=backup,
                storage=self._storage(),
                status=point_status,
            )
        return node, backup, point_model

    @staticmethod
    def _finalize(node, backup):
        with mock.patch(
            "apps._tasks.helper.tasks.delete_from_disk.apply_async"
        ) as cleanup:
            finalize_backup.apply(args=[node.id, backup.id])
        return cleanup

    def test_complete_finalization_closes_the_execution_for_website_database_and_saas(self):
        cases = (
            ("website", CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE),
            ("database", CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE),
            ("wordpress", CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE),
            ("basecamp", CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE),
        )

        with mock.patch.object(CoreNode, "notify_backup_success") as notify:
            for kind, point_status in cases:
                with self.subTest(kind=kind):
                    node, backup, _point_model = self._backup(kind, [point_status])
                    original = backup.claim_execution(
                        lease_owner=f"stale-{kind}",
                        phase="source_dispatch",
                        lease_seconds=300,
                    )
                    self.assertIsNotNone(original)

                    self._finalize(node, backup)

                    backup.refresh_from_db()
                    state = backup.get_execution_state()
                    self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
                    self.assertEqual(state.phase, "complete")
                    self.assertIsNotNone(state.finished_at)
                    self.assertIsNone(state.lease_token)
                    self.assertEqual(state.lease_owner, "")
                    self.assertIsNone(state.lease_expires_at)
                    self.assertIsNone(state.next_retry_at)
                    if kind == "website":
                        execution_status = CoreWebsiteBackupSerializer(
                            backup.__class__.objects.get(pk=backup.pk)
                        ).data["execution_status"]
                        self.assertEqual(execution_status["status"], "complete")
                        self.assertEqual(execution_status["phase"], "complete")
                    self.assertIsNone(
                        backup.heartbeat_execution(
                            lease_owner=f"stale-{kind}",
                            lease_token=original.lease_token,
                            lease_seconds=300,
                        )
                    )
                    self.assertIsNone(
                        backup.release_execution(
                            lease_owner=f"stale-{kind}",
                            lease_token=original.lease_token,
                            phase="source_dispatch",
                        )
                    )
                    stale = backup.__class__.objects.get(pk=backup.pk)
                    stale.bind_execution_fence(
                        f"stale-{kind}", original.lease_token
                    )
                    stale.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
                    with self.assertRaises(BackupExecutionLeaseLostError):
                        stale.save(update_fields=["status", "modified"])

        self.assertEqual(notify.call_count, len(cases))

    def test_partial_finalization_is_terminal_and_duplicate_delivery_is_idempotent(self):
        node, backup, point_model = self._backup(
            "database",
            [
                CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
                CoreDatabaseBackupStoragePoints.Status.UPLOAD_FAILED,
            ],
        )
        account_log = mock.patch.object(CoreAccount, "create_backup_log")
        with account_log as create_backup_log, mock.patch(
            "apps._tasks.helper.tasks.delete_from_disk.apply_async"
        ):
            finalize_backup.apply(args=[node.id, backup.id])
            backup.refresh_from_db()
            first_state = backup.get_execution_state()
            first_finished_at = first_state.finished_at

            # A stale callback cannot downgrade the already committed partial
            # decision, even if a point row is later observed with another terminal
            # status.
            second_point = point_model.objects.filter(backup=backup).last()
            second_point.status = point_model.Status.UPLOAD_FAILED
            second_point.save(update_fields=["status", "modified"])
            finalize_backup.apply(args=[node.id, backup.id])

        backup.refresh_from_db()
        state = backup.get_execution_state()
        self.assertEqual(backup.status, UtilBackup.Status.PARTIAL)
        self.assertEqual(state.phase, "complete")
        self.assertEqual(state.finished_at, first_finished_at)
        self.assertEqual(create_backup_log.call_count, 1)
        self.assertEqual(
            backup.metadata["storage_upload_summary"]["partial"],
            True,
        )

    def test_upload_failed_finalization_is_terminal_and_not_in_progress(self):
        node, backup, _point_model = self._backup(
            "website",
            [CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED],
        )
        with mock.patch("apps._tasks.helper.tasks.delete_from_disk.apply_async"):
            self._finalize(node, backup)

        backup.refresh_from_db()
        state = backup.get_execution_state()
        self.assertEqual(backup.status, UtilBackup.Status.UPLOAD_FAILED)
        self.assertEqual(state.phase, "failed")
        self.assertIsNotNone(state.finished_at)
        self.assertIsNone(state.next_retry_at)

        stale = backup.__class__.objects.get(pk=backup.pk)
        stale.bind_execution_fence("stale-upload-worker", uuid.uuid4())
        stale.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
        with self.assertRaises(BackupExecutionLeaseLostError):
            stale.save(update_fields=["status", "modified"])


class LocalBackupFinalizationUiContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "detail.html"
        ).read_text(encoding="utf-8")

    def test_complete_and_partial_terminal_rows_do_not_use_cancel_action(self):
        self.assertIn(
            "loaded ? Boolean(view && view.category === 'complete')",
            self.source,
        )
        self.assertIn(
            "loaded ? Boolean(view && view.shouldPoll)",
            self.source,
        )
        self.assertIn("Partially complete", self.source)
