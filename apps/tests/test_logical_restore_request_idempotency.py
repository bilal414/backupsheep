"""PostgreSQL races for logical restore HTTP idempotency."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from django.db import close_old_connections
from django.test import TransactionTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.backup.database.views import CoreDatabaseBackupView
from apps.api.v1.backup.website.views import CoreWebsiteBackupView
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWebsiteRestore,
)
from apps.console.connection.models import (
    CoreAuthDatabase,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.console.storage.models import CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.test_backup_engine import make_database_node


class LogicalRestoreConcurrentRequestTests(TransactionTestCase):
    reset_sequences = True

    @staticmethod
    def _ensure_reference_data():
        CoreIntegration.objects.get_or_create(
            code="website",
            defaults={
                "name": "Website",
                "type": CoreIntegration.Type.WEBSITE,
            },
        )
        CoreIntegration.objects.get_or_create(
            code="database",
            defaults={
                "name": "Database",
                "type": CoreIntegration.Type.DATABASE,
            },
        )
        CoreStorageType.objects.get_or_create(
            code="local",
            defaults={
                "name": "Local",
                "is_enabled": True,
            },
        )

    def setUp(self):
        super().setUp()
        self._ensure_reference_data()
        CoreConnectionLocation.objects.get_or_create(
            code="test-loc",
            defaults={"id": 1_000_000, "name": "Test"},
        )
        self.account, self.member, self.user = factories.make_account()
        self.storage = factories.make_storage(
            self.account, self.member, code="local"
        )
        CoreStorageLocal.objects.create(storage=self.storage, path="")

    def _fixture_teardown(self):
        super()._fixture_teardown()
        # TransactionTestCase.flush removes migration-seeded reference rows.
        self._ensure_reference_data()

    def _website_fixture(self):
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"website-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=self.storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="logical-idempotency/website.zip",
        )
        return backup, point

    def _database_fixture(self):
        node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL,
            version="mysql_8_0",
        )
        backup = CoreDatabaseBackup.objects.create(
            database=node.database,
            uuid=f"database-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            all_tables=True,
        )
        point = CoreDatabaseBackupStoragePoints.objects.create(
            backup=backup,
            storage=self.storage,
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="logical-idempotency/database.zip",
        )
        return backup, point

    def _concurrent_posts(self, *, view_class, family, submissions):
        start = threading.Barrier(2)

        def submit(submission):
            close_old_connections()
            try:
                backup_id, payload = submission
                user = type(self.user).objects.get(pk=self.user.pk)
                start.wait(timeout=10)
                view = view_class.as_view({"post": "restore"})
                request = APIRequestFactory().post(
                    f"/api/v1/backups/{family}/{backup_id}/restore/",
                    dict(payload),
                    format="json",
                )
                force_authenticate(request, user=user)
                return view(request, pk=backup_id)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            return list(executor.map(submit, submissions))

    def test_concurrent_identical_website_posts_create_one_row_and_publish(self):
        backup, point = self._website_fixture()
        request_id = str(uuid.uuid4())
        payload = {
            "confirm": True,
            "delete": False,
            "storage_point_id": point.id,
            "request_id": request_id,
        }

        with mock.patch(
            "apps._tasks.integration.restore.restore_website_backup.apply_async"
        ) as dispatch:
            responses = self._concurrent_posts(
                view_class=CoreWebsiteBackupView,
                family="website",
                submissions=((backup.id, payload), (backup.id, payload)),
            )

        self.assertEqual([response.status_code for response in responses], [201, 201])
        self.assertEqual(responses[0].data["id"], responses[1].data["id"])
        self.assertEqual(
            responses[0].data["execution_status"]["recovery_id"], request_id
        )
        self.assertEqual(CoreWebsiteRestore.objects.filter(backup=backup).count(), 1)
        dispatch.assert_called_once()

    def test_concurrent_different_website_requests_reject_the_loser(self):
        backup, point = self._website_fixture()
        payloads = (
            {
                "confirm": True,
                "delete": False,
                "storage_point_id": point.id,
                "request_id": str(uuid.uuid4()),
            },
            {
                "confirm": True,
                "delete": False,
                "storage_point_id": point.id,
                "request_id": str(uuid.uuid4()),
            },
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_website_backup.apply_async"
        ) as dispatch:
            responses = self._concurrent_posts(
                view_class=CoreWebsiteBackupView,
                family="website",
                submissions=(
                    (backup.id, payloads[0]),
                    (backup.id, payloads[1]),
                ),
            )

        self.assertEqual(
            sorted(response.status_code for response in responses), [201, 409]
        )
        conflict = next(
            response for response in responses if response.status_code == 409
        )
        self.assertEqual(conflict.data["code"], "active_restore_exists")
        self.assertEqual(CoreWebsiteRestore.objects.filter(backup=backup).count(), 1)
        dispatch.assert_called_once()

    def test_different_recovery_points_for_one_website_are_serialized(self):
        first_backup, first_point = self._website_fixture()
        second_backup = CoreWebsiteBackup.objects.create(
            website=first_backup.website,
            uuid=f"website-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        second_point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=second_backup,
            storage=self.storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="logical-idempotency/website-second.zip",
        )
        submissions = (
            (
                first_backup.id,
                {
                    "confirm": True,
                    "storage_point_id": first_point.id,
                    "request_id": str(uuid.uuid4()),
                },
            ),
            (
                second_backup.id,
                {
                    "confirm": True,
                    "storage_point_id": second_point.id,
                    "request_id": str(uuid.uuid4()),
                },
            ),
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_website_backup.apply_async"
        ) as dispatch:
            responses = self._concurrent_posts(
                view_class=CoreWebsiteBackupView,
                family="website",
                submissions=submissions,
            )

        self.assertEqual(
            sorted(response.status_code for response in responses), [201, 409]
        )
        conflict = next(
            response for response in responses if response.status_code == 409
        )
        self.assertEqual(conflict.data["code"], "active_restore_exists")
        self.assertEqual(
            CoreWebsiteRestore.objects.filter(
                backup__website=first_backup.website
            ).count(),
            1,
        )
        dispatch.assert_called_once()

    def test_concurrent_identical_database_posts_create_one_row_and_publish(self):
        backup, point = self._database_fixture()
        request_id = str(uuid.uuid4())
        payload = {
            "confirm": True,
            "storage_point_id": point.id,
            "request_id": request_id,
        }

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            responses = self._concurrent_posts(
                view_class=CoreDatabaseBackupView,
                family="database",
                submissions=((backup.id, payload), (backup.id, payload)),
            )

        self.assertEqual([response.status_code for response in responses], [201, 201])
        self.assertEqual(responses[0].data["id"], responses[1].data["id"])
        self.assertEqual(responses[0].data["params"], responses[1].data["params"])
        self.assertEqual(
            responses[0].data["execution_status"]["recovery_id"], request_id
        )
        self.assertEqual(CoreDatabaseRestore.objects.filter(backup=backup).count(), 1)
        dispatch.assert_called_once()

    def test_different_recovery_points_for_one_database_are_serialized(self):
        first_backup, first_point = self._database_fixture()
        second_backup = CoreDatabaseBackup.objects.create(
            database=first_backup.database,
            uuid=f"database-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            all_tables=True,
        )
        second_point = CoreDatabaseBackupStoragePoints.objects.create(
            backup=second_backup,
            storage=self.storage,
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id="logical-idempotency/database-second.zip",
        )
        submissions = (
            (
                first_backup.id,
                {
                    "confirm": True,
                    "storage_point_id": first_point.id,
                    "request_id": str(uuid.uuid4()),
                },
            ),
            (
                second_backup.id,
                {
                    "confirm": True,
                    "storage_point_id": second_point.id,
                    "request_id": str(uuid.uuid4()),
                },
            ),
        )

        with mock.patch(
            "apps._tasks.integration.restore.restore_database_backup.apply_async"
        ) as dispatch:
            responses = self._concurrent_posts(
                view_class=CoreDatabaseBackupView,
                family="database",
                submissions=submissions,
            )

        self.assertEqual(
            sorted(response.status_code for response in responses), [201, 409]
        )
        conflict = next(
            response for response in responses if response.status_code == 409
        )
        self.assertEqual(conflict.data["code"], "active_restore_exists")
        self.assertEqual(
            CoreDatabaseRestore.objects.filter(
                backup__database=first_backup.database
            ).count(),
            1,
        )
        dispatch.assert_called_once()
