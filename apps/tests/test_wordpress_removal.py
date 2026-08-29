"""Regression coverage for the retired WordPress integration.

The migration intentionally leaves historical tables in PostgreSQL, but no
runtime model, route, task, or tenant-visible row may remain usable.
"""

from importlib import import_module
from types import SimpleNamespace
from unittest import mock

from django.apps import apps as django_apps
from django.conf import settings
from django.db import connection, transaction
from django.db.migrations import SeparateDatabaseAndState
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from rest_framework import status
from rest_framework.test import APIClient

from apps._tasks import backup_dispatch
from apps.api.v1.utils.api_helpers import visible_connections, visible_nodes
from apps.console.backup.models import CoreBackupRequest
from apps.console.connection.models import CoreConnection, CoreIntegration
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.setting.models import CoreSiteSettings
from apps.console.storage.models import CoreStorage
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.celery_task_manifest import TASK_POLICIES
from backupsheep.database_lane_policy import LANE_TABLE_POLICY, RETIRED_TABLES
from backupsheep.source_recovery_policy import (
    RETIRED_SOURCE_FAMILIES,
    source_backup_creation_available,
)
from utils.middleware import OnboardingMiddleware


LEGACY_TABLES = {
    "core_auth_wordpress",
    "core_wordpress",
    "core_wordpress_backup",
    "core_wordpress_backup_mtm_storage_points",
}
LEGACY_STORAGE_COLUMNS = {
    "stats_wordpress_count",
    "stats_wordpress_backup_count",
    "stats_wordpress_size",
    "stat_wordpress_size",
}


class WordPressRemovalTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_runtime_models_are_absent_but_legacy_schema_is_preserved(self):
        retired_models = {
            "coreauthwordpress",
            "corewordpress",
            "corewordpressbackup",
            "corewordpressbackupstoragepoints",
        }
        self.assertTrue(retired_models.isdisjoint(django_apps.all_models["apps"]))

        tables = set(connection.introspection.table_names())
        self.assertTrue(LEGACY_TABLES.issubset(tables))
        with connection.cursor() as cursor:
            columns = {
                column.name
                for column in connection.introspection.get_table_description(
                    cursor, "core_storage"
                )
            }
        self.assertTrue(LEGACY_STORAGE_COLUMNS.issubset(columns))

    def test_retired_schema_keeps_only_its_internal_foreign_keys(self):
        migration = import_module(
            "apps._migrations.0048_detach_retired_wordpress_foreign_keys"
        )

        self.assertEqual(
            set(migration.foreign_key_inventory(connection)),
            set(migration.INTERNAL_FOREIGN_KEYS),
        )

    def test_deleting_active_records_preserves_retired_rows_and_identifiers(self):
        integration = CoreIntegration.objects.create(
            code="wordpress",
            name="Retired source",
            type=CoreIntegration.Type.SAAS,
            enabled=False,
        )
        retired_connection = CoreConnection.objects.create(
            account=self.account,
            integration=integration,
            location=factories.make_location("detached-wordpress"),
            name="Historical source",
            status=CoreConnection.Status.PAUSED,
            added_by=self.member,
        )
        retired_node = CoreNode.objects.create(
            connection=retired_connection,
            type=CoreNode.Type.SAAS,
            name="Historical source",
            status=CoreNode.Status.PAUSED,
            added_by=self.member,
        )
        retired_schedule = factories.make_schedule(retired_node, self.member)
        retired_storage = factories.make_storage(
            self.account,
            self.member,
            code="aws_s3",
            bucket="retired-wordpress",
        )

        now = timezone.now()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO core_auth_wordpress
                    (created, modified, url, key, connection_id)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    now,
                    now,
                    "https://retired.example.invalid",
                    "bs-wordpress-fernet-v1:archived",
                    retired_connection.pk,
                ),
            )
            auth_id = cursor.fetchone()[0]
            cursor.execute(
                """
                INSERT INTO core_wordpress
                    (created, modified, include, name, node_id)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (now, now, 1, "Historical source", retired_node.pk),
            )
            wordpress_id = cursor.fetchone()[0]
            cursor.execute(
                """
                INSERT INTO core_wordpress_backup
                    (created, modified, status, old_delete_in_progress,
                     old_max_delete_retry, schedule_id, wordpress_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    now,
                    now,
                    3,
                    False,
                    False,
                    retired_schedule.pk,
                    wordpress_id,
                ),
            )
            backup_id = cursor.fetchone()[0]
            cursor.execute(
                """
                INSERT INTO core_wordpress_backup_mtm_storage_points
                    (created, modified, status, last_error_code,
                     last_error_message, upload_attempt_count,
                     upload_lease_owner, backup_id, storage_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    now,
                    now,
                    3,
                    "",
                    "",
                    0,
                    "",
                    backup_id,
                    retired_storage.pk,
                ),
            )
            storage_point_id = cursor.fetchone()[0]

        active_ids = {
            "connection": retired_connection.pk,
            "node": retired_node.pk,
            "schedule": retired_schedule.pk,
            "storage": retired_storage.pk,
        }
        retired_connection.delete()
        retired_storage.delete()

        self.assertFalse(
            CoreConnection.objects.filter(pk=active_ids["connection"]).exists()
        )
        self.assertFalse(CoreNode.objects.filter(pk=active_ids["node"]).exists())
        self.assertFalse(
            CoreSchedule.objects.filter(pk=active_ids["schedule"]).exists()
        )
        self.assertFalse(
            CoreStorage.objects.filter(pk=active_ids["storage"]).exists()
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT connection_id FROM core_auth_wordpress WHERE id = %s",
                (auth_id,),
            )
            self.assertEqual(cursor.fetchone(), (active_ids["connection"],))
            cursor.execute(
                "SELECT node_id FROM core_wordpress WHERE id = %s",
                (wordpress_id,),
            )
            self.assertEqual(cursor.fetchone(), (active_ids["node"],))
            cursor.execute(
                """
                SELECT schedule_id, wordpress_id
                  FROM core_wordpress_backup
                 WHERE id = %s
                """,
                (backup_id,),
            )
            self.assertEqual(
                cursor.fetchone(),
                (active_ids["schedule"], wordpress_id),
            )
            cursor.execute(
                """
                SELECT storage_id, backup_id
                  FROM core_wordpress_backup_mtm_storage_points
                 WHERE id = %s
                """,
                (storage_point_id,),
            )
            self.assertEqual(
                cursor.fetchone(),
                (active_ids["storage"], backup_id),
            )

    def test_reverse_refuses_orphaned_retired_identifiers(self):
        migration = import_module(
            "apps._migrations.0048_detach_retired_wordpress_foreign_keys"
        )
        now = timezone.now()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO core_auth_wordpress
                    (created, modified, url, key, connection_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    now,
                    now,
                    "https://orphan.example.invalid",
                    "bs-wordpress-fernet-v1:archived",
                    9223372036854775807,
                ),
            )

        schema_editor = SimpleNamespace(
            connection=connection,
            quote_name=connection.ops.quote_name,
        )
        with self.assertRaisesRegex(RuntimeError, "identifiers are orphaned"):
            migration.restore_retired_wordpress_foreign_keys(
                django_apps,
                schema_editor,
            )
        self.assertEqual(
            set(migration.foreign_key_inventory(connection)),
            set(migration.INTERNAL_FOREIGN_KEYS),
        )

    def test_fresh_source_catalog_has_no_retired_integration(self):
        self.assertFalse(CoreIntegration.objects.filter(code="wordpress").exists())

    def test_retirement_migration_contains_no_destructive_schema_operations(self):
        migration = import_module(
            "apps._migrations.0047_retire_wordpress_integration"
        ).Migration
        state_only = [
            operation
            for operation in migration.operations
            if isinstance(operation, SeparateDatabaseAndState)
        ]
        self.assertEqual(len(state_only), 1)
        self.assertEqual(state_only[0].database_operations, [])

    def test_old_routes_are_not_resolvable_as_provider_actions(self):
        for path in (
            "/api/v1/connections/wordpress/endpoints/",
            "/api/v1/saas/wordpress/generate_key/",
            "/api/v1/backups/wordpress/highcharts/",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_disabled_historical_rows_are_invisible_to_tenant_apis(self):
        integration = CoreIntegration.objects.create(
            code="wordpress",
            name="Retired source",
            type=CoreIntegration.Type.SAAS,
            enabled=False,
        )
        retired_connection = CoreConnection.objects.create(
            account=self.account,
            integration=integration,
            location=factories.make_location("retired-wordpress"),
            name="Historical source",
            status=CoreConnection.Status.PAUSED,
            added_by=self.member,
        )
        retired_node = CoreNode.objects.create(
            connection=retired_connection,
            type=CoreNode.Type.SAAS,
            name="Historical source",
            status=CoreNode.Status.PAUSED,
            added_by=self.member,
        )

        self.assertNotIn(retired_connection, visible_connections(self.member))
        self.assertNotIn(retired_node, visible_nodes(self.member))
        self.assertEqual(
            self.client.get(
                f"/api/v1/connections/{retired_connection.pk}/"
            ).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.get(f"/api/v1/nodes/{retired_node.pk}/").status_code,
            status.HTTP_404_NOT_FOUND,
        )

    @override_settings(
        BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
        BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="legacy-only",
        BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
        WORDPRESS_INTEGRATION_ENABLED=True,
    )
    def test_retired_source_cannot_be_reenabled_or_dispatched(self):
        integration = CoreIntegration.objects.create(
            code="wordpress",
            name="Retired source",
            type=CoreIntegration.Type.SAAS,
            enabled=True,
        )
        retired_connection = CoreConnection.objects.create(
            account=self.account,
            integration=integration,
            location=factories.make_location("reenabled-wordpress"),
            name="Historical source",
            status=CoreConnection.Status.ACTIVE,
            added_by=self.member,
        )
        retired_node = CoreNode.objects.create(
            connection=retired_connection,
            type=CoreNode.Type.SAAS,
            name="Historical source",
            status=CoreNode.Status.ACTIVE,
            added_by=self.member,
        )
        request = CoreBackupRequest.objects.create(
            request_key=f"retired-wordpress-{retired_node.pk}",
            task_id=f"retired-wordpress-{retired_node.pk}",
            task_name="backup_wordpress",
            node=retired_node,
            payload={"node_id": retired_node.pk, "storage_ids": []},
            next_dispatch_at=timezone.now(),
        )

        self.assertEqual(RETIRED_SOURCE_FAMILIES, frozenset({"wordpress"}))
        self.assertFalse(source_backup_creation_available("wordpress"))
        self.assertNotIn(retired_connection, visible_connections(self.member))
        self.assertNotIn(retired_node, visible_nodes(self.member))
        self.assertEqual(
            self.client.get(
                f"/api/v1/connections/{retired_connection.pk}/"
            ).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.get(f"/api/v1/nodes/{retired_node.pk}/").status_code,
            status.HTTP_404_NOT_FOUND,
        )

        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            self.assertFalse(backup_dispatch.publish_backup_request(request.pk))
        request.refresh_from_db()
        self.assertEqual(request.status, CoreBackupRequest.Status.CANCELLED)
        self.assertEqual(
            request.last_error_code,
            "SOURCE_RECOVERY_UNAVAILABLE",
        )
        send_task.assert_not_called()

    def test_retirement_migration_pauses_existing_dispatch_rows(self):
        integration = CoreIntegration.objects.create(
            code="wordpress",
            name="Historical source",
            type=CoreIntegration.Type.SAAS,
            enabled=True,
        )
        retired_connection = CoreConnection.objects.create(
            account=self.account,
            integration=integration,
            location=factories.make_location("historical-wordpress"),
            name="Historical source",
            added_by=self.member,
        )
        retired_node = CoreNode.objects.create(
            connection=retired_connection,
            type=CoreNode.Type.SAAS,
            name="Historical source",
            added_by=self.member,
        )
        interval = IntervalSchedule.objects.create(
            every=1,
            period=IntervalSchedule.MINUTES,
        )
        periodic_task = PeriodicTask.objects.create(
            name="historical-wordpress-backup",
            task="backup_wordpress",
            interval=interval,
            enabled=True,
        )
        retired_schedule = CoreSchedule.objects.create(
            node=retired_node,
            celery_periodic_task=periodic_task,
            name="Historical schedule",
            timezone="UTC",
            added_by=self.member,
        )

        migration = import_module(
            "apps._migrations.0047_retire_wordpress_integration"
        )
        migration.retire_wordpress_runtime_rows(django_apps, None)

        integration.refresh_from_db()
        retired_connection.refresh_from_db()
        retired_node.refresh_from_db()
        retired_schedule.refresh_from_db()
        periodic_task.refresh_from_db()
        self.assertFalse(integration.enabled)
        self.assertEqual(retired_connection.status, CoreConnection.Status.PAUSED)
        self.assertEqual(retired_node.status, CoreNode.Status.PAUSED)
        self.assertEqual(retired_schedule.status, CoreSchedule.Status.PAUSED)
        self.assertFalse(periodic_task.enabled)

    def test_no_task_or_database_lane_can_reach_retired_models(self):
        imports = set(settings.CELERY_IMPORTS)
        self.assertFalse(
            any("wordpress" in module.lower() for module in imports)
        )
        self.assertNotIn("backup_wordpress", TASK_POLICIES)
        self.assertEqual(RETIRED_TABLES, LEGACY_TABLES)
        for lane, policy in LANE_TABLE_POLICY.items():
            with self.subTest(lane=lane):
                self.assertTrue(RETIRED_TABLES.isdisjoint(policy))


class WordPressRetiredSchemaFlushTests(TransactionTestCase):
    """The retained tables must never prevent Django from flushing active state."""

    def test_transactional_test_flush_topology_is_detached(self):
        migration = import_module(
            "apps._migrations.0048_detach_retired_wordpress_foreign_keys"
        )
        self.assertEqual(
            set(migration.foreign_key_inventory(connection)),
            set(migration.INTERNAL_FOREIGN_KEYS),
        )

    def test_reverse_round_trip_restores_then_redetaches_exact_topology(self):
        migration = import_module(
            "apps._migrations.0048_detach_retired_wordpress_foreign_keys"
        )
        schema_editor = SimpleNamespace(
            connection=connection,
            quote_name=connection.ops.quote_name,
        )

        with transaction.atomic():
            migration.restore_retired_wordpress_foreign_keys(
                django_apps,
                schema_editor,
            )
            self.assertEqual(
                set(migration.foreign_key_inventory(connection)),
                set(
                    migration.INTERNAL_FOREIGN_KEYS
                    + migration.EXTERNAL_FOREIGN_KEYS
                ),
            )

            migration.detach_retired_wordpress_foreign_keys(
                django_apps,
                schema_editor,
            )
            self.assertEqual(
                set(migration.foreign_key_inventory(connection)),
                set(migration.INTERNAL_FOREIGN_KEYS),
            )

    def test_forward_refuses_unexpected_foreign_key_without_partial_drop(self):
        migration = import_module(
            "apps._migrations.0048_detach_retired_wordpress_foreign_keys"
        )
        schema_editor = SimpleNamespace(
            connection=connection,
            quote_name=connection.ops.quote_name,
        )
        unexpected_name = "unexpected_retired_wordpress_connection_fk"

        with transaction.atomic():
            migration.restore_retired_wordpress_foreign_keys(
                django_apps,
                schema_editor,
            )
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"ALTER TABLE core_auth_wordpress "
                        f"ADD CONSTRAINT "
                        f"{connection.ops.quote_name(unexpected_name)} "
                        "FOREIGN KEY (connection_id) "
                        "REFERENCES core_connection (id) "
                        "DEFERRABLE INITIALLY DEFERRED"
                    )
                with self.assertRaisesRegex(RuntimeError, "topology drifted"):
                    migration.detach_retired_wordpress_foreign_keys(
                        django_apps,
                        schema_editor,
                    )
                inventory = set(migration.foreign_key_inventory(connection))
                self.assertTrue(
                    set(migration.EXTERNAL_FOREIGN_KEYS).issubset(inventory)
                )
            finally:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"ALTER TABLE core_auth_wordpress DROP CONSTRAINT "
                        f"{connection.ops.quote_name(unexpected_name)}"
                    )
                migration.detach_retired_wordpress_foreign_keys(
                    django_apps,
                    schema_editor,
                )
