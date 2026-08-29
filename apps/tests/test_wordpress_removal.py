"""Regression coverage for the retired WordPress integration.

The migration intentionally leaves historical tables in PostgreSQL, but no
runtime model, route, task, or tenant-visible row may remain usable.
"""

from importlib import import_module
from unittest import mock

from django.apps import apps as django_apps
from django.conf import settings
from django.db import connection
from django.db.migrations import SeparateDatabaseAndState
from django.test import override_settings
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
