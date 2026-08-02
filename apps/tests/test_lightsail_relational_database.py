from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError

from apps.api.v1.backup.lightsail.serializers import (
    CoreLightsailBackupSerializer,
)
from apps.api.v1.cloud.lightsail.serializers import (
    CoreCloudLightsailWriteSerializer,
)
from apps.api.v1.cloud.lightsail.views import CoreCloudLightsailView
from apps.api.v1.cloud.lightsail_database.serializers import (
    CoreCloudLightsailDatabaseWriteSerializer,
)
from apps.api.v1.cloud.lightsail_database.views import (
    CoreCloudLightsailDatabaseView,
)
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthLightsail, CoreLightsailRegion
from apps.console.node.models import CoreLightsail, CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class LightsailRelationalDatabaseTests(BaseTestCase):
    def _make_lightsail_node(self, *, resource_type=CoreLightsail.ResourceType.DATABASE):
        connection = factories.make_connection(
            self.account, self.member, code="lightsail"
        )
        CoreAuthLightsail.objects.create(
            connection=connection,
            region=CoreLightsailRegion.objects.get(code="us-east-1"),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="source-database",
            added_by=self.member,
        )
        CoreLightsail.objects.create(
            node=node,
            name="source-database",
            unique_id="source-database",
            resource_type=resource_type,
        )
        return node

    @staticmethod
    def _backup(node, *, unique_id="db-snapshot", status=UtilBackup.Status.IN_PROGRESS):
        return node.lightsail.backups.create(
            uuid="db-snapshot",
            status=status,
            type=UtilBackup.Type.ON_DEMAND,
            unique_id=unique_id,
        )

    def _client_patch(self, client):
        return mock.patch.object(
            CoreAuthLightsail, "get_client", return_value=client
        )

    def test_database_discovery_paginates_and_normalizes_eligible_objects(self):
        node = self._make_lightsail_node()
        client = mock.MagicMock()
        client.get_relational_databases.side_effect = [
            {
                "relationalDatabases": [
                    {
                        "name": "first-db",
                        "location": {"regionName": "us-east-1"},
                        "hardware": {"diskSizeInGb": 20},
                    }
                ],
                "nextPageToken": "second-page",
            },
            {
                "relationalDatabases": [
                    {
                        "name": "second-db",
                        "location": {"regionName": "us-east-1"},
                        "hardware": {"diskSizeInGb": 40},
                    }
                ]
            },
        ]

        with self._client_patch(client):
            databases = node.connection.auth_lightsail.get_eligible_objects(
                object_type="database"
            )

        self.assertEqual([item["_bs_unique_id"] for item in databases], ["first-db", "second-db"])
        self.assertEqual(databases[0]["_bs_name"], "first-db")
        self.assertEqual(databases[0]["_bs_region"], "us-east-1")
        self.assertEqual(databases[0]["_bs_size"], 20)
        self.assertEqual(
            client.get_relational_databases.call_args_list,
            [mock.call(), mock.call(pageToken="second-page")],
        )

    def test_create_snapshot_reuses_exact_snapshot_from_later_page(self):
        node = self._make_lightsail_node()
        backup = self._backup(node)
        client = mock.MagicMock()
        client.get_relational_database_snapshots.side_effect = [
            {
                "relationalDatabaseSnapshots": [{"name": "unrelated"}],
                "nextPageToken": "next-page",
            },
            {
                "relationalDatabaseSnapshots": [
                    {"name": "db-snapshot", "sizeInGb": 16, "state": "available"}
                ]
            },
        ]

        with self._client_patch(client):
            node.lightsail.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "db-snapshot")
        self.assertEqual(backup.size_gigabytes, 16)
        self.assertEqual(backup.metadata["name"], "db-snapshot")
        client.create_relational_database_snapshot.assert_not_called()
        self.assertEqual(
            client.get_relational_database_snapshots.call_args_list,
            [mock.call(), mock.call(pageToken="next-page")],
        )

    def test_create_snapshot_creates_database_snapshot_when_absent(self):
        node = self._make_lightsail_node()
        backup = self._backup(node, unique_id="")
        client = mock.MagicMock()
        client.get_relational_database_snapshots.return_value = {
            "relationalDatabaseSnapshots": []
        }
        client.create_relational_database_snapshot.return_value = {
            "operations": [{"status": "Started"}]
        }

        with self._client_patch(client):
            node.lightsail.create_snapshot(backup)

        client.create_relational_database_snapshot.assert_called_once_with(
            relationalDatabaseName="source-database",
            relationalDatabaseSnapshotName="db-snapshot",
        )
        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "db-snapshot")

    def test_poll_status_completes_from_relational_database_snapshot_state(self):
        node = self._make_lightsail_node()
        backup = self._backup(node)
        client = mock.MagicMock()
        client.get_relational_database_snapshots.return_value = {
            "relationalDatabaseSnapshots": [
                {
                    "name": "db-snapshot",
                    "state": "available",
                    "sizeInGb": 32,
                }
            ]
        }

        with self._client_patch(client):
            result = backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.COMPLETE)
        self.assertEqual(backup.size_gigabytes, 32)
        self.assertEqual(backup.metadata["state"], "available")

    def test_restore_falls_back_to_source_database_zone_and_bundle(self):
        node = self._make_lightsail_node()
        backup = self._backup(node, status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-database"
        )
        client = mock.MagicMock()
        client.get_relational_database_snapshots.return_value = {
            "relationalDatabaseSnapshots": [
                {
                    "name": "db-snapshot",
                    "location": {"availabilityZone": "all"},
                }
            ]
        }
        client.get_relational_database.return_value = {
            "relationalDatabase": {
                "location": {"availabilityZone": "us-east-1a"},
                "relationalDatabaseBundleId": "medium_1_0",
            }
        }
        client.create_relational_database_from_snapshot.return_value = {
            "operations": [{"status": "Started"}]
        }

        with self._client_patch(client):
            node.lightsail.restore_snapshot(backup, restore)

        client.create_relational_database_from_snapshot.assert_called_once_with(
            relationalDatabaseName="restored-database",
            relationalDatabaseSnapshotName="db-snapshot",
            availabilityZone="us-east-1a",
            relationalDatabaseBundleId="medium_1_0",
        )
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "restored-database")

    def test_restore_accepts_native_lightsail_option_names(self):
        node = self._make_lightsail_node()
        backup = self._backup(node, status=UtilBackup.Status.COMPLETE)
        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name="restored-database-native-options",
            params={
                "availabilityZone": "us-east-1b",
                "relationalDatabaseBundleId": "micro_1_0",
                "publiclyAccessible": True,
            },
        )
        client = mock.MagicMock()
        client.get_relational_database_snapshots.return_value = {
            "relationalDatabaseSnapshots": [{"name": "db-snapshot"}]
        }
        client.create_relational_database_from_snapshot.return_value = {
            "operations": [{"status": "Started"}]
        }

        with self._client_patch(client):
            node.lightsail.restore_snapshot(backup, restore)

        client.create_relational_database_from_snapshot.assert_called_once_with(
            relationalDatabaseName="restored-database-native-options",
            relationalDatabaseSnapshotName="db-snapshot",
            availabilityZone="us-east-1b",
            relationalDatabaseBundleId="micro_1_0",
            publiclyAccessible=True,
        )

    def test_check_restore_maps_database_states_and_absent_resources_safely(self):
        node = self._make_lightsail_node()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=1,
            name="restored-database",
            resource_id="restored-database",
        )
        client = mock.MagicMock()

        for provider_state, expected in (
            ("available", CoreCloudRestore.Status.COMPLETE),
            ("creating", CoreCloudRestore.Status.IN_PROGRESS),
            ("failed", CoreCloudRestore.Status.FAILED),
            ("restore-error", CoreCloudRestore.Status.FAILED),
        ):
            client.get_relational_database.return_value = {
                "relationalDatabase": {"state": provider_state}
            }
            with self._client_patch(client):
                self.assertEqual(node.lightsail.check_restore(restore), expected)

        not_found = ClientError(
            {"Error": {"Code": "NotFoundException", "Message": "not ready"}},
            "GetRelationalDatabase",
        )
        client.get_relational_database.side_effect = not_found
        with self._client_patch(client):
            self.assertEqual(
                node.lightsail.check_restore(restore),
                CoreCloudRestore.Status.IN_PROGRESS,
            )

    def test_delete_uses_relational_database_snapshot_api(self):
        node = self._make_lightsail_node()
        backup = self._backup(node, status=UtilBackup.Status.COMPLETE)
        client = mock.MagicMock()

        with self._client_patch(client):
            backup.soft_delete()

        client.delete_relational_database_snapshot.assert_called_once_with(
            relationalDatabaseSnapshotName="db-snapshot"
        )
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)


class LightsailDatabaseApiTests(BaseTestCase):
    def _connection(self):
        connection = factories.make_connection(
            self.account, self.member, code="lightsail"
        )
        CoreAuthLightsail.objects.create(
            connection=connection,
            region=CoreLightsailRegion.objects.get(code="us-east-1"),
        )
        return connection

    def _resource(self, connection, *, name, resource_type):
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name=name,
            added_by=self.member,
        )
        return CoreLightsail.objects.create(
            node=node,
            name=name,
            unique_id=name,
            resource_type=resource_type,
        )

    def _queryset_ids(self, view_class):
        view = view_class()
        view.request = SimpleNamespace(user=self.user)
        view.kwargs = {}
        return set(view.get_queryset().values_list("id", flat=True))

    def test_cloud_and_database_views_are_resource_type_isolated(self):
        connection = self._connection()
        instance = self._resource(
            connection,
            name="instance",
            resource_type=CoreLightsail.ResourceType.INSTANCE,
        )
        database = self._resource(
            connection,
            name="database",
            resource_type=CoreLightsail.ResourceType.DATABASE,
        )

        cloud_ids = self._queryset_ids(CoreCloudLightsailView)
        database_ids = self._queryset_ids(CoreCloudLightsailDatabaseView)

        self.assertEqual(cloud_ids, {instance.id})
        self.assertEqual(database_ids, {database.id})

    def test_write_serializers_assign_their_owned_resource_types(self):
        connection = self._connection()
        request = SimpleNamespace(user=self.user)

        instance_serializer = CoreCloudLightsailWriteSerializer(
            data={
                "name": "instance-through-instance-api",
                "unique_id": "instance-through-instance-api",
                "metadata": {},
                "resource_type": CoreLightsail.ResourceType.DATABASE,
                "node": {
                    "name": "instance-through-instance-api",
                    "connection": connection.id,
                },
            },
            context={"request": request},
        )
        self.assertTrue(instance_serializer.is_valid(), instance_serializer.errors)
        instance = instance_serializer.save()

        database_serializer = CoreCloudLightsailDatabaseWriteSerializer(
            data={
                "name": "database-through-database-api",
                "unique_id": "database-through-database-api",
                "metadata": {},
                "resource_type": CoreLightsail.ResourceType.INSTANCE,
                "node": {
                    "name": "database-through-database-api",
                    "connection": connection.id,
                },
            },
            context={"request": request},
        )
        self.assertTrue(database_serializer.is_valid(), database_serializer.errors)
        database = database_serializer.save()

        self.assertEqual(instance.resource_type, CoreLightsail.ResourceType.INSTANCE)
        self.assertEqual(database.resource_type, CoreLightsail.ResourceType.DATABASE)

    def test_lightsail_backup_serializer_uses_the_lightsail_relation(self):
        connection = self._connection()
        resource = self._resource(
            connection,
            name="instance",
            resource_type=CoreLightsail.ResourceType.INSTANCE,
        )
        backup = resource.backups.create(
            uuid="instance-snapshot",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            unique_id="instance-snapshot",
        )

        data = CoreLightsailBackupSerializer(backup).data

        self.assertIn("lightsail", data)
        self.assertEqual(data["lightsail"]["id"], resource.id)
        self.assertNotIn("website", data)
