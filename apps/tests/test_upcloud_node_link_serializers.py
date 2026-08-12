from unittest import mock

from django.test import RequestFactory

from apps.api.v1.cloud.upcloud.serializers import (
    CoreCloudUpCloudWriteSerializer,
)
from apps.api.v1.node.serializers import CoreNodeSerializer
from apps.api.v1.volume.upcloud.serializers import (
    CoreVolumeUpCloudWriteSerializer,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.connection.models import CoreAuthUpCloud, CoreIntegration
from apps.console.node.models import CoreNode, CoreOracle, CoreUpCloud
from apps.tests import factories
from apps.tests.base import BaseTestCase


class UpCloudNodeLinkSerializerTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="upcloud",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        self.connection = factories.make_connection(
            self.account, self.member, code="upcloud"
        )
        CoreAuthUpCloud.objects.create(
            connection=self.connection,
            username=bs_encrypt("account-user", self.account.get_encryption_key()),
            password=bs_encrypt("account-password", self.account.get_encryption_key()),
        )
        request = RequestFactory().post("/api/v1/clouds/upcloud/")
        request.user = self.user
        self.context = {"request": request}

    def _server(self, resource_id="server-1"):
        return {
            "uuid": resource_id,
            "title": "Provider server",
            "zone": "fi-hel1",
            "state": "started",
        }

    def _volume(self, resource_id="volume-1"):
        return {
            "uuid": resource_id,
            "title": "Provider volume",
            "zone": "fi-hel1",
            "type": "normal",
            "size": 10,
            "state": "online",
        }

    def _payload(self, resource, resource_type, metadata=None):
        if metadata is None:
            metadata = dict(resource)
            metadata.update(
                {
                    "_bs_unique_id": resource["uuid"],
                    "_bs_name": resource.get("title") or resource["uuid"],
                    "_bs_region": resource.get("zone"),
                    "_bs_size": resource.get("size")
                    if resource_type == "volume"
                    else None,
                    "_bs_resource_type": resource_type,
                }
            )
        return {
            "node": {
                "connection": self.connection.id,
                "name": "client supplied name",
            },
            "name": "client supplied name",
            "unique_id": resource["uuid"],
            "resource_type": resource_type,
            "metadata": metadata,
        }

    def test_cloud_link_uses_account_pinned_discovery_and_provider_metadata(self):
        resource = self._server()
        with mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ) as verifier, mock.patch(
            "apps.api.v1.cloud.upcloud.serializers.list_upcloud_servers",
            return_value=[resource],
        ) as discovery:
            serializer = CoreCloudUpCloudWriteSerializer(
                data=self._payload(resource, "cloud"), context=self.context
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            linked = serializer.save()

        verifier.assert_called_once()
        discovery.assert_called_once()
        self.assertEqual(linked.unique_id, "server-1")
        self.assertEqual(linked.name, "Provider server")
        self.assertEqual(linked.node.name, "Provider server")
        self.assertEqual(linked.metadata["_bs_resource_type"], "cloud")

    def test_volume_link_requires_normal_storage_and_provider_metadata(self):
        resource = self._volume()
        with mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps.api.v1.volume.upcloud.serializers.list_upcloud_storages",
            return_value=[resource],
        ):
            serializer = CoreVolumeUpCloudWriteSerializer(
                data=self._payload(resource, "volume"), context=self.context
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            linked = serializer.save()

        self.assertEqual(linked.unique_id, "volume-1")
        self.assertEqual(linked.name, "Provider volume")
        self.assertEqual(linked.metadata["_bs_resource_type"], "volume")

    def test_tampered_type_or_metadata_fails_before_local_creation(self):
        resource = self._server()
        initial_nodes = CoreNode.objects.count()
        with mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps.api.v1.cloud.upcloud.serializers.list_upcloud_servers",
            return_value=[resource],
        ):
            wrong_type = CoreCloudUpCloudWriteSerializer(
                data=self._payload(resource, "volume"), context=self.context
            )
            self.assertFalse(wrong_type.is_valid())
            self.assertIn("resource_type", wrong_type.errors)

            tampered = dict(resource)
            tampered["title"] = "not provider authoritative"
            bad_metadata = CoreCloudUpCloudWriteSerializer(
                data=self._payload(resource, "cloud", metadata=tampered),
                context=self.context,
            )
            self.assertFalse(bad_metadata.is_valid())
            self.assertIn("metadata", bad_metadata.errors)

        self.assertEqual(CoreNode.objects.count(), initial_nodes)

    def test_duplicate_provider_id_is_rejected_across_connections(self):
        resource = self._server()
        with mock.patch.object(
            CoreAuthUpCloud, "get_verified_client", return_value=object()
        ), mock.patch(
            "apps.api.v1.cloud.upcloud.serializers.list_upcloud_servers",
            return_value=[resource],
        ):
            first = CoreCloudUpCloudWriteSerializer(
                data=self._payload(resource, "cloud"), context=self.context
            )
            self.assertTrue(first.is_valid(), first.errors)
            first.save()

            second = CoreCloudUpCloudWriteSerializer(
                data=self._payload(resource, "cloud"), context=self.context
            )
            self.assertFalse(second.is_valid())
            self.assertIn("already linked", str(second.errors).lower())

        self.assertEqual(
            CoreUpCloud.objects.filter(unique_id="server-1").count(), 1
        )

    def test_update_cannot_replace_provider_id_or_metadata(self):
        node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="Provider server",
            added_by=self.member,
        )
        integration = CoreUpCloud.objects.create(
            node=node,
            name="Provider server",
            unique_id="server-1",
            metadata={"uuid": "server-1", "_bs_resource_type": "cloud"},
        )
        serializer = CoreCloudUpCloudWriteSerializer(
            integration,
            data={
                "node": {"connection": self.connection.id},
                "unique_id": "server-2",
                "metadata": integration.metadata,
            },
            context=self.context,
            partial=True,
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("unique_id", serializer.errors)

    def test_generic_node_serializer_exposes_upcloud_and_oracle_details(self):
        upcloud_node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="UpCloud server",
            added_by=self.member,
        )
        upcloud = CoreUpCloud.objects.create(
            node=upcloud_node,
            name="UpCloud server",
            unique_id="server-1",
        )
        self.assertEqual(
            CoreNodeSerializer(upcloud_node).data["type_details"],
            {"name": "upcloud", "id": upcloud.id},
        )

        oracle_node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="Oracle server",
            added_by=self.member,
        )
        oracle = CoreOracle.objects.create(
            node=oracle_node,
            name="Oracle server",
            unique_id="ocid1.instance.test",
        )
        self.assertEqual(
            CoreNodeSerializer(oracle_node).data["type_details"],
            {"name": "oracle", "id": oracle.id},
        )
