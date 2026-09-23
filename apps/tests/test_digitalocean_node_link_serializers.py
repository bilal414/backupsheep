from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection as db_connection
from django.test import RequestFactory, TransactionTestCase, skipUnlessDBFeature
from rest_framework import serializers as drf_serializers

from apps.api.v1.cloud.digitalocean.serializers import (
    CoreCloudDigitalOceanWriteSerializer,
)
from apps.api.v1.connection.digitalocean.client import (
    DigitalOceanAPIError,
    list_eligible_objects,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.api.v1.volume.digitalocean.serializers import (
    CoreVolumeDigitalOceanWriteSerializer,
)
from apps.console.connection.models import (
    CoreAuthDigitalOcean,
    CoreConnection,
    CoreIntegration,
)
from apps.console.node.models import CoreDigitalOcean, CoreNode
from apps.tests import factories
from apps.tests.base import BaseTestCase


class DigitalOceanNodeLinkSerializerTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        self.connection = self._make_connection("DigitalOcean primary")
        request = RequestFactory().post("/api/v1/cloud/digitalocean/")
        request.user = self.user
        self.context = {"request": request}

    def _make_connection(self, name):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name=name,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-token", self.account.get_encryption_key()),
        )
        return connection

    @staticmethod
    def _server(resource_id=1001):
        return {
            "id": resource_id,
            "name": "Provider droplet",
            "region": {"name": "nyc3"},
            "size": {"disk": 25},
        }

    @staticmethod
    def _volume(resource_id=2001):
        return {
            "id": resource_id,
            "name": "Provider volume",
            "region": {"name": "nyc3"},
            "size_gigabytes": 10,
        }

    def _payload(self, resource, *, resource_type, connection=None, metadata=None):
        return {
            "node": {
                "connection": (connection or self.connection).id,
                "name": "Client supplied name",
            },
            "name": "Client supplied name",
            "unique_id": resource["id"],
            "resource_type": resource_type,
            "metadata": metadata,
        }

    @staticmethod
    def _connection_discovery_object(resource, resource_type):
        """Build the exact object returned by connection discovery."""
        with mock.patch(
            "apps.api.v1.connection.digitalocean.client.iter_collection",
            return_value=[resource],
        ):
            return list_eligible_objects(
                headers={"Authorization": "Bearer test"},
                object_type=resource_type,
            )[0]

    def test_server_link_accepts_exact_discovery_metadata_and_stores_provider_metadata(self):
        resource = self._server()
        browser_metadata = self._connection_discovery_object(resource, "cloud")
        self.assertIsInstance(browser_metadata["_bs_unique_id"], int)
        self.assertNotIn("_bs_resource_type", browser_metadata)
        verified_headers = {"Authorization": "Bearer test"}
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value=verified_headers,
        ) as verifier, mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=[browser_metadata],
        ) as discovery:
            serializer = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    metadata=browser_metadata,
                ),
                context=self.context,
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            linked = serializer.save()

        verifier.assert_called_once_with()
        discovery.assert_called_once_with(
            headers=verified_headers,
            object_type="cloud",
        )
        self.assertEqual(linked.unique_id, "1001")
        self.assertEqual(linked.name, "Provider droplet")
        self.assertEqual(linked.node.name, "Provider droplet")
        self.assertEqual(linked.metadata["_bs_unique_id"], "1001")
        self.assertEqual(linked.metadata["_bs_resource_type"], "cloud")

    def test_volume_link_accepts_exact_discovery_metadata_and_normalizes_provider_id(self):
        resource = self._volume()
        browser_metadata = self._connection_discovery_object(resource, "volume")
        self.assertIsInstance(browser_metadata["_bs_unique_id"], int)
        self.assertNotIn("_bs_resource_type", browser_metadata)
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.api.v1.volume.digitalocean.serializers.list_eligible_objects",
            return_value=[browser_metadata],
        ) as discovery:
            serializer = CoreVolumeDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="volume",
                    metadata=browser_metadata,
                ),
                context=self.context,
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            linked = serializer.save()

        discovery.assert_called_once_with(
            headers={"Authorization": "Bearer test"},
            object_type="volume",
        )
        self.assertEqual(linked.unique_id, "2001")
        self.assertEqual(linked.name, "Provider volume")
        self.assertEqual(linked.node.type, CoreNode.Type.VOLUME)
        self.assertEqual(linked.metadata["_bs_unique_id"], "2001")
        self.assertEqual(linked.metadata["_bs_resource_type"], "volume")

    def test_identity_and_type_tampering_cannot_change_authoritative_metadata(self):
        resource = self._server()
        browser_metadata = self._connection_discovery_object(resource, "cloud")
        initial_count = CoreNode.objects.count()
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=[browser_metadata],
        ):
            wrong_type = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(resource, resource_type="volume"),
                context=self.context,
            )
            self.assertFalse(wrong_type.is_valid())
            self.assertEqual(
                wrong_type.errors["resource_type"][0].code,
                "RESOURCE_TYPE_MISMATCH",
            )

            wrong_id_metadata = dict(browser_metadata)
            wrong_id_metadata["_bs_unique_id"] = 9999
            wrong_id = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    metadata=wrong_id_metadata,
                ),
                context=self.context,
            )
            self.assertFalse(wrong_id.is_valid())
            self.assertEqual(
                wrong_id.errors["metadata"][0].code,
                "PROVIDER_OWNERSHIP_MISMATCH",
            )

            wrong_type_metadata = dict(browser_metadata)
            wrong_type_metadata["_bs_resource_type"] = "volume"
            wrong_metadata_type = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    metadata=wrong_type_metadata,
                ),
                context=self.context,
            )
            self.assertFalse(wrong_metadata_type.is_valid())
            self.assertEqual(
                wrong_metadata_type.errors["metadata"][0].code,
                "PROVIDER_OWNERSHIP_MISMATCH",
            )

            stale_descriptions = dict(browser_metadata)
            stale_descriptions["name"] = "stale browser name"
            stale_descriptions["_bs_name"] = "tampered client name"
            stale_descriptions["_bs_size"] = 999999
            accepted = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    metadata=stale_descriptions,
                ),
                context=self.context,
            )
            self.assertTrue(accepted.is_valid(), accepted.errors)
            linked = accepted.save()

        self.assertEqual(CoreNode.objects.count(), initial_count + 1)
        self.assertEqual(linked.unique_id, "1001")
        self.assertEqual(linked.name, "Provider droplet")
        self.assertEqual(linked.metadata["name"], "Provider droplet")
        self.assertEqual(linked.metadata["_bs_name"], "Provider droplet")
        self.assertEqual(linked.metadata["_bs_size"], 25)
        self.assertEqual(linked.metadata["_bs_unique_id"], "1001")
        self.assertEqual(linked.metadata["_bs_resource_type"], "cloud")

    def test_volume_metadata_identity_and_type_contradictions_fail_closed(self):
        resource = self._volume()
        browser_metadata = self._connection_discovery_object(resource, "volume")
        cases = (
            ("id", "different-volume"),
            ("_bs_unique_id", "different-volume"),
            ("resource_type", "droplet"),
            ("_bs_resource_type", "cloud"),
        )

        with mock.patch(
            "apps.api.v1.volume.digitalocean.serializers.list_eligible_objects"
        ) as discovery:
            for key, value in cases:
                with self.subTest(key=key):
                    tampered = dict(browser_metadata)
                    tampered[key] = value
                    serializer = CoreVolumeDigitalOceanWriteSerializer(
                        data=self._payload(
                            resource,
                            resource_type="volume",
                            metadata=tampered,
                        ),
                        context=self.context,
                    )
                    self.assertFalse(serializer.is_valid())
                    self.assertEqual(
                        serializer.errors["metadata"][0].code,
                        "PROVIDER_OWNERSHIP_MISMATCH",
                    )

        discovery.assert_not_called()
        self.assertFalse(CoreDigitalOcean.objects.filter(unique_id="2001").exists())

    def test_provider_not_found_duplicate_malformed_and_provider_error_fail_closed(self):
        resource = self._server()
        cases = (
            (
                [],
                "PROVIDER_NOT_FOUND",
            ),
            (
                [resource, dict(resource)],
                "PROVIDER_DUPLICATE_MATCH",
            ),
            (
                [{"name": "missing id"}],
                "PROVIDER_MALFORMED_RESPONSE",
            ),
        )
        for provider_resources, expected_code in cases:
            with self.subTest(expected_code=expected_code), mock.patch.object(
                CoreAuthDigitalOcean,
                "get_verified_client",
                return_value={"Authorization": "Bearer test"},
            ), mock.patch(
                "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
                return_value=provider_resources,
            ):
                serializer = CoreCloudDigitalOceanWriteSerializer(
                    data=self._payload(resource, resource_type="cloud"),
                    context=self.context,
                )
                self.assertFalse(serializer.is_valid())
                self.assertEqual(serializer.errors["unique_id"][0].code, expected_code)

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            side_effect=Exception("provider credential should not escape"),
        ):
            serializer = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(resource, resource_type="cloud"),
                context=self.context,
            )
            self.assertFalse(serializer.is_valid())
            self.assertEqual(
                serializer.errors["unique_id"][0].code,
                "PROVIDER_MALFORMED_RESPONSE",
            )
            self.assertNotIn("provider credential", str(serializer.errors))

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=[dict(resource, resource_type="volume")],
        ):
            serializer = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(resource, resource_type="cloud"),
                context=self.context,
            )
            self.assertFalse(serializer.is_valid())
            self.assertEqual(
                serializer.errors["unique_id"][0].code,
                "PROVIDER_OWNERSHIP_MISMATCH",
            )

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            side_effect=DigitalOceanAPIError("PROVIDER_AUTH_FAILED"),
        ):
            serializer = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(resource, resource_type="cloud"),
                context=self.context,
            )
            self.assertFalse(serializer.is_valid())
            self.assertEqual(
                serializer.errors["unique_id"][0].code,
                "PROVIDER_AUTH_FAILED",
            )

    def test_duplicate_provider_id_is_fenced_across_connections_in_one_account(self):
        resource = self._server()
        second_connection = self._make_connection("DigitalOcean duplicate connection")
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=[resource],
        ):
            first = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(resource, resource_type="cloud"),
                context=self.context,
            )
            self.assertTrue(first.is_valid(), first.errors)
            first.save()

            second = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    connection=second_connection,
                ),
                context=self.context,
            )
            self.assertFalse(second.is_valid())
            self.assertEqual(
                second.errors["unique_id"][0].code,
                "RESOURCE_ALREADY_LINKED",
            )

        self.assertEqual(
            CoreDigitalOcean.objects.filter(
                node__connection__account=self.account,
                unique_id="1001",
            ).count(),
            1,
        )

    def test_update_keeps_provider_identity_connection_and_metadata_immutable(self):
        node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="Provider droplet",
            added_by=self.member,
        )
        linked = CoreDigitalOcean.objects.create(
            node=node,
            name="Provider droplet",
            unique_id="1001",
            metadata={"id": "1001", "_bs_resource_type": "cloud"},
        )

        changed_id = CoreCloudDigitalOceanWriteSerializer(
            linked,
            data={"unique_id": "1002"},
            context=self.context,
            partial=True,
        )
        self.assertFalse(changed_id.is_valid())
        self.assertEqual(
            changed_id.errors["unique_id"][0].code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

        changed_metadata = CoreCloudDigitalOceanWriteSerializer(
            linked,
            data={"metadata": {"id": "tampered"}},
            context=self.context,
            partial=True,
        )
        self.assertFalse(changed_metadata.is_valid())
        self.assertEqual(
            changed_metadata.errors["metadata"][0].code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

        second_connection = self._make_connection("DigitalOcean update connection")
        changed_connection = CoreCloudDigitalOceanWriteSerializer(
            linked,
            data={"node": {"connection": second_connection.id}},
            context=self.context,
            partial=True,
        )
        self.assertFalse(changed_connection.is_valid())
        self.assertEqual(
            changed_connection.errors["node"][0].code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

        with mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects"
        ) as discovery:
            rename = CoreCloudDigitalOceanWriteSerializer(
                linked,
                data={"notes": "operator note"},
                context=self.context,
                partial=True,
            )
            self.assertTrue(rename.is_valid(), rename.errors)
            rename.save()
        discovery.assert_not_called()
        self.assertEqual(linked.__class__.objects.get(pk=linked.pk).notes, "operator note")

    def test_nested_node_serializer_keeps_tenant_authorization(self):
        other_account, other_member, _ = factories.make_account()
        other_connection = factories.make_connection(
            other_account,
            other_member,
            code="digitalocean",
            name="Other account DigitalOcean",
        )
        resource = self._server()
        with mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects"
        ) as discovery:
            serializer = CoreCloudDigitalOceanWriteSerializer(
                data=self._payload(
                    resource,
                    resource_type="cloud",
                    connection=other_connection,
                ),
                context=self.context,
            )
            self.assertFalse(serializer.is_valid())
        discovery.assert_not_called()
        self.assertIn("node", serializer.errors)
        self.assertIn("access", str(serializer.errors).lower())


@skipUnlessDBFeature("has_select_for_update")
class ConcurrentDigitalOceanNodeLinkSerializerTests(TransactionTestCase):
    def setUp(self):
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        self.account, self.member, self.user = factories.make_account(
            email="digitalocean-concurrent@example.com"
        )
        self.first_connection = self._make_connection("DigitalOcean concurrent 1")
        self.second_connection = self._make_connection("DigitalOcean concurrent 2")
        self.resource = {
            "id": 9001,
            "name": "Concurrent provider droplet",
            "region": {"name": "nyc3"},
        }

    def _make_connection(self, name):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name=name,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-token", self.account.get_encryption_key()),
        )
        return connection

    def test_concurrent_create_is_serialized_by_account_row_lock(self):
        barrier = Barrier(2)
        user_id = self.user.id
        connection_ids = [self.first_connection.id, self.second_connection.id]

        def create_link(connection_id):
            close_old_connections()
            try:
                user = get_user_model().objects.get(pk=user_id)
                request = RequestFactory().post("/api/v1/cloud/digitalocean/")
                request.user = user
                payload = {
                    "node": {"connection": connection_id, "name": "client"},
                    "name": "client",
                    "unique_id": self.resource["id"],
                    "resource_type": "cloud",
                }
                serializer = CoreCloudDigitalOceanWriteSerializer(
                    data=payload,
                    context={"request": request},
                )
                valid = serializer.is_valid()
                barrier.wait(timeout=15)
                if not valid:
                    return "invalid-before-create", serializer.errors
                try:
                    linked = serializer.save()
                    return "created", linked.pk
                except drf_serializers.ValidationError as error:
                    return "invalid-at-create", error.detail
            except Exception as error:
                return "error", repr(error)
            finally:
                close_old_connections()

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ), mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=[self.resource],
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(create_link, connection_ids))

        self.assertNotIn("error", [result[0] for result in results], results)
        self.assertEqual(
            sorted(result[0] for result in results),
            ["created", "invalid-at-create"],
        )
        self.assertEqual(
            CoreDigitalOcean.objects.filter(
                node__connection__account_id=self.account.id,
                unique_id="9001",
            ).count(),
            1,
        )
        self.assertTrue(db_connection.features.has_select_for_update)
