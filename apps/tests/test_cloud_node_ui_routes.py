from pathlib import Path

from django.test import SimpleTestCase
from django.urls import resolve

from apps.api.v1.cloud.aws.views import CoreCloudAWSView


CONNECTION_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "console"
    / "_templates"
    / "console"
    / "setup"
    / "_setup_and_list_connection.html"
)


class CloudNodeUIRouteTests(SimpleTestCase):
    def test_aws_cloud_collection_route_supports_ui_list_and_create(self):
        match = resolve("/api/v1/clouds/aws/")

        self.assertIs(match.func.cls, CoreCloudAWSView)
        self.assertEqual(match.func.actions["get"], "list")
        self.assertEqual(match.func.actions["post"], "create")

    def test_hetzner_does_not_advertise_unsupported_volume_nodes(self):
        source = CONNECTION_TEMPLATE.read_text(encoding="utf-8")

        self.assertIn(
            'integration.code != "aws_rds" and integration.code != "hetzner"',
            source,
        )

    def test_vultr_managed_database_link_uses_cloud_collection_route(self):
        connection_source = CONNECTION_TEMPLATE.read_text(encoding="utf-8")
        node_template = CONNECTION_TEMPLATE.with_name("_setup_cloud_node.html")
        node_source = node_template.read_text(encoding="utf-8")
        create_source = CONNECTION_TEMPLATE.with_name(
            "3_integration_create_node.html"
        ).read_text(encoding="utf-8")

        self.assertIn("Create Managed Database Node", connection_source)
        self.assertIn('object_code == "vultr_database"', create_source)
        self.assertIn('endpointIntegrationCode = isVultrDatabase', node_source)
        self.assertIn('"vultr_database" : this.integration_code', node_source)
        self.assertIn("delete data.resource_type", node_source)
        self.assertIn("data.engine = object._bs_engine", node_source)
