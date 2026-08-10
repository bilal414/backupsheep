from django.test import SimpleTestCase
from django.urls import resolve

from apps.api.v1.cloud.aws.views import CoreCloudAWSView


class CloudNodeUIRouteTests(SimpleTestCase):
    def test_aws_cloud_collection_route_supports_ui_list_and_create(self):
        match = resolve("/api/v1/clouds/aws/")

        self.assertIs(match.func.cls, CoreCloudAWSView)
        self.assertEqual(match.func.actions["get"], "list")
        self.assertEqual(match.func.actions["post"], "create")
