"""OVH Public Cloud API route and legacy-region recovery coverage."""

from unittest import mock

from django.test import SimpleTestCase

from apps.console.connection.models import _ovh_project_regions
from apps.console.node.models import CoreOVHCA


class OVHRegionRouteTests(SimpleTestCase):
    def test_current_region_scoped_paths_are_used(self):
        provider = CoreOVHCA(
            project_id="project-1",
            unique_id="instance-1",
            metadata={"_bs_region": "GRA11"},
        )
        client = mock.Mock()

        self.assertEqual(
            provider._ovh_resource_path(client, "instance"),
            "/cloud/project/project-1/region/GRA11/instance/instance-1",
        )
        self.assertEqual(
            provider._ovh_snapshot_path(client, "instance"),
            "/cloud/project/project-1/region/GRA11/snapshot",
        )
        self.assertEqual(
            provider._ovh_snapshot_path(client, "volume", "snapshot-1"),
            "/cloud/project/project-1/region/GRA11/volume/snapshot/snapshot-1",
        )
        client.get.assert_not_called()

    def test_region_is_discovered_for_legacy_node_metadata(self):
        provider = CoreOVHCA(
            project_id="project-1",
            unique_id="instance-1",
            metadata=None,
        )
        client = mock.Mock()
        client.get.side_effect = [
            ["GRA11", "BHS5"],
            {"id": "instance-1", "region": "GRA11"},
        ]
        with mock.patch.object(provider, "_persist_region", side_effect=lambda region: region):
            self.assertEqual(provider._ovh_region(client, "instance"), "GRA11")

        self.assertEqual(
            client.get.call_args_list[0].args[0],
            "/cloud/project/project-1/region",
        )
        self.assertEqual(
            client.get.call_args_list[1].args[0],
            "/cloud/project/project-1/region/GRA11/instance/instance-1",
        )

    def test_project_region_listing_normalizes_api_region_objects(self):
        client = mock.Mock()
        client.get.return_value = [
            "GRA11",
            {"name": "BHS5"},
            {"region": "WAW1"},
        ]

        self.assertEqual(
            _ovh_project_regions(client, "project-1"),
            ["GRA11", "BHS5", "WAW1"],
        )
        client.get.assert_called_once_with("/cloud/project/project-1/region")
