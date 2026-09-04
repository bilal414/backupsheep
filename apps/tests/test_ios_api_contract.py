from importlib import import_module
from cryptography.fernet import Fernet
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch

from apps.api.v1.backup.digitalocean.serializers import CoreDigitalOceanBackupSerializer
from apps.api.v1.backup.website.serializers import CoreWebsiteBackupSerializer
from apps.console.account.models import CoreAccount
from apps.console.backup.models import CoreDigitalOceanBackup, CoreWebsiteBackup
from apps.console.connection.models import CoreConnection
from apps.console.member.models import CoreMemberAccount
from apps.console.storage.models import CoreStorage
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class IOSAPIContractTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_accounts_and_members_return_ios_switching_shape(self):
        second_account = CoreAccount.objects.create(
            name="Second Account", encryption_key=Fernet.generate_key()
        )
        second_membership = CoreMemberAccount.objects.create(
            member=self.member,
            account=second_account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )
        current_membership = self.member.memberships.get(account=self.account)

        accounts_response = self.client.get("/api/v1/accounts/")
        self.assertEqual(accounts_response.status_code, status.HTTP_200_OK)
        accounts = {item["id"]: item for item in accounts_response.json()}
        self.assertEqual(accounts[self.account.id]["name"], self.account.name)
        self.assertTrue(accounts[self.account.id]["is_current"])
        self.assertFalse(accounts[second_account.id]["is_current"])

        members_response = self.client.get("/api/v1/members/")
        self.assertEqual(members_response.status_code, status.HTTP_200_OK)
        member = members_response.json()[0]
        self.assertEqual(member["id"], self.member.id)
        self.assertEqual(member["member_id"], self.member.id)
        self.assertEqual(member["membership_id"], current_membership.id)
        self.assertEqual(member["name"], self.member.full_name)
        self.assertEqual(member["role"], "owner")
        self.assertEqual(member["role_display"], "Owner")
        self.assertEqual(member["account"]["id"], self.account.id)
        self.assertEqual(member["account"]["name"], self.account.name)

        switch_response = self.client.post(
            f"/api/v1/members/{self.member.id}/switch_current_account/",
            {"account_id": second_account.id},
            format="json",
        )
        self.assertEqual(switch_response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            self.member.memberships.get(account=second_account).current
        )
        self.assertFalse(self.member.memberships.get(account=self.account).current)
        self.assertEqual(second_membership.id, self.member.memberships.get(account=second_account).id)

        accounts_response = self.client.get("/api/v1/accounts/")
        accounts = {item["id"]: item for item in accounts_response.json()}
        self.assertFalse(accounts[self.account.id]["is_current"])
        self.assertTrue(accounts[second_account.id]["is_current"])

    def test_storage_resources_include_nested_references_and_actions_return_resource(self):
        storage = factories.make_storage(self.account, self.member)

        list_response = self.client.get("/api/v1/storage/all/")
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        storage_data = list_response.json()[0]
        self.assertIsInstance(storage_data["type"], dict)
        self.assertEqual(storage_data["type"]["id"], storage.type_id)
        self.assertIsInstance(storage_data["account"], dict)
        self.assertEqual(storage_data["account"]["id"], self.account.id)
        self.assertEqual(storage_data["account"]["name"], self.account.name)
        self.assertEqual(storage_data["status_display"], "Active")

        generic_list_response = self.client.get("/api/v1/storage/")
        self.assertEqual(generic_list_response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(generic_list_response.json()[0]["type"], dict)
        self.assertEqual(generic_list_response.json()[0]["account"]["name"], self.account.name)

        pause_response = self.client.post(f"/api/v1/storage/{storage.id}/pause/")
        self.assertEqual(pause_response.status_code, status.HTTP_200_OK)
        self.assertEqual(pause_response.json()["id"], storage.id)
        self.assertEqual(pause_response.json()["status_display"], "Paused")
        self.assertIsInstance(pause_response.json()["type"], dict)

        resume_response = self.client.post(f"/api/v1/storage/{storage.id}/resume/")
        self.assertEqual(resume_response.status_code, status.HTTP_200_OK)
        self.assertEqual(resume_response.json()["id"], storage.id)
        self.assertEqual(resume_response.json()["status_display"], "Active")

    def test_node_and_schedule_actions_return_decodable_resources(self):
        node = factories.make_website_node(self.account, self.member)
        node_pause = self.client.post(f"/api/v1/nodes/{node.id}/pause/")
        self.assertEqual(node_pause.status_code, status.HTTP_200_OK)
        self.assertEqual(node_pause.json()["id"], node.id)
        self.assertEqual(node_pause.json()["status_display"], "Paused")
        self.assertIn("detail", node_pause.json())

        node_resume = self.client.post(f"/api/v1/nodes/{node.id}/resume/")
        self.assertEqual(node_resume.status_code, status.HTTP_200_OK)
        self.assertEqual(node_resume.json()["id"], node.id)
        self.assertEqual(node_resume.json()["status_display"], "Active")

        schedule = factories.make_schedule(node, self.member)
        schedule_pause = self.client.post(f"/api/v1/schedules/{schedule.id}/pause/")
        self.assertEqual(schedule_pause.status_code, status.HTTP_200_OK)
        self.assertEqual(schedule_pause.json()["id"], schedule.id)
        self.assertEqual(schedule_pause.json()["status_display"], "Paused")

        schedule_resume = self.client.post(f"/api/v1/schedules/{schedule.id}/resume/")
        self.assertEqual(schedule_resume.status_code, status.HTTP_200_OK)
        self.assertEqual(schedule_resume.json()["id"], schedule.id)
        self.assertEqual(schedule_resume.json()["status_display"], "Active")

    def test_generic_validation_routes_return_validation_result(self):
        storage = factories.make_storage(self.account, self.member)
        connection = factories.make_connection(self.account, self.member)

        with patch.object(CoreStorage, "validate", return_value=True):
            storage_response = self.client.post(
                f"/api/v1/storage/{storage.id}/validate/"
            )
        self.assertEqual(storage_response.status_code, status.HTTP_200_OK)
        self.assertEqual(storage_response.json()["success"], True)
        self.assertIsInstance(storage_response.json()["message"], str)

        with patch.object(CoreConnection, "validate", return_value=False):
            connection_response = self.client.post(
                f"/api/v1/connections/{connection.id}/validate/"
            )
        self.assertEqual(connection_response.status_code, status.HTTP_200_OK)
        self.assertEqual(connection_response.json()["success"], False)
        self.assertIsInstance(connection_response.json()["message"], str)
        self.assertEqual(
            self.client.get(f"/api/v1/storage/{storage.id}/validate/").status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.get(f"/api/v1/connections/{connection.id}/validate/").status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

        connections_response = self.client.get("/api/v1/connections/")
        self.assertEqual(connections_response.status_code, status.HTTP_200_OK)
        connection_data = connections_response.json()[0]
        self.assertEqual(connection_data["account"]["name"], self.account.name)
        self.assertIsInstance(connection_data["integration"], dict)
        self.assertIsInstance(connection_data["location"], dict)

        other_account, other_member, _ = factories.make_account()
        other_storage = factories.make_storage(other_account, other_member)
        other_connection = factories.make_connection(other_account, other_member)
        self.assertEqual(
            self.client.post(
                f"/api/v1/storage/{other_storage.id}/validate/"
            ).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.post(
                f"/api/v1/connections/{other_connection.id}/validate/"
            ).status_code,
            status.HTTP_404_NOT_FOUND,
        )

        self.client.force_authenticate(user=None)
        self.assertIn(
            self.client.post(f"/api/v1/storage/{storage.id}/validate/").status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )
        self.assertIn(
            self.client.post(f"/api/v1/connections/{connection.id}/validate/").status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )

    def test_backup_activity_shape_counts_only_visible_nodes(self):
        website_node = factories.make_website_node(self.account, self.member)
        cloud_node = factories.make_cloud_node(self.account, self.member)
        other_account, other_member, _ = factories.make_account()
        other_node = factories.make_website_node(other_account, other_member)

        CoreWebsiteBackup.objects.create(
            website=website_node.website,
            name="website-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        CoreDigitalOceanBackup.objects.create(
            digitalocean=cloud_node.digitalocean,
            name="cloud-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        CoreWebsiteBackup.objects.create(
            website=other_node.website,
            name="other-tenant-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        response = self.client.get("/api/v1/stats/backups/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = response.json()
        self.assertEqual(len(payload["categories"]), 30)
        self.assertEqual(
            [series["name"] for series in payload["series"]],
            ["Database", "Website", "Cloud"],
        )
        self.assertTrue(all(len(series["data"]) == 30 for series in payload["series"]))
        self.assertEqual(sum(payload["series"][0]["data"]), 0)
        self.assertEqual(sum(payload["series"][1]["data"]), 1)
        self.assertEqual(sum(payload["series"][2]["data"]), 1)

    def test_backup_sources_include_common_database_alias(self):
        website_node = factories.make_website_node(self.account, self.member)
        cloud_node = factories.make_cloud_node(self.account, self.member)
        website_backup = CoreWebsiteBackup.objects.create(
            website=website_node.website,
            name="website-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        cloud_backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=cloud_node.digitalocean,
            name="cloud-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        website_data = CoreWebsiteBackupSerializer(website_backup).data
        cloud_data = CoreDigitalOceanBackupSerializer(cloud_backup).data
        self.assertEqual(website_data["database"]["id"], website_node.website.id)
        self.assertEqual(cloud_data["database"]["id"], cloud_node.digitalocean.id)
        self.assertEqual(cloud_data["website"]["id"], cloud_node.digitalocean.id)

    def test_all_ios_backup_provider_serializers_alias_source_as_database(self):
        serializers = {
            "apps.api.v1.backup.aws.serializers": ("CoreAWSBackupSerializer", "aws"),
            "apps.api.v1.backup.aws_rds.serializers": ("CoreAWSRDSBackupSerializer", "aws_rds"),
            "apps.api.v1.backup.basecamp.serializers": ("CoreBasecampBackupSerializer", "basecamp"),
            "apps.api.v1.backup.digitalocean.serializers": ("CoreDigitalOceanBackupSerializer", "digitalocean"),
            "apps.api.v1.backup.google_cloud.serializers": ("CoreGoogleCloudBackupSerializer", "google_cloud"),
            "apps.api.v1.backup.hetzner.serializers": ("CoreHetznerBackupSerializer", "hetzner"),
            "apps.api.v1.backup.lightsail.serializers": ("CoreLightsailBackupSerializer", "lightsail"),
            "apps.api.v1.backup.oracle.serializers": ("CoreOracleBackupSerializer", "oracle"),
            "apps.api.v1.backup.ovh_ca.serializers": ("CoreOVHCABackupSerializer", "ovh_ca"),
            "apps.api.v1.backup.ovh_eu.serializers": ("CoreOVHEUBackupSerializer", "ovh_eu"),
            "apps.api.v1.backup.ovh_us.serializers": ("CoreOVHUSBackupSerializer", "ovh_us"),
            "apps.api.v1.backup.upcloud.serializers": ("CoreUpCloudBackupSerializer", "upcloud"),
            "apps.api.v1.backup.vultr.serializers": ("CoreVultrBackupSerializer", "vultr"),
            "apps.api.v1.backup.website.serializers": ("CoreWebsiteBackupSerializer", "website"),
        }
        for module_name, (class_name, source) in serializers.items():
            serializer = getattr(import_module(module_name), class_name)()
            self.assertEqual(serializer.fields["database"].source, source)
