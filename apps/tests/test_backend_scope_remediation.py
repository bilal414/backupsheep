from datetime import timedelta

from django.contrib.auth.models import Group, Permission
from django.test import Client
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from django.utils.text import slugify

from apps.console.account.models import CoreAccountGroup
from apps.console.backup.models import CoreVultrDatabaseBackup, CoreWebsiteBackup
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode, CoreSchedule, CoreVultrDatabase
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    settings = CoreSiteSettings.load()
    settings.setup_completed = True
    settings.save()
    OnboardingMiddleware._completed = False


class RestrictedBackendScopeTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()

        auth_group = Group.objects.create(name=slugify(f"scope-{self.account.id}"))
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="scope",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        self.group.group.permissions.set(
            Permission.objects.filter(
                codename__in=("backup_download", "backup_delete", "schedule_changes")
            )
        )

        _account, self.client_member, self.client_user = factories.make_account(
            email=f"restricted-{self.account.id}@example.com"
        )
        self.client_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.client_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.client_user.groups.add(self.group.group)
        self.client = APIClient()
        self.client.force_authenticate(user=self.client_user)

        self.allowed_node = factories.make_website_node(self.account, self.member)
        self.hidden_node = factories.make_website_node(self.account, self.member)
        self.group.nodes.add(self.allowed_node)

    def _schedule_payload(self, node, storage_ids, schedule_type=CoreSchedule.Type.CRON):
        payload = {
            "node": node.id,
            "name": "scoped schedule",
            "status": CoreSchedule.Status.ACTIVE,
            "type": schedule_type,
            "timezone": "UTC",
            "minute": "0",
            "hour": "0",
            "day_of_month": "*",
            "month_of_year": "*",
            "day_of_week": "*",
            "year": "*",
            "storage_point_ids": storage_ids,
            "require_air_gapped_copy": False,
        }
        if schedule_type == CoreSchedule.Type.ONETIME:
            payload["at_datetime"] = (timezone.now() + timedelta(hours=1)).isoformat()
        return payload

    def test_hidden_website_backup_is_not_reachable_by_any_detail_action(self):
        allowed_backup = CoreWebsiteBackup.objects.create(
            website=self.allowed_node.website,
            name="allowed backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        hidden_backup = CoreWebsiteBackup.objects.create(
            website=self.hidden_node.website,
            name="hidden backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        response = self.client.get("/api/v1/backups/website/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([item["id"] for item in response.json()], [allowed_backup.id])

        hidden_url = f"/api/v1/backups/website/{hidden_backup.id}"
        self.assertEqual(self.client.get(f"{hidden_url}/").status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(
            self.client.get(f"{hidden_url}/download/?storage_point_id=999999").status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.post(f"{hidden_url}/restore/", {"confirm": True}, format="json").status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            self.client.post(f"{hidden_url}/retry/").status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            self.client.post(f"{hidden_url}/cancel/").status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            self.client.delete(f"{hidden_url}/").status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertTrue(CoreWebsiteBackup.objects.filter(pk=hidden_backup.pk).exists())

        owner_client = APIClient()
        owner_client.force_authenticate(user=self.user)
        owner_response = owner_client.get("/api/v1/backups/website/")
        self.assertEqual(owner_response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item["id"] for item in owner_response.json()},
            {allowed_backup.id, hidden_backup.id},
        )

    def test_backup_stats_include_vultr_managed_databases_and_respect_nodes(self):
        allowed_connection = factories.make_connection(
            self.account, self.member, code="vultr", name="allowed-vultr"
        )
        allowed_node = CoreNode.objects.create(
            connection=allowed_connection,
            type=CoreNode.Type.CLOUD,
            name="allowed managed database node",
            added_by=self.member,
        )
        allowed_database = CoreVultrDatabase.objects.create(
            node=allowed_node,
            name="allowed managed database",
            unique_id="allowed-db",
            engine="postgresql",
            region="ewr",
            plan="vultr-dbaas-startup",
        )

        hidden_connection = factories.make_connection(
            self.account, self.member, code="vultr", name="hidden-vultr"
        )
        hidden_node = CoreNode.objects.create(
            connection=hidden_connection,
            type=CoreNode.Type.CLOUD,
            name="hidden managed database node",
            added_by=self.member,
        )
        hidden_database = CoreVultrDatabase.objects.create(
            node=hidden_node,
            name="hidden managed database",
            unique_id="hidden-db",
            engine="postgresql",
            region="ewr",
            plan="vultr-dbaas-startup",
        )
        self.group.nodes.add(allowed_node)

        CoreVultrDatabaseBackup.objects.create(
            vultr_database=allowed_database,
            name="allowed managed backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        CoreVultrDatabaseBackup.objects.create(
            vultr_database=hidden_database,
            name="hidden managed backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        response = self.client.get("/api/v1/stats/backups/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        cloud_series = next(item for item in response.json()["series"] if item["name"] == "Cloud")
        self.assertEqual(sum(cloud_series["data"]), 1)

        list_response = self.client.get("/api/v1/clouds/vultr_database/")
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item["id"] for item in list_response.json()},
            {allowed_database.id},
        )
        self.assertEqual(
            self.client.get(
                f"/api/v1/clouds/vultr_database/{hidden_database.id}/"
            ).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        totals_response = self.client.get(
            "/api/v1/clouds/vultr_database/totals/"
        )
        self.assertEqual(totals_response.status_code, status.HTTP_200_OK)
        self.assertEqual(totals_response.json()["nodes"], 1)
        self.assertEqual(totals_response.json()["backups"], 1)

    def test_provider_lists_details_totals_and_connections_respect_visible_nodes(self):
        allowed_backup = CoreWebsiteBackup.objects.create(
            website=self.allowed_node.website,
            name="allowed provider backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        CoreWebsiteBackup.objects.create(
            website=self.hidden_node.website,
            name="hidden provider backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        list_response = self.client.get("/api/v1/websites/")
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item["id"] for item in list_response.json()},
            {self.allowed_node.website.id},
        )

        hidden_detail = self.client.get(
            f"/api/v1/websites/{self.hidden_node.website.id}/"
        )
        self.assertEqual(hidden_detail.status_code, status.HTTP_404_NOT_FOUND)

        totals_response = self.client.get("/api/v1/websites/totals/")
        self.assertEqual(totals_response.status_code, status.HTTP_200_OK)
        self.assertEqual(totals_response.json()["nodes"], 1)
        self.assertEqual(totals_response.json()["backups"], 1)
        self.assertTrue(
            CoreWebsiteBackup.objects.filter(pk=allowed_backup.pk).exists()
        )

        connections_response = self.client.get("/api/v1/websites/connections/")
        self.assertEqual(connections_response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item["id"] for item in connections_response.json()},
            {self.allowed_node.connection_id},
        )

    def test_suspended_current_membership_moves_to_active_fallback_without_old_resources(self):
        membership = self.client_member.memberships.get(account=self.account)
        membership.status = CoreMemberAccount.Status.SUSPENDED
        membership.save(update_fields=["status", "modified"])

        responses = {}
        for url in (
            "/api/v1/websites/",
            "/api/v1/websites/totals/",
            "/api/v1/websites/connections/",
            "/api/v1/accounts/",
            "/api/v1/groups/",
            "/api/v1/invites/",
            "/api/v1/logs/",
            "/api/v1/members/",
            "/api/v1/notifications-slack/",
            "/api/v1/notifications-telegram/",
            "/api/v1/notifications-email/",
        ):
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK, url)
            responses[url] = response

        active_membership = self.client_member.memberships.exclude(
            account=self.account
        ).get(status=CoreMemberAccount.Status.ACTIVE)
        membership.refresh_from_db()
        active_membership.refresh_from_db()
        self.assertFalse(membership.current)
        self.assertTrue(active_membership.current)
        self.assertEqual(responses["/api/v1/websites/"].json(), [])
        self.assertEqual(responses["/api/v1/websites/connections/"].json(), [])
        self.assertEqual(responses["/api/v1/websites/totals/"].json()["nodes"], 0)
        self.assertNotIn(
            self.account.id,
            {item["id"] for item in responses["/api/v1/accounts/"].json()},
        )

        switch_response = self.client.post(
            f"/api/v1/members/{self.client_member.id}/switch_current_account/",
            {"account_id": active_membership.account_id},
            format="json",
        )
        self.assertEqual(switch_response.status_code, status.HTTP_200_OK)

    def test_switch_current_account_rejects_suspended_destination(self):
        suspended_account, _suspended_owner, _suspended_user = factories.make_account(
            email=f"suspended-destination-{self.account.id}@example.com"
        )
        CoreMemberAccount.objects.create(
            member=self.member,
            account=suspended_account,
            status=CoreMemberAccount.Status.SUSPENDED,
            current=False,
            primary=False,
        )
        owner_client = APIClient()
        owner_client.force_authenticate(user=self.user)

        response = owner_client.post(
            f"/api/v1/members/{self.member.id}/switch_current_account/",
            {"account_id": suspended_account.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(self.member.memberships.get(account=self.account).current)
        self.assertFalse(
            self.member.memberships.get(account=suspended_account).current
        )
        accounts_response = owner_client.get("/api/v1/accounts/")
        self.assertEqual(accounts_response.status_code, status.HTTP_200_OK)
        self.assertNotIn(
            suspended_account.id,
            {item["id"] for item in accounts_response.json()},
        )

    def test_schedule_create_requires_visible_node_and_owned_storage(self):
        storage = factories.make_storage(self.account, self.member)
        foreign_account, foreign_member, _ = factories.make_account()
        foreign_storage = factories.make_storage(foreign_account, foreign_member)

        hidden_response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(self.hidden_node, [storage.id]),
            format="json",
        )
        self.assertEqual(hidden_response.status_code, status.HTTP_400_BAD_REQUEST)

        foreign_storage_response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(self.allowed_node, [foreign_storage.id]),
            format="json",
        )
        self.assertEqual(foreign_storage_response.status_code, status.HTTP_400_BAD_REQUEST)

        allowed_response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(self.allowed_node, [storage.id]),
            format="json",
        )
        self.assertEqual(allowed_response.status_code, status.HTTP_201_CREATED, allowed_response.content)

    def test_schedule_create_and_reassignment_require_permission_for_selected_node(self):
        visibility_auth_group = Group.objects.create(
            name=slugify(f"visibility-only-{self.account.id}")
        )
        visibility_group = CoreAccountGroup.objects.create(
            account=self.account,
            group=visibility_auth_group,
            name="visibility only",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        self.client_user.groups.add(visibility_auth_group)
        visibility_group.nodes.add(self.hidden_node)

        storage = factories.make_storage(self.account, self.member)
        hidden_response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(self.hidden_node, [storage.id]),
            format="json",
        )
        self.assertEqual(hidden_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("node", hidden_response.json())

        allowed_response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(self.allowed_node, [storage.id]),
            format="json",
        )
        self.assertEqual(
            allowed_response.status_code,
            status.HTTP_201_CREATED,
            allowed_response.content,
        )

        schedule_id = allowed_response.json()["id"]
        reassign_response = self.client.patch(
            f"/api/v1/schedules/{schedule_id}/",
            {"node": self.hidden_node.id},
            format="json",
        )
        self.assertEqual(reassign_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("node", reassign_response.json())
        self.assertEqual(CoreSchedule.objects.get(pk=schedule_id).node, self.allowed_node)

    def test_one_time_schedule_uses_at_datetime_and_partial_patch_is_safe(self):
        storage = factories.make_storage(self.account, self.member)
        response = self.client.post(
            "/api/v1/schedules/",
            self._schedule_payload(
                self.allowed_node, [storage.id], CoreSchedule.Type.ONETIME
            ),
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        schedule_id = response.json()["id"]

        patch_response = self.client.patch(
            f"/api/v1/schedules/{schedule_id}/",
            {"name": "renamed one-time schedule"},
            format="json",
        )
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK, patch_response.content)
        self.assertEqual(patch_response.json()["name"], "renamed one-time schedule")

    def test_member_switch_is_self_only_and_membership_id_editor_path_remains_supported(self):
        other_account, other_member, _other_user = factories.make_account(
            email=f"other-{self.account.id}@example.com"
        )
        other_membership = CoreMemberAccount.objects.create(
            member=other_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )

        owner_client = APIClient()
        owner_client.force_authenticate(user=self.user)

        switch_response = owner_client.post(
            f"/api/v1/members/{other_member.id}/switch_current_account/",
            {"account_id": self.account.id},
            format="json",
        )
        self.assertEqual(switch_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(other_member.memberships.get(account=other_account).current)
        self.assertFalse(other_membership.current)

        update_response = owner_client.post(
            f"/api/v1/members/{other_membership.id}/update_membership/",
            {"groups": []},
            format="json",
        )
        self.assertEqual(update_response.status_code, status.HTTP_200_OK, update_response.content)
        self.assertEqual(update_response.json()["member_id"], other_member.id)

        web_client = Client()
        web_client.force_login(self.user)
        page = web_client.get("/console/settings/users/")
        self.assertEqual(page.status_code, status.HTTP_200_OK)
        self.assertContains(page, f"editMembership('{other_member.id}')")
