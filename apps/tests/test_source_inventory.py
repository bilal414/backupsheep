import csv
import io

from django.contrib.auth.models import Group, Permission
from django.test import Client
from django.utils.text import slugify

from apps.console.account.models import CoreAccountGroup
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.connection.models import CoreConnection
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class SourceInventoryTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_inventory_uses_honest_scope_schedule_and_operation_language(self):
        scheduled = factories.make_website_node(self.account, self.member)
        scheduled.name = "Finance PostgreSQL"
        scheduled.save(update_fields=["name"])
        factories.make_schedule(scheduled, self.member)
        completed = CoreWebsiteBackup.objects.create(
            website=scheduled.website,
            name="completed copy",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.SCHEDULED,
        )
        latest = CoreWebsiteBackup.objects.create(
            website=scheduled.website,
            name="newer failed run",
            status=UtilBackup.Status.MAX_RETRY_FAILED,
            type=UtilBackup.Type.SCHEDULED,
        )

        unscheduled = factories.make_website_node(self.account, self.member)
        unscheduled.name = "Public website"
        unscheduled.save(update_fields=["name"])
        CoreWebsiteBackup.objects.create(
            website=unscheduled.website,
            name="partial run",
            status=UtilBackup.Status.PARTIAL,
            type=UtilBackup.Type.SCHEDULED,
        )

        response = self.client.get("/console/nodes/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["summary"]["total"], 2)
        self.assertEqual(response.context["summary"]["scheduled"], 1)
        self.assertEqual(response.context["summary"]["unscheduled"], 1)
        rows = {node.name: node for node in response.context["page"].object_list}
        self.assertEqual(rows[scheduled.name].latest_operation, latest)
        self.assertEqual(
            rows[scheduled.name].last_complete_started_at, completed.created
        )
        self.assertEqual(
            rows[unscheduled.name].latest_operation.status,
            UtilBackup.Status.PARTIAL,
        )
        self.assertIsNone(rows[unscheduled.name].last_complete_started_at)
        self.assertContains(response, "Sources in scope")
        self.assertContains(response, "No completed run")
        self.assertContains(
            response,
            "Schedule coverage and operation records are observed facts; they do not establish recovery readiness.",
        )
        self.assertNotContains(response, "Protected sources")
        self.assertNotContains(response, "with off-site backups")

    def test_filters_are_shareable_bounded_and_preserve_zero_results(self):
        scheduled = factories.make_website_node(self.account, self.member)
        scheduled.name = "Scheduled source"
        scheduled.save(update_fields=["name"])
        factories.make_schedule(scheduled, self.member)
        missing = factories.make_website_node(self.account, self.member)
        missing.name = "Missing schedule"
        missing.save(update_fields=["name"])

        response = self.client.get(
            "/console/nodes/",
            {
                "q": "Missing",
                "type": "website",
                "schedule": "missing",
                "sort": "name",
                "p_size": "10",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["filtered_count"], 1)
        self.assertEqual(
            [node.id for node in response.context["page"].object_list],
            [missing.id],
        )
        self.assertIn("schedule=missing", response.context["pagination_query"])
        self.assertIn("type=website", response.context["export_query"])

        invalid = self.client.get(
            "/console/nodes/",
            {
                "p_no": "not-a-page",
                "p_size": "999999",
                "type": "unknown",
                "status": "unknown",
                "schedule": "unknown",
                "owner": "unknown",
                "sort": "unknown",
            },
        )
        self.assertEqual(invalid.status_code, 200)
        self.assertEqual(invalid.context["page"].paginator.per_page, 10)
        self.assertEqual(invalid.context["page"].number, 1)

    def test_export_contains_only_the_current_filtered_inventory(self):
        included = factories.make_website_node(self.account, self.member)
        included.name = "Include in export"
        included.save(update_fields=["name"])
        factories.make_schedule(included, self.member)
        excluded = factories.make_website_node(self.account, self.member)
        excluded.name = "Exclude from export"
        excluded.save(update_fields=["name"])

        response = self.client.get(
            "/console/nodes/",
            {"q": "Include", "schedule": "active", "export": "csv"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertEqual(
            response["Content-Disposition"],
            'attachment; filename="backupsheep-sources.csv"',
        )
        content = b"".join(response.streaming_content).decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(content)))
        self.assertEqual([row["Source name"] for row in rows], [included.name])
        self.assertEqual(rows[0]["Active schedules"], "1")

    def test_export_neutralizes_spreadsheet_formula_prefixes(self):
        node = factories.make_website_node(self.account, self.member)
        node.name = "=2+2"
        node.save(update_fields=["name"])
        node.connection.name = "+unsafe connection"
        node.connection.save(update_fields=["name"])
        node.connection.location.location = "@unsafe endpoint"
        node.connection.location.save(update_fields=["location"])
        self.user.email = "-unsafe-owner@example.com"
        self.user.save(update_fields=["email"])

        response = self.client.get("/console/nodes/?export=csv")

        content = b"".join(response.streaming_content).decode("utf-8")
        row = next(csv.DictReader(io.StringIO(content)))
        self.assertEqual(row["Source name"], "'=2+2")
        self.assertEqual(row["Connection"], "'+unsafe connection")
        self.assertEqual(row["Endpoint"], "'@unsafe endpoint")
        self.assertEqual(row["Added by"], "'-unsafe-owner@example.com")

    def test_in_progress_source_is_not_a_review_state_and_connection_tone_is_separate(self):
        node = factories.make_website_node(self.account, self.member)
        node.name = "In progress source"
        node.status = CoreNode.Status.BACKUP_IN_PROGRESS
        node.save(update_fields=["name", "status"])

        response = self.client.get("/console/nodes/")

        row = response.context["page"].object_list[0]
        self.assertEqual(response.context["summary"]["state_review"], 0)
        self.assertEqual(row.source_state_tone, "active")
        self.assertEqual(row.connection_state_tone, "available")
        self.assertFalse(row.can_request_operation)
        self.assertNotContains(response, f"Run backup for {node.name}")

        node.connection.status = CoreConnection.Status.SUSPENDED
        node.connection.save(update_fields=["status"])
        response = self.client.get("/console/nodes/")
        row = response.context["page"].object_list[0]
        self.assertEqual(response.context["summary"]["state_review"], 1)
        self.assertEqual(row.source_state_tone, "active")
        self.assertEqual(row.connection_state_tone, "incident")


class RestrictedSourceInventoryTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        auth_group = Group.objects.create(
            name=slugify(f"source-inventory-scope-{self.account.id}")
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Assigned sources",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )

        _owned_account, self.restricted_member, self.restricted_user = (
            factories.make_account(
                email=f"source-inventory-{self.account.id}@example.com"
            )
        )
        self.restricted_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.restricted_user.groups.add(auth_group)

        self.allowed = factories.make_website_node(self.account, self.member)
        self.allowed.name = "Visible assigned source"
        self.allowed.save(update_fields=["name"])
        self.hidden = factories.make_website_node(self.account, self.member)
        self.hidden.name = "Hidden account source"
        self.hidden.save(update_fields=["name"])
        self.group.nodes.add(self.allowed)

        self.client = Client()
        self.client.force_login(self.restricted_user)

    def test_list_counts_export_and_detail_follow_assigned_scope(self):
        response = self.client.get("/console/nodes/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["summary"]["total"], 1)
        self.assertContains(response, self.allowed.name)
        self.assertNotContains(response, self.hidden.name)
        self.assertFalse(response.context["can_run_backups"])
        self.assertNotContains(response, "Run backup for")

        export = self.client.get("/console/nodes/?export=csv")
        export_content = b"".join(export.streaming_content).decode("utf-8")
        self.assertIn(self.allowed.name, export_content)
        self.assertNotIn(self.hidden.name, export_content)

        hidden_detail = self.client.get(f"/console/nodes/{self.hidden.id}/")
        self.assertEqual(hidden_detail.status_code, 404)
        allowed_detail = self.client.get(f"/console/nodes/{self.allowed.id}/")
        self.assertEqual(allowed_detail.status_code, 200)

    def test_backup_action_is_shown_only_with_account_group_permission(self):
        denied = self.client.get("/console/nodes/")
        self.assertFalse(denied.context["can_run_backups"])

        self.group.group.permissions.add(
            Permission.objects.get(codename="backup_create")
        )
        self.restricted_user = type(self.restricted_user).objects.get(
            pk=self.restricted_user.pk
        )
        self.client.force_login(self.restricted_user)

        allowed = self.client.get("/console/nodes/")
        self.assertTrue(allowed.context["can_run_backups"])
        self.assertContains(allowed, f"Run backup for {self.allowed.name}")

    def test_permission_from_one_group_does_not_authorize_another_groups_node(self):
        permitted_node = factories.make_website_node(self.account, self.member)
        permitted_node.name = "Permission-scoped source"
        permitted_node.save(update_fields=["name"])
        auth_group = Group.objects.create(
            name=slugify(f"source-operation-scope-{self.account.id}")
        )
        permitted_group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Can run backups",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        permitted_group.nodes.add(permitted_node)
        auth_group.permissions.add(Permission.objects.get(codename="backup_create"))
        self.restricted_user.groups.add(auth_group)
        self.restricted_user = type(self.restricted_user).objects.get(
            pk=self.restricted_user.pk
        )
        self.client.force_login(self.restricted_user)

        response = self.client.get("/console/nodes/")

        self.assertNotContains(response, f"Run backup for {self.allowed.name}")
        self.assertContains(response, f"Run backup for {permitted_node.name}")
        denied = self.client.post(
            f"/api/v1/nodes/{self.allowed.id}/take_snapshot/",
            data={"storage_point_ids": [999999]},
            content_type="application/json",
        )
        self.assertEqual(denied.status_code, 403)

    def test_cross_account_source_detail_is_not_reachable(self):
        other_account, other_member, _other_user = factories.make_account()
        other_node = factories.make_website_node(other_account, other_member)

        response = self.client.get(f"/console/nodes/{other_node.id}/")

        self.assertEqual(response.status_code, 404)
