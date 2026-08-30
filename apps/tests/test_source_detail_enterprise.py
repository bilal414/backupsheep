from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.template.loader import get_template
from django.test import Client, SimpleTestCase, override_settings
from django.utils.text import slugify

from apps.console.account.models import CoreAccountGroup
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode, CoreSchedule, CoreWordPress
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class _RenderedIdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        for name, value in attrs:
            if name == "id" and value:
                self.ids.append(value)


def _duplicate_rendered_ids(response):
    collector = _RenderedIdCollector()
    collector.feed(response.content.decode(response.charset or "utf-8"))
    return sorted(
        value for value, count in Counter(collector.ids).items() if count > 1
    )


class SourceConfigurationTemplateContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.template_path = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "setup"
            / "_setup_website_node.html"
        )
        cls.source = cls.template_path.read_text(encoding="utf-8")

    def test_source_configuration_template_compiles(self):
        get_template("console/setup/_setup_website_node.html")

    def test_update_mode_and_record_identifier_are_server_derived(self):
        self.assertIn(
            "isUpdateMode: {% if node.id %}true{% else %}false{% endif %}",
            self.source,
        )
        self.assertIn(
            "websiteRecordId: {% if node.website.id %}",
            self.source,
        )
        self.assertIn(
            'const method = this.isUpdateMode ? "PATCH" : "POST";',
            self.source,
        )
        self.assertIn(
            'encodeURIComponent(this.websiteRecordId) + "/"',
            self.source,
        )
        self.assertNotIn("if (this.website.id)", self.source)
        self.assertNotIn("this.website.id ?", self.source)

    def test_failed_load_keeps_editor_closed_and_offers_retry(self):
        self.assertIn(
            'x-show="isUpdateMode && sourceLoadFailed"',
            self.source,
        )
        self.assertIn(
            'x-show="!isUpdateMode || sourceLoaded"',
            self.source,
        )
        self.assertIn(
            "Source configuration could not be loaded",
            self.source,
        )
        self.assertIn("Saving remains disabled", self.source)
        self.assertIn("async retrySourceLoad()", self.source)
        self.assertIn("const loaded = await this.getWebsite();", self.source)
        self.assertIn("if (!loaded) return;", self.source)

    def test_saving_is_locked_against_stale_state_and_double_submission(self):
        self.assertIn(
            ':disabled="loading || saving || (isUpdateMode && !sourceLoaded)"',
            self.source,
        )
        self.assertIn(':aria-busy="saving"', self.source)
        self.assertIn("if (this.saving || this.loading) return;", self.source)
        self.assertIn(
            "if (this.isUpdateMode && (!this.sourceLoaded || !this.websiteRecordId))",
            self.source,
        )
        self.assertIn("this.saving = true;", self.source)
        self.assertIn("this.saving = false;", self.source)

    def test_parallel_control_and_file_navigation_use_native_semantics(self):
        self.assertIn(
            '<select x-model.number="website.parallel" id="parallel"',
            self.source,
        )
        self.assertNotIn('role="listbox"', self.source)
        self.assertNotIn("listbox-option", self.source)
        self.assertNotIn("toggleParallelDropdown", self.source)
        self.assertNotIn("parallelActiveIndex", self.source)
        self.assertNotRegex(
            self.source,
            r'<a\b[^>]*@click="getObjects\(',
        )
        self.assertIn(
            '<button type="button" @click="getObjects(path.path)"',
            self.source,
        )
        self.assertIn(
            'x-show="object.type===\'file\'" x-text="object.name"></span>',
            self.source,
        )


class SourceDetailEnterpriseTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)
        self.node = factories.make_website_node(self.account, self.member)

    def test_recovery_ledger_keeps_operation_and_proof_axes_separate(self):
        factories.make_schedule(self.node, self.member)
        factories.make_schedule(
            self.node,
            self.member,
            status=CoreSchedule.Status.PAUSED,
        )
        complete = CoreWebsiteBackup.objects.create(
            website=self.node.website,
            name="completed recovery point",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.SCHEDULED,
        )
        latest = CoreWebsiteBackup.objects.create(
            website=self.node.website,
            name="newer failed operation",
            status=UtilBackup.Status.MAX_RETRY_FAILED,
            type=UtilBackup.Type.SCHEDULED,
        )

        active_storage = factories.make_storage(self.account, self.member)
        paused_storage = factories.make_storage(
            self.account,
            self.member,
            bucket="paused-bucket",
        )
        paused_storage.status = CoreStorage.Status.PAUSED
        paused_storage.save(update_fields=["status"])

        response = self.client.get(
            f"/console/nodes/{self.node.id}/",
            {"p_no": "not-a-page", "p_size": "999999"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["page"].number, 1)
        self.assertEqual(response.context["page"].paginator.per_page, 10)
        self.assertEqual(response.context["latest_operation"], latest)
        self.assertEqual(response.context["last_complete_backup"], complete)
        self.assertEqual(response.context["schedule_count"], 2)
        self.assertEqual(response.context["active_schedule_count"], 1)
        self.assertEqual(
            list(response.context["storage_list"]),
            [active_storage],
        )
        self.assertTrue(response.context["can_manage_source"])
        self.assertTrue(response.context["can_manage_schedules"])
        self.assertTrue(response.context["can_run_backups"])
        self.assertTrue(response.context["can_restore_backups"])
        self.assertTrue(response.context["can_validate_storage"])
        self.assertContains(response, "Recovery ledger")
        self.assertContains(response, "No isolated recovery evidence")
        self.assertContains(
            response,
            "A completed backup is not presented as proof of a successful recovery.",
        )
        self.assertContains(
            response,
            "Provider credentials and account access were validated. No backup or recovery was tested.",
        )
        self.assertNotContains(
            response,
            "Validation passed. Integration is good for backups.",
        )
        self.assertContains(response, "Latest operation needs review")
        self.assertTrue(response.context["content_owns_h1"])
        self.assertEqual(
            response.content.decode(response.charset or "utf-8").lower().count("<h1"),
            1,
        )
        self.assertEqual(_duplicate_rendered_ids(response), [])

    def test_source_validation_reports_reachability_without_recovery_claims(self):
        with mock.patch.object(CoreNode, "validate", return_value=True):
            reachable = self.client.post(
                f"/api/v1/nodes/{self.node.id}/validate/",
                content_type="application/json",
            )

        self.assertEqual(reachable.status_code, 200, reachable.content)
        self.assertEqual(
            reachable.json()["detail"],
            "The provider source is currently reachable and active. No backup or recovery was tested.",
        )
        self.assertNotIn("good for backups", reachable.content.decode().lower())

        with mock.patch.object(CoreNode, "validate", return_value=False):
            unavailable = self.client.post(
                f"/api/v1/nodes/{self.node.id}/validate/",
                content_type="application/json",
            )

        self.assertEqual(unavailable.status_code, 400, unavailable.content)
        self.assertIn("could not be confirmed", unavailable.json()["detail"])
        self.assertNotIn("backups will fail", unavailable.content.decode().lower())

    @override_settings(
        BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=True,
        BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="bse1",
        BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=False,
        WORDPRESS_INTEGRATION_ENABLED=True,
    )
    def test_recovery_incomplete_source_has_no_dead_schedule_editor(self):
        connection = factories.make_connection(
            self.account, self.member, code="wordpress"
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.SAAS,
            name="legacy-wordpress",
            added_by=self.member,
        )
        CoreWordPress.objects.create(node=node, name="Legacy WordPress")
        schedule = factories.make_schedule(node, self.member)

        response = self.client.get(f"/console/nodes/{node.id}/")
        source = response.content.decode(response.charset or "utf-8")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(f"openScheduleModal('{schedule.id}')", source)
        self.assertNotContains(response, "Create protection policy")
        self.assertIn(f"pauseSchedule('{schedule.id}')", source)
        self.assertIn(f"openScheduleDeleteModal('{schedule.id}'", source)


class SourceConfigurationEnterpriseTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)
        self.node = factories.make_website_node(self.account, self.member)

    def test_file_discovery_is_explicit_and_save_action_is_singular(self):
        response = self.client.get(
            f"/console/integration/website/{self.node.connection_id}/objects/"
            f"{self.node.id}/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Source display name")
        self.assertContains(response, "Load source files")
        self.assertContains(response, "live, read-only discovery request")
        self.assertEqual(
            response.content.decode(response.charset or "utf-8").count(
                "Save source configuration"
            ),
            1,
        )
        source = response.content.decode(response.charset or "utf-8")
        init_source = source.split("async init()", 1)[1].split(
            "filteredObjects()", 1
        )[0]
        self.assertIn("await this.getWebsite()", init_source)
        self.assertNotIn("getObjects()", init_source)
        self.assertEqual(_duplicate_rendered_ids(response), [])


class RestrictedSourceDetailEnterpriseTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        auth_group = Group.objects.create(
            name=slugify(f"source-detail-scope-{self.account.id}")
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Source readers",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )

        _owned_account, self.restricted_member, self.restricted_user = (
            factories.make_account(
                email=f"source-detail-{self.account.id}@example.com"
            )
        )
        self.restricted_member.memberships.filter(current=True).update(
            current=False
        )
        CoreMemberAccount.objects.create(
            member=self.restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.restricted_user.groups.add(auth_group)

        self.visible = factories.make_website_node(self.account, self.member)
        self.hidden = factories.make_website_node(self.account, self.member)
        self.group.nodes.add(self.visible)
        factories.make_storage(self.account, self.member)

        self.client = Client()
        self.client.force_login(self.restricted_user)

    def _modify_url(self, node):
        return (
            f"/console/integration/website/{node.connection_id}/objects/"
            f"{node.id}/"
        )

    def test_read_only_member_sees_evidence_without_operational_controls(self):
        response = self.client.get(f"/console/nodes/{self.visible.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["can_manage_source"])
        self.assertFalse(response.context["can_manage_schedules"])
        self.assertFalse(response.context["can_run_backups"])
        self.assertFalse(response.context["can_restore_backups"])
        self.assertFalse(response.context["can_download_backups"])
        self.assertFalse(response.context["can_delete_backups"])
        self.assertFalse(response.context["can_validate_storage"])
        self.assertEqual(list(response.context["storage_list"]), [])
        self.assertContains(response, "Recovery ledger")
        self.assertNotContains(response, ">Run backup<")
        self.assertNotContains(response, ">Configure source<")
        self.assertNotContains(response, ">Create protection policy<")

    def test_restore_is_a_distinct_node_scoped_capability(self):
        CoreWebsiteBackup.objects.create(
            website=self.visible.website,
            name="scoped recovery point",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )

        self.group.group.permissions.add(
            Permission.objects.get(codename="backup_create")
        )
        backup_only = self.client.get(f"/console/nodes/{self.visible.id}/")

        self.assertEqual(backup_only.status_code, 200)
        self.assertTrue(backup_only.context["can_run_backups"])
        self.assertFalse(backup_only.context["can_restore_backups"])
        self.assertNotContains(backup_only, '@click="openBackupRestoreModal')

        self.group.group.permissions.remove(
            Permission.objects.get(codename="backup_create")
        )
        self.group.group.permissions.add(
            Permission.objects.get(codename="backup_restore")
        )
        restore_only = self.client.get(f"/console/nodes/{self.visible.id}/")

        self.assertEqual(restore_only.status_code, 200)
        self.assertFalse(restore_only.context["can_run_backups"])
        self.assertTrue(restore_only.context["can_restore_backups"])
        self.assertContains(restore_only, '@click="openBackupRestoreModal')
        self.assertNotContains(restore_only, '@click="openBackupModal()"')
        self.assertEqual(len(restore_only.context["storage_list"]), 1)

    def test_modify_route_intersects_visibility_and_node_permission(self):
        denied = self.client.get(self._modify_url(self.visible))
        hidden = self.client.get(self._modify_url(self.hidden))

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(hidden.status_code, 404)

        self.group.group.permissions.add(
            Permission.objects.get(codename="node_changes")
        )
        self.restricted_user = type(self.restricted_user).objects.get(
            pk=self.restricted_user.pk
        )
        self.client.force_login(self.restricted_user)

        allowed = self.client.get(self._modify_url(self.visible))

        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.context["active_url"], "nodes")
        self.assertFalse(allowed.context["can_browse_source"])
        self.assertContains(allowed, "Source configuration")
        self.assertContains(allowed, "cannot browse remote server contents")
        self.assertNotContains(allowed, '@click="getObjects(object.path)"')
        self.assertEqual(_duplicate_rendered_ids(allowed), [])

    def test_schedule_manager_without_storage_permission_has_no_validate_action(self):
        self.group.group.permissions.add(
            Permission.objects.get(codename="schedule_changes")
        )
        self.restricted_user = type(self.restricted_user).objects.get(
            pk=self.restricted_user.pk
        )
        self.client.force_login(self.restricted_user)

        response = self.client.get(f"/console/nodes/{self.visible.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["can_manage_schedules"])
        self.assertFalse(response.context["can_validate_storage"])
        self.assertNotContains(
            response,
            '@click.prevent="validateStorage(',
        )
