"""Enterprise UI contracts for provider onboarding and connection operations.

These tests deliberately keep provider access, source coverage, and recovery proof
as separate concepts.  Most of the modal checks are source-level contracts because
the forms are rendered once and then populated by Alpine at runtime.
"""

import re
import shutil
import subprocess
from pathlib import Path

from django.contrib.auth.models import Group, Permission
from django.template.loader import get_template
from django.test import Client, SimpleTestCase
from django.urls import reverse
from django.utils.text import slugify

from apps.console.account.models import CoreAccountGroup
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode
from apps.tests import factories
from apps.tests.base import BaseTestCase


class IntegrationEnterpriseTemplateContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        template_dir = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "setup"
        )
        cls.catalog = (template_dir / "1_integration_select.html").read_text(
            encoding="utf-8"
        )
        cls.open_page = (template_dir / "2_integration_open.html").read_text(
            encoding="utf-8"
        )
        cls.register = (
            template_dir / "_setup_and_list_connection.html"
        ).read_text(encoding="utf-8")

    def test_enterprise_integration_templates_compile(self):
        for template_name in (
            "console/setup/1_integration_select.html",
            "console/setup/2_integration_open.html",
            "console/setup/_setup_and_list_connection.html",
        ):
            with self.subTest(template=template_name):
                get_template(template_name)

    def test_connection_controller_is_valid_javascript(self):
        if shutil.which("node") is None:
            self.skipTest(
                "Node.js is intentionally absent from the production runtime; "
                "the dependency-and-deployment CI job performs this syntax check."
            )
        script = self.register.split("<script>", 1)[1].split("</script>", 1)[0]
        completed = subprocess.run(
            ["node", "--check"],
            input=script,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_catalog_separates_provider_access_from_recovery_evidence(self):
        self.assertIn(
            "A connected account proves provider access only.", self.catalog
        )
        self.assertIn(
            "Recovery assurance is established by completed backup and restore evidence.",
            self.catalog,
        )
        self.assertNotIn("recover your data in minutes", self.catalog.lower())
        self.assertIn(
            "Connection state records whether BackupSheep may initiate work. It "
            "does not, by itself, prove a successful backup or restore.",
            self.open_page,
        )
        self.assertIn("Operational eligibility, not recovery proof.", self.register)
        self.assertIn(
            "Provider credentials and account access were validated. No backup or "
            "recovery was tested.",
            self.register,
        )
        self.assertNotIn("good for backups", self.register.lower())

    def test_catalog_exposes_supported_aws_rds_and_secure_file_transports(self):
        self.assertIn(
            "{% url 'console:setup:integration_open' 'aws_rds' %}", self.catalog
        )
        self.assertIn("Amazon RDS", self.catalog)
        self.assertIn("data-search=\"ftp ftps tls", self.catalog)
        self.assertIn("FTP / FTPS", self.catalog)
        self.assertIn("FTPS is preferred.", self.catalog)
        self.assertIn(
            "Plain FTP is available only when installation policy explicitly "
            "allows insecure transport.",
            self.catalog,
        )

    def test_catalog_provider_marks_and_region_dialog_are_accessible(self):
        self.assertNotRegex(self.catalog, r'<img\b[^>]*\balt="[^"]+"')
        self.assertIn('@keydown.tab="trapOVHDialog($event)"', self.catalog)
        self.assertIn("trapOVHDialog(event) {", self.catalog)
        self.assertIn(
            '@keydown.escape.window="if (openOVH) closeOVHModal()"',
            self.catalog,
        )

    def test_browser_never_uses_visible_text_inputs_for_provider_secrets(self):
        for binding in (
            "selectedAuth.api_key",
            "selectedAuth.api_token",
            "selectedAuth.secret_key",
            "selectedAuth.password",
        ):
            with self.subTest(binding=binding):
                tag = re.search(
                    rf'<input\b(?=[^>]*\bx-model="{re.escape(binding)}")[^>]*>',
                    self.register,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(tag, f"missing credential input for {binding}")
                self.assertIn('type="password"', tag.group(0))
                self.assertIn('autocomplete="new-password"', tag.group(0))

    def test_edit_dialog_explains_blank_secret_preservation(self):
        self.assertIn(
            "Existing secret values are never returned to this browser.",
            self.register,
        )
        self.assertIn(
            "Leave secret fields blank to keep the current credential; enter a "
            "value only when rotating it.",
            self.register,
        )
        for configured_witness in (
            "api_key_configured",
            "secret_key_configured",
            "password_configured",
            "private_key_configured",
            "service_key_configured",
        ):
            with self.subTest(witness=configured_witness):
                self.assertIn(configured_witness, self.register)

    def test_connection_delete_is_a_preflight_not_a_row_level_mutation(self):
        register_before_modal = self.register.split(
            "<!-- Delete connection modal -->", 1
        )[0]
        self.assertRegex(
            register_before_modal,
            r"openDeleteConnectionModal\([^\n]+connection\.total_nodes_count",
        )
        self.assertNotIn('@click="deleteConnection(', register_before_modal)
        self.assertRegex(
            self.register,
            r"openDeleteConnectionModal\(connectionID,\s*connectionName,\s*"
            r"(?:connectionNodeCount|nodeCount)(?:\s*=\s*0)?\)",
        )
        self.assertIn("connectionNodeCount: 0", self.register)
        self.assertIn("Deletion blocked", self.register)
        self.assertIn("attached source", self.register)
        self.assertIn(
            "provider resources and provider-native snapshots are not deleted",
            self.register.lower(),
        )
        self.assertRegex(
            self.register,
            r'<button(?=[^>]*@click="deleteConnection\(connection\.id\)")'
            r'(?=[^>]*(?:x-show|:disabled)="[^"]*connectionNodeCount[^"]*")[^>]*>',
        )

    def test_modal_escape_and_timeout_contracts_fail_safe(self):
        self.assertIn(
            '@keydown.escape.window="if (openConnection && !loading) '
            'closeConnectionModal()"',
            self.register,
        )
        self.assertIn(
            '@keydown.escape.window="if (openDeleteConnection && !loading) '
            'closeDeleteConnectionModal()"',
            self.register,
        )
        delete_modal = self.register.split(
            "<!-- Delete connection modal -->", 1
        )[1].split("<script>", 1)[0]
        self.assertNotIn(
            'class="fixed inset-0 bg-ink-950/55" @click=',
            delete_modal,
        )
        self.assertIn("REQUEST_OUTCOME_UNKNOWN", self.register)
        self.assertIn("Outcome not confirmed", self.register)
        self.assertIn("if (!readOnlyRequest)", self.register)
        self.assertIn(
            "failure = this.defaultConnectionFailure('REQUEST_OUTCOME_UNKNOWN')",
            self.register,
        )
        self.assertIn("The operation may have completed.", self.register)

    def test_listbox_escape_does_not_close_the_parent_dialog(self):
        for property_name in (
            "openEndpoint",
            "openAWSRegion",
            "openDatabaseType",
            "openDatabaseVersion",
            "openProtocol",
        ):
            with self.subTest(property_name=property_name):
                self.assertIn(
                    f'@keydown.escape="if ({property_name}) '
                    f'{{ $event.preventDefault(); $event.stopPropagation(); '
                    f'{property_name} = false; }}"',
                    self.register,
                )

    def test_listbox_keyboard_opening_and_initial_navigation_are_deterministic(self):
        self.assertIn(
            "commitListbox(indexProperty, items, openProperty, callback)",
            self.register,
        )
        self.assertIn("if (!this[openProperty])", self.register)
        self.assertIn(
            "this[indexProperty] = delta < 0 ? items.length - 1 : 0;",
            self.register,
        )

    def test_connection_dialog_has_mode_specific_actions_and_focus_restoration(self):
        self.assertIn('x-text="connectionDialogTitle()"', self.register)
        self.assertIn('x-text="connectionDialogDescription()"', self.register)
        self.assertIn('x-text="connectionSubmitLabel()"', self.register)
        for method in (
            "connectionDialogTitle",
            "connectionDialogDescription",
            "connectionSubmitLabel",
        ):
            with self.subTest(method=method):
                self.assertRegex(self.register, rf"{method}\(\)\s*\{{")
        self.assertRegex(self.register, r"modalMode:\s*['\"]create['\"]")
        self.assertIn("lastFocusedElement: null", self.register)
        self.assertIn("this.lastFocusedElement = document.activeElement", self.register)
        self.assertIn(
            "this.focusDialog(this.$refs.connectionDialog, "
            "this.$refs.connectionName)",
            self.register,
        )
        self.assertIn("const trigger = this.lastFocusedElement", self.register)
        self.assertIn("trigger.focus()", self.register)

    def test_clipboard_confirmation_never_repeats_the_copied_value(self):
        copy_block = self.register.split("copyToClipboard(string) {", 1)[1].split(
            "awsRDSReplicaWarning()", 1
        )[0]
        self.assertNotIn("details: string", copy_block)
        self.assertIn("Value copied to clipboard.", copy_block)


class IntegrationEnterpriseViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_connection_register_pagination_is_bounded_and_forgiving(self):
        factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Bounded provider account",
        )
        url = reverse(
            "console:setup:integration_open",
            kwargs={"integration_code": "digitalocean"},
        )

        invalid = self.client.get(
            url,
            {"p_no": "not-a-page", "p_size": "999999"},
        )

        self.assertEqual(invalid.status_code, 200)
        self.assertEqual(invalid.context["page"].number, 1)
        self.assertEqual(invalid.context["page"].paginator.per_page, 10)
        self.assertEqual(tuple(invalid.context["page_sizes"]), (10, 25, 50))

        accepted = self.client.get(url, {"p_no": "1", "p_size": "25"})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.context["page"].paginator.per_page, 25)

    def test_catalog_and_register_each_render_one_document_heading(self):
        catalog = self.client.get(reverse("console:setup:integration_select"))
        register = self.client.get(
            reverse(
                "console:setup:integration_open",
                kwargs={"integration_code": "digitalocean"},
            )
        )

        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(register.status_code, 200)
        self.assertEqual(catalog.content.decode().count("<h1"), 1)
        self.assertEqual(register.content.decode().count("<h1"), 1)

    def test_connection_summary_counts_accounts_and_sources_separately(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Two-source provider account",
        )
        for index in range(2):
            CoreNode.objects.create(
                connection=connection,
                type=CoreNode.Type.CLOUD,
                name=f"Cloud source {index}",
                added_by=self.member,
            )

        response = self.client.get(
            reverse(
                "console:setup:integration_open",
                kwargs={"integration_code": "digitalocean"},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["connections_count"], 1)
        self.assertEqual(response.context["connection_summary"]["active"], 1)
        self.assertEqual(
            response.context["connection_summary"]["protected_sources"], 2
        )
        self.assertContains(response, "Sources attached")
        self.assertContains(response, "Operational eligibility, not recovery proof.")


class RestrictedIntegrationEnterpriseViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        auth_group = Group.objects.create(
            name=slugify(f"integration-register-scope-{self.account.id}")
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Assigned integration sources",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )

        _owned_account, self.restricted_member, self.restricted_user = (
            factories.make_account(
                email=f"integration-register-{self.account.id}@example.com"
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

        self.visible_connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Visible provider account",
        )
        visible_node = CoreNode.objects.create(
            connection=self.visible_connection,
            type=CoreNode.Type.CLOUD,
            name="Visible assigned source",
            added_by=self.member,
        )
        self.hidden_connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Hidden provider account",
        )
        CoreNode.objects.create(
            connection=self.hidden_connection,
            type=CoreNode.Type.CLOUD,
            name="Hidden account source",
            added_by=self.member,
        )
        self.empty_connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Unassigned empty provider account",
        )
        self.group.nodes.add(visible_node)

        self.client = Client()
        self.client.force_login(self.restricted_user)

    def test_catalog_and_register_follow_visible_source_scope(self):
        catalog = self.client.get(reverse("console:setup:integration_select"))

        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(catalog.context["connected_account_count"], 1)
        self.assertEqual(catalog.context["active_connection_count"], 1)
        self.assertEqual(catalog.context["protected_source_count"], 1)
        self.assertIsNone(catalog.context["connected_storage_count"])
        self.assertFalse(catalog.context["can_manage_integrations"])

        register = self.client.get(
            reverse(
                "console:setup:integration_open",
                kwargs={"integration_code": "digitalocean"},
            )
        )

        self.assertEqual(register.status_code, 200)
        self.assertEqual(register.context["connections_count"], 1)
        self.assertEqual(
            [item.id for item in register.context["page"].object_list],
            [self.visible_connection.id],
        )
        self.assertFalse(register.context["can_manage_integrations"])
        self.assertFalse(register.context["can_create_sources"])
        self.assertContains(register, self.visible_connection.name)
        self.assertNotContains(register, self.hidden_connection.name)
        self.assertNotContains(register, self.empty_connection.name)
        self.assertNotContains(register, "Request deletion")

    def test_account_wide_manager_sees_authoritative_attachment_counts(self):
        permission = Permission.objects.get(
            content_type__app_label=CoreAccountGroup._meta.app_label,
            content_type__model=CoreAccountGroup._meta.model_name,
            codename="integration_changes",
        )
        self.group.group.permissions.add(permission)

        register = self.client.get(
            reverse(
                "console:setup:integration_open",
                kwargs={"integration_code": "digitalocean"},
            )
        )

        self.assertEqual(register.status_code, 200)
        self.assertTrue(register.context["can_manage_integrations"])
        self.assertEqual(register.context["connection_summary"]["protected_sources"], 2)
        counts = {
            connection.id: connection.total_nodes_count
            for connection in register.context["page"].object_list
        }
        self.assertEqual(counts[self.visible_connection.id], 1)
        self.assertEqual(counts[self.hidden_connection.id], 1)
        self.assertEqual(counts[self.empty_connection.id], 0)
