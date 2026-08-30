import shutil
import subprocess
from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase
from django.urls import reverse

from apps.console.connection.models import CoreIntegration
from apps.tests import factories
from apps.tests.base import BaseTestCase


REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_TEMPLATE_DIR = (
    REPO_ROOT / "apps" / "console" / "_templates" / "console" / "setup"
)
PAGE_TEMPLATE = SETUP_TEMPLATE_DIR / "3_integration_create_node.html"
DISCOVERY_TEMPLATE = SETUP_TEMPLATE_DIR / "_setup_cloud_node.html"
DISCOVERY_STYLES = (
    REPO_ROOT
    / "apps"
    / "console"
    / "_static"
    / "console"
    / "css"
    / "source_discovery.css"
)


class SourceDiscoveryTemplateContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.page = PAGE_TEMPLATE.read_text(encoding="utf-8")
        cls.discovery = DISCOVERY_TEMPLATE.read_text(encoding="utf-8")
        cls.styles = DISCOVERY_STYLES.read_text(encoding="utf-8")

    def test_source_discovery_templates_compile(self):
        for template_name in (
            "console/setup/3_integration_create_node.html",
            "console/setup/_setup_cloud_node.html",
        ):
            with self.subTest(template=template_name):
                get_template(template_name)

    def test_source_discovery_controller_is_valid_javascript(self):
        if not shutil.which("node"):
            self.skipTest("Node.js is required for the JavaScript syntax contract.")
        script = self.discovery.split("<script>", 1)[1].split("</script>", 1)[0]

        completed = subprocess.run(
            ["node", "--check"],
            input=script,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_page_uses_a_scoped_dedicated_stylesheet(self):
        self.assertIn("console/css/source_discovery.css", self.page)
        self.assertIn("source-discovery-page", self.page)
        self.assertNotIn("<style", self.page)
        self.assertNotIn("<style", self.discovery)
        self.assertTrue(DISCOVERY_STYLES.is_file())

    def test_discovery_receipt_is_truthful_and_exposes_freshness_and_counts(self):
        for witness in (
            "Scope and consequence",
            "Provider inventory receipt",
            "Inventory freshness",
            "BackupSheep registration only",
            "No snapshot, schedule, backup, or recovery evidence is created",
            "Refresh inventory",
            "Returned",
            "Available",
            "Already added",
            "Needs review",
            "Client receipt time; completeness depends on provider permissions.",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.discovery)
        self.assertIn("Registration alone does not create a backup", self.page)
        self.assertNotIn("successfully protected", self.discovery.lower())

    def test_search_filters_and_resource_metadata_have_native_labels(self):
        for witness in (
            'role="search"',
            'for="source-resource-search"',
            'x-model.debounce.200ms="query"',
            'for="source-region-filter"',
            'for="source-state-filter"',
            "resourceId(object)",
            "resourceRegion(object)",
            "resourceSize(object)",
            "providerState(object)",
            "Provider-reported metadata",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.discovery)

    def test_registration_requires_an_accessible_exact_resource_preflight(self):
        for witness in (
            'role="dialog"',
            'aria-modal="true"',
            'aria-labelledby="source-review-title"',
            '@keydown.tab="trapReviewDialog($event)"',
            '@keydown.escape.window="if (reviewOpen',
            "this.reviewTrigger = trigger || document.activeElement",
            "trigger.focus({preventScroll: true})",
            "Exact resource",
            "This action creates",
            "This action does not create",
            "confirmReview()",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.discovery)
        self.assertIn('@click="openReview(object, $event.currentTarget)"', self.discovery)
        self.assertNotIn('@click="linkObject(object', self.discovery)

    def test_single_resource_flow_is_guarded_and_fails_closed_on_unknown_outcome(self):
        for witness in (
            "if (this.linkingKey !== null",
            ":disabled=\"linkingKey !== null || loading || refreshing\"",
            "responseConfirmed",
            "outcomeIsUnknown",
            "Outcome not confirmed",
            "The operation may have completed.",
            "Refresh inventory before attempting another add.",
            "focusTarget?.isConnected",
            "nextAction || this.$refs.stateFilter",
            "target?.isConnected",
            "hasResourceIdentity(object)",
            "Provider ID required",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.discovery)
        self.assertNotIn("Alpine.store('showLoading').toggle()", self.discovery)
        self.assertNotIn('type="checkbox"', self.discovery)
        self.assertNotIn("bulk", self.discovery.lower())
        self.assertIn('attachedCount === totalCount', self.discovery)
        self.assertNotIn('availableCount === 0" class="sd-all-attached', self.discovery)

    def test_empty_loading_error_stale_and_all_attached_states_are_distinct(self):
        for witness in (
            "Discovering provider inventory",
            "No provider inventory has been received.",
            "No resources match these filters",
            "Every returned resource is already added.",
            "The last received inventory remains visible below and may now be stale.",
            "Provider access is not available",
            "Provider request limit reached",
            "Provider discovery timed out",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.discovery)

    def test_styles_cover_targets_responsive_cards_motion_and_forced_colors(self):
        for witness in (
            "min-height: 2.75rem",
            "@media (max-width: 50rem)",
            "content: attr(data-label)",
            ".sd-dialog",
            "@media (prefers-reduced-motion: reduce)",
            "@media (forced-colors: active)",
            "overflow-wrap: anywhere",
        ):
            with self.subTest(witness=witness):
                self.assertIn(witness, self.styles)


class SourceDiscoveryViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        CoreIntegration.objects.get_or_create(
            code="digitalocean",
            defaults={
                "name": "DigitalOcean",
                "type": CoreIntegration.Type.CLOUD,
                "enabled": True,
            },
        )
        self.client.force_login(self.user)

    def test_create_page_renders_one_heading_and_enterprise_discovery_context(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Production provider account",
        )
        response = self.client.get(
            reverse(
                "console:setup:integration_create_node",
                kwargs={
                    "integration_code": "digitalocean",
                    "connection_id": connection.id,
                    "object_code": "cloud",
                },
            )
        )

        self.assertEqual(response.status_code, 200)
        rendered = response.content.decode()
        self.assertEqual(rendered.count("<h1"), 1)
        self.assertEqual(response.context["shell_heading"], "Add provider resources")
        self.assertEqual(response.context["resource_label"], "server")
        self.assertEqual(response.context["resource_label_plural"], "servers")
        self.assertTrue(response.context["oauth_reconnect_available"])
        self.assertContains(response, "Add DigitalOcean resources")
        self.assertContains(response, "Production provider account")
        self.assertContains(response, "console/css/source_discovery.css")
        self.assertContains(response, "Registration alone does not create a backup")
