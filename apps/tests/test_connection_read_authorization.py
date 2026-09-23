import json
import uuid

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory
from rest_framework.test import APIClient

from apps.api.v1.connection.aws.views import CoreAWSView
from apps.api.v1.connection.aws_rds.views import CoreAWSRDSView
from apps.api.v1.connection.basecamp.views import CoreBasecampView
from apps.api.v1.connection.database.views import CoreDatabaseView
from apps.api.v1.connection.digitalocean.views import CoreDigitalOceanView
from apps.api.v1.connection.google_cloud.views import CoreGoogleCloudView
from apps.api.v1.connection.hetzner.views import CoreHetznerView
from apps.api.v1.connection.lightsail.views import CoreLightsailView
from apps.api.v1.connection.oracle.views import CoreOracleView
from apps.api.v1.connection.ovh_ca.views import CoreOVHCAView
from apps.api.v1.connection.ovh_eu.views import CoreOVHEUView
from apps.api.v1.connection.ovh_us.views import CoreOVHUSView
from apps.api.v1.connection.upcloud.views import CoreUpCloudView
from apps.api.v1.connection.views import CoreConnectionView
from apps.api.v1.connection.vultr.views import CoreVultrView
from apps.api.v1.connection.website.views import CoreWebsiteView
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.account.models import CoreAccountGroup
from apps.console.connection.models import CoreAuthDatabase, CoreIntegration
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


PROVIDER_CONNECTION_VIEWS = (
    ("aws", CoreAWSView),
    ("aws_rds", CoreAWSRDSView),
    ("basecamp", CoreBasecampView),
    ("database", CoreDatabaseView),
    ("digitalocean", CoreDigitalOceanView),
    ("google_cloud", CoreGoogleCloudView),
    ("hetzner", CoreHetznerView),
    ("lightsail", CoreLightsailView),
    ("oracle", CoreOracleView),
    ("ovh_ca", CoreOVHCAView),
    ("ovh_eu", CoreOVHEUView),
    ("ovh_us", CoreOVHUSView),
    ("upcloud", CoreUpCloudView),
    ("vultr", CoreVultrView),
    ("website", CoreWebsiteView),
)


def _mark_configured():
    site = CoreSiteSettings.load()
    site.setup_completed = True
    site.save(update_fields=["setup_completed", "modified"])
    OnboardingMiddleware._completed = False


class ConnectionReadScopeTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()
        _foreign_account, self.restricted_member, self.restricted_user = (
            factories.make_account(email="restricted-connections@example.com")
        )
        self.restricted_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        auth_group = Group.objects.create(
            name=f"connection-read-scope-{uuid.uuid4().hex}"
        )
        self.enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Scoped connection readers",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.restricted_user.groups.add(auth_group)
        self.request = RequestFactory().get("/api/v1/connections/")
        self.request.user = self.restricted_user

    def _make_pair(self, code):
        CoreIntegration.objects.get_or_create(
            code=code,
            defaults={
                "name": code.replace("_", " ").title(),
                "type": CoreIntegration.Type.CLOUD,
                "enabled": True,
            },
        )
        visible = factories.make_connection(
            self.account,
            self.member,
            code=code,
            name=f"visible-{code}",
        )
        hidden = factories.make_connection(
            self.account,
            self.member,
            code=code,
            name=f"hidden-{code}",
        )
        node = CoreNode.objects.create(
            connection=visible,
            type=CoreNode.Type.CLOUD,
            name=f"visible-{code}-source",
            added_by=self.member,
        )
        self.enrollment.nodes.add(node)
        return visible, hidden

    def test_every_provider_queryset_hides_unlinked_connections_and_guessed_ids(self):
        first_visible = None
        first_hidden = None
        for code, view_class in PROVIDER_CONNECTION_VIEWS:
            visible, hidden = self._make_pair(code)
            first_visible = first_visible or visible
            first_hidden = first_hidden or hidden
            view = view_class()
            view.request = self.request
            view.action = "list"

            with self.subTest(provider=code):
                ids = set(view.get_queryset().values_list("id", flat=True))
                self.assertIn(visible.id, ids)
                self.assertNotIn(hidden.id, ids)

        generic_view = CoreConnectionView()
        generic_view.request = self.request
        generic_view.action = "list"
        generic_ids = set(
            generic_view.get_queryset().values_list("id", flat=True)
        )
        self.assertIn(first_visible.id, generic_ids)
        self.assertNotIn(first_hidden.id, generic_ids)

    def test_integration_managers_receive_the_account_wide_connection_register(self):
        visible, hidden = self._make_pair("digitalocean")
        permission = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(CoreAccountGroup),
            codename="integration_changes",
        )
        self.enrollment.group.permissions.add(permission)
        view = CoreDigitalOceanView()
        view.request = self.request
        view.action = "list"

        ids = set(view.get_queryset().values_list("id", flat=True))

        self.assertIn(visible.id, ids)
        self.assertIn(hidden.id, ids)

        view.action = "objects"
        discovery_ids = set(
            view.get_queryset().values_list("id", flat=True)
        )
        self.assertIn(visible.id, discovery_ids)
        self.assertNotIn(hidden.id, discovery_ids)


class CredentialAdjacentConnectionReadTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()
        _foreign_account, self.restricted_member, self.restricted_user = (
            factories.make_account(email="database-reader@example.com")
        )
        self.restricted_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.restricted_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        auth_group = Group.objects.create(
            name=f"database-read-scope-{uuid.uuid4().hex}"
        )
        self.enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Scoped database readers",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.restricted_user.groups.add(auth_group)
        self.visible = self._database_connection(
            "visible database",
            "visible.database.example",
            "visible-user",
        )
        self.hidden = self._database_connection(
            "hidden database",
            "hidden.database.example",
            "hidden-user",
        )
        visible_node = CoreNode.objects.create(
            connection=self.visible,
            type=CoreNode.Type.DATABASE,
            name="visible database source",
            added_by=self.member,
        )
        self.enrollment.nodes.add(visible_node)
        self.client = APIClient()
        self.client.force_authenticate(user=self.restricted_user)

    def _database_connection(self, name, host, username):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
            name=name,
        )
        CoreAuthDatabase.objects.create(
            connection=connection,
            host=host,
            port=5432,
            database_name="app",
            username=bs_encrypt(username, self.account.get_encryption_key()),
            password=bs_encrypt("secret", self.account.get_encryption_key()),
            type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version=CoreAuthDatabase.DatabaseVersion.POSTGRESQL_16,
        )
        return connection

    def test_safe_list_and_retrieve_do_not_disclose_hidden_connection_metadata(self):
        listing = self.client.get("/api/v1/connections/database/")
        visible_detail = self.client.get(
            f"/api/v1/connections/database/{self.visible.id}/"
        )
        hidden_detail = self.client.get(
            f"/api/v1/connections/database/{self.hidden.id}/"
        )

        self.assertEqual(listing.status_code, 200, listing.content)
        serialized = json.dumps(listing.json())
        self.assertIn("visible database", serialized)
        self.assertNotIn("hidden database", serialized)
        self.assertNotIn("hidden.database.example", serialized)
        self.assertNotIn("hidden-user", serialized)
        self.assertEqual(visible_detail.status_code, 200, visible_detail.content)
        self.assertEqual(hidden_detail.status_code, 404, hidden_detail.content)
