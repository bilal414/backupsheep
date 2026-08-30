import uuid
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import SimpleTestCase
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

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
from apps.api.v1.connection.vultr.views import CoreVultrView
from apps.api.v1.connection.website.views import CoreWebsiteView
from apps.api.v1.connection.wordpress.views import CoreWordPressView
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
)
from apps.console.account.models import CoreAccountGroup
from apps.console.connection.models import CoreAuthDigitalOcean, CoreIntegration
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreNode
from apps.tests import factories
from apps.tests.base import BaseTestCase


PROVIDER_INVENTORY_VIEWS = (
    CoreAWSView,
    CoreAWSRDSView,
    CoreBasecampView,
    CoreDatabaseView,
    CoreDigitalOceanView,
    CoreGoogleCloudView,
    CoreHetznerView,
    CoreLightsailView,
    CoreOracleView,
    CoreOVHCAView,
    CoreOVHEUView,
    CoreOVHUSView,
    CoreUpCloudView,
    CoreVultrView,
    CoreWebsiteView,
    CoreWordPressView,
)


def _permission(codename):
    content_type = ContentType.objects.get_for_model(CoreAccountGroup)
    return Permission.objects.get(
        content_type=content_type,
        codename=codename,
    )


class SourceDiscoveryAuthorizationContractTests(SimpleTestCase):
    def test_every_provider_inventory_requires_both_management_permissions(self):
        self.assertEqual(
            SOURCE_DISCOVERY_PERMISSIONS,
            ("integration_changes", "node_changes"),
        )

        for view_class in PROVIDER_INVENTORY_VIEWS:
            permission_class = next(
                candidate
                for candidate in view_class.permission_classes
                if issubclass(candidate, MemberGroupPermissions)
            )
            action_permissions = getattr(
                view_class,
                "action_permissions",
                permission_class.action_permissions,
            )

            with self.subTest(view=view_class.__name__):
                self.assertEqual(
                    action_permissions.get("objects"),
                    SOURCE_DISCOVERY_PERMISSIONS,
                )


class SourceDiscoveryAuthorizationTests(BaseTestCase):
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
        self.connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Production DigitalOcean",
        )
        CoreAuthDigitalOcean.objects.create(
            connection=self.connection,
            api_key=bs_encrypt(
                "test-token",
                self.account.get_encryption_key(),
            ),
        )

        self.foreign_account, self.team_member, self.team_user = (
            factories.make_account(email="discovery-team@example.com")
        )
        self.team_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.team_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        auth_group = Group.objects.create(
            name=f"source-discovery-{uuid.uuid4().hex}"
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Source discovery operators",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.team_user.groups.add(auth_group)
        self.visible_node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="Visible registration scope",
            added_by=self.member,
        )
        self.group.nodes.add(self.visible_node)

    def _set_team_permissions(self, *codenames):
        self.group.group.permissions.set(
            [_permission(codename) for codename in codenames]
        )

    @staticmethod
    def _objects_request(user):
        request = APIRequestFactory().get(
            "/api/v1/connections/digitalocean/1/objects/",
            {"object_type": "cloud"},
        )
        force_authenticate(request, user=user)
        return request

    def _discover(self, user, connection_id=None):
        return CoreDigitalOceanView.as_view({"get": "objects"})(
            self._objects_request(user),
            pk=connection_id or self.connection.pk,
        )

    def test_complete_permission_matrix_gates_provider_calls(self):
        cases = (
            ("neither", self.team_user, (), 403, False),
            (
                "integration only",
                self.team_user,
                ("integration_changes",),
                403,
                False,
            ),
            (
                "node only",
                self.team_user,
                ("node_changes",),
                403,
                False,
            ),
            (
                "both",
                self.team_user,
                SOURCE_DISCOVERY_PERMISSIONS,
                200,
                True,
            ),
            ("primary owner", self.user, (), 200, True),
        )

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ) as verified_client, mock.patch(
            "apps.api.v1.connection.digitalocean.views.list_eligible_objects",
            return_value=[],
        ) as provider_inventory:
            for (
                label,
                user,
                codenames,
                expected_status,
                provider_called,
            ) in cases:
                with self.subTest(case=label):
                    self._set_team_permissions(*codenames)
                    verified_client.reset_mock()
                    provider_inventory.reset_mock()

                    response = self._discover(user)

                    self.assertEqual(response.status_code, expected_status)
                    if provider_called:
                        verified_client.assert_called_once_with()
                        provider_inventory.assert_called_once_with(
                            headers={"Authorization": "Bearer test-token"},
                            object_type="cloud",
                        )
                    else:
                        verified_client.assert_not_called()
                        provider_inventory.assert_not_called()

    def test_cross_account_connection_guess_is_404_before_provider_call(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        foreign_connection = factories.make_connection(
            self.foreign_account,
            self.team_member,
            code="digitalocean",
            name="Foreign provider account",
        )
        CoreAuthDigitalOcean.objects.create(
            connection=foreign_connection,
            api_key=bs_encrypt(
                "foreign-test-token",
                self.foreign_account.get_encryption_key(),
            ),
        )

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
        ) as verified_client, mock.patch(
            "apps.api.v1.connection.digitalocean.views.list_eligible_objects",
        ) as provider_inventory:
            response = self._discover(
                self.team_user,
                connection_id=foreign_connection.pk,
            )

        self.assertEqual(response.status_code, 404)
        verified_client.assert_not_called()
        provider_inventory.assert_not_called()

    def test_hidden_current_account_connection_is_not_a_registration_boundary(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        hidden_connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Hidden provider account",
        )
        CoreAuthDigitalOcean.objects.create(
            connection=hidden_connection,
            api_key=bs_encrypt(
                "hidden-test-token",
                self.account.get_encryption_key(),
            ),
        )
        direct_page = reverse(
            "console:setup:integration_create_node",
            kwargs={
                "integration_code": "digitalocean",
                "connection_id": hidden_connection.pk,
                "object_code": "cloud",
            },
        )
        self.client.force_login(self.team_user)

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
        ) as verified_client, mock.patch(
            "apps.api.v1.connection.digitalocean.views.list_eligible_objects",
        ) as provider_inventory:
            discovery = self._discover(
                self.team_user,
                connection_id=hidden_connection.pk,
            )
            page = self.client.get(direct_page)

        self.assertEqual(discovery.status_code, 404)
        self.assertEqual(page.status_code, 404)
        verified_client.assert_not_called()
        provider_inventory.assert_not_called()

    def test_provider_register_marks_add_source_only_for_usable_connections(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        hidden_connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="Hidden management-only provider account",
        )
        self.client.force_login(self.team_user)

        response = self.client.get(
            reverse(
                "console:setup:integration_open",
                kwargs={"integration_code": "digitalocean"},
            )
        )

        self.assertEqual(response.status_code, 200, response.content)
        rows = {connection.id: connection for connection in response.context["page"]}
        self.assertTrue(rows[self.connection.id].source_registration_allowed)
        self.assertFalse(rows[hidden_connection.id].source_registration_allowed)

    def test_unsupported_object_code_routes_are_404(self):
        self.client.force_login(self.user)
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
        )

        unsupported_routes = (
            reverse(
                "console:setup:integration_create_node",
                kwargs={
                    "integration_code": "digitalocean",
                    "connection_id": self.connection.pk,
                    "object_code": "s3",
                },
            ),
            reverse(
                "console:setup:integration_modify_node",
                kwargs={
                    "integration_code": "digitalocean",
                    "connection_id": node.connection_id,
                    "object_code": "s3",
                    "node_id": node.pk,
                },
            ),
        )

        for route in unsupported_routes:
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 404)
