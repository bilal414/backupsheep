import uuid
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory, SimpleTestCase
from django.urls import URLResolver, get_resolver
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.cloud.digitalocean.views import CoreCloudDigitalOceanView
from apps.api.v1.node.serializers import (
    CoreCloudNodeWriteSerializer,
    CoreDatabaseNodeWriteSerializer,
    CoreNodeSerializer,
    CoreNodeWriteSerializer,
    CoreSaaSNodeWriteSerializer,
    CoreVolumeNodeWriteSerializer,
    CoreWebsiteNodeWriteSerializer,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
)
from apps.console.account.models import CoreAccountGroup
from apps.console.connection.models import CoreAuthDigitalOcean, CoreIntegration
from apps.console.member.models import CoreMemberAccount
from apps.console.node.models import CoreDigitalOcean, CoreNode
from apps.tests import factories
from apps.tests.base import BaseTestCase


NODE_WRITE_SERIALIZERS = (
    CoreNodeSerializer,
    CoreDatabaseNodeWriteSerializer,
    CoreWebsiteNodeWriteSerializer,
    CoreNodeWriteSerializer,
    CoreSaaSNodeWriteSerializer,
    CoreCloudNodeWriteSerializer,
    CoreVolumeNodeWriteSerializer,
)


def _permission(codename):
    content_type = ContentType.objects.get_for_model(CoreAccountGroup)
    return Permission.objects.get(
        content_type=content_type,
        codename=codename,
    )


def _leaf_url_patterns(patterns):
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            yield from _leaf_url_patterns(pattern.url_patterns)
        else:
            yield pattern


class DirectSourceCreatePermissionContractTests(SimpleTestCase):
    def test_every_registered_source_create_requires_both_permissions(self):
        request = APIRequestFactory().post("/api/v1/source/")
        guarded_views = set()

        for pattern in _leaf_url_patterns(get_resolver().url_patterns):
            callback = getattr(pattern, "callback", None)
            actions = getattr(callback, "actions", {})
            view_class = getattr(callback, "cls", None)
            if actions.get("post") != "create" or view_class is None:
                continue

            view = view_class()
            view.action = "create"
            try:
                serializer_class = view.get_serializer_class()
            except (AttributeError, AssertionError, TypeError):
                continue
            module = view_class.__module__
            source_module = module == "apps.api.v1.node.views" or module.startswith(
                (
                    "apps.api.v1.cloud.",
                    "apps.api.v1.volume.",
                    "apps.api.v1.database.",
                    "apps.api.v1.website.",
                    "apps.api.v1.saas.",
                )
            )
            if not source_module:
                continue

            node_field = getattr(
                serializer_class,
                "_declared_fields",
                {},
            ).get("node")
            marker = getattr(
                serializer_class,
                "source_creation_permissions",
                None,
            )
            if marker is None:
                marker = getattr(
                    node_field,
                    "source_creation_permissions",
                    None,
                )
            # Account-wide replication controllers also live under ``cloud``
            # but do not create CoreNode sources and have no nested node field.
            if node_field is None and module != "apps.api.v1.node.views":
                continue
            self.assertEqual(marker, SOURCE_DISCOVERY_PERMISSIONS)

            permission_classes = tuple(
                candidate
                for candidate in view_class.permission_classes
                if issubclass(candidate, MemberGroupPermissions)
            )
            self.assertEqual(
                len(permission_classes),
                1,
                view_class.__name__,
            )
            requirement = permission_classes[0]()._permission_codename(
                request,
                view,
            )
            self.assertEqual(
                requirement,
                SOURCE_DISCOVERY_PERMISSIONS,
                view_class.__name__,
            )
            guarded_views.add(view_class)

        # Generic node creation plus every provider/database/site/SaaS source
        # view currently registered by the API router must participate.
        self.assertGreaterEqual(len(guarded_views), 28)


class NodeCreationConnectionAuthorizationTests(BaseTestCase):
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
        self.connection = self._make_connection(
            self.account,
            self.member,
            "Current workspace DigitalOcean",
        )
        self.request_factory = RequestFactory()

    @staticmethod
    def _make_connection(account, member, name):
        connection = factories.make_connection(
            account,
            member,
            code="digitalocean",
            name=name,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-token", account.get_encryption_key()),
        )
        return connection

    def _context(self, user=None):
        request = self.request_factory.post("/api/v1/source/")
        request.user = user or self.user
        return {"request": request}

    @staticmethod
    def _serializer_payload(serializer_class, connection):
        data = {
            "connection": connection.pk,
            "name": "Enterprise source",
        }
        if serializer_class is CoreNodeSerializer:
            data.update(
                {
                    "type": CoreNode.Type.CLOUD,
                    "added_by": connection.added_by_id,
                }
            )
        return data

    def _assert_connection_rejected(self, connection, *, user=None):
        for serializer_class in NODE_WRITE_SERIALIZERS:
            with self.subTest(serializer=serializer_class.__name__):
                serializer = serializer_class(
                    data=self._serializer_payload(serializer_class, connection),
                    context=self._context(user),
                )
                self.assertFalse(serializer.is_valid())
                self.assertIn("connection", serializer.errors)
                self.assertIn(
                    "active workspace",
                    str(serializer.errors["connection"]).lower(),
                )

    def test_every_node_write_serializer_accepts_current_owner_connection(self):
        for serializer_class in NODE_WRITE_SERIALIZERS:
            with self.subTest(serializer=serializer_class.__name__):
                serializer = serializer_class(
                    data=self._serializer_payload(
                        serializer_class,
                        self.connection,
                    ),
                    context=self._context(),
                )
                self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_cross_account_and_noncurrent_connections_are_indistinguishable(self):
        foreign_account, foreign_member, _ = factories.make_account(
            email="foreign-node-create@example.com"
        )
        foreign_connection = self._make_connection(
            foreign_account,
            foreign_member,
            "Foreign DigitalOcean",
        )
        self._assert_connection_rejected(foreign_connection)

        CoreMemberAccount.objects.create(
            member=self.member,
            account=foreign_account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )
        self._assert_connection_rejected(foreign_connection)

    def test_suspended_or_stale_current_membership_has_no_connection_scope(self):
        membership = self.member.memberships.get(account=self.account)
        membership.status = CoreMemberAccount.Status.SUSPENDED
        membership.save(update_fields=("status", "modified"))

        self._assert_connection_rejected(self.connection)
        membership.refresh_from_db()
        self.assertIsNone(self.member.get_active_current_membership())


class DirectSourceProviderBoundaryTests(BaseTestCase):
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
        self.connection = self._make_connection(
            self.account,
            self.member,
            "Scoped DigitalOcean",
        )
        existing_node = CoreNode.objects.create(
            connection=self.connection,
            type=CoreNode.Type.CLOUD,
            name="Existing scoped source",
            added_by=self.member,
        )
        CoreDigitalOcean.objects.create(
            node=existing_node,
            name="Existing scoped source",
            unique_id="existing-source",
        )

        self.foreign_account, self.team_member, self.team_user = (
            factories.make_account(email="source-create-team@example.com")
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
            name=f"source-create-{uuid.uuid4().hex}"
        )
        self.group = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Scoped source operators",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.group.nodes.add(existing_node)
        self.team_user.groups.add(auth_group)

    @staticmethod
    def _make_connection(account, member, name):
        connection = factories.make_connection(
            account,
            member,
            code="digitalocean",
            name=name,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-token", account.get_encryption_key()),
        )
        return connection

    def _set_team_permissions(self, *codenames):
        self.group.group.permissions.set(
            [_permission(codename) for codename in codenames]
        )

    @staticmethod
    def _payload(connection_id, resource_id="new-source"):
        return {
            "node": {
                "connection": connection_id,
                "name": "Client supplied name",
            },
            "name": "Client supplied name",
            "unique_id": resource_id,
            "resource_type": "cloud",
        }

    def _create(self, user, connection_id, resource_id="new-source"):
        request = APIRequestFactory().post(
            "/api/v1/cloud/digitalocean/",
            self._payload(connection_id, resource_id),
            format="json",
        )
        force_authenticate(request, user=user)
        return CoreCloudDigitalOceanView.as_view({"post": "create"})(request)

    def test_permission_matrix_blocks_before_provider_credentials(self):
        cases = (
            ("neither", (), 403),
            ("integration only", ("integration_changes",), 403),
            ("node only", ("node_changes",), 403),
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
        ) as verified_client, mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
        ) as provider_inventory:
            for label, permissions, expected_status in cases:
                with self.subTest(case=label):
                    self._set_team_permissions(*permissions)
                    response = self._create(
                        self.team_user,
                        self.connection.pk,
                    )
                    self.assertEqual(response.status_code, expected_status)

        verified_client.assert_not_called()
        provider_inventory.assert_not_called()

    def test_hidden_cross_account_noncurrent_and_guessed_ids_never_call_provider(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        hidden_connection = self._make_connection(
            self.account,
            self.member,
            "Hidden DigitalOcean",
        )
        foreign_connection = self._make_connection(
            self.foreign_account,
            self.team_member,
            "Noncurrent DigitalOcean",
        )

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
        ) as verified_client, mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
        ) as provider_inventory:
            cases = (
                ("hidden", self.team_user, hidden_connection.pk),
                ("noncurrent", self.team_user, foreign_connection.pk),
                ("cross-account", self.user, foreign_connection.pk),
                ("guessed", self.user, 2**31 - 1),
            )
            for label, user, connection_id in cases:
                with self.subTest(case=label):
                    response = self._create(user, connection_id)
                    self.assertEqual(response.status_code, 400)

        verified_client.assert_not_called()
        provider_inventory.assert_not_called()

    def test_authorized_scoped_member_and_current_owner_reach_provider(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        provider_resources = [
            {
                "id": "new-source",
                "name": "Authoritative provider source",
                "region": {"name": "nyc3"},
                "size": {"disk": 25},
            },
            {
                "id": "owner-source",
                "name": "Owner provider source",
                "region": {"name": "nyc3"},
                "size": {"disk": 25},
            },
        ]
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test"},
        ) as verified_client, mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
            return_value=provider_resources,
        ) as provider_inventory:
            scoped_response = self._create(
                self.team_user,
                self.connection.pk,
            )
            owner_response = self._create(
                self.user,
                self.connection.pk,
                resource_id="owner-source",
            )

        self.assertEqual(scoped_response.status_code, 201)
        self.assertEqual(owner_response.status_code, 201)
        self.assertEqual(verified_client.call_count, 2)
        self.assertEqual(provider_inventory.call_count, 2)

    def test_suspended_current_membership_is_rejected_before_provider(self):
        self._set_team_permissions(*SOURCE_DISCOVERY_PERMISSIONS)
        membership = self.team_member.memberships.get(account=self.account)
        membership.status = CoreMemberAccount.Status.SUSPENDED
        membership.save(update_fields=("status", "modified"))

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
        ) as verified_client, mock.patch(
            "apps.api.v1.cloud.digitalocean.serializers.list_eligible_objects",
        ) as provider_inventory:
            response = self._create(self.team_user, self.connection.pk)

        # The stale current selector is repaired to the member's other active
        # workspace.  The old workspace connection then becomes an opaque,
        # invalid identifier rather than an authorization oracle.
        self.assertEqual(response.status_code, 400)
        verified_client.assert_not_called()
        provider_inventory.assert_not_called()
