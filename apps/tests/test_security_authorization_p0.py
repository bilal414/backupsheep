import os
import tempfile
import time
import uuid
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import Client, RequestFactory, override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.api.v1.callback.views import (
    PCLOUD_OAUTH_STATE_SESSION_KEY,
    PCLOUD_OAUTH_STATE_TTL_SECONDS,
    _validated_pcloud_hostname,
)
from apps.api.v1.connection.google_cloud.views import CoreGoogleCloudView
from apps.api.v1.connection.ovh_ca.views import CoreOVHCAView
from apps.api.v1.connection.ovh_eu.views import CoreOVHEUView
from apps.api.v1.connection.ovh_us.views import CoreOVHUSView
from apps.api.v1.utils.api_permissions import MemberGroupPermissions, member_has_perm
from apps.console.account.models import CoreAccountGroup
from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.member.models import CoreMemberAccount
from apps.console.notification.models import CoreNotificationSlack
from apps.console.setting.models import CoreSiteSettings
from apps.console.storage.models import CoreStorage, CoreStorageLocal, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    site = CoreSiteSettings.load()
    site.setup_completed = True
    site.save()
    OnboardingMiddleware._completed = False


def _permission(codename):
    content_type = ContentType.objects.get_for_model(CoreAccountGroup)
    return Permission.objects.get(content_type=content_type, codename=codename)


def _account_group(account, name, user=None, permissions=()):
    auth_group = Group.objects.create(name=f"security-{account.pk}-{name}-{uuid.uuid4().hex}")
    enrollment = CoreAccountGroup.objects.create(
        account=account,
        group=auth_group,
        name=name,
        type=CoreAccountGroup.Type.Team,
        default=False,
    )
    auth_group.permissions.set([_permission(codename) for codename in permissions])
    if user is not None:
        user.groups.add(auth_group)
    return enrollment


class SecurityAuthorizationP0Tests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()

        self.foreign_account, self.team_member, self.team_user = factories.make_account(
            email=f"team-{self.account.pk}@example.com"
        )
        self.team_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.team_member,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=True,
            primary=False,
        )
        self.current_group = _account_group(
            self.account, "current-no-permissions", self.team_user
        )
        self.foreign_group = _account_group(
            self.foreign_account,
            "foreign-node-admin",
            self.team_user,
            permissions=("node_changes",),
        )

        self.team_client = APIClient()
        self.team_client.force_authenticate(user=self.team_user)
        self.owner_client = APIClient()
        self.owner_client.force_authenticate(user=self.user)

    def test_cross_tenant_group_permission_does_not_authorize_current_account(self):
        node = factories.make_website_node(self.account, self.member)
        self.current_group.nodes.add(node)
        request = SimpleNamespace(user=self.team_user)

        # This demonstrates the dangerous Django-global union that must not be
        # used for tenant authorization.
        self.assertTrue(self.team_user.has_perm("apps.node_changes"))
        self.assertFalse(member_has_perm(request, "node_changes"))

        response = self.team_client.patch(
            f"/api/v1/nodes/{node.pk}/", {"name": "cross-tenant-write"}, format="json"
        )
        self.assertEqual(response.status_code, 403, response.content)
        node.refresh_from_db()
        self.assertNotEqual(node.name, "cross-tenant-write")

        self.current_group.group.permissions.add(_permission("node_changes"))
        self.assertTrue(member_has_perm(request, "node_changes"))
        response = self.team_client.patch(
            f"/api/v1/nodes/{node.pk}/", {"name": "authorized-write"}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_unmapped_unsafe_action_fails_closed_for_non_owner(self):
        request = RequestFactory().post("/future-mutation/")
        request.user = self.team_user
        view = SimpleNamespace(action="future_mutation", action_permissions={})
        self.assertFalse(MemberGroupPermissions().has_permission(request, view))

    def test_all_cloud_connection_management_requires_current_account_permission(self):
        permission = MemberGroupPermissions()
        for view_class in (CoreOVHCAView, CoreOVHEUView, CoreOVHUSView, CoreGoogleCloudView):
            for method, action in (
                ("post", "create"),
                ("patch", "partial_update"),
                ("get", "validate"),
                ("get", "objects"),
            ):
                request = getattr(RequestFactory(), method)(f"/{action}/")
                request.user = self.team_user
                view = SimpleNamespace(
                    action=action,
                    action_permissions=view_class.action_permissions,
                )
                self.assertFalse(
                    permission.has_permission(request, view),
                    f"{view_class.__name__}.{action} unexpectedly allowed",
                )

        # Granting node management in this account authorizes the same actions.
        self.current_group.group.permissions.add(_permission("node_changes"))
        request = RequestFactory().get("/validate/")
        request.user = self.team_user
        view = SimpleNamespace(
            action="validate",
            action_permissions=CoreGoogleCloudView.action_permissions,
        )
        self.assertTrue(permission.has_permission(request, view))

    def test_team_member_cannot_escalate_or_administer_account(self):
        group_response = self.team_client.post(
            "/api/v1/groups/",
            {"name": "admins", "type": CoreAccountGroup.Type.Team, "nodes": []},
            format="json",
        )
        self.assertEqual(group_response.status_code, 403, group_response.content)

        invite_response = self.team_client.post(
            "/api/v1/invites/",
            {
                "email": "victim@example.com",
                "first_name": "Test",
                "last_name": "User",
                "groups": [self.current_group.pk],
                "timezone": "UTC",
            },
            format="json",
        )
        self.assertEqual(invite_response.status_code, 403, invite_response.content)
        self.assertEqual(
            self.team_client.patch(
                f"/api/v1/accounts/{self.account.pk}/", {"name": "Taken Over"}, format="json"
            ).status_code,
            403,
        )
        self.assertEqual(
            self.team_client.patch(
                f"/api/v1/members/{self.member.pk}/",
                {"timezone": "Pacific/Honolulu"},
                format="json",
            ).status_code,
            403,
        )
        self.assertEqual(
            self.team_client.delete(f"/api/v1/members/{self.member.pk}/").status_code,
            403,
        )
        self.assertEqual(self.team_client.get("/api/v1/invites/").status_code, 403)

    def test_invite_rejects_group_from_another_account(self):
        response = self.owner_client.post(
            "/api/v1/invites/",
            {
                "email": "victim@example.com",
                "first_name": "Test",
                "last_name": "User",
                "groups": [self.foreign_group.pk],
                "timezone": "UTC",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("groups", response.json())

    def _slack_integration(self):
        return CoreNotificationSlack.objects.create(
            account=self.account,
            added_by=self.member,
            app_id="app-id",
            token_type="bot",
            access_token="slack-access-secret-marker",
            bot_user_id="bot-id",
            refresh_token="slack-refresh-secret-marker",
            channel="security",
            channel_id="channel-id",
            configuration_url="https://hooks.slack.com/configuration-secret-marker",
            url="https://hooks.slack.com/services/webhook-secret-marker",
            data={"raw_secret": "slack-raw-secret-marker"},
        )

    def test_member_and_slack_bearer_secrets_are_never_serialized(self):
        self.member.password_reset_token = "password-reset-secret-marker"
        self.member.password_reset_token_created = timezone.now()
        self.member.save()
        slack = self._slack_integration()

        member_response = self.team_client.get(f"/api/v1/members/{self.member.pk}/")
        self.assertEqual(member_response.status_code, 200, member_response.content)
        self.assertNotIn("password_reset_token", member_response.json())
        self.assertNotIn("password-reset-secret-marker", member_response.content.decode())

        slack_response = self.team_client.get("/api/v1/notifications-slack/")
        self.assertEqual(slack_response.status_code, 200, slack_response.content)
        serialized = slack_response.content.decode()
        for marker in (
            "slack-access-secret-marker",
            "slack-refresh-secret-marker",
            "configuration-secret-marker",
            "webhook-secret-marker",
            "slack-raw-secret-marker",
        ):
            self.assertNotIn(marker, serialized)
        for field in ("access_token", "refresh_token", "configuration_url", "url", "data"):
            self.assertNotIn(field, slack_response.json()[0])

        # Team members can inspect redacted metadata, but cannot alter or delete
        # the account's shared integration.
        self.assertEqual(
            self.team_client.patch(
                f"/api/v1/notifications-slack/{slack.pk}/",
                {"account": self.foreign_account.pk},
                format="json",
            ).status_code,
            403,
        )
        self.assertEqual(
            self.team_client.delete(f"/api/v1/notifications-slack/{slack.pk}/").status_code,
            403,
        )

        # Even an owner cannot rebind the integration through the serializer.
        owner_patch = self.owner_client.patch(
            f"/api/v1/notifications-slack/{slack.pk}/",
            {"account": self.foreign_account.pk, "added_by": self.team_member.pk},
            format="json",
        )
        self.assertEqual(owner_patch.status_code, 200, owner_patch.content)
        slack.refresh_from_db()
        self.assertEqual(slack.account_id, self.account.pk)
        self.assertEqual(slack.added_by_id, self.member.pk)

    def test_users_page_never_renders_another_members_api_token(self):
        owner_token = Token.objects.create(user=self.user)
        team_token = Token.objects.create(user=self.team_user)
        browser = Client()
        browser.force_login(self.team_user)

        response = browser.get("/console/settings/users/")
        self.assertEqual(response.status_code, 200, response.content)
        html = response.content.decode()
        self.assertNotIn(owner_token.key, html)
        self.assertNotIn(team_token.key, html)
        self.assertNotIn("API Token", html)

    def test_account_name_is_json_encoded_not_interpolated_into_javascript(self):
        payload = "</script><script>window.backupsheep_xss = true</script>"
        self.account.name = payload
        self.account.save(update_fields=["name"])
        browser = Client()
        browser.force_login(self.user)

        response = browser.get("/console/settings/account/")
        self.assertEqual(response.status_code, 200, response.content)
        html = response.content.decode()
        self.assertIn('id="account-name-data"', html)
        self.assertNotIn(payload, html)
        self.assertNotIn("<script>window.backupsheep_xss", html)
        self.assertIn("\\u003C/script\\u003E", html)

    def _local_point(self, root):
        storage = CoreStorage.objects.create(
            account=self.account,
            type=CoreStorageType.objects.get(code="local"),
            name="local-security-test",
            added_by=self.member,
        )
        CoreStorageLocal.objects.create(storage=storage, path=root)
        node = factories.make_website_node(self.account, self.member)
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            uuid=f"t{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        target = os.path.join(root, f"{backup.uuid_str}.zip")
        with open(target, "wb") as output:
            output.write(b"security-test-backup")
        point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=target,
        )
        return point, node

    def test_local_download_requires_permission_and_visible_node(self):
        with tempfile.TemporaryDirectory() as root, override_settings(LOCAL_STORAGE_ROOT=root):
            point, node = self._local_point(root)
            self.current_group.nodes.add(node)
            url = f"/api/v1/storage/local/file/{point.pk}/"

            self.assertEqual(self.team_client.get(url).status_code, 403)

            self.current_group.group.permissions.add(_permission("backup_download"))
            response = self.team_client.get(url)
            self.assertEqual(response.status_code, 200, response)
            self.assertEqual(b"".join(response.streaming_content), b"security-test-backup")

            hidden_node = factories.make_website_node(self.account, self.member)
            self.current_group.nodes.set([hidden_node])
            self.assertEqual(self.team_client.get(url).status_code, 404)

    def _set_pcloud_state(self, browser, state="expected-state"):
        session = browser.session
        session[PCLOUD_OAUTH_STATE_SESSION_KEY] = {
            "state": state,
            "member_id": self.member.pk,
            "account_id": self.account.pk,
            "issued_at": time.time(),
        }
        session.save()

    def test_pcloud_callback_rejects_state_mismatch_before_network(self):
        browser = Client()
        browser.force_login(self.user)
        self._set_pcloud_state(browser)
        with mock.patch("apps.api.v1.callback.views.requests.post") as post:
            response = browser.get(
                "/api/v1/callback/pcloud/?state=wrong-state&code=code&hostname=api.pcloud.com"
            )
        self.assertEqual(response.status_code, 302)
        post.assert_not_called()

    def test_pcloud_callback_rejects_expired_state_before_network(self):
        browser = Client()
        browser.force_login(self.user)
        self._set_pcloud_state(browser)
        session = browser.session
        state = session[PCLOUD_OAUTH_STATE_SESSION_KEY]
        state["issued_at"] = (
            time.time() - PCLOUD_OAUTH_STATE_TTL_SECONDS - 1
        )
        session[PCLOUD_OAUTH_STATE_SESSION_KEY] = state
        session.save()
        with mock.patch("apps.api.v1.callback.views.requests.post") as post:
            response = browser.get(
                "/api/v1/callback/pcloud/?state=expected-state&code=code&hostname=api.pcloud.com"
            )
        self.assertEqual(response.status_code, 302)
        post.assert_not_called()

    def test_pcloud_callback_rejects_non_allowlisted_hostname_before_network(self):
        browser = Client()
        browser.force_login(self.user)
        self._set_pcloud_state(browser)
        with mock.patch("apps.api.v1.callback.views.requests.post") as post:
            response = browser.get(
                "/api/v1/callback/pcloud/?state=expected-state&code=code&hostname=api.pcloud.com.attacker.example"
            )
        self.assertEqual(response.status_code, 302)
        post.assert_not_called()
        self.assertIsNone(_validated_pcloud_hostname("api.pcloud.com.attacker.example"))
        self.assertEqual(_validated_pcloud_hostname("EAPI.PCLOUD.COM."), "eapi.pcloud.com")

    @override_settings(PCLOUD_CLIENT_SECRET="pcloud-client-secret-marker")
    def test_pcloud_token_exchange_uses_allowed_host_and_post_body(self):
        browser = Client()
        browser.force_login(self.user)
        self._set_pcloud_state(browser)
        token_response = mock.MagicMock(status_code=400)
        with mock.patch(
            "apps.api.v1.callback.views.requests.post", return_value=token_response
        ) as post:
            response = browser.get(
                "/api/v1/callback/pcloud/?state=expected-state&code=code&hostname=api.pcloud.com"
            )
        self.assertEqual(response.status_code, 302)
        post.assert_called_once()
        url = post.call_args.args[0]
        self.assertEqual(url, "https://api.pcloud.com/oauth2_token")
        self.assertNotIn("pcloud-client-secret-marker", url)
        self.assertEqual(
            post.call_args.kwargs["data"]["client_secret"],
            "pcloud-client-secret-marker",
        )
