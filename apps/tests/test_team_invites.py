"""End-to-end tests for team invites (public accept/signup page, invite lifecycle
API actions), group permission/node management and account member management.

All email sends are mocked at CoreNotificationLogEmail.send -- no external service
is ever contacted.
"""
import itertools
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import Group, User
from django.utils import timezone
from django.utils.text import slugify
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.console.account.models import CoreAccountGroup
from apps.console.invite.models import CoreInvite
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMemberAccount
from apps.console.notification.models import CoreNotificationLogEmail
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware

_group_seq = itertools.count(1)


def _mark_configured():
    s = CoreSiteSettings.load()
    s.setup_completed = True
    s.save()
    OnboardingMiddleware._completed = False  # force re-read of the DB flag


def _make_group(account, name=None, type_=CoreAccountGroup.Type.Team):
    """Create a CoreAccountGroup (enrollment) + its backing auth Group."""
    n = next(_group_seq)
    name = name or f"group-{n}"
    auth_group = Group.objects.create(name=slugify(f"{account.id}-{name}-{type_}-{n}"))
    return CoreAccountGroup.objects.create(
        account=account, group=auth_group, name=name, type=type_, default=False
    )


def _make_invite(account, member, email="invitee@example.com", groups=(), **kwargs):
    invite = CoreInvite.objects.create(
        added_by=member,
        account=account,
        email=email,
        first_name=kwargs.pop("first_name", "Invited"),
        last_name=kwargs.pop("last_name", "User"),
        **kwargs,
    )
    for group in groups:
        invite.groups.add(group)
    return invite


class InviteApiTests(BaseTestCase):
    """Invite create/list/lifecycle through the DRF API (token authenticated)."""

    def setUp(self):
        super().setUp()
        _mark_configured()  # onboarding gate must not intercept API requests
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.user).key}")
        self.group = _make_group(self.account, "operators")

    def _create_payload(self, email="new.person@example.com", groups=None):
        return {
            "email": email,
            "first_name": "New",
            "last_name": "Person",
            "groups": [g.id for g in (groups if groups is not None else [self.group])],
            "notify_on_success": True,
            "notify_on_fail": False,
            "timezone": "UTC",
        }

    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_invite_create_sends_team_invite_email_with_accept_url(self, mock_send):
        r = self.client.post("/api/v1/invites/", self._create_payload(), format="json")
        self.assertEqual(r.status_code, 201, r.content)

        invite = CoreInvite.objects.get(email="new.person@example.com")
        mock_send.assert_called_once()

        log = CoreNotificationLogEmail.objects.get(email="new.person@example.com")
        self.assertEqual(log.template, "team_invite")
        self.assertEqual(log.member, self.member)  # filed under the inviter
        site = CoreSiteSettings.load()
        expected_url = (
            f"{site.get_app_protocol()}{site.get_app_domain()}/invite/{invite.uuid}/"
        )
        self.assertEqual(log.context["action_url"], expected_url)
        self.assertNotIn("backupsheep.com", log.context["action_url"])
        self.assertEqual(log.context["account_name"], self.account.get_name())

        # A fresh invite gets a ~7 day acceptance window.
        self.assertIsNotNone(invite.expires_at)
        self.assertGreater(invite.expires_at, timezone.now() + timedelta(days=6))

    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_invite_non_user_is_allowed(self, mock_send):
        # The whole point of the public accept page: no existing user required.
        r = self.client.post(
            "/api/v1/invites/", self._create_payload(email="no.such.user@example.com"), format="json"
        )
        self.assertEqual(r.status_code, 201, r.content)
        self.assertFalse(User.objects.filter(email="no.such.user@example.com").exists())

    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_duplicate_pending_invite_blocked(self, mock_send):
        r = self.client.post("/api/v1/invites/", self._create_payload(), format="json")
        self.assertEqual(r.status_code, 201, r.content)

        r = self.client.post("/api/v1/invites/", self._create_payload(), format="json")
        self.assertEqual(r.status_code, 400, r.content)
        self.assertIn("pending invite", str(r.content).lower())

        # A different email for the same account is fine.
        r = self.client.post(
            "/api/v1/invites/", self._create_payload(email="someone.else@example.com"), format="json"
        )
        self.assertEqual(r.status_code, 201, r.content)

    @mock.patch.object(CoreNotificationLogEmail, "send")
    def test_resend_reemails_and_extends_expiry(self, mock_send):
        invite = _make_invite(self.account, self.member)
        invite.expires_at = timezone.now() + timedelta(days=1)
        invite.save()

        r = self.client.post(f"/api/v1/invites/{invite.id}/resend/", format="json")
        self.assertEqual(r.status_code, 200, r.content)
        mock_send.assert_called_once()
        invite.refresh_from_db()
        self.assertGreater(invite.expires_at, timezone.now() + timedelta(days=6))

    def test_resend_rejects_non_pending_invite(self):
        invite = _make_invite(self.account, self.member)
        invite.status = CoreInvite.Status.CANCELLED
        invite.save()
        r = self.client.post(f"/api/v1/invites/{invite.id}/resend/", format="json")
        self.assertEqual(r.status_code, 400, r.content)

    def test_cancel_revokes_invite(self):
        invite = _make_invite(self.account, self.member)
        r = self.client.post(f"/api/v1/invites/{invite.id}/cancel/", format="json")
        self.assertEqual(r.status_code, 200, r.content)
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.CANCELLED)

        # A cancelled invite can no longer be accepted or cancelled again.
        r = self.client.post(f"/api/v1/invites/{invite.id}/cancel/", format="json")
        self.assertEqual(r.status_code, 400, r.content)

    def test_expired_invite_rejected_and_flipped_on_accept(self):
        account2, member2, user2 = factories.make_account(email="invitee2@example.com")
        invite = _make_invite(
            self.account, self.member, email="invitee2@example.com", groups=[self.group]
        )
        invite.expires_at = timezone.now() - timedelta(days=1)
        invite.save()

        client2 = APIClient()
        client2.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=user2).key}")
        r = client2.get(f"/api/v1/invites/{invite.id}/accept/")
        self.assertEqual(r.status_code, 400, r.content)
        self.assertIn("expired", r.json()["detail"].lower())
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.EXPIRED)
        self.assertFalse(member2.memberships.filter(account=self.account).exists())

    def test_expired_invites_flipped_on_list(self):
        invite = _make_invite(self.account, self.member)
        invite.expires_at = timezone.now() - timedelta(hours=1)
        invite.save()
        r = self.client.get("/api/v1/invites/")
        self.assertEqual(r.status_code, 200)
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.EXPIRED)

    def test_accept_via_api_writes_member_log(self):
        account2, member2, user2 = factories.make_account(email="invitee3@example.com")
        invite = _make_invite(
            self.account, self.member, email="invitee3@example.com", groups=[self.group]
        )

        client2 = APIClient()
        client2.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=user2).key}")
        r = client2.get(f"/api/v1/invites/{invite.id}/accept/")
        self.assertEqual(r.status_code, 200, r.content)

        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.ACCEPTED)
        self.assertTrue(member2.memberships.filter(account=self.account).exists())
        self.assertIn(self.group.group, list(user2.groups.all()))

        log = CoreLog.objects.filter(
            account=self.account, type=CoreLog.Type.MEMBER, data__invite_id=invite.id
        )
        self.assertTrue(log.exists())
        self.assertIn("accepted", log.first().data["message"].lower())


class InvitePublicPageTests(BaseTestCase):
    """The public /invite/<uuid>/ accept + signup page."""

    def setUp(self):
        super().setUp()
        _mark_configured()
        self.group = _make_group(self.account, "operators")

    def test_get_renders_signup_form_for_anonymous(self):
        invite = _make_invite(self.account, self.member, groups=[self.group])
        r = self.client.get(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 200)
        content = r.content.decode()
        self.assertIn("Create account &amp; accept invite", content)
        self.assertIn(self.account.get_name(), content)
        self.assertIn(invite.email, content)

    def test_get_unavailable_for_cancelled_invite(self):
        invite = _make_invite(self.account, self.member)
        invite.status = CoreInvite.Status.CANCELLED
        invite.save()
        r = self.client.get(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("no longer active", r.content.decode())

    def test_get_flips_expired_invite(self):
        invite = _make_invite(self.account, self.member)
        invite.expires_at = timezone.now() - timedelta(days=1)
        invite.save()
        r = self.client.get(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("no longer active", r.content.decode())
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.EXPIRED)

    def test_signup_accept_creates_user_membership_groups_and_logs_in(self):
        invite = _make_invite(
            self.account,
            self.member,
            email="brand.new@example.com",
            groups=[self.group],
            notify_on_success=False,
            notify_on_fail=True,
        )
        r = self.client.post(
            f"/invite/{invite.uuid}/",
            {
                "first_name": "Brand",
                "last_name": "New",
                "password1": "a-Strong-pass-123",
                "password2": "a-Strong-pass-123",
            },
        )
        self.assertEqual(r.status_code, 302, r.content)
        self.assertEqual(r.headers["Location"], "/console/")

        user = User.objects.get(email="brand.new@example.com")
        member = user.member
        membership = member.memberships.get(account=self.account)
        self.assertEqual(membership.notify_on_success, False)
        self.assertEqual(membership.notify_on_fail, True)
        self.assertTrue(membership.current)
        self.assertIn(self.group.group, list(user.groups.all()))

        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.ACCEPTED)

        # Logged in as the new user.
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.id)

        # And a MEMBER activity-log row was written.
        self.assertTrue(
            CoreLog.objects.filter(
                account=self.account, type=CoreLog.Type.MEMBER, data__invite_id=invite.id
            ).exists()
        )

    def test_signup_accept_password_mismatch_fails(self):
        invite = _make_invite(self.account, self.member, email="mismatch@example.com")
        r = self.client.post(
            f"/invite/{invite.uuid}/",
            {
                "first_name": "Mis",
                "last_name": "Match",
                "password1": "a-Strong-pass-123",
                "password2": "different-456",
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(User.objects.filter(email="mismatch@example.com").exists())
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.PENDING)

    def test_signup_accept_existing_email_asks_for_login(self):
        account2, member2, user2 = factories.make_account(email="existing@example.com")
        invite = _make_invite(self.account, self.member, email="existing@example.com")
        r = self.client.post(
            f"/invite/{invite.uuid}/",
            {
                "first_name": "Existing",
                "last_name": "User",
                "password1": "a-Strong-pass-123",
                "password2": "a-Strong-pass-123",
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("already exists", r.content.decode())
        self.assertFalse(member2.memberships.filter(account=self.account).exists())

    def test_logged_in_accept_works_and_sets_current_account(self):
        account2, member2, user2 = factories.make_account(email="teammate@example.com")
        invite = _make_invite(
            self.account, self.member, email="teammate@example.com", groups=[self.group]
        )
        self.client.force_login(user2)
        r = self.client.post(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 302, r.content)
        self.assertEqual(r.headers["Location"], "/console/")

        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.ACCEPTED)
        self.assertTrue(member2.memberships.filter(account=self.account).exists())
        self.assertIn(self.group.group, list(user2.groups.all()))
        # The invited account became the member's current one.
        self.assertEqual(member2.get_current_account(), self.account)

        # Accepting again renders the friendly unavailable page.
        r = self.client.post(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("no longer active", r.content.decode())

    def test_logged_in_wrong_email_cannot_accept(self):
        account2, member2, user2 = factories.make_account(email="someone@example.com")
        invite = _make_invite(self.account, self.member, email="other@example.com")
        self.client.force_login(user2)
        r = self.client.post(f"/invite/{invite.uuid}/")
        self.assertEqual(r.status_code, 200)
        invite.refresh_from_db()
        self.assertEqual(invite.status, CoreInvite.Status.PENDING)
        self.assertFalse(member2.memberships.filter(account=self.account).exists())


class GroupApiTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()  # onboarding gate must not intercept API requests
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.user).key}")

    def test_group_permission_clearing_works(self):
        r = self.client.post(
            "/api/v1/groups/",
            {
                "name": "perm-group",
                "type": CoreAccountGroup.Type.Team,
                "permissions": ["backup_create", "backup_download"],
                "nodes": [],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        group_id = r.json()["id"]
        account_group = CoreAccountGroup.objects.get(id=group_id)
        self.assertEqual(account_group.group.permissions.count(), 2)

        # Clearing all permissions must actually clear them.
        r = self.client.patch(
            f"/api/v1/groups/{group_id}/",
            {"name": "perm-group", "type": CoreAccountGroup.Type.Team, "permissions": []},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)
        account_group.refresh_from_db()
        self.assertEqual(account_group.group.permissions.count(), 0)

        # And a MEMBER activity-log row was written for the group changes.
        self.assertTrue(
            CoreLog.objects.filter(account=self.account, type=CoreLog.Type.MEMBER).exists()
        )

    def test_group_nodes_assignment_roundtrips(self):
        node = factories.make_website_node(self.account, self.member)
        r = self.client.post(
            "/api/v1/groups/",
            {
                "name": "node-group",
                "type": CoreAccountGroup.Type.Client,
                "permissions": [],
                "nodes": [node.id],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        group_id = r.json()["id"]

        r = self.client.get(f"/api/v1/groups/{group_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["nodes"], [node.id])

        r = self.client.patch(
            f"/api/v1/groups/{group_id}/",
            {"name": "node-group", "type": CoreAccountGroup.Type.Client, "nodes": []},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(CoreAccountGroup.objects.get(id=group_id).nodes.count(), 0)

    def test_group_nodes_must_belong_to_account(self):
        other_account, other_member, _ = factories.make_account()
        foreign_node = factories.make_website_node(other_account, other_member)
        r = self.client.post(
            "/api/v1/groups/",
            {
                "name": "bad-nodes",
                "type": CoreAccountGroup.Type.Team,
                "permissions": [],
                "nodes": [foreign_node.id],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 400, r.content)


class NodeScopeTests(BaseTestCase):
    """A non-owner is limited to the union of nodes assigned to their groups."""

    def setUp(self):
        super().setUp()
        _mark_configured()
        self.group = _make_group(self.account, "client-scope", CoreAccountGroup.Type.Client)
        _other_account, self.client_member, self.client_user = factories.make_account(
            email="client.scope@example.com"
        )
        # The fixture starts with another account marked current; switch it before
        # adding the current membership to respect the DB's one-current constraint.
        self.client_member.memberships.filter(current=True).update(current=False)
        CoreMemberAccount.objects.create(
            member=self.client_member, account=self.account, current=True, primary=False
        )
        self.client_user.groups.add(self.group.group)
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.client_user).key}"
        )

    def test_nodes_and_schedules_respect_group_node_scope(self):
        allowed = factories.make_website_node(self.account, self.member)
        hidden = factories.make_website_node(self.account, self.member)
        self.group.nodes.add(allowed)
        allowed_schedule = factories.make_schedule(allowed, self.member)
        hidden_schedule = factories.make_schedule(hidden, self.member)

        r = self.client.get("/api/v1/nodes/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([node["id"] for node in r.json()], [allowed.id])

        # A guessed ID is not enough to retrieve a node outside the group scope.
        r = self.client.get(f"/api/v1/nodes/{hidden.id}/")
        self.assertEqual(r.status_code, 404)

        r = self.client.get("/api/v1/schedules/")
        self.assertEqual(r.status_code, 200)
        schedule_ids = [schedule["id"] for schedule in r.json()]
        self.assertEqual(schedule_ids, [allowed_schedule.id])
        self.assertNotIn(hidden_schedule.id, schedule_ids)


class MemberApiTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()  # onboarding gate must not intercept API requests
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.user).key}")
        self.group = _make_group(self.account, "operators")
        # A second member belonging to the same account (an accepted invitee).
        self.account2, self.member2, self.user2 = factories.make_account(
            email="teammate@example.com"
        )
        self.membership2 = CoreMemberAccount.objects.create(
            member=self.member2,
            account=self.account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )

    def test_members_list_shows_account_members(self):
        r = self.client.get("/api/v1/members/")
        self.assertEqual(r.status_code, 200, r.content)
        rows = r.json()
        self.assertEqual(len(rows), 2)
        by_email = {row["email"]: row for row in rows}
        self.assertIn(self.user.email, by_email)
        self.assertIn("teammate@example.com", by_email)

        owner = by_email[self.user.email]
        self.assertTrue(owner["primary"])
        self.assertTrue(owner["current"])

        teammate = by_email["teammate@example.com"]
        self.assertFalse(teammate["primary"])
        self.assertFalse(teammate["current"])
        self.assertIn("notify_on_success", teammate)
        self.assertIn("notify_on_fail", teammate)
        self.assertIn("status", teammate)
        self.assertIn("groups", teammate)
        self.assertEqual(teammate["member_id"], self.member2.id)

    def test_update_membership_syncs_auth_groups_and_notify_flags(self):
        other_group = _make_group(self.account, "viewers")
        self.user2.groups.add(self.group.group)

        r = self.client.post(
            f"/api/v1/members/{self.member2.id}/update_membership/",
            {
                "groups": [other_group.id],
                "notify_on_success": False,
                "notify_on_fail": False,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)

        # Old group replaced by the new one (sync, not append).
        auth_group_names = list(self.user2.groups.values_list("name", flat=True))
        self.assertIn(other_group.group.name, auth_group_names)
        self.assertNotIn(self.group.group.name, auth_group_names)

        self.membership2.refresh_from_db()
        self.assertEqual(self.membership2.notify_on_success, False)
        self.assertEqual(self.membership2.notify_on_fail, False)

        self.assertTrue(
            CoreLog.objects.filter(
                account=self.account,
                type=CoreLog.Type.MEMBER,
                data__member_id=self.member2.id,
            ).exists()
        )

    def test_update_membership_rejects_foreign_groups(self):
        other_account, other_member, _ = factories.make_account()
        foreign_group = _make_group(other_account, "foreign")
        r = self.client.post(
            f"/api/v1/members/{self.member2.id}/update_membership/",
            {"groups": [foreign_group.id]},
            format="json",
        )
        self.assertEqual(r.status_code, 400, r.content)

    def test_update_membership_requires_primary_member(self):
        # member2 is not the primary member of self.account; make it their
        # current account so the gate is exercised against self.account.
        self.member2.memberships.filter(account=self.account2).update(current=False)
        self.member2.memberships.filter(account=self.account).update(current=True)

        client2 = APIClient()
        client2.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.user2).key}")
        r = client2.post(
            f"/api/v1/members/{self.member.id}/update_membership/",
            {"groups": []},
            format="json",
        )
        self.assertEqual(r.status_code, 403, r.content)

    def test_remove_membership_writes_member_log(self):
        r = self.client.post(
            f"/api/v1/accounts/{self.account.id}/remove_membership/",
            {"membership_id": self.membership2.id},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)
        self.assertFalse(
            CoreMemberAccount.objects.filter(id=self.membership2.id).exists()
        )
        self.assertTrue(
            CoreLog.objects.filter(
                account=self.account,
                type=CoreLog.Type.MEMBER,
                data__member_id=self.member2.id,
            ).exists()
        )
