import re

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import Client
from django.utils import timezone
from django.utils.text import slugify

from apps.console.account.models import CoreAccountGroup
from apps.console.invite.models import CoreInvite
from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.notification.models import CoreNotificationTelegram
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


User = get_user_model()


def _mark_configured():
    site = CoreSiteSettings.load()
    site.setup_completed = True
    site.save(update_fields=["setup_completed", "modified"])
    OnboardingMiddleware._completed = False


def _make_member(account, *, email, primary=False):
    user = User.objects.create_user(
        username=email,
        email=email,
        password="x-Secret-123",
        first_name="Tenant",
        last_name="Member",
    )
    member = CoreMember.objects.create(user=user, timezone="UTC")
    membership = CoreMemberAccount.objects.create(
        member=member,
        account=account,
        status=CoreMemberAccount.Status.ACTIVE,
        current=True,
        primary=primary,
    )
    return member, user, membership


class SettingsEnterprisePageTests(BaseTestCase):
    ROUTES = (
        "/console/settings/profile/",
        "/console/settings/account/",
        "/console/settings/multifactor/",
        "/console/settings/password/",
        "/console/settings/groups/",
        "/console/settings/users/",
        "/console/settings/invites/",
        "/console/settings/notifications/",
    )

    def setUp(self):
        super().setUp()
        _mark_configured()
        self.owner_client = Client()
        self.owner_client.force_login(self.user)
        self.tenant_member, self.tenant_user, self.tenant_membership = _make_member(
            self.account,
            email="view-only@example.com",
        )
        self.member_client = Client()
        self.member_client.force_login(self.tenant_user)

        auth_group = Group.objects.create(name=slugify(f"{self.account.id}-sensitive"))
        self.enrollment = CoreAccountGroup.objects.create(
            account=self.account,
            group=auth_group,
            name="Sensitive operators",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        self.outbound_invite = CoreInvite.objects.create(
            account=self.account,
            added_by=self.member,
            email="pending-secret@example.com",
            first_name="Pending",
            last_name="Secret",
        )
        self.outbound_invite.groups.add(self.enrollment)
        self.telegram = CoreNotificationTelegram.objects.create(
            account=self.account,
            added_by=self.member,
            channel_name="Sensitive incident room",
            chat_id="private-destination-123",
        )

    def test_every_settings_route_owns_one_h1_and_shared_shell(self):
        for url in self.ROUTES:
            with self.subTest(url=url):
                response = self.owner_client.get(url)
                self.assertEqual(response.status_code, 200, response.content)
                html = response.content.decode()
                self.assertEqual(len(re.findall(r"<h1\b", html, re.IGNORECASE)), 1)
                self.assertIn('id="settings-page-title"', html)
                self.assertIn("console/css/settings.css", html)
                self.assertTrue(response.context["content_owns_h1"])
                self.assertEqual(response.context["shell_heading"], "Settings")
                rendered_ids = re.findall(r'\bid="([^"]+)"', html)
                self.assertEqual(
                    len(rendered_ids),
                    len(set(rendered_ids)),
                    f"duplicate rendered id on {url}",
                )

    def test_group_editor_exposes_restore_as_a_separate_impactful_capability(self):
        response = self.owner_client.get("/console/settings/groups/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, "Restore Backups")
        self.assertContains(response, "permissions.backup_restore")
        self.assertContains(response, "can overwrite data")
        self.assertContains(response, "may remove files")

    def test_settings_dialogs_restore_focus_without_stale_hidden_triggers(self):
        group_html = self.owner_client.get(
            "/console/settings/groups/"
        ).content.decode()
        mfa_html = self.owner_client.get(
            "/console/settings/multifactor/"
        ).content.decode()

        self.assertIn(
            '@keydown.escape.window="openGroup && closeGroupModal()"',
            group_html,
        )
        self.assertIn("if (!this.openGroup) return", group_html)
        self.assertIn("this.groupDialogReturnFocus = null", group_html)
        self.assertIn("trigger?.isConnected", group_html)
        self.assertIn("const trigger = this.revokeDialog.returnFocus", mfa_html)
        self.assertIn("this.revokeDialog.returnFocus = null", mfa_html)
        self.assertIn("revoked ? this.$refs.setupTokenAuth : trigger", mfa_html)
        self.assertIn("target?.isConnected", mfa_html)

    def test_nonowner_direct_urls_are_sparse_and_do_not_hydrate_owner_objects(self):
        group_page = self.member_client.get("/console/settings/groups/")
        invite_page = self.member_client.get("/console/settings/invites/")
        notification_page = self.member_client.get("/console/settings/notifications/")
        user_page = self.member_client.get("/console/settings/users/")

        for response in (group_page, invite_page, notification_page, user_page):
            self.assertEqual(response.status_code, 200, response.content)
            self.assertIn("View-only workspace access", response.content.decode())
            self.assertEqual(
                len(re.findall(r"<h1\b", response.content.decode(), re.IGNORECASE)),
                1,
            )

        self.assertNotIn("Sensitive operators", group_page.content.decode())
        self.assertEqual(list(group_page.context["account_groups"]), [])
        self.assertEqual(list(invite_page.context["enrollments"]), [])
        self.assertEqual(list(invite_page.context["outbound_invites"]), [])
        self.assertNotIn("pending-secret@example.com", invite_page.content.decode())
        self.assertNotIn(">Create invitation<", invite_page.content.decode())

        notification_html = notification_page.content.decode()
        self.assertEqual(list(notification_page.context["notifications_slack"]), [])
        self.assertEqual(list(notification_page.context["notifications_telegram"]), [])
        self.assertNotIn("Sensitive incident room", notification_html)
        self.assertNotIn("private-destination-123", notification_html)
        self.assertNotIn("/api/v1/notifications-telegram/", notification_html)
        self.assertIn("intentionally not loaded", notification_html)

        user_html = user_page.content.decode()
        self.assertNotIn("@click=\"openRemoveDialog", user_html)
        self.assertNotIn(">Invite member<", user_html)
        self.assertEqual(list(user_page.context["enrollments"]), [])

    def test_owner_notification_page_never_renders_telegram_identifier(self):
        response = self.owner_client.get("/console/settings/notifications/")
        self.assertEqual(response.status_code, 200, response.content)
        html = response.content.decode()
        self.assertIn("Sensitive incident room", html)
        self.assertNotIn("private-destination-123", html)
        self.assertIn("Destination identifier protected", html)

    def test_settings_confirmation_and_unknown_outcome_contracts_are_present(self):
        account_html = self.owner_client.get(
            "/console/settings/account/"
        ).content.decode()
        mfa_html = self.owner_client.get(
            "/console/settings/multifactor/"
        ).content.decode()
        user_html = self.owner_client.get(
            "/console/settings/users/"
        ).content.decode()
        invite_html = self.owner_client.get(
            "/console/settings/invites/"
        ).content.decode()
        group_html = self.owner_client.get(
            "/console/settings/groups/"
        ).content.decode()

        for html in (account_html, mfa_html, user_html, invite_html, group_html):
            self.assertNotIn("window.confirm", html)
            self.assertIn('aria-modal="true"', html)
        self.assertIn("Save outcome not confirmed", account_html)
        self.assertIn("Reload this page before", account_html)
        self.assertIn("Reload this page before retrying", user_html)
        self.assertIn("Email delivery is not independently confirmed", invite_html)
        self.assertIn("/reject/", invite_html)
        self.assertIn("Reject workspace invitation?", invite_html)
        self.assertIn("Save outcome not confirmed", group_html)
        self.assertIn("Delete outcome not confirmed", group_html)
        self.assertIn("Reload this page before retrying", group_html)

    def test_group_delete_dialog_names_impact_and_restores_focus(self):
        response = self.owner_client.get("/console/settings/groups/")

        self.assertEqual(response.status_code, 200, response.content)
        html = response.content.decode()
        self.assertIn('aria-labelledby="delete-group-dialog-title"', html)
        self.assertIn('aria-describedby="delete-group-dialog-description"', html)
        self.assertIn('role="dialog" aria-modal="true"', html)
        self.assertIn('data-group-name="Sensitive operators"', html)
        self.assertIn('data-member-count="0"', html)
        self.assertIn('data-source-count="0"', html)
        self.assertIn("Protected sources, schedules, backups, and stored recovery points are not deleted", html)
        self.assertIn("Remove every member before this group can be deleted", html)
        self.assertIn('@keydown.escape.window="deleteDialog.open && closeDeleteDialog()"', html)
        self.assertIn('@keydown.tab="trapDeleteDialogFocus($event)"', html)
        self.assertIn("if (this.deleteDialog.busy) return", html)
        self.assertIn("deleteDialog.busy || deleteDialog.memberCount > 0", html)
        self.assertIn("this.deleteDialog.returnFocus = null", html)
        self.assertIn("trigger?.isConnected", html)

    def test_group_save_treats_malformed_success_body_as_unknown_outcome(self):
        html = self.owner_client.get("/console/settings/groups/").content.decode()

        self.assertIn("!json || typeof json !== 'object' || Array.isArray(json)", html)
        self.assertIn("throw this.unknownMutationOutcome('Save'", html)
        self.assertIn("Save outcome not confirmed", html)


class SettingsMemberBoundaryTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()
        self.client.force_login(self.user)

    def test_profile_nested_preferences_do_not_mutate_workspace_event_gates(self):
        current = self.member.memberships.get(account=self.account)
        current.notify_on_success = False
        current.notify_on_fail = True
        current.save(update_fields=["notify_on_success", "notify_on_fail", "modified"])
        self.account.notify_on_success = False
        self.account.notify_on_fail = False
        self.account.save(update_fields=["notify_on_success", "notify_on_fail", "modified"])

        response = self.client.patch(
            f"/api/v1/members/{self.member.id}/",
            {
                "timezone": "America/Chicago",
                "user": {"first_name": "Updated", "last_name": "Owner"},
                "memberships": [
                    {"notify_on_success": True, "notify_on_fail": False}
                ],
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        current.refresh_from_db()
        self.account.refresh_from_db()
        self.assertTrue(current.notify_on_success)
        self.assertFalse(current.notify_on_fail)
        self.assertFalse(self.account.notify_on_success)
        self.assertFalse(self.account.notify_on_fail)

    def test_profile_accepts_at_most_one_nested_membership(self):
        response = self.client.patch(
            f"/api/v1/members/{self.member.id}/",
            {
                "memberships": [
                    {"notify_on_success": True, "notify_on_fail": True},
                    {"notify_on_success": False, "notify_on_fail": False},
                ]
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("memberships", response.json())

    def test_self_detail_keeps_own_accounts_and_marks_request_current_account(self):
        other_account, _other_owner, _other_user = factories.make_account()
        CoreMemberAccount.objects.create(
            member=self.member,
            account=other_account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )

        response = self.client.get(f"/api/v1/members/{self.member.id}/")

        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(
            set(payload),
            {"id", "user", "full_name", "email", "memberships"},
        )
        self.assertEqual(
            set(payload["user"]),
            {"id", "username", "first_name", "last_name", "email"},
        )
        self.assertEqual(payload["user"]["id"], self.user.id)
        self.assertEqual(payload["user"]["first_name"], self.user.first_name)
        self.assertEqual(payload["user"]["last_name"], self.user.last_name)
        self.assertEqual(payload["user"]["email"], self.user.email)
        accounts = {
            membership["account"]["id"]: membership["account"]
            for membership in payload["memberships"]
        }
        self.assertEqual(set(accounts), {self.account.id, other_account.id})
        self.assertTrue(accounts[self.account.id]["is_current"])
        self.assertFalse(accounts[other_account.id]["is_current"])

    def test_peer_detail_exposes_only_shared_current_workspace_membership(self):
        peer, peer_user, _peer_current = _make_member(
            self.account,
            email="peer@example.com",
        )
        other_account, _other_owner, _other_user = factories.make_account()
        CoreMemberAccount.objects.create(
            member=peer,
            account=other_account,
            status=CoreMemberAccount.Status.ACTIVE,
            current=False,
            primary=False,
        )
        foreign_auth_group = Group.objects.create(
            name=slugify(f"{other_account.id}-foreign-administrators")
        )
        foreign_enrollment = CoreAccountGroup.objects.create(
            account=other_account,
            group=foreign_auth_group,
            name="Foreign administrators",
            type=CoreAccountGroup.Type.Team,
            default=False,
        )
        foreign_permission = Permission.objects.get(
            content_type__app_label="auth",
            codename="change_user",
        )
        peer_user.groups.add(foreign_auth_group)
        peer_user.user_permissions.add(foreign_permission)
        peer_user.is_staff = True
        peer_user.is_superuser = True
        peer_user.save(update_fields=["is_staff", "is_superuser"])
        peer.timezone = "Pacific/Honolulu"
        peer.auth_multi_factor_display_name = "Foreign workspace authenticator"
        peer.auth_multi_factor_enabled_at = timezone.now()
        peer.save(
            update_fields=[
                "timezone",
                "auth_multi_factor_display_name",
                "auth_multi_factor_enabled_at",
                "modified",
            ]
        )

        detail = self.client.get(f"/api/v1/members/{peer.id}/")
        listing = self.client.get("/api/v1/members/")

        self.assertEqual(detail.status_code, 200, detail.content)
        detail_payload = detail.json()
        self.assertEqual(
            set(detail_payload),
            {"id", "user", "full_name", "email", "memberships"},
        )
        memberships = detail_payload["memberships"]
        self.assertEqual(len(memberships), 1)
        self.assertEqual(memberships[0]["account"]["id"], self.account.id)
        self.assertTrue(memberships[0]["account"]["is_current"])
        self.assertNotIn(other_account.get_name(), detail.content.decode())
        self.assertNotIn(str(other_account.id), detail.content.decode())
        self.assertNotIn("Pacific/Honolulu", detail.content.decode())
        self.assertNotIn("Foreign workspace authenticator", detail.content.decode())
        for private_field in (
            "accounts",
            "timezone",
            "auth_multi_factor_secret",
            "auth_multi_factor_display_name",
            "auth_multi_factor_pending_created",
            "auth_multi_factor_enabled_at",
            "auth_multi_factor_last_counter",
            "auth_session_version",
        ):
            self.assertNotIn(private_field, detail_payload)

        peer_identity = detail_payload["user"]
        self.assertEqual(
            set(peer_identity),
            {"id", "username", "first_name", "last_name", "email"},
        )
        self.assertEqual(peer_identity["id"], peer_user.id)
        self.assertEqual(peer_identity["first_name"], peer_user.first_name)
        self.assertEqual(peer_identity["last_name"], peer_user.last_name)
        self.assertEqual(peer_identity["email"], peer_user.email)
        for private_field in (
            "password",
            "last_login",
            "is_staff",
            "is_active",
            "is_superuser",
            "date_joined",
            "groups",
            "user_permissions",
        ):
            self.assertNotIn(private_field, peer_identity)

        self.assertEqual(listing.status_code, 200, listing.content)
        peer_rows = [row for row in listing.json() if row["member_id"] == peer.id]
        self.assertEqual(len(peer_rows), 1)
        peer_row = peer_rows[0]
        self.assertEqual(peer_row["id"], peer.id)
        self.assertEqual(peer_row["first_name"], peer_user.first_name)
        self.assertEqual(peer_row["last_name"], peer_user.last_name)
        self.assertEqual(peer_row["email"], peer_user.email)
        self.assertEqual(peer_row["account"]["id"], self.account.id)
        self.assertNotIn(
            foreign_enrollment.id,
            [group["id"] for group in peer_row["groups"]],
        )
        self.assertNotIn(
            foreign_enrollment.name,
            [group["name"] for group in peer_row["groups"]],
        )
        for private_field in (
            "password",
            "last_login",
            "is_staff",
            "is_active",
            "is_superuser",
            "date_joined",
            "user_permissions",
        ):
            self.assertNotIn(private_field, peer_row)


class InviteRecipientRejectionTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()
        self.recipient_account, self.recipient, self.recipient_user = (
            factories.make_account(email="recipient@example.com")
        )
        self.invite = CoreInvite.objects.create(
            account=self.account,
            added_by=self.member,
            email=self.recipient_user.email,
            first_name="Invite",
            last_name="Recipient",
        )
        self.recipient_client = Client()
        self.recipient_client.force_login(self.recipient_user)

    def test_addressed_recipient_can_reject_without_gaining_workspace_access(self):
        response = self.recipient_client.post(
            f"/api/v1/invites/{self.invite.id}/reject/",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.invite.refresh_from_db()
        self.assertEqual(self.invite.status, CoreInvite.Status.CANCELLED)
        self.assertFalse(self.recipient.memberships.filter(account=self.account).exists())

    def test_other_identity_cannot_reject_invitation(self):
        _other_account, _other_member, other_user = factories.make_account(
            email="different@example.com"
        )
        other_client = Client()
        other_client.force_login(other_user)

        response = other_client.post(
            f"/api/v1/invites/{self.invite.id}/reject/",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.invite.refresh_from_db()
        self.assertEqual(self.invite.status, CoreInvite.Status.PENDING)
