from cryptography.fernet import Fernet
from django.contrib.auth.models import Group
from django.contrib.auth import SESSION_KEY
from django.test import Client
from rest_framework.authtoken.models import Token

from apps.console.account.models import CoreAccount
from apps.console.account.models import CoreAccountGroup
from apps.console.member.models import CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class MembershipAuthenticationBoundaryTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site = CoreSiteSettings.load()
        site.setup_completed = True
        site.save(update_fields=["setup_completed", "modified"])
        OnboardingMiddleware._completed = False

    def _add_membership(self, name, *, status=CoreMemberAccount.Status.ACTIVE):
        account = CoreAccount.objects.create(
            name=name,
            encryption_key=Fernet.generate_key(),
        )
        membership = CoreMemberAccount.objects.create(
            member=self.member,
            account=account,
            status=status,
            current=False,
            primary=False,
        )
        return account, membership

    def test_password_login_rejects_every_non_active_membership_state(self):
        membership = self.member.memberships.get(account=self.account)

        for index, membership_status in enumerate(
            (
                CoreMemberAccount.Status.SUSPENDED,
                CoreMemberAccount.Status.PENDING,
                CoreMemberAccount.Status.INVITED,
            ),
            start=1,
        ):
            with self.subTest(status=membership_status):
                membership.status = membership_status
                membership.save(update_fields=["status", "modified"])
                response = self.client.post(
                    "/api/v1/auth/login/",
                    {"email": self.user.email, "password": "x-Secret-123"},
                    content_type="application/json",
                    REMOTE_ADDR=f"192.0.2.{index}",
                )

                self.assertEqual(response.status_code, 400, response.content)
                self.assertNotIn(SESSION_KEY, self.client.session)
                self.assertFalse(Token.objects.filter(user=self.user).exists())
                response_text = response.content.decode().lower()
                self.assertNotIn("suspended", response_text)
                self.assertNotIn("pending", response_text)
                self.assertNotIn("invited", response_text)

    def test_login_auto_selects_oldest_active_fallback(self):
        first_account, first_active = self._add_membership("First active")
        _second_account, second_active = self._add_membership("Second active")
        original = self.member.memberships.get(account=self.account)
        original.status = CoreMemberAccount.Status.SUSPENDED
        original.save(update_fields=["status", "modified"])

        response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "x-Secret-123"},
            content_type="application/json",
            REMOTE_ADDR="192.0.2.10",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("api_key", response.json())
        original.refresh_from_db()
        first_active.refresh_from_db()
        second_active.refresh_from_db()
        self.assertFalse(original.current)
        self.assertTrue(first_active.current)
        self.assertFalse(second_active.current)
        self.assertEqual(self.member.get_current_account(), first_account)

    def test_existing_browser_session_is_ended_before_console_or_api_data(self):
        secret = "SUSPENDED-TENANT-NODE-DO-NOT-DISCLOSE"
        node = factories.make_website_node(self.account, self.member)
        node.name = secret
        node.save(update_fields=["name", "modified"])
        membership = self.member.memberships.get(account=self.account)

        for membership_status in (
            CoreMemberAccount.Status.SUSPENDED,
            CoreMemberAccount.Status.PENDING,
            CoreMemberAccount.Status.INVITED,
        ):
            with self.subTest(status=membership_status):
                membership.status = CoreMemberAccount.Status.ACTIVE
                membership.save(update_fields=["status", "modified"])
                browser = Client()
                browser.force_login(self.user)

                membership.status = membership_status
                membership.save(update_fields=["status", "modified"])
                console_response = browser.get("/console/nodes/")

                self.assertEqual(console_response.status_code, 302)
                self.assertEqual(console_response.headers["Location"], "/login")
                self.assertNotContains(console_response, secret, status_code=302)
                self.assertNotIn(SESSION_KEY, browser.session)
                api_response = browser.get("/api/v1/accounts/")
                self.assertEqual(api_response.status_code, 401)
                self.assertNotIn(secret, api_response.content.decode())

    def test_existing_browser_moves_to_active_account_without_old_tenant_data(self):
        old_secret = "OLD-SUSPENDED-NODE-DO-NOT-DISCLOSE"
        new_secret = "ACTIVE-FALLBACK-NODE-IS-VISIBLE"
        old_node = factories.make_website_node(self.account, self.member)
        old_node.name = old_secret
        old_node.save(update_fields=["name", "modified"])
        new_account, fallback = self._add_membership("Active fallback")
        unrestricted_group = Group.objects.create(
            name=f"active-fallback-{new_account.pk}"
        )
        CoreAccountGroup.objects.create(
            account=new_account,
            group=unrestricted_group,
            name="Active fallback access",
            type=CoreAccountGroup.Type.Client,
            default=False,
        )
        self.user.groups.add(unrestricted_group)
        new_node = factories.make_website_node(new_account, self.member)
        new_node.name = new_secret
        new_node.save(update_fields=["name", "modified"])

        browser = Client()
        browser.force_login(self.user)
        original = self.member.memberships.get(account=self.account)
        original.status = CoreMemberAccount.Status.SUSPENDED
        original.save(update_fields=["status", "modified"])

        response = browser.get("/console/nodes/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, new_secret)
        self.assertNotContains(response, old_secret)
        self.assertIn(SESSION_KEY, browser.session)
        original.refresh_from_db()
        fallback.refresh_from_db()
        self.assertFalse(original.current)
        self.assertTrue(fallback.current)

    def test_account_switch_rechecks_status_at_atomic_selection_boundary(self):
        suspended_account, suspended = self._add_membership("Suspended destination")
        # Retain stale application objects, then change authorization state in the
        # database.  The selector must lock and re-read instead of trusting a prior
        # exists()/object check.
        stale_account = CoreAccount.objects.get(pk=suspended_account.pk)
        CoreMemberAccount.objects.filter(pk=suspended.pk).update(
            status=CoreMemberAccount.Status.SUSPENDED
        )

        selected = self.member.set_current_account(stale_account)
        self.client.force_login(self.user)
        response = self.client.post(
            f"/api/v1/members/{self.member.pk}/switch_current_account/",
            {"account_id": suspended_account.pk},
            content_type="application/json",
        )

        self.assertIsNone(selected)
        self.assertEqual(response.status_code, 400)
        suspended.refresh_from_db()
        self.assertFalse(suspended.current)
        self.assertTrue(self.member.memberships.get(account=self.account).current)

    def test_account_switch_can_return_to_active_primary_without_constraint_race(self):
        fallback_account, fallback = self._add_membership("Active fallback")
        primary = self.member.memberships.get(account=self.account)

        self.assertEqual(
            self.member.set_current_account(fallback_account).pk,
            fallback.pk,
        )
        self.assertEqual(
            self.member.set_current_account(self.account).pk,
            primary.pk,
        )
        primary.refresh_from_db()
        fallback.refresh_from_db()
        self.assertTrue(primary.current)
        self.assertFalse(fallback.current)

    def test_existing_bearer_token_stops_authenticating_without_active_membership(self):
        token = Token.objects.create(user=self.user)
        membership = self.member.memberships.get(account=self.account)
        membership.status = CoreMemberAccount.Status.SUSPENDED
        membership.save(update_fields=["status", "modified"])

        response = self.client.get(
            "/api/v1/accounts/",
            HTTP_AUTHORIZATION=f"Token {token.key}",
        )

        self.assertEqual(response.status_code, 401)
        self.assertNotIn(self.account.name, response.content.decode())
