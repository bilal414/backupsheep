"""Personal API tokens: issuance, scope enforcement, binding and lifecycle."""

from datetime import timedelta

from django.test import Client, override_settings
from django.utils import timezone

from apps.console.api_access.models import CoreApiToken
from apps.console.log.models import CoreLog
from apps.console.member.models import CoreMemberAccount
from apps.tests import factories
from apps.tests.base import BaseTestCase

PASSWORD = "x-Secret-123"


class ApiTokenMixin:
    def create_token(self, scopes, *, name="ci", expires_in=None, account_id=None, password=PASSWORD):
        payload = {"name": name, "scopes": scopes, "current_password": password}
        if expires_in is not None:
            payload["expires_in"] = expires_in
        if account_id is not None:
            payload["account_id"] = account_id
        return self.client.post("/api/v1/tokens/", payload, content_type="application/json")

    def bearer(self, secret):
        return {"HTTP_AUTHORIZATION": f"Bearer {secret}"}


class ApiTokenIssuanceTests(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)

    def test_create_returns_secret_once_and_stores_only_a_digest(self):
        response = self.create_token(["backups:read", "storage:read"], name="Nightly report")
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        secret = body["token"]
        self.assertTrue(secret.startswith("bsk_"))
        self.assertEqual(body["scopes"], ["backups:read", "storage:read"])
        self.assertEqual(body["account"]["id"], self.account.id)
        self.assertEqual(body["status"], "active")
        self.assertEqual(body["key_prefix"], secret[:12])

        token = CoreApiToken.objects.get(pk=body["id"])
        self.assertNotIn(secret, token.key_hash)
        self.assertEqual(token.key_hash, CoreApiToken.hash_secret(secret))
        self.assertNotIn("token", self.client.get(f"/api/v1/tokens/{token.id}/").json())
        self.assertNotIn("key_hash", self.client.get(f"/api/v1/tokens/{token.id}/").json())
        self.assertTrue(
            CoreLog.objects.filter(
                account=self.account, type=CoreLog.Type.AUTH, data__action="api_token_create"
            ).exists()
        )

    def test_create_requires_the_current_password(self):
        response = self.create_token(["backups:read"], password="wrong")
        self.assertEqual(response.status_code, 400)
        self.assertIn("current_password", response.json())
        self.assertEqual(CoreApiToken.objects.count(), 0)

    def test_create_rejects_unknown_scopes_and_excessive_lifetimes(self):
        self.assertEqual(self.create_token(["admin"]).status_code, 400)
        self.assertEqual(self.create_token([]).status_code, 400)
        too_long = CoreApiToken.max_ttl_seconds() + 1
        response = self.create_token(["backups:read"], expires_in=too_long)
        self.assertEqual(response.status_code, 400)
        self.assertIn("expires_in", response.json())

    def test_create_binds_to_an_active_membership_only(self):
        other_account, _, _ = factories.make_account()
        response = self.create_token(["backups:read"], account_id=other_account.id)
        self.assertEqual(response.status_code, 400)
        self.assertIn("account_id", response.json())

    def test_default_lifetime_is_bounded(self):
        response = self.create_token(["backups:read"])
        token = CoreApiToken.objects.get(pk=response.json()["id"])
        expected = timezone.now() + timedelta(seconds=CoreApiToken.default_ttl_seconds())
        self.assertLess(abs((token.expires_at - expected).total_seconds()), 60)


class ApiTokenAuthenticationTests(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        self.secret = self.create_token(["backups:read", "schedules:read", "profile"]).json()["token"]
        self.token = CoreApiToken.objects.get(key_hash=CoreApiToken.hash_secret(self.secret))
        # A separate client with no session cookie: the token is the only credential.
        self.api = Client()

    def test_valid_token_authenticates_and_records_use(self):
        response = self.api.get("/api/v1/schedules/", **self.bearer(self.secret))
        self.assertEqual(response.status_code, 200, response.content)
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)

    def test_missing_scope_is_403_insufficient_scope(self):
        response = self.api.get("/api/v1/storage/all/", **self.bearer(self.secret))
        self.assertEqual(response.status_code, 403, response.content)
        body = response.json()
        self.assertEqual(body["code"], "insufficient_scope")
        self.assertEqual(body["required_scope"], "storage:read")

    def test_write_requires_write_scope_before_the_view_runs(self):
        response = self.api.post(
            "/api/v1/schedules/", {}, content_type="application/json", **self.bearer(self.secret)
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["required_scope"], "schedules:write")

    def test_write_scope_implies_read(self):
        secret = self.create_token(["storage:write"]).json()["token"]
        response = self.api.get("/api/v1/storage/all/", **self.bearer(secret))
        self.assertEqual(response.status_code, 200, response.content)

    def test_interactive_only_routes_reject_tokens(self):
        for method, path in (
            ("get", "/api/v1/tokens/"),
            ("post", "/api/v1/tokens/"),
            ("post", f"/api/v1/members/{self.member.id}/auth_multi_factor_token_setup/"),
            ("get", "/api/v1/oauth/applications/"),
        ):
            with self.subTest(method=method, path=path):
                response = getattr(self.api, method)(path, **self.bearer(self.secret))
                self.assertEqual(response.status_code, 403, response.content)
                self.assertEqual(response.json()["code"], "interactive_credential_required")

    def test_unclassified_routes_fail_closed_for_tokens(self):
        from django.test import RequestFactory

        from apps.api.v1.utils.api_authentication import (
            InteractiveCredentialRequired,
            enforce_scope,
        )

        # A registered route that no rule covers must be denied, not allowed.
        request = RequestFactory().get("/api/v1/not-yet-classified/")
        with self.assertRaises(InteractiveCredentialRequired):
            enforce_scope(request, self.token, account_bound=True)

    def test_scope_catalog_is_available_to_any_credential(self):
        response = self.api.get("/api/v1/tokens/scopes/", **self.bearer(self.secret))
        self.assertEqual(response.status_code, 200)
        self.assertIn("backups:restore", [row["scope"] for row in response.json()])

    def test_invalid_expired_and_revoked_tokens_are_401(self):
        self.assertEqual(
            self.api.get("/api/v1/schedules/", **self.bearer("bsk_not-a-real-token")).status_code,
            401,
        )
        CoreApiToken.objects.filter(pk=self.token.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)
        CoreApiToken.objects.filter(pk=self.token.pk).update(
            expires_at=timezone.now() + timedelta(days=1), revoked_at=timezone.now()
        )
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)

    def test_token_stops_working_when_membership_is_suspended(self):
        CoreMemberAccount.objects.filter(member=self.member, account=self.account).update(
            status=CoreMemberAccount.Status.SUSPENDED
        )
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)

    def test_token_cannot_switch_workspace_or_change_password(self):
        secret = self.create_token(["account:write", "profile"]).json()["token"]
        response = self.api.post(
            f"/api/v1/members/{self.member.id}/switch_current_account/",
            {"account_id": self.account.id},
            content_type="application/json",
            **self.bearer(secret),
        )
        self.assertEqual(response.status_code, 403)
        response = self.api.patch(
            f"/api/v1/members/{self.member.id}/",
            {
                "user": {
                    "current_password": PASSWORD,
                    "password": "Another-Secret-456",
                    "password_confirm": "Another-Secret-456",
                }
            },
            content_type="application/json",
            **self.bearer(secret),
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))

    def test_logout_with_a_token_revokes_only_that_token(self):
        other = self.create_token(["profile"]).json()["token"]
        response = self.api.post("/api/v1/auth/logout/", **self.bearer(self.secret))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **self.bearer(other)).status_code, 200)
        # The browser session that created the tokens is untouched.
        self.assertEqual(self.client.get("/api/v1/tokens/").status_code, 200)

    def test_legacy_token_scheme_is_not_accepted_for_personal_tokens(self):
        response = self.api.get("/api/v1/schedules/", HTTP_AUTHORIZATION=f"Token {self.secret}")
        self.assertEqual(response.status_code, 401)


class ApiTokenWorkspaceBindingTests(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()

    def test_token_operates_in_its_bound_workspace(self):
        other_account, _, _ = factories.make_account()
        CoreMemberAccount.objects.create(
            member=self.member,
            account=other_account,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        mine = factories.make_storage(self.account, self.member)
        theirs = factories.make_storage(other_account, self.member)

        self.client.force_login(self.user)
        bound = self.create_token(["storage:read"], account_id=other_account.id).json()["token"]

        api = Client()
        response = api.get("/api/v1/storage/all/", **self.bearer(bound))
        self.assertEqual(response.status_code, 200, response.content)
        ids = {row["id"] for row in response.json()}
        self.assertIn(theirs.id, ids)
        self.assertNotIn(mine.id, ids)
        # The member's console selection is untouched by the bound request.
        self.assertEqual(self.member.get_current_account(), self.account)

    def test_token_lists_are_per_member(self):
        self.client.force_login(self.user)
        self.create_token(["profile"], name="mine")
        _, other_member, other_user = factories.make_account()
        other = Client()
        other.force_login(other_user)
        self.assertEqual(other.get("/api/v1/tokens/").json(), [])


class ApiTokenLifecycleTests(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        body = self.create_token(["schedules:read"]).json()
        self.secret = body["token"]
        self.token_id = body["id"]
        self.api = Client()

    def test_revoke_keeps_the_row_as_audit_trail(self):
        response = self.client.delete(f"/api/v1/tokens/{self.token_id}/")
        self.assertEqual(response.status_code, 204)
        token = CoreApiToken.objects.get(pk=self.token_id)
        self.assertIsNotNone(token.revoked_at)
        self.assertEqual(self.client.get(f"/api/v1/tokens/{self.token_id}/").json()["status"], "revoked")
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)

    def test_rotate_replaces_the_secret(self):
        response = self.client.post(
            f"/api/v1/tokens/{self.token_id}/rotate/",
            {"current_password": PASSWORD},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        rotated = response.json()["token"]
        self.assertNotEqual(rotated, self.secret)
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(self.secret)).status_code, 401)
        self.assertEqual(self.api.get("/api/v1/schedules/", **self.bearer(rotated)).status_code, 200)

    def test_rotate_requires_password_and_refuses_revoked_tokens(self):
        response = self.client.post(
            f"/api/v1/tokens/{self.token_id}/rotate/",
            {"current_password": "wrong"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.client.delete(f"/api/v1/tokens/{self.token_id}/")
        response = self.client.post(
            f"/api/v1/tokens/{self.token_id}/rotate/",
            {"current_password": PASSWORD},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409)

    def test_other_members_cannot_see_or_revoke_the_token(self):
        _, _, other_user = factories.make_account()
        other = Client()
        other.force_login(other_user)
        self.assertEqual(other.get(f"/api/v1/tokens/{self.token_id}/").status_code, 404)
        self.assertEqual(other.delete(f"/api/v1/tokens/{self.token_id}/").status_code, 404)

    @override_settings(API_TOKEN_MAX_TTL_SECONDS=600)
    def test_max_lifetime_is_enforced_by_the_model_too(self):
        with self.assertRaises(ValueError):
            CoreApiToken.issue(
                member=self.member,
                account=self.account,
                name="x",
                scopes=["profile"],
                ttl_seconds=601,
            )
