"""OAuth 2.0 authorization server: registration, PKCE flow, refresh, revocation."""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlencode, urlparse

from datetime import timedelta

from django.core.cache import cache
from django.test import Client
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)

from apps.api.oauth2.maintenance import SWEEP_CACHE_KEY, sweep_expired_credentials_if_due
from apps.console.member.models import CoreMemberAccount
from apps.tests import factories
from apps.tests.base import BaseTestCase

Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()

PASSWORD = "x-Secret-123"
REDIRECT_URI = "backupsheep://oauth/callback"


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def basic_auth(client_id, client_secret):
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class OAuthMixin:
    def register_public_app(self, *, redirect_uris=(REDIRECT_URI,), name="Mobile app"):
        response = self.client.post(
            "/api/v1/oauth/applications/",
            {
                "name": name,
                "client_type": "public",
                "authorization_grant_type": "authorization-code",
                "redirect_uris": list(redirect_uris),
                "current_password": PASSWORD,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def authorize_params(self, client_id, challenge, scope="profile backups:read", **extra):
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "state": "state-123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        params.update(extra)
        return params

    def consent(self, params, allow=True):
        """GET the consent page then submit it, returning the redirect response."""
        page = self.client.get("/o/authorize/", params)
        self.assertEqual(page.status_code, 200, page.content[:500])
        form = {
            "redirect_uri": params["redirect_uri"],
            "scope": params["scope"],
            "client_id": params["client_id"],
            "state": params["state"],
            "response_type": params["response_type"],
            "code_challenge": params["code_challenge"],
            "code_challenge_method": params["code_challenge_method"],
        }
        if allow:
            form["allow"] = "Authorize"
        return self.client.post("/o/authorize/", form)

    def exchange_code(self, code, client_id, verifier, client=None):
        client = client or Client()
        return client.post(
            "/o/token/",
            urlencode(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": client_id,
                    "code_verifier": verifier,
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

    def obtain_tokens(self, scope="profile backups:read"):
        app = self.register_public_app()
        verifier, challenge = pkce_pair()
        redirect = self.consent(self.authorize_params(app["client_id"], challenge, scope=scope))
        self.assertEqual(redirect.status_code, 302)
        code = parse_qs(urlparse(redirect["Location"]).query)["code"][0]
        response = self.exchange_code(code, app["client_id"], verifier)
        self.assertEqual(response.status_code, 200, response.content)
        return app, response.json()


class OAuthApplicationRegistrationTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)

    def test_public_application_has_no_secret(self):
        app = self.register_public_app()
        self.assertIsNone(app["client_secret"])
        self.assertEqual(app["redirect_uris"], [REDIRECT_URI])
        stored = Application.objects.get(client_id=app["client_id"])
        self.assertEqual(stored.user, self.user)
        self.assertEqual(stored.client_type, Application.CLIENT_PUBLIC)
        self.assertNotIn("client_secret", self.client.get(f"/api/v1/oauth/applications/{app['id']}/").json())

    def test_confidential_application_secret_is_returned_once_and_hashed(self):
        response = self.client.post(
            "/api/v1/oauth/applications/",
            {
                "name": "Server integration",
                "client_type": "confidential",
                "authorization_grant_type": "client-credentials",
                "current_password": PASSWORD,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertTrue(body["client_secret"])
        stored = Application.objects.get(client_id=body["client_id"])
        self.assertNotEqual(stored.client_secret, body["client_secret"])
        self.assertNotIn("client_secret", self.client.get(f"/api/v1/oauth/applications/{body['id']}/").json())

    def test_registration_validates_redirect_uris_grant_and_password(self):
        cases = [
            ({"redirect_uris": []}, "redirect_uris"),
            ({"redirect_uris": ["http://evil.example/callback"]}, "redirect_uris"),
            ({"redirect_uris": ["javascript:alert(1)"]}, "redirect_uris"),
            ({"authorization_grant_type": "client-credentials"}, "client_type"),
            ({"current_password": "wrong"}, "current_password"),
        ]
        for overrides, field in cases:
            payload = {
                "name": "x",
                "client_type": "public",
                "authorization_grant_type": "authorization-code",
                "redirect_uris": [REDIRECT_URI],
                "current_password": PASSWORD,
            }
            payload.update(overrides)
            with self.subTest(overrides=overrides):
                response = self.client.post(
                    "/api/v1/oauth/applications/", payload, content_type="application/json"
                )
                self.assertEqual(response.status_code, 400, response.content)
                self.assertIn(field, response.json())

    def test_applications_are_owner_scoped(self):
        app = self.register_public_app()
        _, _, other_user = factories.make_account()
        other = Client()
        other.force_login(other_user)
        self.assertEqual(other.get("/api/v1/oauth/applications/").json(), [])
        self.assertEqual(other.get(f"/api/v1/oauth/applications/{app['id']}/").status_code, 404)
        self.assertEqual(other.delete(f"/api/v1/oauth/applications/{app['id']}/").status_code, 404)

    def test_update_and_delete(self):
        app = self.register_public_app()
        response = self.client.patch(
            f"/api/v1/oauth/applications/{app['id']}/",
            {"name": "Renamed", "redirect_uris": ["https://app.example.com/cb"]},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["redirect_uris"], ["https://app.example.com/cb"])
        response = self.client.patch(
            f"/api/v1/oauth/applications/{app['id']}/",
            {"redirect_uris": []},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.delete(f"/api/v1/oauth/applications/{app['id']}/").status_code, 204)
        self.assertFalse(Application.objects.filter(pk=app["id"]).exists())

    def test_rotate_secret_only_for_confidential_clients(self):
        app = self.register_public_app()
        response = self.client.post(
            f"/api/v1/oauth/applications/{app['id']}/rotate_secret/",
            {"current_password": PASSWORD},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409)


class AuthorizationCodeFlowTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)

    def test_consent_page_shows_scopes_and_locks_csp_to_the_client(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        page = self.client.get("/o/authorize/", self.authorize_params(app["client_id"], challenge))
        self.assertEqual(page.status_code, 200)
        content = page.content.decode()
        self.assertIn("Mobile app", content)
        self.assertIn("backups:read", content)
        self.assertIn("List backups, restores", content)
        csp = page["Content-Security-Policy"]
        self.assertIn("form-action 'self' backupsheep:", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertEqual(page["Referrer-Policy"], "no-referrer")

    def test_full_pkce_flow_issues_scoped_tokens(self):
        app, tokens = self.obtain_tokens()
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertEqual(set(tokens["scope"].split()), {"profile", "backups:read"})
        self.assertIn("refresh_token", tokens)

        api = Client()
        auth = {"HTTP_AUTHORIZATION": f"Bearer {tokens['access_token']}"}
        self.assertEqual(api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 200)
        self.assertEqual(api.get("/api/v1/backups/website/", **auth).status_code, 200)
        denied = api.get("/api/v1/schedules/", **auth)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["required_scope"], "schedules:read")
        self.assertEqual(api.get("/api/v1/tokens/", **auth).status_code, 403)

        # Tokens are stored hashed: the raw value never lands in the database.
        stored = AccessToken.objects.get(application__client_id=app["client_id"])
        self.assertEqual(stored.token, "")
        self.assertEqual(stored.user, self.user)

    def test_state_and_issuer_are_echoed_on_the_redirect(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        redirect = self.consent(self.authorize_params(app["client_id"], challenge))
        query = parse_qs(urlparse(redirect["Location"]).query)
        self.assertEqual(query["state"], ["state-123"])
        self.assertIn("iss", query)
        self.assertTrue(redirect["Location"].startswith(REDIRECT_URI))

    def test_denied_consent_redirects_with_access_denied(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        redirect = self.consent(self.authorize_params(app["client_id"], challenge), allow=False)
        self.assertEqual(redirect.status_code, 302)
        self.assertIn("error=access_denied", redirect["Location"])
        self.assertFalse(AccessToken.objects.exists())

    def test_pkce_is_mandatory_and_plain_is_refused(self):
        app = self.register_public_app()
        params = self.authorize_params(app["client_id"], "ignored")
        params.pop("code_challenge")
        params.pop("code_challenge_method")
        response = self.client.get("/o/authorize/", params)
        self.assertEqual(response.status_code, 302, response.content[:200])
        self.assertIn("error=invalid_request", response["Location"])
        self.assertTrue(response["Location"].startswith(REDIRECT_URI))
        self.assertFalse(AccessToken.objects.exists())

        params = self.authorize_params(app["client_id"], "plain-challenge", code_challenge_method="plain")
        response = self.client.get("/o/authorize/", params)
        self.assertEqual(response.status_code, 302, response.content[:200])
        self.assertIn("error=invalid_request", response["Location"])

    def test_wrong_verifier_or_redirect_uri_is_rejected(self):
        app = self.register_public_app()
        verifier, challenge = pkce_pair()
        redirect = self.consent(self.authorize_params(app["client_id"], challenge))
        code = parse_qs(urlparse(redirect["Location"]).query)["code"][0]
        response = self.exchange_code(code, app["client_id"], "not-the-verifier")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_unregistered_redirect_uri_never_redirects(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        params = self.authorize_params(app["client_id"], challenge, redirect_uri="https://evil.example/cb")
        response = self.client.get("/o/authorize/", params)
        self.assertEqual(response.status_code, 400)
        self.assertIn("form-action 'self'", response["Content-Security-Policy"])

    def test_implicit_and_password_grants_are_disabled(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        params = self.authorize_params(app["client_id"], challenge, response_type="token")
        response = self.client.get("/o/authorize/", params)
        self.assertIn(response.status_code, (302, 400))
        self.assertFalse(AccessToken.objects.exists())

        response = Client().post(
            "/o/token/",
            urlencode(
                {
                    "grant_type": "password",
                    "username": self.user.username,
                    "password": PASSWORD,
                    "client_id": app["client_id"],
                    "scope": "profile",
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AccessToken.objects.exists())

    def test_anonymous_authorization_request_redirects_to_console_login(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        response = Client().get("/o/authorize/", self.authorize_params(app["client_id"], challenge))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/login?next=/o/authorize/"), response["Location"])

    def test_member_without_active_workspace_cannot_consent(self):
        app = self.register_public_app()
        CoreMemberAccount.objects.filter(member=self.member).update(
            status=CoreMemberAccount.Status.SUSPENDED
        )
        _, challenge = pkce_pair()
        response = self.client.get("/o/authorize/", self.authorize_params(app["client_id"], challenge))
        # The session middleware ends the suspended session; either way no consent page.
        self.assertIn(response.status_code, (302, 403))
        self.assertFalse(AccessToken.objects.exists())

    def test_unknown_scope_is_rejected(self):
        app = self.register_public_app()
        _, challenge = pkce_pair()
        params = self.authorize_params(app["client_id"], challenge, scope="profile admin")
        response = self.client.get("/o/authorize/", params)
        self.assertIn(response.status_code, (302, 400))
        if response.status_code == 302:
            self.assertIn("invalid_scope", response["Location"])


class RefreshAndRevocationTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        self.app, self.tokens = self.obtain_tokens()
        self.api = Client()

    def refresh(self, refresh_token):
        return self.api.post(
            "/o/token/",
            urlencode(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.app["client_id"],
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

    def test_refresh_rotates_and_replay_revokes_the_family(self):
        first = self.refresh(self.tokens["refresh_token"])
        self.assertEqual(first.status_code, 200, first.content)
        rotated = first.json()
        self.assertNotEqual(rotated["refresh_token"], self.tokens["refresh_token"])
        auth = {"HTTP_AUTHORIZATION": f"Bearer {rotated['access_token']}"}
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 200)

        # Replaying the original refresh token after the grace window is an attack
        # signal: the whole family, including the freshly rotated pair, is revoked.
        RefreshToken.objects.update(revoked=RefreshToken.objects.first().revoked and RefreshToken.objects.first().revoked - __import__("datetime").timedelta(seconds=120))
        replay = self.refresh(self.tokens["refresh_token"])
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 401)

    def test_revocation_endpoint_ends_access(self):
        auth = {"HTTP_AUTHORIZATION": f"Bearer {self.tokens['access_token']}"}
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 200)
        response = self.api.post(
            "/o/revoke_token/",
            urlencode({"token": self.tokens["access_token"], "client_id": self.app["client_id"]}),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 401)

    def test_logout_with_an_oauth_token_revokes_that_token(self):
        auth = {"HTTP_AUTHORIZATION": f"Bearer {self.tokens['access_token']}"}
        self.assertEqual(self.api.post("/api/v1/auth/logout/", **auth).status_code, 200)
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 401)
        self.assertEqual(self.refresh(self.tokens["refresh_token"]).status_code, 400)

    def test_authorized_applications_can_be_listed_and_revoked(self):
        response = self.client.get("/api/v1/oauth/authorized-applications/")
        self.assertEqual(response.status_code, 200)
        rows = response.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["application"]["client_id"], self.app["client_id"])
        self.assertEqual(rows[0]["scopes"], ["backups:read", "profile"])

        response = self.client.delete(f"/api/v1/oauth/authorized-applications/{self.app['id']}/")
        self.assertEqual(response.status_code, 204)
        auth = {"HTTP_AUTHORIZATION": f"Bearer {self.tokens['access_token']}"}
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 401)
        self.assertEqual(self.refresh(self.tokens["refresh_token"]).status_code, 400)
        self.assertEqual(self.client.get("/api/v1/oauth/authorized-applications/").json(), [])

    def test_access_token_stops_working_when_membership_is_suspended(self):
        CoreMemberAccount.objects.filter(member=self.member).update(
            status=CoreMemberAccount.Status.SUSPENDED
        )
        auth = {"HTTP_AUTHORIZATION": f"Bearer {self.tokens['access_token']}"}
        self.assertEqual(self.api.get("/api/v1/mobile/bootstrap/", **auth).status_code, 401)
        self.assertEqual(self.refresh(self.tokens["refresh_token"]).status_code, 400)

    def test_access_token_in_query_string_is_refused(self):
        response = self.api.get(
            "/api/v1/mobile/bootstrap/", {"access_token": self.tokens["access_token"]}
        )
        self.assertEqual(response.status_code, 401)


class ClientCredentialsTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        response = self.client.post(
            "/api/v1/oauth/applications/",
            {
                "name": "Server integration",
                "client_type": "confidential",
                "authorization_grant_type": "client-credentials",
                "current_password": PASSWORD,
            },
            content_type="application/json",
        )
        self.app = response.json()
        self.api = Client()

    def token(self, scope="profile storage:read", secret=None):
        return self.api.post(
            "/o/token/",
            urlencode({"grant_type": "client_credentials", "scope": scope}),
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION=basic_auth(self.app["client_id"], secret or self.app["client_secret"]),
        )

    def test_client_credentials_token_acts_as_the_owner(self):
        response = self.token()
        self.assertEqual(response.status_code, 200, response.content)
        access = response.json()["access_token"]
        self.assertNotIn("refresh_token", response.json())
        auth = {"HTTP_AUTHORIZATION": f"Bearer {access}"}
        bootstrap = self.api.get("/api/v1/mobile/bootstrap/", **auth)
        self.assertEqual(bootstrap.status_code, 200, bootstrap.content)
        self.assertEqual(self.api.get("/api/v1/storage/all/", **auth).status_code, 200)
        self.assertEqual(self.api.get("/api/v1/schedules/", **auth).status_code, 403)

    def test_wrong_secret_is_rejected(self):
        self.assertEqual(self.token(secret="nope").status_code, 401)

    def test_rotating_the_secret_invalidates_the_old_one(self):
        response = self.client.post(
            f"/api/v1/oauth/applications/{self.app['id']}/rotate_secret/",
            {"current_password": PASSWORD},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        new_secret = response.json()["client_secret"]
        self.assertEqual(self.token().status_code, 401)
        self.assertEqual(self.token(secret=new_secret).status_code, 200)

    def test_owner_without_active_workspace_cannot_mint_tokens(self):
        CoreMemberAccount.objects.filter(member=self.member).update(
            status=CoreMemberAccount.Status.SUSPENDED
        )
        self.assertEqual(self.token().status_code, 400)


class ExpiredCredentialSweepTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        cache.delete(SWEEP_CACHE_KEY)

    def test_token_endpoint_sweeps_expired_rows_at_most_once_per_interval(self):
        app, tokens = self.obtain_tokens()
        stale = AccessToken.objects.create(
            user=self.user,
            application=Application.objects.get(client_id=app["client_id"]),
            token="stale-token",
            scope="profile",
            expires=timezone.now() - timedelta(days=400),
        )
        cache.delete(SWEEP_CACHE_KEY)
        self.assertTrue(sweep_expired_credentials_if_due())
        self.assertFalse(AccessToken.objects.filter(pk=stale.pk).exists())
        # The live token issued moments ago survives, and the gate holds.
        self.assertTrue(AccessToken.objects.filter(token_checksum=hashlib.sha256(tokens["access_token"].encode()).hexdigest()).exists())
        self.assertFalse(sweep_expired_credentials_if_due())

    def test_issuing_a_token_triggers_the_sweep_when_due(self):
        cache.delete(SWEEP_CACHE_KEY)
        self.obtain_tokens()
        # obtain_tokens exchanged a code at /o/token/, which claimed the gate.
        self.assertIsNotNone(cache.get(SWEEP_CACHE_KEY))


class DiscoveryAndThrottlingTests(OAuthMixin, BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()

    def test_metadata_document_describes_the_hardened_server(self):
        response = Client().get("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["authorization_endpoint"].endswith("/o/authorize/"))
        self.assertTrue(data["token_endpoint"].endswith("/o/token/"))
        self.assertTrue(data["revocation_endpoint"].endswith("/o/revoke_token/"))
        self.assertEqual(data["response_types_supported"], ["code"])
        self.assertEqual(data["code_challenge_methods_supported"], ["S256"])
        self.assertNotIn("password", data["grant_types_supported"])
        self.assertNotIn("implicit", data["grant_types_supported"])
        self.assertIn("backups:restore", data["scopes_supported"])

    def test_token_endpoint_is_throttled_per_peer(self):
        api = Client()
        statuses = []
        for _ in range(61):
            response = api.post(
                "/o/token/",
                urlencode({"grant_type": "authorization_code", "code": "x", "client_id": "nope"}),
                content_type="application/x-www-form-urlencoded",
            )
            statuses.append(response.status_code)
        self.assertEqual(statuses[-1], 429)
        self.assertTrue(all(status in (400, 401) for status in statuses[:30]))
