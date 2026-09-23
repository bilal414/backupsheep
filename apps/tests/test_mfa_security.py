import time
from unittest import mock

from django.test import Client
from rest_framework.authtoken.models import Token

from apps.console.member.totp import totp_for_counter
from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import AUTH_SESSION_VERSION_KEY, OnboardingMiddleware


def _mark_configured():
    settings_row = CoreSiteSettings.load()
    settings_row.setup_completed = True
    settings_row.save()
    OnboardingMiddleware._completed = False


class TOTPPrimitiveTests(BaseTestCase):
    def test_rfc_6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(totp_for_counter(secret, 1, digits=8), "94287082")


class MFASecurityTests(BaseTestCase):
    FIXED_TIME = 1_700_000_000

    def setUp(self):
        super().setUp()
        _mark_configured()

    def _enable_mfa(self):
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        counter = self.FIXED_TIME // 30
        self.member.set_pending_totp_secret(secret, "Primary authenticator")
        enrollment_token = totp_for_counter(secret, counter)
        self.assertTrue(
            self.member.verify_pending_totp(
                enrollment_token, at_time=self.FIXED_TIME
            )
        )
        return secret, counter

    def test_secret_is_encrypted_and_totp_counter_cannot_be_replayed(self):
        secret, counter = self._enable_mfa()
        self.member.refresh_from_db()
        self.assertNotIn(secret.encode(), bytes(self.member.auth_multi_factor_secret))
        self.assertTrue(self.member.mfa_enabled)

        # Enrollment burns this counter, while the next period succeeds once.
        self.assertFalse(
            self.member.consume_totp(
                totp_for_counter(secret, counter), at_time=self.FIXED_TIME
            )
        )
        next_time = self.FIXED_TIME + 30
        next_token = totp_for_counter(secret, counter + 1)
        self.assertTrue(self.member.consume_totp(next_token, at_time=next_time))
        self.assertFalse(self.member.consume_totp(next_token, at_time=next_time))

    def test_login_requires_mfa_before_session_or_bearer_token_is_issued(self):
        secret, counter = self._enable_mfa()
        # Permit the current counter for the login phase of this deterministic test.
        self.member.auth_multi_factor_last_counter = counter - 1
        self.member.save(update_fields=["auth_multi_factor_last_counter"])

        first = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "x-Secret-123"},
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertTrue(first.json()["auth_multi_factor"])
        self.assertNotIn("api_key", first.json())
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

        current_token = totp_for_counter(secret, counter)
        with mock.patch("apps.console.member.totp.time.time", return_value=self.FIXED_TIME):
            second = self.client.post(
                "/api/v1/auth/login/",
                {
                    "email": self.user.email,
                    "password": "x-Secret-123",
                    "auth_multi_factor_token": current_token,
                },
                content_type="application/json",
            )
        self.assertEqual(second.status_code, 200, second.content)
        self.assertIn("api_key", second.json())

        other_browser = Client()
        with mock.patch("apps.console.member.totp.time.time", return_value=self.FIXED_TIME):
            replay = other_browser.post(
                "/api/v1/auth/login/",
                {
                    "email": self.user.email,
                    "password": "x-Secret-123",
                    "auth_multi_factor_token": current_token,
                },
                content_type="application/json",
            )
        self.assertEqual(replay.status_code, 400, replay.content)

    def test_setup_requires_current_password_and_never_serializes_secret(self):
        browser = Client()
        browser.force_login(self.user)
        url = f"/api/v1/members/{self.member.pk}/auth_multi_factor_token_setup/"
        denied = browser.post(
            url,
            {"display_name": "Primary authenticator", "current_password": "wrong"},
            content_type="application/json",
        )
        self.assertEqual(denied.status_code, 400, denied.content)

        created = browser.post(
            url,
            {
                "display_name": "Primary authenticator",
                "current_password": "x-Secret-123",
            },
            content_type="application/json",
        )
        self.assertEqual(created.status_code, 200, created.content)
        secret = created.json()["binding"]["secret"]
        detail = browser.get(f"/api/v1/members/{self.member.pk}/")
        self.assertEqual(detail.status_code, 200, detail.content)
        self.assertNotIn(secret, detail.content.decode())
        self.assertNotIn("auth_multi_factor_secret", detail.json())

        page = browser.get("/console/settings/multifactor/")
        self.assertNotIn("cdn.rawgit.com", page.content.decode())

    def test_enabling_mfa_revokes_other_browser_sessions(self):
        primary_browser = Client()
        secondary_browser = Client()
        primary_browser.force_login(self.user)
        secondary_browser.force_login(self.user)

        setup_url = f"/api/v1/members/{self.member.pk}/auth_multi_factor_token_setup/"
        created = primary_browser.post(
            setup_url,
            {
                "display_name": "Primary authenticator",
                "current_password": "x-Secret-123",
            },
            content_type="application/json",
        )
        self.assertEqual(created.status_code, 200, created.content)
        secret = created.json()["binding"]["secret"]
        counter = self.FIXED_TIME // 30
        verify_url = f"/api/v1/members/{self.member.pk}/auth_multi_factor_token_verify/"
        with mock.patch("apps.console.member.totp.time.time", return_value=self.FIXED_TIME):
            verified = primary_browser.post(
                verify_url,
                {"auth_multi_factor_token": totp_for_counter(secret, counter)},
                content_type="application/json",
            )
        self.assertEqual(verified.status_code, 200, verified.content)

        self.member.refresh_from_db()
        self.assertEqual(
            primary_browser.session[AUTH_SESSION_VERSION_KEY],
            self.member.auth_session_version,
        )
        self.assertTrue(primary_browser.get("/api/v1/check/login/").json()["login"])
        self.assertFalse(secondary_browser.get("/api/v1/check/login/").json()["login"])

    def test_revoke_requires_password_and_fresh_totp(self):
        secret, counter = self._enable_mfa()
        self.member.auth_multi_factor_last_counter = counter - 1
        self.member.save(update_fields=["auth_multi_factor_last_counter"])
        current_token = totp_for_counter(secret, counter)
        browser = Client()
        browser.force_login(self.user)
        url = f"/api/v1/members/{self.member.pk}/auth_multi_factor_token_revoke/"

        with mock.patch("apps.console.member.totp.time.time", return_value=self.FIXED_TIME):
            denied = browser.post(
                url,
                {
                    "current_password": "wrong",
                    "auth_multi_factor_token": current_token,
                },
                content_type="application/json",
            )
        self.assertEqual(denied.status_code, 400, denied.content)

        with mock.patch("apps.console.member.totp.time.time", return_value=self.FIXED_TIME):
            revoked = browser.post(
                url,
                {
                    "current_password": "x-Secret-123",
                    "auth_multi_factor_token": current_token,
                },
                content_type="application/json",
            )
        self.assertEqual(revoked.status_code, 200, revoked.content)
        self.member.refresh_from_db()
        self.assertFalse(self.member.mfa_enabled)
        self.assertIsNone(self.member.auth_multi_factor_secret)
