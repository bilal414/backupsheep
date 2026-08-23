from datetime import timedelta

from django.test import Client, override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    settings_row = CoreSiteSettings.load()
    settings_row.setup_completed = True
    settings_row.save()
    OnboardingMiddleware._completed = False


class AuthTokenSecurityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()

    @override_settings(API_TOKEN_TTL_SECONDS=60)
    def test_expired_token_is_rejected_deleted_and_rotated_at_login(self):
        token = Token.objects.create(user=self.user)
        Token.objects.filter(pk=token.pk).update(
            created=timezone.now() - timedelta(seconds=61)
        )

        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(api.get("/api/v1/check/login/").status_code, 401)
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())

        response = self.client.post(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": "x-Secret-123"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotEqual(response.json()["api_key"], token.key)

    def test_logout_requires_post_and_revokes_bearer_token(self):
        token = Token.objects.create(user=self.user)
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        self.assertEqual(api.get("/api/v1/auth/logout/").status_code, 405)
        self.assertTrue(Token.objects.filter(pk=token.pk).exists())
        self.assertEqual(api.post("/api/v1/auth/logout/").status_code, 200)
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())

    def test_password_reset_consumes_link_and_revokes_bearer_token(self):
        token = Token.objects.create(user=self.user)
        self.member.set_pending_totp_secret(
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "Recovery test"
        )
        self.member.auth_multi_factor_enabled_at = timezone.now()
        self.member.auth_multi_factor_pending_created = None
        self.member.save(
            update_fields=[
                "auth_multi_factor_enabled_at",
                "auth_multi_factor_pending_created",
            ]
        )
        self.member.password_reset_token = self.member.generate_password_reset_token()
        self.member.password_reset_token_created = timezone.now()
        self.member.save()
        reset_token = self.member.password_reset_token

        response = self.client.patch(
            "/api/v1/auth/reset/",
            {
                "password": "A-new-Secret-456!",
                "password_confirm": "A-new-Secret-456!",
                "password_token": reset_token,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())
        self.member.refresh_from_db()
        self.assertIsNone(self.member.password_reset_token)
        self.assertFalse(self.member.mfa_enabled)
        self.assertIsNone(self.member.auth_multi_factor_secret)
        replay = self.client.patch(
            "/api/v1/auth/reset/",
            {
                "password": "Another-Secret-789!",
                "password_confirm": "Another-Secret-789!",
                "password_token": reset_token,
            },
            content_type="application/json",
        )
        self.assertNotEqual(replay.status_code, 200)

    def test_password_reset_missing_confirmation_is_validation_error_not_server_error(self):
        response = self.client.patch(
            "/api/v1/auth/reset/",
            {
                "password": "A-new-Secret-456!",
                "password_token": "nonexistent-token",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400, response.content)

    def test_password_change_requires_current_password_and_revokes_token(self):
        token = Token.objects.create(user=self.user)
        browser = Client()
        browser.force_login(self.user)
        url = f"/api/v1/members/{self.member.pk}/"
        payload = {
            "user": {
                "current_password": "wrong-password",
                "password": "A-new-Secret-456!",
                "password_confirm": "A-new-Secret-456!",
            }
        }
        denied = browser.patch(url, payload, content_type="application/json")
        self.assertEqual(denied.status_code, 400, denied.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("x-Secret-123"))

        payload["user"]["current_password"] = "x-Secret-123"
        changed = browser.patch(url, payload, content_type="application/json")
        self.assertEqual(changed.status_code, 200, changed.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("A-new-Secret-456!"))
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())
        self.assertTrue(browser.get("/console/").wsgi_request.user.is_authenticated)
