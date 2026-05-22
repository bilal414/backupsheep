from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    s = CoreSiteSettings.load()
    s.setup_completed = True
    s.save()
    OnboardingMiddleware._completed = False  # force re-read of the DB flag


class GatingTests(BaseTestCase):
    def test_not_configured_forces_console_traffic_to_wizard(self):
        r = self.client.get("/console/")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].startswith("/onboarding"))

    def test_configured_anonymous_redirects_to_login(self):
        _mark_configured()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login")

    def test_configured_locks_the_wizard(self):
        _mark_configured()
        self.client.force_login(self.user)
        r = self.client.get("/onboarding/account/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/console")


class LoginEndpointTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()  # so OnboardingMiddleware doesn't intercept /api/

    def test_login_with_email_and_password_succeeds(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": self.user.email, "password": "x-Secret-123"},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("api_key", r.json())

    def test_login_with_wrong_password_fails(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": self.user.email, "password": "wrong"},
                             content_type="application/json")
        self.assertNotEqual(r.status_code, 200)

    def test_login_with_unknown_email_fails(self):
        r = self.client.post("/api/v1/auth/login/",
                             {"email": "nobody@example.com", "password": "x-Secret-123"},
                             content_type="application/json")
        self.assertNotEqual(r.status_code, 200)
