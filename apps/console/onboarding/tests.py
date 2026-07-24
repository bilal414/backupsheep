from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from apps.console.account.models import CoreAccount
from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from utils.middleware import OnboardingMiddleware

User = get_user_model()

PW = "Sup3r-Secret-Pw!"
INSTALL_TOKEN = "test-install-token"


@override_settings(ONBOARDING_INSTALL_TOKEN=INSTALL_TOKEN)
class OnboardingFlowTests(TestCase):
    def setUp(self):
        # OnboardingMiddleware caches "setup completed" in a process-global latch; reset it
        # so each test starts from a clean, not-configured state.
        OnboardingMiddleware._completed = False
        self.client = Client()

    def tearDown(self):
        OnboardingMiddleware._completed = False

    def _create_admin(self, email="ada@example.com", install_token=INSTALL_TOKEN):
        return self.client.post(
            "/onboarding/account/",
            {"full_name": "Ada Admin", "organization": "Acme", "email": email,
             "password1": PW, "password2": PW, "install_token": install_token},
        )

    def test_anonymous_is_forced_into_wizard(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].startswith("/onboarding"))

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_healthcheck_bypasses_onboarding_and_login_gates(self):
        r = self.client.get("/healthz/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"ok")

    def test_account_creation_rejects_missing_or_wrong_install_token(self):
        for bad_token in ("", "wrong-token"):
            r = self._create_admin(install_token=bad_token)
            self.assertEqual(r.status_code, 200)  # re-rendered with an error
            self.assertIn("Invalid install token", r.content.decode())
            self.assertEqual(User.objects.count(), 0)

    def test_account_creation_builds_chain_and_logs_in(self):
        r = self._create_admin()
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/onboarding/settings/"))

        self.assertEqual(User.objects.count(), 1)
        user = User.objects.get()
        self.assertFalse(user.is_superuser)  # console is reserved for non-superusers
        self.assertEqual(CoreMember.objects.count(), 1)

        account = CoreAccount.objects.get()
        self.assertTrue(account.encryption_key)  # Fernet key generated

        membership = CoreMemberAccount.objects.get()
        self.assertTrue(membership.primary)
        self.assertTrue(membership.current)
        self.assertEqual(membership.status, CoreMemberAccount.Status.ACTIVE)

        self.assertIn("_auth_user_id", self.client.session)  # auto-logged-in

    def test_full_flow_completes_and_locks_wizard(self):
        self._create_admin()
        self.client.post(
            "/onboarding/settings/",
            {"app_name": "My BS", "app_protocol": "https://", "app_domain": "bs.test",
             "default_timezone": "UTC"},
        )
        self.assertEqual(CoreSiteSettings.load().app_name, "My BS")

        self.client.post("/onboarding/email/", {"email_provider": "none", "action": "continue"})

        r = self.client.post("/onboarding/finish/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/console")
        self.assertTrue(CoreSiteSettings.load().setup_completed)

        # Wizard is now locked.
        r = self.client.get("/onboarding/account/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/console")

    def test_account_step_refuses_a_second_admin(self):
        self._create_admin()
        self.client.logout()
        OnboardingMiddleware._completed = False

        r = self.client.get("/onboarding/account/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "already")

        before = User.objects.count()
        self._create_admin(email="evil@example.com")
        self.assertEqual(User.objects.count(), before)

    def test_email_test_action_without_provider_warns_not_crashes(self):
        self._create_admin()
        r = self.client.post("/onboarding/email/", {"email_provider": "none", "action": "test"})
        self.assertEqual(r.status_code, 200)  # re-renders with a warning

    def test_storage_step_lists_seeded_providers(self):
        self._create_admin()
        r = self.client.get("/onboarding/storage/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Amazon S3")  # from the seeded catalog


class SiteSettingsModelTests(TestCase):
    def test_email_credentials_encrypted_roundtrip(self):
        s = CoreSiteSettings.load()
        s.email_provider = "postmark"
        s.set_email_credentials({"postmark": {"api_key": "secret-xyz"}})
        s.save()

        again = CoreSiteSettings.load()
        self.assertTrue(again.email_credentials_encrypted)
        self.assertNotIn("secret-xyz", again.email_credentials_encrypted)  # not plaintext
        self.assertEqual(again.email_credentials["postmark"]["api_key"], "secret-xyz")
        self.assertEqual(again.email_cred("api_key"), "secret-xyz")

    def test_singleton(self):
        a = CoreSiteSettings.load()
        a.app_name = "One"
        a.save()
        b = CoreSiteSettings.load()
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(CoreSiteSettings.objects.count(), 1)
