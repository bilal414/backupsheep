from unittest import mock

from django.test import Client, override_settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.api.v1.utils.oauth_security import OAUTH_STATE_SESSION_KEY
from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


def _mark_configured():
    site = CoreSiteSettings.load()
    site.setup_completed = True
    site.save(update_fields=["setup_completed"])
    OnboardingMiddleware._completed = False


@override_settings(
    APP_URL="https://demo.backupsheep.com",
    BASECAMP_OAUTH_ENDPOINT="https://launchpad.37signals.com/authorization/new",
    BASECAMP_CLIENT_ID="basecamp-client",
    BASECAMP_REDIRECT_URL="/api/v1/callback/basecamp",
    BASECAMP_INTEGRATION_ENABLED=True,
    BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
    BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="legacy-only",
    BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
    DIGITALOCEAN_APP_CLIENT_ID="digitalocean-client",
    DROPBOX_APP_KEY="dropbox-client",
    GOOGLE_CLIENT_ID="google-client",
    MS_OAUTH_ENDPOINT=(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    ),
    MS_CLIENT_ID="microsoft-client",
    MS_RESPONSE_TYPE="code",
    MS_SCOPE="Files.ReadWrite offline_access",
    MS_REDIRECT_URL="/api/v1/callback/microsoft",
    PCLOUD_AUTH_URL="https://my.pcloud.com/oauth2/authorize",
    PCLOUD_CLIENT_ID="pcloud-client",
    PCLOUD_RESPONSE_TYPE="code",
    PCLOUD_REDIRECT_URL="/api/v1/callback/pcloud/",
    SLACK_CLIENT_ID="slack-client",
    SLACK_CLIENT_SECRET="slack-secret",
    SLACK_TOKEN_URL="https://slack.com/api/oauth.v2.access",
)
class OAuthStartSecurityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()
        self.browser = Client(enforce_csrf_checks=True)
        self.browser.force_login(self.user)

    def _csrf(self):
        response = self.browser.get("/console/settings/account/")
        self.assertEqual(response.status_code, 200, response.content)
        return self.browser.cookies["csrftoken"].value

    def _pending(self, provider):
        return dict(self.browser.session[OAUTH_STATE_SESSION_KEY][provider])

    def test_digitalocean_start_is_post_csrf_protected_and_explicitly_rotates(self):
        url = "/api/v1/connections/digitalocean/oauth_url/"
        self.assertEqual(self.browser.get(url, {"name": "team"}).status_code, 405)
        self.assertNotIn(OAUTH_STATE_SESSION_KEY, self.browser.session)

        missing_csrf = self.browser.post(
            url,
            {"name": "team"},
            content_type="application/json",
            HTTP_SEC_FETCH_SITE="same-origin",
        )
        self.assertEqual(missing_csrf.status_code, 403, missing_csrf.content)
        self.assertNotIn(OAUTH_STATE_SESSION_KEY, self.browser.session)

        csrf = self._csrf()
        first = self.browser.post(
            url,
            {"name": "team"},
            content_type="application/json",
            HTTP_SEC_FETCH_SITE="same-origin",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(first.status_code, 200, first.content)
        first_state = self._pending("digitalocean")["state"]
        self.assertIn(first_state, first.json()["oauth_url"])

        second = self.browser.post(
            url,
            {"name": "team"},
            content_type="application/json",
            HTTP_SEC_FETCH_SITE="same-origin",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(second.status_code, 200, second.content)
        self.assertNotEqual(self._pending("digitalocean")["state"], first_state)

    def test_every_ovh_start_rejects_get_missing_csrf_and_cross_site_post(self):
        csrf = self._csrf()
        cases = (
            ("ovh_ca", "apps.api.v1.connection.ovh_ca.views"),
            ("ovh_eu", "apps.api.v1.connection.ovh_eu.views"),
            ("ovh_us", "apps.api.v1.connection.ovh_us.views"),
        )
        for provider, module in cases:
            url = f"/api/v1/connections/{provider}/oauth_url/"
            with self.subTest(provider=provider), mock.patch(
                f"{module}.prepare_ovh_authorization",
                return_value=f"https://{provider}.example/authorize",
            ) as prepare:
                self.assertEqual(self.browser.get(url).status_code, 405)
                self.assertEqual(
                    self.browser.post(
                        url,
                        {},
                        content_type="application/json",
                        HTTP_SEC_FETCH_SITE="same-origin",
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    self.browser.post(
                        url,
                        {},
                        content_type="application/json",
                        HTTP_SEC_FETCH_SITE="cross-site",
                        HTTP_X_CSRFTOKEN=csrf,
                    ).status_code,
                    403,
                )
                allowed = self.browser.post(
                    url,
                    {},
                    content_type="application/json",
                    HTTP_SEC_FETCH_SITE="same-origin",
                    HTTP_X_CSRFTOKEN=csrf,
                )
                self.assertEqual(allowed.status_code, 200, allowed.content)
                prepare.assert_called_once()

    def test_oauth_start_is_browser_session_only_not_api_token_authenticated(self):
        token = Token.objects.create(user=self.user)
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        for provider in ("digitalocean", "ovh_ca", "ovh_eu", "ovh_us"):
            with self.subTest(provider=provider):
                response = api.post(
                    f"/api/v1/connections/{provider}/oauth_url/",
                    {"name": "team"},
                    format="json",
                    HTTP_SEC_FETCH_SITE="same-origin",
                )
                self.assertEqual(response.status_code, 403, response.content)

    def test_console_gets_reuse_every_live_oauth_and_pkce_transaction(self):
        pages = (
            ("basecamp", "/console/integration/basecamp/"),
            ("dropbox", "/console/integration/storage/dropbox/"),
            ("google_drive", "/console/integration/storage/google_drive/"),
            ("pcloud", "/console/integration/storage/pcloud/"),
            ("microsoft", "/console/integration/storage/onedrive/"),
            ("slack", "/console/settings/notifications/"),
        )
        for provider, url in pages:
            with self.subTest(provider=provider):
                first_response = self.browser.get(url)
                self.assertEqual(
                    first_response.status_code, 200, first_response.content
                )
                first = self._pending(provider)
                second_response = self.browser.get(url)
                self.assertEqual(
                    second_response.status_code, 200, second_response.content
                )
                self.assertEqual(self._pending(provider), first)

        pending = self.browser.session[OAUTH_STATE_SESSION_KEY]
        self.assertEqual(set(pending), {provider for provider, _url in pages})
        for provider in ("dropbox", "google_drive", "microsoft"):
            self.assertIn("code_verifier", pending[provider])
            self.assertIn("code_challenge", pending[provider])
