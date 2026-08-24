import re
from unittest import mock

from django.conf import settings
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.test import Client, override_settings
from rest_framework.authtoken.models import Token

from apps.console.invite.models import CoreInvite
from apps.console.member.totp import totp_for_counter
from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import BrowserSecurityHeadersMiddleware, OnboardingMiddleware


THIRD_PARTY_CANARIES = (
    "googletagmanager",
    "google-analytics",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "jsdelivr",
    "rewardful",
    "wdfl.co",
    "intercom",
    "iubenda",
)


def _mark_configured():
    site = CoreSiteSettings.load()
    site.setup_completed = True
    site.save()
    OnboardingMiddleware._completed = False


class AuthPageIsolationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        _mark_configured()

    def assert_isolated_auth_document(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            BrowserSecurityHeadersMiddleware.AUTH_CONTENT_SECURITY_POLICY,
        )
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

        document = response.content.decode()
        lowered = document.lower()
        for canary in THIRD_PARTY_CANARIES:
            with self.subTest(canary=canary):
                self.assertNotIn(canary, lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotRegex(lowered, r"\son[a-z]+\s*=")
        self.assertNotIn("javascript:", lowered)
        self.assertNotIn("x-data", lowered)
        self.assertNotIn("@click", lowered)

        scripts = re.findall(
            r"<script(?P<attributes>[^>]*)>(?P<body>.*?)</script>",
            document,
            flags=re.IGNORECASE | re.DOTALL,
        )
        self.assertEqual(len(scripts), 1, scripts)
        attributes, body = scripts[0]
        self.assertRegex(attributes, r'src="/static/console/js/auth(?:\.[^/\"]+)?\.js"')
        self.assertEqual(body.strip(), "")

    @override_settings(ALLOWED_HOSTS=["allowed.example"], DEBUG=False)
    def test_invalid_host_fails_closed_as_bad_request(self):
        response = self.client.get(
            "/healthz/",
            HTTP_HOST="attacker.invalid",
            secure=True,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            BrowserSecurityHeadersMiddleware.AUTH_CONTENT_SECURITY_POLICY,
        )
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_login_reset_and_invite_pages_are_third_party_isolated(self):
        invite = CoreInvite.objects.create(
            added_by=self.member,
            account=self.account,
            email="isolated-invite@example.com",
            first_name="Isolated",
            last_name="Invite",
        )
        for path in (
            "/login/",
            "/reset/",
            f"/invite/{invite.uuid}/",
        ):
            with self.subTest(path=path):
                self.assert_isolated_auth_document(self.client.get(path))

    def test_reset_bearer_is_form_state_not_executable_script_content(self):
        reset_token = self.member.issue_password_reset_token()
        response = self.client.get(f"/reset/{reset_token}/")

        self.assert_isolated_auth_document(response)
        document = response.content.decode()
        self.assertIn(
            f'name="password_token" value="{reset_token}"', document
        )
        script_documents = " ".join(
            body
            for _attributes, body in re.findall(
                r"<script([^>]*)>(.*?)</script>",
                document,
                flags=re.IGNORECASE | re.DOTALL,
            )
        )
        self.assertNotIn(reset_token, script_documents)

    def test_static_error_documents_have_no_third_party_resources(self):
        for template in ("400.html", "403.html", "404.html", "500.html"):
            with self.subTest(template=template):
                document = render_to_string(template).lower()
                for canary in THIRD_PARTY_CANARIES:
                    self.assertNotIn(canary, document)
                self.assertNotIn("https://", document)
                self.assertNotIn("<script", document)

        middleware = BrowserSecurityHeadersMiddleware(
            lambda _request: HttpResponse(
                "<h1>Authentication error</h1>",
                status=400,
                content_type="text/html",
            )
        )
        response = middleware(self.client.request().wsgi_request)
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            BrowserSecurityHeadersMiddleware.AUTH_CONTENT_SECURITY_POLICY,
        )


class BrowserSessionLoginTests(BaseTestCase):
    FIXED_TIME = 1_700_000_000

    def setUp(self):
        super().setUp()
        _mark_configured()
        self.browser = Client(enforce_csrf_checks=True)

    def _csrf(self):
        response = self.browser.get("/login/")
        self.assertEqual(response.status_code, 200, response.content)
        return self.browser.cookies["csrftoken"].value

    def _payload(self):
        return {"email": self.user.email, "password": "x-Secret-123"}

    def test_same_origin_browser_login_creates_session_without_api_token(self):
        response = self.browser.post(
            "/api/v1/auth/login/",
            self._payload(),
            content_type="application/json",
            HTTP_X_BACKUPSHEEP_SESSION_LOGIN="1",
            HTTP_SEC_FETCH_SITE="same-origin",
            HTTP_X_CSRFTOKEN=self._csrf(),
            REMOTE_ADDR="192.0.2.201",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn("api_key", response.json())
        self.assertIn("_auth_user_id", self.browser.session)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_browser_marker_fails_closed_without_same_origin_or_csrf_proof(self):
        csrf_token = self._csrf()
        cross_origin = self.browser.post(
            "/api/v1/auth/login/",
            self._payload(),
            content_type="application/json",
            HTTP_X_BACKUPSHEEP_SESSION_LOGIN="1",
            HTTP_SEC_FETCH_SITE="cross-site",
            HTTP_X_CSRFTOKEN=csrf_token,
            REMOTE_ADDR="192.0.2.202",
        )
        self.assertEqual(cross_origin.status_code, 403, cross_origin.content)

        missing_csrf = self.browser.post(
            "/api/v1/auth/login/",
            self._payload(),
            content_type="application/json",
            HTTP_X_BACKUPSHEEP_SESSION_LOGIN="1",
            HTTP_SEC_FETCH_SITE="same-origin",
            REMOTE_ADDR="192.0.2.203",
        )
        self.assertEqual(missing_csrf.status_code, 403, missing_csrf.content)
        self.assertNotIn("_auth_user_id", self.browser.session)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_browser_request_cannot_omit_marker_to_get_native_api_token(self):
        response = self.browser.post(
            "/api/v1/auth/login/",
            self._payload(),
            content_type="application/json",
            HTTP_SEC_FETCH_SITE="same-origin",
            HTTP_X_CSRFTOKEN=self._csrf(),
            REMOTE_ADDR="192.0.2.206",
        )

        self.assertEqual(response.status_code, 403, response.content)
        self.assertNotIn("api_key", response.json())
        self.assertNotIn("_auth_user_id", self.browser.session)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_browser_mfa_challenge_never_returns_or_mints_api_token(self):
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        counter = self.FIXED_TIME // 30
        self.member.set_pending_totp_secret(secret, "Browser authenticator")
        self.assertTrue(
            self.member.verify_pending_totp(
                totp_for_counter(secret, counter), at_time=self.FIXED_TIME
            )
        )
        self.member.auth_multi_factor_last_counter = counter - 1
        self.member.save(update_fields=["auth_multi_factor_last_counter"])
        csrf_token = self._csrf()
        request_headers = {
            "HTTP_X_BACKUPSHEEP_SESSION_LOGIN": "1",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "HTTP_X_CSRFTOKEN": csrf_token,
            "REMOTE_ADDR": "192.0.2.205",
        }

        challenge = self.browser.post(
            "/api/v1/auth/login/",
            self._payload(),
            content_type="application/json",
            **request_headers,
        )
        self.assertEqual(challenge.status_code, 200, challenge.content)
        self.assertTrue(challenge.json()["auth_multi_factor"])
        self.assertNotIn("api_key", challenge.json())
        self.assertNotIn("_auth_user_id", self.browser.session)

        payload = self._payload()
        payload["auth_multi_factor_token"] = totp_for_counter(secret, counter)
        with mock.patch(
            "apps.console.member.totp.time.time", return_value=self.FIXED_TIME
        ):
            authenticated = self.browser.post(
                "/api/v1/auth/login/",
                payload,
                content_type="application/json",
                **request_headers,
            )
        self.assertEqual(authenticated.status_code, 200, authenticated.content)
        self.assertNotIn("api_key", authenticated.json())
        self.assertIn("_auth_user_id", self.browser.session)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_unmarked_native_login_keeps_api_token_contract(self):
        native = Client()
        with mock.patch("apps.api.v1.auth.views.login") as session_login:
            response = native.post(
                "/api/v1/auth/login/",
                self._payload(),
                content_type="application/json",
                REMOTE_ADDR="192.0.2.204",
            )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {"api_key": Token.objects.get(user=self.user).key},
        )
        session_login.assert_not_called()
        self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, native.cookies)

    def test_unmarked_native_login_does_not_mutate_pre_authenticated_session(self):
        native = Client()
        native.force_login(self.user)
        session = native.session
        session["previous_url"] = "/console/private-origin/"
        session["next"] = "/console/private-next/"
        session["django_timezone"] = "America/Chicago"
        session["native-session-canary"] = "unchanged"
        session.save()
        session_key = session.session_key
        session_before = dict(session)

        with mock.patch("apps.api.v1.auth.views.login") as session_login:
            response = native.post(
                "/api/v1/auth/login/",
                self._payload(),
                content_type="application/json",
                REMOTE_ADDR="192.0.2.207",
            )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {"api_key": Token.objects.get(user=self.user).key},
        )
        session_login.assert_not_called()
        self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)
        session_after = native.session
        self.assertEqual(session_after.session_key, session_key)
        self.assertEqual(dict(session_after), session_before)
