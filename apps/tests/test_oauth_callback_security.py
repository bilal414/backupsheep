import base64
import hashlib
import time
from types import SimpleNamespace
from unittest import mock

from django.http import HttpResponseRedirect
from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.callback.views import (
    APICallbackBasecamp,
    APICallbackDigitalOcean,
    APICallbackDropbox,
    APICallbackGoogleDrive,
    APICallbackMicrosoft,
    APICallbackSlack,
    APIGoogleCloud,
    _post_oauth_token,
)
from apps.api.v1.utils.oauth_security import (
    OAUTH_STATE_SESSION_KEY,
    OAUTH_STATE_TTL_SECONDS,
    consume_oauth_state,
    issue_oauth_state,
    validated_https_endpoint,
)


class OAuthStateSecurityTests(SimpleTestCase):
    def setUp(self):
        self.member = SimpleNamespace(pk="member-1")
        self.account = SimpleNamespace(pk="account-1")
        self.request = SimpleNamespace(session={})

    def test_state_is_random_bound_expiring_single_use_and_pkce_protected(self):
        first = issue_oauth_state(
            self.request,
            provider="dropbox",
            member=self.member,
            account=self.account,
            use_pkce=True,
        )
        second_request = SimpleNamespace(session={})
        second = issue_oauth_state(
            second_request,
            provider="dropbox",
            member=self.member,
            account=self.account,
            use_pkce=True,
        )
        self.assertNotEqual(first["state"], second["state"])
        self.assertGreaterEqual(len(first["state"]), 40)
        self.assertNotIn(first["code_verifier"], first["state"])
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(first["code_verifier"].encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(first["code_challenge"], expected_challenge)

        consumed = consume_oauth_state(
            self.request,
            provider="dropbox",
            received_state=first["state"],
            member=self.member,
            account=self.account,
        )
        self.assertEqual(consumed["code_verifier"], first["code_verifier"])
        self.assertNotIn(OAUTH_STATE_SESSION_KEY, self.request.session)
        self.assertIsNone(
            consume_oauth_state(
                self.request,
                provider="dropbox",
                received_state=first["state"],
                member=self.member,
                account=self.account,
            )
        )

    def test_state_rejects_member_account_provider_mismatch_and_expiry(self):
        for replacement in (
            {"member": SimpleNamespace(pk="member-2")},
            {"account": SimpleNamespace(pk="account-2")},
        ):
            request = SimpleNamespace(session={})
            state = issue_oauth_state(
                request,
                provider="basecamp",
                member=self.member,
                account=self.account,
            )
            self.assertIsNone(
                consume_oauth_state(
                    request,
                    provider="basecamp",
                    received_state=state["state"],
                    member=replacement.get("member", self.member),
                    account=replacement.get("account", self.account),
                )
            )

        request = SimpleNamespace(session={})
        state = issue_oauth_state(
            request,
            provider="basecamp",
            member=self.member,
            account=self.account,
        )
        request.session[OAUTH_STATE_SESSION_KEY]["basecamp"]["issued_at"] = (
            time.time() - OAUTH_STATE_TTL_SECONDS - 1
        )
        self.assertIsNone(
            consume_oauth_state(
                request,
                provider="basecamp",
                received_state=state["state"],
                member=self.member,
                account=self.account,
            )
        )

        request = SimpleNamespace(session={})
        state = issue_oauth_state(
            request,
            provider="basecamp",
            member=self.member,
            account=self.account,
        )
        self.assertIsNone(
            consume_oauth_state(
                request,
                provider="dropbox",
                received_state=state["state"],
                member=self.member,
                account=self.account,
            )
        )

    def test_endpoint_allowlist_rejects_confusion_and_credential_urls(self):
        allowed = {"api.dropboxapi.com"}
        options = {"allowed_hostnames": allowed, "allowed_paths": {"/oauth2/token"}}
        self.assertEqual(
            validated_https_endpoint(
                "https://API.DROPBOXAPI.COM./oauth2/token", **options
            ),
            "https://api.dropboxapi.com/oauth2/token",
        )
        for value in (
            "http://api.dropboxapi.com/oauth2/token",
            "https://api.dropboxapi.com.attacker.invalid/oauth2/token",
            "https://api.dropboxapi.com:444/oauth2/token",
            "https://user:pass@api.dropboxapi.com/oauth2/token",
            "https://api.dropboxapi.com/oauth2/token?next=https://attacker.invalid",
            "https://api.dropboxapi.com/other",
        ):
            with self.subTest(value=value):
                self.assertIsNone(validated_https_endpoint(value, **options))

    @mock.patch("apps.api.v1.callback.views.requests.post")
    def test_token_helper_rejects_untrusted_host_and_never_forwards_redirects(
        self, post
    ):
        self.assertIsNone(
            _post_oauth_token(
                "https://slack.com.attacker.invalid/api/oauth.v2.access",
                allowed_hostnames={"slack.com"},
                allowed_paths={"/api/oauth.v2.access"},
                data={"client_secret": "secret-marker"},
            )
        )
        post.assert_not_called()

        post.return_value = mock.Mock(status_code=400)
        _post_oauth_token(
            "https://slack.com/api/oauth.v2.access",
            allowed_hostnames={"slack.com"},
            allowed_paths={"/api/oauth.v2.access"},
            data={"client_secret": "secret-marker"},
        )
        self.assertNotIn("secret-marker", post.call_args.args[0])
        self.assertEqual(post.call_args.kwargs["data"]["client_secret"], "secret-marker")
        self.assertFalse(post.call_args.kwargs["allow_redirects"])


@override_settings(
    APP_URL="https://demo.backupsheep.com",
    SLACK_TOKEN_URL="https://slack.com/api/oauth.v2.access",
    SLACK_CLIENT_ID="slack-client",
    SLACK_CLIENT_SECRET="slack-secret-marker",
    DIGITALOCEAN_TOKEN_URL="https://cloud.digitalocean.com/v1/oauth/token",
    DIGITALOCEAN_APP_CLIENT_ID="do-client",
    DIGITALOCEAN_APP_CLIENT_SECRET="do-secret-marker",
    BASECAMP_TOKEN_ENDPOINT="https://launchpad.37signals.com/authorization/token",
    BASECAMP_CLIENT_ID="basecamp-client",
    BASECAMP_CLIENT_SECRET="basecamp-secret-marker",
    BASECAMP_REDIRECT_URL="/api/v1/callback/basecamp",
    MS_OAUTH_TOKEN_URL="https://login.microsoftonline.com/common/oauth2/v2.0/token",
    MS_CLIENT_ID="ms-client",
    MS_CLIENT_SECRET_VALUE="ms-secret-marker",
    MS_REDIRECT_URL="/api/v1/callback/microsoft",
    DROPBOX_APP_KEY="dropbox-client",
    DROPBOX_APP_SECRET="dropbox-secret-marker",
    GOOGLE_CLIENT_ID="google-client",
    GOOGLE_CLIENT_SECRET="google-secret-marker",
)
class OAuthCallbackBoundaryTests(SimpleTestCase):
    callback_cases = (
        (APICallbackSlack, "slack", False, "https://slack.com/api/oauth.v2.access"),
        (
            APICallbackDigitalOcean,
            "digitalocean",
            False,
            "https://cloud.digitalocean.com/v1/oauth/token",
        ),
        (
            APICallbackBasecamp,
            "basecamp",
            False,
            "https://launchpad.37signals.com/authorization/token",
        ),
        (
            APICallbackMicrosoft,
            "microsoft",
            True,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        ),
        (
            APICallbackDropbox,
            "dropbox",
            True,
            "https://api.dropboxapi.com/oauth2/token",
        ),
        (
            APICallbackGoogleDrive,
            "google_drive",
            True,
            "https://oauth2.googleapis.com/token",
        ),
    )

    def setUp(self):
        self.factory = APIRequestFactory()
        self.account = SimpleNamespace(
            pk="account-1",
            get_encryption_key=lambda: b"test-encryption-key",
        )
        self.member = SimpleNamespace(
            pk="member-1",
            id="member-1",
            get_current_account=lambda: self.account,
        )
        self.user = SimpleNamespace(member=self.member, is_authenticated=True)

    def _request(self, provider, *, valid_state, use_pkce):
        request = self.factory.get("/callback/", {"state": "wrong", "code": "code"})
        request.session = {}
        if valid_state:
            state = issue_oauth_state(
                request,
                provider=provider,
                member=self.member,
                account=self.account,
                use_pkce=use_pkce,
            )
            request.GET = request.GET.copy()
            request.GET["state"] = state["state"]
        force_authenticate(request, user=self.user)
        return request

    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch("apps.api.v1.callback.views.current_account_is_primary", return_value=True)
    @mock.patch("apps.api.v1.callback.views.member_has_perm", return_value=True)
    @mock.patch("apps.api.v1.callback.views.requests.post")
    def test_every_callback_rejects_mismatched_state_before_network(
        self, post, has_perm, is_primary, add_message, redirect
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        for view_class, provider, use_pkce, endpoint in self.callback_cases:
            with self.subTest(provider=provider):
                post.reset_mock()
                response = view_class.as_view()(
                    self._request(provider, valid_state=False, use_pkce=use_pkce)
                )
                self.assertEqual(response.status_code, 302)
                post.assert_not_called()

    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch("apps.api.v1.callback.views.current_account_is_primary", return_value=True)
    @mock.patch("apps.api.v1.callback.views.member_has_perm", return_value=True)
    @mock.patch("apps.api.v1.callback.views.requests.post")
    def test_every_token_exchange_uses_exact_host_post_body_and_no_redirects(
        self, post, has_perm, is_primary, add_message, redirect
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        post.return_value = mock.Mock(status_code=400)
        for view_class, provider, use_pkce, endpoint in self.callback_cases:
            with self.subTest(provider=provider):
                post.reset_mock()
                response = view_class.as_view()(
                    self._request(provider, valid_state=True, use_pkce=use_pkce)
                )
                self.assertEqual(response.status_code, 302)
                post.assert_called_once()
                self.assertEqual(post.call_args.args[0], endpoint)
                self.assertIn("client_secret", post.call_args.kwargs["data"])
                self.assertNotIn(
                    post.call_args.kwargs["data"]["client_secret"], endpoint
                )
                self.assertFalse(post.call_args.kwargs["allow_redirects"])
                if use_pkce:
                    self.assertIn("code_verifier", post.call_args.kwargs["data"])

    @mock.patch("apps.api.v1.callback.views.requests.post")
    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    def test_retired_google_cloud_callback_performs_no_exchange(
        self, add_message, redirect, post
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        request = self.factory.get("/callback/google-cloud/", {"code": "attacker"})
        force_authenticate(request, user=self.user)
        response = APIGoogleCloud.as_view()(request)
        self.assertEqual(response.status_code, 302)
        post.assert_not_called()
