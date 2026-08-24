from unittest import mock

from django.core.cache import cache
from django.test import Client, override_settings
from rest_framework.authtoken.models import Token

from apps.api.v1.utils.api_throttles import (
    LoginIdentityRateThrottle,
    LoginRateThrottle,
    MFAIdentityRateThrottle,
    PasswordResetIdentityRateThrottle,
)
from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class AuthenticationThrottleSecurityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        settings_row = CoreSiteSettings.load()
        settings_row.setup_completed = True
        settings_row.save()
        OnboardingMiddleware._completed = False
        cache.clear()

    def tearDown(self):
        cache.clear()
        super().tearDown()

    @staticmethod
    def _bad_login(
        client,
        email,
        *,
        peer="192.0.2.10",
        xff=None,
        trusted_client_ip=None,
        token=None,
    ):
        extra = {"REMOTE_ADDR": peer}
        if xff is not None:
            extra["HTTP_X_FORWARDED_FOR"] = xff
        if trusted_client_ip is not None:
            extra["HTTP_X_BACKUPSHEEP_CLIENT_IP"] = trusted_client_ip
        if token is not None:
            extra["HTTP_AUTHORIZATION"] = f"Token {token.key}"
        return client.post(
            "/api/v1/auth/login/",
            {"email": email, "password": "definitely-wrong"},
            content_type="application/json",
            **extra,
        )

    def test_authenticated_sessions_and_tokens_do_not_bypass_login_limit(self):
        with mock.patch.object(LoginIdentityRateThrottle, "rate", "2/minute"):
            session_client = Client()
            session_client.force_login(self.user)
            results = [
                self._bad_login(session_client, self.user.email)
                for _ in range(3)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

        cache.clear()
        api_token = Token.objects.create(user=self.user)
        with mock.patch.object(LoginIdentityRateThrottle, "rate", "2/minute"):
            token_results = [
                self._bad_login(
                    Client(),
                    self.user.email,
                    peer="192.0.2.11",
                    token=api_token,
                )
                for _ in range(3)
            ]
        self.assertEqual(
            [response.status_code for response in token_results],
            [400, 400, 429],
        )

    def test_identity_is_normalized_before_login_bucket_is_selected(self):
        variants = [
            self.user.email.upper(),
            self.user.email.lower(),
            f"  {self.user.email.upper()}  ",
        ]
        with mock.patch.object(LoginIdentityRateThrottle, "rate", "2/minute"):
            results = [self._bad_login(Client(), email) for email in variants]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

    def test_changed_identities_and_spoofed_forwarded_for_cannot_evade_peer_guard(self):
        with mock.patch.object(LoginRateThrottle, "rate", "2/minute"):
            results = [
                self._bad_login(
                    Client(),
                    f"spray-{index}@example.com",
                    peer="198.51.100.22",
                    xff=f"203.0.113.{index}",
                )
                for index in range(1, 4)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

    def test_non_object_json_is_bucketed_instead_of_raising_a_server_error(self):
        with mock.patch.object(LoginIdentityRateThrottle, "rate", "2/minute"):
            results = [
                Client().post(
                    "/api/v1/auth/login/",
                    ["not", "an", "object"],
                    content_type="application/json",
                    REMOTE_ADDR="198.51.100.23",
                )
                for _ in range(3)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

    @override_settings(
        AUTH_THROTTLE_TRUSTED_PROXY_ENABLED=False,
        AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS=("10.0.0.0/8",),
    )
    def test_dedicated_client_header_is_ignored_when_proxy_mode_is_disabled(self):
        with mock.patch.object(LoginRateThrottle, "rate", "2/minute"):
            results = [
                self._bad_login(
                    Client(),
                    f"disabled-{index}@example.com",
                    peer="10.1.2.3",
                    trusted_client_ip=f"192.0.2.{index}",
                )
                for index in range(1, 4)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

    @override_settings(
        AUTH_THROTTLE_TRUSTED_PROXY_ENABLED=True,
        AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS=("10.0.0.0/8",),
    )
    def test_trusted_proxy_overwritten_client_header_separates_client_buckets(self):
        headers = ("192.0.2.50", "192.0.2.50", "192.0.2.51")
        with mock.patch.object(LoginRateThrottle, "rate", "2/minute"):
            results = [
                self._bad_login(
                    Client(),
                    f"trusted-{index}@example.com",
                    peer="10.1.2.3",
                    trusted_client_ip=client_ip,
                )
                for index, client_ip in enumerate(headers)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 400])

    @override_settings(
        AUTH_THROTTLE_TRUSTED_PROXY_ENABLED=True,
        AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS=("10.0.0.0/8",),
    )
    def test_untrusted_direct_peer_cannot_spoof_dedicated_client_header(self):
        with mock.patch.object(LoginRateThrottle, "rate", "2/minute"):
            results = [
                self._bad_login(
                    Client(),
                    f"untrusted-{index}@example.com",
                    peer="198.51.100.60",
                    trusted_client_ip=f"192.0.2.{index}",
                )
                for index in range(1, 4)
            ]
        self.assertEqual([response.status_code for response in results], [400, 400, 429])

    @override_settings(
        AUTH_THROTTLE_TRUSTED_PROXY_ENABLED=True,
        AUTH_THROTTLE_TRUSTED_PROXY_NETWORKS=("10.0.0.0/8",),
    )
    def test_malformed_or_multiple_dedicated_header_falls_back_to_direct_peer(self):
        for header in ("not-an-ip", "192.0.2.70, 192.0.2.71"):
            with self.subTest(header=header):
                cache.clear()
                with mock.patch.object(LoginRateThrottle, "rate", "2/minute"):
                    results = [
                        self._bad_login(
                            Client(),
                            f"malformed-{index}@example.com",
                            peer="10.1.2.3",
                            trusted_client_ip=header,
                        )
                        for index in range(1, 4)
                    ]
                self.assertEqual(
                    [response.status_code for response in results],
                    [400, 400, 429],
                )

    def test_authenticated_reset_post_and_token_patch_are_both_limited(self):
        client = Client()
        client.force_login(self.user)
        with mock.patch.object(
            PasswordResetIdentityRateThrottle, "rate", "2/minute"
        ):
            post_results = [
                client.post(
                    "/api/v1/auth/reset/",
                    {"email": "unknown@example.com"},
                    content_type="application/json",
                    REMOTE_ADDR="192.0.2.30",
                )
                for _ in range(3)
            ]
        self.assertEqual(
            [response.status_code for response in post_results],
            [200, 200, 429],
        )

        cache.clear()
        with mock.patch.object(
            PasswordResetIdentityRateThrottle, "rate", "2/minute"
        ):
            patch_results = [
                client.patch(
                    "/api/v1/auth/reset/",
                    {
                        "password": "Different-Secret-456!",
                        "password_confirm": "Different-Secret-456!",
                        "password_token": "invalid-reset-bearer",
                    },
                    content_type="application/json",
                    REMOTE_ADDR="192.0.2.31",
                )
                for _ in range(3)
            ]
        self.assertEqual(
            [response.status_code for response in patch_results],
            [400, 400, 429],
        )

    def test_mfa_setup_verify_and_revoke_are_independently_exercised_by_throttle(self):
        client = Client()
        client.force_login(self.user)
        endpoints_and_payloads = [
            (
                "auth_multi_factor_token_setup",
                {
                    "display_name": "Primary authenticator",
                    "current_password": "wrong-password",
                },
            ),
            (
                "auth_multi_factor_token_verify",
                {"auth_multi_factor_token": "000000"},
            ),
            (
                "auth_multi_factor_token_revoke",
                {
                    "current_password": "x-Secret-123",
                    "auth_multi_factor_token": "000000",
                },
            ),
        ]

        for index, (action, payload) in enumerate(endpoints_and_payloads, start=40):
            cache.clear()
            url = f"/api/v1/members/{self.member.pk}/{action}/"
            with mock.patch.object(MFAIdentityRateThrottle, "rate", "2/minute"):
                results = [
                    client.post(
                        url,
                        payload,
                        content_type="application/json",
                        REMOTE_ADDR=f"192.0.2.{index}",
                    )
                    for _ in range(3)
                ]
            self.assertEqual(
                [response.status_code for response in results],
                [400, 400, 429],
                action,
            )
