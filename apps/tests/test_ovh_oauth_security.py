from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet
from django.http import HttpResponseRedirect
from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.callback.views import (
    APICallbackOVHCA,
    APICallbackOVHEU,
    APICallbackOVHUS,
)
from apps.api.v1.connection.ovh_ca.views import CoreOVHCAView
from apps.api.v1.connection.ovh_ca.serializers import CoreAuthOVHCAWriteSerializer
from apps.api.v1.connection.ovh_eu.views import CoreOVHEUView
from apps.api.v1.connection.ovh_eu.serializers import CoreAuthOVHEUWriteSerializer
from apps.api.v1.connection.ovh_oauth import (
    OVH_PROVIDER_CONFIG,
    build_ovh_client,
    consume_ovh_transaction,
    ovh_start_request_is_same_origin,
    prepare_ovh_authorization,
    validated_ovh_authorization_url,
)
from apps.api.v1.connection.ovh_us.views import CoreOVHUSView
from apps.api.v1.connection.ovh_us.serializers import CoreAuthOVHUSWriteSerializer
from apps.api.v1.utils.oauth_security import (
    OAUTH_STATE_SESSION_KEY,
    OAUTH_STATE_TTL_SECONDS,
)
from apps.console.connection.models import (
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS,
)


@override_settings(
    APP_URL="https://demo.backupsheep.com",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "ovh-oauth-security-tests",
        }
    },
    OVH_CA_APP_KEY="ca-app-key",
    OVH_CA_APP_SECRET="ca-secret-marker",
    OVH_EU_APP_KEY="eu-app-key",
    OVH_EU_APP_SECRET="eu-secret-marker",
    OVH_US_APP_KEY="us-app-key",
    OVH_US_APP_SECRET="us-secret-marker",
)
class OVHOAuthSecurityTests(SimpleTestCase):
    providers = {
        "ovh_ca": {
            "endpoint": "https://ca.api.ovh.com/1.0",
            "callback_path": "/api/v1/callback/ovh/ca/",
            "view": APICallbackOVHCA,
            "start_view": CoreOVHCAView,
            "start_module": "apps.api.v1.connection.ovh_ca.views",
            "secret": "ca-secret-marker",
        },
        "ovh_eu": {
            "endpoint": "https://eu.api.ovh.com/1.0",
            "callback_path": "/api/v1/callback/ovh/eu/",
            "view": APICallbackOVHEU,
            "start_view": CoreOVHEUView,
            "start_module": "apps.api.v1.connection.ovh_eu.views",
            "secret": "eu-secret-marker",
        },
        "ovh_us": {
            "endpoint": "https://api.us.ovhcloud.com/1.0",
            "callback_path": "/api/v1/callback/ovh/us/",
            "view": APICallbackOVHUS,
            "start_view": CoreOVHUSView,
            "start_module": "apps.api.v1.connection.ovh_us.views",
            "secret": "us-secret-marker",
        },
    }

    def setUp(self):
        self.factory = APIRequestFactory()
        self.encryption_key = Fernet.generate_key()
        self.account = SimpleNamespace(
            pk="account-1",
            id="account-1",
            get_encryption_key=lambda: self.encryption_key,
        )
        self.member = SimpleNamespace(
            pk="member-1",
            id="member-1",
            get_current_account=lambda: self.account,
        )
        self.user = SimpleNamespace(member=self.member, is_authenticated=True)

    def _prepare(self, provider, *, validation_url=None, consumer_key=None):
        hostname = OVH_PROVIDER_CONFIG[provider]["api_hostname"]
        consumer_key = consumer_key or ("consumer-key-" + provider + "-0123456789")
        validation_url = validation_url or (
            f"https://{hostname}/auth/?credentialToken="
            f"credential-token-{provider}-0123456789"
        )
        key_request = mock.Mock()
        key_request.request.return_value = {
            "consumerKey": consumer_key,
            "validationUrl": validation_url,
        }
        client = mock.Mock()
        client.new_consumer_key_request.return_value = key_request
        request = SimpleNamespace(
            session={},
            user=SimpleNamespace(member=self.member),
        )
        with mock.patch(
            "apps.api.v1.connection.ovh_oauth.ovh_member_has_integration_permission",
            return_value=True,
        ), mock.patch(
            "apps.api.v1.connection.ovh_oauth.build_ovh_client",
            return_value=client,
        ):
            authorization_url = prepare_ovh_authorization(request, provider)
        callback_url = key_request.request.call_args.kwargs["redirect_url"]
        state = parse_qs(urlsplit(callback_url).query)["state"][0]
        return request, authorization_url, callback_url, state, consumer_key

    def _callback_request(self, state, session):
        request = self.factory.get("/callback/ovh/", {"state": state})
        request.session = session
        force_authenticate(request, user=self.user)
        return request

    def test_authorization_url_is_exactly_allowlisted_for_every_region(self):
        token = "credential-token-0123456789"
        for provider, config in OVH_PROVIDER_CONFIG.items():
            hostname = config["api_hostname"]
            with self.subTest(provider=provider):
                self.assertEqual(
                    validated_ovh_authorization_url(
                        provider,
                        f"https://{hostname}/auth/?credentialToken={token}",
                    ),
                    f"https://{hostname}/auth/?credentialToken={token}",
                )

                for value in (
                    f"http://{hostname}/auth/?credentialToken={token}",
                    f"https://{hostname}.attacker.invalid/auth/?credentialToken={token}",
                    f"https://user:password@{hostname}/auth/?credentialToken={token}",
                    f"https://{hostname}:443/auth/?credentialToken={token}",
                    f"https://{hostname}/other?credentialToken={token}",
                    f"https://{hostname}/auth/?credentialToken={token}&next=x",
                    f"https://{hostname}/auth/?credentialToken=short",
                    f"https://{hostname}/auth/?credentialToken={token}#fragment",
                ):
                    with self.subTest(value=value):
                        self.assertIsNone(
                            validated_ovh_authorization_url(provider, value)
                        )

    @mock.patch("apps.api.v1.connection.ovh_oauth.ovh.Client")
    def test_sdk_clients_use_finite_timeouts_exact_hosts_and_no_redirects(
        self, client_constructor
    ):
        consumer_key = "consumer-key-01234567890123456789"
        for provider, case in self.providers.items():
            with self.subTest(provider=provider):
                session = SimpleNamespace(max_redirects=30)
                client = SimpleNamespace(
                    _endpoint=case["endpoint"],
                    _session=session,
                )
                client_constructor.reset_mock()
                client_constructor.return_value = client

                self.assertIs(
                    build_ovh_client(provider, consumer_key=consumer_key),
                    client,
                )
                kwargs = client_constructor.call_args.kwargs
                self.assertEqual(kwargs["consumer_key"], consumer_key)
                self.assertEqual(kwargs["application_secret"], case["secret"])
                self.assertNotIn(case["secret"], case["endpoint"])
                self.assertNotIn(consumer_key, case["endpoint"])
                self.assertEqual(len(kwargs["timeout"]), 2)
                self.assertTrue(all(0 < value < 86401 for value in kwargs["timeout"]))
                self.assertEqual(session.max_redirects, 0)

    @mock.patch("apps.api.v1.connection.ovh_oauth.ovh.Client")
    def test_sdk_client_fails_before_use_when_sdk_endpoint_is_not_exact(
        self, client_constructor
    ):
        for endpoint in (
            "http://ca.api.ovh.com/1.0",
            "https://ca.api.ovh.com.attacker.invalid/1.0",
            "https://ca.api.ovh.com:443/1.0",
            "https://ca.api.ovh.com/other",
        ):
            with self.subTest(endpoint=endpoint):
                client_constructor.return_value = SimpleNamespace(
                    _endpoint=endpoint,
                    _session=SimpleNamespace(max_redirects=30),
                )
                with self.assertRaises(ValueError):
                    build_ovh_client("ovh_ca")

    def test_real_sdk_transport_keeps_credentials_out_of_urls(self):
        consumer_key = "consumer-key-01234567890123456789"
        response = mock.Mock(status_code=200)
        response.json.return_value = {
            "consumerKey": consumer_key,
            "validationUrl": (
                "https://ca.api.ovh.com/auth/"
                "?credentialToken=credential-token-0123456789"
            ),
        }
        client = build_ovh_client("ovh_ca")
        client._session.request = mock.Mock(return_value=response)
        key_request = client.new_consumer_key_request()
        key_request.add_rules(["GET"], "/me")
        key_request.request(
            redirect_url=(
                "https://demo.backupsheep.com/api/v1/callback/ovh/ca/"
                "?state=random-state-0123456789"
            )
        )

        method, url = client._session.request.call_args.args[:2]
        request_kwargs = client._session.request.call_args.kwargs
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://ca.api.ovh.com/1.0/auth/credential")
        self.assertEqual(
            request_kwargs["headers"]["X-Ovh-Application"], "ca-app-key"
        )
        self.assertNotIn("ca-secret-marker", url)
        self.assertNotIn("ca-secret-marker", repr(request_kwargs))
        self.assertNotIn(consumer_key, url)
        self.assertEqual(client._session.max_redirects, 0)

        response.json.return_value = {"customerCode": "customer"}
        client._session.request.reset_mock()
        client._time_delta = 0
        client.get("/me")
        method, url = client._session.request.call_args.args[:2]
        request_kwargs = client._session.request.call_args.kwargs
        self.assertEqual(method, "GET")
        self.assertEqual(url, "https://ca.api.ovh.com/1.0/me")
        self.assertEqual(
            request_kwargs["headers"]["X-Ovh-Consumer"], consumer_key
        )
        self.assertIn("X-Ovh-Signature", request_kwargs["headers"])
        self.assertNotIn(consumer_key, url)
        self.assertNotIn("ca-secret-marker", repr(request_kwargs))

    @mock.patch("apps.api.v1.connection.ovh_oauth.build_ovh_client")
    @mock.patch(
        "apps.console.connection.models.bs_decrypt",
        return_value="consumer-key-01234567890123456789",
    )
    def test_persisted_ovh_clients_share_the_pinned_transport(
        self, decrypt, build_client
    ):
        account = SimpleNamespace(get_encryption_key=lambda: self.encryption_key)
        connection = SimpleNamespace(account=account)
        for auth_model, provider in (
            (CoreAuthOVHCA, "ovh_ca"),
            (CoreAuthOVHEU, "ovh_eu"),
            (CoreAuthOVHUS, "ovh_us"),
        ):
            with self.subTest(provider=provider):
                decrypt.reset_mock()
                build_client.reset_mock()
                expected_client = object()
                build_client.return_value = expected_client
                auth = auth_model(consumer_key=b"encrypted-consumer-key")
                auth._state.fields_cache["connection"] = connection

                self.assertIs(auth.get_client(), expected_client)
                decrypt.assert_called_once_with(
                    b"encrypted-consumer-key", self.encryption_key
                )
                build_client.assert_called_once_with(
                    provider,
                    consumer_key="consumer-key-01234567890123456789",
                )

    def test_manual_consumer_key_validation_uses_the_pinned_transport(self):
        consumer_key = "consumer-key-01234567890123456789"
        for serializer_class, provider, module in (
            (
                CoreAuthOVHCAWriteSerializer,
                "ovh_ca",
                "apps.api.v1.connection.ovh_ca.serializers",
            ),
            (
                CoreAuthOVHEUWriteSerializer,
                "ovh_eu",
                "apps.api.v1.connection.ovh_eu.serializers",
            ),
            (
                CoreAuthOVHUSWriteSerializer,
                "ovh_us",
                "apps.api.v1.connection.ovh_us.serializers",
            ),
        ):
            with self.subTest(provider=provider):
                client = mock.Mock()
                with mock.patch(
                    f"{module}.build_ovh_client", return_value=client
                ) as build_client:
                    validated = serializer_class(
                        context={"encryption_key": self.encryption_key}
                    ).validate({"consumer_key": consumer_key})
                build_client.assert_called_once_with(
                    provider, consumer_key=consumer_key
                )
                client.get.assert_called_once_with("/cloud/project")
                self.assertNotEqual(validated["consumer_key"], consumer_key)
                self.assertEqual(
                    Fernet(self.encryption_key).decrypt(
                        validated["consumer_key"]
                    ).decode("utf-8"),
                    consumer_key,
                )

    def test_transaction_is_random_encrypted_bound_and_single_use(self):
        first_states = {}
        for provider, case in self.providers.items():
            with self.subTest(provider=provider):
                request, authorization_url, callback_url, state, consumer_key = (
                    self._prepare(provider)
                )
                first_states[provider] = state
                self.assertGreaterEqual(len(state), 40)
                self.assertEqual(urlsplit(callback_url).scheme, "https")
                self.assertEqual(
                    urlsplit(callback_url).hostname, "demo.backupsheep.com"
                )
                self.assertEqual(urlsplit(callback_url).path, case["callback_path"])
                self.assertNotIn(consumer_key, callback_url)
                self.assertNotIn(case["secret"], callback_url)
                self.assertNotIn(consumer_key, repr(request.session))
                self.assertIn("credentialToken", authorization_url)

                self.assertEqual(
                    consume_ovh_transaction(
                        request,
                        provider,
                        member=self.member,
                        account=self.account,
                        received_state=state,
                    ),
                    consumer_key,
                )
                self.assertIsNone(
                    consume_ovh_transaction(
                        request,
                        provider,
                        member=self.member,
                        account=self.account,
                        received_state=state,
                    )
                )
        self.assertEqual(len(set(first_states.values())), len(first_states))

    def test_transaction_rejects_member_account_and_expiry_mismatches(self):
        request, _, _, state, _ = self._prepare("ovh_ca")
        self.assertIsNone(
            consume_ovh_transaction(
                request,
                "ovh_ca",
                member=SimpleNamespace(pk="member-2"),
                account=self.account,
                received_state=state,
            )
        )

        request, _, _, state, _ = self._prepare("ovh_ca")
        self.assertIsNone(
            consume_ovh_transaction(
                request,
                "ovh_ca",
                member=self.member,
                account=SimpleNamespace(
                    pk="account-2",
                    get_encryption_key=lambda: self.encryption_key,
                ),
                received_state=state,
            )
        )

        request, _, _, state, _ = self._prepare("ovh_ca")
        request.session[OAUTH_STATE_SESSION_KEY]["ovh_ca"]["issued_at"] -= (
            OAUTH_STATE_TTL_SECONDS + 1
        )
        self.assertIsNone(
            consume_ovh_transaction(
                request,
                "ovh_ca",
                member=self.member,
                account=self.account,
                received_state=state,
            )
        )

    def test_untrusted_provider_response_discards_pending_transaction(self):
        key_request = mock.Mock()
        key_request.request.return_value = {
            "consumerKey": "consumer-key-01234567890123456789",
            "validationUrl": (
                "https://ca.api.ovh.com.attacker.invalid/auth/"
                "?credentialToken=credential-token-0123456789"
            ),
        }
        client = mock.Mock()
        client.new_consumer_key_request.return_value = key_request
        request = SimpleNamespace(
            session={}, user=SimpleNamespace(member=self.member)
        )
        with mock.patch(
            "apps.api.v1.connection.ovh_oauth.ovh_member_has_integration_permission",
            return_value=True,
        ), mock.patch(
            "apps.api.v1.connection.ovh_oauth.build_ovh_client",
            return_value=client,
        ):
            with self.assertRaises(ValueError):
                prepare_ovh_authorization(request, "ovh_ca")
        self.assertNotIn(OAUTH_STATE_SESSION_KEY, request.session)

    def test_get_start_requires_role_and_same_origin_browser_evidence(self):
        for provider, case in self.providers.items():
            module = case["start_module"]
            view = case["start_view"]()
            self.assertEqual(
                case["start_view"].action_permissions["oauth_url"],
                "integration_changes",
            )
            request = SimpleNamespace(
                headers={"Sec-Fetch-Site": "same-origin"}
            )
            with self.subTest(provider=provider, boundary="role"):
                with mock.patch(f"{module}.member_has_perm", return_value=False), mock.patch(
                    f"{module}.prepare_ovh_authorization"
                ) as prepare:
                    response = view.oauth_url(request)
                self.assertEqual(response.status_code, 403)
                prepare.assert_not_called()

            request = SimpleNamespace(headers={})
            with self.subTest(provider=provider, boundary="origin"):
                with mock.patch(f"{module}.member_has_perm", return_value=True), mock.patch(
                    f"{module}.prepare_ovh_authorization"
                ) as prepare:
                    response = view.oauth_url(request)
                self.assertEqual(response.status_code, 403)
                prepare.assert_not_called()

    def test_same_origin_check_fails_closed(self):
        for headers, expected in (
            ({"Sec-Fetch-Site": "same-origin"}, True),
            ({"Origin": "https://demo.backupsheep.com"}, True),
            ({"Referer": "https://demo.backupsheep.com/setup/"}, True),
            ({"Sec-Fetch-Site": "same-site"}, False),
            ({"Sec-Fetch-Site": "cross-site"}, False),
            ({"Origin": "https://demo.backupsheep.com.attacker.invalid"}, False),
            ({}, False),
        ):
            with self.subTest(headers=headers):
                self.assertEqual(
                    ovh_start_request_is_same_origin(
                        SimpleNamespace(headers=headers)
                    ),
                    expected,
                )

    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch(
        "apps.api.v1.callback.views.ovh_member_has_integration_permission",
        return_value=True,
    )
    @mock.patch("apps.api.v1.callback.views.build_ovh_client")
    def test_callbacks_reject_wrong_state_before_provider_call(
        self, build_client, has_perm, add_message, redirect
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        for provider, case in self.providers.items():
            with self.subTest(provider=provider):
                self.assertTrue(case["view"].permission_classes)
                build_client.reset_mock()
                response = case["view"].as_view()(
                    self._callback_request("wrong-state", {})
                )
                self.assertEqual(response.status_code, 302)
                build_client.assert_not_called()

    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch(
        "apps.api.v1.callback.views.ovh_member_has_integration_permission",
        return_value=False,
    )
    @mock.patch("apps.api.v1.callback.views.build_ovh_client")
    def test_callbacks_consume_state_and_reject_lost_role_before_provider_call(
        self, build_client, has_perm, add_message, redirect
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        request, _, _, state, _ = self._prepare("ovh_ca")
        session = request.session
        response = APICallbackOVHCA.as_view()(
            self._callback_request(state, session)
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(OAUTH_STATE_SESSION_KEY, session)
        build_client.assert_not_called()

    @mock.patch("apps.api.v1.callback.views.capture_message")
    @mock.patch("apps.api.v1.callback.views.redirect")
    @mock.patch("apps.api.v1.callback.views.messages.add_message")
    @mock.patch(
        "apps.api.v1.callback.views.ovh_member_has_integration_permission",
        return_value=True,
    )
    @mock.patch("apps.api.v1.callback.views.build_ovh_client")
    def test_valid_callbacks_use_bound_key_and_stop_on_mocked_provider_failure(
        self,
        build_client,
        has_perm,
        add_message,
        redirect,
        capture_message,
    ):
        redirect.return_value = HttpResponseRedirect("/return")
        for provider, case in self.providers.items():
            with self.subTest(provider=provider):
                request, _, _, state, consumer_key = self._prepare(provider)
                client = mock.Mock()
                client.get.side_effect = RuntimeError("offline provider failure")
                build_client.reset_mock()
                build_client.return_value = client
                response = case["view"].as_view()(
                    self._callback_request(state, request.session)
                )
                self.assertEqual(response.status_code, 302)
                build_client.assert_called_once_with(
                    provider, consumer_key=consumer_key
                )
                client.get.assert_called_once_with("/me")
