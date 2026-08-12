import inspect
from types import SimpleNamespace
from unittest import mock

import oci
from django.test import SimpleTestCase, override_settings

from apps.console.account.models import CoreAccount
from apps.console.connection.models import (
    CoreAuthAWS,
    CoreAuthGoogleCloud,
    CoreAuthOracle,
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS,
    CoreAWSRegion,
    CoreConnection,
    _BoundedGoogleAuthorizedSession,
    _oci_client_kwargs,
    _provider_sdk_timeout,
)


class ProviderSDKTimeoutPolicyTests(SimpleTestCase):
    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=None,
        PROVIDER_HTTP_READ_TIMEOUT=None,
        PROVIDER_HTTP_MAX_TIMEOUT=None,
    )
    def test_invalid_or_missing_timeout_settings_use_conservative_defaults(self):
        self.assertEqual(_provider_sdk_timeout(), (10.0, 60.0))

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=3.5,
        PROVIDER_HTTP_READ_TIMEOUT=17.25,
    )
    def test_shared_sdk_timeout_uses_django_settings(self):
        self.assertEqual(_provider_sdk_timeout(), (3.5, 17.25))

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=99999,
        PROVIDER_HTTP_READ_TIMEOUT=float("inf"),
        PROVIDER_HTTP_MAX_TIMEOUT=21,
    )
    def test_sdk_timeout_is_finite_and_capped(self):
        self.assertEqual(_provider_sdk_timeout(), (21.0, 21.0))

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=4,
        PROVIDER_HTTP_READ_TIMEOUT=23,
    )
    @mock.patch("ovh.Client")
    @mock.patch("apps.console.connection.models.bs_decrypt", return_value="consumer")
    @mock.patch.object(CoreAccount, "get_encryption_key", return_value="key")
    def test_all_ovh_regions_receive_bounded_connect_and_read_timeout(
        self, _encryption_key, _decrypt, ovh_client
    ):
        account = CoreAccount()
        connection = CoreConnection(account=account)

        for auth_class, endpoint in (
            (CoreAuthOVHCA, "ovh-ca"),
            (CoreAuthOVHEU, "ovh-eu"),
            (CoreAuthOVHUS, "ovh-us"),
        ):
            with self.subTest(endpoint=endpoint):
                ovh_client.reset_mock()
                auth_class(
                    connection=connection,
                    consumer_key=b"encrypted-consumer-key",
                ).get_client()
                self.assertEqual(
                    ovh_client.call_args.kwargs["timeout"], (4.0, 23.0)
                )
                self.assertEqual(ovh_client.call_args.kwargs["endpoint"], endpoint)

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=2,
        PROVIDER_HTTP_READ_TIMEOUT=9,
    )
    @mock.patch("oci.core.BlockstorageClient")
    @mock.patch("oci.identity.IdentityClient")
    @mock.patch("oci.pagination.list_call_get_all_results")
    def test_oci_clients_receive_bounded_timeout_and_no_retry_strategy(
        self, list_all, identity_client, block_storage_client
    ):
        list_all.return_value = SimpleNamespace(status=200, data=[])
        identity_client.return_value.list_compartments.return_value = SimpleNamespace(
            status=200, data=[]
        )
        auth = CoreAuthOracle(tenancy="tenancy-ocid")
        auth.get_client = mock.Mock(return_value={"region": "us-chicago-1"})
        auth.get_verified_client = mock.Mock(return_value={"region": "us-chicago-1"})

        self.assertEqual(auth.get_eligible_objects("volume"), [])

        for constructor in (block_storage_client, identity_client):
            self.assertEqual(constructor.call_args.kwargs["timeout"], (2.0, 9.0))
            self.assertIsInstance(
                constructor.call_args.kwargs["retry_strategy"],
                oci.retry.NoneRetryStrategy,
            )

        direct_kwargs = _oci_client_kwargs()
        self.assertEqual(direct_kwargs["timeout"], (2.0, 9.0))
        self.assertIsInstance(
            direct_kwargs["retry_strategy"], oci.retry.NoneRetryStrategy
        )

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=3,
        PROVIDER_HTTP_READ_TIMEOUT=11,
    )
    @mock.patch(
        "apps.console.connection.models.service_account.Credentials.from_service_account_info"
    )
    def test_google_authorized_session_applies_default_and_explicit_timeout(
        self, credentials_factory
    ):
        credentials = mock.Mock()
        credentials.with_scopes.return_value = credentials
        credentials_factory.return_value = credentials
        client = CoreAuthGoogleCloud().get_client(data={"service_key": "{}"})

        self.assertIsInstance(client, _BoundedGoogleAuthorizedSession)
        with mock.patch("requests.sessions.Session.request") as request:
            request.return_value = SimpleNamespace(status_code=200)
            client.get("https://provider.example.invalid/default")
            self.assertEqual(request.call_args.kwargs["timeout"], (3.0, 11.0))

            client.get(
                "https://provider.example.invalid/explicit",
                timeout=(1, 2),
            )
            self.assertEqual(request.call_args.kwargs["timeout"], (1, 2))

        self.assertEqual(
            client.adapters["https://"].max_retries.total,
            0,
        )
        self.assertEqual(
            client._auth_request.session.adapters["https://"].max_retries.total,
            0,
        )

    @mock.patch(
        "apps.console.connection.models.service_account.Credentials.from_service_account_info"
    )
    def test_google_mutation_401_is_not_replayed_after_credential_refresh(
        self, credentials_factory
    ):
        credentials = mock.Mock()
        credentials.with_scopes.return_value = credentials
        credentials_factory.return_value = credentials
        client = CoreAuthGoogleCloud().get_client(data={"service_key": "{}"})

        with mock.patch("requests.sessions.Session.request") as request:
            request.return_value = SimpleNamespace(status_code=401)
            client.post(
                "https://provider.example.invalid/mutate",
                json={"resource": "marker"},
            )

        self.assertEqual(request.call_count, 1)
        credentials.refresh.assert_not_called()

    def test_connection_module_has_no_unbounded_boto_client_constructor(self):
        source = inspect.getsource(CoreAuthAWS)
        self.assertNotIn("boto3.client(", source)
        self.assertIn("bounded_boto3_client(", source)
