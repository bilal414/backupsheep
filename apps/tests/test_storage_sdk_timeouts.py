import importlib
import inspect
from types import SimpleNamespace
from unittest import mock

from botocore.config import Config
from django.test import SimpleTestCase, override_settings

from apps.api.v1.utils.boto import (
    bounded_boto3_client,
    bounded_ibm_boto3_client,
    provider_boto_config,
)
from apps.api.v1.utils.http import TimeoutSession, request_timeout
from apps.console.storage.models import _validation_object_key


S3_ADAPTERS = (
    "alibaba",
    "aws_s3",
    "backblaze_b2",
    "cloudflare",
    "do_spaces",
    "exoscale",
    "filebase",
    "ibm",
    "idrive",
    "ionos",
    "leviia",
    "linode",
    "oracle",
    "rackcorp",
    "scaleway",
    "tencent",
    "upcloud",
    "vultr",
    "wasabi",
)


class StorageSDKTimeoutContractTests(SimpleTestCase):
    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=None,
        PROVIDER_HTTP_READ_TIMEOUT=float("inf"),
        PROVIDER_HTTP_MAX_TIMEOUT=17,
        PROVIDER_HTTP_MAX_RETRIES=4,
    )
    def test_invalid_timeout_settings_are_finite_and_capped(self):
        self.assertEqual(request_timeout(), (10.0, 17.0))
        config = provider_boto_config(
            Config(
                connect_timeout=9999,
                read_timeout=9999,
                retries={"max_attempts": 50, "mode": "adaptive"},
            )
        )
        self.assertEqual(config.connect_timeout, 10.0)
        self.assertEqual(config.read_timeout, 17.0)
        self.assertEqual(config.retries["max_attempts"], 1)
        self.assertEqual(config.retries["mode"], "standard")

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=2.5,
        PROVIDER_HTTP_READ_TIMEOUT=8.5,
        PROVIDER_HTTP_MAX_TIMEOUT=30,
        PROVIDER_HTTP_MAX_RETRIES=2,
    )
    def test_explicit_read_only_retry_opt_in_stays_bounded(self):
        config = provider_boto_config(allow_retries=True)
        self.assertEqual(config.connect_timeout, 2.5)
        self.assertEqual(config.read_timeout, 8.5)
        self.assertEqual(config.retries["max_attempts"], 3)
        self.assertEqual(config.retries["mode"], "standard")

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=3,
        PROVIDER_HTTP_READ_TIMEOUT=11,
        PROVIDER_HTTP_MAX_TIMEOUT=20,
    )
    @mock.patch("apps.api.v1.utils.boto.boto3.client")
    def test_boto_constructor_preserves_provider_fields_and_disables_replay(
        self, client_factory
    ):
        bounded_boto3_client(
            "s3",
            endpoint_url="https://storage.example.invalid",
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "virtual"},
                retries={"max_attempts": 99, "mode": "adaptive"},
            ),
        )
        config = client_factory.call_args.kwargs["config"]
        self.assertEqual(config.connect_timeout, 3.0)
        self.assertEqual(config.read_timeout, 11.0)
        self.assertEqual(config.signature_version, "s3v4")
        self.assertEqual(config.s3["addressing_style"], "virtual")
        self.assertEqual(config.retries["max_attempts"], 1)

    @mock.patch("ibm_boto3.client")
    def test_ibm_constructor_is_also_bounded(self, client_factory):
        bounded_ibm_boto3_client("s3", endpoint_url="https://ibm.example.invalid")
        config = client_factory.call_args.kwargs["config"]
        self.assertGreater(config.connect_timeout, 0)
        self.assertGreater(config.read_timeout, 0)
        self.assertEqual(config.retries["max_attempts"], 1)

    def test_http_sessions_do_not_transport_retry_mutations_by_default(self):
        session = TimeoutSession()
        adapter = session.adapters["https://"]
        self.assertEqual(adapter.max_retries.total, 4)
        self.assertNotIn("PUT", adapter.max_retries.allowed_methods)
        self.assertNotIn("DELETE", adapter.max_retries.allowed_methods)

        explicitly_opted_in = TimeoutSession(allow_mutation_retries=True)
        self.assertIn(
            "PUT",
            explicitly_opted_in.adapters["https://"].max_retries.allowed_methods,
        )

    def test_all_s3_adapters_use_the_shared_constructor(self):
        for provider in S3_ADAPTERS:
            with self.subTest(provider=provider):
                module = importlib.import_module(
                    f"apps._tasks.integration.storage.{provider}"
                )
                source = inspect.getsource(module)
                self.assertNotIn("boto3.client(", source)
                self.assertIn("bounded_boto3_client(", source)

    @override_settings(
        PROVIDER_HTTP_CONNECT_TIMEOUT=4,
        PROVIDER_HTTP_READ_TIMEOUT=12,
        PROVIDER_HTTP_MAX_TIMEOUT=25,
    )
    def test_representative_s3_compatible_constructors_receive_finite_config(self):
        region = SimpleNamespace(code="us-east-1", endpoint="s3.example.invalid")
        providers = {
            "do_spaces": SimpleNamespace(
                access_key=b"access",
                secret_key=b"secret",
                region=region,
            ),
            "cloudflare": SimpleNamespace(
                access_key=b"access",
                secret_key=b"secret",
                endpoint="account.r2.cloudflarestorage.com",
            ),
            "oracle": SimpleNamespace(
                access_key=b"access",
                secret_key=b"secret",
                endpoint="namespace.compat.objectstorage.us-chicago-1.oraclecloud.com",
                region=region,
            ),
            "ibm": SimpleNamespace(
                access_key=b"access",
                secret_key=b"secret",
                endpoint="s3.us-east.cloud-object-storage.appdomain.cloud",
                region=region,
            ),
        }
        for provider, config_object in providers.items():
            with self.subTest(provider=provider):
                module = importlib.import_module(
                    f"apps._tasks.integration.storage.{provider}"
                )
                with mock.patch.object(module, "bs_decrypt", return_value="secret"), mock.patch(
                    "apps.api.v1.utils.boto.boto3.client"
                ) as client_factory:
                    module._s3_client(config_object, "encryption-key")
                config = client_factory.call_args.kwargs["config"]
                self.assertEqual(config.connect_timeout, 4.0)
                self.assertEqual(config.read_timeout, 12.0)
                self.assertEqual(config.retries["mode"], "standard")

    def test_validation_probe_keys_are_unique(self):
        first = _validation_object_key("prefix")
        second = _validation_object_key("prefix")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("prefix/"))
        self.assertTrue(first.endswith(".txt"))
