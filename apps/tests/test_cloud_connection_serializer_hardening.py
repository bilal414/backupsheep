import json
from unittest.mock import Mock, patch

from django.test import override_settings
from rest_framework.renderers import JSONRenderer
from rest_framework.test import APIClient

from apps.api.v1.connection.aws.serializers import (
    CoreAuthAWSReadSerializer,
    CoreAuthAWSWriteSerializer,
    CoreAWSConnectionWriteSerializer,
)
from apps.api.v1.connection.aws_rds.serializers import (
    CoreAuthAWSRDSReadSerializer,
    CoreAuthAWSRDSWriteSerializer,
)
from apps.api.v1.connection.basecamp.serializers import (
    CoreAuthBasecampReadSerializer,
    CoreAuthBasecampWriteSerializer,
)
from apps.api.v1.connection.digitalocean.serializers import (
    CoreAuthDigitalOceanReadSerializer,
    CoreAuthDigitalOceanWriteSerializer,
    CoreDigitalOceanConnectionWriteSerializer,
)
from apps.api.v1.connection.google_cloud.serializers import (
    CoreAuthGoogleCloudReadSerializer,
    CoreAuthGoogleCloudWriteSerializer,
)
from apps.api.v1.connection.hetzner.serializers import (
    CoreAuthHetznerReadSerializer,
    CoreAuthHetznerWriteSerializer,
)
from apps.api.v1.connection.lightsail.serializers import (
    CoreAuthLightsailReadSerializer,
    CoreAuthLightsailWriteSerializer,
)
from apps.api.v1.connection.oracle.serializers import (
    CoreAuthOracleReadSerializer,
    CoreAuthOracleWriteSerializer,
)
from apps.api.v1.connection.ovh_ca.serializers import (
    CoreAuthOVHCAReadSerializer,
    CoreAuthOVHCAWriteSerializer,
)
from apps.api.v1.connection.ovh_eu.serializers import (
    CoreAuthOVHEUReadSerializer,
    CoreAuthOVHEUWriteSerializer,
)
from apps.api.v1.connection.ovh_us.serializers import (
    CoreAuthOVHUSReadSerializer,
    CoreAuthOVHUSWriteSerializer,
)
from apps.api.v1.connection.upcloud.serializers import (
    CoreAuthUpCloudReadSerializer,
    CoreAuthUpCloudWriteSerializer,
)
from apps.api.v1.connection.vultr.serializers import (
    CoreAuthVultrReadSerializer,
    CoreAuthVultrWriteSerializer,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.connection.models import (
    CoreAuthAWS,
    CoreAuthAWSRDS,
    CoreAuthBasecamp,
    CoreAuthDigitalOcean,
    CoreAuthGoogleCloud,
    CoreAuthHetzner,
    CoreAuthLightsail,
    CoreAuthOracle,
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS,
    CoreAuthUpCloud,
    CoreAuthVultr,
    CoreAWSRegion,
    CoreLightsailRegion,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase
from apps.console.setting.models import CoreSiteSettings
from utils.middleware import OnboardingMiddleware


class CloudConnectionSerializerHardeningTests(BaseTestCase):
    CANARY_PREFIX = "SERIALIZER-SECRET-CANARY-"

    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.encryption_key = self.account.get_encryption_key()
        self.aws_region, _ = CoreAWSRegion.objects.get_or_create(
            code="serializer-test-1",
            defaults={
                "name": "Serializer test",
                "endpoint": "ec2.serializer.invalid",
            },
        )
        self.lightsail_region, _ = CoreLightsailRegion.objects.get_or_create(
            code="serializer-test-1",
            defaults={
                "name": "Serializer test",
                "endpoint": "lightsail.serializer.invalid",
            },
        )
        self.context = {"encryption_key": self.encryption_key}

    def _secret(self, name):
        return f"{self.CANARY_PREFIX}{name}"

    def _encrypted(self, name):
        return bs_encrypt(self._secret(name), self.encryption_key)

    def _render(self, serializer_class, instance):
        payload = serializer_class(instance, context=self.context).data
        return payload, JSONRenderer().render(payload).decode("utf-8")

    def test_all_cloud_auth_read_serializers_expose_only_safe_metadata(self):
        specs = [
            (
                CoreAuthAWSReadSerializer,
                CoreAuthAWS(
                    region=self.aws_region,
                    access_key=self._encrypted("aws-access"),
                    secret_key=self._encrypted("aws-secret"),
                ),
                {"access_key_configured", "secret_key_configured"},
                {"access_key", "secret_key"},
            ),
            (
                CoreAuthAWSRDSReadSerializer,
                CoreAuthAWSRDS(
                    region=self.aws_region,
                    access_key=self._encrypted("rds-access"),
                    secret_key=self._encrypted("rds-secret"),
                ),
                {"access_key_configured", "secret_key_configured"},
                {"access_key", "secret_key"},
            ),
            (
                CoreAuthDigitalOceanReadSerializer,
                CoreAuthDigitalOcean(
                    api_key=self._encrypted("do-api"),
                    access_token=self._encrypted("do-access-token"),
                    refresh_token=self._encrypted("do-refresh-token"),
                    info_name="safe account name",
                ),
                {"api_key_configured"},
                {"api_key", "access_token", "refresh_token"},
            ),
            (
                CoreAuthHetznerReadSerializer,
                CoreAuthHetzner(api_key=self._encrypted("hetzner-api")),
                {"api_key_configured"},
                {"api_key"},
            ),
            (
                CoreAuthLightsailReadSerializer,
                CoreAuthLightsail(
                    region=self.lightsail_region,
                    access_key=self._encrypted("lightsail-access"),
                    secret_key=self._encrypted("lightsail-secret"),
                ),
                {"access_key_configured", "secret_key_configured"},
                {"access_key", "secret_key"},
            ),
            (
                CoreAuthGoogleCloudReadSerializer,
                CoreAuthGoogleCloud(service_key=self._encrypted("gcp-json-private-key")),
                {"service_key_configured"},
                {"service_key"},
            ),
            (
                CoreAuthOracleReadSerializer,
                CoreAuthOracle(
                    user="safe-user-ocid",
                    fingerprint="safe-fingerprint",
                    tenancy="safe-tenancy-ocid",
                    region="us-test-1",
                    profile="DEFAULT",
                    private_key=self._encrypted("oracle-private-key"),
                ),
                {"private_key_configured"},
                {"private_key"},
            ),
            (
                CoreAuthUpCloudReadSerializer,
                CoreAuthUpCloud(
                    username=bs_encrypt("safe-upcloud-user", self.encryption_key),
                    password=self._encrypted("upcloud-password"),
                ),
                {"password_configured"},
                {"password"},
            ),
            (
                CoreAuthVultrReadSerializer,
                CoreAuthVultr(api_key=self._encrypted("vultr-api")),
                {"api_key_configured"},
                {"api_key"},
            ),
            (
                CoreAuthBasecampReadSerializer,
                CoreAuthBasecamp(
                    identity_id="safe-identity-id",
                    access_token=self._encrypted("basecamp-access"),
                    refresh_token=self._encrypted("basecamp-refresh"),
                    metadata={"nested_secret": self._secret("basecamp-metadata")},
                ),
                {"access_token_configured", "refresh_token_configured"},
                {"access_token", "refresh_token", "metadata"},
            ),
            *[
                (
                    serializer_class,
                    model_class(
                        consumer_key=self._encrypted(f"{name}-consumer"),
                        info_name=f"safe {name} account",
                    ),
                    {"consumer_key_configured"},
                    {"consumer_key"},
                )
                for name, serializer_class, model_class in (
                    ("ovh-ca", CoreAuthOVHCAReadSerializer, CoreAuthOVHCA),
                    ("ovh-eu", CoreAuthOVHEUReadSerializer, CoreAuthOVHEU),
                    ("ovh-us", CoreAuthOVHUSReadSerializer, CoreAuthOVHUS),
                )
            ],
        ]

        rendered_responses = []
        for serializer_class, instance, configured_fields, forbidden_fields in specs:
            payload, rendered = self._render(serializer_class, instance)
            rendered_responses.append(rendered)
            for field in configured_fields:
                self.assertIs(payload[field], True, serializer_class.__name__)
            for field in forbidden_fields:
                self.assertNotIn(field, payload, serializer_class.__name__)

        rendered_json = json.dumps(rendered_responses)
        self.assertNotIn(self.CANARY_PREFIX, rendered_json)

    def test_list_and_detail_apis_never_render_any_provider_canary(self):
        providers = []

        def add(code, model_class, **auth_fields):
            connection = factories.make_connection(
                self.account, self.member, code=code, name=f"{code} canary connection"
            )
            model_class.objects.create(connection=connection, **auth_fields)
            providers.append((code, connection.id))

        add(
            "aws",
            CoreAuthAWS,
            region=self.aws_region,
            access_key=self._encrypted("api-aws-access"),
            secret_key=self._encrypted("api-aws-secret"),
        )
        add(
            "aws_rds",
            CoreAuthAWSRDS,
            region=self.aws_region,
            access_key=self._encrypted("api-rds-access"),
            secret_key=self._encrypted("api-rds-secret"),
        )
        add(
            "lightsail",
            CoreAuthLightsail,
            region=self.lightsail_region,
            access_key=self._encrypted("api-lightsail-access"),
            secret_key=self._encrypted("api-lightsail-secret"),
        )
        add(
            "digitalocean",
            CoreAuthDigitalOcean,
            api_key=self._encrypted("api-do-key"),
            access_token=self._encrypted("api-do-access"),
            refresh_token=self._encrypted("api-do-refresh"),
        )
        add("hetzner", CoreAuthHetzner, api_key=self._encrypted("api-hetzner-key"))
        add("vultr", CoreAuthVultr, api_key=self._encrypted("api-vultr-key"))
        add(
            "upcloud",
            CoreAuthUpCloud,
            username=bs_encrypt("safe-upcloud-api-user", self.encryption_key),
            password=self._encrypted("api-upcloud-password"),
        )
        add(
            "google_cloud",
            CoreAuthGoogleCloud,
            service_key=self._encrypted("api-google-service-json"),
        )
        add(
            "oracle",
            CoreAuthOracle,
            user="safe-oracle-user",
            fingerprint="safe-oracle-fingerprint",
            tenancy="safe-oracle-tenancy",
            region="us-test-1",
            profile="DEFAULT",
            private_key=self._encrypted("api-oracle-private-key"),
        )
        for code, model_class in (
            ("ovh_ca", CoreAuthOVHCA),
            ("ovh_eu", CoreAuthOVHEU),
            ("ovh_us", CoreAuthOVHUS),
        ):
            add(
                code,
                model_class,
                consumer_key=self._encrypted(f"api-{code}-consumer-key"),
                info_name=f"safe {code} name",
            )
        add(
            "basecamp",
            CoreAuthBasecamp,
            identity_id="safe-basecamp-identity",
            access_token=self._encrypted("api-basecamp-access"),
            refresh_token=self._encrypted("api-basecamp-refresh"),
            metadata={"nested_secret": self._secret("api-basecamp-metadata")},
        )

        for code, connection_id in providers:
            for url in (
                f"/api/v1/connections/{code}/",
                f"/api/v1/connections/{code}/{connection_id}/",
            ):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200, (url, response.content))
                rendered = response.content.decode("utf-8")
                self.assertNotIn(self.CANARY_PREFIX, rendered, url)

    def test_every_secret_input_field_is_write_only_and_patch_optional(self):
        specs = (
            (CoreAuthAWSWriteSerializer, ("access_key", "secret_key")),
            (CoreAuthAWSRDSWriteSerializer, ("access_key", "secret_key")),
            (
                CoreAuthDigitalOceanWriteSerializer,
                ("api_key", "access_token", "refresh_token"),
            ),
            (CoreAuthHetznerWriteSerializer, ("api_key",)),
            (CoreAuthLightsailWriteSerializer, ("access_key", "secret_key")),
            (CoreAuthGoogleCloudWriteSerializer, ("service_key",)),
            (CoreAuthOracleWriteSerializer, ("private_key",)),
            (CoreAuthUpCloudWriteSerializer, ("password",)),
            (CoreAuthVultrWriteSerializer, ("api_key",)),
            (CoreAuthBasecampWriteSerializer, ("access_token", "refresh_token", "metadata")),
            (CoreAuthOVHCAWriteSerializer, ("consumer_key",)),
            (CoreAuthOVHEUWriteSerializer, ("consumer_key",)),
            (CoreAuthOVHUSWriteSerializer, ("consumer_key",)),
        )

        for serializer_class, field_names in specs:
            serializer = serializer_class(context=self.context)
            for field_name in field_names:
                field = serializer.fields[field_name]
                self.assertTrue(field.write_only, f"{serializer_class.__name__}.{field_name}")
                self.assertFalse(field.required, f"{serializer_class.__name__}.{field_name}")

    def test_partial_credential_pairs_are_rejected_without_provider_calls(self):
        specs = (
            (CoreAuthAWSWriteSerializer, {"access_key": "only-access"}),
            (CoreAuthAWSRDSWriteSerializer, {"secret_key": "only-secret"}),
            (CoreAuthLightsailWriteSerializer, {"access_key": "only-access"}),
            (CoreAuthUpCloudWriteSerializer, {"password": "only-password"}),
            (CoreAuthDigitalOceanWriteSerializer, {"access_token": "only-token"}),
        )

        for serializer_class, data in specs:
            serializer = serializer_class(data=data, partial=True, context=self.context)
            self.assertFalse(serializer.is_valid(), serializer_class.__name__)
            self.assertNotIn(self.CANARY_PREFIX, json.dumps(serializer.errors))

    @patch("apps.api.v1.connection.aws.serializers.bounded_boto3_client")
    def test_aws_replacement_uses_bounded_client_encrypts_and_never_echoes_secrets(
        self, bounded_client
    ):
        bounded_client.return_value.get_caller_identity.return_value = {
            "Account": "safe-account-id"
        }
        access_key = self._secret("replacement-access")
        secret_key = self._secret("replacement-secret")
        serializer = CoreAuthAWSWriteSerializer(
            data={
                "region": self.aws_region.id,
                "access_key": access_key,
                "secret_key": secret_key,
            },
            context=self.context,
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        bounded_client.assert_called_once()
        self.assertEqual(
            bs_decrypt(serializer.validated_data["access_key"], self.encryption_key),
            access_key,
        )
        self.assertEqual(
            bs_decrypt(serializer.validated_data["secret_key"], self.encryption_key),
            secret_key,
        )
        self.assertNotIn(self.CANARY_PREFIX, json.dumps(serializer.data))

    @patch("apps.api.v1.connection.aws.serializers.bounded_boto3_client")
    def test_provider_exception_text_cannot_echo_credentials(self, bounded_client):
        bounded_client.side_effect = RuntimeError(self._secret("provider-error-echo"))
        serializer = CoreAuthAWSWriteSerializer(
            data={
                "region": self.aws_region.id,
                "access_key": self._secret("failed-access"),
                "secret_key": self._secret("failed-secret"),
            },
            context=self.context,
        )

        self.assertFalse(serializer.is_valid())
        self.assertNotIn(self.CANARY_PREFIX, json.dumps(serializer.errors))

    @patch("apps.api.v1.connection.digitalocean.serializers.requests.get")
    def test_direct_http_validation_uses_bounded_facade_and_encrypts(self, get):
        get.return_value = Mock(
            status_code=200,
            json=Mock(
                return_value={
                    "account": {
                        "status": "active",
                        "uuid": "account-uuid",
                        "team": {"uuid": "team-uuid", "name": "Personal"},
                    }
                }
            ),
        )
        api_key = self._secret("do-replacement")
        serializer = CoreAuthDigitalOceanWriteSerializer(
            data={"api_key": api_key}, context=self.context
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        get.assert_called_once()
        self.assertEqual(
            bs_decrypt(serializer.validated_data["api_key"], self.encryption_key),
            api_key,
        )
        self.assertNotIn(self.CANARY_PREFIX, json.dumps(serializer.data))

    def test_nested_non_secret_patch_preserves_aws_credentials(self):
        connection = factories.make_connection(
            self.account, self.member, code="aws", name="AWS serializer test"
        )
        auth = CoreAuthAWS.objects.create(
            connection=connection,
            region=self.aws_region,
            access_key=self._encrypted("stored-aws-access"),
            secret_key=self._encrypted("stored-aws-secret"),
            backup_vault_name="Default",
        )
        original_access = bytes(auth.access_key)
        original_secret = bytes(auth.secret_key)
        serializer = CoreAWSConnectionWriteSerializer(
            connection,
            data={"auth_aws": {"backup_vault_name": "PatchedVault"}},
            partial=True,
            context=self.context,
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        auth.refresh_from_db()
        self.assertEqual(bytes(auth.access_key), original_access)
        self.assertEqual(bytes(auth.secret_key), original_secret)
        self.assertEqual(auth.backup_vault_name, "PatchedVault")

    def test_nested_non_secret_patch_preserves_digitalocean_tokens(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="digitalocean",
            name="DigitalOcean serializer test",
        )
        auth = CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=self._encrypted("stored-do-api"),
            access_token=self._encrypted("stored-do-access"),
            refresh_token=self._encrypted("stored-do-refresh"),
            info_name="Before",
        )
        originals = (
            bytes(auth.api_key),
            bytes(auth.access_token),
            bytes(auth.refresh_token),
        )
        serializer = CoreDigitalOceanConnectionWriteSerializer(
            connection,
            data={"auth_digitalocean": {"info_name": "After"}},
            partial=True,
            context=self.context,
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        auth.refresh_from_db()
        self.assertEqual(
            (bytes(auth.api_key), bytes(auth.access_token), bytes(auth.refresh_token)),
            originals,
        )
        self.assertEqual(auth.info_name, "After")
