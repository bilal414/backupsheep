import importlib
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, override_settings

from apps.api.v1.connection.wordpress.serializers import (
    CoreAuthWordPressWriteSerializer,
)
from apps.api.v1.utils.wordpress_transport import (
    WORDPRESS_KEY_ID_HEADER,
    WORDPRESS_SIGNATURE_HEADER,
)
from apps.api.v1.saas.wordpress.views import CoreWordPressView
from apps.console.connection.models import (
    CoreAuthWordPress,
    WORDPRESS_SECRET_PREFIX,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


@override_settings(WORDPRESS_INTEGRATION_ENABLED=True)
class WordPressCredentialModelTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.connection = factories.make_connection(
            self.account, self.member, code="wordpress"
        )

    def make_auth(self, **overrides):
        values = {
            "connection": self.connection,
            "url": "https://wordpress.example.test/subsite",
            "key": "wordpress-key-canary-32-bytes",
            "http_user": "http-user-canary",
            "http_pass": "http-password-canary",
        }
        values.update(overrides)
        return CoreAuthWordPress.objects.create(**values)

    def test_direct_writes_encrypt_every_credential_and_do_not_double_encrypt(self):
        row = self.make_auth()
        row.refresh_from_db()

        stored = {}
        for field_name, plaintext in {
            "key": "wordpress-key-canary-32-bytes",
            "http_user": "http-user-canary",
            "http_pass": "http-password-canary",
        }.items():
            ciphertext = getattr(row, field_name)
            self.assertTrue(ciphertext.startswith(WORDPRESS_SECRET_PREFIX))
            self.assertNotIn(plaintext, ciphertext)
            self.assertEqual(row._decrypt_secret(field_name), plaintext)
            stored[field_name] = ciphertext

        row.save()
        row.refresh_from_db()
        for field_name, ciphertext in stored.items():
            self.assertEqual(getattr(row, field_name), ciphertext)

    def test_database_constraint_rejects_plaintext_bypass(self):
        row = self.make_auth()
        with self.assertRaises(IntegrityError), transaction.atomic():
            CoreAuthWordPress.objects.filter(pk=row.pk).update(
                key="plaintext-queryset-bypass"
            )

    def test_missing_account_key_aborts_before_plaintext_is_persisted(self):
        with mock.patch.object(
            self.connection.account,
            "get_encryption_key",
            return_value=None,
        ):
            with self.assertRaises(ValueError):
                self.make_auth()
        self.assertFalse(
            CoreAuthWordPress.objects.filter(connection=self.connection).exists()
        )

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.pinned_wordpress_request"
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.resolve_wordpress_target"
    )
    def test_request_keeps_secrets_out_of_url_and_query_and_disables_redirects(
        self, resolve_target, pinned_get
    ):
        target = SimpleNamespace(pinned_url="https://8.8.8.8:443/subsite/")
        resolve_target.return_value = target
        pinned_get.return_value = SimpleNamespace(status_code=302)
        row = self.make_auth(url="https://WordPress.Example.Test:443/subsite/")

        response = row.request(
            "status",
            params={"backup_uuid": "backup-123", "t": 123},
            timeout=30,
        )

        self.assertEqual(response.status_code, 302)
        resolve_target.assert_called_once_with(
            "https://wordpress.example.test:443/subsite",
        )
        pinned_get.assert_called_once()
        self.assertIs(pinned_get.call_args.args[0], target)
        self.assertEqual(pinned_get.call_args.kwargs["route"], "status")
        self.assertEqual(
            pinned_get.call_args.kwargs["body"],
            b'{"backup_uuid":"backup-123","t":123}',
        )
        headers = pinned_get.call_args.kwargs["headers"]
        self.assertRegex(headers[WORDPRESS_SIGNATURE_HEADER], r"^[0-9a-f]{64}$")
        self.assertRegex(headers[WORDPRESS_KEY_ID_HEADER], r"^[0-9a-f]{32}$")
        self.assertNotIn("wordpress-key-canary-32-bytes", repr(headers))
        self.assertEqual(
            pinned_get.call_args.kwargs["auth"],
            ("http-user-canary", "http-password-canary"),
        )
        rendered_url_data = repr(
            (target.pinned_url, pinned_get.call_args.kwargs["body"], headers)
        )
        self.assertNotIn("wordpress-key-canary-32-bytes", rendered_url_data)
        self.assertNotIn("http-password-canary", rendered_url_data)

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.pinned_wordpress_request"
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.resolve_wordpress_target"
    )
    def test_download_request_signs_backup_file_and_uuid_in_canonical_body(
        self, resolve_target, pinned_get
    ):
        target = SimpleNamespace(pinned_url="https://8.8.8.8:443/subsite/")
        resolve_target.return_value = target
        pinned_get.return_value = SimpleNamespace(status_code=200)
        row = self.make_auth()

        row.request(
            "download",
            params={
                "backup_file": "backup_2026-08-25_backup-123-db.gz",
                "backup_uuid": "backup-123",
                "t": 123,
            },
            stream=True,
        )

        pinned_get.assert_called_once()
        self.assertEqual(pinned_get.call_args.kwargs["route"], "download")
        self.assertEqual(
            pinned_get.call_args.kwargs["body"],
            b'{"backup_file":"backup_2026-08-25_backup-123-db.gz",'
            b'"backup_uuid":"backup-123","t":123}',
        )
        self.assertTrue(pinned_get.call_args.kwargs["stream"])
        self.assertRegex(
            pinned_get.call_args.kwargs["headers"][WORDPRESS_SIGNATURE_HEADER],
            r"^[0-9a-f]{64}$",
        )

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.pinned_wordpress_request"
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.resolve_wordpress_target"
    )
    def test_untrusted_url_ambient_data_and_query_credentials_fail_before_network(
        self, resolve_target, pinned_get
    ):
        resolve_target.return_value = SimpleNamespace()
        row = self.make_auth()
        for invalid_url in (
            "http://wordpress.example.test",
            "https://user:password@wordpress.example.test",
            "https://wordpress.example.test/?next=https://attacker.invalid",
            "https://wordpress.example.test/#fragment",
        ):
            row.url = invalid_url
            with self.assertRaises(ValueError):
                row.request("validate")

        row.url = "https://wordpress.example.test"
        with self.assertRaises(ValueError):
            row.request("validate", params={"key": "query-secret"})
        pinned_get.assert_not_called()

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.pinned_wordpress_request"
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.resolve_wordpress_target"
    )
    def test_cross_account_ciphertext_transplant_fails_closed_before_network(
        self, resolve_target, pinned_get
    ):
        resolve_target.return_value = SimpleNamespace()
        source = self.make_auth()
        other_account, other_member, _ = factories.make_account()
        other_connection = factories.make_connection(
            other_account, other_member, code="wordpress"
        )
        target = CoreAuthWordPress.objects.create(
            connection=other_connection,
            url="https://other-wordpress.example.test",
            key="other-wordpress-key",
        )
        CoreAuthWordPress.objects.filter(pk=target.pk).update(key=source.key)
        target.refresh_from_db()

        self.assertIsNone(target.get_key())
        with self.assertRaises(ValueError):
            target.request("validate")
        pinned_get.assert_not_called()

    def test_serializer_rejects_versioned_ciphertext_as_user_input(self):
        serializer = CoreAuthWordPressWriteSerializer(
            data={
                "url": "https://wordpress.example.test",
                "key": f"{WORDPRESS_SECRET_PREFIX}foreign-ciphertext",
            },
            partial=True,
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("key", serializer.errors)


class WordPressProtocolKillSwitchTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.connection = factories.make_connection(
            self.account, self.member, code="wordpress"
        )
        self.auth = CoreAuthWordPress.objects.create(
            connection=self.connection,
            url="https://wordpress.example.test",
            key="wordpress-key-canary",
        )

    @override_settings(WORDPRESS_INTEGRATION_ENABLED=False)
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.pinned_wordpress_request"
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.resolve_wordpress_target"
    )
    def test_disabled_protocol_refuses_before_resolution_or_secret_decryption(
        self, resolve_target, pinned_get
    ):
        with mock.patch.object(
            self.auth, "_decrypt_secret", wraps=self.auth._decrypt_secret
        ) as decrypt:
            with self.assertRaisesRegex(ValueError, "complete recovery workflow"):
                self.auth.request("validate")

        resolve_target.assert_not_called()
        pinned_get.assert_not_called()
        decrypt.assert_not_called()


@override_settings(WORDPRESS_INTEGRATION_ENABLED=True)
class WordPressProtocolValidationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        connection = factories.make_connection(
            self.account, self.member, code="wordpress"
        )
        self.auth = CoreAuthWordPress.objects.create(
            connection=connection,
            url="https://wordpress.example.test",
            key="wordpress-key-canary-32-bytes",
        )

    @staticmethod
    def response(payload):
        return SimpleNamespace(
            status_code=200,
            json=lambda: payload,
            raise_for_status=lambda: None,
        )

    def test_validation_requires_explicit_protocol_v2_confirmation(self):
        payload = {
            "plugins": {"backupsheep": True, "updraftplus": True},
        }
        with mock.patch.object(self.auth, "request", return_value=self.response(payload)):
            with self.assertRaisesRegex(ValueError, "protocol v2"):
                self.auth.validate(check_errors=True)

    def test_validation_accepts_only_v2_with_both_plugins_active(self):
        payload = {
            "protocol": 2,
            "plugins": {"backupsheep": True, "updraftplus": True},
        }
        with mock.patch.object(self.auth, "request", return_value=self.response(payload)):
            self.assertTrue(self.auth.validate(check_errors=True))


@override_settings(
    BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
    BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE="legacy-only",
    BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
    WORDPRESS_INTEGRATION_ENABLED=True,
)
class WordPressIntegrationKeyTests(SimpleTestCase):
    def test_generated_key_is_a_high_entropy_url_safe_string(self):
        first = CoreWordPressView().generate_key(None).data["key"]
        second = CoreWordPressView().generate_key(None).data["key"]

        self.assertIsInstance(first, str)
        self.assertRegex(first, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotEqual(first, second)


class WordPressCredentialMigrationTests(SimpleTestCase):
    def test_migration_helpers_are_idempotent_reversible_and_fail_closed(self):
        migration = importlib.import_module(
            "apps._migrations.0039_encrypt_wordpress_credentials"
        )
        key = Fernet.generate_key()
        encrypted = migration._encrypt_legacy_value(
            "legacy-wordpress-secret",
            key,
            row_id=7,
            field_name="key",
        )
        self.assertTrue(encrypted.startswith(WORDPRESS_SECRET_PREFIX))
        self.assertNotIn("legacy-wordpress-secret", encrypted)
        self.assertEqual(
            migration._encrypt_legacy_value(
                encrypted,
                key,
                row_id=7,
                field_name="key",
            ),
            encrypted,
        )
        self.assertEqual(
            migration._decrypt_for_rollback(
                encrypted,
                key,
                row_id=7,
                field_name="key",
            ),
            "legacy-wordpress-secret",
        )
        with self.assertRaises(RuntimeError):
            migration._encrypt_legacy_value(
                f"{WORDPRESS_SECRET_PREFIX}malformed",
                key,
                row_id=7,
                field_name="key",
            )
        with self.assertRaises(RuntimeError):
            migration._account_key(None, row_id=7)
