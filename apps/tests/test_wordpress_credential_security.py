import importlib
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase

from apps.api.v1.connection.wordpress.serializers import (
    CoreAuthWordPressWriteSerializer,
)
from apps.console.connection.models import (
    CoreAuthWordPress,
    WORDPRESS_KEY_HEADER,
    WORDPRESS_SECRET_PREFIX,
)
from apps.tests import factories
from apps.tests.base import BaseTestCase


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
            "key": "wordpress-key-canary",
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
            "key": "wordpress-key-canary",
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

    @mock.patch("apps.console.connection.models.requests.get")
    def test_request_keeps_secrets_out_of_url_and_query_and_disables_redirects(
        self, get
    ):
        get.return_value = SimpleNamespace(status_code=302)
        row = self.make_auth(url="https://WordPress.Example.Test:443/subsite/")

        response = row.request(
            "status",
            params={"backup_uuid": "backup-123", "t": 123},
            timeout=30,
        )

        self.assertEqual(response.status_code, 302)
        get.assert_called_once()
        self.assertEqual(
            get.call_args.args[0],
            "https://wordpress.example.test:443/subsite/",
        )
        self.assertEqual(
            get.call_args.kwargs["params"],
            {
                "rest_route": "/backupsheep/updraftplus/status",
                "backup_uuid": "backup-123",
                "t": 123,
            },
        )
        self.assertEqual(
            get.call_args.kwargs["headers"][WORDPRESS_KEY_HEADER],
            "wordpress-key-canary",
        )
        self.assertEqual(
            get.call_args.kwargs["auth"],
            ("http-user-canary", "http-password-canary"),
        )
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        rendered_url_data = repr(
            (get.call_args.args[0], get.call_args.kwargs["params"])
        )
        self.assertNotIn("wordpress-key-canary", rendered_url_data)
        self.assertNotIn("http-password-canary", rendered_url_data)

    @mock.patch("apps.console.connection.models.requests.get")
    def test_untrusted_url_ambient_data_and_query_credentials_fail_before_network(
        self, get
    ):
        row = self.make_auth()
        for invalid_url in (
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
        get.assert_not_called()

    @mock.patch("apps.console.connection.models.requests.get")
    def test_cross_account_ciphertext_transplant_fails_closed_before_network(
        self, get
    ):
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
        get.assert_not_called()

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
