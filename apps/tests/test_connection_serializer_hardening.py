import json
from unittest.mock import patch

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.connection.models import CoreAuthDatabase, CoreAuthWebsite
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


class ConnectionCredentialSerializerTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.encryption_key = self.account.get_encryption_key()

    def _website_auth(
        self,
        *,
        use_public_key=False,
        use_private_key=False,
        password="website-password-secret",
        private_key=None,
    ):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="website",
            name="website credentials",
        )
        auth = CoreAuthWebsite.objects.create(
            connection=connection,
            host="website.example.test",
            port=22,
            protocol=CoreAuthWebsite.Protocol.SFTP,
            username=bs_encrypt("website-user", self.encryption_key),
            password=bs_encrypt(password, self.encryption_key),
            private_key=bs_encrypt(private_key, self.encryption_key),
            use_public_key=use_public_key,
            use_private_key=use_private_key,
        )
        return connection, auth

    def _database_auth(
        self,
        *,
        use_public_key=False,
        use_private_key=False,
        ssh_password="ssh-passphrase-secret",
        private_key="database-private-key-secret",
    ):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
            name="database credentials",
        )
        auth = CoreAuthDatabase.objects.create(
            connection=connection,
            host="database.example.test",
            port=5432,
            database_name="app_database",
            all_databases=False,
            username=bs_encrypt("database-user", self.encryption_key),
            password=bs_encrypt("database-password-secret", self.encryption_key),
            type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version=CoreAuthDatabase.DatabaseVersion.POSTGRESQL_16,
            ssh_host="ssh.example.test" if use_public_key or use_private_key else None,
            ssh_port=22 if use_public_key or use_private_key else None,
            ssh_username=bs_encrypt(
                "ssh-user" if use_public_key or use_private_key else None,
                self.encryption_key,
            ),
            ssh_password=bs_encrypt(
                ssh_password if use_private_key else None,
                self.encryption_key,
            ),
            private_key=bs_encrypt(
                private_key if use_private_key else None,
                self.encryption_key,
            ),
            use_public_key=use_public_key,
            use_private_key=use_private_key,
        )
        return connection, auth

    def test_website_read_response_never_contains_decrypted_secrets(self):
        connection, _auth = self._website_auth(
            use_private_key=True,
            private_key="website-private-key-secret",
        )

        response = self.client.get(f"/api/v1/connections/website/{connection.id}/")

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth_payload = response.json()["auth_website"]
        self.assertNotIn("password", auth_payload)
        self.assertNotIn("private_key", auth_payload)
        self.assertTrue(auth_payload["password_configured"])
        self.assertTrue(auth_payload["private_key_configured"])
        self.assertEqual(auth_payload["auth_mode"], "private_key")
        serialized = json.dumps(response.json())
        self.assertNotIn("website-password-secret", serialized)
        self.assertNotIn("website-private-key-secret", serialized)

    def test_database_read_response_never_contains_decrypted_secrets(self):
        connection, _auth = self._database_auth(use_private_key=True)

        response = self.client.get(f"/api/v1/connections/database/{connection.id}/")

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth_payload = response.json()["auth_database"]
        self.assertNotIn("password", auth_payload)
        self.assertNotIn("ssh_password", auth_payload)
        self.assertNotIn("private_key", auth_payload)
        self.assertTrue(auth_payload["password_configured"])
        self.assertTrue(auth_payload["ssh_password_configured"])
        self.assertTrue(auth_payload["private_key_configured"])
        self.assertEqual(auth_payload["auth_mode"], "private_key")
        serialized = json.dumps(response.json())
        self.assertNotIn("database-password-secret", serialized)
        self.assertNotIn("ssh-passphrase-secret", serialized)
        self.assertNotIn("database-private-key-secret", serialized)

    @patch.object(CoreAuthWebsite, "check_connection", return_value=True)
    def test_website_create_still_encrypts_write_only_credentials(self, _check):
        response = self.client.post(
            "/api/v1/connections/website/",
            {
                "name": "created website credentials",
                "location": factories.make_location().id,
                "auth_website": {
                    "host": "new-website.example.test",
                    "port": 22,
                    "protocol": CoreAuthWebsite.Protocol.SFTP,
                    "username": "new-website-user",
                    "password": "new-website-password",
                    "use_public_key": False,
                    "use_private_key": False,
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        auth = CoreAuthWebsite.objects.get(connection_id=response.json()["id"])
        self.assertNotEqual(bytes(auth.password), b"new-website-password")
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "new-website-password",
        )
        self.assertNotIn("new-website-password", json.dumps(response.json()))

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_database_create_still_encrypts_write_only_credentials(self, _check):
        response = self.client.post(
            "/api/v1/connections/database/",
            {
                "name": "created database credentials",
                "location": factories.make_location().id,
                "auth_database": {
                    "host": "new-database.example.test",
                    "port": 5432,
                    "database_name": "new_database",
                    "all_databases": False,
                    "username": "new-database-user",
                    "password": "new-database-password",
                    "type": CoreAuthDatabase.DatabaseType.POSTGRESQL,
                    "version": CoreAuthDatabase.DatabaseVersion.POSTGRESQL_16,
                    "use_public_key": False,
                    "use_private_key": False,
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        auth = CoreAuthDatabase.objects.get(connection_id=response.json()["id"])
        self.assertNotEqual(bytes(auth.password), b"new-database-password")
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "new-database-password",
        )
        self.assertNotIn("new-database-password", json.dumps(response.json()))

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_new_mysql_84_connection_defaults_database_tls_on(self, check):
        response = self.client.post(
            "/api/v1/connections/database/",
            {
                "name": "mysql 8.4 secure default",
                "location": factories.make_location().id,
                "auth_database": {
                    "host": "mysql84.example.test",
                    "port": 3306,
                    "database_name": "appdb",
                    "all_databases": False,
                    "username": "backup-user",
                    "password": "backup-password",
                    "type": CoreAuthDatabase.DatabaseType.MYSQL,
                    "version": CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
                    "use_public_key": False,
                    "use_private_key": False,
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        auth = CoreAuthDatabase.objects.get(connection_id=response.json()["id"])
        self.assertTrue(auth.use_ssl)
        self.assertTrue(check.call_args.kwargs["data"]["use_ssl"])

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_new_mysql_84_connection_preserves_explicit_tls_opt_out(self, check):
        response = self.client.post(
            "/api/v1/connections/database/",
            {
                "name": "mysql 8.4 explicit plaintext",
                "location": factories.make_location().id,
                "auth_database": {
                    "host": "mysql84.example.test",
                    "port": 3306,
                    "database_name": "appdb",
                    "all_databases": False,
                    "username": "backup-user",
                    "password": "backup-password",
                    "type": CoreAuthDatabase.DatabaseType.MYSQL,
                    "version": CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
                    "use_ssl": False,
                    "use_public_key": False,
                    "use_private_key": False,
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        auth = CoreAuthDatabase.objects.get(connection_id=response.json()["id"])
        self.assertFalse(auth.use_ssl)
        self.assertFalse(check.call_args.kwargs["data"]["use_ssl"])

    @patch.object(CoreAuthWebsite, "check_connection", return_value=True)
    def test_website_patch_omitted_private_key_and_passphrase_are_retained(self, check):
        connection, auth = self._website_auth(
            use_private_key=True,
            private_key="website-private-key-secret",
        )

        response = self.client.patch(
            f"/api/v1/connections/website/{connection.id}/",
            {"auth_website": {"info_name": "renamed"}},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "website-password-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.private_key, self.encryption_key),
            "website-private-key-secret",
        )
        checked = check.call_args.kwargs["data"]
        self.assertEqual(checked["password"], "website-password-secret")
        self.assertEqual(checked["private_key"], "website-private-key-secret")

    @patch.object(CoreAuthWebsite, "check_connection", return_value=True)
    def test_website_read_payload_can_be_patched_without_resending_secrets(self, _check):
        connection, auth = self._website_auth(
            use_private_key=True,
            private_key="website-private-key-secret",
        )
        read_response = self.client.get(
            f"/api/v1/connections/website/{connection.id}/"
        )
        auth_payload = read_response.json()["auth_website"]
        auth_payload["info_name"] = "round-trip edit"

        response = self.client.patch(
            f"/api/v1/connections/website/{connection.id}/",
            {"auth_website": auth_payload},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "website-password-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.private_key, self.encryption_key),
            "website-private-key-secret",
        )

    @patch.object(CoreAuthWebsite, "check_connection", return_value=True)
    def test_website_auth_mode_switch_clears_incompatible_secrets(self, check):
        connection, auth = self._website_auth(
            use_private_key=True,
            private_key="website-private-key-secret",
        )

        response = self.client.patch(
            f"/api/v1/connections/website/{connection.id}/",
            {
                "auth_website": {
                    "use_private_key": False,
                    "use_public_key": False,
                    "password": "replacement-login-password",
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertFalse(auth.use_private_key)
        self.assertFalse(auth.use_public_key)
        self.assertIsNone(auth.private_key)
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "replacement-login-password",
        )
        checked = check.call_args.kwargs["data"]
        self.assertIsNone(checked["private_key"])
        self.assertEqual(checked["password"], "replacement-login-password")

    @patch.object(CoreAuthWebsite, "check_connection", return_value=True)
    def test_website_switch_to_private_key_does_not_reuse_login_password(self, check):
        connection, auth = self._website_auth()

        response = self.client.patch(
            f"/api/v1/connections/website/{connection.id}/",
            {
                "auth_website": {
                    "use_private_key": True,
                    "private_key": "replacement-private-key",
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertTrue(auth.use_private_key)
        self.assertIsNone(auth.password)
        self.assertEqual(
            bs_decrypt(auth.private_key, self.encryption_key),
            "replacement-private-key",
        )
        self.assertIsNone(check.call_args.kwargs["data"]["password"])

    def test_website_rejects_two_key_auth_modes(self):
        connection, _auth = self._website_auth()

        response = self.client.patch(
            f"/api/v1/connections/website/{connection.id}/",
            {
                "auth_website": {
                    "use_public_key": True,
                    "use_private_key": True,
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        errors = response.json()["auth_website"]
        self.assertIn("use_public_key", errors)
        self.assertIn("use_private_key", errors)

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_database_patch_omitted_secrets_are_retained(self, check):
        connection, auth = self._database_auth(use_private_key=True)

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {"auth_database": {"info_name": "renamed"}},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "database-password-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.ssh_password, self.encryption_key),
            "ssh-passphrase-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.private_key, self.encryption_key),
            "database-private-key-secret",
        )
        checked = check.call_args.kwargs["data"]
        self.assertEqual(checked["password"], "database-password-secret")
        self.assertEqual(checked["ssh_password"], "ssh-passphrase-secret")
        self.assertEqual(checked["private_key"], "database-private-key-secret")

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_database_read_payload_can_be_patched_without_resending_secrets(self, _check):
        connection, auth = self._database_auth(use_private_key=True)
        read_response = self.client.get(
            f"/api/v1/connections/database/{connection.id}/"
        )
        auth_payload = read_response.json()["auth_database"]
        auth_payload["info_name"] = "round-trip edit"

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {"auth_database": auth_payload},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "database-password-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.ssh_password, self.encryption_key),
            "ssh-passphrase-secret",
        )
        self.assertEqual(
            bs_decrypt(auth.private_key, self.encryption_key),
            "database-private-key-secret",
        )

    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_database_switch_to_direct_clears_all_ssh_credentials(self, check):
        connection, auth = self._database_auth(use_private_key=True)

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {
                "auth_database": {
                    "use_public_key": False,
                    "use_private_key": False,
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.password, self.encryption_key),
            "database-password-secret",
        )
        self.assertFalse(auth.use_public_key)
        self.assertFalse(auth.use_private_key)
        self.assertIsNone(auth.ssh_host)
        self.assertIsNone(auth.ssh_port)
        self.assertIsNone(auth.ssh_username)
        self.assertIsNone(auth.ssh_password)
        self.assertIsNone(auth.private_key)
        checked = check.call_args.kwargs["data"]
        self.assertIsNone(checked["ssh_host"])
        self.assertIsNone(checked["ssh_username"])
        self.assertIsNone(checked["ssh_password"])
        self.assertIsNone(checked["private_key"])

    @override_settings(
        SSH_MANAGED_PUBLIC_KEY=(
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIG1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1t"
        )
    )
    @patch.object(CoreAuthDatabase, "check_connection", return_value=True)
    def test_database_switch_to_public_key_clears_private_key_and_passphrase(self, _check):
        connection, auth = self._database_auth(use_private_key=True)

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {"auth_database": {"use_public_key": True}},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        auth.refresh_from_db()
        self.assertTrue(auth.use_public_key)
        self.assertFalse(auth.use_private_key)
        self.assertEqual(auth.ssh_host, "ssh.example.test")
        self.assertEqual(
            bs_decrypt(auth.ssh_username, self.encryption_key),
            "ssh-user",
        )
        self.assertIsNone(auth.ssh_password)
        self.assertIsNone(auth.private_key)

    def test_database_rejects_private_key_mode_without_required_ssh_fields(self):
        connection, _auth = self._database_auth()

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {"auth_database": {"use_private_key": True}},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        errors = response.json()["auth_database"]
        self.assertIn("ssh_host", errors)
        self.assertIn("ssh_username", errors)
        self.assertIn("ssh_port", errors)
        self.assertIn("private_key", errors)

    @patch.object(
        CoreAuthDatabase,
        "check_connection",
        side_effect=TimeoutError("database-password-secret must never be returned"),
    )
    def test_database_validation_error_uses_shared_safe_structure(self, _check):
        connection, _auth = self._database_auth()

        response = self.client.patch(
            f"/api/v1/connections/database/{connection.id}/",
            {"auth_database": {"info_name": "renamed"}},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        payload = response.json()["auth_database"]
        self.assertIn("non_field_errors", payload)
        self.assertEqual(
            payload["connection_error"],
            {
                "code": "TCP_TIMEOUT",
                "detail": "The destination did not respond before the connection timeout.",
                "stage": "tcp",
                "retryable": True,
                "remediation": (
                    "Allow the BackupSheep worker address through the firewall and "
                    "confirm the configured port is reachable."
                ),
            },
        )
        self.assertNotIn("database-password-secret", json.dumps(response.json()))
