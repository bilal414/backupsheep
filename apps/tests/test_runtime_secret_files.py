import os
import tempfile
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from backupsheep.runtime_secrets import resolve_file_backed_secrets


class RuntimeSecretFileTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.secret_root = Path(self.temporary_directory.name) / "run" / "secrets"
        self.secret_root.mkdir(parents=True, mode=0o700)

    def tearDown(self):
        self.temporary_directory.cleanup()
        super().tearDown()

    def _secret(self, name, value="correct horse battery staple"):
        path = self.secret_root / name
        path.write_text(f"{value}\n", encoding="utf-8")
        path.chmod(0o444)
        return path

    def test_allowlisted_files_override_direct_environment_values(self):
        original_process_value = os.environ.get("DJANGO_SECRET_KEY")
        django_secret = self._secret("django_secret_key", "file-django-secret")
        db_secret = self._secret("db_password", "file-db-secret")
        rabbit_secret = self._secret("rabbitmq_password", "file-rabbit-secret")
        onboarding_secret = self._secret("onboarding_token", "file-install-token")

        resolved = resolve_file_backed_secrets(
            {
                "DJANGO_SECRET_KEY": "stale-environment-value",
                "DJANGO_SECRET_KEY_FILE": str(django_secret),
                "DB_PASSWORD_FILE": str(db_secret),
                "RABBITMQ_PASSWORD_FILE": str(rabbit_secret),
                "ONBOARDING_INSTALL_TOKEN_SECRET_FILE": str(onboarding_secret),
            },
            secret_root=self.secret_root,
        )

        self.assertEqual(resolved["DJANGO_SECRET_KEY"], "file-django-secret")
        self.assertEqual(resolved["DB_PASSWORD"], "file-db-secret")
        self.assertEqual(resolved["RABBITMQ_PASSWORD"], "file-rabbit-secret")
        self.assertEqual(resolved["ONBOARDING_INSTALL_TOKEN"], "file-install-token")
        self.assertEqual(os.environ.get("DJANGO_SECRET_KEY"), original_process_value)

    def test_unrecognized_file_setting_is_not_read(self):
        outside = Path(self.temporary_directory.name) / "outside"
        outside.write_text("sensitive", encoding="utf-8")

        resolved = resolve_file_backed_secrets(
            {"UNRELATED_FILE": str(outside)},
            secret_root=self.secret_root,
        )

        self.assertNotIn("UNRELATED", resolved)

    def test_relative_and_outside_paths_fail_closed(self):
        outside = Path(self.temporary_directory.name) / "outside"
        outside.write_text("sensitive", encoding="utf-8")
        outside.chmod(0o400)

        for path in ("django_secret_key", str(outside)):
            with self.subTest(path=path), self.assertRaises(ImproperlyConfigured):
                resolve_file_backed_secrets(
                    {"DJANGO_SECRET_KEY_FILE": path},
                    secret_root=self.secret_root,
                )

    def test_symlink_nested_writable_and_multiline_secrets_fail_closed(self):
        safe = self._secret("safe", "secret")
        symlink = self.secret_root / "symlink"
        symlink.symlink_to(safe)
        nested_directory = self.secret_root / "nested"
        nested_directory.mkdir()
        nested = nested_directory / "secret"
        nested.write_text("secret", encoding="utf-8")
        nested.chmod(0o400)
        writable = self.secret_root / "writable"
        writable.write_text("secret", encoding="utf-8")
        writable.chmod(0o666)
        multiline = self.secret_root / "multiline"
        multiline.write_text("first\nsecond\n", encoding="utf-8")
        multiline.chmod(0o400)

        for path in (symlink, nested, writable, multiline):
            with self.subTest(path=path), self.assertRaises(ImproperlyConfigured):
                resolve_file_backed_secrets(
                    {"DB_PASSWORD_FILE": str(path)},
                    secret_root=self.secret_root,
                )

    def test_empty_and_oversized_secrets_fail_closed(self):
        empty = self.secret_root / "empty"
        empty.touch(mode=0o400)
        oversized = self.secret_root / "oversized"
        oversized.write_bytes(b"x" * 4097)
        oversized.chmod(0o400)

        for path in (empty, oversized):
            with self.subTest(path=path), self.assertRaises(ImproperlyConfigured):
                resolve_file_backed_secrets(
                    {"RABBITMQ_PASSWORD_FILE": str(path)},
                    secret_root=self.secret_root,
                )
