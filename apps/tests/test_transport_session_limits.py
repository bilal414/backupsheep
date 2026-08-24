"""Regression tests for transport trust, browser sessions, and signed URLs."""

from __future__ import annotations

import inspect
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, override_settings

from apps.api.v1.utils.http import TimeoutSession
from apps.console.backup.models import BaseBackupStoragePoints, _presigned_url_expiry
from apps.signals import bind_auth_session_version
from backupsheep import settings as project_settings
from utils.middleware import (
    AUTH_SESSION_STARTED_AT_KEY,
    AuthenticationVersionMiddleware,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _CookieHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.observed_cookies.append(self.headers.get("Cookie"))
        body = b"bounded-stream-canary" if self.path == "/stream" else b""
        self.send_response(200)
        if self.path == "/seed":
            self.send_header(
                "Set-Cookie",
                "provider_session=cross-tenant-canary; Path=/; HttpOnly",
            )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        del format, args


class ProviderCookieIsolationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CookieHandler)
        cls.server.observed_cookies = []
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            name="provider-cookie-isolation",
            daemon=True,
        )
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)
        super().tearDownClass()

    def setUp(self):
        self.server.observed_cookies.clear()
        self.session = TimeoutSession()
        self.session.trust_env = False
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.session.close()

    def test_set_cookie_is_never_retained_or_sent_on_a_later_call(self):
        self.session.get(f"{self.base_url}/seed", timeout=(1, 1))
        self.session.get(f"{self.base_url}/later", timeout=(1, 1))

        self.assertEqual(self.server.observed_cookies, [None, None])
        self.assertEqual(list(self.session.cookies), [])

    def test_explicit_cookie_is_one_request_only(self):
        self.session.get(
            f"{self.base_url}/one-shot",
            cookies={"one_shot": "allowed-for-this-call"},
            timeout=(1, 1),
        )
        self.session.get(f"{self.base_url}/later", timeout=(1, 1))

        self.assertIn("one_shot=allowed-for-this-call", self.server.observed_cookies[0])
        self.assertIsNone(self.server.observed_cookies[1])

    def test_streaming_responses_remain_lazy_and_readable(self):
        with self.session.get(
            f"{self.base_url}/stream",
            stream=True,
            timeout=(1, 1),
        ) as response:
            self.assertFalse(response._content_consumed)
            self.assertEqual(b"".join(response.iter_content(4)), b"bounded-stream-canary")

    @override_settings(PROVIDER_HTTP_MAX_POOL_CONNECTIONS=73)
    def test_connection_pooling_is_preserved_and_bounded(self):
        session = TimeoutSession()
        try:
            self.assertEqual(session.adapters["https://"]._pool_connections, 73)
            self.assertEqual(session.adapters["https://"]._pool_maxsize, 73)
        finally:
            session.close()


class PresignedDownloadLifetimeTests(SimpleTestCase):
    @override_settings(S3_DOWNLOAD_URL_EXPIRES=999_999)
    def test_runtime_helper_never_exceeds_one_hour(self):
        self.assertEqual(_presigned_url_expiry(), 3600)

    @override_settings(S3_DOWNLOAD_URL_EXPIRES=300)
    def test_runtime_helper_accepts_secure_five_minute_default(self):
        self.assertEqual(_presigned_url_expiry(), 300)

    def test_all_configurable_download_signatures_use_the_bounded_helper(self):
        source = inspect.getsource(BaseBackupStoragePoints.generate_download_url)

        self.assertIn("expiration=timedelta(seconds=_presigned_url_expiry())", source)
        self.assertIn("sas_expiry = datetime.datetime.now(", source)
        self.assertIn("datetime.timezone.utc", source)
        self.assertIn("seconds=_presigned_url_expiry()", source)
        self.assertRegex(
            source,
            r'bucket\.sign_url\(\s*"GET",\s*self\.storage_file_id,'
            r"\s*_presigned_url_expiry\(\)",
        )
        self.assertIn("Expired=_presigned_url_expiry()", source)
        self.assertNotIn("timedelta(hours=24)", source)
        self.assertNotIn("timedelta(hours=48)", source)
        self.assertNotIn("3600 * 24", source)
        self.assertNotIn("24 * 3600", source)


class AbsoluteBrowserSessionTests(SimpleTestCase):
    @staticmethod
    def _request(started_at):
        session = {}
        if started_at is not None:
            session[AUTH_SESSION_STARTED_AT_KEY] = started_at
        return SimpleNamespace(
            user=SimpleNamespace(is_authenticated=True),
            session=session,
        )

    @mock.patch("utils.middleware.wall_time", return_value=1_000_000)
    @mock.patch("django.contrib.auth.logout")
    def test_expired_and_legacy_sessions_are_logged_out(self, logout, _clock):
        middleware = AuthenticationVersionMiddleware(lambda request: request)

        middleware(self._request(1_000_000 - project_settings.SESSION_COOKIE_AGE))
        middleware(self._request(None))

        self.assertEqual(logout.call_count, 2)

    @mock.patch("utils.middleware.wall_time", return_value=1_000_000)
    @mock.patch("django.contrib.auth.logout")
    def test_fresh_session_remains_authenticated(self, logout, _clock):
        middleware = AuthenticationVersionMiddleware(lambda request: request)

        middleware(self._request(1_000_000 - 60))

        logout.assert_not_called()

    @mock.patch("apps.signals.wall_time", return_value=123_456)
    def test_every_login_records_immutable_session_start(self, _clock):
        request = SimpleNamespace(session={})

        bind_auth_session_version(
            sender=None,
            request=request,
            user=SimpleNamespace(),
        )

        self.assertEqual(request.session[AUTH_SESSION_STARTED_AT_KEY], 123_456)


class ProductionTransportSettingsSubprocessTests(SimpleTestCase):
    """Import settings in a clean process so import-time gates are exercised."""

    CONFIG_KEYS = {
        "BACKUPSHEEP_SECRETS",
        "DATABASE_URL",
        "DJANGO_SECRET_KEY_FILE",
        "DB_PASSWORD_FILE",
        "RABBITMQ_PASSWORD_FILE",
        "ONBOARDING_INSTALL_TOKEN_SECRET_FILE",
        "DB_SSLMODE",
        "DB_SSLROOTCERT",
        "PGHOST",
        "PGHOSTADDR",
        "PGSERVICE",
        "PGSERVICEFILE",
        "CELERY_BROKER_URL",
        "CLOUDAMQP_URL",
        "RABBITMQ_SCHEME",
        "RABBITMQ_HOST",
        "RABBITMQ_PORT",
        "RABBITMQ_USER",
        "RABBITMQ_PASSWORD",
        "RABBITMQ_VHOST",
        "RABBITMQ_CA_CERT",
        "SESSION_COOKIE_AGE",
        "SESSION_EXPIRE_AT_BROWSER_CLOSE",
        "S3_DOWNLOAD_URL_EXPIRES",
    }

    BASE_ENV = {
        "DJANGO_SERVER": "prod",
        "DJANGO_DEBUG": "false",
        "DJANGO_SECRET_KEY": "settings-subprocess-test-secret-not-for-production",
        "DJANGO_ALLOWED_HOSTS": "localhost",
        "DJANGO_HTTPS": "true",
        "APP_PROTOCOL": "https://",
        "APP_DOMAIN": "localhost",
        "DB_NAME": "backupsheep",
        "DB_USER": "backupsheep",
        "DB_PASSWORD": "db-test-password",
        "DB_HOST": "db",
        "DB_PORT": "5432",
        "DATABASE_URL": "",
        "DB_SSLMODE": "",
        "DB_SSLROOTCERT": "",
        "PGHOST": "",
        "PGHOSTADDR": "",
        "PGSERVICE": "",
        "PGSERVICEFILE": "",
        "CELERY_BROKER_URL": "",
        "CLOUDAMQP_URL": "",
        "RABBITMQ_SCHEME": "amqp",
        "RABBITMQ_HOST": "rabbitmq",
        "RABBITMQ_PORT": "5672",
        "RABBITMQ_USER": "backupsheep",
        "RABBITMQ_PASSWORD": "rabbit-test-password",
        "RABBITMQ_VHOST": "backupsheep",
        "RABBITMQ_CA_CERT": "",
        "SESSION_COOKIE_AGE": "43200",
        "SESSION_EXPIRE_AT_BROWSER_CLOSE": "true",
        "S3_DOWNLOAD_URL_EXPIRES": "300",
        "SENTRY_DSN": "",
    }

    def _run_settings(self, overrides=None, code="print('settings-imported')"):
        environment = os.environ.copy()
        for key in self.CONFIG_KEYS:
            environment.pop(key, None)
        environment.update(self.BASE_ENV)
        environment.update(overrides or {})
        return subprocess.run(
            [sys.executable, "-c", f"import backupsheep.settings as s; {code}"],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def assertSettingsRejected(self, overrides, message):
        result = self._run_settings(overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_stock_compose_plaintext_is_the_narrow_local_exception(self):
        result = self._run_settings(
            code=(
                "print(s.DATABASES['default']['HOST'], s.CELERY_BROKER_URL, "
                "s.SESSION_COOKIE_AGE, s.SESSION_EXPIRE_AT_BROWSER_CLOSE, "
                "s.SESSION_COOKIE_HTTPONLY, s.SESSION_COOKIE_SAMESITE, "
                "s.S3_DOWNLOAD_URL_EXPIRES)"
            )
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "db amqp://backupsheep:rabbit-test-password@rabbitmq:5672/backupsheep "
            "43200 True True Lax 300",
            result.stdout,
        )

    def test_external_postgresql_rejects_plaintext_or_weak_tls(self):
        self.assertSettingsRejected(
            {"DB_HOST": "postgres.example.invalid"},
            "External PostgreSQL requires sslmode=verify-full",
        )
        self.assertSettingsRejected(
            {
                "DATABASE_URL": (
                    "postgresql:///backup?host=postgres.example.invalid"
                )
            },
            "External PostgreSQL requires sslmode=verify-full",
        )
        self.assertSettingsRejected(
            {"PGHOSTADDR": "10.0.0.8"},
            "External PostgreSQL requires sslmode=verify-full",
        )
        self.assertSettingsRejected(
            {
                "DB_HOST": "postgres.example.invalid",
                "DB_SSLMODE": "require",
                "DB_SSLROOTCERT": "/run/secrets/postgres-ca.pem",
            },
            "External PostgreSQL requires sslmode=verify-full",
        )

    def test_external_postgresql_accepts_verified_tls_with_ca(self):
        result = self._run_settings(
            {
                "DATABASE_URL": (
                    "postgresql://backup:secret@postgres.example.invalid:5432/backup"
                    "?sslmode=verify-full&sslrootcert=%2Frun%2Fsecrets%2Fpostgres-ca.pem"
                )
            },
            code=(
                "print(s.DATABASES['default']['HOST'], "
                "s.DATABASES['default']['OPTIONS']['sslmode'], "
                "s.DATABASES['default']['OPTIONS']['sslrootcert'])"
            ),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "postgres.example.invalid verify-full /run/secrets/postgres-ca.pem",
            result.stdout,
        )

    def test_external_rabbitmq_rejects_plaintext(self):
        self.assertSettingsRejected(
            {
                "RABBITMQ_HOST": "mq.example.invalid",
                "RABBITMQ_SCHEME": "amqp",
            },
            "External RabbitMQ requires amqps://",
        )

    def test_external_rabbitmq_enforces_ca_and_hostname_verification(self):
        result = self._run_settings(
            {
                "RABBITMQ_HOST": "mq.example.invalid",
                "RABBITMQ_PORT": "5671",
                "RABBITMQ_SCHEME": "amqps",
                "RABBITMQ_CA_CERT": "/run/secrets/rabbitmq-ca.pem",
            },
            code=(
                "from backupsheep.celery import app; "
                "connection = app.connection_for_write(); "
                "print(connection.as_uri(include_password=False), "
                "int(connection.ssl['cert_reqs']), "
                "connection.ssl['server_hostname'], "
                "connection.ssl['ca_certs'])"
            ),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "amqps://backupsheep:**@mq.example.invalid:5671/"
            "backupsheep 2 mq.example.invalid /run/secrets/rabbitmq-ca.pem",
            result.stdout,
        )

    def test_broker_url_cannot_override_tls_verification(self):
        self.assertSettingsRejected(
            {
                "RABBITMQ_HOST": "",
                "CELERY_BROKER_URL": (
                    "amqps://backup:secret@mq.example.invalid/vhost"
                    "?ssl_cert_reqs=CERT_NONE"
                ),
            },
            "certificate and hostname verification cannot be overridden",
        )

    def test_browser_session_and_signed_url_limits_fail_closed(self):
        self.assertSettingsRejected(
            {"SESSION_COOKIE_AGE": "43201"},
            "SESSION_COOKIE_AGE must be between 1 and 43200 seconds",
        )
        self.assertSettingsRejected(
            {"S3_DOWNLOAD_URL_EXPIRES": "3601"},
            "S3_DOWNLOAD_URL_EXPIRES must be between 1 and 3600 seconds",
        )


class LocalTransportClassificationTests(SimpleTestCase):
    def test_only_exact_compose_loopback_and_unix_endpoints_are_local(self):
        self.assertTrue(project_settings._is_local_transport_host("db", "db"))
        self.assertTrue(project_settings._is_local_transport_host("127.0.0.1", "db"))
        self.assertTrue(project_settings._is_local_transport_host("::1", "db"))
        self.assertTrue(
            project_settings._is_local_transport_host(
                "/var/run/postgresql",
                "db",
            )
        )
        self.assertFalse(project_settings._is_local_transport_host("db.internal", "db"))
        self.assertFalse(project_settings._is_local_transport_host("10.0.0.8", "db"))
