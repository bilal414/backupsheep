"""Regression canaries for outbound credential and telemetry boundaries."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import sentry_sdk
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase
from sentry_sdk.client import Client
from sentry_sdk.transport import Transport

from apps.api.v1.utils.http import RequestsFacade, TimeoutSession
from backupsheep import settings as project_settings
from backupsheep.sentry_security import scrub_sentry_event


class _CapturingTransport(Transport):
    """An in-memory Sentry transport: using the network is impossible."""

    def __init__(self):
        super().__init__({})
        self.envelopes = []

    def capture_envelope(self, envelope):
        self.envelopes.append(envelope)


class SentryPrivacyBoundaryTests(SimpleTestCase):
    def test_configured_client_disables_high_risk_collection(self):
        client = sentry_sdk.get_client()

        self.assertIs(client.options["include_local_variables"], False)
        self.assertEqual(client.options["max_request_body_size"], "never")
        self.assertIs(client.options["send_default_pii"], False)
        self.assertIs(client.options["before_send"], scrub_sentry_event)
        self.assertIs(client.options["before_send_transaction"], scrub_sentry_event)
        self.assertEqual(
            client.options["traces_sample_rate"],
            project_settings.SENTRY_TRACES_SAMPLE_RATE,
        )
        self.assertEqual(
            client.options["profiles_sample_rate"],
            project_settings.SENTRY_PROFILES_SAMPLE_RATE,
        )

    def test_tracing_and_profiling_default_off_and_reject_invalid_values(self):
        with mock.patch.dict(project_settings.config, {}, clear=True):
            self.assertEqual(
                project_settings._sentry_sample_rate("SENTRY_TRACES_SAMPLE_RATE"),
                0,
            )
            self.assertEqual(
                project_settings._sentry_sample_rate("SENTRY_PROFILES_SAMPLE_RATE"),
                0,
            )

        with mock.patch.dict(
            project_settings.config,
            {"SENTRY_TRACES_SAMPLE_RATE": "1.01"},
            clear=True,
        ):
            with self.assertRaisesMessage(
                ImproperlyConfigured, "must be between 0 and 1"
            ):
                project_settings._sentry_sample_rate("SENTRY_TRACES_SAMPLE_RATE")

    def test_no_network_canary_scrubs_error_and_transaction_events(self):
        error_marker = "RAW-ERROR-CANARY-8c39d44f"
        transaction_marker = "RAW-TRANSACTION-CANARY-e2849c83"
        transport = _CapturingTransport()
        client = Client(
            dsn="https://public@example.invalid/1",
            transport=transport,
            default_integrations=False,
            before_send=scrub_sentry_event,
            before_send_transaction=scrub_sentry_event,
            include_local_variables=False,
            max_request_body_size="never",
            send_default_pii=False,
            traces_sample_rate=1,
            profiles_sample_rate=0,
        )

        now = time.time()
        with sentry_sdk.isolation_scope() as scope:
            scope.set_client(client)
            sentry_sdk.capture_event(
                {
                    "message": error_marker,
                    "exception": {
                        "values": [
                            {
                                "type": "RuntimeError",
                                "value": error_marker,
                                "stacktrace": {
                                    "frames": [
                                        {
                                            "filename": "backup.py",
                                            "vars": {"decrypted_password": error_marker},
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                    "breadcrumbs": {
                        "values": [{"message": error_marker, "data": {"raw": error_marker}}]
                    },
                    "extra": {"raw": error_marker},
                    "contexts": {"provider": {"raw": error_marker}},
                    "request": {
                        "url": (
                            "https://provider.example.invalid/reset/"
                            f"{error_marker}?next={error_marker}"
                        ),
                        "path": f"/reset/{error_marker}",
                        "query_string": error_marker,
                        "data": error_marker,
                        "headers": {"X-Diagnostic": error_marker},
                        "cookies": {"session": error_marker},
                    },
                }
            )
            sentry_sdk.capture_event(
                {
                    "type": "transaction",
                    "transaction": f"/backup/{transaction_marker}",
                    "start_timestamp": now - 1,
                    "timestamp": now,
                    "contexts": {
                        "trace": {
                            "trace_id": "a" * 32,
                            "span_id": "b" * 16,
                        },
                        "provider": {"raw": transaction_marker},
                    },
                    "extra": {"raw": transaction_marker},
                    "breadcrumbs": {
                        "values": [{"message": transaction_marker}]
                    },
                    "spans": [
                        {
                            "trace_id": "a" * 32,
                            "span_id": "c" * 16,
                            "parent_span_id": "b" * 16,
                            "start_timestamp": now - 1,
                            "timestamp": now,
                            "op": transaction_marker,
                            "description": transaction_marker,
                            "data": {"raw": transaction_marker},
                        }
                    ],
                }
            )
        client.flush()

        self.assertEqual(len(transport.envelopes), 2)
        payloads = []
        for envelope in transport.envelopes:
            for item in envelope.items:
                payload = item.get_event() or item.get_transaction_event()
                if payload is not None:
                    payloads.append(payload)
        serialized = json.dumps(payloads, sort_keys=True)
        self.assertNotIn(error_marker, serialized)
        self.assertNotIn(transaction_marker, serialized)
        self.assertEqual(len(payloads), 2)


class _RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.observed_requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body,
            }
        )
        if self.path == "/redirect":
            self.send_response(307)
            self.send_header("Location", "/sink")
        else:
            self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        del format, args


class ProviderRedirectBoundaryTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        cls.server.observed_requests = []
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            name="provider-redirect-regression",
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
        self.server.observed_requests.clear()

    def test_307_does_not_replay_postmark_token_authorization_or_body(self):
        marker = "POSTMARK-REDIRECT-CANARY-ae99bd31"
        requests = RequestsFacade()
        requests._session.trust_env = False

        response = requests.post(
            f"http://127.0.0.1:{self.server.server_port}/redirect",
            headers={
                "X-Postmark-Server-Token": marker,
                "Authorization": f"Bearer {marker}",
            },
            data=marker,
            timeout=(1, 1),
        )

        self.assertEqual(response.status_code, 307)
        self.assertEqual(len(self.server.observed_requests), 1)
        observed = self.server.observed_requests[0]
        self.assertEqual(observed["path"], "/redirect")
        self.assertEqual(observed["body"], marker.encode())
        self.assertEqual(observed["headers"]["Authorization"], f"Bearer {marker}")

    def test_explicit_automatic_redirect_opt_in_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "Automatic redirects are disabled"):
            TimeoutSession().post(
                "https://provider.example.invalid/resource",
                allow_redirects=True,
            )
