import errno
import socket
from unittest import mock

import paramiko
from django.test import SimpleTestCase, override_settings

from apps.console.connection.reliability import (
    ClassifiedConnectionError,
    classify_connection_error,
)
from apps.console.connection.ssh import open_ssh_client
from apps.api.v1.utils.http import TimeoutSession, _retry_policy


class ConnectionErrorClassificationTests(SimpleTestCase):
    def test_dns_failure_has_stable_safe_contract(self):
        failure = classify_connection_error(socket.gaierror("secret.example"))
        self.assertEqual(failure.code, "DNS_FAILURE")
        self.assertEqual(failure.stage, "dns")
        self.assertTrue(failure.retryable)
        self.assertNotIn("secret.example", failure.detail)

    def test_timeout_is_retryable_and_does_not_echo_exception(self):
        failure = classify_connection_error(
            TimeoutError("password=do-not-return-this")
        )
        self.assertEqual(failure.code, "TCP_TIMEOUT")
        self.assertTrue(failure.retryable)
        self.assertNotIn("do-not-return-this", failure.detail)

    def test_refused_connection_is_distinct_from_authentication(self):
        refused = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        self.assertEqual(
            classify_connection_error(refused).code, "CONNECTION_REFUSED"
        )
        auth = paramiko.AuthenticationException("username and password")
        self.assertEqual(classify_connection_error(auth).code, "AUTH_FAILED")

    def test_changed_host_key_is_permanent(self):
        failure = classify_connection_error(
            paramiko.BadHostKeyException("server", mock.Mock(), mock.Mock())
        )
        self.assertEqual(failure.code, "HOST_KEY_CHANGED")
        self.assertFalse(failure.retryable)


@override_settings(
    SSH_KNOWN_HOSTS_PATH="/tmp/backupsheep-test-known-hosts",
    SSH_CONNECT_TIMEOUT=7,
    SSH_BANNER_TIMEOUT=8,
    SSH_AUTH_TIMEOUT=9,
    SSH_KEEPALIVE_SECONDS=10,
)
class StrictSSHClientTests(SimpleTestCase):
    @mock.patch("apps.console.connection.ssh.configure_host_keys")
    @mock.patch("apps.console.connection.ssh.paramiko.SSHClient")
    def test_password_connect_is_bounded_and_disables_ambient_keys(
        self, client_class, configure_host_keys
    ):
        client = client_class.return_value
        transport = client.get_transport.return_value

        returned, temporary_key = open_ssh_client(
            host="example.invalid",
            port=2222,
            username="backup",
            password="not-returned",
        )

        self.assertIs(returned, client)
        self.assertIsNone(temporary_key)
        configure_host_keys.assert_called_once_with(client)
        client.connect.assert_called_once_with(
            hostname="example.invalid",
            port=2222,
            username="backup",
            timeout=7,
            banner_timeout=8,
            auth_timeout=9,
            allow_agent=False,
            look_for_keys=False,
            password="not-returned",
        )
        transport.set_keepalive.assert_called_once_with(10)

    @mock.patch("apps.console.connection.ssh.configure_host_keys")
    @mock.patch("apps.console.connection.ssh.paramiko.SSHClient")
    def test_raw_client_error_is_classified(self, client_class, configure_host_keys):
        client_class.return_value.connect.side_effect = socket.timeout(
            "credential fragment"
        )
        with self.assertRaises(ClassifiedConnectionError) as raised:
            open_ssh_client(
                host="example.invalid",
                port=22,
                username="backup",
                password="secret",
            )
        self.assertEqual(raised.exception.code, "TCP_TIMEOUT")
        self.assertNotIn("credential fragment", str(raised.exception))


@override_settings(
    PROVIDER_HTTP_CONNECT_TIMEOUT=3,
    PROVIDER_HTTP_READ_TIMEOUT=11,
    PROVIDER_HTTP_MAX_RETRIES=5,
)
class ProviderHTTPClientTests(SimpleTestCase):
    @mock.patch("apps.api.v1.utils.http._requests.Session.request")
    def test_default_timeout_is_applied(self, request):
        request.return_value = mock.Mock(status_code=200)
        TimeoutSession().get("https://provider.example.invalid/resource")
        self.assertEqual(request.call_args.kwargs["timeout"], (3.0, 11.0))

    @mock.patch("apps.api.v1.utils.http._requests.Session.request")
    def test_explicit_provider_timeout_is_preserved(self, request):
        request.return_value = mock.Mock(status_code=200)
        TimeoutSession().get(
            "https://provider.example.invalid/resource", timeout=(1, 2)
        )
        self.assertEqual(request.call_args.kwargs["timeout"], (1, 2))

    def test_retry_policy_honors_retry_after_only_for_idempotent_methods(self):
        policy = _retry_policy()
        self.assertEqual(policy.total, 5)
        self.assertTrue(policy.respect_retry_after_header)
        self.assertIn("GET", policy.allowed_methods)
        self.assertIn("PUT", policy.allowed_methods)
        self.assertNotIn("POST", policy.allowed_methods)
