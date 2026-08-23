import ipaddress
import socket
from unittest import mock

from django.test import SimpleTestCase, override_settings

from apps.api.v1.utils.wordpress_transport import (
    WordPressPinnedHTTPSAdapter,
    WordPressTransportError,
    pinned_wordpress_get,
    resolve_wordpress_target,
)
from apps.console.connection.models import WORDPRESS_KEY_HEADER


def _answer(address):
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sockaddr = (str(parsed), 443, 0, 0) if parsed.version == 6 else (str(parsed), 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


class _FakeSocket:
    def __init__(self, peer):
        self.peer = peer

    def getpeername(self):
        return (self.peer, 443)


class _FakeResponse:
    def __init__(self, *, status_code=200, peer="8.8.8.8", content=b"{}"):
        self.status_code = status_code
        self.raw = type(
            "Raw",
            (),
            {
                "_connection": type(
                    "Connection",
                    (),
                    {"sock": _FakeSocket(peer)},
                )()
            },
        )()
        self.content = content
        self.closed = False

    def close(self):
        self.closed = True


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.trust_env = True
        self.mounts = {}
        self.calls = []
        self.closed = False

    def mount(self, prefix, adapter):
        self.mounts[prefix] = adapter

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response

    def close(self):
        self.closed = True


@override_settings(WORDPRESS_PRIVATE_TARGET_CIDRS=())
class WordPressTargetResolutionTests(SimpleTestCase):
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
        side_effect=socket.gaierror("no answer"),
    )
    def test_dns_failure_is_fail_closed(self, resolver):
        with self.assertRaisesRegex(WordPressTransportError, "resolution failed"):
            resolve_wordpress_target("https://wordpress.example.test")
        resolver.assert_called_once()

    def test_plaintext_http_is_rejected_before_resolution(self):
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo"
        ) as resolver:
            with self.assertRaisesRegex(WordPressTransportError, "require HTTPS"):
                resolve_wordpress_target("http://wordpress.example.test")
            resolver.assert_not_called()

    def test_metadata_hostname_and_link_local_addresses_are_always_rejected(self):
        with self.assertRaisesRegex(WordPressTransportError, "metadata"):
            resolve_wordpress_target("https://metadata.google.internal")

        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
            return_value=[_answer("169.254.169.254")],
        ):
            with self.assertRaisesRegex(WordPressTransportError, "target policy"):
                resolve_wordpress_target("https://wordpress.example.test")

        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
            return_value=[_answer("127.0.0.1")],
        ):
            with self.assertRaisesRegex(WordPressTransportError, "target policy"):
                resolve_wordpress_target("https://wordpress.example.test")

        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
            return_value=[_answer("::ffff:169.254.169.254")],
        ):
            with self.assertRaisesRegex(WordPressTransportError, "target policy"):
                resolve_wordpress_target("https://wordpress.example.test")

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
        return_value=[_answer("10.20.30.40")],
    )
    def test_private_address_is_rejected_by_default(self, resolver):
        with self.assertRaisesRegex(WordPressTransportError, "target policy"):
            resolve_wordpress_target("https://wordpress.example.test")

    @override_settings(
        WORDPRESS_PRIVATE_TARGET_CIDRS=(ipaddress.ip_network("10.20.30.0/24"),)
    )
    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
        return_value=[_answer("10.20.30.40")],
    )
    def test_explicit_private_cidr_is_allowed_but_still_pinned(self, resolver):
        target = resolve_wordpress_target(
            "https://private-wordpress.example.test:8443/site"
        )
        self.assertEqual(target.selected_ip, ipaddress.ip_address("10.20.30.40"))
        self.assertEqual(target.pinned_url, "https://10.20.30.40:8443/site/")
        self.assertEqual(target.authority, "private-wordpress.example.test:8443")

    @mock.patch(
        "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
        return_value=[_answer("8.8.8.8"), _answer("10.20.30.40")],
    )
    def test_mixed_public_private_dns_answer_rejects_the_entire_target(self, resolver):
        with self.assertRaisesRegex(WordPressTransportError, "target policy"):
            resolve_wordpress_target("https://wordpress.example.test")

    def test_private_catch_all_cannot_be_injected_at_runtime(self):
        with override_settings(
            WORDPRESS_PRIVATE_TARGET_CIDRS=(ipaddress.ip_network("0.0.0.0/0"),)
        ):
            with mock.patch(
                "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
                return_value=[_answer("10.20.30.40")],
            ):
                with self.assertRaisesRegex(
                    WordPressTransportError, "only RFC1918 or ULA"
                ):
                    resolve_wordpress_target("https://wordpress.example.test")

    def test_documentation_and_reserved_ranges_cannot_be_allowlisted_as_private(self):
        with override_settings(
            WORDPRESS_PRIVATE_TARGET_CIDRS=(ipaddress.ip_network("192.0.2.0/24"),)
        ):
            with mock.patch(
                "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
                return_value=[_answer("192.0.2.10")],
            ):
                with self.assertRaisesRegex(
                    WordPressTransportError, "only RFC1918 or ULA"
                ):
                    resolve_wordpress_target("https://wordpress.example.test")


@override_settings(WORDPRESS_PRIVATE_TARGET_CIDRS=())
class WordPressPinnedRequestTests(SimpleTestCase):
    def _public_target(self):
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
            return_value=[_answer("8.8.8.8")],
        ):
            return resolve_wordpress_target(
                "https://WordPress.Example.Test:443/subsite"
            )

    def test_adapter_preserves_tls_sni_and_hostname_verification(self):
        adapter = WordPressPinnedHTTPSAdapter("wordpress.example.test")
        pool = adapter.poolmanager.connection_pool_kw
        self.assertEqual(pool["server_hostname"], "wordpress.example.test")
        self.assertEqual(pool["assert_hostname"], "wordpress.example.test")
        self.assertEqual(adapter.max_retries.total, 0)
        with self.assertRaisesRegex(WordPressTransportError, "Proxies are disabled"):
            adapter.proxy_manager_for("https://proxy.example.test")

    def test_dns_is_resolved_once_then_request_uses_only_the_pinned_ip(self):
        resolver = mock.Mock(
            side_effect=[
                [_answer("8.8.8.8")],
                [_answer("10.20.30.40")],
            ]
        )
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.socket.getaddrinfo",
            resolver,
        ):
            target = resolve_wordpress_target(
                "https://wordpress.example.test/subsite"
            )

        response = _FakeResponse(peer="8.8.8.8")
        session = _FakeSession(response)
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.TimeoutSession",
            return_value=session,
        ):
            pinned_wordpress_get(
                target,
                params={"rest_route": "/backupsheep/updraftplus/status"},
                headers={WORDPRESS_KEY_HEADER: "header-key-canary"},
                auth=("http-user-canary", "http-password-canary"),
            )

        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(session.calls[0][0][0], "https://8.8.8.8:443/subsite/")
        self.assertFalse(session.trust_env)
        self.assertTrue(session.closed)
        adapter = session.mounts["https://"]
        self.assertEqual(adapter.tls_hostname, "wordpress.example.test")

    def test_redirect_is_returned_without_replay_and_url_query_never_contains_secrets(self):
        target = self._public_target()
        response = _FakeResponse(status_code=302, peer="8.8.8.8")
        session = _FakeSession(response)
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.TimeoutSession",
            return_value=session,
        ):
            result = pinned_wordpress_get(
                target,
                params={
                    "rest_route": "/backupsheep/updraftplus/status",
                    "backup_uuid": "backup-123",
                },
                headers={WORDPRESS_KEY_HEADER: "header-key-canary"},
                auth=("http-user-canary", "http-password-canary"),
            )

        self.assertIs(result, response)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(len(session.calls), 1)
        args, kwargs = session.calls[0]
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["verify"])
        self.assertEqual(kwargs["headers"]["Host"], "wordpress.example.test")
        self.assertEqual(
            kwargs["headers"][WORDPRESS_KEY_HEADER], "header-key-canary"
        )
        rendered_url_data = repr((args[0], kwargs["params"]))
        self.assertNotIn("header-key-canary", rendered_url_data)
        self.assertNotIn("http-password-canary", rendered_url_data)

    def test_observed_peer_mismatch_is_rejected(self):
        target = self._public_target()
        response = _FakeResponse(peer="1.1.1.1")
        session = _FakeSession(response)
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.TimeoutSession",
            return_value=session,
        ):
            with self.assertRaisesRegex(WordPressTransportError, "peer"):
                pinned_wordpress_get(
                    target,
                    params={},
                    headers={WORDPRESS_KEY_HEADER: "header-key-canary"},
                    auth=None,
                )
        self.assertTrue(response.closed)
        self.assertTrue(session.closed)

    def test_transport_rejects_credentials_under_any_query_name_before_connect(self):
        target = self._public_target()
        with mock.patch(
            "apps.api.v1.utils.wordpress_transport.TimeoutSession"
        ) as session_class:
            with self.assertRaisesRegex(WordPressTransportError, "query"):
                pinned_wordpress_get(
                    target,
                    params={"innocent_name": "header-key-canary"},
                    headers={WORDPRESS_KEY_HEADER: "header-key-canary"},
                    auth=None,
                )
        session_class.assert_not_called()
