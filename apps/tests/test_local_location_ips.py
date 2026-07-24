"""Tests for the self-hosted ("local") location public-IP detection:
CoreConnectionLocation.refresh_local_ip_addresses() and the middleware that triggers
it when the connection-setup endpoints dropdown data is fetched. All HTTP is mocked.
"""
from unittest import mock

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from apps.console.connection.models import CoreConnectionLocation
from utils.middleware import LocalLocationIPMiddleware

V4_URL = "https://v4-lookup.example.test"
V6_URL = "https://v6-lookup.example.test"
IP4 = "203.0.113.10"
IP6 = "2001:db8::10"

_LOOKUP_URLS = override_settings(
    PUBLIC_IPV4_LOOKUP_URL=V4_URL,
    PUBLIC_IPV6_LOOKUP_URL=V6_URL,
)


def _response(text):
    return mock.Mock(text=text)


def _fake_get(v4_text=IP4, v6_text=IP6, v4_error=None, v6_error=None):
    """Build a requests.get replacement dispatching on the lookup URL."""
    def get(url, timeout=None):
        if url == V4_URL:
            if v4_error:
                raise v4_error
            return _response(v4_text)
        if url == V6_URL:
            if v6_error:
                raise v6_error
            return _response(v6_text)
        raise AssertionError(f"unexpected URL: {url}")
    return get


@_LOOKUP_URLS
class RefreshLocalIPTests(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.location = CoreConnectionLocation.objects.get(code="local")  # seeded by 0007
        self.location.ip_address = None
        self.location.ip_address_v6 = None
        self.location.save()

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def _refresh(self):
        CoreConnectionLocation.refresh_local_ip_addresses()
        self.location.refresh_from_db()

    @mock.patch("apps.console.connection.models.requests.get")
    def test_v4_and_v6_success_persisted(self, mock_get):
        mock_get.side_effect = _fake_get()
        self._refresh()
        self.assertEqual(self.location.ip_address, IP4)
        self.assertEqual(self.location.ip_address_v6, IP6)
        self.assertEqual(mock_get.call_count, 2)
        # URLs from settings were used.
        called_urls = {call.args[0] for call in mock_get.call_args_list}
        self.assertEqual(called_urls, {V4_URL, V6_URL})

    @mock.patch("apps.console.connection.models.requests.get")
    def test_second_call_within_24h_is_throttled(self, mock_get):
        mock_get.side_effect = _fake_get()
        self._refresh()
        self._refresh()
        self.assertEqual(mock_get.call_count, 2)  # no new network hits

    @mock.patch("apps.console.connection.models.requests.get")
    def test_v6_failure_keeps_old_v6_and_still_updates_v4(self, mock_get):
        self.location.ip_address_v6 = "2001:db8::1"
        self.location.save()
        mock_get.side_effect = _fake_get(v6_error=ConnectionError("no ipv6 route"))
        self._refresh()
        self.assertEqual(self.location.ip_address, IP4)  # v4 still updated
        self.assertEqual(self.location.ip_address_v6, "2001:db8::1")  # untouched

    @mock.patch("apps.console.connection.models.requests.get")
    def test_invalid_response_body_leaves_fields_unchanged(self, mock_get):
        mock_get.side_effect = _fake_get(v4_text="not-an-ip", v6_text="<html>404</html>")
        self._refresh()  # exceptions swallowed
        self.assertIsNone(self.location.ip_address)
        self.assertIsNone(self.location.ip_address_v6)

    @mock.patch("apps.console.connection.models.requests.get")
    def test_request_exception_sets_failure_throttle(self, mock_get):
        mock_get.side_effect = _fake_get(
            v4_error=ConnectionError("down"), v6_error=ConnectionError("down")
        )
        self._refresh()
        self.assertIsNone(self.location.ip_address)
        self.assertIsNone(self.location.ip_address_v6)
        self.assertIsNotNone(cache.get(CoreConnectionLocation.LOCAL_IP_CACHE_KEY))
        # A retry right away is throttled (~15 min) instead of hammering the service.
        self._refresh()
        self.assertEqual(mock_get.call_count, 2)

    @mock.patch("apps.console.connection.models.requests.get")
    def test_missing_local_row_is_quiet(self, mock_get):
        # The seeded "local" row can't be .delete()d (PROTECT integration links), so
        # simulate its absence at the queryset level.
        with mock.patch.object(CoreConnectionLocation, "objects") as mock_objects:
            mock_objects.filter.return_value.first.return_value = None
            CoreConnectionLocation.refresh_local_ip_addresses()  # no crash
        mock_get.assert_not_called()


class LocalLocationIPMiddlewareTests(TestCase):
    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        self.sentinel = object()
        self.middleware = LocalLocationIPMiddleware(lambda request: self.sentinel)

    def _call(self, method, path):
        request = getattr(self.factory, method.lower())(path)
        with mock.patch.object(
            CoreConnectionLocation, "refresh_local_ip_addresses"
        ) as mock_refresh:
            response = self.middleware(request)
        return mock_refresh, response

    def test_get_on_endpoints_path_invokes_refresh(self):
        mock_refresh, response = self._call("GET", "/api/v1/connections/upcloud/endpoints/")
        mock_refresh.assert_called_once_with()
        self.assertIs(response, self.sentinel)  # response unaffected

    def test_non_matching_path_does_not_invoke_refresh(self):
        for path in (
            "/api/v1/connections/upcloud/",
            "/api/v1/connections/",
            "/console/setup",
        ):
            mock_refresh, response = self._call("GET", path)
            mock_refresh.assert_not_called()
            self.assertIs(response, self.sentinel)

    def test_non_get_on_endpoints_path_does_not_invoke_refresh(self):
        mock_refresh, response = self._call("POST", "/api/v1/connections/upcloud/endpoints/")
        mock_refresh.assert_not_called()
        self.assertIs(response, self.sentinel)
