from types import SimpleNamespace
from unittest import mock

from django.conf import settings

from apps.console.vultr_monitoring import (
    VultrMonitoringError,
    list_instance_backups,
)
from apps.tests.base import BaseTestCase


def _response(status_code, payload):
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: payload,
        close=lambda: None,
    )


class VultrAutomaticBackupMonitoringTests(BaseTestCase):
    def test_lists_all_cursor_pages_and_sanitizes_payload(self):
        auth = SimpleNamespace(get_client=lambda: {"Authorization": "Bearer test"})
        responses = [
            _response(
                200,
                {
                    "backups": [{"id": "b-1", "instance_id": "i-1", "status": "complete", "secret": "omit"}],
                    "meta": {"links": {"next": "cursor-2"}},
                },
            ),
            _response(
                200,
                {"backups": [{"id": "b-2", "instance_id": "i-1", "status": "pending"}], "meta": {}},
            ),
        ]
        with mock.patch("apps.console.vultr_monitoring.requests.get", side_effect=responses) as get:
            backups = list_instance_backups(auth, instance_id="i-1")

        self.assertEqual([backup["id"] for backup in backups], ["b-1", "b-2"])
        self.assertNotIn("secret", backups[0])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args_list[0].kwargs["timeout"], getattr(settings, "VULTR_API_TIMEOUT", (10, 60)))
        self.assertEqual(get.call_args_list[1].kwargs["params"]["cursor"], "cursor-2")

    def test_repeated_cursor_fails_closed(self):
        auth = SimpleNamespace(get_client=lambda: {})
        response = _response(
            200,
            {"backups": [], "meta": {"links": {"next": "same-cursor"}}},
        )
        with mock.patch("apps.console.vultr_monitoring.requests.get", return_value=response):
            with self.assertRaises(VultrMonitoringError) as raised:
                list_instance_backups(auth)
        self.assertEqual(raised.exception.classification, "malformed_pagination")

    def test_rate_limit_is_not_reported_as_empty_inventory(self):
        auth = SimpleNamespace(get_client=lambda: {})
        with mock.patch(
            "apps.console.vultr_monitoring.requests.get",
            return_value=_response(429, {"error": "rate limited"}),
        ):
            with self.assertRaises(VultrMonitoringError) as raised:
                list_instance_backups(auth)
        self.assertEqual(raised.exception.classification, "rate_limited")
