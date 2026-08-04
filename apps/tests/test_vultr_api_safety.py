from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from apps.console.vultr import (
    iter_vultr_collection,
    provider_classification,
    snapshot_matches,
)


class VultrApiSafetyHelperTests(SimpleTestCase):
    def response(self, payload, status_code=200):
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload,
            close=mock.Mock(),
        )

    def test_cursor_pagination_uses_next_cursor_and_timeout(self):
        get = mock.Mock(side_effect=[
            self.response({"snapshots": [{"id": "one"}], "meta": {"links": {"next": "c1"}}}),
            self.response({"snapshots": [{"id": "two"}], "meta": {"links": {"next": None}}}),
        ])
        values = list(iter_vultr_collection(
            get, "https://api.vultr.test/v2/snapshots", headers={}, item_key="snapshots"
        ))
        self.assertEqual([item["id"] for item in values], ["one", "two"])
        self.assertEqual(get.call_args_list[1].kwargs["params"]["cursor"], "c1")
        self.assertEqual(get.call_args_list[0].kwargs["timeout"], (10, 60))

    def test_repeated_cursor_fails_closed(self):
        get = mock.Mock(side_effect=[
            self.response({"snapshots": [], "meta": {"links": {"next": "same"}}}),
            self.response({"snapshots": [], "meta": {"links": {"next": "same"}}}),
        ])
        with self.assertRaisesRegex(ValueError, "repeated"):
            list(iter_vultr_collection(
                get, "https://api.vultr.test/v2/snapshots", headers={}, item_key="snapshots"
            ))

    def test_malformed_cursor_and_partial_page_fail_closed(self):
        malformed = mock.Mock(return_value=self.response({
            "snapshots": [], "meta": {"links": {"next": ["not-a-cursor"]}}
        }))
        with self.assertRaisesRegex(ValueError, "malformed cursor"):
            list(iter_vultr_collection(
                malformed, "https://api.vultr.test/v2/snapshots", headers={}, item_key="snapshots"
            ))

        failed = mock.Mock(return_value=self.response({}, status_code=502))
        with self.assertRaisesRegex(ValueError, "status 502"):
            list(iter_vultr_collection(
                failed, "https://api.vultr.test/v2/snapshots", headers={}, item_key="snapshots"
            ))

    def test_snapshot_identity_requires_all_ownership_fields(self):
        snapshot = {
            "id": "snap-1", "instance_id": "instance-1", "description": "backup-1"
        }
        self.assertTrue(snapshot_matches(
            snapshot, provider_id="snap-1", source_id="instance-1",
            description="backup-1", source_key="instance_id"
        ))
        self.assertFalse(snapshot_matches(
            snapshot, provider_id="snap-1", source_id="foreign",
            description="backup-1", source_key="instance_id"
        ))
        self.assertFalse(snapshot_matches(
            snapshot, provider_id="snap-1", source_id="instance-1",
            description="foreign", source_key="instance_id"
        ))

    def test_provider_classification_is_stable(self):
        self.assertEqual(provider_classification(401), "authentication")
        self.assertEqual(provider_classification(404), "missing")
        self.assertEqual(provider_classification(429), "rate_limited")
        self.assertEqual(provider_classification(503), "transient_provider_error")
        self.assertEqual(provider_classification(400), "permanent_provider_error")
