from datetime import timedelta
import io
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests as raw_requests
from django.test import SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.digitalocean import (
    DIGITALOCEAN_REQUEST_METADATA_KEY,
    _digitalocean_create_callback,
)
from apps.api.v1.connection.digitalocean import client as do_client
from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError
from apps.api.v1.connection.digitalocean.serializers import (
    CoreAuthDigitalOceanWriteSerializer,
)
from apps.api.v1.connection.digitalocean.views import CoreDigitalOceanView
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.backup.models import CoreCloudRestore, CoreDigitalOceanBackup
from apps.console.connection.models import CoreAuthDigitalOcean
from apps.console.node.models import CoreDigitalOcean, CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from scripts import digitalocean_live_e2e as live_harness


class Response:
    def __init__(self, status_code=200, payload=None, *, content=b"", headers=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.content = content
        self.headers = headers or {}
        self.closed = False

    def json(self):
        return self.payload

    def close(self):
        self.closed = True

    def iter_content(self, chunk_size=4096):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]


@override_settings(DIGITALOCEAN_API="https://api.digitalocean.com")
class DigitalOceanClientTests(SimpleTestCase):
    @mock.patch.object(do_client.requests, "request")
    def test_collection_follows_provider_next_link_and_proves_total(self, request):
        first = Response(
            payload={
                "snapshots": [
                    {
                        "id": "snapshot-1",
                        "name": "marker",
                        "resource_id": "source-1",
                        "resource_type": "volume",
                    }
                ],
                "meta": {"total": 2},
                "links": {
                    "pages": {
                        "next": "https://api.digitalocean.com/v2/snapshots?page=2&per_page=200&resource_type=volume"
                    }
                },
            }
        )
        second = Response(
            payload={
                "snapshots": [
                    {
                        "id": "snapshot-2",
                        "name": "other",
                        "resource_id": "source-2",
                        "resource_type": "volume",
                    }
                ],
                "meta": {"total": 2},
                "links": {},
            }
        )
        request.side_effect = [first, second]

        snapshots = do_client.iter_collection(
            "/v2/snapshots",
            "snapshots",
            headers={"Authorization": "Bearer redacted"},
            params={"resource_type": "volume"},
        )

        self.assertEqual([item["id"] for item in snapshots], ["snapshot-1", "snapshot-2"])
        self.assertEqual(request.call_count, 2)
        self.assertIn("timeout", request.call_args_list[0].kwargs)
        self.assertIn("timeout", request.call_args_list[1].kwargs)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    @mock.patch.object(do_client.requests, "request")
    def test_collection_rejects_cross_origin_next_link(self, request):
        request.return_value = Response(
            payload={
                "snapshots": [],
                "meta": {"total": 1},
                "links": {
                    "pages": {
                        "next": "https://credential-thief.invalid/v2/snapshots?page=2"
                    }
                },
            }
        )

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.iter_collection(
                "/v2/snapshots", "snapshots", headers={"Authorization": "secret"}
            )

        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")
        self.assertEqual(request.call_count, 1)

    @mock.patch.object(do_client.requests, "request")
    def test_collection_rejects_incomplete_final_page(self, request):
        request.return_value = Response(
            payload={"snapshots": [], "meta": {"total": 1}, "links": {}}
        )

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.iter_collection(
                "/v2/snapshots", "snapshots", headers={"Authorization": "secret"}
            )

        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")

    @mock.patch.object(do_client.requests, "request")
    def test_collection_rejects_repeated_item_across_pages(self, request):
        item = {
            "id": "snapshot-1",
            "name": "marker",
            "resource_id": "source-1",
            "resource_type": "droplet",
        }
        request.side_effect = [
            Response(
                payload={
                    "snapshots": [item],
                    "meta": {"total": 2},
                    "links": {
                        "pages": {
                            "next": "https://api.digitalocean.com/v2/snapshots?page=2"
                        }
                    },
                }
            ),
            Response(
                payload={"snapshots": [item], "meta": {"total": 2}, "links": {}}
            ),
        ]

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.iter_collection(
                "/v2/snapshots", "snapshots", headers={"Authorization": "secret"}
            )

        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")

    @override_settings(DIGITALOCEAN_API_MAX_PAGES=1)
    @mock.patch.object(do_client.requests, "request")
    def test_collection_stops_at_configured_page_bound(self, request):
        request.return_value = Response(
            payload={
                "snapshots": [
                    {
                        "id": "snapshot-1",
                        "name": "marker",
                        "resource_id": "source-1",
                        "resource_type": "droplet",
                    }
                ],
                "meta": {"total": 2},
                "links": {
                    "pages": {
                        "next": "https://api.digitalocean.com/v2/snapshots?page=2"
                    }
                },
            }
        )

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.iter_collection(
                "/v2/snapshots", "snapshots", headers={"Authorization": "redacted"}
            )

        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")
        self.assertEqual(request.call_count, 1)

    @mock.patch.object(do_client, "iter_collection")
    def test_exact_snapshot_requires_marker_source_and_type(self, collection):
        collection.return_value = [
            {
                "id": "snapshot-1",
                "name": "stable-marker",
                "resource_id": "source-1",
                "resource_type": "volume",
            }
        ]

        snapshot = do_client.find_exact_snapshot(
            headers={},
            marker="stable-marker",
            source_id="source-1",
            resource_type="volume",
        )

        self.assertEqual(snapshot["id"], "snapshot-1")
        self.assertEqual(
            collection.call_args.kwargs["params"], {"resource_type": "volume"}
        )

    @mock.patch.object(do_client, "iter_collection")
    def test_same_marker_for_another_source_fails_closed(self, collection):
        collection.return_value = [
            {
                "id": "snapshot-1",
                "name": "stable-marker",
                "resource_id": "another-source",
                "resource_type": "volume",
            }
        ]

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.find_exact_snapshot(
                headers={},
                marker="stable-marker",
                source_id="source-1",
                resource_type="volume",
            )

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")

    @mock.patch.object(do_client, "iter_collection")
    def test_duplicate_exact_marker_matches_fail_closed(self, collection):
        collection.return_value = [
            {
                "id": value,
                "name": "stable-marker",
                "resource_id": "source-1",
                "resource_type": "droplet",
            }
            for value in ("snapshot-1", "snapshot-2")
        ]

        with self.assertRaises(DigitalOceanAPIError) as raised:
            do_client.find_exact_snapshot(
                headers={},
                marker="stable-marker",
                source_id="source-1",
                resource_type="droplet",
            )

        self.assertEqual(raised.exception.code, "PROVIDER_DUPLICATE_MATCH")

    def test_personal_team_guard_requires_exact_name_and_uuid(self):
        account = {
            "team_name": "Personal",
            "team_uuid": "team-1",
            "account_uuid": "account-1",
            "status": "active",
        }
        live_harness.require_personal_team(
            account,
            expected_uuid="team-1",
            expected_name="Personal",
            mutation=True,
        )
        with self.assertRaises(live_harness.HarnessError):
            live_harness.require_personal_team(
                account,
                expected_uuid="other-team",
                expected_name="Personal",
                mutation=True,
            )

    def test_harness_resource_names_are_volume_safe_and_stable(self):
        run_id = "9" + ("a" * 61)
        first = live_harness._resource_name(run_id, "volume")
        second = live_harness._resource_name(run_id, "volume")

        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 64)
        self.assertTrue(first[0].isalpha())

    def test_harness_refuses_unledgered_name_and_tag_match(self):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_tag = "bs-e2e-do-test-run"
        harness.apply = False
        harness.intents = mock.Mock()
        harness.intents.get.return_value = None
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = None
        resource = {
            "id": "droplet-1",
            "name": "bs-e2e-do-test-run-droplet",
            "tags": [harness.run_tag],
        }
        harness._owned_candidates = mock.Mock(return_value=[resource])
        harness._read_resource = mock.Mock(return_value=resource)

        with self.assertRaises(live_harness.HarnessError):
            harness.ensure_source(
                "source_droplet",
                {
                    "name": resource["name"],
                    "region": "nyc3",
                    "size": "s-1vcpu-1gb",
                    "image": "ubuntu-24-04-x64",
                    "tags": [harness.run_tag],
                },
            )

    @mock.patch.object(live_harness.requests, "request")
    def test_harness_lost_mutation_response_is_ambiguous(self, request):
        request.side_effect = raw_requests.Timeout("credential-canary")

        with self.assertRaises(live_harness.AmbiguousMutation) as raised:
            live_harness._mutation_response(
                "POST",
                "/v2/droplets",
                headers={"Authorization": "Bearer credential-canary"},
                body={"name": "safe"},
            )

        self.assertNotIn("credential-canary", str(raised.exception))
        self.assertIn("timeout", request.call_args.kwargs)

    @mock.patch.object(live_harness.requests, "request")
    def test_harness_separates_not_found_rate_limit_and_transient_mutations(
        self, request
    ):
        for status_code, exception_type, message in (
            (404, live_harness.HarnessError, "rejected"),
            (429, live_harness.HarnessError, "rate-limited"),
            (503, live_harness.AmbiguousMutation, "transient"),
        ):
            with self.subTest(status_code=status_code):
                request.reset_mock()
                request.return_value = Response(status_code, {"message": "provider"})
                with self.assertRaises(exception_type) as raised:
                    live_harness._mutation_response(
                        "DELETE",
                        "/v2/droplets/droplet-1",
                        headers={"Authorization": "Bearer redacted"},
                    )
                self.assertIn(message, str(raised.exception))

    def _restore_witness(self):
        return {
            "target_kind": "droplet",
            "provider_id": "901",
            "name": "bs-e2e-do-test-run-restored",
            "snapshot_marker": "bs-ui-backup-marker",
            "restore_marker": "bs-ui-restore-marker",
            "marker": "bs-ui-restore-marker",
            "run_tag": "bs-e2e-do-test-run",
            "snapshot_id": "123456",
        }

    def _restore_candidate(self, **updates):
        witness = self._restore_witness()
        candidate = {
            "id": 901,
            "name": witness["name"],
            "tags": [
                witness["restore_marker"],
                "backupsheep-restore-droplet",
            ],
            "image": {"id": 123456},
            "status": "active",
        }
        candidate.update(updates)
        return candidate

    def test_harness_selects_one_exact_ui_restore_witness(self):
        selected = live_harness.select_ui_restore_witness(
            [self._restore_candidate()], self._restore_witness()
        )
        self.assertEqual(str(selected["id"]), "901")

    def test_harness_uses_ui_restore_marker_without_requiring_extra_ui_tag(self):
        candidate = self._restore_candidate()
        self.assertNotIn(self._restore_witness()["run_tag"], candidate["tags"])
        selected = live_harness.select_ui_restore_witness(
            [candidate], self._restore_witness()
        )
        self.assertEqual(str(selected["id"]), "901")

    def test_harness_refuses_restore_marker_mismatch(self):
        witness = self._restore_witness()
        witness["marker"] = "bs-ui-other-restore-marker"
        with self.assertRaises(live_harness.HarnessError):
            live_harness.select_ui_restore_witness(
                [self._restore_candidate()], witness
            )

    def test_cli_exposes_distinct_snapshot_and_restore_witnesses(self):
        parsed = live_harness._parser().parse_args(
            [
                "--run-id",
                "bs-e2e-do-test-run",
                "--ui-droplet-snapshot-marker",
                "bs-ui-backup-marker",
                "--ui-droplet-restore-marker",
                "bs-ui-restore-marker",
            ]
        )
        self.assertEqual(parsed.ui_droplet_snapshot_marker, "bs-ui-backup-marker")
        self.assertEqual(parsed.ui_droplet_restore_marker, "bs-ui-restore-marker")

    def test_harness_accepts_distinct_snapshot_and_restore_markers(self):
        witness = self._restore_witness()
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_tag = witness["run_tag"]
        harness.account = {"team_uuid": "team-uuid"}
        harness.headers = {"Authorization": "Bearer redacted"}
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": "team-uuid",
                "run_tag": witness["run_tag"],
                "snapshot_marker": witness["snapshot_marker"],
                "marker": witness["snapshot_marker"],
                "source_id": "source-1",
                "resource_type": "volume",
            },
        }
        candidate = {
            "id": 901,
            "name": witness["name"],
            "tags": [
                witness["restore_marker"],
                "backupsheep-restore-volume",
            ],
            "snapshot_id": 123456,
            "status": "available",
        }
        harness._read_resource = mock.Mock(return_value=candidate)
        with mock.patch.object(
            live_harness, "iter_collection", return_value=[candidate]
        ):
            result = harness.verify_ui_restore(
                target_kind="volume",
                provider_id=witness["provider_id"],
                name=witness["name"],
                snapshot_id=witness["snapshot_id"],
                run_tag=witness["run_tag"],
                snapshot_marker=witness["snapshot_marker"],
                restore_marker=witness["restore_marker"],
            )

        self.assertEqual(result["snapshot_marker"], witness["snapshot_marker"])
        self.assertEqual(result["restore_marker"], witness["restore_marker"])
        ownership = harness.ledger.record.call_args.kwargs["ownership"]
        self.assertEqual(ownership["snapshot_marker"], witness["snapshot_marker"])
        self.assertEqual(ownership["restore_marker"], witness["restore_marker"])

    def test_harness_refuses_snapshot_marker_mismatch_before_inventory(self):
        witness = self._restore_witness()
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_tag = witness["run_tag"]
        harness.account = {"team_uuid": "team-uuid"}
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": "team-uuid",
                "run_tag": witness["run_tag"],
                "snapshot_marker": witness["snapshot_marker"],
                "source_id": "source-1",
                "resource_type": "volume",
            },
        }

        with mock.patch.object(live_harness, "iter_collection") as inventory:
            with self.assertRaises(live_harness.HarnessError):
                harness.verify_ui_restore(
                    target_kind="volume",
                    provider_id=witness["provider_id"],
                    name=witness["name"],
                    snapshot_id=witness["snapshot_id"],
                    run_tag=witness["run_tag"],
                    snapshot_marker="bs-ui-wrong-backup-marker",
                    restore_marker=witness["restore_marker"],
                )

        inventory.assert_not_called()

    def test_harness_refuses_foreign_ui_restore_witness(self):
        with self.assertRaises(live_harness.HarnessError):
            live_harness.select_ui_restore_witness(
                [self._restore_candidate(image={"id": 999999})],
                self._restore_witness(),
            )

    def test_harness_refuses_duplicate_ui_restore_witnesses(self):
        duplicate = self._restore_candidate(id=902)
        with self.assertRaises(live_harness.HarnessError):
            live_harness.select_ui_restore_witness(
                [self._restore_candidate(), duplicate], self._restore_witness()
            )

    def test_harness_refuses_missing_ui_restore_witness(self):
        with self.assertRaises(live_harness.HarnessError):
            live_harness.select_ui_restore_witness([], self._restore_witness())

    @mock.patch.object(live_harness, "iter_collection")
    def test_harness_refuses_restore_snapshot_from_foreign_run_ledger(
        self, iter_collection
    ):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_tag = "bs-e2e-do-test-run"
        harness.account = {"team_uuid": "team-uuid"}
        harness.ledger = mock.Mock()
        harness.ledger.get.return_value = {
            "cleanup_state": "eligible",
            "ownership": {
                "team_uuid": "team-uuid",
                "run_tag": "foreign-run",
                "snapshot_marker": "bs-ui-backup-marker",
                "source_id": "source-volume",
                "resource_type": "volume",
            },
        }

        with self.assertRaises(live_harness.HarnessError):
            harness.verify_ui_restore(
                target_kind="volume",
                provider_id="901",
                name="bs-e2e-do-test-run-restored",
                marker="bs-ui-backup-marker",
                snapshot_id="123456",
                run_tag=harness.run_tag,
            )

        iter_collection.assert_not_called()

    def test_payload_is_deterministic_bounded_and_cloud_init_contains_no_credentials(self):
        first = live_harness._payload_expectation("bs-e2e-do-test-run")
        second = live_harness._payload_expectation("bs-e2e-do-test-run")
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(first["byte_count"], len(first["payload"]))
        self.assertLessEqual(first["byte_count"], live_harness.PAYLOAD_MAX_BYTES)
        cloud_init = live_harness._cloud_init("bs-e2e-do-test-run", first)
        self.assertIn(first["sha256"], cloud_init)
        self.assertNotIn("DIGITALOCEAN_TOKEN", cloud_init)
        self.assertNotIn("Authorization", cloud_init)
        # runcmd starts the service synchronously from cloud-final. Making the
        # service wait for cloud-final creates a dependency deadlock.
        self.assertNotIn("After=cloud-final.service", cloud_init)
        cloud_config = json.loads(cloud_init.split("\n", 1)[1])
        generated_server = next(
            item["content"]
            for item in cloud_config["write_files"]
            if item["path"] == "/opt/backupsheep-e2e/server.py"
        )
        compile(generated_server, "generated-digitalocean-server.py", "exec")

    def test_payload_firewall_requires_exact_host_cidrs(self):
        self.assertEqual(
            live_harness._probe_cidrs(["203.0.113.10/32", "2001:db8::10/128"]),
            ["203.0.113.10/32", "2001:db8::10/128"],
        )
        for unsafe in ("0.0.0.0/0", "203.0.113.0/24", "::/0"):
            with self.assertRaises(live_harness.HarnessError):
                live_harness._probe_cidrs([unsafe])

    @mock.patch.object(live_harness, "_mutation_response")
    def test_payload_firewall_uses_current_zero_all_ports_and_clears_definite_rejection(
        self, mutation_response
    ):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.account = {"team_uuid": "team-uuid"}
        harness.headers = {"Authorization": "Bearer redacted-test-token"}
        harness.probe_cidrs = ["203.0.113.10/32"]
        harness.apply = True
        harness.intents = mock.Mock()
        harness.intents.get.return_value = None
        harness.ledger = mock.Mock()
        harness._resources = mock.Mock(return_value=[])
        mutation_response.side_effect = live_harness.HarnessError(
            "DigitalOcean rejected the mutation."
        )

        with self.assertRaises(live_harness.HarnessError):
            harness.ensure_payload_firewall("901")

        request = mutation_response.call_args.kwargs["body"]
        self.assertEqual(
            {rule["protocol"]: rule["ports"] for rule in request["outbound_rules"]},
            {"tcp": "0", "udp": "0", "icmp": "0"},
        )
        harness.intents.clear.assert_called_once_with("payload_firewall")

    @mock.patch.object(live_harness, "_mutation_response")
    def test_payload_firewall_keeps_intent_after_ambiguous_response(
        self, mutation_response
    ):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.account = {"team_uuid": "team-uuid"}
        harness.headers = {"Authorization": "Bearer redacted-test-token"}
        harness.probe_cidrs = ["203.0.113.10/32"]
        harness.apply = True
        harness.intents = mock.Mock()
        harness.intents.get.return_value = None
        harness.ledger = mock.Mock()
        harness._resources = mock.Mock(return_value=[])
        mutation_response.side_effect = live_harness.AmbiguousMutation(
            "unknown outcome"
        )

        with self.assertRaises(live_harness.AmbiguousMutation):
            harness.ensure_payload_firewall("901")

        harness.intents.clear.assert_not_called()

    def _firewall_request(self, harness, source_droplet_id="901"):
        name = live_harness._resource_name(harness.run_id, "payload-firewall")
        request = {
            "name": name,
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "ports": str(live_harness.PAYLOAD_PORT),
                    "sources": {"addresses": list(harness.probe_cidrs)},
                }
            ],
            "outbound_rules": [
                {
                    "protocol": protocol,
                    "ports": "0",
                    "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                }
                for protocol in ("tcp", "udp", "icmp")
            ],
            "droplet_ids": [int(source_droplet_id)],
        }
        return request

    def _firewall_resource(self, harness, firewall_id="fw-1", droplet_ids=None):
        request = self._firewall_request(harness)
        return {
            "id": firewall_id,
            "name": request["name"],
            "inbound_rules": request["inbound_rules"],
            "outbound_rules": request["outbound_rules"],
            "droplet_ids": list(["901"] if droplet_ids is None else droplet_ids),
        }

    def test_payload_firewall_adoption_requires_bounded_intent_and_unique_match(self):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.account = {"team_uuid": "team-uuid"}
        harness.headers = {"Authorization": "Bearer redacted-test-token"}
        harness.probe_cidrs = ["203.0.113.10/32"]
        harness.apply = True
        harness.intents = mock.Mock()
        harness.ledger = mock.Mock()
        harness.ledger.entries.side_effect = lambda kind: (
            [{"resource_id": "901"}] if kind == "source_droplet" else []
        )
        candidate = self._firewall_resource(harness)
        harness._resources = mock.Mock(return_value=[candidate])
        harness._read_resource = mock.Mock(return_value=candidate)
        request = self._firewall_request(harness)
        immutable = harness._firewall_immutable_fingerprint(request)
        harness.intents.get.return_value = {
            "marker": harness.run_tag,
            "kind": "payload_firewall",
            "name": request["name"],
            "operation": "create",
            "request_fingerprint": live_harness._fingerprint(request),
            "immutable_fingerprint": immutable,
            "intent_schema": 1,
            "created_at": live_harness.time.time()
            - live_harness.MUTATION_INTENT_MAX_AGE_SECONDS
            - 1,
            "preflight_absent": True,
            "preflight_candidate_count": 0,
            "request_boundary_crossed": True,
        }
        with mock.patch.object(live_harness, "_mutation_response") as mutation:
            with self.assertRaises(live_harness.HarnessError):
                harness.ensure_payload_firewall("901")
        mutation.assert_not_called()
        harness.ledger.record.assert_not_called()

        harness.intents.get.return_value = None
        duplicate = dict(candidate)
        duplicate["id"] = "fw-duplicate"
        harness._resources.return_value = [candidate, duplicate]
        harness._read_resource.reset_mock()
        with mock.patch.object(live_harness, "_mutation_response") as mutation:
            with self.assertRaises(live_harness.HarnessError):
                harness.ensure_payload_firewall("901")
        mutation.assert_not_called()
        harness._read_resource.assert_not_called()

    def test_payload_firewall_rejects_foreign_selector_broadened_same_name(self):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.account = {"team_uuid": "team-uuid"}
        harness.headers = {"Authorization": "Bearer redacted-test-token"}
        harness.probe_cidrs = ["203.0.113.10/32"]
        harness.apply = True
        harness.intents = mock.Mock()
        harness.ledger = mock.Mock()
        harness.ledger.entries.side_effect = lambda kind: (
            [{"resource_id": "901"}] if kind == "source_droplet" else []
        )
        broadened = self._firewall_resource(harness)
        broadened["inbound_rules"][0]["sources"].update(
            {"tags": ["foreign-tag"], "droplet_ids": ["foreign-droplet"]}
        )
        harness._resources = mock.Mock(return_value=[broadened])
        harness._read_resource = mock.Mock(return_value=broadened)
        with self.assertRaises(live_harness.HarnessError):
            harness._firewall_immutable_fingerprint(
                {
                    **broadened,
                    "outbound_rules": broadened["outbound_rules"],
                }
            )
        with mock.patch.object(live_harness, "_mutation_response") as mutation:
            with self.assertRaises(live_harness.HarnessError):
                harness.ensure_payload_firewall("901")
        mutation.assert_not_called()

    def test_payload_firewall_allows_only_empty_echoed_optional_selectors(self):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.probe_cidrs = ["203.0.113.10/32"]
        request = self._firewall_request(harness)
        echoed = self._firewall_resource(harness)
        optional = {
            "droplet_ids": [],
            "load_balancer_uids": [],
            "kubernetes_ids": [],
            "tags": [],
        }
        echoed["inbound_rules"][0]["sources"].update(optional)
        echoed["outbound_rules"] = [
            {
                **rule,
                "destinations": {**rule["destinations"], **optional},
                "sources": {**rule["destinations"], **optional},
            }
            for rule in echoed["outbound_rules"]
        ]
        normalized = dict(echoed)
        normalized["outbound_rules"] = [
            {**rule, "sources": rule["destinations"]}
            for rule in echoed["outbound_rules"]
        ]
        harness.account = {"team_uuid": "team-uuid"}
        self.assertTrue(
            harness._firewall_owned(
                normalized,
                firewall_id="fw-1",
                allowed_droplet_ids={"901"},
                required_droplet_id="901",
            )
        )
        self.assertEqual(
            harness._firewall_immutable_fingerprint(echoed),
            harness._firewall_immutable_fingerprint(request),
        )

    def test_cleanup_accepts_provider_auto_detached_firewall_only_when_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "bs-e2e-do-test-run"
            intents = live_harness.DurableMutationIntentStore(
                root / "intents.json",
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            harness = object.__new__(live_harness.DigitalOceanHarness)
            harness.run_id = run_id
            harness.run_tag = run_id
            harness.account = {"team_uuid": "team-uuid"}
            harness.headers = {"Authorization": "Bearer redacted-test-token"}
            harness.probe_cidrs = ["203.0.113.10/32"]
            harness.apply = True
            harness.cleanup_enabled = True
            harness.intents = intents
            harness.mutation_reconcile_timeout_seconds = 0
            request = self._firewall_request(harness)
            immutable = harness._firewall_immutable_fingerprint(request)
            firewall = self._firewall_resource(harness, droplet_ids=[])
            still_attached = self._firewall_resource(harness, droplet_ids=["901"])
            still_attached["outbound_rules"] = [
                {**rule, "sources": rule.get("destinations")}
                for rule in still_attached["outbound_rules"]
            ]
            self.assertFalse(
                harness._firewall_owned(
                    still_attached,
                    firewall_id="fw-1",
                    allowed_droplet_ids={"901"},
                    require_empty_droplet_ids=True,
                )
            )
            entry = {
                "resource_id": "fw-1",
                "name": firewall["name"],
                "cleanup_state": "eligible",
                "ownership": {
                    "team_uuid": "team-uuid",
                    "run_tag": run_id,
                    "probe_cidrs": list(harness.probe_cidrs),
                    "source_droplet_id": "901",
                    "immutable_fingerprint": immutable,
                    "creation_witness": {
                        "name": firewall["name"],
                        "rules_fingerprint": immutable,
                        "source_droplet_id": "901",
                        "immutable_fingerprint": immutable,
                    },
                },
            }
            ledger = mock.Mock()

            def entries(kind=None):
                if kind == "payload_firewall":
                    return [entry]
                return []

            ledger.entries.side_effect = entries
            ledger.get.return_value = None
            ledger.cleanup_eligible.return_value = True
            harness.ledger = ledger
            harness._read_resource = mock.Mock(
                side_effect=[firewall, firewall, None]
            )
            with mock.patch.object(
                live_harness, "_mutation_response", return_value={}
            ) as mutation:
                result = harness.cleanup()

            self.assertEqual(result, None)
            mutation.assert_called_once_with(
                "DELETE",
                "/v2/firewalls/fw-1",
                headers=harness.headers,
            )

    def test_payload_firewall_attachment_intent_reconciles_after_worker_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent_path = root / "intents.json"
            run_id = "bs-e2e-do-test-run"
            entry = {
                "resource_id": "fw-1",
                "cleanup_state": "eligible",
                "ownership": {"source_droplet_id": "901"},
            }

            def make_harness(intents, read_resource):
                harness = object.__new__(live_harness.DigitalOceanHarness)
                harness.run_id = run_id
                harness.run_tag = run_id
                harness.account = {"team_uuid": "team-uuid"}
                harness.headers = {"Authorization": "Bearer redacted-test-token"}
                harness.probe_cidrs = ["203.0.113.10/32"]
                harness.intents = intents
                harness.ledger = mock.Mock()

                def entries(kind):
                    if kind == "payload_firewall":
                        return [entry]
                    if kind == "source_droplet":
                        return [{"resource_id": "901"}]
                    if kind == "ui_restore_droplet":
                        return [{"resource_id": "902"}]
                    return []

                harness.ledger.entries.side_effect = entries
                harness._read_resource = read_resource
                return harness

            intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            first = make_harness(intents, mock.Mock())
            first_firewall = self._firewall_resource(first, droplet_ids=["901"])
            first_request = self._firewall_request(first)
            first_immutable = first._firewall_immutable_fingerprint(first_request)
            entry["ownership"].update(
                {
                    "immutable_fingerprint": first_immutable,
                    "creation_witness": {
                        "name": first_request["name"],
                        "rules_fingerprint": first_immutable,
                        "source_droplet_id": "901",
                        "immutable_fingerprint": first_immutable,
                    },
                }
            )
            first.mutation_reconcile_timeout_seconds = 0
            first._read_resource.side_effect = [
                first_firewall,
                first_firewall,
                first_firewall,
            ]
            intent_key = "attach:payload-firewall:fw-1:902"
            with mock.patch.object(
                live_harness, "_mutation_response", side_effect=live_harness.AmbiguousMutation("lost-attach")
            ) as mutation:
                with self.assertRaises(live_harness.AmbiguousMutation):
                    first._attach_payload_firewall("902")
            mutation.assert_called_once()
            pending = intents.get(intent_key)
            self.assertEqual(pending["intent_schema"], 1)
            self.assertTrue(pending["request_boundary_crossed"])
            self.assertEqual(pending["firewall_id"], "fw-1")
            self.assertEqual(pending["droplet_id"], "902")

            retry = make_harness(
                live_harness.DurableMutationIntentStore(
                    intent_path,
                    provider="digitalocean",
                    run_id=run_id,
                    scope="team-uuid",
                ),
                mock.Mock(return_value=first_firewall),
            )
            retry.mutation_reconcile_timeout_seconds = 0
            with mock.patch.object(live_harness, "_mutation_response") as mutation:
                with self.assertRaises(live_harness.AmbiguousMutation):
                    retry._attach_payload_firewall("902")
            mutation.assert_not_called()

            changed = self._firewall_resource(first, droplet_ids=["901"])
            changed["inbound_rules"][0]["sources"] = {
                "addresses": ["198.51.100.7/32"]
            }
            blocked = make_harness(
                live_harness.DurableMutationIntentStore(
                    intent_path,
                    provider="digitalocean",
                    run_id=run_id,
                    scope="team-uuid",
                ),
                mock.Mock(return_value=changed),
            )
            with mock.patch.object(live_harness, "_mutation_response") as mutation:
                with self.assertRaises(live_harness.HarnessError):
                    blocked._attach_payload_firewall("902")
            mutation.assert_not_called()
            self.assertIsNotNone(blocked.intents.get(intent_key))

            accepted = make_harness(
                live_harness.DurableMutationIntentStore(
                    intent_path,
                    provider="digitalocean",
                    run_id=run_id,
                    scope="team-uuid",
                ),
                mock.Mock(
                    return_value=self._firewall_resource(
                        first, droplet_ids=["901", "902"]
                    )
                ),
            )
            with mock.patch.object(live_harness, "_mutation_response") as mutation:
                accepted._attach_payload_firewall("902")
            mutation.assert_not_called()
            self.assertIsNone(accepted.intents.get(intent_key))

    def test_cleanup_intents_reconcile_exact_state_after_lost_response_and_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "bs-e2e-do-test-run"
            intent_path = root / "intents.json"
            intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            harness = object.__new__(live_harness.DigitalOceanHarness)
            harness.run_tag = run_id
            harness.intents = intents
            harness.mutation_reconcile_timeout_seconds = 0
            resource = {
                "id": "droplet-1",
                "name": f"{run_id}-droplet",
                "tags": [run_id],
                "region": {"slug": "nyc3"},
                "size_slug": "s-1vcpu-1gb",
                "image": {"slug": "ubuntu-24-04-x64"},
                "status": "active",
            }
            request = {
                "provider_id": resource["id"],
                "kind": "source_droplet",
                "name": resource["name"],
                "region": "nyc3",
                "size": "s-1vcpu-1gb",
                "image": "ubuntu-24-04-x64",
                "tags": [run_id],
            }
            witness = live_harness._creation_witness("source_droplet", resource, request)
            witness["immutable_fingerprint"] = live_harness._fingerprint(witness)

            def verify(current):
                if not live_harness._creation_witness_matches(
                    "source_droplet", current, witness
                ):
                    raise live_harness.HarnessError("immutable witness drift")

            read_first = mock.Mock(side_effect=[resource, resource])
            delete_first = mock.Mock(
                side_effect=live_harness.AmbiguousMutation("lost-delete")
            )
            with self.assertRaises(live_harness.AmbiguousMutation):
                harness._delete_provider_with_intent(
                    intent_key="cleanup:source_droplet:droplet-1",
                    kind="source_droplet",
                    resource_id="droplet-1",
                    name=resource["name"],
                    request=request,
                    read_back=read_first,
                    verify_present=verify,
                    delete_call=delete_first,
                )
            delete_first.assert_called_once()
            pending = intents.get("cleanup:source_droplet:droplet-1")
            self.assertTrue(pending["request_boundary_crossed"])
            self.assertEqual(pending["provider_id"], "droplet-1")
            self.assertEqual(read_first.call_count, 2)

            foreign = dict(resource)
            foreign["size_slug"] = "s-2vcpu-4gb"
            restarted = object.__new__(live_harness.DigitalOceanHarness)
            restarted.run_tag = run_id
            restarted.mutation_reconcile_timeout_seconds = 0
            restarted.intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            foreign_read = mock.Mock(return_value=foreign)
            replay_delete = mock.Mock()
            with self.assertRaises(live_harness.HarnessError):
                restarted._delete_provider_with_intent(
                    intent_key="cleanup:source_droplet:droplet-1",
                    kind="source_droplet",
                    resource_id="droplet-1",
                    name=resource["name"],
                    request=request,
                    read_back=foreign_read,
                    verify_present=verify,
                    delete_call=replay_delete,
                )
            replay_delete.assert_not_called()
            self.assertIsNotNone(intents.get("cleanup:source_droplet:droplet-1"))

            adopted = object.__new__(live_harness.DigitalOceanHarness)
            adopted.run_tag = run_id
            adopted.mutation_reconcile_timeout_seconds = 0
            absent_read = mock.Mock(side_effect=[resource, None])
            final_delete = mock.Mock()
            restarted_intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            adopted.intents = restarted_intents
            self.assertEqual(
                adopted._delete_provider_with_intent(
                    intent_key="cleanup:source_droplet:droplet-1",
                    kind="source_droplet",
                    resource_id="droplet-1",
                    name=resource["name"],
                    request=request,
                    read_back=absent_read,
                    verify_present=verify,
                    delete_call=final_delete,
                ),
                "deleted",
            )
            final_delete.assert_not_called()
            self.assertIsNone(restarted_intents.get("cleanup:source_droplet:droplet-1"))

            spaces_intent_path = root / "spaces-intents.json"
            spaces_intents = live_harness.DurableMutationIntentStore(
                spaces_intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            spaces_harness = object.__new__(live_harness.DigitalOceanHarness)
            spaces_harness.run_tag = run_id
            spaces_harness.mutation_reconcile_timeout_seconds = 0
            head = {
                "ContentLength": 3,
                "ETag": '"etag"',
                "VersionId": "version-1",
                "Metadata": {"backupsheep-run": run_id},
            }
            spaces_request = {
                "bucket": "bucket",
                "key": "ui/bs-e2e-do-test-run/website.zip",
                "version_id": "version-1",
                "etag": "etag",
                "byte_count": 3,
            }
            verify_head = lambda current: self.assertEqual(current, head)
            with self.assertRaises(live_harness.AmbiguousMutation):
                spaces_harness.intents = spaces_intents
                spaces_harness._delete_spaces_with_intent(
                    intent_key="cleanup:spaces-object:object-1",
                    kind="spaces_ui_website_object",
                    name=spaces_request["key"],
                    request=spaces_request,
                    read_back=mock.Mock(side_effect=[head, head]),
                    verify_present=verify_head,
                    delete_call=mock.Mock(
                        side_effect=live_harness.AmbiguousMutation("lost-object-delete")
                    ),
                )
            self.assertIsNotNone(spaces_intents.get("cleanup:spaces-object:object-1"))
            spaces_restarted = object.__new__(live_harness.DigitalOceanHarness)
            spaces_restarted.run_tag = run_id
            spaces_restarted.mutation_reconcile_timeout_seconds = 0
            spaces_restarted.intents = live_harness.DurableMutationIntentStore(
                spaces_intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            spaces_delete = mock.Mock()
            self.assertEqual(
                spaces_restarted._delete_spaces_with_intent(
                    intent_key="cleanup:spaces-object:object-1",
                    kind="spaces_ui_website_object",
                    name=spaces_request["key"],
                    request=spaces_request,
                    read_back=mock.Mock(side_effect=[head, None]),
                    verify_present=verify_head,
                    delete_call=spaces_delete,
                ),
                "deleted",
            )
            spaces_delete.assert_not_called()
            self.assertIsNone(
                spaces_restarted.intents.get("cleanup:spaces-object:object-1")
            )

    def test_accepted_delete_polls_without_replaying_on_worker_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "bs-e2e-do-test-run"
            intent_path = root / "intents.json"
            intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            resource = {
                "id": "droplet-accepted",
                "name": f"{run_id}-accepted",
                "tags": [run_id],
                "region": {"slug": "nyc3"},
                "size_slug": "s-1vcpu-1gb",
                "image": {"slug": "ubuntu-24-04-x64"},
            }
            request = {
                "provider_id": resource["id"],
                "kind": "source_droplet",
                "name": resource["name"],
                "region": "nyc3",
                "size": "s-1vcpu-1gb",
                "image": "ubuntu-24-04-x64",
                "tags": [run_id],
            }
            witness = live_harness._creation_witness("source_droplet", resource, request)
            witness["immutable_fingerprint"] = live_harness._fingerprint(witness)

            def verify(current):
                if not live_harness._creation_witness_matches(
                    "source_droplet", current, witness
                ):
                    raise live_harness.HarnessError("immutable witness drift")

            first = object.__new__(live_harness.DigitalOceanHarness)
            first.run_tag = run_id
            first.intents = intents
            first.mutation_reconcile_timeout_seconds = 0
            delete_call = mock.Mock()
            with self.assertRaises(live_harness.AmbiguousMutation):
                first._delete_provider_with_intent(
                    intent_key="cleanup:source_droplet:droplet-accepted",
                    kind="source_droplet",
                    resource_id=resource["id"],
                    name=resource["name"],
                    request=request,
                    read_back=mock.Mock(side_effect=[resource, resource]),
                    verify_present=verify,
                    delete_call=delete_call,
                )
            delete_call.assert_called_once()
            accepted = intents.get("cleanup:source_droplet:droplet-accepted")
            self.assertEqual(accepted["state"], "accepted")
            self.assertEqual(accepted["mutation_state"], "accepted")

            resumed = object.__new__(live_harness.DigitalOceanHarness)
            resumed.run_tag = run_id
            resumed.intents = live_harness.DurableMutationIntentStore(
                intent_path,
                provider="digitalocean",
                run_id=run_id,
                scope="team-uuid",
            )
            resumed.mutation_reconcile_timeout_seconds = 0
            replay_delete = mock.Mock()
            self.assertEqual(
                resumed._delete_provider_with_intent(
                    intent_key="cleanup:source_droplet:droplet-accepted",
                    kind="source_droplet",
                    resource_id=resource["id"],
                    name=resource["name"],
                    request=request,
                    read_back=mock.Mock(side_effect=[resource, None]),
                    verify_present=verify,
                    delete_call=replay_delete,
                ),
                "deleted",
            )
            replay_delete.assert_not_called()
            self.assertIsNone(
                resumed.intents.get("cleanup:source_droplet:droplet-accepted")
            )

    @mock.patch.object(live_harness.requests, "get")
    def test_payload_probe_verifies_health_and_exact_bytes(self, get):
        expectation = live_harness._payload_expectation("bs-e2e-do-test-run")
        health = json.dumps(
            {
                "ready": True,
                "sha256": expectation["sha256"],
                "byte_count": expectation["byte_count"],
                "run_marker": "bs-e2e-do-test-run",
            }
        ).encode()
        get.side_effect = [
            Response(content=health),
            Response(content=expectation["payload"]),
        ]

        live_harness._probe_payload_endpoint("203.0.113.20", expectation)

        self.assertEqual(get.call_count, 2)
        for call in get.call_args_list:
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertTrue(call.kwargs["stream"])

    def test_spaces_runtime_secret_is_0600_and_outside_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "spaces.json"
            payload = {
                "endpoint_url": "https://nyc3.digitaloceanspaces.com",
                "region": "nyc3",
                "bucket": "bs-e2e-bucket",
                "access_key": "ACCESS-CANARY",
                "secret_key": "SECRET-CANARY",
            }
            live_harness._write_runtime_secret(path, payload)
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            self.assertEqual(live_harness._read_runtime_secret(path), payload)

    @mock.patch.object(live_harness.requests, "request")
    def test_spaces_key_scope_rejection_is_explicit_and_secret_free(self, request):
        request.return_value = Response(
            403, {"message": "SECRET-CANARY provider body"}
        )
        with self.assertRaises(live_harness.ScopedProviderRejection) as raised:
            live_harness._mutation_response(
                "POST",
                "/v2/spaces/keys",
                headers={"Authorization": "Bearer SECRET-CANARY"},
                body={"name": "safe"},
                required_scope="spaces_key:create_credentials",
            )
        self.assertEqual(
            raised.exception.required_scope, "spaces_key:create_credentials"
        )
        self.assertNotIn("SECRET-CANARY", str(raised.exception))

    def test_spaces_ledger_stores_key_hash_not_access_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = live_harness.DurableResourceLedger(
                Path(temporary) / "ledger.json",
                provider="digitalocean",
                run_id="bs-e2e-do-test-run",
                scope="team-uuid",
            )
            harness = object.__new__(live_harness.DigitalOceanHarness)
            harness.account = {"team_uuid": "team-uuid"}
            harness.run_tag = "bs-e2e-do-test-run"
            harness.ledger = ledger
            harness._record_spaces_key(
                {
                    "access_key": "ACCESS-CANARY",
                    "name": "bs-e2e-do-test-run-spaces-key",
                    "grants": [{"bucket": "", "permission": "fullaccess"}],
                },
                {
                    "name": "bs-e2e-do-test-run-spaces-key",
                    "grants": [{"bucket": "", "permission": "fullaccess"}],
                },
            )
            serialized = (Path(temporary) / "ledger.json").read_text()
            self.assertNotIn("ACCESS-CANARY", serialized)
            self.assertNotIn("SECRET-CANARY", serialized)

    def test_spaces_key_inventory_matches_name_locally(self):
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.headers = {"Authorization": "Bearer TOKEN-CANARY"}
        with mock.patch.object(
            live_harness,
            "_iter_provider_collection",
            return_value=[
                {"access_key": "FOREIGN", "name": "foreign"},
                {"access_key": "OWNED", "name": "exact-run-name"},
            ],
        ) as inventory:
            result = harness._spaces_keys(name="exact-run-name")
        self.assertEqual([item["access_key"] for item in result], ["OWNED"])
        params = inventory.call_args.kwargs["params"]
        self.assertNotIn("name", params)
        self.assertEqual(params["sort"], "created_at")
        self.assertEqual(params["sort_direction"], "asc")

    def test_spaces_cleanup_refuses_unledgered_version_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = live_harness.DurableResourceLedger(
                root / "ledger.json",
                provider="digitalocean",
                run_id="bs-e2e-do-test-run",
                scope="team-uuid",
            )
            harness = object.__new__(live_harness.DigitalOceanHarness)
            harness.account = {"team_uuid": "team-uuid"}
            harness.run_id = "bs-e2e-do-test-run"
            harness.run_tag = harness.run_id
            harness.region = "nyc3"
            harness.spaces_prefix = f"ui/{harness.run_id}/"
            harness.apply = True
            harness.cleanup_enabled = True
            harness.spaces_cleanup_enabled = True
            harness.ledger = ledger
            harness.intents = mock.Mock()
            harness.intents.get.return_value = None
            harness.spaces_secret_path = root / "spaces.json"
            credentials = {
                "endpoint_url": "https://nyc3.digitaloceanspaces.com",
                "region": "nyc3",
                "bucket": "bs-e2e-test-bucket",
                "access_key": "ACCESS-CANARY",
                "secret_key": "SECRET-CANARY",
            }
            live_harness._write_runtime_secret(
                harness.spaces_secret_path, credentials
            )
            key = {
                "access_key": credentials["access_key"],
                "name": "bs-e2e-do-test-run-spaces-key",
                "grants": [{"bucket": "", "permission": "fullaccess"}],
            }
            key_entry = harness._record_spaces_key(
                key,
                {
                    "name": key["name"],
                    "grants": key["grants"],
                },
            )
            ledger.record(
                kind="spaces_bucket",
                resource_id=credentials["bucket"],
                name=credentials["bucket"],
                ownership={
                    "team_uuid": "team-uuid",
                    "run_tag": harness.run_id,
                    "region": "nyc3",
                    "endpoint_sha256": live_harness.hashlib.sha256(
                        credentials["endpoint_url"].encode()
                    ).hexdigest(),
                    "access_key_sha256": key_entry["resource_id"],
                    "request_fingerprint": "f" * 64,
                    "versioning": "Enabled",
                    "prefix": harness.spaces_prefix,
                    "creation_witness": {
                        "bucket": credentials["bucket"],
                        "region": "nyc3",
                        "prefix": harness.spaces_prefix,
                        "acl": "private",
                        "versioning": "Enabled",
                        "immutable_fingerprint": live_harness._fingerprint(
                            {
                                "bucket": credentials["bucket"],
                                "region": "nyc3",
                                "prefix": harness.spaces_prefix,
                                "acl": "private",
                                "versioning": "Enabled",
                            }
                        ),
                    },
                },
                source_witness="spaces-bucket:test",
            )
            client = mock.Mock()
            foreign_inventory = {
                "versions": [{"Key": "foreign", "VersionId": "foreign-v1"}],
                "delete_markers": [],
                "objects": [{"Key": "foreign"}],
                "multipart_uploads": [],
            }
            with mock.patch.object(
                live_harness, "_spaces_client", return_value=client
            ), mock.patch.object(
                harness,
                "_spaces_bucket_names",
                return_value=[credentials["bucket"]],
            ), mock.patch.object(
                harness, "_spaces_inventory", return_value=foreign_inventory
            ), mock.patch.object(harness, "_spaces_keys") as keys:
                with self.assertRaises(live_harness.InventoryNotEmpty):
                    harness.cleanup_spaces()

            client.delete_bucket.assert_not_called()
            keys.assert_not_called()
            self.assertTrue(harness.spaces_secret_path.exists())

    def _spaces_ui_manifest_fixture(self, root):
        ledger_path = root / "ledger.json"
        ledger = live_harness.DurableResourceLedger(
            ledger_path,
            provider="digitalocean",
            run_id="bs-e2e-do-test-run",
            scope="team-uuid",
        )
        harness = object.__new__(live_harness.DigitalOceanHarness)
        harness.account = {"team_uuid": "team-uuid"}
        harness.run_id = "bs-e2e-do-test-run"
        harness.run_tag = harness.run_id
        harness.region = "nyc3"
        harness.spaces_prefix = f"ui/{harness.run_id}/"
        harness.ledger = ledger
        harness.spaces_secret_path = root / "spaces.json"
        credentials = {
            "endpoint_url": "https://nyc3.digitaloceanspaces.com",
            "region": "nyc3",
            "bucket": "bs-e2e-test-bucket",
            "access_key": "ACCESS-CANARY",
            "secret_key": "SECRET-CANARY",
        }
        live_harness._write_runtime_secret(harness.spaces_secret_path, credentials)
        bucket_creation = {
            "bucket": credentials["bucket"],
            "region": "nyc3",
            "prefix": harness.spaces_prefix,
            "acl": "private",
            "versioning": "Enabled",
        }
        bucket_ownership = {
            "team_uuid": "team-uuid",
            "run_tag": harness.run_id,
            "region": "nyc3",
            "endpoint_sha256": live_harness.hashlib.sha256(
                credentials["endpoint_url"].encode()
            ).hexdigest(),
            "access_key_sha256": harness._spaces_key_hash(credentials["access_key"]),
            "request_fingerprint": "f" * 64,
            "versioning": "Enabled",
            "prefix": harness.spaces_prefix,
            "creation_witness": {
                **bucket_creation,
                "immutable_fingerprint": live_harness._fingerprint(bucket_creation),
            },
        }
        ledger.record(
            kind="spaces_bucket",
            resource_id=credentials["bucket"],
            name=credentials["bucket"],
            ownership=bucket_ownership,
            source_witness="spaces-bucket:test",
        )
        payloads = {
            f"{harness.spaces_prefix}website/site.zip": b"website-payload",
            f"{harness.spaces_prefix}database/db.zip": b"database-payload",
        }
        objects = []
        heads = {}
        versions = []
        for index, (key, payload) in enumerate(payloads.items(), start=1):
            kind = "website" if "/website/" in key else "database"
            sha256 = live_harness.hashlib.sha256(payload).hexdigest()
            version_id = f"version-{index}"
            etag = f"etag-{index}"
            metadata = {
                "backupsheep-sha256": sha256,
                "backupsheep-bytes": str(len(payload)),
                "backupsheep-backup-id": str(index),
            }
            objects.append(
                {
                    "kind": kind,
                    "key": key,
                    "version_id": version_id,
                    "sha256": sha256,
                    "byte_count": len(payload),
                    "etag": etag,
                    "backup_id": str(index),
                    "metadata": metadata,
                }
            )
            versions.append({"Key": key, "VersionId": version_id})
            heads[(key, version_id)] = {
                "ContentLength": len(payload),
                "ETag": f'"{etag}"',
                "VersionId": version_id,
                "Metadata": metadata,
            }
        client = mock.Mock()
        client.head_object.side_effect = lambda **kwargs: heads[
            (kwargs["Key"], kwargs["VersionId"])
        ]
        client.get_object.side_effect = lambda **kwargs: {
            "Body": io.BytesIO(payloads[kwargs["Key"]])
        }
        inventory = {
            "versions": versions,
            "delete_markers": [],
            "objects": [],
            "multipart_uploads": [],
        }
        manifest = {
            "schema": 1,
            "run_id": harness.run_id,
            "prefix": harness.spaces_prefix,
            "objects": objects,
        }
        return harness, ledger, credentials, client, inventory, manifest

    def test_spaces_ui_manifest_verifies_website_and_database_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, ledger, _credentials, client, inventory, manifest = (
                self._spaces_ui_manifest_fixture(root)
            )
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))

            with mock.patch.object(
                live_harness, "_spaces_client", return_value=client
            ), mock.patch.object(
                harness, "_spaces_inventory", return_value=inventory
            ):
                result = harness.verify_spaces_ui_uploads(
                    str(manifest_path), maximum_bytes=1024
                )

            self.assertEqual(result["object_counts"], {"website": 1, "database": 1})
            serialized = (root / "ledger.json").read_text()
            self.assertNotIn("ACCESS-CANARY", serialized)
            self.assertNotIn("SECRET-CANARY", serialized)
            self.assertEqual(len(ledger.entries("spaces_ui_website_object")), 1)
            self.assertEqual(len(ledger.entries("spaces_ui_database_object")), 1)

    def test_spaces_ui_manifest_rejects_foreign_scope_before_provider_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, ledger, _credentials, _client, _inventory, manifest = (
                self._spaces_ui_manifest_fixture(root)
            )
            first = manifest["objects"][0]
            invalid_manifests = []
            for field, value in (
                ("schema", 2),
                ("run_id", "foreign-run"),
                ("prefix", "ui/foreign-run/"),
            ):
                candidate = json.loads(json.dumps(manifest))
                candidate[field] = value
                invalid_manifests.append(candidate)
            for key in (
                "/absolute/foreign.zip",
                f"{harness.spaces_prefix}../foreign.zip",
                f"{harness.spaces_prefix}foreign%2e.zip",
                f"ui/{harness.run_id}/nested//foreign.zip",
            ):
                candidate = json.loads(json.dumps(manifest))
                candidate["objects"][0]["key"] = key
                invalid_manifests.append(candidate)
            candidate = json.loads(json.dumps(manifest))
            candidate["objects"][0]["backup_id"] = "0"
            invalid_manifests.append(candidate)
            candidate = json.loads(json.dumps(manifest))
            candidate["objects"][0]["metadata"]["foreign"] = "metadata"
            invalid_manifests.append(candidate)
            candidate = json.loads(json.dumps(manifest))
            candidate["objects"][0]["metadata"]["backupsheep-backup-id"] = "999"
            invalid_manifests.append(candidate)

            manifest_path = root / "manifest.json"
            for invalid in invalid_manifests:
                manifest_path.write_text(json.dumps(invalid))
                with self.subTest(invalid=invalid):
                    with mock.patch.object(live_harness, "_spaces_client") as client:
                        with self.assertRaises(live_harness.HarnessError):
                            harness.verify_spaces_ui_uploads(
                                str(manifest_path), maximum_bytes=1024
                            )
                    client.assert_not_called()

            self.assertEqual(ledger.entries("spaces_ui_website_object"), [])
            self.assertEqual(ledger.entries("spaces_ui_database_object"), [])

    def test_spaces_ui_manifest_rejects_duplicate_provider_matches_before_head_or_get(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, ledger, _credentials, client, inventory, manifest = (
                self._spaces_ui_manifest_fixture(root)
            )
            key = manifest["objects"][0]["key"]
            inventory["versions"] = [
                {"Key": key, "VersionId": "version-1"},
                {"Key": key, "VersionId": "version-duplicate"},
                inventory["versions"][1],
            ]
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            with mock.patch.object(
                live_harness, "_spaces_client", return_value=client
            ), mock.patch.object(
                harness, "_spaces_inventory", return_value=inventory
            ):
                with self.assertRaises(live_harness.HarnessError):
                    harness.verify_spaces_ui_uploads(
                        str(manifest_path), maximum_bytes=1024
                    )
            client.head_object.assert_not_called()
            client.get_object.assert_not_called()
            self.assertEqual(ledger.entries("spaces_ui_website_object"), [])

            inventory["versions"] = inventory["versions"][::2]
            inventory["delete_markers"] = [
                {"Key": key, "VersionId": "delete-marker"}
            ]
            with mock.patch.object(
                live_harness, "_spaces_client", return_value=client
            ), mock.patch.object(
                harness, "_spaces_inventory", return_value=inventory
            ):
                with self.assertRaises(live_harness.HarnessError):
                    harness.verify_spaces_ui_uploads(
                        str(manifest_path), maximum_bytes=1024
                    )
            client.head_object.assert_not_called()
            client.get_object.assert_not_called()

    def test_spaces_ui_manifest_rejects_duplicate_rows_before_client_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, _ledger, _credentials, _client, _inventory, manifest = (
                self._spaces_ui_manifest_fixture(root)
            )
            manifest["objects"].append(json.loads(json.dumps(manifest["objects"][0])))
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            with mock.patch.object(live_harness, "_spaces_client") as client:
                with self.assertRaises(live_harness.HarnessError):
                    harness.verify_spaces_ui_uploads(
                        str(manifest_path), maximum_bytes=1024
                    )
            client.assert_not_called()

    def test_spaces_inventory_applies_exact_prefix_on_every_page(self):
        prefix = "ui/bs-e2e-do-test-run/"
        client = mock.Mock()
        client.list_object_versions.side_effect = [
            {
                "Versions": [{"Key": f"{prefix}one", "VersionId": "v1"}],
                "DeleteMarkers": [],
                "IsTruncated": True,
                "NextKeyMarker": f"{prefix}one",
                "NextVersionIdMarker": "v1",
            },
            {"Versions": [], "DeleteMarkers": [], "IsTruncated": False},
        ]
        client.list_objects_v2.side_effect = [
            {
                "Contents": [{"Key": f"{prefix}one"}],
                "IsTruncated": True,
                "NextContinuationToken": "objects-2",
            },
            {"Contents": [], "IsTruncated": False},
        ]
        client.list_multipart_uploads.side_effect = [
            {
                "Uploads": [{"Key": f"{prefix}one", "UploadId": "upload-1"}],
                "IsTruncated": True,
                "NextKeyMarker": f"{prefix}one",
                "NextUploadIdMarker": "upload-1",
            },
            {"Uploads": [], "IsTruncated": False},
        ]

        inventory = live_harness.DigitalOceanHarness._spaces_inventory(
            client, "bucket", prefix
        )

        self.assertEqual(len(inventory["versions"]), 1)
        for method in (
            client.list_object_versions,
            client.list_objects_v2,
            client.list_multipart_uploads,
        ):
            self.assertTrue(method.call_args_list)
            self.assertTrue(
                all(call.kwargs["Prefix"] == prefix for call in method.call_args_list)
            )

    def test_spaces_ui_manifest_refuses_foreign_bucket_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = live_harness.DurableResourceLedger(
                root / "ledger.json",
                provider="digitalocean",
                run_id="bs-e2e-do-test-run",
                scope="team-uuid",
            )
            harness = object.__new__(live_harness.DigitalOceanHarness)
            harness.account = {"team_uuid": "team-uuid"}
            harness.run_id = "bs-e2e-do-test-run"
            harness.run_tag = harness.run_id
            harness.region = "nyc3"
            harness.ledger = ledger
            harness.spaces_secret_path = root / "spaces.json"
            credentials = {
                "endpoint_url": "https://nyc3.digitaloceanspaces.com",
                "region": "nyc3",
                "bucket": "bs-e2e-test-bucket",
                "access_key": "ACCESS-CANARY",
                "secret_key": "SECRET-CANARY",
            }
            live_harness._write_runtime_secret(
                harness.spaces_secret_path, credentials
            )
            ledger.record(
                kind="spaces_bucket",
                resource_id=credentials["bucket"],
                name=credentials["bucket"],
                ownership={
                    "team_uuid": "foreign-team",
                    "run_tag": harness.run_id,
                    "region": "nyc3",
                    "endpoint_sha256": "f" * 64,
                    "access_key_sha256": "e" * 64,
                    "versioning": "Enabled",
                },
                source_witness="spaces-bucket:foreign",
            )
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"objects": [{}]}))

            with mock.patch.object(live_harness, "_spaces_client") as client:
                with self.assertRaises(live_harness.HarnessError):
                    harness.verify_spaces_ui_uploads(
                        str(manifest_path), maximum_bytes=1024
                    )

            client.assert_not_called()


class DigitalOceanAdapterDatabaseTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.node = factories.make_cloud_node(
            self.account, self.member, code="digitalocean"
        )
        CoreAuthDigitalOcean.objects.create(
            connection=self.node.connection,
            api_key=bs_encrypt("test-token", self.account.get_encryption_key()),
        )
        self.backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=self.node.digitalocean,
            uuid="bs-digitalocean-stable-marker",
            celery_task_id="create-task-1",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        self.backup.initialize_execution(
            celery_task_id="create-task-1",
            attempt_no=1,
            task_name="backup_digitalocean",
        )

    def _claim(self, task_id):
        claimed = helper_tasks._claim_provider_create(self.backup, task_id)
        self.assertIsNotNone(claimed)
        return claimed

    def _expire_create_lease(self):
        self.backup.refresh_from_db()
        state = self.backup.get_execution_state(create=False)
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(update_fields=["lease_expires_at", "modified"])
        metadata = dict(self.backup.metadata or {})
        control = dict(metadata.get("_backup_control") or {})
        control["create_lease_until"] = 0
        metadata["_backup_control"] = control
        self.backup.metadata = metadata
        self.backup.save(update_fields=["metadata", "modified"])

    def test_request_marker_and_fingerprint_are_durable_before_adapter_call(self):
        claimed = self._claim("create-task-1")
        with mock.patch.object(
            CoreDigitalOcean,
            "create_snapshot",
            side_effect=raw_requests.Timeout("provider-secret"),
        ):
            with self.assertRaises(raw_requests.Timeout):
                _digitalocean_create_callback(self.node, "create-task-1")(claimed)

        self.backup.refresh_from_db()
        witness = self.backup.metadata[DIGITALOCEAN_REQUEST_METADATA_KEY]
        self.assertEqual(witness["marker"], self.backup.uuid_str)
        self.assertEqual(witness["source_id"], self.node.digitalocean.unique_id)
        self.assertEqual(witness["resource_type"], "droplet")
        self.assertEqual(len(witness["request_fingerprint"]), 64)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.provider_idempotency_key, self.backup.uuid_str)

    def test_lost_response_recovery_adopts_exact_snapshot_without_duplicate_create(self):
        claimed = self._claim("create-task-1")
        with mock.patch.object(
            CoreDigitalOcean,
            "create_snapshot",
            side_effect=raw_requests.Timeout("lost-response"),
        ):
            with self.assertRaises(raw_requests.Timeout):
                _digitalocean_create_callback(self.node, "create-task-1")(claimed)
        self._expire_create_lease()
        recovered = self._claim("create-task-2")
        exact = {
            "id": "snapshot-adopted",
            "name": self.backup.uuid_str,
            "resource_id": self.node.digitalocean.unique_id,
            "resource_type": "droplet",
            "size_gigabytes": 1.25,
            "state": "available",
        }

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps._tasks.integration.digitalocean.find_exact_snapshot",
            return_value=exact,
        ) as reconcile, mock.patch.object(
            CoreDigitalOcean, "create_snapshot"
        ) as duplicate_create:
            _digitalocean_create_callback(self.node, "create-task-2")(recovered)

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.unique_id, "snapshot-adopted")
        self.assertEqual(self.backup.size_gigabytes, 1.25)
        duplicate_create.assert_not_called()
        reconcile.assert_called_once()

    def test_preflight_timeout_retries_and_crosses_provider_create_once(self):
        first = self._claim("create-task-1")
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.api.v1.connection.digitalocean.client.find_exact_snapshot",
            return_value=None,
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=raw_requests.Timeout("preflight-timeout"),
        ), mock.patch("apps.console.node.models.requests.post") as create:
            with self.assertRaises(NodeBackupFailedError) as raised:
                _digitalocean_create_callback(self.node, "create-task-1")(first)

        self.assertEqual(raised.exception.error_code, "PROVIDER_TIMEOUT")
        create.assert_not_called()
        self.backup.refresh_from_db()
        self.assertNotIn(
            DIGITALOCEAN_REQUEST_METADATA_KEY, self.backup.metadata or {}
        )
        execution = self.backup.get_execution_state(create=False)
        self.assertFalse(execution.provider_metadata.get("create_attempted"))
        self.assertFalse(execution.provider_metadata.get("outcome_unknown"))

        self._expire_create_lease()
        replay = self._claim("create-task-2")
        source = Response(
            200,
            {
                "droplet": {
                    "id": self.node.digitalocean.unique_id,
                    "status": "active",
                    "locked": False,
                }
            },
        )
        action = Response(
            201,
            {
                "action": {
                    "id": 8123,
                    "type": "snapshot",
                    "resource_id": self.node.digitalocean.unique_id,
                    "resource_type": "droplet",
                    "status": "in-progress",
                }
            },
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.api.v1.connection.digitalocean.client.find_exact_snapshot",
            return_value=None,
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=source
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=action
        ) as create:
            _digitalocean_create_callback(self.node, "create-task-2")(replay)

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.action_id, "8123")
        create.assert_called_once()

    def test_worker_replay_adopts_execution_action_pointer_without_create(self):
        first = self._claim("create-task-1")

        def persist_pointer_then_crash(claimed):
            control = (claimed.metadata or {})["_backup_control"]
            saved = claimed.record_provider_reference(
                operation_id="action-ledger-1",
                idempotency_key=claimed.uuid_str,
                provider_status="in-progress",
                metadata={
                    "provider": "digitalocean",
                    "source_id": str(self.node.digitalocean.unique_id),
                    "resource_type": "droplet",
                    "request_fingerprint": (
                        claimed.metadata[DIGITALOCEAN_REQUEST_METADATA_KEY][
                            "request_fingerprint"
                        ]
                    ),
                    "create_attempted": True,
                    "outcome_unknown": False,
                },
                lease_owner="create-task-1",
                lease_token=control["create_lease_token"],
            )
            self.assertIsNotNone(saved)
            raise raw_requests.Timeout("post-ledger-worker-crash")

        with mock.patch.object(
            CoreDigitalOcean,
            "create_snapshot",
            side_effect=persist_pointer_then_crash,
        ):
            with self.assertRaises(raw_requests.Timeout):
                _digitalocean_create_callback(self.node, "create-task-1")(first)

        self.backup.refresh_from_db()
        self.assertFalse(self.backup.action_id)
        self._expire_create_lease()
        replay = self._claim("create-task-2")
        with mock.patch(
            "apps._tasks.integration.digitalocean.find_exact_snapshot"
        ) as reconcile, mock.patch.object(
            CoreDigitalOcean, "create_snapshot"
        ) as duplicate_create:
            _digitalocean_create_callback(self.node, "create-task-2")(replay)

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.action_id, "action-ledger-1")
        reconcile.assert_not_called()
        duplicate_create.assert_not_called()

    def test_identity_drift_blocks_recovery_before_provider_mutation(self):
        claimed = self._claim("create-task-1")
        with mock.patch.object(
            CoreDigitalOcean,
            "create_snapshot",
            side_effect=raw_requests.Timeout("lost-response"),
        ):
            with self.assertRaises(raw_requests.Timeout):
                _digitalocean_create_callback(self.node, "create-task-1")(claimed)
        self.node.digitalocean.unique_id = "different-source"
        self.node.digitalocean.save(update_fields=["unique_id", "modified"])
        self._expire_create_lease()
        recovered = self._claim("create-task-2")

        with mock.patch(
            "apps._tasks.integration.digitalocean.find_exact_snapshot"
        ) as reconcile, mock.patch.object(
            CoreDigitalOcean, "create_snapshot"
        ) as create:
            with self.assertRaises(DigitalOceanAPIError) as raised:
                _digitalocean_create_callback(self.node, "create-task-2")(recovered)

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        reconcile.assert_not_called()
        create.assert_not_called()

    def test_post_accept_snapshot_fault_is_adopted_on_worker_replay(self):
        marker = self.backup.uuid_str
        source_id = self.node.digitalocean.unique_id
        action = {
            "id": 77,
            "type": "snapshot",
            "resource_id": source_id,
            "resource_type": "droplet",
            "status": "in-progress",
        }
        exact = {
            "id": "snapshot-after-fault",
            "name": marker,
            "resource_id": source_id,
            "resource_type": "droplet",
            "status": "available",
        }
        source = Response(
            payload={
                "droplet": {
                    "id": source_id,
                    "status": "active",
                    "locked": False,
                }
            }
        )
        accepted = Response(payload={"action": action})
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch.object(
            do_client, "find_exact_snapshot", side_effect=[None, exact]
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=source
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=accepted
        ) as post, override_settings(
            DIGITALOCEAN_ENABLE_TEST_FAULTS=True,
            DIGITALOCEAN_FAULT_AFTER_ACCEPT=f"snapshot-droplet:{marker}",
        ):
            with self.assertRaises(NodeBackupFailedError) as raised:
                self.node.digitalocean.create_snapshot(self.backup)
            self.assertEqual(raised.exception.error_code, "PROVIDER_TIMEOUT")

            with override_settings(DIGITALOCEAN_ENABLE_TEST_FAULTS=False):
                self.node.digitalocean.create_snapshot(self.backup)

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.unique_id, "snapshot-after-fault")
        self.assertEqual(post.call_count, 1)
        execution = self.backup.get_execution_state(create=False)
        self.assertEqual(execution.provider_resource_id, "snapshot-after-fault")
        self.assertFalse(execution.provider_metadata["outcome_unknown"])

    def test_post_accept_restore_fault_is_adopted_without_second_create(self):
        marker = "bs-digitalocean-restore-fault"
        restore = CoreCloudRestore.objects.create(
            node=self.node,
            backup_id=self.backup.id,
            name="bs-do-restored",
            restore_marker=marker,
            params={"size": "s-1vcpu-1gb"},
        )
        candidate = {
            "id": 901,
            "name": "bs-do-restored",
            "tags": [
                marker,
                "backupsheep-restore-droplet",
                self.node.digitalocean._digitalocean_restore_source_tag(
                    self.backup.unique_id
                ),
            ],
            "image": {"id": int(self.backup.unique_id or 123456)},
            "status": "new",
        }
        # The setup backup has no provider pointer; give the restore one exact
        # completed snapshot identity for this isolated adapter test.
        self.backup.unique_id = "123456"
        self.backup.status = UtilBackup.Status.COMPLETE
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        candidate["image"] = {"id": 123456}
        accepted = Response(payload={"droplet": candidate})
        inventory = Response(
            payload={
                "droplets": [candidate],
                "meta": {"total": 1},
                "links": {},
            }
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.post", return_value=accepted
        ) as post, mock.patch.object(
            do_client.requests, "request", return_value=inventory
        ), override_settings(
            DIGITALOCEAN_ENABLE_TEST_FAULTS=True,
            DIGITALOCEAN_FAULT_AFTER_ACCEPT=f"restore-droplet:{marker}",
        ):
            first = self.node.digitalocean.restore_snapshot(self.backup, restore)
            self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
            restore.refresh_from_db()
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])

            with override_settings(DIGITALOCEAN_ENABLE_TEST_FAULTS=False):
                self.node.digitalocean.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "901")
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(post.call_count, 1)

    def test_delete_post_accept_fault_reconciles_404_without_second_delete(self):
        marker = self.backup.uuid_str
        self.backup.unique_id = "snapshot-delete-fault"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        owned = Response(
            payload={
                "snapshot": {
                    "id": self.backup.unique_id,
                    "name": marker,
                    "resource_id": self.node.digitalocean.unique_id,
                    "resource_type": "droplet",
                    "status": "available",
                }
            }
        )
        absent = Response(status_code=404)
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.backup.models.requests.get",
            side_effect=[owned, absent],
        ), mock.patch(
            "apps.console.backup.models.requests.delete",
            return_value=Response(status_code=204),
        ) as delete, override_settings(
            DIGITALOCEAN_ENABLE_TEST_FAULTS=True,
            DIGITALOCEAN_FAULT_AFTER_ACCEPT=f"delete-snapshot:{marker}",
            DIGITALOCEAN_DELETE_RETRY_GRACE_SECONDS=0,
        ):
            self.assertFalse(self.backup.soft_delete())
            self.backup.refresh_from_db()
            self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_FAILED)
            with override_settings(DIGITALOCEAN_ENABLE_TEST_FAULTS=False):
                self.assertTrue(self.backup.soft_delete())

        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(delete.call_count, 1)

    def test_poll_refuses_conflicting_local_and_execution_snapshot_ids(self):
        self.backup.unique_id = "snapshot-row"
        self.backup.save(update_fields=["unique_id", "modified"])
        state = self.backup.get_execution_state(create=False)
        state.provider_resource_id = "snapshot-execution"
        state.save(update_fields=["provider_resource_id", "modified"])
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch("apps.console.backup.models.requests.get") as get:
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.FAILED)
        get.assert_not_called()
        state.refresh_from_db()
        self.assertEqual(state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")

    def test_oauth_refresh_timeout_is_bounded_and_classified(self):
        auth = self.node.connection.auth_digitalocean
        auth.api_key = None
        auth.access_token = bs_encrypt(
            "old-access", self.account.get_encryption_key()
        )
        auth.refresh_token = bs_encrypt(
            "refresh-token", self.account.get_encryption_key()
        )
        auth.token_type = "Bearer"
        auth.save(
            update_fields=[
                "api_key",
                "access_token",
                "refresh_token",
                "token_type",
                "modified",
            ]
        )
        with mock.patch(
            "apps.console.connection.models.requests.post",
            side_effect=raw_requests.Timeout("credential-canary"),
        ) as post:
            with self.assertRaises(DigitalOceanAPIError) as raised:
                auth.refresh_auth_token()
        self.assertEqual(raised.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("credential-canary", str(raised.exception))
        self.assertIn("timeout", post.call_args.kwargs)
        self.assertIn("refresh_token", post.call_args.kwargs["data"])

    @mock.patch("apps.api.v1.connection.digitalocean.serializers.requests.get")
    def test_connection_validation_has_timeout_and_persists_team_witness(self, get):
        response = Response(
            payload={
                "account": {
                    "status": "active",
                    "uuid": "account-uuid",
                    "name": "Owner",
                    "email": "owner@example.com",
                    "team": {"name": "Personal", "uuid": "team-uuid"},
                }
            }
        )
        get.return_value = response
        serializer = CoreAuthDigitalOceanWriteSerializer(
            data={"api_key": "replacement-token"},
            context={"encryption_key": self.account.get_encryption_key()},
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIn("timeout", get.call_args.kwargs)
        self.assertEqual(serializer.validated_data["info_name"], "Personal")
        self.assertEqual(serializer.validated_data["info_uuid"], "team-uuid")
        self.assertEqual(
            bs_decrypt(
                serializer.validated_data["api_key"],
                self.account.get_encryption_key(),
            ),
            "replacement-token",
        )
        self.assertTrue(response.closed)

    @mock.patch(
        "apps.api.v1.connection.digitalocean.views.list_eligible_objects"
    )
    def test_object_discovery_uses_complete_client_and_marks_attached(self, listing):
        listing.return_value = [
            {"id": "droplet-1", "_bs_unique_id": "droplet-1"},
            {"id": "droplet-2", "_bs_unique_id": "droplet-2"},
        ]
        request = APIRequestFactory().get("/objects/", {"object_type": "cloud"})
        force_authenticate(request, user=self.user)

        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_verified_client",
            return_value={
                "content-type": "application/json",
                "Authorization": "Bearer test-token",
            },
        ) as verifier:
            response = CoreDigitalOceanView.as_view({"get": "objects"})(
                request, pk=self.node.connection_id
            )

        self.assertEqual(response.status_code, 200)
        verifier.assert_called_once()
        self.assertTrue(response.data[0]["_bs_attached"])
        self.assertNotIn("_bs_attached", response.data[1])
        listing.assert_called_once_with(
            headers={
                "content-type": "application/json",
                "Authorization": "Bearer test-token",
            },
            object_type="cloud",
        )

    @mock.patch(
        "apps.api.v1.connection.digitalocean.views.list_eligible_objects"
    )
    def test_object_discovery_rejects_unknown_type_without_provider_call(self, listing):
        request = APIRequestFactory().get("/objects/", {"object_type": "database"})
        force_authenticate(request, user=self.user)

        response = CoreDigitalOceanView.as_view({"get": "objects"})(
            request, pk=self.node.connection_id
        )

        self.assertEqual(response.status_code, 400)
        listing.assert_not_called()
