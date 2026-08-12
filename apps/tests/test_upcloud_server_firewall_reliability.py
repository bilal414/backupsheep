"""Offline UpCloud Cloud Server firewall-chain reliability tests.

These tests use deterministic HTTP responses only.  They exercise the source
witness boundary and the restore state machine without reading credentials or
contacting UpCloud.
"""

from copy import deepcopy
from unittest import mock
from datetime import timedelta
from uuid import uuid4

import requests as raw_requests
from django.utils import timezone

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.upcloud import (
    create_upcloud_snapshot,
    normalize_upcloud_firewall_rules,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthUpCloud, CoreIntegration
from apps.console.node.models import CoreNode
from apps.console.node.models import CoreUpCloud
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class Response:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def firewall_rule(position, *, port=None, protocol="tcp", family="IPv4"):
    if port is None:
        return {
            "action": "drop",
            "comment": "",
            "destination_address_end": "",
            "destination_address_start": "",
            "destination_port_end": "",
            "destination_port_start": "",
            "direction": "in",
            "family": "",
            "icmp_type": "",
            "position": str(position),
            "protocol": "",
            "source_address_end": "",
            "source_address_start": "",
            "source_port_end": "",
            "source_port_start": "",
        }
    return {
        "action": "accept",
        "comment": f"allow-{port}",
        "destination_address_end": "",
        "destination_address_start": "",
        "destination_port_end": str(port),
        "destination_port_start": str(port),
        "direction": "in",
        "family": family,
        "icmp_type": "",
        "position": str(position),
        "protocol": protocol,
        "source_address_end": "",
        "source_address_start": "",
        "source_port_end": "",
        "source_port_start": "",
    }


def firewall_payload(rules):
    return {"firewall_rules": {"firewall_rule": rules}}


def source_server(server_id="source-server"):
    return {
        "uuid": server_id,
        "state": "started",
        "zone": "us-chi1",
        "title": "source-server",
        "hostname": "source.example",
        "plan": "1xCPU-1GB",
        "firewall": "on",
        "metadata": "no",
        "server_group": "",
        "devices": {"device": []},
        "networking": {
            "interfaces": {
                "interface": [
                    {
                        "index": 1,
                        "type": "public",
                        "ip_addresses": {
                            "ip_address": [{"family": "IPv4"}]
                        },
                    },
                    {
                        "index": 2,
                        "type": "utility",
                        "ip_addresses": {
                            "ip_address": [{"family": "IPv4"}]
                        },
                    },
                ]
            }
        },
        "storage_devices": {
            "storage_device": [
                {
                    "storage": "boot-storage",
                    "type": "disk",
                    "boot_disk": "1",
                    "address": "virtio:0",
                }
            ]
        },
    }


def source_storage(storage_id="boot-storage", *, source_server_id="source-server"):
    return {
        "uuid": storage_id,
        "type": "normal",
        "zone": "us-chi1",
        "state": "online",
        "servers": {"server": [{"uuid": source_server_id}]},
    }


def backup_storage(storage_id, marker):
    return {
        "uuid": storage_id,
        "type": "backup",
        "title": marker,
        "origin": "boot-storage",
        "zone": "us-chi1",
        "state": "online",
    }


class UpCloudServerFirewallReliabilityTests(BaseTestCase):
    def _server_backup(self):
        CoreIntegration.objects.get_or_create(
            code="upcloud",
            defaults={"type": CoreIntegration.Type.CLOUD, "enabled": True},
        )
        connection = factories.make_connection(
            self.account, self.member, code="upcloud"
        )
        CoreAuthUpCloud.objects.create(
            connection=connection,
            username=bs_encrypt("test-user", self.account.get_encryption_key()),
            password=bs_encrypt(
                "test-password", self.account.get_encryption_key()
            ),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="upcloud-server",
            added_by=self.member,
        )
        integration = CoreUpCloud.objects.create(
            node=node,
            name="upcloud-server",
            unique_id="source-server",
            metadata={"_bs_zone": "us-chi1"},
        )
        backup = integration.backups.create(
            uuid="server-backup-marker",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id="upcloud-server-backup-task",
        )
        return integration, backup

    def _complete_server_backup(self):
        integration, backup = self._server_backup()
        rules = [firewall_rule(1, port=22), firewall_rule(2)]
        backup_resource = backup_storage("backup-storage", backup.uuid_str)
        get_responses = [
            Response(200, {"server": source_server()}),
            Response(200, {"storage": source_storage()}),
            Response(200, firewall_payload(rules)),
            Response(200, {"storages": {"storage": []}}),
        ]
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=get_responses,
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            return_value=Response(201, {"storage": backup_resource}),
        ):
            create_upcloud_snapshot(backup)
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        return integration, backup, rules

    @staticmethod
    def _restore_ids(integration, backup, restore):
        digest = integration._upcloud_restore_marker_digest(
            restore, backup.unique_id
        )
        return {
            "storage": f"backupsheep-upcloud-storage-{restore.pk}-{digest}"[:128],
            "server": f"backupsheep-upcloud-server-{restore.pk}-{digest}"[:128],
            "hostname": f"bs-upcloud-{restore.pk}-{digest[:16]}"[:63],
        }

    def _target_server(self, integration, backup, restore, storage_id):
        ids = self._restore_ids(integration, backup, restore)
        target = deepcopy(source_server("restored-server"))
        target.update(
            {
                "title": ids["server"],
                "hostname": ids["hostname"],
                "storage_devices": {
                    "storage_device": [
                        {
                            "storage": storage_id,
                            "type": "disk",
                            "boot_disk": "1",
                            "address": "virtio:0",
                        }
                    ]
                },
                "labels": {
                    "label": [
                        {
                            "key": "backupsheep-restore",
                            "value": ids["server"],
                        },
                        {
                            "key": "backupsheep-source",
                            "value": integration.unique_id,
                        },
                    ]
                },
            }
        )
        return target, ids

    def _restore_http(
        self, integration, backup, restore, rules, *, lost=False, lost_firewall=False
    ):
        lease_token = uuid4()
        restore.lease_owner = "upcloud-firewall-test"
        restore.lease_token = lease_token
        restore.lease_expires_at = timezone.now() + timedelta(hours=1)
        restore.save(
            update_fields=["lease_owner", "lease_token", "lease_expires_at", "modified"]
        )
        restore.bind_execution_fence("upcloud-firewall-test", lease_token)
        target_storage = {
            "uuid": "restored-storage",
            "type": "normal",
            "title": self._restore_ids(integration, backup, restore)["storage"],
            "origin": backup.unique_id,
            "zone": "us-chi1",
            "state": "online",
        }
        target_server, ids = self._target_server(
            integration, backup, restore, target_storage["uuid"]
        )
        default_rules = [firewall_rule(1)]
        state = {"storage_created": False, "server_created": False}

        def get(url, **kwargs):
            if str(url).endswith(f"/storage/{backup.unique_id}"):
                return Response(
                    200,
                    {"storage": backup_storage(backup.unique_id, backup.uuid_str)},
                )
            if str(url).endswith("/storage/normal"):
                if state["storage_created"]:
                    return Response(
                        200,
                        {"storages": {"storage": [target_storage]}},
                        headers={"UpCloud-Total-Count": "1"},
                    )
                return Response(
                    200,
                    {"storages": {"storage": []}},
                    headers={"UpCloud-Total-Count": "0"},
                )
            if str(url).endswith(f"/storage/{target_storage['uuid']}"):
                return Response(200, {"storage": target_storage})
            if str(url).endswith("/server"):
                if state["server_created"]:
                    return Response(
                        200,
                        {"servers": {"server": [{"uuid": target_server["uuid"], "title": ids["server"]}]}},
                        headers={"UpCloud-Total-Count": "1"},
                    )
                return Response(
                    200,
                    {"servers": {"server": []}},
                    headers={"UpCloud-Total-Count": "0"},
                )
            if str(url).endswith(f"/server/{target_server['uuid']}"):
                return Response(200, {"server": target_server})
            if str(url).endswith(
                f"/server/{target_server['uuid']}/firewall_rule"
            ):
                if state.get("firewall_replaced"):
                    return Response(200, firewall_payload(rules))
                return Response(200, firewall_payload(default_rules))
            raise AssertionError(f"Unexpected UpCloud GET: {url}")

        def post(url, **kwargs):
            if str(url).endswith(f"/storage/{backup.unique_id}/clone"):
                state["storage_created"] = True
                return Response(202, {"storage": target_storage})
            if str(url).endswith("/server"):
                state["server_created"] = True
                response = Response(202, {"server": target_server})
                if lost:
                    raise raw_requests.Timeout("lost response")
                return response
            raise AssertionError(f"Unexpected UpCloud POST: {url}")

        def put(url, **kwargs):
            if not str(url).endswith(
                f"/server/{target_server['uuid']}/firewall_rule"
            ):
                raise AssertionError(f"Unexpected UpCloud PUT: {url}")
            state["firewall_replaced"] = True
            if lost_firewall:
                raise raw_requests.Timeout("lost firewall response")
            return Response(204)

        return get, post, put, state, target_server

    def test_firewall_enabled_backup_persists_exact_chain_before_snapshot(self):
        integration, backup = self._server_backup()
        rules = [firewall_rule(1, port=22), firewall_rule(2)]
        get_responses = [
            Response(200, {"server": source_server()}),
            Response(200, {"storage": source_storage()}),
            Response(200, firewall_payload(rules)),
            Response(200, {"storages": {"storage": []}}),
        ]
        post_response = Response(
            201,
            {"storage": backup_storage("backup-storage", backup.uuid_str)},
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=get_responses,
        ) as get, mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            return_value=post_response,
        ) as post:
            create_upcloud_snapshot(backup)

        self.assertEqual(backup.unique_id, "backup-storage")
        witness = backup.get_execution_state().provider_metadata["witness"]
        self.assertEqual(witness["upcloud_firewall"]["rules"][0]["position"], 1)
        self.assertEqual(witness["upcloud_firewall"]["rules"][-1]["action"], "drop")
        self.assertEqual(get.call_count, 4)
        post.assert_called_once()
        self.assertTrue(
            all(call.kwargs["timeout"] for call in get.call_args_list)
        )
        self.assertTrue(post.call_args.kwargs["json"]["storage"]["title"])

    def test_firewall_rule_inventory_failure_fences_before_backup_mutation(self):
        for bad_rules, expected_code in (
            (
                [firewall_rule(1, port=22), firewall_rule(3)],
                "PROVIDER_MALFORMED_RESPONSE",
            ),
            (
                [firewall_rule(1, port=22), firewall_rule(2, port=22), firewall_rule(3)],
                "PROVIDER_DUPLICATE_MATCH",
            ),
            (
                [{**firewall_rule(1, port=22), "unsupported": "foreign"}, firewall_rule(2)],
                "PROVIDER_MALFORMED_RESPONSE",
            ),
        ):
            with self.subTest(expected_code=expected_code):
                integration, backup = self._server_backup()
                auth_cls = integration.node.connection.auth_upcloud.__class__
                with mock.patch.object(
                    auth_cls, "get_verified_client", return_value=mock.Mock()
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.get",
                    side_effect=[
                        Response(200, {"server": source_server()}),
                        Response(200, {"storage": source_storage()}),
                        Response(200, firewall_payload(bad_rules)),
                    ],
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.post"
                ) as post:
                    with self.assertRaises(NodeBackupFailedError) as raised:
                        create_upcloud_snapshot(backup)
                self.assertEqual(raised.exception.error_code, expected_code)
                post.assert_not_called()

    def test_restore_lost_server_response_reconciles_chain_without_duplicate_server(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="lost-server-response",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules, lost=True
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ) as put_mock:
            result = integration.restore_snapshot(backup, restore)
            self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
            restore.refresh_from_db()
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(
            post_mock.call_count,
            2,
        )  # one boot clone and one server create
        self.assertEqual(put_mock.call_count, 1)
        self.assertTrue(state["firewall_replaced"])

    def test_restore_lost_firewall_response_reconciles_without_duplicate_put(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="lost-firewall-response",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules, lost_firewall=True
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ) as put_mock:
            result = integration.restore_snapshot(backup, restore)
            self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
            restore.refresh_from_db()
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(put_mock.call_count, 1)
        self.assertTrue(state["firewall_replaced"])

    def test_restore_worker_crash_after_firewall_acceptance_reconciles_without_duplicate_put(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="firewall-worker-crash",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__

        def crash_after_firewall(_restore, _marker, stage):
            if stage == "firewall":
                raise SystemExit("worker crash after firewall acceptance")

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ) as put_mock, mock.patch.object(
            CoreUpCloud,
            "_upcloud_server_restore_fault_after_accept",
            side_effect=crash_after_firewall,
        ):
            with self.assertRaises(SystemExit):
                integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        identity = restore.params["_bs_upcloud_restore"]
        self.assertEqual(identity["active_mutation"], "firewall")
        self.assertTrue(identity["firewall_mutation_started"])
        self.assertFalse(restore.resource_id)
        self.assertEqual(put_mock.call_count, 1)

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ):
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(put_mock.call_count, 1)
        self.assertTrue(state["firewall_replaced"])

    def test_restore_worker_crash_after_server_acceptance_adopts_one_exact_target(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="worker-crash",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__

        def crash_after_server(_restore, _marker, stage):
            if stage == "server":
                raise SystemExit("worker crash")

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ) as put_mock, mock.patch.object(
            CoreUpCloud,
            "_upcloud_server_restore_fault_after_accept",
            side_effect=crash_after_server,
        ):
            with self.assertRaises(SystemExit):
                integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertFalse(restore.resource_id)
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ):
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(put_mock.call_count, 0)
        self.assertTrue(state["firewall_replaced"])

    def test_restore_duplicate_or_foreign_server_candidate_never_mutates(self):
        for candidate_count, foreign, expected_code in (
            (2, False, "PROVIDER_DUPLICATE_MATCH"),
            (1, True, "PROVIDER_OWNERSHIP_MISMATCH"),
        ):
            with self.subTest(expected_code=expected_code):
                integration, backup, rules = self._complete_server_backup()
                restore = CoreCloudRestore.objects.create(
                    node=integration.node,
                    backup_id=backup.id,
                    name=f"candidate-{candidate_count}-{foreign}",
                    params={"zone": "us-chi1"},
                )
                get, post, put, state, target = self._restore_http(
                    integration, backup, restore, rules
                )
                integration._prepare_upcloud_server_restore(backup, restore)
                params = dict(restore.params)
                identity = dict(params["_bs_upcloud_restore"])
                identity.update(
                    {
                        "target_storage_id": "restored-storage",
                        "active_mutation": "server",
                    }
                )
                params["_bs_upcloud_restore"] = identity
                params["_bs_create_outcome_unknown"] = True
                restore.params = params
                restore.save(update_fields=["params", "modified"])
                state["storage_created"] = True
                original_get = get
                candidates = []
                for index in range(candidate_count):
                    candidate = {
                        "uuid": f"foreign-{index}",
                        "title": self._restore_ids(integration, backup, restore)["server"],
                    }
                    candidates.append(candidate)
                if foreign:
                    foreign_server = deepcopy(target)
                    foreign_server["labels"]["label"][1]["value"] = "other-source"

                def candidate_get(url, **kwargs):
                    if str(url).endswith("/server"):
                        return Response(
                            200,
                            {"servers": {"server": candidates}},
                            headers={"UpCloud-Total-Count": str(candidate_count)},
                        )
                    if str(url).endswith(f"/server/{candidates[0]['uuid']}"):
                        return Response(
                            200,
                            {"server": foreign_server if foreign else target},
                        )
                    return original_get(url, **kwargs)

                auth_cls = integration.node.connection.auth_upcloud.__class__
                with mock.patch.object(
                    auth_cls, "get_verified_client", return_value=mock.Mock()
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.get",
                    side_effect=candidate_get,
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.post",
                    side_effect=post,
                ) as post_mock, mock.patch(
                    "apps._tasks.integration.upcloud.requests.put",
                    side_effect=put,
                ) as put_mock:
                    with self.assertRaises(Exception):
                        integration.restore_snapshot(backup, restore)
                restore.refresh_from_db()
                self.assertEqual(
                    restore.params["_bs_last_error_code"], expected_code
                )
                post_mock.assert_not_called()
                put_mock.assert_not_called()
                self.assertFalse(state.get("server_created"))

    def test_restore_rejects_malformed_target_chain_without_put(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="malformed-target-chain",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules
        )
        integration._prepare_upcloud_server_restore(backup, restore)
        params = dict(restore.params)
        identity = dict(params["_bs_upcloud_restore"])
        identity.update(
            {
                "target_storage_id": "restored-storage",
                "active_mutation": "server",
            }
        )
        params["_bs_upcloud_restore"] = identity
        params["_bs_create_outcome_unknown"] = True
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        state["storage_created"] = True
        original_get = get

        def malformed_get(url, **kwargs):
            if str(url).endswith(
                f"/server/{target['uuid']}/firewall_rule"
            ):
                return Response(
                    200,
                    firewall_payload(
                        [
                            {**firewall_rule(1, port=22), "position": "1"},
                            {**firewall_rule(1, port=22), "position": "2"},
                            firewall_rule(3),
                        ]
                    ),
                )
            if str(url).endswith("/server"):
                return Response(
                    200,
                    {
                        "servers": {
                            "server": [
                                {
                                    "uuid": target["uuid"],
                                    "title": self._restore_ids(
                                        integration, backup, restore
                                    )["server"],
                                }
                            ]
                        }
                    },
                    headers={"UpCloud-Total-Count": "1"},
                )
            if str(url).endswith(f"/server/{target['uuid']}"):
                return Response(200, {"server": target})
            return original_get(url, **kwargs)

        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=malformed_get,
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ) as put_mock:
            with self.assertRaises(Exception):
                integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(
            restore.params["_bs_last_error_code"],
            "PROVIDER_DUPLICATE_MATCH",
        )
        post_mock.assert_not_called()
        put_mock.assert_not_called()

    def test_firewall_chain_canonicalization_rejects_unknown_and_unordered_rules(self):
        with self.assertRaises(Exception):
            normalize_upcloud_firewall_rules(
                firewall_payload(
                    [
                        {**firewall_rule(2, port=22), "position": "2"},
                        firewall_rule(2),
                    ]
                )
            )
