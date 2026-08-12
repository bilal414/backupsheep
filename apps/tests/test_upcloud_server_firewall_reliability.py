"""Offline UpCloud Cloud Server firewall-chain reliability tests.

These tests use deterministic HTTP responses only.  They exercise the source
witness boundary and the restore state machine without reading credentials or
contacting UpCloud.
"""

from copy import deepcopy
from unittest import mock
from datetime import timedelta
import hashlib
import os
from uuid import uuid4

import requests as raw_requests
from django.utils import timezone

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.upcloud import (
    create_upcloud_snapshot,
    normalize_upcloud_firewall_rules,
    select_upcloud_boot_device,
)
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthUpCloud, CoreIntegration
from apps.console.node.models import CoreNode
from apps.console.node.models import (
    CoreUpCloud,
    _BackupProviderError,
    _RestoreProviderError,
)
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


SOURCE_BOOT_ID = "11111111-1111-4111-8111-111111111111"
SOURCE_DATA_ID = "22222222-2222-4222-8222-222222222222"
BACKUP_STORAGE_ID = "33333333-3333-4333-8333-333333333333"
TARGET_STORAGE_ID = "44444444-4444-4444-8444-444444444444"


def storage_labels():
    return [
        {"key": "_os_type", "value": "debian"},
        {
            "key": "_template_uuid",
            "value": "01000000-0000-4000-8000-000020050100",
        },
        {"key": "_os_main_category", "value": "Linux"},
    ]


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
        "boot_order": "disk",
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
                    "storage": SOURCE_BOOT_ID,
                    "type": "disk",
                    "boot_disk": "1",
                    "address": "virtio:0",
                    "labels": storage_labels(),
                }
            ]
        },
    }


def source_storage(storage_id=SOURCE_BOOT_ID, *, source_server_id="source-server"):
    return {
        "uuid": storage_id,
        "type": "normal",
        "zone": "us-chi1",
        "state": "online",
        "size": 10,
        "tier": "standard",
        "encrypted": "yes",
        "servers": {"server": [{"uuid": source_server_id}]},
    }


def backup_storage(storage_id, marker, *, origin=SOURCE_BOOT_ID, include_attributes=False):
    value = {
        "uuid": storage_id,
        "type": "backup",
        "title": marker,
        "origin": origin,
        "zone": "us-chi1",
        "state": "online",
        "size": 10,
    }
    if include_attributes:
        value.update({"tier": "standard", "encrypted": "yes"})
    return value


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

    def _complete_volume_backup(self):
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
            type=CoreNode.Type.VOLUME,
            name="upcloud-volume",
            added_by=self.member,
        )
        integration = CoreUpCloud.objects.create(
            node=node,
            name="upcloud-volume",
            unique_id="source-volume",
            metadata={
                "_bs_zone": "us-chi1",
                "tier": "standard",
                "encrypted": "yes",
            },
        )
        backup = integration.backups.create(
            uuid="volume-backup-marker",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            celery_task_id="upcloud-volume-backup-task",
        )
        source = source_storage("source-volume")
        backup_resource = backup_storage(
            BACKUP_STORAGE_ID,
            backup.uuid_str,
            origin="source-volume",
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get",
            side_effect=[
                Response(200, {"storage": source}),
                Response(
                    200,
                    {"storages": {"storage": []}},
                    headers={"UpCloud-Total-Count": "0"},
                ),
            ],
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post",
            return_value=Response(201, {"storage": backup_resource}),
        ):
            create_upcloud_snapshot(backup)
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        return integration, backup

    @staticmethod
    def _bind_restore(restore):
        lease_token = uuid4()
        restore.lease_owner = "upcloud-firewall-test"
        restore.lease_token = lease_token
        restore.lease_expires_at = timezone.now() + timedelta(hours=1)
        restore.save(
            update_fields=["lease_owner", "lease_token", "lease_expires_at", "modified"]
        )
        restore.bind_execution_fence("upcloud-firewall-test", lease_token)

    def _volume_restore_http(self, integration, backup, restore, *, conflict=False):
        self._bind_restore(restore)
        digest = integration._upcloud_restore_marker_digest(restore, backup.unique_id)
        marker = f"backupsheep-upcloud-{restore.pk}-{digest}"[:128]
        target = {
            "uuid": TARGET_STORAGE_ID,
            "type": "normal",
            "title": marker,
            "origin": backup.unique_id,
            "zone": "us-chi1",
            "state": "online",
            "size": 10,
            "tier": "standard",
            "encrypted": "yes",
        }

        def get(url, **kwargs):
            if str(url).endswith(f"/storage/{backup.unique_id}"):
                # The provider backup deliberately omits tier; the durable
                # source witness and CoreUpCloud metadata carry it.
                return Response(
                    200,
                    {"storage": backup_storage(backup.unique_id, backup.uuid_str, origin=integration.unique_id)},
                )
            if str(url).endswith("/storage/normal"):
                return Response(
                    200,
                    {"storages": {"storage": []}},
                    headers={"UpCloud-Total-Count": "0"},
                )
            if str(url).endswith(f"/storage/{TARGET_STORAGE_ID}"):
                return Response(200, {"storage": target})
            raise AssertionError(f"Unexpected UpCloud GET: {url}")

        def post(url, **kwargs):
            self.assertTrue(str(url).endswith(f"/storage/{backup.unique_id}/clone"))
            if conflict:
                return Response(409, {"error": {"error_code": "CONFLICT"}})
            self.assertEqual(
                kwargs["json"]["storage"]["tier"], "standard"
            )
            self.assertEqual(
                kwargs["json"]["storage"]["encrypted"], "yes"
            )
            return Response(201, {"storage": target})

        return get, post, target

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
        self,
        integration,
        backup,
        restore,
        rules,
        *,
        lost=False,
        lost_firewall=False,
        lost_ip=False,
        target_storage_overrides=None,
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
            "uuid": TARGET_STORAGE_ID,
            "type": "normal",
            "title": self._restore_ids(integration, backup, restore)["storage"],
            "origin": backup.unique_id,
            "zone": "us-chi1",
            "state": "online",
            "size": 10,
            "tier": "standard",
            "encrypted": "yes",
        }
        target_storage.update(target_storage_overrides or {})
        target_server, ids = self._target_server(
            integration, backup, restore, target_storage["uuid"]
        )
        default_rules = [firewall_rule(1)]
        isolated_target = deepcopy(target_server)
        isolated_target["networking"]["interfaces"]["interface"] = [
            interface
            for interface in isolated_target["networking"]["interfaces"]["interface"]
            if interface.get("type") != "public"
        ]
        state = {
            "storage_created": False,
            "server_created": False,
            "ip_assigned": False,
        }

        def target_view():
            return deepcopy(target_server if state["ip_assigned"] else isolated_target)

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
                return Response(200, {"server": target_view()})
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
                response = Response(202, {"server": target_view()})
                if lost:
                    raise raw_requests.Timeout("lost response")
                return response
            if str(url).endswith("/ip_address"):
                request = kwargs.get("json") or {}
                self.assertEqual(
                    request,
                    {
                        "ip_address": {
                            "family": "IPv4",
                            "server": target_server["uuid"],
                        }
                    },
                )
                state["ip_assigned"] = True
                response = Response(
                    201,
                    {
                        "ip_address": {
                            "family": "IPv4",
                            "server": target_server["uuid"],
                        }
                    },
                )
                if lost_ip:
                    raise raw_requests.Timeout("lost public IP response")
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

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
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
            3,
        )  # boot clone, isolated server create, and public IPv4 assignment
        self.assertEqual(put_mock.call_count, 1)
        self.assertTrue(state["firewall_replaced"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
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
        self.assertEqual(post_mock.call_count, 3)
        self.assertEqual(put_mock.call_count, 1)
        self.assertTrue(state["firewall_replaced"])
        self.assertTrue(state["ip_assigned"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
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
        self.assertTrue(state["ip_assigned"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
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
        self.assertTrue(state["ip_assigned"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
    def test_server_boot_clone_without_origin_uses_durable_backup_size(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="server-storage-origin-omitted",
            params={"zone": "us-chi1"},
        )
        get, post, put, _state, target = self._restore_http(
            integration,
            backup,
            restore,
            rules,
            target_storage_overrides={"origin": None},
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__

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
        self.assertEqual(
            restore.params["_bs_upcloud_restore"]["boot_storage_size"], 10
        )

    def test_server_boot_clone_rejects_conflicting_origin_or_size(self):
        for field, value in (("origin", "foreign-backup"), ("size", 11)):
            with self.subTest(field=field):
                integration, backup, rules = self._complete_server_backup()
                restore = CoreCloudRestore.objects.create(
                    node=integration.node,
                    backup_id=backup.id,
                    name=f"server-storage-invalid-{field}",
                    params={"zone": "us-chi1"},
                )
                get, post, put, _state, _target = self._restore_http(
                    integration,
                    backup,
                    restore,
                    rules,
                    target_storage_overrides={field: value},
                )
                auth_cls = integration.node.connection.auth_upcloud.__class__
                with mock.patch.object(
                    auth_cls, "get_verified_client", return_value=mock.Mock()
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.get", side_effect=get
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.post", side_effect=post
                ), mock.patch(
                    "apps._tasks.integration.upcloud.requests.put", side_effect=put
                ):
                    with self.assertRaises(_RestoreProviderError):
                        integration.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(
                    restore.params["_bs_last_error_code"],
                    "PROVIDER_MALFORMED_RESPONSE",
                )
                self.assertIsNone(restore.resource_id)

    def test_pointerless_server_restore_resume_requires_exact_durable_contract(self):
        integration, backup, _rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="server-pointerless-resume",
            status=CoreCloudRestore.Status.FAILED,
            operation_phase=CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
            execution_phase="manual_review",
        )
        identity = integration._prepare_upcloud_server_restore(backup, restore)
        params = dict(restore.params)
        identity = dict(identity)
        identity.update(
            {
                "stage": "storage_create_requested",
                "active_mutation": "storage",
            }
        )
        params["_bs_create_outcome_unknown"] = True
        params["_bs_upcloud_restore"] = identity
        restore.params = params
        restore.status = CoreCloudRestore.Status.FAILED
        restore.operation_phase = CoreCloudRestore.OperationPhase.MANUAL_REVIEW
        restore.save(
            update_fields=[
                "params",
                "status",
                "operation_phase",
                "modified",
            ]
        )

        self.assertTrue(restore.can_resume_verification)
        self.assertEqual(
            restore.verification_resume_mode, "provider_reconciliation"
        )

        params = dict(restore.params)
        identity = dict(params["_bs_upcloud_restore"])
        identity["boot_storage_size"] = 11
        params["_bs_upcloud_restore"] = identity
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        self.assertFalse(restore.can_resume_verification)

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
    def test_exact_acceptance_hold_persists_hash_only_witness_before_pointer(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="acceptance-hold",
            params={"zone": "us-chi1"},
        )
        get, post, put, _state, target = self._restore_http(
            integration, backup, restore, rules
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        digest = integration._upcloud_restore_marker_digest(
            restore, backup.unique_id
        )
        marker = f"backupsheep-upcloud-server-{restore.pk}-{digest}"[:128]
        environment = {
            "BACKUPSHEEP_UPCLOUD_FAULT_MODE": (
                "restore-server-post-accept-pre-persist"
            ),
            "BACKUPSHEEP_UPCLOUD_FAULT_RESTORE_ID": str(restore.pk),
            "BACKUPSHEEP_UPCLOUD_FAULT_RESTORE_MARKER": marker,
            "BACKUPSHEEP_UPCLOUD_FAULT_ACTION": "hold",
            "BACKUPSHEEP_UPCLOUD_FAULT_HOLD_SECONDS": "300",
        }

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.get", side_effect=get
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.post", side_effect=post
        ), mock.patch(
            "apps._tasks.integration.upcloud.requests.put", side_effect=put
        ), mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "apps.console.node.models.time.sleep"
        ) as hold:
            integration.restore_snapshot(backup, restore)

        hold.assert_called_once_with(300)
        restore.refresh_from_db()
        witness = restore.params["_bs_upcloud_restore"]["acceptance_fault"]
        self.assertEqual(
            witness,
            {
                "consumed": True,
                "mode": "hold",
                "stage": "server",
                "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
                "triggered_at": witness["triggered_at"],
            },
        )
        self.assertEqual(restore.resource_id, target["uuid"])

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
                        "target_storage_id": TARGET_STORAGE_ID,
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
                "target_storage_id": TARGET_STORAGE_ID,
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

    def test_multi_disk_boot_selector_accepts_unique_provider_os_device(self):
        server = source_server()
        devices = server["storage_devices"]["storage_device"]
        devices[0]["boot_disk"] = "0"
        devices.append(
            {
                "storage": SOURCE_DATA_ID,
                "type": "disk",
                "boot_disk": "0",
                "address": "scsi:0:0",
            }
        )
        self.assertEqual(select_upcloud_boot_device(server)["storage"], SOURCE_BOOT_ID)

    def test_multi_disk_boot_selector_rejects_duplicate_or_ambiguous_candidates(self):
        duplicate = source_server()
        duplicate_devices = duplicate["storage_devices"]["storage_device"]
        duplicate_devices[0]["boot_disk"] = "0"
        duplicate_devices.append(
            {
                "storage": SOURCE_DATA_ID,
                "type": "disk",
                "boot_disk": "0",
                "address": "virtio:0",
                "labels": storage_labels(),
            }
        )
        with self.assertRaises(_BackupProviderError) as raised:
            select_upcloud_boot_device(duplicate)
        self.assertEqual(raised.exception.code, "PROVIDER_DUPLICATE_MATCH")

        ambiguous = source_server()
        ambiguous_devices = ambiguous["storage_devices"]["storage_device"]
        ambiguous_devices[0]["boot_disk"] = "0"
        ambiguous_devices[0]["address"] = "virtio:1"
        ambiguous_devices.append(
            {
                "storage": SOURCE_DATA_ID,
                "type": "disk",
                "boot_disk": "0",
                "address": "scsi:0:0",
                "labels": storage_labels(),
            }
        )
        with self.assertRaises(_BackupProviderError) as raised:
            select_upcloud_boot_device(ambiguous)
        self.assertEqual(
            raised.exception.code, "PROVIDER_RECONCILIATION_REQUIRED"
        )

    def test_volume_witness_persists_source_attributes_when_backup_omits_them(self):
        integration, backup = self._complete_volume_backup()
        witness = backup.get_execution_state().provider_metadata["witness"]
        self.assertEqual(witness["scope"]["tier"], "standard")
        self.assertEqual(witness["scope"]["encrypted"], "yes")

        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="volume-attributes",
            params={"zone": "us-chi1"},
        )
        get, post, target = self._volume_restore_http(integration, backup, restore)
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock:
            result = integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertIsNone(result)
        self.assertEqual(restore.resource_id, target["uuid"])
        post_mock.assert_called_once()
        self.assertEqual(
            post_mock.call_args.kwargs["json"]["storage"]["tier"], "standard"
        )
        self.assertEqual(
            post_mock.call_args.kwargs["json"]["storage"]["encrypted"], "yes"
        )
        self.assertFalse(restore.params.get("_bs_create_outcome_unknown"))

    def test_volume_clone_without_provider_origin_uses_exact_durable_contract(self):
        integration, backup = self._complete_volume_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="volume-origin-omitted",
            params={"zone": "us-chi1"},
        )
        get, post, target = self._volume_restore_http(integration, backup, restore)
        target.pop("origin")
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock:
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(post_mock.call_count, 1)
        identity = restore.params["_bs_upcloud_restore"]
        self.assertEqual(identity["source_size"], 10)
        self.assertEqual(identity["target_size"], 10)

    def test_volume_clone_rejects_nonempty_conflicting_origin_or_size(self):
        for field, value in (("origin", "foreign-backup"), ("size", 11)):
            with self.subTest(field=field):
                integration, backup = self._complete_volume_backup()
                restore = CoreCloudRestore.objects.create(
                    node=integration.node,
                    backup_id=backup.id,
                    name=f"volume-invalid-{field}",
                    params={"zone": "us-chi1"},
                )
                get, post, target = self._volume_restore_http(
                    integration, backup, restore
                )
                target[field] = value
                auth_cls = integration.node.connection.auth_upcloud.__class__
                with mock.patch.object(
                    auth_cls, "get_verified_client", return_value=mock.Mock()
                ), mock.patch(
                    "apps.console.node.models.requests.get", side_effect=get
                ), mock.patch(
                    "apps.console.node.models.requests.post", side_effect=post
                ):
                    with self.assertRaises(_RestoreProviderError):
                        integration.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(
                    restore.params["_bs_last_error_code"],
                    "PROVIDER_OWNERSHIP_MISMATCH",
                )
                self.assertIsNone(restore.resource_id)

    def test_volume_provider_conflict_is_definitive_and_never_blindly_replayed(self):
        integration, backup = self._complete_volume_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="volume-provider-conflict",
            params={"zone": "us-chi1"},
        )
        get, post, _target = self._volume_restore_http(
            integration, backup, restore, conflict=True
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock:
            first = integration.restore_snapshot(backup, restore)
            second = integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(first, CoreCloudRestore.Status.FAILED)
        self.assertEqual(second, CoreCloudRestore.Status.FAILED)
        self.assertEqual(post_mock.call_count, 1)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_CONFLICT")
        self.assertEqual(
            restore.params["_bs_upcloud_restore"]["stage"], "clone_rejected"
        )
        self.assertFalse(restore.params.get("_bs_create_outcome_unknown"))

    def test_firewall_stabilization_blocks_public_ip_until_deadline_then_assigns_once(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="firewall-stabilization",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules
        )
        base = timezone.now().replace(microsecond=0)
        clock = [base]
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.timezone.now",
            side_effect=lambda: clock[0],
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps.console.node.models.requests.put", side_effect=put
        ) as put_mock:
            first = integration.restore_snapshot(backup, restore)
            self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
            self.assertEqual(post_mock.call_count, 2)
            self.assertFalse(state["ip_assigned"])
            restore.refresh_from_db()
            verified_at = restore.params["_bs_upcloud_restore"]["firewall_verified_at"]
            self.assertEqual(verified_at, base.isoformat())
            self.assertEqual(
                restore.params["_bs_upcloud_restore"]["stage"],
                "firewall_stabilizing",
            )

            clock[0] = base + timedelta(seconds=119)
            integration.restore_snapshot(backup, restore)
            self.assertEqual(post_mock.call_count, 2)
            self.assertFalse(state["ip_assigned"])

            clock[0] = base + timedelta(seconds=120)
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(put_mock.call_count, 1)
        ip_posts = [
            call
            for call in post_mock.call_args_list
            if str(call.args[0]).endswith("/ip_address")
        ]
        self.assertEqual(len(ip_posts), 1)
        self.assertTrue(state["ip_assigned"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
    def test_restore_lost_public_ip_response_reconciles_without_duplicate_assignment(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="lost-public-ip-response",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules, lost_ip=True
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__
        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps.console.node.models.requests.put", side_effect=put
        ) as put_mock:
            result = integration.restore_snapshot(backup, restore)
            self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
            restore.refresh_from_db()
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(put_mock.call_count, 1)
        ip_posts = [
            call
            for call in post_mock.call_args_list
            if str(call.args[0]).endswith("/ip_address")
        ]
        self.assertEqual(len(ip_posts), 1)
        self.assertTrue(state["ip_assigned"])

    @mock.patch(
        "apps.console.node.models._UPCLOUD_FIREWALL_STABILIZATION_SECONDS", 0
    )
    def test_restore_worker_crash_after_public_ip_acceptance_adopts_without_duplicate_assignment(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="public-ip-worker-crash",
            params={"zone": "us-chi1"},
        )
        get, post, put, state, target = self._restore_http(
            integration, backup, restore, rules
        )
        auth_cls = integration.node.connection.auth_upcloud.__class__

        def crash_after_ip(_restore, _marker, stage):
            if stage == "ip":
                raise SystemExit("worker crash after public IP acceptance")

        with mock.patch.object(
            auth_cls, "get_verified_client", return_value=mock.Mock()
        ), mock.patch(
            "apps.console.node.models.requests.get", side_effect=get
        ), mock.patch(
            "apps.console.node.models.requests.post", side_effect=post
        ) as post_mock, mock.patch(
            "apps.console.node.models.requests.put", side_effect=put
        ) as put_mock, mock.patch.object(
            CoreUpCloud,
            "_upcloud_server_restore_fault_after_accept",
            side_effect=crash_after_ip,
        ) as fault:
            with self.assertRaises(SystemExit):
                integration.restore_snapshot(backup, restore)
            restore.refresh_from_db()
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])
            self.assertEqual(
                restore.params["_bs_upcloud_restore"]["active_mutation"],
                "public_ip:0:IPv4",
            )
            fault.side_effect = None
            integration.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, target["uuid"])
        self.assertEqual(put_mock.call_count, 1)
        ip_posts = [
            call
            for call in post_mock.call_args_list
            if str(call.args[0]).endswith("/ip_address")
        ]
        self.assertEqual(len(ip_posts), 1)
        self.assertTrue(state["ip_assigned"])

    def test_target_ownership_accepts_provider_all_zero_boot_disk_one_disk_fallback(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="target-all-zero-boot",
            params={"zone": "us-chi1"},
        )
        target, _ids = self._target_server(
            integration, backup, restore, TARGET_STORAGE_ID
        )
        target["networking"]["interfaces"]["interface"] = [
            interface
            for interface in target["networking"]["interfaces"]["interface"]
            if interface.get("type") != "public"
        ]
        target["storage_devices"]["storage_device"][0]["boot_disk"] = "0"

        integration._prepare_upcloud_server_restore(backup, restore)
        identity = dict(restore.params["_bs_upcloud_restore"])
        identity.update(
            {
                "target_storage_id": TARGET_STORAGE_ID,
                "stage": "firewall_verified",
            }
        )
        self.assertTrue(
            integration._upcloud_server_restore_owned(
                target, identity, resource_id=target["uuid"]
            )
        )

        foreign_boot = deepcopy(target)
        foreign_boot["storage_devices"]["storage_device"][0]["storage"] = SOURCE_DATA_ID
        self.assertFalse(
            integration._upcloud_server_restore_owned(
                foreign_boot, identity, resource_id=target["uuid"]
            )
        )

    def test_target_ownership_rejects_ambiguous_all_zero_boot_disks(self):
        integration, backup, rules = self._complete_server_backup()
        restore = CoreCloudRestore.objects.create(
            node=integration.node,
            backup_id=backup.id,
            name="target-ambiguous-boot",
            params={"zone": "us-chi1"},
        )
        target, _ids = self._target_server(
            integration, backup, restore, TARGET_STORAGE_ID
        )
        target["networking"]["interfaces"]["interface"] = [
            interface
            for interface in target["networking"]["interfaces"]["interface"]
            if interface.get("type") != "public"
        ]
        devices = target["storage_devices"]["storage_device"]
        devices[0]["boot_disk"] = "0"
        devices.append(
            {
                "storage": SOURCE_DATA_ID,
                "type": "disk",
                "boot_disk": "0",
                "address": "scsi:0:0",
            }
        )

        integration._prepare_upcloud_server_restore(backup, restore)
        identity = dict(restore.params["_bs_upcloud_restore"])
        identity.update(
            {
                "target_storage_id": TARGET_STORAGE_ID,
                "stage": "firewall_verified",
            }
        )
        self.assertFalse(
            integration._upcloud_server_restore_owned(
                target, identity, resource_id=target["uuid"]
            )
        )
