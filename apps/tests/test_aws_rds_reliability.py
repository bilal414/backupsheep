"""Crash/reconciliation tests for native AWS RDS snapshots."""

import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest import mock

from botocore.exceptions import ClientError
from django.test import override_settings
from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.aws_rds import backup_aws_rds
from apps.console.backup.models import (
    CoreAWSRDSBackup,
    CoreBackupExecution,
    CoreCloudRestore,
    RDSMalformedResponse,
    RestoreExecutionLeaseLostError,
)
from apps.console.connection.models import (
    CoreAuthAWSRDS,
    CoreAWSRegion,
    CoreConnection,
)
from apps.console.node.models import CoreAWSRDS, CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class AWSRDSReliabilityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        connection = factories.make_connection(self.account, self.member, code="aws_rds")
        key = self.account.get_encryption_key()
        self.auth = CoreAuthAWSRDS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="rds-reliability-node",
            added_by=self.member,
        )
        self.rds = CoreAWSRDS.objects.create(
            node=node,
            name="rds-reliability-node",
            unique_id="source-db",
        )
        self.backup = CoreAWSRDSBackup.objects.create(
            aws_rds=self.rds,
            uuid="rds-reliability-backup",
            unique_id="rds-reliability-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        self.client = mock.MagicMock()
        self.client.describe_db_instances.return_value = {
            "DBInstances": [self._source_instance()]
        }
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [self._snapshot(status="available")]
        }
        self.client.list_tags_for_resource.return_value = {
            "TagList": [
                {
                    "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                    "Value": CoreAWSRDSBackup._rds_ownership_marker(
                        identifier=self.backup.unique_id,
                        source_id=self.rds.unique_id,
                        region="us-east-1",
                        source_node_id=self.rds.node_id,
                        source_resource_id=self.rds.id,
                    ),
                }
            ]
        }
        self.sts = mock.MagicMock()
        self.sts.get_caller_identity.return_value = {"Account": "123456789012"}

    def _clients(self):
        configured_side_effect = self.client.list_tags_for_resource.side_effect
        self.client.list_tags_for_resource.side_effect = (
            lambda **kwargs: self._list_tags_for_resource(
                configured_side_effect, **kwargs
            )
        )

        def get_client(service=None):
            return self.sts if service == "sts" else self.client

        return mock.patch.object(CoreAuthAWSRDS, "get_client", side_effect=get_client)

    def _list_tags_for_resource(self, configured_side_effect, **kwargs):
        resource_name = str(kwargs.get("ResourceName") or "")
        if ":snapshot:" in resource_name:
            override = getattr(self, "_snapshot_tags_override", None)
            if override is not None:
                return override
            return {
                "TagList": [
                    {
                        "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                        "Value": CoreAWSRDSBackup._rds_ownership_marker(
                            identifier=self.backup.unique_id,
                            source_id=self.rds.unique_id,
                            region="us-east-1",
                            source_node_id=self.rds.node_id,
                            source_resource_id=self.rds.id,
                        ),
                    }
                ]
            }
        if configured_side_effect is not None:
            return configured_side_effect(**kwargs)
        configured = self.client.list_tags_for_resource.return_value
        if isinstance(configured, dict):
            return configured
        return {"TagList": []}

    @staticmethod
    def _client_error(code, operation="DescribeDBSnapshots", status=400):
        return ClientError(
            {
                "Error": {"Code": code, "Message": "test"},
                "ResponseMetadata": {"HTTPStatusCode": status},
            },
            operation,
        )

    @staticmethod
    def _snapshot(
        identifier="rds-reliability-backup",
        *,
        source="source-db",
        account="123456789012",
        region="us-east-1",
        snapshot_arn="__default__",
        snapshot_type="manual",
        status="creating",
        source_dbi_resource_id="__default__",
        snapshot_create_time="2026-08-10T12:00:00Z",
    ):
        arn = (
            f"arn:aws:rds:{region}:{account}:snapshot:{identifier}"
            if snapshot_arn == "__default__"
            else snapshot_arn
        )
        snapshot = {
            "DBSnapshotIdentifier": identifier,
            "DBInstanceIdentifier": source,
            "DBSnapshotArn": arn,
            "SnapshotType": snapshot_type,
            "AllocatedStorage": 20,
            "Status": status,
        }
        if snapshot_create_time is not None:
            snapshot["SnapshotCreateTime"] = snapshot_create_time
        if source_dbi_resource_id == "__default__":
            source_dbi_resource_id = f"db-resource-{source}" if source else None
        if source_dbi_resource_id is not None:
            snapshot["DbiResourceId"] = source_dbi_resource_id
        return snapshot

    def _persist_witness(self):
        self.backup._rds_persist_witness(
            self.backup._rds_witness(
                identifier="rds-reliability-backup",
                source_id="source-db",
                account_id="123456789012",
                region="us-east-1",
                source_node_id=self.rds.node_id,
                source_resource_id=self.rds.id,
                snapshot_create_time="2026-08-10T12:00:00Z",
            )
        )

    def _full_witness(self, backup=None, **overrides):
        backup = backup or self.backup
        source_instance = self._source_instance()
        values = {
            "identifier": backup.unique_id,
            "source_id": self.rds.unique_id,
            "account_id": "123456789012",
            "region": "us-east-1",
            "source_node_id": self.rds.node_id,
            "source_resource_id": self.rds.id,
                "source_restore_configuration": (
                backup._rds_source_restore_configuration(
                    source_instance, source_id=self.rds.unique_id
                )
            ),
            "snapshot_create_time": "2026-08-10T12:00:00Z",
        }
        values.update(overrides)
        values.setdefault(
            "source_dbi_resource_id", "db-resource-" + values["source_id"]
        )
        values.setdefault(
            "source_db_instance_arn",
            (
                "arn:aws:rds:"
                + values["region"]
                + ":"
                + values["account_id"]
                + ":db:"
                + values["source_id"]
            ),
        )
        return backup._rds_witness(**values)

    def _persist_full_witness(self, backup=None, **overrides):
        backup = backup or self.backup
        witness = self._full_witness(backup, **overrides)
        backup._rds_persist_witness(witness)
        return witness

    def _expire_execution_lease(self):
        state = self.backup.get_execution_state(create=False)
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(update_fields=["lease_expires_at", "modified"])

    @staticmethod
    def _source_instance(identifier="source-db"):
        return {
            "DBInstanceIdentifier": identifier,
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:123456789012:db:" + identifier
            ),
            "DbiResourceId": "db-resource-" + identifier,
            "DBInstanceClass": "db.r6g.large",
            "DBSubnetGroup": {"DBSubnetGroupName": "source-subnet"},
            "VpcSecurityGroups": [
                {"VpcSecurityGroupId": "sg-0123456789abcdef0"}
            ],
            "MultiAZ": True,
            "PubliclyAccessible": False,
            "StorageType": "gp3",
            "Iops": 3000,
            "StorageThroughput": 125,
        }

    def _restore(self, name="rds-restore-target", params=None):
        if params is None:
            # Existing crash/adoption tests intentionally exercise the request
            # protocol, not source-default discovery. Keep their request fully
            # explicit and use params={} in tests that cover inheritance.
            params = {
                "db_instance_class": "db.t3.micro",
                "db_subnet_group_name": "source-subnet",
                "multi_az": False,
                "publicly_accessible": False,
                "vpc_security_group_ids": ["sg-0123456789abcdef0"],
                "storage_type": "gp3",
                "iops": 3000,
                "storage_throughput": 125,
            }
        if self.backup.get_execution_state(create=False) is None or not (
            self.backup.get_execution_state(create=False).provider_metadata or {}
        ).get("rds_request"):
            self._persist_full_witness()
        restore = CoreCloudRestore.objects.create(
            node=self.rds.node,
            backup_id=self.backup.id,
            name=name,
            params=params,
        )
        return self._bind_restore_lease(restore)

    @staticmethod
    def _bind_restore_lease(restore):
        owner = f"rds-test-restore-{uuid.uuid4().hex}"
        token = uuid.uuid4()
        now = timezone.now()
        restore.lease_owner = owner
        restore.lease_token = token
        restore.lease_expires_at = now + timedelta(hours=1)
        restore.heartbeat_at = now
        restore.save(
            update_fields=[
                "lease_owner",
                "lease_token",
                "lease_expires_at",
                "heartbeat_at",
                "modified",
            ]
        )
        return restore.bind_execution_fence(owner, token)

    @staticmethod
    def _expire_restore_lease(restore):
        CoreCloudRestore.objects.filter(pk=restore.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )

    @staticmethod
    def _restored_instance(restore, marker, *, tags="owned", source=None):
        tag_list = []
        if tags == "owned":
            tag_list = [
                {"Key": "BackupSheepRestore", "Value": marker},
                {
                    "Key": "BackupSheepSource",
                    "Value": source or "rds-reliability-backup",
                },
            ]
        elif tags == "foreign":
            tag_list = [
                {"Key": "BackupSheepRestore", "Value": "another-restore"}
            ]
        return {
            "DBInstanceIdentifier": restore.name,
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:123456789012:db:" + restore.name
            ),
            "DBSnapshotIdentifier": source or "rds-reliability-backup",
            "DBInstanceStatus": "creating",
            "DbiResourceId": "db-resource-" + restore.name,
            "TagList": tag_list,
        }

    def test_celery_entry_point_uses_durable_backup_row_create_protocol(self):
        self.backup.status = UtilBackup.Status.COMPLETE
        self.backup.save(update_fields=["status", "modified"])

        def create_durably(backup, task_id=None):
            backup.unique_id = backup.uuid_str
            backup.save(update_fields=["unique_id", "modified"])
            return backup

        task_kwargs = {
            "node_id": self.rds.node_id,
            "schedule_id": None,
            "storage_ids": None,
            "notes": None,
        }
        with mock.patch.object(CoreConnection, "validate", return_value=True), \
                mock.patch.object(CoreNode, "validate", return_value=True), \
                mock.patch.object(
                    CoreAWSRDSBackup,
                    "create_snapshot",
                    autospec=True,
                    side_effect=create_durably,
                ) as durable_create, \
                mock.patch.object(CoreAWSRDS, "create_snapshot") as legacy_create, \
                mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as poll:
            backup_aws_rds.apply(
                kwargs=task_kwargs,
                task_id="rds-durable-entry-point",
            )

        durable_create.assert_called_once()
        self.assertEqual(
            durable_create.call_args.kwargs["task_id"],
            "rds-durable-entry-point",
        )
        legacy_create.assert_not_called()
        poll.assert_called_once()

    def test_ambiguous_create_enters_polling_without_celery_retry(self):
        self.backup.status = UtilBackup.Status.COMPLETE
        self.backup.save(update_fields=["status", "modified"])

        def ambiguous_create(backup, task_id=None):
            state = backup.get_execution_state(create=True)
            state.reconciliation_state = CoreBackupExecution.ReconciliationState.REQUIRED
            state.reconciliation_reason = "rds_create_outcome_unknown"
            state.save(
                update_fields=[
                    "reconciliation_state",
                    "reconciliation_reason",
                    "modified",
                ]
            )
            raise TimeoutError("provider response was lost")

        task_kwargs = {
            "node_id": self.rds.node_id,
            "schedule_id": None,
            "storage_ids": None,
            "notes": None,
        }
        with mock.patch.object(CoreConnection, "validate", return_value=True), \
                mock.patch.object(CoreNode, "validate", return_value=True), \
                mock.patch.object(
                    CoreAWSRDSBackup,
                    "create_snapshot",
                    autospec=True,
                    side_effect=ambiguous_create,
                ), \
                mock.patch.object(helper_tasks.poll_cloud_backup, "apply_async") as poll:
            result = backup_aws_rds.apply(
                kwargs=task_kwargs,
                task_id="rds-ambiguous-entry-point",
                throw=True,
            )

        self.assertTrue(result.successful())
        poll.assert_called_once()

    def test_initial_snapshot_persists_restore_witness_before_provider_mutation(self):
        self.client.describe_db_snapshots.return_value = {"DBSnapshots": []}
        witnessed = {}

        def create_snapshot(**_kwargs):
            state = self.backup.get_execution_state(create=False)
            witnessed.update(state.provider_metadata["rds_request"])
            return {"DBSnapshot": self._snapshot()}

        self.client.create_db_snapshot.side_effect = create_snapshot

        with self._clients():
            self.backup.create_snapshot(task_id="rds-initial-witness")

        self.assertEqual(witnessed["witness_version"], 3)
        self.assertEqual(witnessed["witness_state"], "provisional")
        self.assertRegex(witnessed["ownership_marker"], r"^bs-rds-[0-9a-f]{64}$")
        self.assertEqual(witnessed["source_node_id"], self.rds.node_id)
        self.assertEqual(witnessed["source_resource_id"], self.rds.id)
        self.assertEqual(witnessed["account_id"], "123456789012")
        self.assertEqual(witnessed["region"], "us-east-1")
        self.assertEqual(
            witnessed["snapshot_arn"],
            "arn:aws:rds:us-east-1:123456789012:snapshot:rds-reliability-backup",
        )
        self.assertEqual(
            witnessed["source_dbi_resource_id"], "db-resource-source-db"
        )
        self.assertEqual(
            witnessed["source_db_instance_arn"],
            "arn:aws:rds:us-east-1:123456789012:db:source-db",
        )
        self.assertEqual(
            witnessed["source_restore_configuration"],
            {
                "db_instance_class": "db.r6g.large",
                "db_subnet_group_name": "source-subnet",
                "multi_az": True,
                "publicly_accessible": False,
                "vpc_security_group_ids": ["sg-0123456789abcdef0"],
                "storage_type": "gp3",
                "iops": 3000,
                "storage_throughput": 125,
            },
        )
        self.assertRegex(
            witnessed["source_restore_configuration_sha256"], r"^[0-9a-f]{64}$"
        )
        self.client.describe_db_instances.assert_called_once_with(
            DBInstanceIdentifier="source-db"
        )
        self.client.create_db_snapshot.assert_called_once()

    def test_stale_create_lease_is_rejected_before_provider_mutation(self):
        def expire_before_lookup(**_kwargs):
            self._expire_execution_lease()
            return {"DBSnapshots": []}

        self.client.describe_db_snapshots.side_effect = expire_before_lookup

        with self._clients():
            result = self.backup.create_snapshot(task_id="rds-stale-worker")

        self.assertFalse(result)
        self.client.create_db_snapshot.assert_not_called()

    def test_in_progress_rds_poll_preserves_control_and_schedules_successor(self):
        self._persist_full_witness(snapshot_create_time=None)
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                self._snapshot(
                    status="creating",
                    snapshot_create_time="2026-08-11T01:03:34.012Z",
                )
            ]
        }

        with self._clients(), mock.patch.object(
            helper_tasks.poll_cloud_backup, "apply_async"
        ) as successor:
            helper_tasks.poll_cloud_backup.apply(
                args=[self.rds.node_id, self.backup.id, time.time(), 120, 86400],
                task_id="rds-poll-control-task",
            )

        successor.assert_called_once()
        self.backup.refresh_from_db()
        control = self.backup.metadata["_backup_control"]
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(control["poll_task_id"], "rds-poll-control-task")
        self.assertEqual(control["poll_lease_token"], str(state.lease_token))
        self.assertIn("poll_next_run_at", control)
        self.assertGreater(float(control["poll_next_run_at"]), time.time())
        self.assertGreaterEqual(successor.call_args.kwargs["countdown"], 1)

    def test_rds_create_timestamp_is_provisional_until_available(self):
        self.client.describe_db_snapshots.return_value = {"DBSnapshots": []}
        self.client.create_db_snapshot.return_value = {
            "DBSnapshot": self._snapshot(
                status="creating",
                snapshot_create_time="2026-08-11T01:03:34.012Z",
            )
        }

        with self._clients():
            self.backup.create_snapshot(task_id="rds-timestamp-create")

        state = self.backup.get_execution_state(create=False)
        provisional = state.provider_metadata["rds_request"]
        self.assertEqual(
            provisional["witness_state"],
            CoreAWSRDSBackup._RDS_PROVISIONAL_WITNESS_STATE,
        )
        self.assertNotIn("snapshot_create_time", provisional)
        self.assertNotIn("original_snapshot_create_time", provisional)
        self.assertEqual(
            provisional["snapshot_arn"],
            "arn:aws:rds:us-east-1:123456789012:snapshot:rds-reliability-backup",
        )
        self.assertEqual(
            provisional["source_db_instance_identifier"], "source-db"
        )
        self.assertEqual(
            provisional["source_dbi_resource_id"], "db-resource-source-db"
        )
        provisional_marker = provisional["ownership_marker"]
        self.backup.refresh_from_db()
        self.assertNotIn("SnapshotCreateTime", self.backup.metadata or {})
        self.assertNotIn("OriginalSnapshotCreateTime", self.backup.metadata or {})

        stable_time = "2026-08-11T01:03:38.195Z"
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                self._snapshot(status="available", snapshot_create_time=stable_time)
            ]
        }
        with self._clients():
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.COMPLETE)
        state = self.backup.get_execution_state(create=False)
        committed = state.provider_metadata["rds_request"]
        self.assertEqual(
            committed["witness_state"],
            CoreAWSRDSBackup._RDS_COMMITTED_WITNESS_STATE,
        )
        self.assertEqual(
            committed["snapshot_create_time"],
            "2026-08-11T01:03:38.195000Z",
        )
        self.assertEqual(committed["ownership_marker"], provisional_marker)
        self.assertEqual(committed["snapshot_arn"], provisional["snapshot_arn"])
        self.assertEqual(
            committed["source_db_instance_identifier"],
            provisional["source_db_instance_identifier"],
        )

    def test_committed_rds_witness_rejects_replacement_after_stable_timestamp(self):
        self._persist_full_witness(
            snapshot_create_time="2026-08-11T01:03:38.195Z"
        )
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                self._snapshot(
                    status="available",
                    snapshot_create_time="2026-08-11T01:03:38.196Z",
                )
            ]
        }

        with self._clients():
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.FAILED)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")

    def test_snapshot_substitution_or_recreation_fails_v2_ownership_proof(self):
        self._persist_full_witness()
        for label, changes in (
            (
                "arn",
                {
                    "snapshot_arn": (
                        "arn:aws:rds:us-east-1:999999999999:"
                        "snapshot:rds-reliability-backup"
                    )
                },
            ),
            ("db-resource", {"source_dbi_resource_id": "db-resource-recreated"}),
            (
                "same-source-recreated",
                {"snapshot_create_time": "2026-08-10T12:00:01Z"},
            ),
        ):
            with self.subTest(label=label):
                snapshot = self._snapshot()
                if label == "arn":
                    snapshot["DBSnapshotArn"] = changes["snapshot_arn"]
                elif label == "db-resource":
                    snapshot["DbiResourceId"] = changes[
                        "source_dbi_resource_id"
                    ]
                else:
                    snapshot["SnapshotCreateTime"] = changes[
                        "snapshot_create_time"
                    ]
                self.client.describe_db_snapshots.return_value = {
                    "DBSnapshots": [snapshot]
                }
                with self._clients():
                    result = self.backup.poll_status()
                self.assertEqual(result, UtilBackup.Status.FAILED)
                state = self.backup.get_execution_state(create=False)
                self.assertEqual(
                    state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                )

    def test_snapshot_missing_or_foreign_ownership_tag_fails_closed(self):
        self._persist_full_witness()
        for tag_list in (
            [],
            [{"Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY, "Value": "bs-rds-" + "0" * 64}],
        ):
            with self.subTest(tag_list=tag_list):
                self._snapshot_tags_override = {"TagList": tag_list}
                with self._clients():
                    result = self.backup.poll_status()
                self.assertEqual(result, UtilBackup.Status.FAILED)
                state = self.backup.get_execution_state(create=False)
                self.assertEqual(
                    state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                )
                self.client.describe_db_snapshots.reset_mock()
                self.client.list_tags_for_resource.reset_mock()

    def test_v2_witness_without_provider_identity_fails_closed(self):
        witness = self._full_witness()
        witness.pop("source_dbi_resource_id")
        state = self.backup.get_execution_state(create=True)
        metadata = dict(state.provider_metadata or {})
        metadata["rds_request"] = witness
        state.provider_metadata = metadata
        state.save(update_fields=["provider_metadata", "modified"])
        restore = self._restore(params={})

        with self._clients():
            with self.assertRaises(ValueError):
                self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_lost_create_response_is_adopted_without_duplicate_create(self):
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": []},
            {
                "DBSnapshots": [
                    self._snapshot(
                        status="available",
                        snapshot_create_time="2026-08-11T01:03:38.195Z",
                    )
                ]
            },
        ]
        self.client.create_db_snapshot.side_effect = TimeoutError("lost response")

        with self._clients():
            with self.assertRaises(TimeoutError):
                self.backup.create_snapshot(task_id="rds-create-worker-1")
            first_witness = dict(
                self.backup.get_execution_state(create=False).provider_metadata[
                    "rds_request"
                ]
            )

            # A crashed worker leaves a live fence. Recovery waits for expiry, then
            # reconciles the deterministic identifier before it can create again.
            self._expire_execution_lease()
            self.backup.create_snapshot(task_id="rds-create-worker-2")

        request = self.client.create_db_snapshot.call_args.kwargs
        self.assertEqual(
            request["DBSnapshotIdentifier"], "rds-reliability-backup"
        )
        self.assertEqual(request["DBInstanceIdentifier"], "source-db")
        self.assertEqual(
            request["Tags"],
            [
                {
                    "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                    "Value": first_witness["ownership_marker"],
                }
            ],
        )
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.unique_id, "rds-reliability-backup")
        state = self.backup.get_execution_state(create=False)
        final_witness = state.provider_metadata["rds_request"]
        self.assertEqual(
            final_witness["ownership_marker"], first_witness["ownership_marker"]
        )
        self.assertEqual(final_witness["witness_state"], "committed")
        self.assertEqual(
            final_witness["snapshot_create_time"],
            "2026-08-11T01:03:38.195000Z",
        )
        self.assertEqual(self.client.describe_db_instances.call_count, 1)
        self.assertEqual(
            state.provider_metadata["rds_request"]["account_id"], "123456789012"
        )
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.RESOLVED,
        )

    def test_live_create_lease_blocks_duplicate_worker_after_crash(self):
        self.client.describe_db_snapshots.return_value = {"DBSnapshots": []}
        self.client.create_db_snapshot.side_effect = KeyboardInterrupt()

        with self._clients():
            with self.assertRaises(KeyboardInterrupt):
                self.backup.create_snapshot(task_id="rds-crashed-worker")
            state = self.backup.get_execution_state(create=False)
            self.assertEqual(state.phase, "create")
            self.assertTrue(state.lease_is_active())
            self.assertIsNone(self.backup._rds_create_lease("rds-duplicate-worker"))
            self.assertIsNone(self.backup._rds_create_lease("rds-crashed-worker"))
            self.assertIsNone(self.backup._rds_create_lease(None))
            self.assertIsNone(self.backup.create_snapshot(task_id="rds-duplicate-worker"))

        self.client.create_db_snapshot.assert_called_once()

    def test_pre_mutation_rate_limit_is_retrying_not_unknown_in_progress(self):
        self.client.describe_db_snapshots.side_effect = self._client_error(
            "ThrottlingException", operation="DescribeDBSnapshots", status=429
        )

        with self._clients():
            result = self.backup.create_snapshot(task_id="rds-rate-limited-create")

        self.assertIsNotNone(result)
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.RETRYING)
        state = self.backup.get_execution_state(create=False)
        self.assertFalse(state.lease_is_active())
        # No provider mutation checkpoint exists, so the provider error is not
        # confused with a request whose outcome is unknown.
        self.assertEqual(state.last_error_code, "PROVIDER_RATE_LIMIT")
        self.assertEqual(state.provider_status, "rate_limited")
        self.assertEqual(state.reconciliation_state, CoreBackupExecution.ReconciliationState.NONE)

    def test_crash_create_lease_uses_bounded_rds_specific_default(self):
        self.client.describe_db_snapshots.return_value = {"DBSnapshots": []}
        self.client.create_db_snapshot.side_effect = KeyboardInterrupt()

        with self._clients():
            with self.assertRaises(KeyboardInterrupt):
                self.backup.create_snapshot(task_id="rds-short-crash-lease")

        state = self.backup.get_execution_state(create=False)
        self.assertTrue(state.lease_is_active())
        self.assertLessEqual(
            state.lease_expires_at - state.heartbeat_at,
            timedelta(seconds=300),
        )

        with override_settings(RDS_CREATE_LEASE_SECONDS=99999):
            self.assertEqual(CoreAWSRDSBackup._rds_create_lease_seconds(), 900)

    def test_provisional_witness_is_refused_for_restore(self):
        restore = self._restore(params={})
        provisional = self._full_witness(
            snapshot_create_time=None,
        )
        state = self.backup.get_execution_state(create=False)
        metadata = dict(state.provider_metadata or {})
        metadata["rds_request"] = provisional
        state.provider_metadata = metadata
        state.save(update_fields=["provider_metadata", "modified"])

        with self._clients():
            with self.assertRaises(ValueError):
                self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_lost_restore_response_adopts_exact_tagged_target_without_duplicate(self):
        restore = self._restore()
        not_found = self._client_error(
            "DBInstanceNotFound", operation="DescribeDBInstances"
        )
        self.client.describe_db_instances.side_effect = [
            not_found,
            {
                "DBInstances": [
                    self._restored_instance(restore, "placeholder")
                ]
            },
        ]
        self.client.restore_db_instance_from_db_snapshot.side_effect = TimeoutError(
            "lost response"
        )

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        marker = restore.restore_marker
        self.client.list_tags_for_resource.return_value = {
            "TagList": self._restored_instance(restore, marker)["TagList"]
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, restore.name)
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.client.restore_db_instance_from_db_snapshot.assert_called_once()

    def test_db_instance_already_exists_adopts_only_exact_owned_target(self):
        restore = self._restore()
        self.client.describe_db_instances.side_effect = [
            self._client_error("DBInstanceNotFound", operation="DescribeDBInstances"),
            {
                "DBInstances": [
                    self._restored_instance(restore, "placeholder")
                ]
            },
        ]
        self.client.restore_db_instance_from_db_snapshot.side_effect = (
            self._client_error(
                "DBInstanceAlreadyExists",
                operation="RestoreDBInstanceFromDBSnapshot",
            )
        )

        def owned_tags(**_kwargs):
            return {
                "TagList": self._restored_instance(
                    restore, restore.restore_marker
                )["TagList"]
            }

        self.client.list_tags_for_resource.side_effect = owned_tags

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, restore.name)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.client.restore_db_instance_from_db_snapshot.assert_called_once()
        self.assertEqual(
            self.client.describe_db_instances.call_count, 2
        )

    def test_db_instance_already_exists_foreign_collision_requires_manual_review(self):
        restore = self._restore()
        foreign = self._restored_instance(restore, "placeholder", tags="foreign")
        foreign["DBInstanceArn"] = (
            "arn:aws:rds:us-east-1:999999999999:db:" + restore.name
        )
        self.client.describe_db_instances.side_effect = [
            self._client_error("DBInstanceNotFound", operation="DescribeDBInstances"),
            {"DBInstances": [foreign]},
        ]
        self.client.restore_db_instance_from_db_snapshot.side_effect = (
            self._client_error(
                "DBInstanceAlreadyExists",
                operation="RestoreDBInstanceFromDBSnapshot",
            )
        )

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        restore.refresh_from_db()
        self.assertEqual(
            restore.last_error_code, "PROVIDER_RECONCILIATION_REQUIRED"
        )
        self.assertEqual(
            restore.operation_phase, CoreCloudRestore.OperationPhase.MANUAL_REVIEW
        )
        self.assertIsNone(restore.resource_id)
        self.client.restore_db_instance_from_db_snapshot.assert_called_once()

    def test_stale_restore_lease_is_rejected_before_provider_mutation(self):
        restore = self._restore()
        self._expire_restore_lease(restore)
        self.client.describe_db_instances.return_value = {
            "DBInstances": []
        }

        with self._clients():
            with self.assertRaises(RestoreExecutionLeaseLostError):
                self.rds.restore_snapshot(self.backup, restore)

        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_restore_target_identifier_or_arn_mismatch_blocks_mutation(self):
        for label, mutate in (
            (
                "identifier",
                lambda instance, restore: instance.update(
                    {"DBInstanceIdentifier": restore.name + "-foreign"}
                ),
            ),
            (
                "arn",
                lambda instance, restore: instance.update(
                    {
                        "DBInstanceArn": (
                            "arn:aws:rds:us-east-1:999999999999:db:"
                            + restore.name
                        )
                    }
                ),
            ),
        ):
            with self.subTest(label=label):
                restore = self._restore(name=f"rds-target-{label}")
                existing = self._restored_instance(restore, "placeholder")
                mutate(existing, restore)
                self.client.describe_db_instances.return_value = {
                    "DBInstances": [existing]
                }

                with self._clients():
                    with self.assertRaises(ValueError):
                        self.rds.restore_snapshot(self.backup, restore)

                restore.refresh_from_db()
                self.assertEqual(
                    restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                )
                self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_restore_inherits_exact_source_defaults_before_mutation(self):
        restore = self._restore(params={})
        self.client.describe_db_instances.side_effect = [
            self._client_error("DBInstanceNotFound", operation="DescribeDBInstances"),
        ]
        self.client.restore_db_instance_from_db_snapshot.return_value = {
            "DBInstance": self._restored_instance(restore, "ignored", tags="empty")
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        request = self.client.restore_db_instance_from_db_snapshot.call_args.kwargs
        self.assertEqual(request["DBInstanceClass"], "db.r6g.large")
        self.assertEqual(request["DBSubnetGroupName"], "source-subnet")
        self.assertEqual(
            request["VpcSecurityGroupIds"], ["sg-0123456789abcdef0"]
        )
        self.assertTrue(request["MultiAZ"])
        self.assertFalse(request["PubliclyAccessible"])
        self.assertEqual(request["StorageType"], "gp3")
        self.assertEqual(request["Iops"], 3000)
        self.assertEqual(request["StorageThroughput"], 125)
        restore.refresh_from_db()
        self.assertEqual(restore.params["db_instance_class"], "db.r6g.large")
        self.assertEqual(restore.params["db_subnet_group_name"], "source-subnet")
        self.assertEqual(
            restore.params["vpc_security_group_ids"],
            ["sg-0123456789abcdef0"],
        )
        self.assertEqual(
            self.client.describe_db_instances.call_args_list[0].kwargs,
            {"DBInstanceIdentifier": restore.name},
        )

    def test_legacy_restore_does_not_trust_mutable_snapshot_metadata(self):
        restore = self._restore(params={})
        state = self.backup.get_execution_state(create=False)
        state.provider_metadata = {}
        state.save(update_fields=["provider_metadata", "modified"])
        self.backup.metadata = {
            "DBSnapshotIdentifier": self.backup.unique_id,
            "DBInstanceIdentifier": self.rds.unique_id,
            "DBInstanceClass": "db.r6g.large",
            "DBSubnetGroupName": "metadata-subnet",
            "VpcSecurityGroupIds": ["sg-11111111111111111"],
            "MultiAZ": False,
            "PubliclyAccessible": False,
            "StorageType": "gp2",
        }
        self.client.describe_db_instances.side_effect = self._client_error(
            "DBInstanceNotFound", operation="DescribeDBInstances"
        )

        with self._clients():
            with self.assertRaises(ValueError):
                self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_source_deleted_restore_uses_immutable_backup_witness(self):
        witness = self._persist_full_witness()
        restore = self._restore(params={})
        self.client.describe_db_instances.side_effect = self._client_error(
            "DBInstanceNotFound", operation="DescribeDBInstances"
        )
        self.client.restore_db_instance_from_db_snapshot.return_value = {
            "DBInstance": self._restored_instance(restore, "ignored", tags="empty")
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        request = self.client.restore_db_instance_from_db_snapshot.call_args.kwargs
        configuration = witness["source_restore_configuration"]
        self.assertEqual(request["DBInstanceClass"], configuration["db_instance_class"])
        self.assertEqual(
            request["DBSubnetGroupName"], configuration["db_subnet_group_name"]
        )
        self.assertEqual(
            request["VpcSecurityGroupIds"],
            configuration["vpc_security_group_ids"],
        )
        self.assertEqual(request["MultiAZ"], configuration["multi_az"])
        self.assertEqual(
            request["PubliclyAccessible"], configuration["publicly_accessible"]
        )
        self.assertEqual(request["StorageType"], configuration["storage_type"])
        self.assertEqual(request["Iops"], configuration["iops"])
        self.assertEqual(
            request["StorageThroughput"], configuration["storage_throughput"]
        )
        self.assertEqual(
            self.client.describe_db_instances.call_args_list[0].kwargs,
            {"DBInstanceIdentifier": restore.name},
        )

    def test_mismatched_durable_restore_witness_fails_before_mutation(self):
        variants = (
            ("node", {"source_node_id": self.rds.node_id + 1}),
            ("resource", {"source_resource_id": self.rds.id + 1}),
            ("source", {"source_id": "other-source"}),
            ("snapshot", {"identifier": "other-snapshot"}),
            ("account", {"account_id": "999999999999"}),
            ("region", {"region": "us-west-2"}),
        )
        for suffix, overrides in variants:
            with self.subTest(suffix=suffix):
                backup = CoreAWSRDSBackup.objects.create(
                    aws_rds=self.rds,
                    uuid=f"rds-mismatch-{suffix}",
                    unique_id=f"rds-mismatch-{suffix}",
                    status=UtilBackup.Status.COMPLETE,
                    type=UtilBackup.Type.ON_DEMAND,
                    attempt_no=1,
                )
                backup._rds_persist_witness(
                    self._full_witness(backup, **overrides)
                )
                restore = CoreCloudRestore.objects.create(
                    node=self.rds.node,
                    backup_id=backup.id,
                    name=f"rds-restore-mismatch-{suffix}",
                    params={},
                )
                self._bind_restore_lease(restore)
                self.client.reset_mock()

                with self._clients():
                    with self.assertRaises(ValueError):
                        self.rds.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(
                    restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                )
                self.client.describe_db_instances.assert_not_called()
                self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_source_configuration_drift_does_not_change_restore_request(self):
        witness = self._persist_full_witness()
        restore = self._restore(params={})
        drifted_source = self._source_instance()
        drifted_source.update(
            {
                "DBInstanceClass": "db.t3.micro",
                "DBSubnetGroup": {"DBSubnetGroupName": "drifted-subnet"},
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-33333333333333333"}
                ],
                "MultiAZ": False,
                "PubliclyAccessible": True,
                "StorageType": "io2",
                "Iops": 5000,
                "StorageThroughput": None,
            }
        )

        def describe_instance(**kwargs):
            if kwargs["DBInstanceIdentifier"] == self.rds.unique_id:
                return {"DBInstances": [drifted_source]}
            raise self._client_error(
                "DBInstanceNotFound", operation="DescribeDBInstances"
            )

        self.client.describe_db_instances.side_effect = describe_instance
        self.client.restore_db_instance_from_db_snapshot.return_value = {
            "DBInstance": self._restored_instance(restore, "ignored", tags="empty")
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        request = self.client.restore_db_instance_from_db_snapshot.call_args.kwargs
        self.assertEqual(
            request["DBInstanceClass"],
            witness["source_restore_configuration"]["db_instance_class"],
        )
        self.assertEqual(
            request["DBSubnetGroupName"],
            witness["source_restore_configuration"]["db_subnet_group_name"],
        )
        self.assertEqual(
            request["VpcSecurityGroupIds"],
            witness["source_restore_configuration"]["vpc_security_group_ids"],
        )
        self.assertEqual(
            request["MultiAZ"],
            witness["source_restore_configuration"]["multi_az"],
        )
        self.assertEqual(
            request["PubliclyAccessible"],
            witness["source_restore_configuration"]["publicly_accessible"],
        )
        self.assertEqual(
            request["StorageType"],
            witness["source_restore_configuration"]["storage_type"],
        )
        self.assertEqual(
            request["Iops"], witness["source_restore_configuration"]["iops"]
        )
        self.assertEqual(
            request["StorageThroughput"],
            witness["source_restore_configuration"]["storage_throughput"],
        )
        self.assertNotIn(
            {"DBInstanceIdentifier": self.rds.unique_id},
            [call.kwargs for call in self.client.describe_db_instances.call_args_list],
        )

    def test_explicit_restore_params_override_source_defaults(self):
        self._persist_full_witness()
        restore = self._restore(
            params={
                "db_instance_class": "db.t3.micro",
                "db_subnet_group_name": "explicit-subnet",
                "multi_az": False,
                "publicly_accessible": True,
                "vpc_security_group_ids": ["sg-22222222222222222"],
                "storage_type": "io2",
                "iops": 4000,
                "storage_throughput": None,
            }
        )
        self.client.describe_db_instances.side_effect = self._client_error(
            "DBInstanceNotFound", operation="DescribeDBInstances"
        )
        self.client.restore_db_instance_from_db_snapshot.return_value = {
            "DBInstance": self._restored_instance(restore, "ignored", tags="empty")
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        request = self.client.restore_db_instance_from_db_snapshot.call_args.kwargs
        self.assertEqual(request["DBInstanceClass"], "db.t3.micro")
        self.assertEqual(request["DBSubnetGroupName"], "explicit-subnet")
        self.assertFalse(request["MultiAZ"])
        self.assertTrue(request["PubliclyAccessible"])
        self.assertEqual(
            request["VpcSecurityGroupIds"], ["sg-22222222222222222"]
        )
        self.assertEqual(request["StorageType"], "io2")
        self.assertEqual(request["Iops"], 4000)
        self.assertNotIn("StorageThroughput", request)
        self.assertEqual(
            self.client.describe_db_instances.call_args_list[0].kwargs,
            {"DBInstanceIdentifier": restore.name},
        )

    def test_rds_storage_boundaries_and_provider_defaults(self):
        base = {
            "db_instance_class": "db.r6g.large",
            "db_subnet_group_name": "source-subnet",
            "multi_az": True,
            "publicly_accessible": False,
            "vpc_security_group_ids": ["sg-0123456789abcdef0"],
            "storage_type": "io1",
            "iops": 1000,
            "storage_throughput": None,
        }
        self.assertEqual(
            CoreAWSRDSBackup._rds_validate_restore_configuration(base)["iops"],
            1000,
        )

        for throughput in (125, 1000):
            configuration = dict(base)
            configuration.update(
                {"storage_type": "gp3", "iops": None, "storage_throughput": throughput}
            )
            self.assertEqual(
                CoreAWSRDSBackup._rds_validate_restore_configuration(
                    configuration
                )["storage_throughput"],
                throughput,
            )

        configuration = dict(base)
        configuration.update(
            {"storage_type": "gp3", "iops": None, "storage_throughput": None}
        )
        self.assertIsNone(
            CoreAWSRDSBackup._rds_validate_restore_configuration(configuration)[
                "iops"
            ]
        )
        self.assertEqual(CoreAWSRDS._validate_rds_restore_default("iops", 1000), 1000)
        CoreAWSRDS._validate_rds_restore_combination(
            {"storage_type": "gp3", "iops": None, "storage_throughput": None}
        )

        for throughput in (124, 1001):
            invalid = dict(configuration)
            invalid["storage_throughput"] = throughput
            with self.subTest(throughput=throughput):
                with self.assertRaises(RDSMalformedResponse):
                    CoreAWSRDSBackup._rds_validate_restore_configuration(invalid)

    def test_malformed_or_ambiguous_source_lookup_fails_before_mutation(self):
        cases = (
            (
                "malformed",
                {"DBInstances": {"DBInstanceIdentifier": "source-db"}},
                "PROVIDER_MALFORMED_RESPONSE",
            ),
            (
                "ambiguous",
                {"DBInstances": [self._source_instance(), self._source_instance()]},
                "PROVIDER_DUPLICATE_MATCH",
            ),
        )
        for suffix, response, expected_code in cases:
            with self.subTest(suffix=suffix):
                restore = self._restore(name=f"rds-restore-{suffix}", params={})
                self.client.reset_mock()
                self.client.describe_db_instances.return_value = response

                with self._clients():
                    with self.assertRaises(ValueError):
                        self.rds.restore_snapshot(self.backup, restore)

                restore.refresh_from_db()
                self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
                self.assertEqual(restore.last_error_code, expected_code)
                self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_source_provider_rate_limit_stays_in_progress_without_mutation(self):
        restore = self._restore(params={})
        self.client.describe_db_instances.side_effect = self._client_error(
            "ThrottlingException", operation="DescribeDBInstances", status=429
        )

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertEqual(restore.last_error_code, "PROVIDER_RATE_LIMIT")
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_inherited_restore_request_is_replayed_without_duplicate_mutation(self):
        restore = self._restore(params={})
        self.client.describe_db_instances.side_effect = [
            self._client_error("DBInstanceNotFound", operation="DescribeDBInstances"),
            {
                "DBInstances": [
                    self._restored_instance(restore, "ignored", tags="empty")
                ]
            },
        ]
        self.client.restore_db_instance_from_db_snapshot.side_effect = TimeoutError(
            "lost response"
        )

        with self._clients():
            first = self.rds.restore_snapshot(self.backup, restore)
        self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        marker = restore.restore_marker
        self.client.list_tags_for_resource.return_value = {
            "TagList": self._restored_instance(restore, marker)["TagList"]
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        self.client.restore_db_instance_from_db_snapshot.assert_called_once()
        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, restore.name)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(
            self.client.describe_db_instances.call_args_list[0].kwargs,
            {"DBInstanceIdentifier": restore.name},
        )
        self.assertEqual(
            self.client.describe_db_instances.call_args_list[1].kwargs,
            {"DBInstanceIdentifier": restore.name},
        )

    def test_create_response_without_snapshot_or_visible_tags_is_adopted_for_polling(self):
        restore = self._restore()
        self.client.describe_db_instances.side_effect = self._client_error(
            "DBInstanceNotFound", operation="DescribeDBInstances"
        )
        self.client.restore_db_instance_from_db_snapshot.return_value = {
            "DBInstance": {
                "DBInstanceIdentifier": restore.name,
                "DBInstanceArn": (
                    "arn:aws:rds:us-east-1:123456789012:db:" + restore.name
                ),
                "DBInstanceStatus": "creating",
                "TagList": [],
            }
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, restore.name)
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.operation_phase, CoreCloudRestore.OperationPhase.POLLING)
        self.assertEqual(
            restore.params["_backupsheep_restore"]["target_name"],
            restore.name,
        )

    def test_restore_adoption_uses_exact_source_tag_when_instance_omits_snapshot(self):
        restore = self._restore()
        restore.params = {"_bs_create_outcome_unknown": True}
        restore.save(update_fields=["params", "modified"])
        instance = self._restored_instance(
            restore,
            f"backupsheep-restore-{restore.id}",
        )
        instance.pop("DBSnapshotIdentifier")
        self.client.describe_db_instances.return_value = {
            "DBInstances": [instance]
        }
        self.client.list_tags_for_resource.return_value = {
            "TagList": instance["TagList"]
        }

        with self._clients():
            self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, restore.name)
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_restore_reconciliation_waits_for_eventually_consistent_tags(self):
        restore = self._restore()
        restore.params = {"_bs_create_outcome_unknown": True}
        restore.save(update_fields=["params", "modified"])
        self.client.describe_db_instances.return_value = {
            "DBInstances": [self._restored_instance(restore, "ignored", tags="empty")]
        }
        self.client.list_tags_for_resource.return_value = {"TagList": []}

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        self.assertIsNone(restore.resource_id)
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_restore_reconciliation_rejects_foreign_tag_list(self):
        restore = self._restore()
        restore.params = {"_bs_create_outcome_unknown": True}
        restore.save(update_fields=["params", "modified"])
        self.client.describe_db_instances.return_value = {
            "DBInstances": [
                self._restored_instance(restore, "ignored", tags="foreign")
            ]
        }
        self.client.list_tags_for_resource.return_value = {
            "TagList": self._restored_instance(
                restore, "ignored", tags="foreign"
            )["TagList"]
        }

        with self._clients():
            result = self.rds.restore_snapshot(self.backup, restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
        )
        self.assertIsNone(restore.resource_id)
        self.client.restore_db_instance_from_db_snapshot.assert_not_called()

    def test_restore_poll_requires_exact_rds_tag_list(self):
        restore = self._restore()
        restore.resource_id = restore.name
        restore.restore_marker = "backupsheep-restore-rds-poll"
        restore.params = {
            "_bs_marker_required": True,
            "_backupsheep_restore": {
                "source_id": self.backup.unique_id,
            },
        }
        restore.save()
        self.client.describe_db_instances.return_value = {
            "DBInstances": [
                self._restored_instance(
                    restore, restore.restore_marker, tags="foreign"
                )
            ]
        }
        self.client.list_tags_for_resource.return_value = {
            "TagList": self._restored_instance(
                restore, restore.restore_marker, tags="foreign"
            )["TagList"]
        }

        with self._clients():
            result = self.rds.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
        )

    def test_duplicate_exact_matches_fail_closed_and_never_create(self):
        matches = [self._snapshot(), self._snapshot()]
        self.client.describe_db_snapshots.return_value = {"DBSnapshots": matches}

        with self._clients():
            self.backup.create_snapshot(task_id="rds-duplicate-match")

        self.client.create_db_snapshot.assert_not_called()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.FAILED)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_DUPLICATE_MATCH")
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )

    def test_missing_or_mismatched_ownership_fields_fail_closed(self):
        variants = (
            ("missing-source", {"source": None}),
            ("wrong-source", {"source": "another-db"}),
            ("wrong-account", {"account": "999999999999"}),
            ("wrong-region", {"region": "us-west-2"}),
            ("missing-account-region", {"snapshot_arn": None}),
            ("missing-type", {"snapshot_type": None}),
            ("automated-type", {"snapshot_type": "automated"}),
        )
        expected_codes = {
            "missing-account-region": "PROVIDER_MALFORMED_RESPONSE",
        }
        for suffix, changes in variants:
            with self.subTest(suffix=suffix):
                backup = CoreAWSRDSBackup.objects.create(
                    aws_rds=self.rds,
                    uuid=f"rds-{suffix}",
                    unique_id="rds-reliability-backup",
                    status=UtilBackup.Status.IN_PROGRESS,
                    type=UtilBackup.Type.ON_DEMAND,
                    attempt_no=1,
                )
                backup._rds_persist_witness(
                    backup._rds_witness(
                        identifier="rds-reliability-backup",
                        source_id="source-db",
                        account_id="123456789012",
                        region="us-east-1",
                    )
                )
                snapshot = self._snapshot(**changes)
                self.client.describe_db_snapshots.return_value = {
                    "DBSnapshots": [snapshot]
                }
                with self._clients():
                    result = backup.poll_status()
                self.assertEqual(result, UtilBackup.Status.FAILED)
                state = backup.get_execution_state(create=False)
                self.assertEqual(
                    state.last_error_code,
                    expected_codes.get(suffix, "PROVIDER_OWNERSHIP_MISMATCH"),
                )

    def test_reconciliation_consumes_all_marker_pages(self):
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [], "Marker": "page-2"},
            {"DBSnapshots": [self._snapshot(status="available")]},
        ]

        with self._clients():
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.COMPLETE)
        self.assertEqual(self.client.describe_db_snapshots.call_count, 2)
        self.assertEqual(
            self.client.describe_db_snapshots.call_args_list[1].kwargs,
            {"DBSnapshotIdentifier": "rds-reliability-backup", "Marker": "page-2"},
        )

    def test_snapshot_cursor_pagination_has_a_finite_page_bound(self):
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [], "Marker": "page-2"},
            {"DBSnapshots": [], "Marker": "page-3"},
        ]

        with override_settings(RDS_SNAPSHOT_LIST_MAX_PAGES=2), self._clients():
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.FAILED)
        self.assertEqual(self.client.describe_db_snapshots.call_count, 2)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_MALFORMED_RESPONSE")

    def test_snapshot_cursor_pagination_has_a_finite_item_bound(self):
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {
                "DBSnapshots": [self._snapshot(), self._snapshot()],
                "Marker": "page-2",
            },
            {"DBSnapshots": [self._snapshot()]},
        ]

        with override_settings(RDS_SNAPSHOT_LIST_MAX_ITEMS=2), self._clients():
            result = self.backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.FAILED)
        self.assertEqual(self.client.describe_db_snapshots.call_count, 2)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_MALFORMED_RESPONSE")

    def test_lost_delete_response_is_adopted_without_second_delete(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [self._snapshot(status="available")]},
            self._client_error("DBSnapshotNotFoundFault"),
        ]
        self.client.delete_db_snapshot.side_effect = TimeoutError("lost delete response")

        with self._clients():
            self.assertFalse(self.backup.soft_delete())
            self.assertTrue(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="rds-reliability-backup"
        )
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)
        delete_state = self.backup.get_execution_state(create=False).provider_metadata[
            "rds_delete"
        ]
        self.assertTrue(delete_state["ownership_verified"])
        self.assertTrue(delete_state["delete_started"])
        self.assertTrue(delete_state["delete_completed"])

    def test_delete_404_is_success_only_after_prior_exact_proof(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            self._client_error("DBSnapshotNotFoundFault")
        ]

        with self._clients():
            self.assertFalse(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_not_called()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_FAILED_NOT_FOUND)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_NOT_FOUND")

    def test_delete_404_after_exact_proof_is_adopted_as_success(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [self._snapshot(status="available")]},
            self._client_error("DBSnapshotNotFoundFault"),
        ]
        self.client.delete_db_snapshot.side_effect = self._client_error(
            "DBSnapshotNotFoundFault", "DeleteDBSnapshot"
        )

        with self._clients():
            self.assertTrue(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_called_once()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)

    def test_accepted_delete_waits_for_absence_without_redispatch(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [self._snapshot(status="available")]},
            {"DBSnapshots": [self._snapshot(status="deleting")]},
            {"DBSnapshots": [self._snapshot(status="deleting")]},
        ]

        with self._clients():
            self.assertFalse(self.backup.soft_delete())
            self.assertFalse(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="rds-reliability-backup"
        )
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        delete_state = self.backup.get_execution_state(create=False).provider_metadata[
            "rds_delete"
        ]
        self.assertEqual(delete_state["delete_attempts"], 1)
        self.assertIsNotNone(delete_state["delete_response_received_at"])
        self.assertEqual(delete_state["provider_status"], "deleting")

    def test_crash_before_delete_request_can_redispatch_after_grace(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [self._snapshot(status="available")]},
            {"DBSnapshots": [self._snapshot(status="available")]},
            self._client_error("DBSnapshotNotFoundFault"),
        ]
        original_checkpoint = self.backup._rds_checkpoint_delete

        def crash_after_request_checkpoint(owner, token, patch):
            result = original_checkpoint(owner, token, patch)
            if patch.get("delete_request_sent_at") and not patch.get(
                "delete_response_received_at"
            ):
                raise KeyboardInterrupt("worker crashed before delete request")
            return result

        def age_request_checkpoint():
            state = self.backup.get_execution_state(create=False)
            metadata = dict(state.provider_metadata or {})
            delete_state = dict(metadata["rds_delete"])
            delete_state["delete_request_sent_at"] = (
                timezone.now() - timedelta(seconds=5)
            ).isoformat()
            metadata["rds_delete"] = delete_state
            state.provider_metadata = metadata
            state.save(update_fields=["provider_metadata", "modified"])

        with override_settings(RDS_DELETE_REDISPATCH_GRACE_SECONDS=1), self._clients():
            with mock.patch.object(
                self.backup,
                "_rds_checkpoint_delete",
                side_effect=crash_after_request_checkpoint,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.backup.soft_delete()
            self.client.delete_db_snapshot.assert_not_called()
            age_request_checkpoint()
            self.assertTrue(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="rds-reliability-backup"
        )
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)

    def test_delete_max_attempts_exhaust_to_manual_review(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [self._snapshot(status="available")]},
            {"DBSnapshots": [self._snapshot(status="available")]},
            {"DBSnapshots": [self._snapshot(status="available")]},
        ]
        original_checkpoint = self.backup._rds_checkpoint_delete

        def crash_after_request_checkpoint(owner, token, patch):
            result = original_checkpoint(owner, token, patch)
            if patch.get("delete_request_sent_at") and not patch.get(
                "delete_response_received_at"
            ):
                raise KeyboardInterrupt("worker crashed before delete request")
            return result

        def age_request_checkpoint():
            state = self.backup.get_execution_state(create=False)
            metadata = dict(state.provider_metadata or {})
            delete_state = dict(metadata["rds_delete"])
            delete_state["delete_request_sent_at"] = (
                timezone.now() - timedelta(seconds=5)
            ).isoformat()
            metadata["rds_delete"] = delete_state
            state.provider_metadata = metadata
            state.save(update_fields=["provider_metadata", "modified"])

        with override_settings(
            RDS_DELETE_REDISPATCH_GRACE_SECONDS=1,
            RDS_DELETE_MAX_ATTEMPTS=2,
        ), self._clients():
            with mock.patch.object(
                self.backup,
                "_rds_checkpoint_delete",
                side_effect=crash_after_request_checkpoint,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.backup.soft_delete()
            age_request_checkpoint()
            with mock.patch.object(
                self.backup,
                "_rds_checkpoint_delete",
                side_effect=crash_after_request_checkpoint,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.backup.soft_delete()
            age_request_checkpoint()
            self.assertFalse(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_not_called()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_FAILED)
        state = self.backup.get_execution_state(create=False)
        self.assertEqual(
            state.reconciliation_state,
            CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
        )
        self.assertEqual(state.last_error_code, "PROVIDER_RECONCILIATION_REQUIRED")
        self.assertEqual(
            state.provider_metadata["rds_delete"]["delete_attempts"], 2
        )

    def test_delete_refuses_mismatched_source_before_provider_mutation(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        self._persist_witness()
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [self._snapshot(source="another-db")]
        }

        with self._clients():
            self.assertFalse(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_not_called()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_FAILED)

    def test_rate_limit_and_transient_poll_errors_are_retrying_not_in_progress(self):
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            self._client_error("ThrottlingException", status=429),
            self._client_error("ServiceUnavailable", status=503),
        ]

        with self._clients():
            self.assertEqual(self.backup.poll_status(), UtilBackup.Status.RETRYING)
            self.assertEqual(self.backup.poll_status(), UtilBackup.Status.RETRYING)

        state = self.backup.get_execution_state(create=False)
        self.assertEqual(state.last_error_code, "PROVIDER_TRANSIENT_OUTAGE")
        self.assertIsNotNone(state.next_retry_at)

    def test_duplicate_delete_worker_is_fenced(self):
        self.backup.unique_id = "rds-reliability-backup"
        self.backup.status = UtilBackup.Status.DELETE_REQUESTED
        self.backup.save(update_fields=["unique_id", "status", "modified"])
        first = self.backup._rds_claim_delete_lease()
        self.assertIsNotNone(first)
        self.assertIsNone(self.backup._rds_claim_delete_lease())
