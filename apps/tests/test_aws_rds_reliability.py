"""Crash/reconciliation tests for native AWS RDS snapshots."""

from datetime import timedelta
from unittest import mock

from botocore.exceptions import ClientError
from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps._tasks.helper import tasks as helper_tasks
from apps._tasks.integration.aws_rds import backup_aws_rds
from apps.console.backup.models import (
    CoreAWSRDSBackup,
    CoreBackupExecution,
    CoreCloudRestore,
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
        self.sts = mock.MagicMock()
        self.sts.get_caller_identity.return_value = {"Account": "123456789012"}

    def _clients(self):
        def get_client(service=None):
            return self.sts if service == "sts" else self.client

        return mock.patch.object(CoreAuthAWSRDS, "get_client", side_effect=get_client)

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
    ):
        arn = (
            f"arn:aws:rds:{region}:{account}:snapshot:{identifier}"
            if snapshot_arn == "__default__"
            else snapshot_arn
        )
        return {
            "DBSnapshotIdentifier": identifier,
            "DBInstanceIdentifier": source,
            "DBSnapshotArn": arn,
            "SnapshotType": snapshot_type,
            "AllocatedStorage": 20,
            "Status": status,
        }

    def _persist_witness(self):
        self.backup._rds_persist_witness(
            self.backup._rds_witness(
                identifier="rds-reliability-backup",
                source_id="source-db",
                account_id="123456789012",
                region="us-east-1",
            )
        )

    def _expire_execution_lease(self):
        state = self.backup.get_execution_state(create=False)
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(update_fields=["lease_expires_at", "modified"])

    def _restore(self, name="rds-restore-target"):
        return CoreCloudRestore.objects.create(
            node=self.rds.node,
            backup_id=self.backup.id,
            name=name,
            params={"db_instance_class": "db.t3.micro"},
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

    def test_lost_create_response_is_adopted_without_duplicate_create(self):
        self.client.describe_db_snapshots.side_effect = [
            {"DBSnapshots": []},
            {"DBSnapshots": [self._snapshot()]},
        ]
        self.client.create_db_snapshot.side_effect = TimeoutError("lost response")

        with self._clients():
            with self.assertRaises(TimeoutError):
                self.backup.create_snapshot(task_id="rds-create-worker-1")

            # A crashed worker leaves a live fence. Recovery waits for expiry, then
            # reconciles the deterministic identifier before it can create again.
            self._expire_execution_lease()
            self.backup.create_snapshot(task_id="rds-create-worker-2")

        self.client.create_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="rds-reliability-backup",
            DBInstanceIdentifier="source-db",
        )
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.unique_id, "rds-reliability-backup")
        state = self.backup.get_execution_state(create=False)
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
            self.assertIsNone(self.backup.create_snapshot(task_id="rds-duplicate-worker"))

        self.client.create_db_snapshot.assert_called_once()

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
                self.assertEqual(state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")

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
        self.client.describe_db_snapshots.return_value = {
            "DBSnapshots": [self._snapshot(status="available")]
        }
        self.client.delete_db_snapshot.side_effect = self._client_error(
            "DBSnapshotNotFoundFault", "DeleteDBSnapshot"
        )

        with self._clients():
            self.assertTrue(self.backup.soft_delete())

        self.client.delete_db_snapshot.assert_called_once()
        self.backup.refresh_from_db()
        self.assertEqual(self.backup.status, UtilBackup.Status.DELETE_COMPLETED)

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

    def test_rate_limit_and_transient_poll_errors_remain_in_progress(self):
        self._persist_witness()
        self.client.describe_db_snapshots.side_effect = [
            self._client_error("ThrottlingException", status=429),
            self._client_error("ServiceUnavailable", status=503),
        ]

        with self._clients():
            self.assertEqual(self.backup.poll_status(), UtilBackup.Status.IN_PROGRESS)
            self.assertEqual(self.backup.poll_status(), UtilBackup.Status.IN_PROGRESS)

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
