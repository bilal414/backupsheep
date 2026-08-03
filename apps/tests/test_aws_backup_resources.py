from datetime import datetime, timezone
from unittest import mock

from botocore.exceptions import ClientError

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreAWSRDSBackup, CoreCloudRestore
from apps.console.connection.models import CoreAuthAWS, CoreAuthAWSRDS, CoreAWSRegion
from apps.console.node.models import CoreAWS, CoreAWSRDS, CoreNode
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.restore import restore_cloud_backup
from apps._tasks.integration.aws_backup import idempotency_token
from apps.tests import factories
from apps.tests.base import BaseTestCase


class AWSBackupResourceTests(BaseTestCase):
    def test_backup_idempotency_token_is_stable_and_provider_sized(self):
        token = idempotency_token("backup", "a-resource-name")

        self.assertEqual(token, idempotency_token("backup", "a-resource-name"))
        self.assertNotEqual(token, idempotency_token("backup", "another-resource"))
        self.assertLessEqual(len(token), 50)

    def _make_aws_node(self, resource_type, unique_id):
        connection = factories.make_connection(self.account, self.member, code="aws")
        key = self.account.get_encryption_key()
        CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
            backup_vault_name="test-vault",
            backup_role_arn="arn:aws:iam::123456789012:role/BackupSheepTest",
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name=unique_id,
            added_by=self.member,
        )
        aws = CoreAWS.objects.create(
            node=node,
            name=unique_id,
            unique_id=unique_id,
            resource_type=resource_type,
        )
        return node, aws

    @staticmethod
    def _backup(aws, *, uuid="backup-1", unique_id="", status=UtilBackup.Status.IN_PROGRESS):
        return aws.backups.create(
            uuid=uuid,
            unique_id=unique_id,
            status=status,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )

    def test_s3_discovery_is_region_scoped_and_marks_resource_type(self):
        connection = factories.make_connection(self.account, self.member, code="aws")
        auth = CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
        )
        s3 = mock.MagicMock()
        s3.list_buckets.return_value = {
            "Buckets": [{"Name": "test-east"}, {"Name": "test-west"}]
        }
        s3.get_bucket_location.side_effect = [
            {"LocationConstraint": None},
            {"LocationConstraint": "us-west-2"},
        ]

        with mock.patch.object(
            auth,
            "get_client",
            side_effect=lambda service="ec2": s3 if service == "s3" else mock.MagicMock(),
        ):
            buckets = auth.get_eligible_objects("s3")

        self.assertEqual([bucket["_bs_unique_id"] for bucket in buckets], ["test-east"])
        self.assertEqual(buckets[0]["_bs_resource_type"], "s3")

    def test_dynamodb_discovery_paginates_and_normalizes_size(self):
        connection = factories.make_connection(self.account, self.member, code="aws")
        auth = CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
        )
        dynamodb = mock.MagicMock()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"TableNames": ["test-table"]}]
        dynamodb.get_paginator.return_value = paginator
        dynamodb.describe_table.return_value = {
            "Table": {"TableName": "test-table", "TableSizeBytes": 2_000_000_000}
        }

        with mock.patch.object(
            auth,
            "get_client",
            side_effect=lambda service="ec2": dynamodb if service == "dynamodb" else mock.MagicMock(),
        ):
            tables = auth.get_eligible_objects("dynamodb")

        self.assertEqual(tables[0]["_bs_unique_id"], "test-table")
        self.assertEqual(tables[0]["_bs_resource_type"], "dynamodb")
        self.assertEqual(tables[0]["_bs_size"], 2.0)

    @mock.patch("apps._tasks.integration.aws_backup.resource_arn", return_value="arn:aws:s3:::test-bucket")
    @mock.patch("apps._tasks.integration.aws_backup.start_backup_job")
    def test_aws_backup_create_persists_job_id_and_stable_metadata(self, start_job, resource_arn):
        node, aws = self._make_aws_node(CoreAWS.ResourceType.S3, "test-bucket")
        backup = self._backup(aws, uuid="stable-backup")
        start_job.return_value = {"BackupJobId": "job-123"}

        node.aws.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "job-123")
        self.assertEqual(backup.metadata["_aws_backup"]["vault_name"], "test-vault")
        self.assertEqual(backup.metadata["_aws_backup"]["resource_type"], "s3")
        self.assertEqual(backup.metadata["_aws_backup"]["resource_arn"], "arn:aws:s3:::test-bucket")
        self.assertEqual(start_job.call_args.args[:3], (node.connection.auth_aws, "s3", "test-bucket"))
        self.assertEqual(start_job.call_args.args[3], "test-vault")

    @mock.patch("apps._tasks.integration.aws_backup.describe_backup_job")
    def test_dynamodb_aws_backup_poll_persists_recovery_point_and_completes(self, describe_job):
        node, aws = self._make_aws_node(CoreAWS.ResourceType.DYNAMODB, "test-table")
        backup = self._backup(aws, uuid="ddb-backup", unique_id="job-456")
        describe_job.return_value = {
            "BackupJobId": "job-456",
            "State": "COMPLETED",
            "RecoveryPointArn": "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-1",
            "BackupSizeInBytes": 3_000_000_000,
            "CompletionDate": datetime.now(timezone.utc),
        }

        result = backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertEqual(backup.metadata["_aws_backup"]["recovery_point_arn"], describe_job.return_value["RecoveryPointArn"])
        self.assertIsInstance(
            backup.metadata["_aws_backup"]["backup_job"]["CompletionDate"],
            str,
        )
        self.assertEqual(backup.size_gigabytes, 3.0)

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_s3_restore_persists_provider_job_id_and_destination(self, start_restore):
        node, aws = self._make_aws_node(CoreAWS.ResourceType.S3, "source-bucket")
        backup = self._backup(
            aws,
            uuid="s3-backup",
            unique_id="job-1",
            status=UtilBackup.Status.COMPLETE,
        )
        backup.metadata = {
            "_aws_backup": {
                "recovery_point_arn": "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-1"
            }
        }
        backup.save(update_fields=["metadata", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="s3-restore",
            params={"destination_bucket_name": "restore-bucket"},
        )
        start_restore.return_value = {"RestoreJobId": "restore-job-1"}
        s3 = mock.MagicMock()
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=lambda service="ec2": s3,
        ):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.provider_job_id, "restore-job-1")
        self.assertEqual(restore.resource_id, "restore-bucket")
        self.assertEqual(
            start_restore.call_args.args[:3],
            (
                node.connection.auth_aws,
                "s3",
                "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-1",
            ),
        )
        self.assertEqual(
            start_restore.call_args.args[3]["RestoreACLs"],
            "false",
        )

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_dynamodb_restore_rejects_existing_target_and_persists_new_target(
        self, start_restore
    ):
        node, aws = self._make_aws_node(CoreAWS.ResourceType.DYNAMODB, "source-table")
        backup = self._backup(
            aws,
            uuid="ddb-backup",
            unique_id="job-1",
            status=UtilBackup.Status.COMPLETE,
        )
        backup.metadata = {
            "_aws_backup": {
                "recovery_point_arn": "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-1"
            }
        }
        backup.save(update_fields=["metadata", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="ddb-restore",
            params={"target_table_name": "ddb-restore"},
        )
        start_restore.return_value = {"RestoreJobId": "restore-job-1"}
        dynamodb = mock.MagicMock()

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=lambda service="ec2": dynamodb,
        ):
            dynamodb.describe_table.return_value = {"Table": {"TableName": "ddb-restore"}}
            with self.assertRaises(ValueError):
                node.aws.restore_snapshot(backup, restore)

            dynamodb.describe_table.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "DescribeTable",
            )
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.provider_job_id, "restore-job-1")
        self.assertEqual(restore.resource_id, "ddb-restore")
        self.assertEqual(
            start_restore.call_args.args[1],
            "dynamodb",
        )

    def test_restore_redelivery_with_provider_job_id_only_resumes_polling(self):
        node, aws = self._make_aws_node(CoreAWS.ResourceType.S3, "source-bucket")
        backup = self._backup(
            aws,
            uuid="s3-backup",
            unique_id="job-1",
            status=UtilBackup.Status.COMPLETE,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="s3-restore",
            resource_id="restore-bucket",
            provider_job_id="restore-job-1",
            status=CoreCloudRestore.Status.IN_PROGRESS,
        )

        with mock.patch.object(restore_cloud_backup, "apply_async") as unused:
            with mock.patch(
                "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
            ) as poll, mock.patch.object(node.aws, "restore_snapshot") as start:
                restore_cloud_backup.apply(
                    kwargs={
                        "node_id": node.id,
                        "backup_id": backup.id,
                        "restore_id": restore.id,
                    },
                    task_id="redelivered-restore",
                )

        start.assert_not_called()
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=60)


class TestAWSRDSNativeSnapshot(BaseTestCase):
    def test_rds_native_snapshot_uses_deterministic_identifier(self):
        connection = factories.make_connection(self.account, self.member, code="aws_rds")
        key = self.account.get_encryption_key()
        CoreAuthAWSRDS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="test-rds",
            added_by=self.member,
        )
        CoreAWSRDS.objects.create(
            node=node,
            name="test-rds",
            unique_id="test-db",
        )
        backup = CoreAWSRDSBackup.objects.create(
            aws_rds=node.aws_rds,
            uuid="rds-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        client = mock.MagicMock()
        client.describe_db_snapshots.side_effect = ClientError(
            {"Error": {"Code": "DBSnapshotNotFound"}},
            "DescribeDBSnapshots",
        )
        client.create_db_snapshot.return_value = {
            "DBSnapshot": {
                "DBSnapshotIdentifier": "rds-backup",
                "AllocatedStorage": 20,
            }
        }

        with mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
            node.aws_rds.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "rds-backup")
        client.create_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="rds-backup",
            DBInstanceIdentifier="test-db",
        )

    def test_rds_snapshot_poll_normalizes_datetime_metadata(self):
        connection = factories.make_connection(self.account, self.member, code="aws_rds")
        key = self.account.get_encryption_key()
        CoreAuthAWSRDS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="test-rds-poll",
            added_by=self.member,
        )
        CoreAWSRDS.objects.create(
            node=node,
            name="test-rds-poll",
            unique_id="test-db-poll",
        )
        backup = CoreAWSRDSBackup.objects.create(
            aws_rds=node.aws_rds,
            uuid="rds-poll-backup",
            unique_id="rds-poll-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        client = mock.MagicMock()
        client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "rds-poll-backup",
                    "AllocatedStorage": 20,
                    "Status": "available",
                    "SnapshotCreateTime": datetime.now(timezone.utc),
                }
            ]
        }

        with mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
            result = backup.poll_status()

        self.assertEqual(result, UtilBackup.Status.COMPLETE)
        backup.refresh_from_db()
        self.assertIsInstance(backup.metadata["SnapshotCreateTime"], str)

    def test_rds_snapshot_retry_reuses_existing_snapshot_with_datetime_metadata(self):
        connection = factories.make_connection(self.account, self.member, code="aws_rds")
        key = self.account.get_encryption_key()
        CoreAuthAWSRDS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="test-rds-retry",
            added_by=self.member,
        )
        CoreAWSRDS.objects.create(
            node=node,
            name="test-rds-retry",
            unique_id="test-db-retry",
        )
        backup = CoreAWSRDSBackup.objects.create(
            aws_rds=node.aws_rds,
            uuid="rds-retry-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        client = mock.MagicMock()
        client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "rds-retry-backup",
                    "AllocatedStorage": 20,
                    "Status": "creating",
                    "SnapshotCreateTime": datetime.now(timezone.utc),
                }
            ]
        }

        with mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
            node.aws_rds.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "rds-retry-backup")
        self.assertIsInstance(backup.metadata["SnapshotCreateTime"], str)
        client.create_db_snapshot.assert_not_called()

    def test_rds_restore_redelivery_with_resource_id_only_resumes_polling(self):
        connection = factories.make_connection(self.account, self.member, code="aws_rds")
        key = self.account.get_encryption_key()
        CoreAuthAWSRDS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="test-rds-restore-redelivery",
            added_by=self.member,
        )
        CoreAWSRDS.objects.create(
            node=node,
            name="test-rds-restore-redelivery",
            unique_id="test-db-restore-redelivery",
        )
        backup = CoreAWSRDSBackup.objects.create(
            aws_rds=node.aws_rds,
            uuid="rds-restore-backup",
            unique_id="rds-restore-backup",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="rds-restore-redelivery",
            resource_id="rds-restore-redelivery",
            status=CoreCloudRestore.Status.IN_PROGRESS,
        )

        with mock.patch(
            "apps._tasks.integration.restore.poll_cloud_restore.apply_async"
        ) as poll, mock.patch.object(node.aws_rds, "restore_snapshot") as start:
            restore_cloud_backup.apply(
                kwargs={
                    "node_id": node.id,
                    "backup_id": backup.id,
                    "restore_id": restore.id,
                },
                task_id="redelivered-rds-restore",
            )

        start.assert_not_called()
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=60)
