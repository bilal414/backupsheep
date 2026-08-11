from datetime import datetime, timezone
from unittest import mock

from botocore.exceptions import ClientError

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreAWSBackup,
    CoreAWSRDSBackup,
    CoreCloudRestore,
)
from apps.console.connection.models import CoreAuthAWS, CoreAuthAWSRDS, CoreAWSRegion
from apps.console.node.models import CoreAWS, CoreAWSRDS, CoreNode
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.restore import restore_cloud_backup
from apps._tasks.integration.aws_backup import idempotency_token
from apps.tests import factories
from apps.tests.base import BaseTestCase


class AWSBackupResourceTests(BaseTestCase):
    DDB_ACCOUNT_ID = "123456789012"
    DDB_RECOVERY_POINT = (
        "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-restore-1"
    )
    DDB_RESTORE_TARGET = "ddb-restore-owned"

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

    def _completed_dynamodb_restore(self):
        node, aws = self._make_aws_node(
            CoreAWS.ResourceType.DYNAMODB,
            "source-table",
        )
        backup = self._backup(
            aws,
            uuid="ddb-owned-backup",
            unique_id="backup-job-1",
            status=UtilBackup.Status.COMPLETE,
        )
        marker = "backupsheep-restore-ddb-owned"
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name=self.DDB_RESTORE_TARGET,
            resource_id=self.DDB_RESTORE_TARGET,
            provider_job_id="restore-job-1",
            restore_marker=marker,
            status=CoreCloudRestore.Status.IN_PROGRESS,
            operation_phase=CoreCloudRestore.OperationPhase.POLLING,
            params={
                "_bs_marker_required": True,
                "_bs_provider_name": marker,
                "_backupsheep_restore": {
                    "provider": "aws_backup",
                    "source_id": self.DDB_RECOVERY_POINT,
                    "target_kind": "dynamodb",
                    "target_name": self.DDB_RESTORE_TARGET,
                    "marker": marker,
                },
            },
        )
        table_arn = (
            "arn:aws:dynamodb:us-east-1:123456789012:table/"
            f"{self.DDB_RESTORE_TARGET}"
        )
        dynamodb = mock.MagicMock()
        dynamodb.describe_table.return_value = {
            "Table": {
                "TableName": self.DDB_RESTORE_TARGET,
                "TableArn": table_arn,
                "TableStatus": "ACTIVE",
            }
        }
        sts = mock.MagicMock()
        sts.get_caller_identity.return_value = {"Account": self.DDB_ACCOUNT_ID}
        job = {
            "RestoreJobId": restore.provider_job_id,
            "RecoveryPointArn": self.DDB_RECOVERY_POINT,
            "CreatedResourceArn": table_arn,
            "AccountId": self.DDB_ACCOUNT_ID,
            "ResourceType": "DynamoDB",
            "Status": "COMPLETED",
        }
        return node, restore, dynamodb, sts, job, table_arn

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
        backup.metadata = {
            "_aws_backup": {
                "resource_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
            }
        }
        backup.save(update_fields=["metadata", "modified"])
        describe_job.return_value = {
            "BackupJobId": "job-456",
            "ResourceArn": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table",
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
                "resource_arn": "arn:aws:s3:::source-bucket",
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
        s3.head_bucket.return_value = {}
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3.list_objects_v2.return_value = {
            "Contents": [],
            "IsTruncated": False,
        }
        s3.list_object_versions.return_value = {
            "Versions": [],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }
        s3.list_multipart_uploads.return_value = {
            "Uploads": [],
            "IsTruncated": False,
        }

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

    @mock.patch("apps._tasks.integration.aws_backup.describe_restore_job")
    def test_completed_dynamodb_restore_tags_then_verifies_before_completion(
        self, describe_restore
    ):
        node, restore, dynamodb, sts, job, table_arn = (
            self._completed_dynamodb_restore()
        )
        describe_restore.return_value = job
        expected_tags = [
            {"Key": "BackupSheepRestore", "Value": restore.restore_marker},
            {"Key": "BackupSheepSource", "Value": self.DDB_RECOVERY_POINT},
        ]
        dynamodb.list_tags_of_resource.side_effect = [
            {"Tags": []},
            {"Tags": expected_tags},
        ]

        def client(service="ec2"):
            return sts if service == "sts" else dynamodb

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=client,
        ):
            first = node.aws.check_restore(restore)
            restore.refresh_from_db()
            self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
            self.assertEqual(
                restore.params["_bs_dynamodb_tagging"]["state"],
                "submitted",
            )
            self.assertTrue(restore.params["_bs_create_outcome_unknown"])
            dynamodb.tag_resource.assert_called_once_with(
                ResourceArn=table_arn,
                Tags=expected_tags,
            )

            second = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(second, CoreCloudRestore.Status.COMPLETE)
        self.assertEqual(
            restore.params["_bs_dynamodb_tagging"]["state"],
            "verified",
        )
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(
            restore.operation_phase,
            CoreCloudRestore.OperationPhase.COMPLETE,
        )
        self.assertEqual(dynamodb.tag_resource.call_count, 1)

    @mock.patch("apps._tasks.integration.aws_backup.describe_restore_job")
    def test_dynamodb_tag_lost_response_retries_same_idempotent_tags(
        self, describe_restore
    ):
        node, restore, dynamodb, sts, job, table_arn = (
            self._completed_dynamodb_restore()
        )
        describe_restore.return_value = job
        expected_tags = [
            {"Key": "BackupSheepRestore", "Value": restore.restore_marker},
            {"Key": "BackupSheepSource", "Value": self.DDB_RECOVERY_POINT},
        ]
        dynamodb.list_tags_of_resource.side_effect = [
            {"Tags": []},
            {"Tags": []},
            {"Tags": expected_tags},
        ]
        dynamodb.tag_resource.side_effect = [TimeoutError("lost response"), None]

        def client(service="ec2"):
            return sts if service == "sts" else dynamodb

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=client,
        ):
            self.assertEqual(
                node.aws.check_restore(restore),
                CoreCloudRestore.Status.IN_PROGRESS,
            )
            restore.refresh_from_db()
            tagging = dict(restore.params["_bs_dynamodb_tagging"])
            tagging["last_attempt_at"] = "2000-01-01T00:00:00+00:00"
            restore.params["_bs_dynamodb_tagging"] = tagging
            restore.save(update_fields=["params", "modified"])

            self.assertEqual(
                node.aws.check_restore(restore),
                CoreCloudRestore.Status.IN_PROGRESS,
            )
            self.assertEqual(
                node.aws.check_restore(restore),
                CoreCloudRestore.Status.COMPLETE,
            )

        self.assertEqual(dynamodb.tag_resource.call_count, 2)
        self.assertEqual(
            dynamodb.tag_resource.call_args_list[0],
            dynamodb.tag_resource.call_args_list[1],
        )
        self.assertEqual(
            dynamodb.tag_resource.call_args.kwargs["ResourceArn"],
            table_arn,
        )

    @mock.patch("apps._tasks.integration.aws_backup.describe_restore_job")
    def test_dynamodb_conflicting_restore_tag_fails_closed(self, describe_restore):
        node, restore, dynamodb, sts, job, _table_arn = (
            self._completed_dynamodb_restore()
        )
        describe_restore.return_value = job
        dynamodb.list_tags_of_resource.return_value = {
            "Tags": [
                {"Key": "BackupSheepRestore", "Value": "another-restore"}
            ]
        }

        def client(service="ec2"):
            return sts if service == "sts" else dynamodb

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=client,
        ):
            status = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.operation_phase,
            CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
        )
        self.assertEqual(restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")
        dynamodb.tag_resource.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.describe_restore_job")
    def test_dynamodb_repeated_tag_cursor_fails_closed(self, describe_restore):
        node, restore, dynamodb, sts, job, _table_arn = (
            self._completed_dynamodb_restore()
        )
        describe_restore.return_value = job
        dynamodb.list_tags_of_resource.side_effect = [
            {"Tags": [], "NextToken": "loop"},
            {"Tags": [], "NextToken": "loop"},
        ]

        def client(service="ec2"):
            return sts if service == "sts" else dynamodb

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=client,
        ):
            status = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        dynamodb.tag_resource.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.describe_restore_job")
    def test_dynamodb_restore_rejects_wrong_job_created_resource(
        self, describe_restore
    ):
        node, restore, dynamodb, sts, job, _table_arn = (
            self._completed_dynamodb_restore()
        )
        job["CreatedResourceArn"] = (
            "arn:aws:dynamodb:us-east-1:123456789012:table/foreign-table"
        )
        describe_restore.return_value = job

        def client(service="ec2"):
            return sts if service == "sts" else dynamodb

        with mock.patch.object(
            node.connection.auth_aws,
            "get_client",
            side_effect=client,
        ):
            status = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH")
        dynamodb.list_tags_of_resource.assert_not_called()
        dynamodb.tag_resource.assert_not_called()

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
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=30)


class AWSDeletionRecoveryTests(BaseTestCase):
    account_id = "123456789012"

    def _node(
        self,
        *,
        node_type=CoreNode.Type.CLOUD,
        resource_type="instance",
        unique_id=None,
    ):
        connection = factories.make_connection(self.account, self.member, code="aws")
        key = self.account.get_encryption_key()
        auth = CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
            backup_vault_name="test-vault",
            backup_role_arn=(
                "arn:aws:iam::123456789012:role/BackupSheepTest"
            ),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=node_type,
            name="aws-source",
            added_by=self.member,
        )
        aws = CoreAWS.objects.create(
            node=node,
            name="aws-source",
            unique_id=(
                unique_id
                or ("vol-source" if node_type == CoreNode.Type.VOLUME else "i-source")
            ),
            resource_type=resource_type,
        )
        return node, aws, auth

    @staticmethod
    def _client_error(code, operation):
        return ClientError(
            {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 404}},
            operation,
        )

    def _client_patch(self, auth, ec2, sts=None, backup_client=None):
        sts = sts or mock.MagicMock()
        sts.get_caller_identity.return_value = {"Account": self.account_id}

        def get_client(_auth, service="ec2"):
            if service == "sts":
                return sts
            if service == "backup" and backup_client is not None:
                return backup_client
            return ec2

        return mock.patch.object(
            CoreAuthAWS,
            "get_client",
            autospec=True,
            side_effect=get_client,
        )

    def test_ami_child_deletion_resumes_after_lost_response(self):
        _node, aws, auth = self._node()
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid="ami-backup-marker",
            unique_id="ami-owned",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        ec2 = mock.MagicMock()
        ec2.describe_images.return_value = {
            "Images": [
                {
                    "ImageId": "ami-owned",
                    "Name": "ami-backup-marker",
                    "Description": "ami-backup-marker",
                    "OwnerId": self.account_id,
                    "BlockDeviceMappings": [
                        {"Ebs": {"SnapshotId": "snap-child-1"}},
                        {"Ebs": {"SnapshotId": "snap-child-2"}},
                    ],
                }
            ]
        }
        ec2.describe_snapshots.side_effect = [
            {"Snapshots": [{"SnapshotId": "snap-child-1", "OwnerId": self.account_id}]},
            {"Snapshots": [{"SnapshotId": "snap-child-2", "OwnerId": self.account_id}]},
        ]
        ec2.delete_snapshot.side_effect = [None, TimeoutError("lost response")]

        with self._client_patch(auth, ec2), mock.patch(
            "apps.console.backup.models.time.sleep"
        ) as sleep:
            self.assertFalse(backup.soft_delete())

        sleep.assert_not_called()
        backup.refresh_from_db()
        state = backup.metadata["_aws_delete"]
        self.assertEqual(state["children"]["snap-child-1"]["status"], "deleted")
        self.assertEqual(
            state["children"]["snap-child-2"]["status"],
            "delete_outcome_unknown",
        )
        self.assertTrue(state["image_deregistered"])
        self.assertNotIn("lease_token", state)
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        ec2.deregister_image.assert_called_once_with(ImageId="ami-owned")

        retry_ec2 = mock.MagicMock()
        retry_ec2.describe_snapshots.side_effect = self._client_error(
            "InvalidSnapshot.NotFound", "DescribeSnapshots"
        )
        with self._client_patch(auth, retry_ec2):
            result = backup.soft_delete()

        backup.refresh_from_db()
        self.assertTrue(
            result,
            (backup.status, backup.metadata.get("_aws_delete")),
        )

        retry_ec2.describe_images.assert_not_called()
        retry_ec2.deregister_image.assert_not_called()
        retry_ec2.delete_snapshot.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)
        self.assertEqual(
            backup.metadata["_aws_delete"]["children"]["snap-child-2"]["status"],
            "deleted",
        )

    def test_live_delete_lease_blocks_duplicate_worker(self):
        _node, aws, _auth = self._node()
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid="leased-delete",
            unique_id="ami-leased",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        state, token = backup._claim_aws_delete_lease()

        self.assertFalse(backup.soft_delete())
        backup.refresh_from_db()
        self.assertEqual(
            backup.metadata["_aws_delete"]["lease_token"],
            token,
        )
        backup._checkpoint_aws_delete(state, token, release=True)

    def test_ebs_delete_rejects_missing_source_identity(self):
        _node, aws, auth = self._node(
            node_type=CoreNode.Type.VOLUME,
            resource_type=CoreAWS.ResourceType.VOLUME,
        )
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid="ebs-marker",
            unique_id="snap-owned",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        ec2 = mock.MagicMock()
        ec2.describe_snapshots.return_value = {
            "Snapshots": [
                {
                    "SnapshotId": "snap-owned",
                    "Description": "ebs-marker",
                    "OwnerId": self.account_id,
                    # Deliberately no VolumeId.
                }
            ]
        }

        with self._client_patch(auth, ec2):
            self.assertFalse(backup.soft_delete())

        ec2.delete_snapshot.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_FAILED)
        self.assertEqual(
            backup.get_execution_state().last_error_code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

    def test_recovery_point_lost_response_is_adopted_without_second_delete(self):
        _node, aws, auth = self._node(
            resource_type=CoreAWS.ResourceType.S3,
            unique_id="source-bucket",
        )
        recovery_arn = "arn:aws:backup:us-east-1:123456789012:recovery-point/rp-1"
        resource_arn = "arn:aws:s3:::source-bucket"
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid="s3-delete-marker",
            unique_id="job-1",
            status=UtilBackup.Status.DELETE_REQUESTED,
            metadata={
                "_aws_backup": {
                    "recovery_point_arn": recovery_arn,
                    "resource_arn": resource_arn,
                    "vault_name": "test-vault",
                }
            },
        )
        first = mock.MagicMock()
        first.describe_recovery_point.return_value = {
            "RecoveryPointArn": recovery_arn,
            "ResourceArn": resource_arn,
        }
        first.delete_recovery_point.side_effect = TimeoutError("lost response")
        with self._client_patch(auth, mock.MagicMock(), backup_client=first):
            self.assertFalse(backup.soft_delete())

        backup.refresh_from_db()
        self.assertTrue(backup.metadata["_aws_delete"]["delete_started"])
        second = mock.MagicMock()
        second.describe_recovery_point.side_effect = self._client_error(
            "ResourceNotFoundException", "DescribeRecoveryPoint"
        )
        with self._client_patch(auth, mock.MagicMock(), backup_client=second):
            result = backup.soft_delete()

        backup.refresh_from_db()
        self.assertTrue(
            result,
            (backup.status, backup.metadata.get("_aws_delete")),
        )

        second.delete_recovery_point.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_COMPLETED)

    def test_unproven_not_found_never_becomes_delete_success(self):
        _node, aws, auth = self._node(
            node_type=CoreNode.Type.VOLUME,
            resource_type=CoreAWS.ResourceType.VOLUME,
        )
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid="unproven-delete",
            unique_id="snap-absent",
            status=UtilBackup.Status.DELETE_REQUESTED,
        )
        ec2 = mock.MagicMock()
        ec2.describe_snapshots.side_effect = self._client_error(
            "InvalidSnapshot.NotFound", "DescribeSnapshots"
        )
        with self._client_patch(auth, ec2):
            self.assertFalse(backup.soft_delete())

        ec2.delete_snapshot.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(
            backup.status,
            UtilBackup.Status.DELETE_FAILED_NOT_FOUND,
        )


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
        client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-db",
                    "DBInstanceArn": (
                        "arn:aws:rds:us-east-1:123456789012:db:test-db"
                    ),
                    "DbiResourceId": "db-resource-test-db",
                    "DBInstanceClass": "db.t3.micro",
                    "DBSubnetGroup": {"DBSubnetGroupName": "test-subnet"},
                    "VpcSecurityGroups": [
                        {"VpcSecurityGroupId": "sg-0123456789abcdef0"}
                    ],
                    "MultiAZ": False,
                    "PubliclyAccessible": False,
                    "StorageType": "gp3",
                    "Iops": 3000,
                    "StorageThroughput": 125,
                }
            ]
        }
        client.describe_db_snapshots.side_effect = ClientError(
            {"Error": {"Code": "DBSnapshotNotFound"}},
            "DescribeDBSnapshots",
        )
        client.create_db_snapshot.return_value = {
            "DBSnapshot": {
                "DBSnapshotIdentifier": "rds-backup",
                "DBInstanceIdentifier": "test-db",
                "DbiResourceId": "db-resource-test-db",
                "DBSnapshotArn": (
                    "arn:aws:rds:us-east-1:123456789012:snapshot:rds-backup"
                ),
                "SnapshotType": "manual",
                "AllocatedStorage": 20,
                "Status": "creating",
                "SnapshotCreateTime": datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
            }
        }
        client.list_tags_for_resource.return_value = {
            "TagList": [
                {
                    "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                    "Value": CoreAWSRDSBackup._rds_ownership_marker(
                        identifier="rds-backup",
                        source_id="test-db",
                        region="us-east-1",
                        source_node_id=node.id,
                        source_resource_id=node.aws_rds.id,
                    ),
                }
            ]
        }

        with mock.patch.object(
            CoreAWSRDSBackup, "_rds_account_id", return_value="123456789012"
        ), mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
            node.aws_rds.create_snapshot(backup)

        backup.refresh_from_db()
        self.assertEqual(backup.unique_id, "rds-backup")
        request = client.create_db_snapshot.call_args.kwargs
        self.assertEqual(request["DBSnapshotIdentifier"], "rds-backup")
        self.assertEqual(request["DBInstanceIdentifier"], "test-db")
        self.assertEqual(
            request["Tags"][0]["Key"],
            CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
        )
        self.assertRegex(request["Tags"][0]["Value"], r"^bs-rds-[0-9a-f]{64}$")

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
        snapshot_time = datetime.now(timezone.utc)
        backup._rds_persist_witness(
            backup._rds_witness(
                identifier="rds-poll-backup",
                source_id="test-db-poll",
                account_id="123456789012",
                region="us-east-1",
                source_node_id=node.id,
                source_resource_id=node.aws_rds.id,
                snapshot_create_time=snapshot_time,
            )
        )
        client = mock.MagicMock()
        client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "rds-poll-backup",
                    "DBInstanceIdentifier": "test-db-poll",
                    "DbiResourceId": "db-resource-test-db-poll",
                    "DBSnapshotArn": (
                        "arn:aws:rds:us-east-1:123456789012:"
                        "snapshot:rds-poll-backup"
                    ),
                    "SnapshotType": "manual",
                    "AllocatedStorage": 20,
                    "Status": "available",
                    "SnapshotCreateTime": snapshot_time,
                }
            ]
        }
        client.list_tags_for_resource.return_value = {
            "TagList": [
                {
                    "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                    "Value": CoreAWSRDSBackup._rds_ownership_marker(
                        identifier="rds-poll-backup",
                        source_id="test-db-poll",
                        region="us-east-1",
                        source_node_id=node.id,
                        source_resource_id=node.aws_rds.id,
                    ),
                }
            ]
        }

        with mock.patch.object(
            CoreAWSRDSBackup,
            "_rds_account_id",
            return_value="123456789012",
        ), mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
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
        client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-db-retry",
                    "DBInstanceArn": (
                        "arn:aws:rds:us-east-1:123456789012:db:test-db-retry"
                    ),
                    "DbiResourceId": "db-resource-test-db-retry",
                    "DBInstanceClass": "db.t3.micro",
                    "DBSubnetGroup": {"DBSubnetGroupName": "test-subnet"},
                    "VpcSecurityGroups": [
                        {"VpcSecurityGroupId": "sg-0123456789abcdef0"}
                    ],
                    "MultiAZ": False,
                    "PubliclyAccessible": False,
                    "StorageType": "gp3",
                    "Iops": 3000,
                    "StorageThroughput": 125,
                }
            ]
        }
        client.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "rds-retry-backup",
                    "DBInstanceIdentifier": "test-db-retry",
                    "DbiResourceId": "db-resource-test-db-retry",
                    "DBSnapshotArn": (
                        "arn:aws:rds:us-east-1:123456789012:"
                        "snapshot:rds-retry-backup"
                    ),
                    "SnapshotType": "manual",
                    "AllocatedStorage": 20,
                    "Status": "creating",
                    "SnapshotCreateTime": datetime.now(timezone.utc),
                }
            ]
        }
        client.list_tags_for_resource.return_value = {
            "TagList": [
                {
                    "Key": CoreAWSRDSBackup._RDS_SNAPSHOT_OWNERSHIP_TAG_KEY,
                    "Value": CoreAWSRDSBackup._rds_ownership_marker(
                        identifier="rds-retry-backup",
                        source_id="test-db-retry",
                        region="us-east-1",
                        source_node_id=node.id,
                        source_resource_id=node.aws_rds.id,
                    ),
                }
            ]
        }

        with mock.patch.object(
            CoreAWSRDSBackup, "_rds_account_id", return_value="123456789012"
        ), mock.patch.object(CoreAuthAWSRDS, "get_client", return_value=client):
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
        poll.assert_called_once_with(args=[node.id, restore.id], countdown=30)
