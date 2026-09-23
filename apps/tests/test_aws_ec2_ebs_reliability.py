"""Crash-safe reconciliation tests for native AWS EC2 and EBS backups."""

from datetime import timedelta
from unittest import mock

from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps._tasks.integration.aws import backup_aws
from apps.console.backup.models import (
    AWSDeleteLeaseLost,
    AWSNativeLeaseLost,
    CoreAWSBackup,
    CoreBackupExecution,
)
from apps.console.connection.models import CoreAuthAWS, CoreAWSRegion, CoreConnection
from apps.console.node.models import CoreAWS, CoreNode
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class AWSNativeEC2EBSReliabilityTests(BaseTestCase):
    """Verify the durable witness, lease, and reconciliation protocol.

    These tests intentionally mock only the AWS clients.  No provider resources
    are created; the state machine is exercised with the same response shapes
    returned by EC2's native APIs.
    """

    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"

    def _make_backup(
        self,
        kind,
        *,
        suffix,
        status=UtilBackup.Status.IN_PROGRESS,
        unique_id="",
    ):
        is_instance = kind == "instance"
        connection = factories.make_connection(
            self.account,
            self.member,
            code="aws",
            name=f"aws-reliability-{suffix}",
        )
        key = self.account.get_encryption_key()
        CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code=self.REGION),
            access_key=bs_encrypt("access", key),
            secret_key=bs_encrypt("secret", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD if is_instance else CoreNode.Type.VOLUME,
            name=f"aws-source-{suffix}",
            added_by=self.member,
        )
        source_id = f"{'i' if is_instance else 'vol'}-source-{suffix}"
        aws = CoreAWS.objects.create(
            node=node,
            name=f"aws-resource-{suffix}",
            unique_id=source_id,
            resource_type=(
                CoreAWS.ResourceType.INSTANCE
                if is_instance
                else CoreAWS.ResourceType.VOLUME
            ),
        )
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid=f"bs-aws-native-{suffix}",
            unique_id=unique_id,
            status=status,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        return backup, aws, connection.auth_aws

    @classmethod
    def _tags(cls, marker, source_id, *, account=None, region=None, source_type=None):
        return [
            {"Key": "BackupSheepBackup", "Value": marker},
            {"Key": "BackupSheepSourceId", "Value": str(source_id)},
            {
                "Key": "BackupSheepSourceType",
                "Value": source_type or "instance",
            },
            {"Key": "BackupSheepAccountId", "Value": account or cls.ACCOUNT_ID},
            {"Key": "BackupSheepRegion", "Value": region or cls.REGION},
        ]

    @classmethod
    def _resource(
        cls,
        kind,
        marker,
        source_id,
        *,
        resource_id=None,
        account=None,
        region=None,
        state=None,
        tags=None,
    ):
        account = account or cls.ACCOUNT_ID
        region = region or cls.REGION
        is_instance = kind == "instance"
        tags = tags if tags is not None else cls._tags(
            marker,
            source_id,
            account=account,
            region=region,
            source_type=kind,
        )
        if is_instance:
            return {
                "ImageId": resource_id or f"ami-{marker}",
                "Name": marker,
                "Description": marker,
                "OwnerId": account,
                "Region": region,
                "State": state or "pending",
                "Tags": tags,
                "BlockDeviceMappings": [
                    {"Ebs": {"SnapshotId": f"snap-child-{marker}", "VolumeSize": 8}}
                ],
            }
        return {
            "SnapshotId": resource_id or f"snap-{marker}",
            "Description": marker,
            "OwnerId": account,
            "Region": region,
            "AvailabilityZone": f"{region}a",
            "State": state or "completed",
            "VolumeId": source_id,
            "VolumeSize": 8,
            "Tags": tags,
        }

    @staticmethod
    def _source_response(kind, source_id, *, account=None, region=None):
        account = account or AWSNativeEC2EBSReliabilityTests.ACCOUNT_ID
        region = region or AWSNativeEC2EBSReliabilityTests.REGION
        if kind == "instance":
            return {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": source_id,
                                "OwnerId": account,
                                "InstanceType": "t3.micro",
                                "SubnetId": "subnet-0123456789abcdef0",
                                "SecurityGroups": [
                                    {"GroupId": "sg-0123456789abcdef0"}
                                ],
                                "KeyName": "backup-restore-key",
                                "Placement": {"AvailabilityZone": f"{region}a"},
                                "State": {"Name": "running"},
                            }
                        ]
                    }
                ]
            }
        return {
            "Volumes": [
                {
                    "VolumeId": source_id,
                    "OwnerId": account,
                    "AvailabilityZone": f"{region}a",
                    "State": "available",
                }
            ]
        }

    @staticmethod
    def _client_patch(auth, ec2, sts=None):
        sts = sts or mock.MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": AWSNativeEC2EBSReliabilityTests.ACCOUNT_ID
        }

        def get_client(_auth, service_name="ec2"):
            return sts if service_name == "sts" else ec2

        return mock.patch.object(
            CoreAuthAWS,
            "get_client",
            autospec=True,
            side_effect=get_client,
        )

    @staticmethod
    def _api_methods(kind):
        if kind == "instance":
            return "describe_instances", "describe_images", "create_image"
        return "describe_volumes", "describe_snapshots", "create_snapshot"

    @staticmethod
    def _collection_response(kind, resources, **extra):
        response = {
            "Images" if kind == "instance" else "Snapshots": resources,
        }
        response.update(extra)
        return response

    def _configure_source(self, client, kind, source_id):
        source_method, _list_method, _create_method = self._api_methods(kind)
        getattr(client, source_method).return_value = self._source_response(
            kind, source_id
        )

    @staticmethod
    def _expire_create_lease(backup):
        state = backup.get_execution_state(create=False)
        state.lease_expires_at = timezone.now() - timedelta(seconds=1)
        state.save(update_fields=["lease_expires_at", "modified"])

    def test_lost_create_response_is_adopted_without_duplicate_ami_or_snapshot(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"lost-{kind}"
                )
                client = mock.MagicMock()
                self._configure_source(client, kind, aws.unique_id)
                source_method, list_method, create_method = self._api_methods(kind)
                getattr(client, source_method).side_effect = [
                    self._source_response(kind, aws.unique_id),
                    AssertionError(
                        "a durable retry must not require the deleted source"
                    ),
                ]
                resource = self._resource(
                    kind,
                    backup.uuid_str,
                    aws.unique_id,
                    resource_id=(
                        f"ami-adopt-{kind}"
                        if kind == "instance"
                        else f"snap-adopt-{kind}"
                    ),
                )
                getattr(client, list_method).side_effect = [
                    self._collection_response(kind, []),
                    self._collection_response(kind, [resource]),
                ]
                getattr(client, create_method).side_effect = TimeoutError(
                    "provider accepted the request but the response was lost"
                )

                with self._client_patch(auth, client):
                    with self.assertRaises(TimeoutError):
                        backup.create_snapshot(task_id=f"lost-worker-{kind}")

                backup.refresh_from_db()
                first_state = backup.get_execution_state(create=False)
                self.assertEqual(
                    first_state.reconciliation_state,
                    CoreBackupExecution.ReconciliationState.REQUIRED,
                )
                self.assertEqual(
                    first_state.last_error_code,
                    "PROVIDER_CREATE_OUTCOME_UNKNOWN",
                )

                self._expire_create_lease(backup)
                with self._client_patch(auth, client):
                    backup.create_snapshot(task_id=f"adopter-{kind}")

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                self.assertEqual(backup.unique_id, resource["ImageId"] if kind == "instance" else resource["SnapshotId"])
                self.assertEqual(
                    state.reconciliation_state,
                    CoreBackupExecution.ReconciliationState.RESOLVED,
                )
                self.assertTrue(state.provider_metadata["adopted"])
                getattr(client, create_method).assert_called_once()
                getattr(client, source_method).assert_called_once()

    def test_native_backup_persists_source_restore_configuration(self):
        backup, aws, auth = self._make_backup(
            "instance", suffix="source-configuration"
        )
        client = mock.MagicMock()
        self._configure_source(client, "instance", aws.unique_id)
        resource = self._resource(
            "instance",
            backup.uuid_str,
            aws.unique_id,
            resource_id="ami-source-configuration",
            state="available",
        )
        client.describe_images.side_effect = [
            self._collection_response("instance", []),
            self._collection_response("instance", [resource]),
        ]
        client.create_image.return_value = {
            "ImageId": "ami-source-configuration"
        }

        with self._client_patch(auth, client):
            backup.create_snapshot(task_id="source-configuration-worker")

        state = backup.get_execution_state(create=False)
        self.assertEqual(
            state.provider_metadata["source_configuration"],
            {
                "schema": 1,
                "source_type": "instance",
                "source_id": aws.unique_id,
                "instance_type": "t3.micro",
                "subnet_id": "subnet-0123456789abcdef0",
                "security_group_ids": ["sg-0123456789abcdef0"],
                "key_name": "backup-restore-key",
            },
        )

    def test_celery_entry_point_uses_backup_row_durable_protocol(self):
        backup, aws, _auth = self._make_backup(
            "instance", suffix="durable-entry"
        )
        backup.celery_task_id = "aws-durable-entry"
        backup.save(update_fields=["celery_task_id", "modified"])

        def create_durably(current, task_id=None):
            current.unique_id = "ami-durable-entry"
            current.save(update_fields=["unique_id", "modified"])
            return current

        with mock.patch.object(
            CoreConnection, "validate", return_value=True
        ), mock.patch.object(
            CoreNode, "validate", return_value=True
        ), mock.patch.object(
            CoreNode, "backup_initiate", return_value=backup
        ), mock.patch.object(
            CoreAWSBackup,
            "create_snapshot",
            autospec=True,
            side_effect=create_durably,
        ) as durable_create, mock.patch(
            "apps._tasks.helper.tasks.poll_cloud_backup.apply_async"
        ) as poll:
            result = backup_aws.apply(
                kwargs={
                    "node_id": aws.node_id,
                    "schedule_id": None,
                    "storage_ids": None,
                    "notes": None,
                },
                task_id="aws-durable-entry",
                throw=True,
            )

        self.assertTrue(result.successful())
        durable_create.assert_called_once()
        self.assertEqual(
            durable_create.call_args.kwargs["task_id"], "aws-durable-entry"
        )
        poll.assert_called_once_with(args=[aws.node_id, backup.id], countdown=60)

    def test_exact_duplicate_matches_fail_closed_for_ami_and_ebs(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"duplicate-{kind}"
                )
                client = mock.MagicMock()
                self._configure_source(client, kind, aws.unique_id)
                _source_method, list_method, create_method = self._api_methods(kind)
                resources = [
                    self._resource(
                        kind,
                        backup.uuid_str,
                        aws.unique_id,
                        resource_id=f"{'ami' if kind == 'instance' else 'snap'}-duplicate-{n}",
                    )
                    for n in (1, 2)
                ]
                getattr(client, list_method).return_value = self._collection_response(
                    kind, resources
                )

                with self._client_patch(auth, client):
                    backup.create_snapshot(task_id=f"duplicate-worker-{kind}")

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                self.assertEqual(backup.status, UtilBackup.Status.FAILED)
                self.assertEqual(
                    state.last_error_code, "PROVIDER_DUPLICATE_MATCH"
                )
                self.assertEqual(
                    state.reconciliation_state,
                    CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
                )
                getattr(client, create_method).assert_not_called()

    def test_next_token_pagination_adopts_exact_match_for_ami_and_ebs(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"pagination-{kind}"
                )
                client = mock.MagicMock()
                self._configure_source(client, kind, aws.unique_id)
                _source_method, list_method, create_method = self._api_methods(kind)
                resource = self._resource(
                    kind, backup.uuid_str, aws.unique_id, resource_id=f"page-{kind}"
                )
                getattr(client, list_method).side_effect = [
                    {"Images": [], "NextToken": "page-2"}
                    if kind == "instance"
                    else {"Snapshots": [], "NextToken": "page-2"},
                    {"Images": [resource]}
                    if kind == "instance"
                    else {"Snapshots": [resource]},
                ]

                with self._client_patch(auth, client):
                    backup.create_snapshot(task_id=f"pagination-worker-{kind}")

                self.assertEqual(getattr(client, list_method).call_count, 2)
                self.assertEqual(
                    getattr(client, list_method).call_args_list[1].kwargs[
                        "NextToken"
                    ],
                    "page-2",
                )
                getattr(client, create_method).assert_not_called()
                backup.refresh_from_db()
                self.assertNotEqual(backup.unique_id, "")

    def test_repeated_next_token_is_manual_review_and_never_creates(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"repeated-token-{kind}"
                )
                client = mock.MagicMock()
                self._configure_source(client, kind, aws.unique_id)
                _source_method, list_method, create_method = self._api_methods(kind)
                getattr(client, list_method).side_effect = [
                    {"Images": [], "NextToken": "loop-token"}
                    if kind == "instance"
                    else {"Snapshots": [], "NextToken": "loop-token"},
                    {"Images": [], "NextToken": "loop-token"}
                    if kind == "instance"
                    else {"Snapshots": [], "NextToken": "loop-token"},
                ]

                with self._client_patch(auth, client):
                    backup.create_snapshot(task_id=f"repeated-token-worker-{kind}")

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                self.assertEqual(backup.status, UtilBackup.Status.FAILED)
                self.assertEqual(
                    state.last_error_code, "PROVIDER_MALFORMED_RESPONSE"
                )
                self.assertEqual(
                    state.reconciliation_state,
                    CoreBackupExecution.ReconciliationState.MANUAL_REVIEW,
                )
                getattr(client, create_method).assert_not_called()

    def _poll_mismatch_resource(self, kind, backup, aws, mismatch):
        resource = self._resource(
            kind,
            backup.uuid_str,
            aws.unique_id,
            resource_id=f"poll-{kind}-{mismatch}",
            state="available" if kind == "instance" else "completed",
        )
        if mismatch == "account":
            resource["OwnerId"] = "999999999999"
        elif mismatch == "region":
            if kind == "instance":
                resource["Region"] = "us-west-2"
            else:
                resource["AvailabilityZone"] = "us-west-2a"
                resource["Region"] = "us-west-2"
        elif mismatch == "source":
            if kind == "instance":
                for tag in resource["Tags"]:
                    if tag["Key"] == "BackupSheepSourceId":
                        tag["Value"] = "i-foreign-source"
            else:
                resource["VolumeId"] = "vol-foreign-source"
        elif mismatch == "tag":
            for tag in resource["Tags"]:
                if tag["Key"] == "BackupSheepBackup":
                    tag["Value"] = "bs-foreign-backup"
        else:
            raise AssertionError(f"unknown mismatch: {mismatch}")
        return resource

    def test_account_region_source_and_tag_mismatches_block_polling(self):
        for kind in ("instance", "volume"):
            for mismatch in ("account", "region", "source", "tag"):
                with self.subTest(kind=kind, mismatch=mismatch):
                    backup, aws, auth = self._make_backup(
                        kind,
                        suffix=f"poll-{kind}-{mismatch}",
                    )
                    client = mock.MagicMock()
                    self._configure_source(client, kind, aws.unique_id)
                    _source_method, list_method, _create_method = self._api_methods(
                        kind
                    )
                    resource = self._poll_mismatch_resource(
                        kind, backup, aws, mismatch
                    )
                    getattr(client, list_method).return_value = self._collection_response(
                        kind, [resource]
                    )

                    with self._client_patch(auth, client):
                        result = backup.poll_status()

                    backup.refresh_from_db()
                    state = backup.get_execution_state(create=False)
                    self.assertEqual(result, UtilBackup.Status.FAILED)
                    self.assertEqual(backup.status, UtilBackup.Status.FAILED)
                    self.assertEqual(
                        state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                    )
                    client.deregister_image.assert_not_called()
                    client.delete_snapshot.assert_not_called()

    def test_account_region_source_and_tag_mismatches_block_deletion(self):
        for kind in ("instance", "volume"):
            for mismatch in ("account", "region", "source", "tag"):
                with self.subTest(kind=kind, mismatch=mismatch):
                    provider_id = (
                        f"ami-delete-{kind}-{mismatch}"
                        if kind == "instance"
                        else f"snap-delete-{kind}-{mismatch}"
                    )
                    backup, aws, auth = self._make_backup(
                        kind,
                        suffix=f"delete-{kind}-{mismatch}",
                        status=UtilBackup.Status.DELETE_REQUESTED,
                        unique_id=provider_id,
                    )
                    client = mock.MagicMock()
                    resource = self._resource(
                        kind,
                        backup.uuid_str,
                        aws.unique_id,
                        resource_id=provider_id,
                    )
                    if mismatch == "account":
                        resource["OwnerId"] = "999999999999"
                    elif mismatch == "region":
                        if kind == "instance":
                            resource["Region"] = "us-west-2"
                        else:
                            resource["AvailabilityZone"] = "us-west-2a"
                            resource["Region"] = "us-west-2"
                    elif mismatch == "source":
                        if kind == "instance":
                            for tag in resource["Tags"]:
                                if tag["Key"] == "BackupSheepSourceId":
                                    tag["Value"] = "i-foreign-source"
                        else:
                            resource["VolumeId"] = "vol-foreign-source"
                    elif mismatch == "tag":
                        for tag in resource["Tags"]:
                            if tag["Key"] == "BackupSheepBackup":
                                tag["Value"] = "bs-foreign-backup"
                    else:
                        raise AssertionError(f"unknown mismatch: {mismatch}")

                    _source_method, list_method, _create_method = self._api_methods(
                        kind
                    )
                    getattr(client, list_method).return_value = (
                        {"Images": [resource]}
                        if kind == "instance"
                        else {"Snapshots": [resource]}
                    )

                    with self._client_patch(auth, client):
                        result = backup.soft_delete()

                    backup.refresh_from_db()
                    state = backup.get_execution_state(create=False)
                    self.assertFalse(result)
                    self.assertEqual(backup.status, UtilBackup.Status.DELETE_FAILED)
                    self.assertEqual(
                        state.last_error_code, "PROVIDER_OWNERSHIP_MISMATCH"
                    )
                    client.deregister_image.assert_not_called()
                    client.delete_snapshot.assert_not_called()

    def test_request_timeout_is_retryable_and_does_not_create(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"timeout-{kind}"
                )
                client = mock.MagicMock()
                source_method, _list_method, create_method = self._api_methods(kind)
                getattr(client, source_method).side_effect = TimeoutError(
                    "bounded AWS request timed out"
                )

                with self._client_patch(auth, client):
                    with self.assertRaises(TimeoutError):
                        backup.create_snapshot(task_id=f"timeout-worker-{kind}")

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)
                self.assertEqual(state.last_error_code, "PROVIDER_TIMEOUT")
                self.assertIsNotNone(state.next_retry_at)
                getattr(client, create_method).assert_not_called()

    def test_poll_request_timeout_remains_in_progress(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                backup, aws, auth = self._make_backup(
                    kind, suffix=f"poll-timeout-{kind}"
                )
                client = mock.MagicMock()
                self._configure_source(client, kind, aws.unique_id)
                _source_method, list_method, _create_method = self._api_methods(kind)
                getattr(client, list_method).side_effect = TimeoutError(
                    "read timeout while reconciling AWS"
                )

                with self._client_patch(auth, client):
                    result = backup.poll_status()

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                self.assertEqual(result, UtilBackup.Status.IN_PROGRESS)
                self.assertEqual(backup.status, UtilBackup.Status.IN_PROGRESS)
                self.assertEqual(state.last_error_code, "PROVIDER_TIMEOUT")
                self.assertIsNotNone(state.next_retry_at)

    def test_stale_create_fence_cannot_persist_provider_id(self):
        backup, aws, _auth = self._make_backup(
            "instance", suffix="stale-create-fence"
        )
        old_owner, old_token, _created = backup._aws_native_create_lease("old-worker")
        self._expire_create_lease(backup)
        new_owner, new_token, _created = backup._aws_native_create_lease("new-worker")
        self.assertNotEqual(old_token, new_token)

        witness = backup._aws_native_witness(
            marker=backup.uuid_str,
            provider="aws_ec2",
            source_id=aws.unique_id,
            source_type="instance",
            account_id=self.ACCOUNT_ID,
            region=self.REGION,
        )
        with self.assertRaises(AWSNativeLeaseLost):
            backup._aws_native_persist_provider_id(
                "ami-stale-worker",
                witness,
                owner=old_owner,
                token=old_token,
            )

        backup.refresh_from_db()
        state = backup.get_execution_state(create=False)
        self.assertEqual(str(state.lease_token), new_token)
        self.assertEqual(state.provider_resource_id, "")

    def test_stale_delete_fence_cannot_checkpoint_or_issue_delete(self):
        provider_id = "snap-stale-delete-fence"
        backup, _aws, _auth = self._make_backup(
            "volume",
            suffix="stale-delete-fence",
            status=UtilBackup.Status.DELETE_REQUESTED,
            unique_id=provider_id,
        )
        old_state, old_token = backup._claim_aws_delete_lease()
        backup.refresh_from_db()
        metadata = dict(backup.metadata or {})
        metadata["_aws_delete"]["lease_expires_at"] = timezone.now().timestamp() - 1
        backup.metadata = metadata
        backup.save(update_fields=["metadata", "modified"])
        _new_state, new_token = backup._claim_aws_delete_lease()
        self.assertNotEqual(old_token, new_token)

        with self.assertRaises(AWSDeleteLeaseLost):
            backup._checkpoint_aws_delete(old_state, old_token)

        backup.refresh_from_db()
        self.assertEqual(
            backup.metadata["_aws_delete"]["lease_token"],
            new_token,
        )

    def test_ambiguous_delete_response_is_reconciled_without_second_mutation(self):
        for kind in ("instance", "volume"):
            with self.subTest(kind=kind):
                provider_id = (
                    f"ami-ambiguous-{kind}"
                    if kind == "instance"
                    else f"snap-ambiguous-{kind}"
                )
                backup, aws, auth = self._make_backup(
                    kind,
                    suffix=f"ambiguous-delete-{kind}",
                    status=UtilBackup.Status.DELETE_REQUESTED,
                    unique_id=provider_id,
                )
                client = mock.MagicMock()
                resource = self._resource(
                    kind,
                    backup.uuid_str,
                    aws.unique_id,
                    resource_id=provider_id,
                )
                _source_method, list_method, _create_method = self._api_methods(kind)
                response_key = "Images" if kind == "instance" else "Snapshots"
                getattr(client, list_method).side_effect = [
                    {response_key: [resource]},
                    {response_key: [resource]},
                ]
                mutation_method = (
                    "deregister_image" if kind == "instance" else "delete_snapshot"
                )
                getattr(client, mutation_method).side_effect = TimeoutError(
                    "provider accepted delete but response was lost"
                )

                with self._client_patch(auth, client):
                    self.assertFalse(backup.soft_delete())
                    self.assertFalse(backup.soft_delete())

                backup.refresh_from_db()
                state = backup.get_execution_state(create=False)
                delete_state = backup.metadata["_aws_delete"]
                self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
                self.assertEqual(
                    state.last_error_code,
                    "PROVIDER_RECONCILIATION_REQUIRED",
                )
                self.assertEqual(delete_state["phase"], "delete_outcome_unknown")
                getattr(client, mutation_method).assert_called_once()
