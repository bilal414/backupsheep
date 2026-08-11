"""Focused safety tests for native AWS Backup S3 restore destinations."""

import json
from unittest import mock

from botocore.exceptions import ClientError
from botocore.session import get_session
from botocore.stub import Stubber

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthAWS, CoreAWSRegion
from apps.console.node.models import CoreAWS, CoreNode, _aws_backup_restore_identity
from apps.console.utils.models import UtilBackup
from apps._tasks.integration.aws_backup import idempotency_token
from apps.tests import factories
from apps.tests.base import BaseTestCase


class AWSS3RestoreDestinationSafetyTests(BaseTestCase):
    def _fixture(self, *, destination="restore-bucket", params=None):
        connection = factories.make_connection(self.account, self.member, code="aws")
        key = self.account.get_encryption_key()
        auth = CoreAuthAWS.objects.create(
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
            name="s3-source-node",
            added_by=self.member,
        )
        aws = CoreAWS.objects.create(
            node=node,
            name="source-bucket",
            unique_id="source-bucket",
            resource_type=CoreAWS.ResourceType.S3,
        )
        backup = aws.backups.create(
            uuid="s3-restore-safety-backup",
            unique_id="backup-job-1",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            metadata={
                "_aws_backup": {
                    "resource_arn": "arn:aws:s3:::source-bucket",
                    "recovery_point_arn": (
                        "arn:aws:backup:us-east-1:123456789012:"
                        "recovery-point/rp-1"
                    ),
                }
            },
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="s3-safety-restore",
            params=params or {"destination_bucket_name": destination},
        )
        s3 = mock.MagicMock()
        backup_client = mock.MagicMock()
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
        return node, aws, backup, restore, auth, s3, backup_client

    @staticmethod
    def _client_patch(auth, s3, backup_client):
        return mock.patch.object(
            auth,
            "get_client",
            side_effect=lambda service="ec2": (
                backup_client if service == "backup" else s3
            ),
        )

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_source_bucket_is_rejected_before_any_provider_mutation(
        self, start_restore
    ):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture(
            destination="source-bucket"
        )

        with self._client_patch(auth, s3, backup_client), self.assertRaises(ValueError):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.params["_bs_s3_restore_preflight"]["reason"], "source_bucket"
        )
        self.assertNotIn("source-bucket", restore.error)
        s3.head_bucket.assert_not_called()
        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_each_non_empty_destination_category_is_terminal_and_non_mutating(
        self, start_restore
    ):
        categories = (
            ("current_objects", "objects"),
            ("noncurrent_versions", "versions"),
            ("delete_markers", "delete_markers"),
            ("multipart_uploads", "uploads"),
        )
        for reason, category in categories:
            with self.subTest(reason=reason):
                node, _aws, backup, restore, auth, s3, backup_client = self._fixture(
                    destination=f"restore-{reason}"
                )
                if category == "objects":
                    s3.list_objects_v2.return_value = {
                        "Contents": [{"Key": "object"}],
                        "IsTruncated": False,
                    }
                elif category == "versions":
                    s3.list_object_versions.return_value = {
                        "Versions": [{"Key": "object", "IsLatest": False}],
                        "DeleteMarkers": [],
                        "IsTruncated": False,
                    }
                elif category == "delete_markers":
                    s3.list_object_versions.return_value = {
                        "Versions": [],
                        "DeleteMarkers": [{"Key": "object"}],
                        "IsTruncated": False,
                    }
                else:
                    s3.list_multipart_uploads.return_value = {
                        "Uploads": [{"Key": "object", "UploadId": "upload"}],
                        "IsTruncated": False,
                    }

                with self._client_patch(auth, s3, backup_client), self.assertRaises(
                    ValueError
                ):
                    node.aws.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
                self.assertEqual(
                    restore.params["_bs_s3_restore_preflight"]["reason"], reason
                )
                self.assertNotIn(f"restore-{reason}", restore.error)

        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_empty_versioned_destination_persists_redacted_witness_and_starts(
        self, start_restore
    ):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.return_value = {"RestoreJobId": "restore-job-1"}

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        witness = restore.params["_bs_s3_restore_preflight"]
        self.assertEqual(witness["result"], "passed")
        self.assertTrue(witness["destination_exists"])
        self.assertEqual(witness["versioning"], "Enabled")
        self.assertTrue(witness["empty"])
        self.assertTrue(witness["scan_complete"])
        self.assertEqual(restore.provider_job_id, "restore-job-1")
        self.assertEqual(restore.resource_id, "restore-bucket")
        self.assertNotIn("access", json.dumps(restore.params))
        self.assertNotIn("secret", json.dumps(restore.params))
        start_restore.assert_called_once()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_target_and_provider_job_pointer_are_persisted_atomically(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.return_value = {"RestoreJobId": "restore-job-atomic"}
        persisted_pointer_states = []
        original_save = CoreCloudRestore.save

        def recording_save(instance, *args, **kwargs):
            result = original_save(instance, *args, **kwargs)
            persisted_pointer_states.append(
                (instance.resource_id, instance.provider_job_id)
            )
            return result

        with self._client_patch(auth, s3, backup_client), mock.patch.object(
            CoreCloudRestore,
            "save",
            autospec=True,
            side_effect=recording_save,
        ):
            node.aws.restore_snapshot(backup, restore)

        target_states = [
            state for state in persisted_pointer_states if state[0] == "restore-bucket"
        ]
        self.assertTrue(target_states)
        self.assertTrue(
            all(job_id == "restore-job-atomic" for _target, job_id in target_states)
        )

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_suspended_or_unversioned_destination_is_rejected(self, start_restore):
        for status in ("Suspended", None):
            with self.subTest(status=status):
                node, _aws, backup, restore, auth, s3, backup_client = self._fixture(
                    destination=f"restore-versioning-{status or 'missing'}"
                )
                s3.get_bucket_versioning.return_value = (
                    {"Status": status} if status else {}
                )

                with self._client_patch(auth, s3, backup_client), self.assertRaises(
                    ValueError
                ):
                    node.aws.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
                self.assertIn(
                    restore.params["_bs_s3_restore_preflight"]["reason"],
                    {"versioning_suspended", "versioning_unenabled"},
                )
                s3.list_objects_v2.assert_not_called()

        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_empty_lists_use_bounded_single_page_proofs(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        self.assertEqual(s3.list_objects_v2.call_args.kwargs["MaxKeys"], 1)
        self.assertEqual(s3.list_object_versions.call_args.kwargs["MaxKeys"], 1)
        self.assertEqual(s3.list_multipart_uploads.call_args.kwargs["MaxUploads"], 1)
        self.assertEqual(
            restore.params["_bs_s3_restore_preflight"]["scan_complete"], True
        )
        start_restore.assert_called_once()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_malformed_pagination_response_is_safe_and_non_mutating(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        s3.list_objects_v2.return_value = {
            "Contents": [],
            "IsTruncated": True,
        }

        with self._client_patch(auth, s3, backup_client), self.assertRaises(ValueError):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.params["_bs_s3_restore_preflight"]["reason"],
            "malformed_response",
        )
        self.assertNotIn("NextContinuationToken", restore.error)
        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_rate_limit_and_transient_preflight_failures_remain_in_progress(
        self, start_restore
    ):
        cases = (
            ("SlowDown", 429, "PROVIDER_RATE_LIMIT"),
            ("ServiceUnavailable", 503, "PROVIDER_TRANSIENT_OUTAGE"),
        )
        for code, http_status, expected_code in cases:
            with self.subTest(code=code):
                node, _aws, backup, restore, auth, s3, backup_client = self._fixture(
                    destination=f"restore-{code.lower()}"
                )
                s3.list_objects_v2.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": code,
                            "Message": "provider body must not be persisted",
                        },
                        "ResponseMetadata": {"HTTPStatusCode": http_status},
                    },
                    "ListObjectsV2",
                )

                with self._client_patch(auth, s3, backup_client):
                    node.aws.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
                self.assertEqual(restore.params["_bs_last_error_code"], expected_code)
                self.assertNotIn("provider body", restore.error)

        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_not_found_and_provider_secrets_are_terminal_and_redacted(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        s3.head_bucket.side_effect = ClientError(
            {
                "Error": {
                    "Code": "404",
                    "Message": "secret-access-key=do-not-persist",
                },
                "ResponseMetadata": {"HTTPStatusCode": 404},
            },
            "HeadBucket",
        )

        with self._client_patch(auth, s3, backup_client), self.assertRaises(ValueError):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        serialized = json.dumps({"params": restore.params, "error": restore.error})
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertNotIn("secret-access-key", serialized)
        self.assertNotIn("do-not-persist", serialized)
        self.assertNotIn("restore-bucket", restore.error)
        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_unknown_outcome_adopts_without_running_mutable_preflight(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture(
            params={
                "destination_bucket_name": "restore-bucket",
                "_bs_create_outcome_unknown": True,
            }
        )
        backup_client.list_restore_jobs.return_value = {
            "RestoreJobs": [
                {
                    "RestoreJobId": "adopted-restore-job",
                    "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
                    "CreatedResourceArn": "arn:aws:s3:::restore-bucket",
                    "AccountId": "123456789012",
                    "ResourceType": "S3",
                    "Status": "RUNNING",
                }
            ]
        }

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.provider_job_id, "adopted-restore-job")
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        s3.head_bucket.assert_not_called()
        s3.get_bucket_versioning.assert_not_called()
        s3.list_objects_v2.assert_not_called()
        s3.list_object_versions.assert_not_called()
        s3.list_multipart_uploads.assert_not_called()
        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_provider_job_id_redelivery_skips_all_preflight_calls(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        restore.provider_job_id = "already-created"
        restore.resource_id = "restore-bucket"
        restore.save(update_fields=["provider_job_id", "resource_id", "modified"])

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        s3.head_bucket.assert_not_called()
        s3.list_objects_v2.assert_not_called()
        s3.list_object_versions.assert_not_called()
        s3.list_multipart_uploads.assert_not_called()
        backup_client.list_restore_jobs.assert_not_called()
        start_restore.assert_not_called()

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_lost_restore_response_sets_unknown_and_replay_adopts_once(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.side_effect = [{}, {"RestoreJobId": "recovered-after-lost-response"}]

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        first_token = start_restore.call_args.args[4]
        self.assertEqual(first_token, idempotency_token("restore", restore.id))

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.provider_job_id, "recovered-after-lost-response")
        self.assertEqual(start_restore.call_count, 2)
        self.assertEqual(start_restore.call_args_list[0].args[4], start_restore.call_args_list[1].args[4])
        self.assertEqual(
            start_restore.call_args_list[1].args[4],
            idempotency_token("restore", restore.id),
        )
        backup_client.list_restore_jobs.assert_not_called()
        s3.list_objects_v2.assert_called_once()
        s3.list_object_versions.assert_called_once()
        s3.list_multipart_uploads.assert_called_once()

    def test_list_restore_jobs_uses_sdk_valid_filters_and_exact_identity(self):
        node, _aws, backup, restore, auth, _s3, _backup_client = self._fixture()
        recovery_point_arn = backup.metadata["_aws_backup"]["recovery_point_arn"]
        expected = _aws_backup_restore_identity(
            auth, "s3", recovery_point_arn, "restore-bucket"
        )
        backup_client = get_session().create_client(
            "backup",
            region_name="us-east-1",
            aws_access_key_id="access",
            aws_secret_access_key="secret",
        )
        job = {
            "RestoreJobId": "restore-job-shape",
            "RecoveryPointArn": recovery_point_arn,
            "CreatedResourceArn": expected["target_arn"],
            "AccountId": expected["account_id"],
            "ResourceType": expected["resource_type"],
            "Status": "RUNNING",
        }
        with Stubber(backup_client) as stubber:
            stubber.add_response(
                "list_restore_jobs",
                {"RestoreJobs": [job]},
                {
                    "ByAccountId": expected["account_id"],
                    "ByResourceType": expected["resource_type"],
                    "MaxResults": 1000,
                },
            )
            jobs = node.aws._find_aws_backup_restore_job(
                backup_client,
                recovery_point_arn=recovery_point_arn,
                target_id="restore-bucket",
                expected=expected,
            )

        self.assertEqual([item["RestoreJobId"] for item in jobs], ["restore-job-shape"])

    def test_list_restore_jobs_rejects_same_target_with_wrong_identity(self):
        node, _aws, backup, restore, auth, _s3, _backup_client = self._fixture()
        recovery_point_arn = backup.metadata["_aws_backup"]["recovery_point_arn"]
        expected = _aws_backup_restore_identity(
            auth, "s3", recovery_point_arn, "restore-bucket"
        )
        backup_client = mock.MagicMock()
        backup_client.list_restore_jobs.return_value = {
            "RestoreJobs": [{
                "RestoreJobId": "foreign-job",
                "RecoveryPointArn": "arn:aws:backup:us-east-1:123456789012:recovery-point/foreign",
                "CreatedResourceArn": expected["target_arn"],
                "AccountId": expected["account_id"],
                "ResourceType": expected["resource_type"],
                "Status": "RUNNING",
            }]
        }

        with self.assertRaises(ValueError) as raised:
            node.aws._find_aws_backup_restore_job(
                backup_client,
                recovery_point_arn=recovery_point_arn,
                target_id="restore-bucket",
                expected=expected,
            )

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")

    def test_list_restore_jobs_rejects_duplicate_exact_targets(self):
        node, _aws, backup, _restore, auth, _s3, _backup_client = self._fixture()
        recovery_point_arn = backup.metadata["_aws_backup"]["recovery_point_arn"]
        expected = _aws_backup_restore_identity(
            auth, "s3", recovery_point_arn, "restore-bucket"
        )
        job = {
            "RestoreJobId": "duplicate-job",
            "RecoveryPointArn": recovery_point_arn,
            "CreatedResourceArn": expected["target_arn"],
            "AccountId": expected["account_id"],
            "ResourceType": expected["resource_type"],
            "Status": "RUNNING",
        }
        backup_client = mock.MagicMock()
        backup_client.list_restore_jobs.return_value = {
            "RestoreJobs": [job, {**job, "RestoreJobId": "duplicate-job-2"}]
        }

        with self.assertRaises(ValueError) as raised:
            node.aws._find_aws_backup_restore_job(
                backup_client,
                recovery_point_arn=recovery_point_arn,
                target_id="restore-bucket",
                expected=expected,
            )

        self.assertEqual(raised.exception.code, "PROVIDER_DUPLICATE_MATCH")

    def test_list_restore_jobs_accepts_exact_transitional_job_without_target_arn(self):
        node, _aws, backup, _restore, auth, _s3, _backup_client = self._fixture()
        recovery_point_arn = backup.metadata["_aws_backup"]["recovery_point_arn"]
        expected = _aws_backup_restore_identity(
            auth, "s3", recovery_point_arn, "restore-bucket"
        )
        backup_client = mock.MagicMock()
        backup_client.list_restore_jobs.return_value = {
            "RestoreJobs": [{
                "RestoreJobId": "transitional-job",
                "RecoveryPointArn": recovery_point_arn,
                "AccountId": expected["account_id"],
                "ResourceType": expected["resource_type"],
                "Status": "RUNNING",
            }]
        }

        jobs = node.aws._find_aws_backup_restore_job(
            backup_client,
            recovery_point_arn=recovery_point_arn,
            target_id="restore-bucket",
            expected=expected,
        )

        self.assertEqual([item["RestoreJobId"] for item in jobs], ["transitional-job"])

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_missing_created_resource_arn_is_transitional_until_exact_poll(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.return_value = {"RestoreJobId": "restore-job-transitional"}
        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        backup_client.describe_restore_job.return_value = {
            "RestoreJobId": "restore-job-transitional",
            "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
            "AccountId": "123456789012",
            "ResourceType": "S3",
            "Status": "RUNNING",
        }
        with self._client_patch(auth, s3, backup_client):
            first = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(
            restore.params["_bs_restore_reconciliation"]["missing_target_observations"],
            1,
        )
        self.assertEqual(restore.operation_phase, CoreCloudRestore.OperationPhase.RECONCILING)
        self.assertNotEqual(restore.status, CoreCloudRestore.Status.FAILED)

        backup_client.describe_restore_job.return_value = {
            "RestoreJobId": "restore-job-transitional",
            "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
            "CreatedResourceArn": "arn:aws:s3:::restore-bucket",
            "AccountId": "123456789012",
            "ResourceType": "S3",
            "Status": "COMPLETED",
        }
        with self._client_patch(auth, s3, backup_client):
            second = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(second, CoreCloudRestore.Status.COMPLETE)
        self.assertEqual(restore.last_error_code, "")

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_failed_job_without_created_target_is_provider_failure(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.return_value = {"RestoreJobId": "restore-job-failed"}
        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        backup_client.describe_restore_job.return_value = {
            "RestoreJobId": "restore-job-failed",
            "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
            "AccountId": "123456789012",
            "ResourceType": "S3",
            "Status": "FAILED",
        }
        with self._client_patch(auth, s3, backup_client):
            result = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "PROVIDER_FAILED")
        self.assertEqual(
            restore.operation_phase,
            CoreCloudRestore.OperationPhase.FAILED,
        )

    @mock.patch("apps._tasks.integration.aws_backup.start_restore_job")
    def test_unsupported_restore_job_state_is_not_treated_as_in_progress(self, start_restore):
        node, _aws, backup, restore, auth, s3, backup_client = self._fixture()
        start_restore.return_value = {"RestoreJobId": "restore-job-unsupported"}
        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        backup_client.describe_restore_job.return_value = {
            "RestoreJobId": "restore-job-unsupported",
            "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
            "CreatedResourceArn": "arn:aws:s3:::restore-bucket",
            "AccountId": "123456789012",
            "ResourceType": "S3",
            # EXPIRED is a backup-job state, not a current AWS restore-job state.
            "Status": "EXPIRED",
        }
        with self._client_patch(auth, s3, backup_client):
            result = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.last_error_code, "PROVIDER_MALFORMED_RESPONSE")
        self.assertEqual(
            restore.operation_phase,
            CoreCloudRestore.OperationPhase.MANUAL_REVIEW,
        )
