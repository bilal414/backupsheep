"""Focused safety tests for native AWS Backup S3 restore destinations."""

import json
from unittest import mock

from botocore.exceptions import ClientError

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import CoreAuthAWS, CoreAWSRegion
from apps.console.node.models import CoreAWS, CoreNode
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
        start_restore.return_value = {}

        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        first_token = start_restore.call_args.args[4]
        self.assertEqual(first_token, idempotency_token("restore", restore.id))

        backup_client.list_restore_jobs.return_value = {
            "RestoreJobs": [
                {
                    "RestoreJobId": "recovered-after-lost-response",
                    "RecoveryPointArn": backup.metadata["_aws_backup"]["recovery_point_arn"],
                    "CreatedResourceArn": "arn:aws:s3:::restore-bucket",
                    "Status": "RUNNING",
                }
            ]
        }
        with self._client_patch(auth, s3, backup_client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.provider_job_id, "recovered-after-lost-response")
        self.assertEqual(start_restore.call_count, 1)
        s3.list_objects_v2.assert_called_once()
        s3.list_object_versions.assert_called_once()
        s3.list_multipart_uploads.assert_called_once()
