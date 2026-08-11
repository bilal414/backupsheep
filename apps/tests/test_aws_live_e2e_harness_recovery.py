"""Pure recovery tests for the AWS S3/DynamoDB/RDS live E2E harness.

These tests never construct a boto3 client or contact AWS. Provider calls are
represented by small fakes so the crash boundary and fail-closed reconciliation
rules stay deterministic.
"""

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from botocore.exceptions import ClientError

from scripts import aws_s3_dynamodb_rds_e2e as harness


RUN_ID = "bs-e2e-test-1234"
SOURCE_ARN = (
    "arn:aws:backup:us-east-2:123456789012:recovery-point/test-recovery-point"
)
TARGET = "bs-e2e-test-1234-ddb-restore"
TARGET_ARN = f"arn:aws:dynamodb:us-east-2:123456789012:table/{TARGET}"


class FakeRestore:
    def __init__(self, restore_id=42):
        self.id = restore_id
        self.pk = restore_id
        self.correlation_id = f"correlation-{restore_id}"
        self.params = {}
        self.restore_marker = ""
        self.request_fingerprint = ""
        self.provider_job_id = ""
        self.resource_id = ""
        self.status = 1
        self.operation_phase = "pending"
        self.error = ""
        self.saved_fields = []

    def refresh_from_db(self):
        return self

    def save(self, update_fields=None, **kwargs):
        self.saved_fields.append(tuple(update_fields or ()))


class FakeBackupClient:
    def __init__(self, pages, description=None):
        self.pages = list(pages)
        self.description = description
        self.list_calls = []
        self.describe_calls = []

    def list_restore_jobs(self, **request):
        self.list_calls.append(dict(request))
        if not self.pages:
            return {"RestoreJobs": []}
        return self.pages.pop(0)

    def describe_restore_job(self, **request):
        self.describe_calls.append(dict(request))
        if self.description is None:
            raise AssertionError("unexpected restore-job description")
        return dict(self.description)


class FakeDynamoDB:
    def __init__(self, tag_pages):
        self.tag_pages = list(tag_pages)
        self.tag_calls = []
        self.describe_calls = []

    def describe_table(self, **request):
        self.describe_calls.append(dict(request))
        return {
            "Table": {
                "TableName": TARGET,
                "TableArn": TARGET_ARN,
                "TableStatus": "ACTIVE",
            }
        }

    def list_tags_of_resource(self, **request):
        if not self.tag_pages:
            return {"Tags": []}
        page = self.tag_pages.pop(0)
        if isinstance(page, BaseException):
            raise page
        return page

    def tag_resource(self, **request):
        self.tag_calls.append(dict(request))

    def get_item(self, **request):
        return {"Item": {"marker": {"S": "fixture-marker"}}}


class FakeLedger:
    def __init__(self, records=None):
        self.records = list(records or [])

    def record(self, **kwargs):
        self.records.append(dict(kwargs))
        return dict(kwargs)

    def entries(self, kind=None):
        if kind is None:
            return list(self.records)
        return [row for row in self.records if row.get("kind") == kind]


class AWSLiveE2EHarnessRecoveryTests(TestCase):
    def setUp(self):
        self.prefix_patch = mock.patch.object(harness, "PREFIX", RUN_ID)
        self.prefix_patch.start()

    def tearDown(self):
        self.prefix_patch.stop()

    def _store(self, directory):
        return harness.RestoreIntentStore(
            Path(directory) / "aws.json",
            run_id=RUN_ID,
            scope="123456789012:us-east-2",
        )

    def _intent(self, store, restore=None):
        restore = restore or FakeRestore()
        key, intent = harness._prepare_restore_intent(
            store,
            restore,
            resource_type="dynamodb",
            source_recovery_point_arn=SOURCE_ARN,
            target_name=TARGET,
            account_id="123456789012",
        )
        return key, intent, restore

    def _job(self, restore, *, status="RUNNING", target_arn=TARGET_ARN, metadata=None):
        return {
            "RestoreJobId": "restore-job-1",
            "RecoveryPointArn": SOURCE_ARN,
            "ResourceType": "DynamoDB",
            "CreatedResourceArn": target_arn,
            "Status": status,
            "RestoreMetadata": metadata
            or {
                "TargetTableName": TARGET,
                "BackupSheepRestoreMarker": restore.restore_marker,
            },
        }

    def test_lost_response_fences_the_second_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            provider = FakeBackupClient([{"RestoreJobs": []}])

            def lose_response():
                self.assertEqual(store.get(key)["mutation_state"], "request_started")
                raise TimeoutError("response lost")

            start = mock.Mock(side_effect=lose_response)

            with self.assertRaises(harness.RestoreRecoveryError) as first:
                harness._start_or_reconcile_restore(
                    None,
                    provider,
                    restore,
                    store,
                    key,
                    start_callback=start,
                )

            self.assertEqual(first.exception.code, "PROVIDER_TIMEOUT")
            self.assertEqual(start.call_count, 1)
            self.assertEqual(store.get(key)["mutation_state"], "outcome_unknown")

            with self.assertRaises(harness.RestoreRecoveryError) as retry:
                harness._start_or_reconcile_restore(
                    None,
                    provider,
                    restore,
                    store,
                    key,
                    start_callback=start,
                )
            self.assertEqual(retry.exception.code, "PROVIDER_RECONCILIATION_REQUIRED")
            self.assertEqual(start.call_count, 1)

    def test_exact_job_is_adopted_without_starting_another_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            job = self._job(restore)
            provider = FakeBackupClient(
                [{"RestoreJobs": [job]}], description=job
            )
            start = mock.Mock()

            adopted = harness._start_or_reconcile_restore(
                None,
                provider,
                restore,
                store,
                key,
                start_callback=start,
            )

            self.assertEqual(adopted["RestoreJobId"], "restore-job-1")
            self.assertEqual(restore.provider_job_id, "restore-job-1")
            self.assertEqual(restore.resource_id, TARGET)
            self.assertEqual(start.call_count, 0)
            self.assertEqual(store.get(key)["mutation_state"], "accepted")

    def test_in_progress_job_can_be_adopted_from_exact_restore_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            job = self._job(restore, target_arn="")
            provider = FakeBackupClient(
                [{"RestoreJobs": [job]}], description=job
            )

            harness._start_or_reconcile_restore(
                None,
                provider,
                restore,
                store,
                key,
                start_callback=mock.Mock(),
            )

            self.assertEqual(restore.provider_job_id, "restore-job-1")
            self.assertEqual(restore.resource_id, TARGET)

    def test_duplicate_exact_jobs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            first = self._job(restore)
            second = dict(first, RestoreJobId="restore-job-2")
            provider = FakeBackupClient([{"RestoreJobs": [first, second]}])
            start = mock.Mock()

            with self.assertRaises(harness.RestoreRecoveryError) as error:
                harness._start_or_reconcile_restore(
                    None,
                    provider,
                    restore,
                    store,
                    key,
                    start_callback=start,
                )

            self.assertEqual(error.exception.code, "PROVIDER_DUPLICATE_MATCH")
            self.assertEqual(start.call_count, 0)
            self.assertEqual(store.get(key)["mutation_state"], "prepared")

    def test_repeated_next_token_is_rejected(self):
        restore = FakeRestore()
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            _, intent, _ = self._intent(store, restore)
            provider = FakeBackupClient(
                [
                    {"RestoreJobs": [], "NextToken": "cursor-1"},
                    {"RestoreJobs": [], "NextToken": "cursor-1"},
                ]
            )

            with self.assertRaises(harness.RestoreRecoveryError) as error:
                harness._list_restore_jobs_exact(provider, intent)
            self.assertEqual(error.exception.code, "PROVIDER_REPEATED_CURSOR")

    def test_completed_job_requires_exact_target_and_source(self):
        restore = FakeRestore()
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            _, intent, _ = self._intent(store, restore)
            wrong_target = self._job(restore, status="COMPLETED", target_arn="arn:aws:dynamodb:us-east-2:123456789012:table/other")
            provider = FakeBackupClient([], description=wrong_target)
            with self.assertRaises(harness.RestoreRecoveryError) as error:
                harness._verify_completed_restore_job(
                    provider, intent, "restore-job-1"
                )
            self.assertEqual(error.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")

    def test_delayed_tag_visibility_is_retried_then_ledgered(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            restore.provider_job_id = "restore-job-1"
            store.update(
                key,
                provider_job_id="restore-job-1",
                mutation_state="accepted",
            )
            job = self._job(restore, status="COMPLETED")
            provider = FakeBackupClient([], description=job)
            dynamodb = FakeDynamoDB(
                [
                    {"Tags": []},
                    {"Tags": [{"Key": harness.OWNERSHIP_TAG, "Value": RUN_ID}]},
                ]
            )
            ledger = FakeLedger()

            harness._finalize_ddb_restore(
                dynamodb,
                provider,
                restore,
                store,
                key,
                ledger,
                marker="fixture-marker",
            )

            self.assertEqual(len(dynamodb.tag_calls), 1)
            self.assertEqual(len(ledger.records), 1)
            self.assertIn("restore-job-1", ledger.records[0]["source_witness"])
            self.assertIsNone(store.get(key))

    def test_exact_legacy_restore_witness_is_idempotently_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, intent, restore = self._intent(store)
            restore.provider_job_id = "restore-job-1"
            store.update(
                key,
                provider_job_id="restore-job-1",
                mutation_state="accepted",
            )
            job = self._job(restore, status="COMPLETED")
            provider = FakeBackupClient([], description=job)
            owned_tags = {
                "Tags": [
                    {"Key": harness.OWNERSHIP_TAG, "Value": RUN_ID}
                ]
            }
            dynamodb = FakeDynamoDB(
                [
                    owned_tags,
                    owned_tags,
                ]
            )
            legacy = (
                f"{SOURCE_ARN}|restore-job:restore-job-1"
                f"|created-resource:{TARGET_ARN}"
            )
            ledger = FakeLedger(
                [
                    {
                        "kind": "dynamodb_table",
                        "resource_id": TARGET,
                        "name": TARGET,
                        "ownership": {
                            "tag_key": harness.OWNERSHIP_TAG,
                            "tag_value": RUN_ID,
                        },
                        "source_witness": legacy,
                    }
                ]
            )

            harness._finalize_ddb_restore(
                dynamodb,
                provider,
                restore,
                store,
                key,
                ledger,
                marker="fixture-marker",
            )

            self.assertEqual(len(ledger.records), 1)
            self.assertIsNone(store.get(key))

    def test_wrong_existing_tag_is_not_overwritten(self):
        restore = FakeRestore()
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store, restore)
            dynamodb = FakeDynamoDB(
                [{"Tags": [{"Key": harness.OWNERSHIP_TAG, "Value": "another-run"}]}]
            )
            with self.assertRaises(harness.RestoreRecoveryError) as error:
                harness._wait_ddb_tag_readback(
                    dynamodb,
                    TARGET,
                    TARGET_ARN,
                    timeout=0,
                    sleep_callback=lambda: None,
                )
            self.assertEqual(error.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
            self.assertEqual(dynamodb.tag_calls, [])

    def test_worker_crash_boundary_is_visible_to_a_new_store_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            key, _, restore = self._intent(store)
            provider = FakeBackupClient([{"RestoreJobs": []}])
            start = mock.Mock(side_effect=KeyboardInterrupt())
            with self.assertRaises(KeyboardInterrupt):
                harness._start_or_reconcile_restore(
                    None,
                    provider,
                    restore,
                    store,
                    key,
                    start_callback=start,
                )

            restarted = self._store(directory)
            observed = restarted.get(key)
            self.assertEqual(observed["mutation_state"], "outcome_unknown")
            self.assertEqual(observed["restore_token"], harness.idempotency_token("restore", 42))

            with self.assertRaises(harness.RestoreRecoveryError):
                harness._start_or_reconcile_restore(
                    None,
                    provider,
                    restore,
                    restarted,
                    key,
                    start_callback=start,
                )
            self.assertEqual(start.call_count, 1)

    def test_provider_failures_are_not_reported_as_in_progress(self):
        not_found = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}}, "DescribeRestoreJob"
        )
        throttled = ClientError(
            {"Error": {"Code": "ThrottlingException"}}, "ListRestoreJobs"
        )
        outage = ClientError(
            {
                "Error": {"Code": "ServiceUnavailableException"},
                "ResponseMetadata": {"HTTPStatusCode": 503},
            },
            "ListRestoreJobs",
        )
        self.assertEqual(harness._provider_error_code(not_found), "PROVIDER_NOT_FOUND")
        self.assertEqual(harness._provider_error_code(throttled), "PROVIDER_RATE_LIMIT")
        self.assertEqual(harness._provider_error_code(outage), "PROVIDER_TRANSIENT_OUTAGE")

    def test_rds_resume_delegates_existing_target_adoption_to_owned_adapter(self):
        source = f"{RUN_ID}-rds"
        target = f"{RUN_ID}-rds-restore"
        snapshot = f"{RUN_ID}-rds-snapshot"
        marker = "backupsheep-rds-restore-marker"
        rds_backup = SimpleNamespace(
            unique_id=snapshot,
            save=mock.Mock(),
            refresh_from_db=mock.Mock(),
        )
        rds_restore = FakeRestore(restore_id=91)
        rds_restore.params = {}
        adapter = mock.Mock()

        def adopt(_backup, restore):
            restore.resource_id = target
            restore.restore_marker = marker

        adapter.restore_snapshot.side_effect = adopt
        rds = mock.Mock()
        rds.describe_db_snapshots.return_value = {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": snapshot,
                    "DBInstanceIdentifier": source,
                    "SnapshotType": "manual",
                }
            ]
        }
        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": target,
                    "DBInstanceArn": "arn:aws:rds:us-east-2:123456789012:db:target",
                    "DBInstanceStatus": "available",
                }
            ]
        }
        rds.list_tags_for_resource.return_value = {
            "TagList": [
                {"Key": "BackupSheepRestore", "Value": marker},
                {"Key": "BackupSheepSource", "Value": snapshot},
            ]
        }
        graph = {
            "rds_backup": rds_backup,
            "rds_restore": rds_restore,
            "rds_node": SimpleNamespace(aws_rds=adapter),
        }
        report = {"tests": {}}

        with mock.patch.multiple(
            harness,
            RDS_SOURCE=source,
            RDS_RESTORE=target,
            RDS_SUBNET_GROUP=f"{RUN_ID}-subnet",
        ), mock.patch.object(
            harness, "_register_rds_snapshot"
        ), mock.patch.object(
            harness,
            "_wait_backup",
            return_value={"state": "Complete", "history": ["3"]},
        ), mock.patch.object(
            harness, "_register_rds_instance"
        ) as register_instance, mock.patch.object(
            harness, "_assert_rds_marker"
        ) as assert_marker:
            harness._resume_rds_continuation(
                rds,
                graph,
                FakeLedger(),
                security_group_id="sg-owned",
                rds_password="fixture-password",
                report=report,
            )

        adapter.restore_snapshot.assert_called_once_with(rds_backup, rds_restore)
        register_instance.assert_called_once_with(
            mock.ANY,
            rds,
            target,
            source=snapshot,
        )
        assert_marker.assert_called_once_with(
            rds, target, "fixture-password"
        )
        rds.add_tags_to_resource.assert_called_once_with(
            ResourceName="arn:aws:rds:us-east-2:123456789012:db:target",
            Tags=[{"Key": harness.OWNERSHIP_TAG, "Value": RUN_ID}],
        )
