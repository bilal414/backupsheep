import io
from datetime import timedelta
from unittest import mock

from botocore.exceptions import ClientError
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.cloud.lightsail_bucket_replication.views import (
    CoreLightsailBucketReplicationView,
)
from apps._tasks.integration.lightsail_bucket import (
    LightsailBucketReplicationError,
    copy_s3_object,
    list_source_objects,
    replicate_lightsail_bucket,
    run_lightsail_bucket_prefix_restore,
    run_lightsail_bucket_replication,
    resume_lightsail_bucket_replications,
    resume_lightsail_bucket_restores,
)
from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreRun,
)
from apps.console.connection.models import CoreAuthLightsail, CoreLightsailRegion
from apps.console.storage.models import CoreStorageAWSS3
from apps.tests import factories
from apps.tests.base import BaseTestCase


def _not_found():
    return ClientError(
        {"Error": {"Code": "NotFound", "Message": "not found"}},
        "HeadObject",
    )


class LightsailBucketHelperTests(BaseTestCase):
    def test_version_listing_preserves_versions_and_delete_markers(self):
        client = mock.MagicMock()
        client.list_object_versions.side_effect = [
            {
                "Versions": [
                    {"Key": "docs/a.txt", "VersionId": "v2", "ETag": '"two"', "Size": 2},
                ],
                "DeleteMarkers": [
                    {"Key": "docs/a.txt", "VersionId": "v3"},
                ],
                "IsTruncated": True,
                "NextKeyMarker": "docs/a.txt",
                "NextVersionIdMarker": "v2",
            },
            {
                "Versions": [
                    {"Key": "docs/a.txt", "VersionId": "v1", "ETag": '"one"', "Size": 1},
                ],
                "DeleteMarkers": [],
                "IsTruncated": False,
            },
        ]

        entries = list_source_objects(client, "source", prefix="docs/", include_versions=True)

        self.assertEqual(
            [(row["key"], row["version_id"], row["is_delete_marker"]) for row in entries],
            [
                ("docs/a.txt", "v2", False),
                ("docs/a.txt", "v3", True),
                ("docs/a.txt", "v1", False),
            ],
        )
        self.assertEqual(
            client.list_object_versions.call_args_list,
            [
                mock.call(Bucket="source", Prefix="docs/"),
                mock.call(
                    Bucket="source",
                    Prefix="docs/",
                    KeyMarker="docs/a.txt",
                    VersionIdMarker="v2",
                ),
            ],
        )

    def test_duplicate_object_delivery_is_a_single_put(self):
        source = mock.MagicMock()
        destination = mock.MagicMock()
        source.get_object.return_value = {
            "Body": io.BytesIO(b"hello"),
            "ContentLength": 5,
            "ContentType": "text/plain",
        }
        destination.head_object.side_effect = [_not_found(), {
            "ETag": '"abc"',
            "ContentLength": 5,
            "Metadata": {},
        }]
        destination.put_object.return_value = {"ETag": '"abc"'}
        entry = {
            "key": "hello.txt",
            "version_id": "",
            "is_delete_marker": False,
            "etag": "abc",
            "size": 5,
        }

        first = copy_s3_object(
            source,
            destination,
            "source",
            "destination",
            entry,
            "prefix/hello.txt",
            part_size=64,
        )
        second = copy_s3_object(
            source,
            destination,
            "source",
            "destination",
            entry,
            "prefix/hello.txt",
            part_size=64,
        )

        self.assertEqual(first["status"], "complete")
        self.assertTrue(second["skipped"])
        destination.put_object.assert_called_once()
        source.get_object.assert_called_once()

    def test_multipart_copy_resumes_completed_parts_after_worker_crash(self):
        source = mock.MagicMock()
        destination = mock.MagicMock()

        def source_object(*args, **kwargs):
            return {"Body": io.BytesIO(b"abcdefghij"), "ContentLength": 10}

        source.get_object.side_effect = source_object
        destination.head_object.side_effect = [_not_found(), _not_found()]
        destination.create_multipart_upload.return_value = {"UploadId": "upload-1"}
        destination.upload_part.side_effect = lambda **kwargs: {
            "ETag": f'etag-{kwargs["PartNumber"]}'
        }
        destination.complete_multipart_upload.return_value = {"VersionId": "dest-v1"}
        progress = {}

        def crash_after_first_part(value):
            progress.update(value)
            if len(value.get("completed_parts") or []) == 1:
                raise RuntimeError("simulated worker crash")

        entry = {
            "key": "large.bin",
            "version_id": "v1",
            "is_delete_marker": False,
            "etag": "etag-source",
            "size": 10,
        }
        with self.assertRaises(RuntimeError):
            copy_s3_object(
                source,
                destination,
                "source",
                "destination",
                entry,
                "large.bin",
                part_size=5,
                multipart_progress=progress,
                progress_callback=crash_after_first_part,
            )

        resumed = copy_s3_object(
            source,
            destination,
            "source",
            "destination",
            entry,
            "large.bin",
            part_size=5,
            multipart_progress=progress,
        )

        self.assertEqual(resumed["status"], "complete")
        self.assertEqual(destination.create_multipart_upload.call_count, 1)
        self.assertEqual(
            [call.kwargs["PartNumber"] for call in destination.upload_part.call_args_list],
            [1, 2],
        )
        destination.complete_multipart_upload.assert_called_once()


class LightsailBucketDurabilityTests(BaseTestCase):
    def _replication(self):
        connection = factories.make_connection(self.account, self.member, code="lightsail")
        CoreAuthLightsail.objects.create(
            connection=connection,
            region=CoreLightsailRegion.objects.get(code="us-east-1"),
        )
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        CoreStorageAWSS3.objects.filter(storage=storage).update(
            access_key=b"unused", secret_key=b"unused"
        )
        return CoreLightsailBucketReplication.objects.create(
            account=self.account,
            source_connection=connection,
            source_bucket_name="source-bucket",
            destination_storage=storage,
            destination_prefix="replica/",
            part_size_bytes=5,
        )

    @staticmethod
    def _clients():
        source = mock.MagicMock()
        destination = mock.MagicMock()
        source.list_object_versions.return_value = {
            "Versions": [
                {"Key": "one.txt", "VersionId": "v1", "ETag": '"abc"', "Size": 3}
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }
        source.get_object.return_value = {
            "Body": io.BytesIO(b"one"),
            "ContentLength": 3,
        }
        destination.head_object.side_effect = [_not_found(), _not_found()]
        destination.get_bucket_versioning.return_value = {"Status": "Enabled"}
        destination.put_object.return_value = {"VersionId": "dest-v1", "ETag": '"abc"'}
        return source, destination

    def test_run_state_and_manifest_survive_duplicate_delivery(self):
        replication = self._replication()
        source, destination = self._clients()
        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.build_source_client",
            return_value=source,
        ), mock.patch(
            "apps._tasks.integration.lightsail_bucket.build_destination_client",
            return_value=destination,
        ), mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ):
            first = run_lightsail_bucket_replication(
                replication.id, idempotency_key="run-1"
            )
            second = run_lightsail_bucket_replication(
                replication.id, idempotency_key="run-1"
            )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        run = replication.runs.get(idempotency_key="run-1")
        state = run.object_states.get(key="one.txt", source_version_id="v1")
        self.assertEqual(state.status, state.Status.COMPLETE)
        self.assertEqual(run.manifest["object_count"], 1)
        self.assertEqual(destination.put_object.call_count, 2)  # object + manifest

    def test_prefix_restore_records_a_resumable_completion(self):
        replication = self._replication()
        source, destination = self._clients()
        destination.list_objects_v2.return_value = {
            "Contents": [
                {"Key": "replica/one.txt", "ETag": '"abc"', "Size": 3},
                {
                    "Key": "replica/.backupsheep/manifests/ignored.json",
                    "ETag": '"manifest"',
                    "Size": 20,
                },
            ],
            "IsTruncated": False,
        }
        # The replica object must exist for restore; the target Lightsail key does
        # not exist yet and is checked by the copy helper.
        destination.head_object.side_effect = None
        destination.head_object.return_value = {
            "ETag": '"abc"',
            "ContentLength": 3,
            "Metadata": {},
        }
        destination.get_object.return_value = {
            "Body": io.BytesIO(b"one"),
            "ContentLength": 3,
        }
        source.head_object.side_effect = [_not_found()]
        source.put_object.return_value = {"VersionId": "restored-v1"}

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.build_source_client",
            return_value=source,
        ), mock.patch(
            "apps._tasks.integration.lightsail_bucket.build_destination_client",
            return_value=destination,
        ), mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ):
            result = run_lightsail_bucket_prefix_restore(
                replication.id,
                # restore_prefix is relative to the replication's destination
                # prefix (replica/), so an empty value restores that full prefix.
                restore_prefix="",
                target_prefix="restored/",
                idempotency_key="restore-1",
            )

        self.assertEqual(
            result["status"],
            "complete",
            f"{result}; error={replication.restore_runs.get(idempotency_key='restore-1').error}",
        )
        restore = replication.restore_runs.get(idempotency_key="restore-1")
        self.assertEqual(restore.completed_count, 1)
        source.put_object.assert_called_once()
        self.assertEqual(source.put_object.call_args.kwargs["Key"], "restored/one.txt")

    def test_api_idempotency_publishes_each_run_and_restore_once_after_commit(self):
        replication = self._replication()
        factory = APIRequestFactory()

        run_view = CoreLightsailBucketReplicationView.as_view({"post": "run"})
        run_request = factory.post(
            "/cloud/lightsail_bucket_replications/1/run/",
            {"idempotency_key": "api-run-1"},
            format="json",
        )
        force_authenticate(run_request, user=self.user)
        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.start_lightsail_bucket_replication.apply_async"
        ) as enqueue:
            with self.captureOnCommitCallbacks(execute=True):
                response = run_view(run_request, pk=replication.id)
            self.assertEqual(response.status_code, 202)
            self.assertEqual(enqueue.call_count, 1)

            retry_request = factory.post(
                "/cloud/lightsail_bucket_replications/1/run/",
                {"idempotency_key": "api-run-1"},
                format="json",
            )
            force_authenticate(retry_request, user=self.user)
            retry_response = run_view(retry_request, pk=replication.id)
            self.assertEqual(retry_response.status_code, 202)
            self.assertEqual(enqueue.call_count, 1)

        restore_view = CoreLightsailBucketReplicationView.as_view({"post": "restore"})
        restore_request = factory.post(
            "/cloud/lightsail_bucket_replications/1/restore/",
            {"idempotency_key": "api-restore-1"},
            format="json",
        )
        force_authenticate(restore_request, user=self.user)
        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.restore_lightsail_bucket_replication.apply_async"
        ) as enqueue_restore:
            with self.captureOnCommitCallbacks(execute=True):
                response = restore_view(restore_request, pk=replication.id)
            self.assertEqual(response.status_code, 202)
            self.assertEqual(enqueue_restore.call_count, 1)

            retry_request = factory.post(
                "/cloud/lightsail_bucket_replications/1/restore/",
                {"idempotency_key": "api-restore-1"},
                format="json",
            )
            force_authenticate(retry_request, user=self.user)
            retry_response = restore_view(retry_request, pk=replication.id)
            self.assertEqual(retry_response.status_code, 202)
            self.assertEqual(enqueue_restore.call_count, 1)

        restore_run = replication.restore_runs.get(idempotency_key="api-restore-1")
        self.assertEqual(restore_run.target_prefix, "")
        self.assertEqual(
            enqueue_restore.call_args.kwargs["kwargs"]["target_prefix"], ""
        )

    def test_recovery_requeues_only_stale_runs_and_restores(self):
        replication = self._replication()
        stale_at = timezone.now() - timedelta(hours=2)
        stale_run = replication.runs.create(
            idempotency_key="stale-run",
            celery_task_id="old-run-task",
            status=CoreLightsailBucketReplicationRun.Status.RUNNING,
        )
        CoreLightsailBucketReplicationRun.objects.filter(pk=stale_run.id).update(
            modified=stale_at
        )
        fresh_run = replication.runs.create(
            idempotency_key="fresh-run",
            celery_task_id="fresh-run-task",
            status=CoreLightsailBucketReplicationRun.Status.PENDING,
        )
        stale_restore = replication.restore_runs.create(
            idempotency_key="stale-restore",
            celery_task_id="old-restore-task",
            status=CoreLightsailBucketRestoreRun.Status.RUNNING,
            lease_expires_at=stale_at,
        )
        CoreLightsailBucketRestoreRun.objects.filter(pk=stale_restore.id).update(
            modified=stale_at
        )

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.replicate_lightsail_bucket.apply_async"
        ) as enqueue_run, mock.patch(
            "apps._tasks.integration.lightsail_bucket.restore_lightsail_bucket_replication.apply_async"
        ) as enqueue_restore:
            result = resume_lightsail_bucket_replications.run()
            restore_result = resume_lightsail_bucket_restores.run()

        self.assertEqual(result["dispatched"], 1)
        self.assertEqual(restore_result["dispatched"], 1)
        self.assertEqual(enqueue_run.call_count, 1)
        self.assertEqual(enqueue_restore.call_count, 1)
        fresh_run.refresh_from_db()
        self.assertEqual(fresh_run.celery_task_id, "fresh-run-task")

    def test_task_exception_keeps_run_resumable(self):
        replication = self._replication()
        run = replication.runs.create(idempotency_key="crash-run")

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.run_lightsail_bucket_replication",
            side_effect=RuntimeError("simulated worker failure"),
        ), self.assertRaises(RuntimeError):
            replicate_lightsail_bucket.run(replication.id, run.id, "crash-run")

        run.refresh_from_db()
        self.assertEqual(run.status, CoreLightsailBucketReplicationRun.Status.RUNNING)
        self.assertIsNone(run.completed_at)
        self.assertIn("simulated worker failure", run.error)

    def test_direct_task_rejects_inactive_source_before_provider_access(self):
        replication = self._replication()
        replication.source_connection.status = replication.source_connection.Status.SUSPENDED
        replication.source_connection.save(update_fields=["status", "modified"])
        source, destination = self._clients()

        with self.assertRaises(LightsailBucketReplicationError):
            run_lightsail_bucket_replication(
                replication.id,
                idempotency_key="inactive-source",
                source_client=source,
                destination_client=destination,
            )

        source.list_object_versions.assert_not_called()
        destination.put_object.assert_not_called()
