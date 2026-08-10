import io
import json
from datetime import timedelta
from unittest import mock

from botocore.exceptions import ClientError
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.cloud.lightsail_bucket_replication.serializers import (
    CoreLightsailBucketReplicationObjectSerializer,
    CoreLightsailBucketReplicationReadSerializer,
    CoreLightsailBucketReplicationRunSerializer,
    CoreLightsailBucketReplicationWriteSerializer,
    CoreLightsailBucketRestoreRunSerializer,
)
from apps.api.v1.cloud.lightsail_bucket_replication.views import (
    CoreLightsailBucketReplicationView,
)
from apps._tasks.integration.lightsail_bucket import (
    LightsailBucketReplicationError,
    _failure_for,
    _get_or_create_object_state,
    _get_or_create_restore_object_state,
    _object_identity_metadata,
    copy_s3_object,
    list_source_objects,
    replicate_lightsail_bucket,
    run_lightsail_bucket_prefix_restore,
    run_lightsail_bucket_replication,
    resume_lightsail_bucket_replications,
)
from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreObject,
    CoreLightsailBucketRestoreRun,
)
from apps.console.connection.models import CoreAuthLightsail, CoreLightsailRegion
from apps.console.storage.models import CoreStorageAWSS3
from apps.tests import factories
from apps.tests.base import BaseTestCase


CANARY = "lightsail-secret-canary.example.invalid"


def _provider_error(code, status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = str(retry_after)
    return ClientError(
        {
            "Error": {
                "Code": str(code),
                "Message": f"{CANARY} provider response body",
            },
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "HTTPHeaders": headers,
            },
        },
        "LightsailOperation",
    )


def _not_found():
    return _provider_error("NotFound", 404)


class LightsailBucketErrorContractTests(BaseTestCase):
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

    def test_provider_outcomes_are_distinct_and_retry_after_is_bounded(self):
        not_found = _failure_for(_provider_error("NotFound", 404))
        auth = _failure_for(_provider_error("AccessDenied", 403))
        limited = _failure_for(_provider_error("SlowDown", 429, retry_after=17))
        outage = _failure_for(_provider_error("ServiceUnavailable", 503))
        timeout = _failure_for(TimeoutError("request contained a secret"))
        terminal = _failure_for(_provider_error("InvalidRequest", 400))

        self.assertEqual(not_found.code, "LIGHTSAIL_NOT_FOUND")
        self.assertFalse(not_found.retryable)
        self.assertEqual(auth.code, "LIGHTSAIL_AUTH_FAILED")
        self.assertFalse(auth.retryable)
        self.assertEqual(limited.code, "LIGHTSAIL_RATE_LIMITED")
        self.assertTrue(limited.retryable)
        self.assertEqual(limited.retry_after_seconds, 17)
        self.assertEqual(outage.code, "LIGHTSAIL_TRANSIENT_OUTAGE")
        self.assertTrue(outage.retryable)
        self.assertEqual(timeout.code, "LIGHTSAIL_TIMEOUT")
        self.assertTrue(timeout.retryable)
        self.assertEqual(terminal.code, "LIGHTSAIL_TERMINAL_FAILURE")
        self.assertFalse(terminal.retryable)
        self.assertNotIn(CANARY, json.dumps(limited.as_dict()))

    def test_lost_single_put_response_adopts_verified_object(self):
        source = mock.MagicMock()
        destination = mock.MagicMock()
        entry = {
            "key": "documents/report.txt",
            "version_id": "v1",
            "is_delete_marker": False,
            "etag": "source-etag",
            "size": 5,
        }
        expected_metadata = _object_identity_metadata(entry)
        source.get_object.return_value = {
            "Body": io.BytesIO(b"hello"),
            "ContentLength": 5,
        }
        destination.head_object.side_effect = [
            _not_found(),
            {
                "Metadata": expected_metadata,
                "ContentLength": 5,
                "ETag": '"source-etag"',
                "VersionId": "adopted-v1",
            },
        ]
        destination.put_object.side_effect = TimeoutError(CANARY)

        result = copy_s3_object(
            source,
            destination,
            "source",
            "destination",
            entry,
            "replica/documents/report.txt",
            part_size=64,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["destination_version_id"], "adopted-v1")
        destination.put_object.assert_called_once()

    def test_lost_multipart_create_response_adopts_one_remote_upload(self):
        source = mock.MagicMock()
        destination = mock.MagicMock()
        entry = {
            "key": "large.bin",
            "version_id": "v1",
            "is_delete_marker": False,
            "etag": "source-etag",
            "size": 5,
        }
        source.get_object.return_value = {
            "Body": io.BytesIO(b"hello"),
            "ContentLength": 5,
        }
        destination.head_object.side_effect = [_not_found()]
        destination.list_multipart_uploads.side_effect = [
            {"Uploads": []},
            {"Uploads": [{"Key": "replica/large.bin", "UploadId": "adopt-me"}]},
        ]
        destination.create_multipart_upload.side_effect = TimeoutError(CANARY)
        destination.upload_part.return_value = {"ETag": "part-etag"}
        destination.complete_multipart_upload.return_value = {"VersionId": "v1"}

        result = copy_s3_object(
            source,
            destination,
            "source",
            "destination",
            entry,
            "replica/large.bin",
            part_size=5,
        )

        self.assertEqual(result["status"], "complete")
        destination.create_multipart_upload.assert_called_once()
        self.assertEqual(destination.complete_multipart_upload.call_args.kwargs["UploadId"], "adopt-me")
        self.assertNotIn(CANARY, repr(result))

    def test_conflicting_duplicate_object_version_fails_closed(self):
        client = mock.MagicMock()
        client.list_object_versions.return_value = {
            "Versions": [
                {"Key": "same.txt", "VersionId": "v1", "ETag": '"one"', "Size": 3},
                {"Key": "same.txt", "VersionId": "v1", "ETag": '"two"', "Size": 3},
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }

        with self.assertRaises(LightsailBucketReplicationError) as raised:
            list(list_source_objects(client, "source", include_versions=True))

        self.assertEqual(raised.exception.failure.code, "LIGHTSAIL_DUPLICATE_MATCH")
        self.assertNotIn(CANARY, str(raised.exception))

    def test_version_cursor_can_resume_after_worker_crash(self):
        first = mock.MagicMock()
        first.list_object_versions.return_value = {
            "Versions": [
                {"Key": "old.txt", "VersionId": "v1", "ETag": '"one"', "Size": 3}
            ],
            "DeleteMarkers": [],
            "IsTruncated": True,
            "NextKeyMarker": "next-key",
            "NextVersionIdMarker": "next-version",
        }
        cursor = {}

        def crash_after_checkpoint(value):
            cursor.update(value)
            raise RuntimeError(CANARY)

        with self.assertRaises(RuntimeError):
            list(
                list_source_objects(
                    first,
                    "source",
                    include_versions=True,
                    cursor_state=cursor,
                    progress_callback=crash_after_checkpoint,
                )
            )

        self.assertEqual(cursor["key_marker"], "next-key")
        second = mock.MagicMock()
        second.list_object_versions.return_value = {
            "Versions": [
                {"Key": "new.txt", "VersionId": "v2", "ETag": '"two"', "Size": 3}
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }
        entries = list(
            list_source_objects(
                second,
                "source",
                include_versions=True,
                cursor_state=cursor,
            )
        )

        self.assertEqual([entry["key"] for entry in entries], ["new.txt"])
        second.list_object_versions.assert_called_once_with(
            Bucket="source",
            KeyMarker="next-key",
            VersionIdMarker="next-version",
        )

    def test_page_is_materialized_before_cursor_checkpoint(self):
        client = mock.MagicMock()
        client.list_objects_v2.return_value = {
            "Contents": [{"Key": "page-one.txt", "ETag": '"one"', "Size": 3}],
            "IsTruncated": True,
            "NextContinuationToken": "cursor-2",
        }
        events = []
        with self.assertRaises(RuntimeError):
            list(
                list_source_objects(
                    client,
                    "source",
                    include_versions=False,
                    page_callback=lambda entries, state: events.append(("page", entries)),
                    progress_callback=lambda state: (_ for _ in ()).throw(
                        RuntimeError("simulated worker crash")
                    ),
                )
            )

        self.assertEqual(events[0][0], "page")
        self.assertEqual(events[0][1][0]["key"], "page-one.txt")

    def test_existing_pending_and_failed_fingerprints_never_change(self):
        replication = self._replication()
        run = replication.runs.create(idempotency_key="immutable-fingerprint")
        observed_at = timezone.now().replace(microsecond=0)
        original = {
            "key": "immutable.txt",
            "version_id": "v1",
            "is_delete_marker": False,
            "etag": "etag-one",
            "size": 7,
            "last_modified": observed_at,
            "last_modified_iso": observed_at.isoformat(),
        }
        state = _get_or_create_object_state(run, replication, original)

        for field, value in (
            ("etag", "etag-two"),
            ("size", 8),
            ("last_modified", observed_at + timedelta(seconds=1)),
        ):
            with self.subTest(status="pending", field=field):
                changed = dict(original)
                changed[field] = value
                if field == "last_modified":
                    changed["last_modified_iso"] = value.isoformat()
                with self.assertRaises(LightsailBucketReplicationError) as raised:
                    _get_or_create_object_state(run, replication, changed)
                self.assertEqual(
                    raised.exception.failure.code,
                    "LIGHTSAIL_DUPLICATE_MATCH",
                )

        state.status = CoreLightsailBucketReplicationObject.Status.FAILED
        state.save(update_fields=["status", "modified"])
        replication.destination_prefix = "different-destination/"
        replication.save(update_fields=["destination_prefix", "modified"])
        with self.assertRaises(LightsailBucketReplicationError) as raised:
            _get_or_create_object_state(run, replication, original)
        self.assertEqual(raised.exception.failure.code, "LIGHTSAIL_DUPLICATE_MATCH")

        state.refresh_from_db()
        self.assertEqual(state.source_etag, "etag-one")
        self.assertEqual(state.source_size, 7)
        self.assertEqual(state.source_last_modified, observed_at)
        self.assertEqual(state.destination_key, "replica/immutable.txt")

    def test_cross_page_restart_conflict_fails_closed_without_overwrite(self):
        replication = self._replication()
        observed_at = timezone.now().replace(microsecond=0)
        first_worker = mock.MagicMock()
        first_worker.list_object_versions.side_effect = [
            {
                "Versions": [
                    {
                        "Key": "same.txt",
                        "VersionId": "v1",
                        "ETag": '"etag-one"',
                        "Size": 3,
                        "LastModified": observed_at,
                    }
                ],
                "DeleteMarkers": [],
                "IsTruncated": True,
                "NextKeyMarker": "same.txt",
                "NextVersionIdMarker": "v1",
            },
            TimeoutError(CANARY),
        ]
        destination = mock.MagicMock()

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ), self.assertRaises(TimeoutError):
            run_lightsail_bucket_replication(
                replication.id,
                idempotency_key="cross-page-restart",
                source_client=first_worker,
                destination_client=destination,
            )

        run = replication.runs.get(idempotency_key="cross-page-restart")
        state = run.object_states.get(key="same.txt", source_version_id="v1")
        state.status = CoreLightsailBucketReplicationObject.Status.FAILED
        state.save(update_fields=["status", "modified"])
        second_worker = mock.MagicMock()
        second_worker.list_object_versions.return_value = {
            "Versions": [
                {
                    "Key": "same.txt",
                    "VersionId": "v1",
                    "ETag": '"etag-conflict"',
                    "Size": 3,
                    "LastModified": observed_at,
                }
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ), self.assertRaises(LightsailBucketReplicationError) as raised:
            run_lightsail_bucket_replication(
                replication.id,
                run_id=run.id,
                source_client=second_worker,
                destination_client=destination,
            )

        self.assertEqual(raised.exception.failure.code, "LIGHTSAIL_DUPLICATE_MATCH")
        state.refresh_from_db()
        self.assertEqual(state.source_etag, "etag-one")
        self.assertEqual(state.status, CoreLightsailBucketReplicationObject.Status.FAILED)
        second_worker.list_object_versions.assert_called_once_with(
            Bucket="source-bucket",
            KeyMarker="same.txt",
            VersionIdMarker="v1",
        )

    def test_recovery_requeues_the_same_run_after_worker_crash(self):
        replication = self._replication()
        run = replication.runs.create(
            idempotency_key="crash-resume",
            celery_task_id="old-task",
            status=CoreLightsailBucketReplicationRun.Status.RUNNING,
        )
        CoreLightsailBucketReplicationRun.objects.filter(pk=run.pk).update(
            modified=timezone.now() - timedelta(hours=2)
        )

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.replicate_lightsail_bucket.apply_async"
        ) as enqueue:
            result = resume_lightsail_bucket_replications.run()

        self.assertEqual(result["dispatched"], 1)
        self.assertEqual(enqueue.call_args.kwargs["kwargs"]["run_id"], run.id)
        self.assertEqual(replication.runs.filter(idempotency_key="crash-resume").count(), 1)

    def test_restore_inventory_uses_child_rows_not_unbounded_json(self):
        replication = self._replication()
        source_run = replication.runs.create(
            idempotency_key="restore-source",
            status=CoreLightsailBucketReplicationRun.Status.COMPLETE,
        )
        source_object = source_run.object_states.create(
            key=CANARY,
            source_version_id="source-v1",
            destination_key=CANARY,
            destination_version_id="v1",
            status=CoreLightsailBucketReplicationObject.Status.COMPLETE,
        )
        restore = replication.restore_runs.create(
            idempotency_key="encrypted-inventory",
            status=CoreLightsailBucketRestoreRun.Status.RUNNING,
            source_run=source_run,
        )
        ledger = _get_or_create_restore_object_state(
            restore,
            replication,
            CANARY,
            {
                "source_object": source_object,
                "_source_key": CANARY,
                "_target_key": CANARY,
                "backup_version_id": "v1",
                "is_delete_marker": False,
                "backup_etag": "etag",
                "backup_size": 1,
                "backup_last_modified": None,
                "source_version_id": "source-v1",
                "source_etag": "etag",
            },
        )
        restore.refresh_from_db()

        self.assertNotIn(CANARY, json.dumps(restore.manifest))
        self.assertEqual(restore.completed_objects, [])
        self.assertEqual(restore.object_states.count(), 1)
        self.assertNotIn(CANARY, ledger.backup_key_encrypted)
        self.assertNotIn(CANARY, ledger.source_key_encrypted)
        self.assertNotIn(CANARY, ledger.target_key_encrypted)
        with self.assertRaises(LightsailBucketReplicationError) as raised:
            _get_or_create_restore_object_state(
                restore,
                replication,
                "different-backup-key",
                {
                    "source_object": source_object,
                    "_source_key": CANARY,
                    "_target_key": CANARY,
                    "backup_version_id": "v2",
                    "is_delete_marker": False,
                    "backup_etag": "etag-two",
                    "backup_size": 1,
                    "backup_last_modified": None,
                    "source_version_id": "source-v1",
                    "source_etag": "etag",
                },
            )
        self.assertEqual(raised.exception.failure.code, "LIGHTSAIL_DUPLICATE_MATCH")
        serialized = json.dumps(CoreLightsailBucketRestoreRunSerializer(restore).data)
        self.assertNotIn(CANARY, serialized)
        self.assertNotIn("object_states", serialized)

    def test_restore_adopts_provider_write_after_worker_crash(self):
        replication = self._replication()
        backup_modified = timezone.now().replace(microsecond=0)
        source_run = replication.runs.create(
            idempotency_key="restore-crash-source",
            status=CoreLightsailBucketReplicationRun.Status.COMPLETE,
        )
        source_state = source_run.object_states.create(
            key="one.txt",
            source_version_id="v1",
            source_etag="abc",
            source_size=3,
            destination_key="replica/one.txt",
            destination_version_id="backup-v1",
            status=CoreLightsailBucketReplicationObject.Status.COMPLETE,
        )
        replication.last_run = source_run
        replication.save(update_fields=["last_run", "modified"])

        source = mock.MagicMock()
        destination = mock.MagicMock()
        destination.list_object_versions.return_value = {
            "Versions": [
                {
                    "Key": "replica/one.txt",
                    "VersionId": "backup-v1",
                    "ETag": '"abc"',
                    "Size": 3,
                    "LastModified": backup_modified,
                    "IsLatest": True,
                }
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }
        destination.head_object.return_value = {
            "ETag": '"abc"',
            "ContentLength": 3,
            "LastModified": backup_modified,
            "VersionId": "backup-v1",
            "Metadata": _object_identity_metadata(
                {
                    "key": source_state.key,
                    "version_id": source_state.source_version_id,
                    "is_delete_marker": False,
                    "etag": source_state.source_etag,
                }
            ),
        }
        destination.get_object.return_value = {
            "Body": io.BytesIO(b"one"),
            "ContentLength": 3,
        }
        source.head_object.side_effect = [_not_found()]
        source.put_object.return_value = {"VersionId": "restored-v1"}

        original_save = CoreLightsailBucketRestoreObject.save
        crashed = {"value": False}

        def crash_before_completion_checkpoint(instance, *args, **kwargs):
            if (
                instance.status == CoreLightsailBucketRestoreObject.Status.COMPLETE
                and not crashed["value"]
            ):
                crashed["value"] = True
                raise SystemExit("simulated worker process exit")
            return original_save(instance, *args, **kwargs)

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ), mock.patch.object(
            CoreLightsailBucketRestoreObject,
            "save",
            new=crash_before_completion_checkpoint,
        ), self.assertRaises(SystemExit):
            run_lightsail_bucket_prefix_restore(
                replication.id,
                source_run_id=source_run.id,
                target_prefix="restored/",
                idempotency_key="restore-crash",
                source_client=source,
                destination_client=destination,
            )

        restore = replication.restore_runs.get(idempotency_key="restore-crash")
        ledger = restore.object_states.get()
        self.assertEqual(ledger.status, CoreLightsailBucketRestoreObject.Status.RESTORING)
        source.put_object.assert_called_once()
        accepted = source.put_object.call_args.kwargs
        source.head_object.side_effect = None
        source.head_object.return_value = {
            "ETag": accepted.get("ETag", '"abc"'),
            "ContentLength": 3,
            "VersionId": "restored-v1",
            "Metadata": accepted["Metadata"],
        }

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket._destination_bucket",
            return_value="destination-bucket",
        ):
            result = run_lightsail_bucket_prefix_restore(
                replication.id,
                restore_id=restore.id,
                source_run_id=source_run.id,
                source_client=source,
                destination_client=destination,
            )

        self.assertEqual(result["status"], CoreLightsailBucketRestoreRun.Status.COMPLETE)
        ledger.refresh_from_db()
        self.assertEqual(ledger.status, CoreLightsailBucketRestoreObject.Status.SKIPPED)
        self.assertEqual(ledger.restored_version_id, "restored-v1")
        source.put_object.assert_called_once()
        destination.list_object_versions.assert_called_once()

    def test_task_failure_and_api_output_are_redacted(self):
        replication = self._replication()
        run = replication.runs.create(
            idempotency_key="run-canary",
            status=CoreLightsailBucketReplicationRun.Status.RUNNING,
        )

        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.run_lightsail_bucket_replication",
            side_effect=RuntimeError(CANARY),
        ), self.assertRaises(RuntimeError):
            replicate_lightsail_bucket.run(replication.id, run.id, "run-canary")

        run.refresh_from_db()
        self.assertNotIn(CANARY, run.error)
        self.assertIn("LIGHTSAIL_WORKER_FAILURE", run.error)

        run.manifest = {"response_body": CANARY}
        run.save(update_fields=["manifest", "modified"])
        object_state = replication.runs.get(pk=run.pk).object_states.create(
            key=CANARY,
            destination_key=CANARY,
            error=json.dumps(
                {
                    "code": "LIGHTSAIL_TIMEOUT",
                    "message": CANARY,
                    "status": "timeout",
                    "retryable": True,
                    "correlation_id": "corr-1",
                }
            ),
        )
        restore = replication.restore_runs.create(
            idempotency_key="restore-canary",
            status=CoreLightsailBucketRestoreRun.Status.RUNNING,
            error=json.dumps(
                {
                    "code": "LIGHTSAIL_AUTH_FAILED",
                    "message": CANARY,
                    "status": "auth_failed",
                    "retryable": False,
                    "correlation_id": "corr-2",
                }
            ),
            manifest={"object_key": CANARY},
            completed_objects=[CANARY],
        )

        run_data = CoreLightsailBucketReplicationRunSerializer(run).data
        object_data = CoreLightsailBucketReplicationObjectSerializer(object_state).data
        restore_data = CoreLightsailBucketRestoreRunSerializer(restore).data
        replication_data = CoreLightsailBucketReplicationReadSerializer(replication).data
        write_data = CoreLightsailBucketReplicationWriteSerializer(replication).data
        serialized = json.dumps(
            [run_data, object_data, restore_data, replication_data, write_data],
            default=str,
        )

        self.assertNotIn(CANARY, serialized)
        self.assertNotIn("manifest", run_data)
        self.assertNotIn("key", object_data)
        self.assertNotIn("destination_version_id", object_data)
        self.assertNotIn("completed_objects", restore_data)
        self.assertEqual(run_data["error_code"], "LIGHTSAIL_WORKER_FAILURE")
        self.assertEqual(object_data["error_code"], "LIGHTSAIL_TIMEOUT")
        self.assertEqual(restore_data["error_code"], "LIGHTSAIL_AUTH_FAILED")
        self.assertNotIn("source_bucket_name", replication_data)
        self.assertNotIn("source_endpoint_url", replication_data)
        self.assertNotIn("source_bucket_name", write_data)
        self.assertNotIn("source_endpoint_url", write_data)

        factory = APIRequestFactory()
        request = factory.get(
            f"/cloud/lightsail_bucket_replications/{replication.id}/runs/{run.id}/objects/"
        )
        force_authenticate(request, user=self.user)
        view = CoreLightsailBucketReplicationView.as_view({"get": "objects"})
        response = view(request, pk=replication.id, run_pk=run.id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("results", response.data)
        self.assertNotIn(CANARY, json.dumps(response.data, default=str))

    def test_validate_api_returns_safe_failure_contract(self):
        replication = self._replication()
        factory = APIRequestFactory()
        request = factory.post(
            "/cloud/lightsail_bucket_replications/1/validate/",
            {},
            format="json",
        )
        force_authenticate(request, user=self.user)
        view = CoreLightsailBucketReplicationView.as_view({"post": "validate"})
        with mock.patch(
            "apps._tasks.integration.lightsail_bucket.build_source_client",
            side_effect=_provider_error("AccessDenied", 403),
        ):
            response = view(request, pk=replication.id)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn(CANARY, json.dumps(response.data))
        self.assertEqual(response.data["error"]["code"], "LIGHTSAIL_AUTH_FAILED")
        self.assertFalse(response.data["error"]["retryable"])
