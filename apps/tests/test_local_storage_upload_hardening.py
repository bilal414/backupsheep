import copy
import hashlib
import os
import stat
import tempfile
import uuid
from types import SimpleNamespace
from unittest import TestCase, mock

from apps._tasks.exceptions import StorageLocalUploadFailedError
from apps._tasks.integration.storage import local as local_storage_module
from apps._tasks.integration.storage.local import (
    LOCAL_OBJECT_METADATA_KEY,
    storage_local,
)
from apps._tasks.integration.storage.lease import StorageUploadLeaseLost
from apps.console.backup.models import CoreWebsiteBackupStoragePoints


class _LocalStorageConfig:
    def __init__(self, root, path="backups"):
        self.root = os.path.realpath(root)
        self.path = path

    def storage_root(self):
        return self.root

    def resolve_path(self):
        target = os.path.realpath(os.path.join(self.root, self.path or ""))
        if target != self.root and not target.startswith(self.root + os.sep):
            raise ValueError("/sensitive/server/storage path escaped")
        return target

    def prepare_directory(self):
        target = self.resolve_path()
        os.makedirs(target, mode=0o700, exist_ok=True)
        return target


class _Backup:
    def __init__(self, identifier, events):
        self.uuid = identifier
        self.uuid_str = identifier
        self.attempt_no = 3
        self.type = "website"
        self.events = events

    def record_artifact_integrity(self, **kwargs):
        self.events.append(("artifact", copy.deepcopy(kwargs)))


class _Point:
    Status = CoreWebsiteBackupStoragePoints.Status

    def __init__(self, root, identifier, events, path="backups"):
        self.backup = _Backup(identifier, events)
        self.storage = SimpleNamespace(
            storage_local=_LocalStorageConfig(root, path=path)
        )
        self.storage_file_id = None
        self.metadata = {}
        self.status = self.Status.UPLOAD_IN_PROGRESS
        self.events = events

    def save(self):
        self.events.append(("save", self.status, copy.deepcopy(self.metadata)))


class LocalStorageUploadHardeningTests(TestCase):
    def setUp(self):
        os.makedirs("_storage", exist_ok=True)
        self.identifier = f"local-hardening-{uuid.uuid4().hex}"
        self.source = os.path.join("_storage", f"{self.identifier}.zip")
        self.addCleanup(lambda: os.path.exists(self.source) and os.remove(self.source))

    def _write_source(self, payload):
        with open(self.source, "wb") as source:
            source.write(payload)
        return hashlib.sha256(payload).hexdigest()

    def _point(self, root, events=None, path="backups"):
        return _Point(root, self.identifier, events if events is not None else [], path)

    @staticmethod
    def _target(root, path, identifier):
        return os.path.join(os.path.realpath(root), path, f"{identifier}.zip")

    def test_upload_is_private_fsynced_atomic_and_records_artifact_before_complete(self):
        payload = b"local-upload" * 1000
        checksum = self._write_source(payload)
        events = []

        with self.subTest("filesystem commit"):
            with mock.patch.object(
                local_storage_module.os,
                "replace",
                wraps=local_storage_module.os.replace,
            ) as atomic_replace, mock.patch.object(
                local_storage_module.os,
                "fsync",
                wraps=local_storage_module.os.fsync,
            ) as fsync:
                with tempfile.TemporaryDirectory() as root:
                    point = self._point(root, events)
                    storage_local(point)
                    target = self._target(root, "backups", self.identifier)

                    self.assertEqual(atomic_replace.call_count, 1)
                    self.assertGreaterEqual(fsync.call_count, 2)
                    self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
                    with open(target, "rb") as stored:
                        self.assertEqual(stored.read(), payload)

        state = point.metadata[LOCAL_OBJECT_METADATA_KEY]
        self.assertEqual(state["object_key"], f"backups/{self.identifier}.zip")
        self.assertEqual(state["sha256"], checksum)
        self.assertEqual(state["size_bytes"], len(payload))
        self.assertEqual(state["checksum_algorithm"], "sha256")
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)

        artifact_index = next(i for i, event in enumerate(events) if event[0] == "artifact")
        complete_save_index = next(
            i
            for i, event in enumerate(events)
            if event[0] == "save" and event[1] == point.Status.UPLOAD_COMPLETE
        )
        self.assertLess(artifact_index, complete_save_index)
        artifact = events[artifact_index][1]
        self.assertEqual(artifact["role"], "destination")
        self.assertEqual(artifact["object_key"], f"backups/{self.identifier}.zip")
        self.assertEqual(artifact["byte_count"], len(payload))
        self.assertEqual(artifact["checksum_value"], checksum)

    def test_long_hash_and_copy_loops_pulse_the_bound_upload_lease(self):
        payload = b"lease-heartbeat-checkpoints"
        self._write_source(payload)

        with tempfile.TemporaryDirectory() as root:
            point = self._point(root)
            point._renew_upload_lease = mock.Mock()
            with mock.patch.object(local_storage_module, "CHUNK_SIZE", 4):
                storage_local(point)

        # Source identity, atomic copy, and destination identity all checkpoint.
        self.assertGreaterEqual(point._renew_upload_lease.call_count, 3)

    def test_lease_loss_is_preserved_for_the_task_retry_boundary(self):
        self._write_source(b"lease-loss")

        with tempfile.TemporaryDirectory() as root:
            point = self._point(root)
            point._renew_upload_lease = mock.Mock(
                side_effect=StorageUploadLeaseLost("lost")
            )

            with self.assertRaises(StorageUploadLeaseLost):
                storage_local(point)

        self.assertEqual(point.status, point.Status.UPLOAD_IN_PROGRESS)

    def test_retry_adopts_target_when_final_database_response_is_lost(self):
        payload = b"adopt-after-lost-response"
        checksum = self._write_source(payload)
        events = []

        class LostFinalSavePoint(_Point):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.lose_response = True

            def save(self):
                if self.status == self.Status.UPLOAD_COMPLETE and self.lose_response:
                    self.lose_response = False
                    raise OSError("database response lost at /srv/backupsheep/db.sock")
                super().save()

        with tempfile.TemporaryDirectory() as root:
            point = LostFinalSavePoint(root, self.identifier, events)
            with self.assertRaises(StorageLocalUploadFailedError) as first_error:
                storage_local(point)
            self.assertNotIn(root, str(first_error.exception))
            self.assertNotIn("db.sock", str(first_error.exception))

            # The target and committed state survived the lost response.  Remove
            # the source to prove the retry adopts verified durable destination
            # state instead of trying to start a second upload.
            os.remove(self.source)
            storage_local(point)

            target = self._target(root, "backups", self.identifier)
            self.assertEqual(point.status, point.Status.UPLOAD_COMPLETE)
            self.assertEqual(point.metadata[LOCAL_OBJECT_METADATA_KEY]["sha256"], checksum)
            with open(target, "rb") as stored:
                self.assertEqual(stored.read(), payload)

    def test_existing_committed_target_with_wrong_content_fails_without_overwrite(self):
        payload = b"expected-content"
        checksum = self._write_source(payload)

        with tempfile.TemporaryDirectory() as root:
            point = self._point(root)
            target = self._target(root, "backups", self.identifier)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as existing:
                existing.write(b"different-content")
            point.storage_file_id = target
            point.metadata = {
                LOCAL_OBJECT_METADATA_KEY: {
                    "object_key": f"backups/{self.identifier}.zip",
                    "sha256": checksum,
                    "size_bytes": len(payload),
                    "checksum_algorithm": "sha256",
                    "phase": "committed",
                }
            }

            with self.assertRaises(StorageLocalUploadFailedError) as error:
                storage_local(point)

            self.assertNotIn(root, str(error.exception))
            self.assertNotIn(target, str(error.exception))
            self.assertEqual(point.status, point.Status.UPLOAD_IN_PROGRESS)
            with open(target, "rb") as existing:
                self.assertEqual(existing.read(), b"different-content")

    def test_corruption_after_atomic_replace_is_detected(self):
        payload = b"must-be-verified"
        self._write_source(payload)
        real_replace = local_storage_module.os.replace

        def replace_then_corrupt(source, target):
            real_replace(source, target)
            with open(target, "wb") as corrupted:
                corrupted.write(b"corrupt")

        with tempfile.TemporaryDirectory() as root:
            point = self._point(root)
            with mock.patch.object(
                local_storage_module.os, "replace", side_effect=replace_then_corrupt
            ):
                with self.assertRaises(StorageLocalUploadFailedError):
                    storage_local(point)
            self.assertNotEqual(point.status, point.Status.UPLOAD_COMPLETE)

    def test_path_errors_are_safe_and_do_not_expose_absolute_paths(self):
        self._write_source(b"path-safety")
        with tempfile.TemporaryDirectory() as root:
            point = self._point(root, path="../outside")
            with self.assertRaises(StorageLocalUploadFailedError) as error:
                storage_local(point)
            self.assertNotIn(root, str(error.exception))
            self.assertNotIn("outside", str(error.exception))
            self.assertNotIn("sensitive", str(error.exception))

    def test_source_missing_preserves_file_not_found_status(self):
        with tempfile.TemporaryDirectory() as root:
            point = self._point(root)
            storage_local(point)
            self.assertEqual(
                point.status,
                point.Status.UPLOAD_FAILED_FILE_NOT_FOUND,
            )
