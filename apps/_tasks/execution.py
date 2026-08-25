"""Durable worker leases and local-artifact commit records.

Celery delivery is not execution ownership: a message may be redelivered while the
first worker is alive, and a process can disappear after creating an archive but before
publishing its upload chord.  This module keeps a short database lease alive from a
separate heartbeat thread and records a verified source artifact before downstream work
is allowed to consume it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import uuid

from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone
from sentry_sdk import capture_exception

from apps.console.utils.models import BackupExecutionLeaseLostError


class ExecutionLeaseLost(BackupExecutionLeaseLostError):
    """Raised when a stale worker has been fenced by a replacement delivery."""


class DurableExecutionLease:
    def __init__(self, backup, *, phase, task_id=None):
        self.backup = backup
        self.phase = str(phase)
        task_id = str(task_id or backup.celery_task_id or "backup")
        self.owner = f"{task_id}:{os.getpid()}:{uuid.uuid4().hex[:12]}"[:255]
        self.lease_seconds = max(
            30, int(getattr(settings, "BACKUP_WORKER_LEASE_SECONDS", 180))
        )
        configured_heartbeat = int(
            getattr(settings, "BACKUP_WORKER_HEARTBEAT_SECONDS", 30)
        )
        self.heartbeat_seconds = max(
            5, min(configured_heartbeat, max(5, self.lease_seconds // 3))
        )
        self.state = None
        self.token = None
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = None

    @property
    def acquired(self):
        return self.token is not None

    def __enter__(self):
        self.state = self.backup.claim_execution(
            lease_owner=self.owner,
            phase=self.phase,
            lease_seconds=self.lease_seconds,
            increment_attempt=False,
        )
        if self.state is None:
            return self
        self.token = self.state.lease_token
        self.backup.bind_execution_fence(self.owner, self.token)
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"backup-lease-{self.backup.pk}",
            daemon=True,
        )
        self._thread.start()
        return self

    def _heartbeat_loop(self):
        model = self.backup.__class__
        backup_id = self.backup.pk
        while not self._stop.wait(self.heartbeat_seconds):
            close_old_connections()
            try:
                backup = model.objects.get(pk=backup_id)
                state = backup.heartbeat_execution(
                    lease_owner=self.owner,
                    lease_token=self.token,
                    lease_seconds=self.lease_seconds,
                )
                if state is None:
                    self._lost.set()
                    return
            except Exception as error:
                # A transient DB outage is not itself proof that another worker owns
                # the lease. Keep trying; once connectivity returns, the token check
                # will fence this worker if a recovery delivery took over.
                capture_exception(error)
            finally:
                close_old_connections()

    def ensure_owned(self):
        if not self.acquired or self._lost.is_set():
            raise ExecutionLeaseLost(
                "Backup execution ownership changed while the worker was running."
            )
        state = self.backup.heartbeat_execution(
            lease_owner=self.owner,
            lease_token=self.token,
            lease_seconds=self.lease_seconds,
        )
        if state is None:
            self._lost.set()
            raise ExecutionLeaseLost(
                "Backup execution ownership changed while the worker was running."
            )
        self.state = state
        return state

    def progress(
        self,
        completed,
        total=None,
        unit="bytes",
        *,
        metadata_updates=None,
    ):
        self.ensure_owned()
        state = self.backup.heartbeat_execution(
            lease_owner=self.owner,
            lease_token=self.token,
            lease_seconds=self.lease_seconds,
            progress_completed=completed,
            progress_total=total,
            progress_unit=unit,
            metadata_updates=metadata_updates,
        )
        if state is None:
            self._lost.set()
            raise ExecutionLeaseLost(
                "Backup execution ownership changed while progress was recorded."
            )
        self.state = state

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1, self.heartbeat_seconds + 1))
        try:
            if not self.acquired:
                return False
            lease_error = bool(
                exc_type
                and issubclass(exc_type, BackupExecutionLeaseLostError)
            )
            if lease_error or self._lost.is_set():
                self.backup.record_execution_error(
                    code="WORKER_LEASE_LOST",
                    message=str(exc_value or ""),
                    lease_owner=self.owner,
                    lease_token=self.token,
                )
            self.backup.release_execution(
                lease_owner=self.owner,
                lease_token=self.token,
                phase=self.phase,
            )
        finally:
            self.backup.unbind_execution_fence()
        return False


def durable_execution_lease(backup, *, phase, task_id=None):
    return DurableExecutionLease(backup, phase=phase, task_id=task_id)


def _file_identity(path):
    digest = hashlib.sha256()
    byte_count = 0
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
    return byte_count, digest.hexdigest()


def _verify_zip_crc_bounded(archive_path):
    """Validate ZIP structure and member CRCs without loading its directory in Python."""

    timeout = max(
        1,
        min(
            int(
                getattr(
                    settings,
                    "SOURCE_ARCHIVE_VERIFY_TIMEOUT_SECONDS",
                    12 * 3600,
                )
            ),
            24 * 3600,
        ),
    )
    try:
        result = subprocess.run(
            ["unzip", "-tqq", archive_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("The local backup archive validation timed out.") from error
    except OSError as error:
        raise ValueError("The local backup archive could not be verified.") from error
    if result.returncode != 0:
        raise ValueError("The local backup archive is not a valid ZIP file.")


def verify_and_commit_source_artifact(backup):
    """Validate the local ZIP and durably commit its exact identity."""
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
    archive_path = os.path.realpath(
        os.path.join(storage_dir, f"{backup.uuid_str}.zip")
    )
    if getattr(
        settings, "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE", "legacy-only"
    ) == "bse1" or backup.artifact_records.filter(
        artifact_format="bse1"
    ).exists():
        # A durable BSE1 ledger always wins over runtime policy so a retry can
        # never reinterpret encrypted bytes as a legacy ZIP.  The helper also
        # handles the post-commit retry where the plaintext ZIP is already gone.
        from apps._tasks.artifact_encryption import seal_or_validate_source_artifact

        return seal_or_validate_source_artifact(
            backup,
            archive_path,
            zip_verifier=_verify_zip_crc_bounded,
        )
    if (
        archive_path == storage_dir
        or os.path.commonpath([storage_dir, archive_path]) != storage_dir
        or not os.path.isfile(archive_path)
    ):
        raise FileNotFoundError("The local backup archive is missing.")
    if os.path.getsize(archive_path) <= 0:
        raise ValueError("The local backup archive is empty.")
    _verify_zip_crc_bounded(archive_path)

    byte_count, checksum = _file_identity(archive_path)
    verified_at = timezone.now()
    existing = backup.artifact_records.filter(
        role="source", storage__isnull=True
    ).first()
    if existing and existing.verified_at and (
        existing.byte_count != byte_count
        or existing.checksum_algorithm != "sha256"
        or existing.checksum_value != checksum
    ):
        raise ValueError(
            "The local backup archive no longer matches its committed identity."
        )
    artifact = backup.record_artifact_integrity(
        role="source",
        object_key=os.path.basename(archive_path),
        byte_count=byte_count,
        checksum_algorithm="sha256",
        checksum_value=checksum,
        verified_at=verified_at,
        metadata={"archive_format": "zip", "verification": "zip_crc_sha256"},
    )

    # The local commit marker makes an accepted archive distinguishable from a
    # partially written ZIP after a hard reboot, even before PostgreSQL is queried.
    manifest_path = os.path.join(storage_dir, f"{backup.uuid_str}.manifest.json")
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path, "r") as source:
                committed = json.load(source)
            committed_checksum = (committed.get("checksum") or {}).get("value")
            if (
                int(committed.get("bytes", -1)) != byte_count
                or committed_checksum != checksum
            ):
                raise ValueError(
                    "The local backup archive does not match its commit marker."
                )
        except (OSError, TypeError, json.JSONDecodeError) as error:
            raise ValueError(
                "The local backup artifact commit marker is invalid."
            ) from error
    temporary_path = f"{manifest_path}.{uuid.uuid4().hex}.tmp"
    manifest = {
        "schema": 1,
        "backup_id": backup.pk,
        "backup_uuid": backup.uuid_str,
        "archive": os.path.basename(archive_path),
        "bytes": byte_count,
        "checksum": {"algorithm": "sha256", "value": checksum},
        "verified_at": verified_at.isoformat(),
    }
    descriptor = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w") as destination:
            json.dump(manifest, destination, sort_keys=True, separators=(",", ":"))
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, manifest_path)
    except Exception:
        try:
            os.remove(temporary_path)
        except FileNotFoundError:
            pass
        raise
    return artifact
