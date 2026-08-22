"""Renewable, fenced leases for one backup storage destination."""

from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone
from sentry_sdk import capture_exception


class StorageUploadAlreadyComplete(RuntimeError):
    pass


class StorageUploadLeaseBusy(RuntimeError):
    def __init__(self, retry_after=30):
        self.retry_after = max(5, int(retry_after))
        super().__init__("Another worker owns this storage upload.")


class StorageUploadLeaseLost(RuntimeError):
    pass


class StorageCleanupNotEligible(RuntimeError):
    pass


class DurableStorageUploadLease:
    """Own and renew a storage-point lease until the provider call returns.

    The random token is a fencing token, not merely a mutex.  A stale worker's
    model instance is bound to it, so every adapter save fails after takeover.
    """

    def __init__(self, point, *, task_id="", worker_name="", purpose="upload"):
        self.model = point.__class__
        self.point_id = point.pk
        if purpose not in {"upload", "multipart_cleanup"}:
            raise ValueError("Unknown storage lease purpose.")
        self.purpose = purpose
        self.task_id = str(task_id or "")[:255]
        self.owner = (
            f"storage-{purpose}:{self.task_id or 'delivery'}:"
            f"{os.getpid()}:{uuid.uuid4().hex}"
        )[:255]
        self.worker_name = str(worker_name or "")[:255]
        self.lease_seconds = max(
            30, int(getattr(settings, "BACKUP_STORAGE_LEASE_SECONDS", 180))
        )
        configured_heartbeat = max(
            5, int(getattr(settings, "BACKUP_STORAGE_HEARTBEAT_SECONDS", 30))
        )
        self.heartbeat_seconds = min(
            configured_heartbeat, max(5, self.lease_seconds // 3)
        )
        self.token = None
        self.point = None
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = None
        self._last_heartbeat_monotonic = None

    def claim(self):
        now = timezone.now()
        with transaction.atomic():
            point = self.model.objects.select_for_update().get(pk=self.point_id)
            if point.status == point.Status.UPLOAD_COMPLETE:
                raise StorageUploadAlreadyComplete()
            if self.purpose == "multipart_cleanup":
                terminal_names = (
                    "UPLOAD_FAILED",
                    "UPLOAD_FAILED_STORAGE_LIMIT",
                    "UPLOAD_FAILED_FILE_NOT_FOUND",
                    "UPLOAD_TIME_LIMIT_REACHED",
                    "STORAGE_VALIDATION_FAILED",
                    "CANCELLED",
                )
                terminal_statuses = {
                    value
                    for value in (
                        getattr(point.Status, name, None)
                        for name in terminal_names
                    )
                    if value is not None
                }
                if point.status not in terminal_statuses:
                    raise StorageCleanupNotEligible(
                        "Storage point is not terminal cleanup state."
                    )
            if (
                point.upload_lease_token
                and point.upload_lease_expires_at
                and point.upload_lease_expires_at > now
            ):
                retry_after = (
                    point.upload_lease_expires_at - now
                ).total_seconds()
                raise StorageUploadLeaseBusy(min(retry_after, 60))

            metadata = dict(point.metadata or {})
            execution_key = (
                "_multipart_cleanup_execution"
                if self.purpose == "multipart_cleanup"
                else "_upload_execution"
            )
            execution = dict(metadata.get(execution_key) or {})
            if point.upload_lease_owner or point.upload_lease_token:
                takeovers = list(execution.get("stale_lease_takeovers") or [])
                takeovers.append(
                    {
                        "detected_at": now.isoformat(),
                        "previous_owner": point.upload_lease_owner,
                        "previous_expires_at": (
                            point.upload_lease_expires_at.isoformat()
                            if point.upload_lease_expires_at
                            else None
                        ),
                    }
                )
                execution["stale_lease_takeovers"] = takeovers[-20:]
            self.token = uuid.uuid4()
            execution.update(
                {
                    "phase": self.purpose,
                    "claimed_at": now.isoformat(),
                    "worker": self.worker_name,
                }
            )
            metadata[execution_key] = execution
            point.metadata = metadata
            point.upload_lease_owner = self.owner
            point.upload_lease_token = self.token
            point.upload_lease_expires_at = now + timedelta(
                seconds=self.lease_seconds
            )
            point.upload_heartbeat_at = now
            if self.purpose == "upload":
                point.upload_attempt_count += 1
                point.celery_task_id = self.task_id or point.celery_task_id
                point.status = point.Status.UPLOAD_IN_PROGRESS
                point.last_error_code = ""
                point.last_error_message = ""
                point.save()
            else:
                point.save(
                    update_fields=[
                        "metadata",
                        "upload_lease_owner",
                        "upload_lease_token",
                        "upload_lease_expires_at",
                        "upload_heartbeat_at",
                        "modified",
                    ]
                )

        self.point = point.bind_upload_fence(self.owner, self.token)
        self._last_heartbeat_monotonic = time.monotonic()
        # Provider adapters normally rely on the background heartbeat. Long local
        # filesystem reads also pulse from the task thread so a worker runtime that
        # cannot schedule the helper thread cannot silently expire its own fence.
        self.point._renew_upload_lease = self.heartbeat_if_due
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"storage-lease-{self.point_id}",
            daemon=True,
        )
        self._thread.start()
        return self.point

    def _heartbeat_once(self):
        now = timezone.now()
        updated = self.model.objects.filter(
            pk=self.point_id,
            upload_lease_owner=self.owner,
            upload_lease_token=self.token,
            upload_lease_expires_at__gt=now,
        ).update(
            upload_heartbeat_at=now,
            upload_lease_expires_at=now + timedelta(seconds=self.lease_seconds),
        )
        if updated != 1:
            self._lost.set()
            return False
        self._last_heartbeat_monotonic = time.monotonic()
        return True

    def heartbeat_if_due(self):
        """Renew from the task thread when a long adapter loop reaches a checkpoint."""
        if self._lost.is_set() or not self.token:
            raise StorageUploadLeaseLost("Storage upload lease ownership was lost.")
        now = time.monotonic()
        if (
            self._last_heartbeat_monotonic is not None
            and now - self._last_heartbeat_monotonic < self.heartbeat_seconds
        ):
            return
        if not self._heartbeat_once():
            raise StorageUploadLeaseLost("Storage upload lease ownership was lost.")

    def _heartbeat_loop(self):
        close_old_connections()
        try:
            while not self._stop.wait(self.heartbeat_seconds):
                try:
                    if not self._heartbeat_once():
                        return
                except Exception as error:
                    # A temporary DB outage is captured, but the worker is never
                    # allowed to revive an expired lease when connectivity returns.
                    capture_exception(error)
        finally:
            close_old_connections()

    def ensure_owned(self):
        if self._lost.is_set() or not self.token:
            raise StorageUploadLeaseLost("Storage upload lease ownership was lost.")
        now = timezone.now()
        if not self.model.objects.filter(
            pk=self.point_id,
            upload_lease_owner=self.owner,
            upload_lease_token=self.token,
            upload_lease_expires_at__gt=now,
        ).exists():
            self._lost.set()
            raise StorageUploadLeaseLost("Storage upload lease ownership was lost.")

    def release(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(1, self.heartbeat_seconds + 1))
        if self.token:
            self.model.objects.filter(
                pk=self.point_id,
                upload_lease_owner=self.owner,
                upload_lease_token=self.token,
            ).update(
                upload_lease_owner="",
                upload_lease_token=None,
                upload_lease_expires_at=None,
            )
