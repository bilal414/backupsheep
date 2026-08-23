"""Renewable, fenced execution leases for all restore workflows."""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from sentry_sdk import capture_exception

from apps.console.utils.execution_history import (
    begin_public_attempt,
    update_public_attempt,
)


class RestoreAlreadyTerminal(RuntimeError):
    pass


class RestoreLeaseBusy(RuntimeError):
    def __init__(self, retry_after=30):
        self.retry_after = max(5, int(retry_after))
        super().__init__("Another worker owns this restore execution.")


class RestoreLeaseLost(RuntimeError):
    pass


SCHEDULED_RETRY_RESERVED_UNTIL = "scheduled_retry_reserved_until"


class DurableRestoreLease:
    def __init__(self, restore, *, phase, task_id="", worker_name=""):
        self.model = restore.__class__
        self.restore_id = restore.pk
        self.phase = str(phase or "restore")[:64]
        self.task_id = str(task_id or "")[:255]
        self.owner = (
            f"restore:{self.task_id or 'delivery'}:{os.getpid()}:{uuid.uuid4().hex}"
        )[:255]
        self.worker_name = str(worker_name or "")[:255]
        self.lease_seconds = max(
            30, int(getattr(settings, "RESTORE_WORKER_LEASE_SECONDS", 180))
        )
        requested_heartbeat = max(
            5, int(getattr(settings, "RESTORE_WORKER_HEARTBEAT_SECONDS", 30))
        )
        self.heartbeat_seconds = min(
            requested_heartbeat, max(5, self.lease_seconds // 3)
        )
        self.token = None
        self.restore = None
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = None

    @staticmethod
    def _terminal_statuses(restore):
        statuses = {restore.Status.COMPLETE, restore.Status.FAILED}
        cancelled = getattr(restore.Status, "CANCELLED", None)
        if cancelled is not None:
            statuses.add(cancelled)
        return statuses

    def claim(self):
        now = timezone.now()
        with transaction.atomic():
            restore = self.model.objects.select_for_update().get(pk=self.restore_id)
            if restore.status in self._terminal_statuses(restore):
                raise RestoreAlreadyTerminal()
            metadata = dict(restore.execution_metadata or {})
            reservation_consumable = False
            reserved_until_value = metadata.get(
                "recovery_dispatch_reserved_until"
            )
            if isinstance(reserved_until_value, str):
                reserved_until = parse_datetime(reserved_until_value)
            else:
                reserved_until = None
            expected_recovery_task_id = (
                f"recover-restore-{self.model.__name__}-{self.restore_id}"
            )
            if restore.next_retry_at and restore.next_retry_at > now:
                reservation_consumable = (
                    self.task_id == expected_recovery_task_id
                    and reserved_until is not None
                    and reserved_until == restore.next_retry_at
                )
            if (
                restore.next_retry_at
                and restore.next_retry_at > now
                and not reservation_consumable
            ):
                raise RestoreLeaseBusy(
                    min((restore.next_retry_at - now).total_seconds(), 300)
                )
            if (
                restore.lease_token
                and restore.lease_expires_at
                and restore.lease_expires_at > now
            ):
                raise RestoreLeaseBusy(
                    min((restore.lease_expires_at - now).total_seconds(), 60)
                )

            if reservation_consumable:
                metadata.pop("recovery_dispatch_reserved_until", None)
                metadata["recovery_claimed_at"] = now.isoformat()
                metadata["recovery_claimed_task_id"] = self.task_id
            # An orderly task retry writes this reservation before publishing its
            # countdown delivery.  Any delivery that successfully claims the row
            # consumes it; a lost publish leaves it for the recovery sweep to
            # reclaim after the bounded reservation expires.
            metadata.pop(SCHEDULED_RETRY_RESERVED_UNTIL, None)
            if restore.lease_owner or restore.lease_token:
                if restore.attempt_count:
                    metadata = update_public_attempt(
                        metadata,
                        attempt_no=restore.attempt_count,
                        correlation_id=restore.correlation_id,
                        stage=restore.execution_phase or self.phase,
                        retry_decision="lease_lost",
                        now=now,
                        finished=True,
                    )
                takeovers = list(metadata.get("stale_lease_takeovers") or [])
                previous_owner = str(restore.lease_owner or "")
                previous_token = str(restore.lease_token or "")
                takeover = {
                    "detected_at": now.isoformat(),
                    "previous_owner": restore.lease_owner,
                    "previous_phase": restore.execution_phase,
                    "previous_expires_at": (
                        restore.lease_expires_at.isoformat()
                        if restore.lease_expires_at
                        else None
                    ),
                }
                if previous_owner or previous_token:
                    # Restore work files are fence-scoped so a stale worker's
                    # finally block cannot remove a replacement's files. Keep
                    # the non-secret derived suffix so the replacement can
                    # later remove only the crashed generation it superseded.
                    takeover["previous_work_suffix"] = hashlib.sha256(
                        f"{previous_owner}|{previous_token}".encode("utf-8")
                    ).hexdigest()[:16]
                takeovers.append(takeover)
                metadata["stale_lease_takeovers"] = takeovers[-20:]

            self.token = uuid.uuid4()
            restore.execution_metadata = metadata
            restore.execution_phase = self.phase
            restore.lease_owner = self.owner
            restore.lease_token = self.token
            restore.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
            restore.heartbeat_at = now
            restore.attempt_count += 1
            restore.execution_metadata = begin_public_attempt(
                restore.execution_metadata,
                attempt_no=restore.attempt_count,
                correlation_id=restore.correlation_id,
                stage=self.phase,
                now=now,
            )
            # The root restore task id is the durable request identity. Poll and
            # recovery deliveries have their own lease owner and must not replace
            # that identity; it is used for correlation and idempotent adoption.
            if not restore.celery_task_id and self.task_id:
                restore.celery_task_id = self.task_id
            restore.status = restore.Status.IN_PROGRESS
            restore.last_error_code = ""
            restore.error = None
            restore.next_retry_at = None
            restore.save()

        self.restore = restore.bind_execution_fence(self.owner, self.token)
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"restore-lease-{self.restore_id}",
            daemon=True,
        )
        self._thread.start()
        return self.restore

    def _heartbeat_once(self):
        now = timezone.now()
        updated = self.model.objects.filter(
            pk=self.restore_id,
            lease_owner=self.owner,
            lease_token=self.token,
            lease_expires_at__gt=now,
        ).update(
            heartbeat_at=now,
            lease_expires_at=now + timedelta(seconds=self.lease_seconds),
        )
        if updated != 1:
            self._lost.set()
            return False
        return True

    def _heartbeat_loop(self):
        close_old_connections()
        try:
            while not self._stop.wait(self.heartbeat_seconds):
                try:
                    if not self._heartbeat_once():
                        return
                except Exception as error:
                    capture_exception(error)
        finally:
            close_old_connections()

    def ensure_owned(self):
        if self._lost.is_set() or not self.token:
            raise RestoreLeaseLost("Restore execution lease ownership was lost.")
        if not self.model.objects.filter(
            pk=self.restore_id,
            lease_owner=self.owner,
            lease_token=self.token,
            lease_expires_at__gt=timezone.now(),
        ).exists():
            self._lost.set()
            raise RestoreLeaseLost("Restore execution lease ownership was lost.")

    def checkpoint(
        self,
        phase,
        *,
        metadata=None,
        progress_completed=None,
        progress_total=None,
        progress_unit=None,
    ):
        self.ensure_owned()
        self.restore.execution_phase = str(phase or "")[:64]
        values = dict(self.restore.execution_metadata or {})
        if metadata:
            values.update(dict(metadata))
        values = update_public_attempt(
            values,
            attempt_no=self.restore.attempt_count,
            correlation_id=self.restore.correlation_id,
            stage=self.restore.execution_phase,
            now=timezone.now(),
        )
        self.restore.execution_metadata = values
        if progress_completed is not None:
            self.restore.progress_completed = max(
                self.restore.progress_completed, int(progress_completed)
            )
        if progress_total is not None:
            self.restore.progress_total = int(progress_total)
        if progress_unit is not None:
            self.restore.progress_unit = str(progress_unit)[:32]
        self.restore.save()

    def release(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(1, self.heartbeat_seconds + 1))
        if self.token:
            self.model.objects.filter(
                pk=self.restore_id,
                lease_owner=self.owner,
                lease_token=self.token,
            ).update(
                lease_owner="",
                lease_token=None,
                lease_expires_at=None,
            )
