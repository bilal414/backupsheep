import datetime
import json
import math
import os
import shutil
import uuid
import boto3
import humanfriendly
import pytz
from apps.api.v1.utils.http import requests
from django.conf import settings
import time
from celery import current_app
from django.db import transaction
from django.db.models import Q, Sum, Count
from django.utils import timezone
from sentry_sdk import capture_exception, capture_message

from apps.console.account.models import CoreAccount
from backupsheep.celery import app

from apps.console.connection.models import CoreAuthBasecamp
from apps.console.member.models import CoreMember
from apps.console.notification.models import CoreNotificationSlack
from apps.console.storage.models import CoreStorageType, CoreStorage, CoreStorageOneDrive, CoreStorageDropbox, \
    CoreStorageGoogleDrive
from apps.console.utils.models import UtilBackup
from slack_sdk import WebhookClient


@current_app.task(name="run_scheduled_backup", bind=True, ignore_result=True)
def run_scheduled_backup(self, schedule_id=None, occurrence_id=None):
    """Legacy fallback for already queued beat messages.

    The BackupSheep DatabaseScheduler now creates the durable outbox directly.
    This task remains compatible with messages emitted by older Beat processes,
    and accepts an explicit stable occurrence id for integrations that still
    choose to use the task hop.
    """
    from apps.console.node.models import CoreSchedule, CoreScheduleRun

    try:
        schedule = CoreSchedule.objects.get(
            id=schedule_id, status=CoreSchedule.Status.ACTIVE
        )
    except CoreSchedule.DoesNotExist:
        return

    request_id = str(
        occurrence_id
        or getattr(self.request, "id", "")
        or uuid.uuid4().hex
    )
    CoreScheduleRun.objects.get_or_create(
        schedule=schedule, request_id=request_id
    )
    from apps._tasks.backup_dispatch import create_backup_request

    create_backup_request(
        node=schedule.node,
        schedule=schedule,
        storage_ids=schedule.storage_ids,
        trigger="schedule",
        idempotency_key=(
            f"periodic-occurrence:{schedule.id}:{request_id}"
            if occurrence_id
            else f"celery-schedule:{schedule.id}:{request_id}"
        ),
    )


@current_app.task(
    name="resume_pending_backup_requests", bind=True, ignore_result=True
)
def resume_pending_backup_requests(self):
    """Republish durable requests lost before a backup worker claimed them."""
    from apps._tasks.backup_dispatch import publish_backup_request
    from apps._tasks.backup_dispatch import _backup_request_ineligible_q
    from apps.console.backup.models import CoreBackupRequest

    now = timezone.now()
    try:
        batch_size = int(
            getattr(settings, "BACKUP_REQUEST_RECOVERY_BATCH_SIZE", 100)
        )
    except (TypeError, ValueError):
        batch_size = 100
    # Keep one misconfigured deployment from selecting an unbounded outbox batch
    # on every beat tick. The per-row lease remains the concurrency boundary.
    batch_size = max(1, min(batch_size, 1000))
    lease_available = (
        Q(dispatch_lease_token__isnull=True)
        | Q(dispatch_lease_expires_at__isnull=True)
        | Q(dispatch_lease_expires_at__lte=now)
    )
    dispatch_due = Q(next_dispatch_at__isnull=True) | Q(next_dispatch_at__lte=now)
    candidates = list(
        CoreBackupRequest.objects.filter(
            status__in=(
                CoreBackupRequest.Status.PENDING,
                CoreBackupRequest.Status.DISPATCHED,
            )
        )
        .filter(lease_available)
        # Ineligible requests are selected even while their confirmed claim
        # timeout is in the future, so pausing/deleting a source terminalizes
        # the outbox on the next beat tick instead of waiting for the timeout.
        .filter(dispatch_due | _backup_request_ineligible_q())
        .order_by("next_dispatch_at", "created", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    for request_id in candidates:
        try:
            publish_backup_request(request_id)
        except CoreBackupRequest.DoesNotExist:
            continue
        except Exception as error:
            # One malformed/deleted row cannot stop recovery of the rest.
            capture_exception(error)


_CLOUD_BACKUP_MODELS = None
_LOCAL_BACKUP_MODELS = None


def _recovery_backup_models():
    """Load every backup model lazily to avoid the node/model import cycle."""
    global _CLOUD_BACKUP_MODELS, _LOCAL_BACKUP_MODELS
    if _CLOUD_BACKUP_MODELS is None:
        from apps.console.backup.models import (
            CoreAWSBackup,
            CoreAWSRDSBackup,
            CoreVultrDatabaseBackup,
            CoreDigitalOceanBackup,
            CoreGoogleCloudBackup,
            CoreHetznerBackup,
            CoreLightsailBackup,
            CoreOracleBackup,
            CoreOVHCABackup,
            CoreOVHEUBackup,
            CoreOVHUSBackup,
            CoreUpCloudBackup,
            CoreVultrBackup,
        )
        _CLOUD_BACKUP_MODELS = (
            CoreDigitalOceanBackup,
            CoreHetznerBackup,
            CoreUpCloudBackup,
            CoreOracleBackup,
            CoreOVHCABackup,
            CoreOVHEUBackup,
            CoreOVHUSBackup,
            CoreVultrBackup,
            CoreGoogleCloudBackup,
            CoreAWSBackup,
            CoreLightsailBackup,
            CoreAWSRDSBackup,
            CoreVultrDatabaseBackup,
        )
    if _LOCAL_BACKUP_MODELS is None:
        from apps.console.backup.models import (
            CoreBasecampBackup,
            CoreDatabaseBackup,
            CoreWebsiteBackup,
            CoreWordPressBackup,
        )
        _LOCAL_BACKUP_MODELS = (
            CoreWebsiteBackup,
            CoreDatabaseBackup,
            CoreWordPressBackup,
            CoreBasecampBackup,
        )
    return _CLOUD_BACKUP_MODELS, _LOCAL_BACKUP_MODELS


def _backup_control(backup):
    """Return mutable provider-independent recovery metadata."""
    metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
    metadata = dict(metadata)
    control = metadata.get("_backup_control")
    control = dict(control) if isinstance(control, dict) else {}
    return metadata, control


def _save_backup_control(backup, control, metadata=None, include_status=False):
    if metadata is None:
        metadata, _ = _backup_control(backup)
    metadata["_backup_control"] = control
    backup.metadata = metadata
    fields = ["metadata", "modified"]
    if include_status:
        fields.insert(0, "status")
    backup.save(update_fields=fields)


def _claim_backup_lease(backup, task_id, lease_name="recovery", lease_seconds=None):
    """Claim a fenced DB lease and mirror it into legacy JSON metadata.

    The dedicated execution row is authoritative. The JSON mirror remains during the
    rolling-upgrade window so workers from the previous release still see the lease.
    """
    lease_seconds = int(
        lease_seconds
        or (int(getattr(settings, "BACKUP_POLL_INTERVAL", 120)) + 30)
    )
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        if fresh.status not in UtilBackup.ACTIVE_STATUSES:
            return None
        metadata, control = _backup_control(fresh)
        now = time.time()
        lease_until_key = f"{lease_name}_lease_until"
        task_key = f"{lease_name}_task_id"
        token_key = f"{lease_name}_lease_token"
        try:
            active_until = float(control.get(lease_until_key) or 0)
        except (TypeError, ValueError):
            active_until = 0
        # A lease is exclusive even when a duplicate delivery carries the same
        # Celery id. Unknown provider outcomes retain the create lease until the
        # deterministic recovery lookup can safely take over; allowing the same id
        # here would let a recovery sweep enter a still-live provider call and issue
        # a second snapshot request.
        if active_until > now:
            return None

        state = fresh.claim_execution(
            lease_owner=task_id,
            phase=lease_name,
            lease_seconds=lease_seconds,
            increment_attempt=lease_name in {"create", "recovery"},
        )
        if state is None:
            return None

        # A pre-migration JSON lease that expired is still evidence of a worker loss.
        if (control.get(task_key) or control.get(lease_until_key)) and active_until <= now:
            reconciliation_metadata = dict(state.reconciliation_metadata or {})
            legacy_history = list(
                reconciliation_metadata.get("stale_legacy_lease_takeovers") or []
            )
            legacy_history.append(
                {
                    "detected_at": timezone.now().isoformat(),
                    "phase": lease_name,
                    "previous_owner": control.get(task_key),
                    "previous_expires_at": active_until or None,
                }
            )
            reconciliation_metadata["stale_legacy_lease_takeovers"] = legacy_history[-20:]
            state.reconciliation_metadata = reconciliation_metadata
            if state.reconciliation_state != state.ReconciliationState.MANUAL_REVIEW:
                state.reconciliation_state = state.ReconciliationState.REQUIRED
            state.reconciliation_reason = "stale_legacy_execution_lease"
            state.save(
                update_fields=[
                    "reconciliation_metadata",
                    "reconciliation_state",
                    "reconciliation_reason",
                    "modified",
                ]
            )

        control[task_key] = str(task_id)
        control[lease_until_key] = state.lease_expires_at.timestamp()
        control[token_key] = str(state.lease_token)
        _save_backup_control(fresh, control, metadata, include_status=True)
        return fresh


def _claim_cloud_poll(backup, task_id, interval):
    """Claim the poller lease and return a fresh backup row, or None if busy."""
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        if fresh.status not in UtilBackup.ACTIVE_STATUSES:
            return None
        metadata, control = _backup_control(fresh)
        now = time.time()
        state = fresh.get_execution_state(create=False)
        handoff_token = control.get("poll_handoff_lease_token")
        handoff_owned = bool(
            state is not None
            and control.get("poll_handoff_task_id") == str(task_id)
            and control.get("poll_task_id") == str(task_id)
            and state.lease_matches(
                task_id,
                handoff_token,
                phase="poll",
            )
        )
        if handoff_owned:
            # The recovery sweep reserves the DB lease before publishing so two
            # Beat deliveries cannot enqueue competing pollers.  Exactly one
            # delivered task consumes this handoff and continues under the same
            # fencing token.  A duplicate carrying the same Celery id arrives
            # after these fields are removed and is blocked by the live lease.
            control.pop("poll_handoff_task_id", None)
            control.pop("poll_handoff_lease_token", None)
            control.pop("recovery_task_id", None)
            control.pop("recovery_lease_until", None)
            control.pop("recovery_lease_token", None)
            _save_backup_control(fresh, control, metadata)
            return fresh
        try:
            active_until = float(control.get("poll_lease_until") or 0)
        except (TypeError, ValueError):
            active_until = 0
        try:
            next_poll_at = float(control.get("poll_next_run_at") or 0)
        except (TypeError, ValueError):
            next_poll_at = 0
        if active_until > now:
            # The lease covers the gap between publishing the next ETA message
            # and the recovery sweep taking over after a worker loss.  Once the
            # ETA is due, the scheduled successor is the rightful claimant and
            # must be allowed through; otherwise the first poll's five-minute
            # safety lease can swallow the next two-minute poll forever.
            if not next_poll_at or next_poll_at > now:
                return None

        state = fresh.claim_execution(
            lease_owner=task_id,
            phase="poll",
            lease_seconds=max(int(interval) * 2, 300),
        )
        if state is None:
            return None
        control.pop("poll_next_run_at", None)
        control.pop("poll_handoff_task_id", None)
        control.pop("poll_handoff_lease_token", None)
        control["poll_task_id"] = str(task_id)
        control["poll_lease_until"] = state.lease_expires_at.timestamp()
        control["poll_lease_token"] = str(state.lease_token)
        # A recovery message has reached a worker; its enqueue lease no longer
        # needs to block the real poller or the next recovery cycle.
        control.pop("recovery_task_id", None)
        control.pop("recovery_lease_until", None)
        control.pop("recovery_lease_token", None)
        if not control.get("started_at"):
            try:
                control["started_at"] = fresh.created.timestamp()
            except (AttributeError, TypeError, ValueError):
                control["started_at"] = now
        _save_backup_control(fresh, control, metadata)
        return fresh


def _mark_cloud_poll_handoff(backup, task_id):
    """Authorize one recovery poll delivery to consume its reserved lease.

    ``claim_execution`` intentionally rejects duplicate deliveries, even when
    they use the same Celery id.  The recovery sweep, however, must reserve the
    lease before publishing.  This one-use token bridges those two boundaries:
    the first delivered poller adopts the exact lease; all later deliveries are
    rejected until it expires or schedules its successor.
    """
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        if fresh.status not in UtilBackup.ACTIVE_STATUSES:
            return None
        metadata, control = _backup_control(fresh)
        state = fresh.get_execution_state(create=False)
        lease_token = control.get("poll_lease_token")
        if (
            state is None
            or control.get("poll_task_id") != str(task_id)
            or not state.lease_matches(task_id, lease_token, phase="poll")
        ):
            return None
        control["poll_handoff_task_id"] = str(task_id)
        control["poll_handoff_lease_token"] = str(lease_token)
        _save_backup_control(fresh, control, metadata)
        return fresh


def _release_backup_lease(backup, task_id, lease_name, lease_token=None):
    """Release a phase lease only when the releasing worker still owns it."""
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        metadata, control = _backup_control(fresh)
        task_key = f"{lease_name}_task_id"
        token_key = f"{lease_name}_lease_token"
        state = fresh.get_execution_state(create=False)
        token = lease_token or control.get(token_key)
        released = None
        if state is not None and token is not None:
            released = fresh.release_execution(
                lease_owner=task_id,
                lease_token=token,
                phase=lease_name,
            )
        legacy_owner_matches = control.get(task_key) == str(task_id)
        legacy_token_matches = not control.get(token_key) or str(
            control.get(token_key)
        ) == str(token or "")
        if legacy_owner_matches and legacy_token_matches and (
            state is None or released is not None
        ):
            control.pop(task_key, None)
            control.pop(f"{lease_name}_lease_until", None)
            control.pop(token_key, None)
            _save_backup_control(fresh, control, metadata)
        return fresh


def _claim_provider_create(backup, task_id):
    return _claim_backup_lease(
        backup,
        task_id,
        lease_name="create",
        lease_seconds=getattr(settings, "BACKUP_CREATE_LEASE_SECONDS", 3600),
    )


def _backup_lease_active(backup, lease_name):
    """Return whether a phase lease is still held by a live/unknown worker."""
    state = backup.get_execution_state(create=False)
    if state is not None and state.phase == lease_name and state.lease_is_active():
        return True
    _, control = _backup_control(backup)
    try:
        return float(control.get(f"{lease_name}_lease_until") or 0) > time.time()
    except (TypeError, ValueError):
        return False


_PROVIDER_CREATE_RETRYABLE_CODES = frozenset(
    {
        "PROVIDER_RATE_LIMIT",
        "PROVIDER_TIMEOUT",
        "PROVIDER_TRANSIENT_OUTAGE",
    }
)
_PROVIDER_CREATE_MANUAL_REVIEW_CODES = frozenset(
    {
        "PROVIDER_DUPLICATE_MATCH",
        "PROVIDER_MALFORMED_RESPONSE",
        "PROVIDER_OWNERSHIP_MISMATCH",
        "PROVIDER_RECONCILIATION_REQUIRED",
        "WORKER_LEASE_LOST",
    }
)
_PROVIDER_CREATE_SAFE_MESSAGES = {
    "PROVIDER_AUTH_FAILED": "The cloud provider rejected the configured credentials or permissions.",
    "PROVIDER_DUPLICATE_MATCH": "Multiple provider resources matched this backup. Manual review is required.",
    "PROVIDER_FAILED": "The cloud provider reported a terminal backup failure.",
    "PROVIDER_MALFORMED_RESPONSE": "The cloud provider returned an invalid response. Manual review is required.",
    "PROVIDER_NOT_FOUND": "The cloud provider could not find the backup source.",
    "PROVIDER_OWNERSHIP_MISMATCH": "Provider ownership verification failed. Manual review is required.",
    "PROVIDER_RECONCILIATION_REQUIRED": "The provider operation could not be reconciled automatically. Manual review is required.",
    "PROVIDER_REQUEST_FAILED": "The cloud provider rejected the backup request.",
    "WORKER_LEASE_LOST": "The backup worker lost ownership of this provider operation.",
}


def _provider_create_state(backup, error=None, *, previous_error_code=""):
    """Return a secret-free disposition derived from durable provider state."""
    backup.refresh_from_db()
    state = backup.get_execution_state(create=False)
    provider_metadata = (
        dict(state.provider_metadata or {}) if state is not None else {}
    )
    error_code = str(
        getattr(error, "error_code", "")
        or getattr(error, "code", "")
        or ""
    )[:64]
    state_code = str(
        getattr(state, "last_error_code", "") if state is not None else ""
    )[:64]
    # Do not mistake a previous retry's durable code for the exception from
    # this provider call when a legacy adapter supplied no typed contract.
    if not error_code and state_code == str(previous_error_code or ""):
        state_code = ""
    code = error_code or state_code
    reconciliation_state = str(
        getattr(state, "reconciliation_state", "") or ""
    )
    manual_review = (
        reconciliation_state == "manual_review"
        or code in _PROVIDER_CREATE_MANUAL_REVIEW_CODES
    )
    retryable = bool(
        getattr(error, "retryable", False)
        or code in _PROVIDER_CREATE_RETRYABLE_CODES
        or (state is not None and state.next_retry_at)
    )
    unknown = bool(
        getattr(error, "unknown_outcome", False)
        or reconciliation_state in {"required", "in_progress"}
        or provider_metadata.get("outcome_unknown")
        or (
            provider_metadata.get("create_attempted")
            and not _backup_has_provider_reference(backup)
        )
    )
    terminal = backup.status not in UtilBackup.ACTIVE_STATUSES or manual_review
    return state, code, retryable, unknown, terminal


def _provider_create_delay(state, *, retain_lease):
    """Return a bounded delay that never overlaps a retained mutation fence."""
    now = timezone.now()
    candidates = [60]
    if state is not None and state.next_retry_at:
        candidates.append(
            max(1, math.ceil((state.next_retry_at - now).total_seconds()))
        )
    if retain_lease and state is not None and state.lease_expires_at:
        candidates.append(
            max(1, math.ceil((state.lease_expires_at - now).total_seconds())) + 1
        )
    return min(max(candidates), 86400)


def _schedule_provider_create_resume(backup, countdown):
    """Best-effort ETA publication; the DB recovery sweep is the fallback."""
    node = backup.node
    task_id = str(backup.celery_task_id or f"recover-create-{backup.pk}")
    try:
        current_app.send_task(
            node.backup_task_name(),
            task_id=task_id,
            kwargs=_backup_recovery_kwargs(backup, node),
            countdown=max(1, int(countdown)),
            delivery_mode=2,
        )
    except Exception as error:
        # Do not convert a broker outage into a provider retry or terminal
        # backup. The active row and lease remain discoverable by recovery.
        capture_exception(error)


def _notify_terminal_provider_create(backup, code):
    """Finalize and notify one terminal create without provider error text."""
    from apps._tasks.exceptions import NodeBackupFailedError

    try:
        backup, should_notify = _finish_cloud_backup(
            backup,
            UtilBackup.Status.FAILED,
            "failure_notified",
        )
        _reset_node_if_no_active_backup(backup.node, backup)
        if should_notify:
            failure = NodeBackupFailedError(
                backup.node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                message=_PROVIDER_CREATE_SAFE_MESSAGES.get(
                    code,
                    _PROVIDER_CREATE_SAFE_MESSAGES["PROVIDER_FAILED"],
                ),
            )
            failure.error_code = code or "PROVIDER_FAILED"
            backup.node.notify_backup_fail(failure, backup.type)
    except Exception as error:
        # Notification/log failures never alter the terminal provider outcome.
        capture_exception(error)


def run_provider_create(backup, task_id, create_callback):
    """Serialize a provider create call across duplicate Celery deliveries.

    The callback is deliberately not released on an exception: a provider request
    may have been accepted even when the worker saw a timeout. Keeping the lease
    prevents a second worker from issuing a blind create while the original task's
    retry/recovery path performs the provider-specific deterministic lookup.
    """
    claimed = _claim_provider_create(backup, task_id)
    if claimed is None:
        return None
    state = claimed.get_execution_state(create=False)
    lease_token = state.lease_token if state is not None else None
    previous_error_code = getattr(state, "last_error_code", "") if state else ""
    try:
        if not _backup_has_provider_reference(claimed):
            create_callback(claimed)
    except Exception as error:
        current_state = claimed.get_execution_state(create=False)
        if (
            current_state is None
            or lease_token is None
            or not current_state.lease_matches(
                task_id,
                lease_token,
                phase="create",
                now=timezone.now(),
                require_live=True,
            )
        ):
            # A replacement worker owns recovery now.  The stale delivery must
            # not classify, release, notify, or schedule from its old result.
            return None
        state, code, retryable, unknown, terminal = _provider_create_state(
            claimed,
            error,
            previous_error_code=previous_error_code,
        )
        if terminal:
            try:
                _release_backup_lease(
                    claimed,
                    task_id,
                    "create",
                    lease_token=lease_token,
                )
            finally:
                _notify_terminal_provider_create(claimed, code)
            return None

        if unknown or not code:
            retry_at = (
                state.lease_expires_at
                if state is not None and state.lease_expires_at
                else timezone.now()
                + datetime.timedelta(
                    seconds=max(
                        60,
                        int(
                            getattr(
                                settings,
                                "BACKUP_CREATE_LEASE_SECONDS",
                                3600,
                            )
                        ),
                    )
                )
            )
            claimed.record_execution_error(
                code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                message=(
                    "The provider create response was not confirmed; deterministic "
                    "reconciliation is required before another create request."
                ),
                retry_at=retry_at,
                retryable=True,
                reconciliation_reason="provider_create_outcome_unknown",
                reconciliation_metadata={"phase": "create"},
                lease_owner=task_id,
                lease_token=lease_token,
            )
            state = claimed.get_execution_state(create=False)
            _schedule_provider_create_resume(
                claimed,
                _provider_create_delay(state, retain_lease=True),
            )
            return None

        if retryable:
            delay = _provider_create_delay(state, retain_lease=False)
            claimed.record_execution_error(
                code=code,
                retry_at=timezone.now() + datetime.timedelta(seconds=delay),
                retryable=True,
                lease_owner=task_id,
                lease_token=lease_token,
            )
            _release_backup_lease(
                claimed,
                task_id,
                "create",
                lease_token=lease_token,
            )
            claimed.node.backup_retrying_reset(task_id)
            claimed.refresh_from_db()
            _schedule_provider_create_resume(claimed, delay)
            return None

        claimed.status = UtilBackup.Status.FAILED
        claimed.save(update_fields=["status", "modified"])
        _release_backup_lease(
            claimed,
            task_id,
            "create",
            lease_token=lease_token,
        )
        _notify_terminal_provider_create(claimed, code or "PROVIDER_FAILED")
        return None
    else:
        claimed.refresh_from_db()
        current_state = claimed.get_execution_state(create=False)
        if (
            current_state is None
            or lease_token is None
            or not current_state.lease_matches(
                task_id,
                lease_token,
                phase="create",
                now=timezone.now(),
                require_live=True,
            )
        ):
            return None
        if claimed.status not in UtilBackup.ACTIVE_STATUSES:
            code = str(current_state.last_error_code or "PROVIDER_FAILED")[:64]
            try:
                _release_backup_lease(
                    claimed,
                    task_id,
                    "create",
                    lease_token=lease_token,
                )
            finally:
                _notify_terminal_provider_create(claimed, code)
            return None
        if not _backup_has_provider_reference(claimed):
            retry_at = state.lease_expires_at if state is not None else None
            claimed.record_execution_error(
                code="PROVIDER_CREATE_OUTCOME_UNKNOWN",
                message=(
                    "The provider create call returned without a durable provider "
                    "resource identifier; reconciliation is required."
                ),
                retry_at=retry_at,
                retryable=True,
                reconciliation_reason="provider_create_missing_reference",
                reconciliation_metadata={"phase": "create"},
                lease_owner=task_id,
                lease_token=lease_token,
            )
            state = claimed.get_execution_state(create=False)
            _schedule_provider_create_resume(
                claimed,
                _provider_create_delay(state, retain_lease=True),
            )
            return None
        claimed.record_provider_reference(
            operation_id=(
                getattr(claimed, "action_id", None)
                or getattr(claimed, "provider_job_id", None)
            ),
            resource_id=(
                getattr(claimed, "unique_id", None)
                or getattr(claimed, "provider_backup_id", None)
            ),
            idempotency_key=(
                getattr(claimed, "provider_marker", None) or claimed.uuid_str
            ),
            lease_owner=task_id,
            lease_token=lease_token,
        )
        _release_backup_lease(
            claimed, task_id, "create", lease_token=lease_token
        )
    return claimed


def _update_poll_control(backup, task_id=None, **updates):
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        metadata, control = _backup_control(fresh)
        if task_id and control.get("poll_task_id") != task_id:
            return None
        state = fresh.get_execution_state(create=False)
        lease_token = control.get("poll_lease_token")
        if state is None or not lease_token:
            return None
        control.update(updates)
        # Refresh the lease after a slow provider request so a recovery sweep cannot
        # enqueue a second poller while the first one is still healthy.
        interval = max(int(getattr(settings, "BACKUP_POLL_INTERVAL", 120)), 1)
        lease_seconds = max(interval * 2, 300)
        if updates.get("poll_next_run_at"):
            # The successor becomes the rightful claimant at its persisted ETA. The
            # JSON lease remains conservative for old workers; _claim_cloud_poll uses
            # poll_next_run_at to recognize the scheduled hand-off.
            lease_seconds = max(
                int(float(updates["poll_next_run_at"]) - time.time()), 1
            )
        heartbeat = fresh.heartbeat_execution(
            lease_owner=task_id,
            lease_token=lease_token,
            lease_seconds=lease_seconds,
        )
        if heartbeat is None:
            return None
        control["poll_lease_until"] = time.time() + max(interval * 2, 300)
        _save_backup_control(fresh, control, metadata)
        return fresh


def _finish_cloud_backup(backup, status, flag_name):
    """Persist a cloud terminal state exactly once and clear its poll lease."""
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        metadata, control = _backup_control(fresh)
        already_finished = bool(control.get(flag_name))
        fresh.status = status
        control[flag_name] = True
        control.pop("poll_task_id", None)
        control.pop("poll_lease_until", None)
        control.pop("poll_lease_token", None)
        control.pop("poll_handoff_task_id", None)
        control.pop("poll_handoff_lease_token", None)
        control.pop("recovery_task_id", None)
        control.pop("recovery_lease_until", None)
        control.pop("recovery_lease_token", None)
        _save_backup_control(fresh, control, metadata, include_status=True)
        # Terminalize the execution ledger with the backup status under the same
        # transaction. This clears the poll fence/next retry and resolves a stale
        # required/in-progress reconciliation state, while preserving explicit
        # manual review for an operator. A completed provider backup must never
        # remain visible as "Recovery Required" after a worker reboot.
        terminal_phase = (
            "complete"
            if status in UtilBackup.SUCCESS_STATUSES
            else "cancelled"
            if status == UtilBackup.Status.CANCELLED
            else "failed"
        )
        fresh.finalize_execution(terminal_phase=terminal_phase)
        return fresh, not already_finished


def _notify_cloud_success_once(node, backup, should_notify):
    if not should_notify:
        return
    if backup.schedule and (backup.schedule.keep_last or 0) > 0:
        keep_last = backup.schedule.keep_last
        completed = list(
            backup.__class__.objects.filter(
                schedule=backup.schedule, status=UtilBackup.Status.COMPLETE
            ).order_by("created")
        )
        for old_backup in completed[:-keep_last]:
            old_backup.soft_delete()
    node.notify_backup_success(backup)


def _notify_cloud_failure_once(node, backup, should_notify, status):
    if not should_notify:
        return
    if status == UtilBackup.Status.TIMEOUT:
        from apps._tasks.exceptions import NodeBackupStatusCheckTimeOutError

        error = NodeBackupStatusCheckTimeOutError(node, backup.uuid_str)
    else:
        from apps._tasks.exceptions import NodeBackupFailedError

        error = NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            "Cloud provider reported the snapshot as errored.",
        )
        # Provider polling persists the categorized failure before the
        # notification boundary. Carry only that stable code across the legacy
        # exception interface; CoreNode's notification contract allowlists it
        # before putting anything in an account log or email.
        try:
            execution = backup.get_execution_state(create=False)
            stable_error_code = str(
                getattr(execution, "last_error_code", "") or ""
            ).strip().upper()[:64]
        except Exception as lookup_error:
            capture_exception(lookup_error)
            stable_error_code = ""
        if stable_error_code:
            error.error_code = stable_error_code
    node.notify_backup_fail(error, backup.type)


def _reset_node_if_no_active_backup(node, backup=None):
    """Repair a stale node-level in-progress status after a terminal backup.

    The backup row is the source of truth. A worker can die after committing that
    row but before the older node reset call, so terminal poll messages must repair
    the denormalized node status. Never reset while another backup for the same node
    is still active.
    """
    from apps.console.node.models import CoreNode

    with transaction.atomic():
        fresh_node = CoreNode.objects.select_for_update().get(pk=node.pk)
        if fresh_node.status not in (
            CoreNode.Status.BACKUP_IN_PROGRESS,
            CoreNode.Status.BACKUP_RETRYING,
        ):
            return fresh_node

        node_type_object = fresh_node._integration_object()
        if not node_type_object:
            return fresh_node
        active_backups = node_type_object.backups.filter(
            status__in=UtilBackup.ACTIVE_STATUSES
        )
        if backup is not None:
            active_backups = active_backups.exclude(pk=backup.pk)
        if not active_backups.exists():
            fresh_node.status = CoreNode.Status.ACTIVE
            fresh_node.save(update_fields=["status", "modified"])
        return fresh_node


def _cloud_poll_countdown(backup, default_interval):
    """Honor a provider Retry-After persisted in the durable execution row."""
    countdown = max(1, int(default_interval))
    state = backup.get_execution_state(create=False)
    if state is None or not state.next_retry_at:
        return countdown
    retry_seconds = int((state.next_retry_at - timezone.now()).total_seconds())
    if retry_seconds > countdown:
        countdown = min(retry_seconds, 86400)
    return max(1, countdown)


def _backup_recovery_kwargs(backup, node):
    schedule = getattr(backup, "schedule", None)
    metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
    requested_storage_ids = metadata.get("_backup_storage_ids")
    if requested_storage_ids is None and schedule is not None:
        requested_storage_ids = schedule.storage_ids
    return {
        "node_id": node.id,
        "schedule_id": getattr(schedule, "id", None),
        "storage_ids": requested_storage_ids,
        "notes": backup.notes,
        "resume": True,
    }


def _backup_has_provider_reference(backup):
    return bool(
        getattr(backup, "unique_id", None)
        or getattr(backup, "action_id", None)
    )


def _local_upload_is_active(backup):
    """Return whether a *healthy* storage-point worker owns this local backup.

    An old UPLOAD_IN_PROGRESS row may belong to a worker that died before RabbitMQ
    could redeliver its message. Once the point lease is stale, the parent recovery
    path must be allowed to republish that point instead of skipping the backup
    forever.
    """
    now = timezone.now()
    for relation_name in (
        "stored_website_backups",
        "stored_database_backups",
        "stored_wordpress_backups",
        "stored_basecamp_backups",
    ):
        relation = getattr(backup, relation_name, None)
        if relation is None:
            continue
        status = relation.model.Status.UPLOAD_IN_PROGRESS
        return relation.filter(
            status=status,
            upload_lease_token__isnull=False,
            upload_lease_expires_at__gt=now,
        ).exists()
    return False


def _recoverable_backup_queryset(model, *, cutoff, now, batch_size):
    """Return active rows whose durable lease is absent or stale.

    ``modified`` remains the compatibility fallback for rows created before the
    execution-ledger migration. Once a lease exists, its expiry is authoritative: an
    active heartbeat prevents recovery even when the backup row itself is old, while
    an expired lease is recovered immediately without waiting for ``modified``.
    """
    from django.contrib.contenttypes.models import ContentType
    from apps.console.backup.models import CoreBackupExecution

    content_type = ContentType.objects.get_for_model(
        model, for_concrete_model=False
    )
    states = CoreBackupExecution.objects.filter(backup_content_type=content_type)
    live_ids = states.filter(
        lease_token__isnull=False,
        lease_expires_at__gt=now,
    ).values("backup_object_id")
    stale_ids = states.filter(
        Q(lease_expires_at__lte=now)
        | Q(
            lease_expires_at__isnull=True,
            lease_owner__gt="",
        )
    ).values("backup_object_id")
    return (
        model.objects.filter(status__in=UtilBackup.ACTIVE_STATUSES)
        .exclude(pk__in=live_ids)
        .filter(Q(pk__in=stale_ids) | Q(modified__lt=cutoff))
        .order_by("modified")[:batch_size]
    )


@current_app.task(name="resume_in_progress_backups", bind=True, ignore_result=True)
def resume_in_progress_backups(self):
    """Requeue work left behind by a worker or server restart.

    RabbitMQ late acknowledgements handle ordinary worker loss. This sweep is the
    durable fallback for messages lost during broker migration, old ETA pollers, and
    rows created by versions of the worker that did not use late acknowledgements.
    Every dispatch is protected by a DB lease and keeps the original backup task id,
    so ``backup_initiate`` reopens the same row instead of creating a second backup.
    """
    from apps.console.node.models import CoreNode

    stale_seconds = int(getattr(settings, "BACKUP_RECOVERY_STALE_SECONDS", 900))
    batch_size = int(getattr(settings, "BACKUP_RECOVERY_BATCH_SIZE", 100))
    cutoff = timezone.now() - datetime.timedelta(seconds=stale_seconds)
    recovery_now = timezone.now()
    cloud_models, local_models = _recovery_backup_models()

    for model in cloud_models + local_models:
        backups = _recoverable_backup_queryset(
            model,
            cutoff=cutoff,
            now=recovery_now,
            batch_size=batch_size,
        )
        for backup in backups:
            try:
                node = backup.node
                if not node or node.status in (
                    CoreNode.Status.DELETE_REQUESTED,
                    CoreNode.Status.PAUSED,
                ):
                    continue

                # Managed database backups use a provider-owned metadata record
                # and a database-specific poller. They do not have a CoreVultr
                # compute/volume backup relation, so routing them through the
                # generic cloud poller would load the wrong model on recovery.
                if model.__name__ == "CoreVultrDatabaseBackup":
                    task_id = backup.celery_task_id or f"recover-vultr-db-{backup.pk}"
                    task_name = (
                        "poll_vultr_database_backup"
                        if getattr(backup, "provider_marker", None)
                        else "backup_vultr_database"
                    )
                    if task_name == "poll_vultr_database_backup":
                        current_app.send_task(
                            task_name, task_id=task_id, args=[backup.id]
                        )
                    else:
                        current_app.send_task(
                            task_name,
                            task_id=task_id,
                            kwargs=_backup_recovery_kwargs(backup, node),
                        )
                    continue

                if model in cloud_models and _backup_has_provider_reference(backup):
                    recovery_id = f"recover-poll-{model.__name__}-{backup.pk}"
                    claimed = _claim_cloud_poll(
                        backup,
                        recovery_id,
                        getattr(settings, "BACKUP_POLL_INTERVAL", 120),
                    )
                    if claimed is None:
                        continue
                    claimed = _mark_cloud_poll_handoff(claimed, recovery_id)
                    if claimed is None:
                        continue
                    _, control = _backup_control(claimed)
                    current_app.send_task(
                        "poll_cloud_backup",
                        task_id=recovery_id,
                        args=[
                            node.id,
                            claimed.id,
                            control.get("started_at"),
                            getattr(settings, "BACKUP_POLL_INTERVAL", 120),
                            86400,
                        ],
                    )
                    continue

                # A provider create call can legitimately take longer than the
                # recovery sweep interval. Never dispatch a second creator while
                # the original create lease is still active; if the worker died,
                # the lease expiry is the safe hand-off point.
                if (
                    model in cloud_models
                    and not _backup_has_provider_reference(backup)
                    and _backup_lease_active(backup, "create")
                ):
                    continue

                # An upload task is already protected by its late acknowledgement
                # and storage-point lease. Re-publishing the parent while that child
                # is healthy would create a second chord whose callback could run
                # before the first upload finishes.
                if (
                    model in local_models
                    and backup.status == UtilBackup.Status.UPLOAD_IN_PROGRESS
                    and _local_upload_is_active(backup)
                ):
                    continue

                # A cloud create request may have succeeded before its id was saved.
                # The original provider task is responsible for deterministic name
                # lookup before creating anything new.
                task_id = backup.celery_task_id or uuid.uuid4().hex
                if not backup.celery_task_id:
                    with transaction.atomic():
                        locked = model.objects.select_for_update().get(pk=backup.pk)
                        if not locked.celery_task_id:
                            locked.celery_task_id = task_id
                            locked.save(update_fields=["celery_task_id", "modified"])
                        task_id = locked.celery_task_id
                        backup = locked

                recovery_id = f"recover-create-{model.__name__}-{backup.pk}"
                if _claim_backup_lease(backup, recovery_id) is None:
                    continue
                current_app.send_task(
                    node.backup_task_name(),
                    task_id=task_id,
                    kwargs=_backup_recovery_kwargs(backup, node),
                )
            except Exception as error:
                # One malformed/removed row must not prevent recovery of the rest of
                # the provider catalog. The next sweep can retry this row.
                capture_exception(error)


@current_app.task(
    name="digitalocean_refresh_tokens",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def digitalocean_refresh_tokens(self):
    try:
        from datetime import datetime
        from apps.console.connection.models import CoreAuthDigitalOcean, CoreConnection
        from apps.console.node.models import CoreNode

        if settings.DJANGO_SERVER == "prod":
            query = Q()
            query &= ~Q(connection__status=CoreConnection.Status.TOKEN_REFRESH_FAIL)
            query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
            for auth_digitalocean in CoreAuthDigitalOcean.objects.filter(query):
                if (
                    not auth_digitalocean.connection.nodes.filter(status=CoreNode.Status.BACKUP_IN_PROGRESS).exists()
                ) and (not auth_digitalocean.connection.nodes.filter(status=CoreNode.Status.BACKUP_RETRYING).exists()):
                    auth_digitalocean.refresh_auth_token()
    except Exception as e:
        raise self.retry()


@current_app.task(
    name="delete_from_disk",
    track_started=True,
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def delete_from_disk(self, backup_uuid, path_type):
    """Remove a backup's local working files from _storage once uploads have settled.

    path_type selects what to remove (everything lives under <BASE_DIR>/_storage/):
        "dir"  -> the working directory  <uuid>/      (uncompressed dump tree)
        "zip"  -> the archive and commit marker <uuid>.zip/.manifest.json
        "both" -> the working directory, archive, and commit marker

    The run log (<uuid>.log) is intentionally kept on disk and pruned later by
    delete_old_logs; it is never removed here.

    Uses plain Python file operations -- no shell, no sudo, no hardcoded host paths --
    and is idempotent: a missing file is success, not an error. Only unexpected failures
    retry (bounded), so cleanup can never wedge a backup or leak disk silently.
    """
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))

    def _remove(name, is_dir):
        # Resolve and confine to _storage so a malformed uuid can't escape the directory
        # (and never delete _storage itself).
        target = os.path.realpath(os.path.join(storage_dir, name))
        if target == storage_dir or os.path.commonpath([storage_dir, target]) != storage_dir:
            return
        if is_dir:
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.remove(target)
            except FileNotFoundError:
                pass

    try:
        if path_type in ("dir", "both"):
            _remove(backup_uuid, is_dir=True)

        if path_type in ("zip", "both"):
            _remove(f"{backup_uuid}.zip", is_dir=False)
            _remove(f"{backup_uuid}.manifest.json", is_dir=False)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(name="delete_old_logs", bind=True, ignore_result=True)
def delete_old_logs(self, max_age_days=None):
    """Prune backup run logs from local _storage once they pass the retention window.

    Self-hosted builds keep run logs (and the .files/.md5 artefacts) on the container
    instead of uploading them anywhere, so this task is what bounds their disk usage.
    It is scheduled daily by Celery beat (see CELERY_BEAT_SCHEDULE). max_age_days
    defaults to settings.LOG_RETENTION_DAYS (30).
    """
    if max_age_days is None:
        max_age_days = getattr(settings, "LOG_RETENTION_DAYS", 30)
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
    cutoff = time.time() - (max_age_days * 86400)
    suffixes = (".log", ".files", ".md5")
    try:
        with os.scandir(storage_dir) as entries:
            for entry in entries:
                if not entry.is_file() or not entry.name.endswith(suffixes):
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        os.remove(entry.path)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    except Exception as e:
        capture_exception(e)


@current_app.task(name="delete_old_db_logs", bind=True, ignore_result=True)
def delete_old_db_logs(self):
    """Prune old CoreLog rows from the database.

    DB counterpart of delete_old_logs (which prunes on-disk run logs): delegates
    to CoreLog.prune(), which deletes rows older than settings.LOG_RETENTION_DAYS.
    Scheduled daily by Celery beat (see CELERY_BEAT_SCHEDULE).
    """
    from apps.console.log.models import CoreLog

    try:
        CoreLog.prune()
    except Exception as e:
        capture_exception(e)


@current_app.task(name="poll_cloud_backup", bind=True, ignore_result=True)
def poll_cloud_backup(self, node_id, backup_id, started_at=None, interval=120, timeout=86400):
    """Asynchronously wait for a cloud / volume snapshot to finish.

    Runs ONE status check per invocation and re-queues itself between checks, so the
    worker is never blocked for the whole (potentially hours-long) snapshot -- replacing
    the old blocking `while ...: time.sleep(60)` poll inside each backup model.

    Resilience: a single failed or transient status check never fails the backup --
    backup.poll_status() returns IN_PROGRESS and we simply poll again. The backup is
    marked FAILED only when the provider itself reports the snapshot errored, and TIMEOUT
    only after `timeout` seconds of polling.
    """
    from apps.console.node.models import CoreNode

    try:
        node = CoreNode.objects.get(id=node_id)
    except CoreNode.DoesNotExist:
        return

    backup = node.get_cloud_backup(backup_id)
    if backup is None:
        return

    # Stop polling once the backup has reached any terminal state (completed elsewhere,
    # cancelled, or queued/processed for deletion).
    terminal = (
        UtilBackup.Status.COMPLETE,
        UtilBackup.Status.PARTIAL,
        UtilBackup.Status.FAILED,
        UtilBackup.Status.TIMEOUT,
        UtilBackup.Status.CANCELLED,
        UtilBackup.Status.DELETE_REQUESTED,
        UtilBackup.Status.DELETE_IN_PROGRESS,
        UtilBackup.Status.DELETE_COMPLETED,
    )
    if backup.status in terminal:
        # A provider adapter may commit the terminal backup status and then the
        # worker can die before the poll-control flags, execution ledger, node
        # reset, retention, or notification are committed.  Redelivery repairs
        # that split commit idempotently instead of returning with a terminal row
        # still presented as Recovery Required.
        if backup.status in UtilBackup.SUCCESS_STATUSES:
            backup, should_notify = _finish_cloud_backup(
                backup, backup.status, "success_notified"
            )
            _reset_node_if_no_active_backup(node, backup)
            _notify_cloud_success_once(node, backup, should_notify)
            return
        if backup.status in (UtilBackup.Status.FAILED, UtilBackup.Status.TIMEOUT):
            flag_name = (
                "timeout_notified"
                if backup.status == UtilBackup.Status.TIMEOUT
                else "failure_notified"
            )
            backup, should_notify = _finish_cloud_backup(
                backup, backup.status, flag_name
            )
            _reset_node_if_no_active_backup(node, backup)
            _notify_cloud_failure_once(
                node, backup, should_notify, backup.status
            )
            return
        if backup.status == UtilBackup.Status.CANCELLED:
            backup, _ = _finish_cloud_backup(
                backup, backup.status, "cancel_finalized"
            )
        _reset_node_if_no_active_backup(node, backup)
        return

    task_id = self.request.id or uuid.uuid4().hex
    backup = _claim_cloud_poll(backup, task_id, interval)
    if backup is None:
        return

    _, control = _backup_control(backup)
    if started_at is None:
        started_at = control.get("started_at")
    try:
        started_at = float(started_at)
    except (TypeError, ValueError):
        started_at = time.time()
    if _update_poll_control(backup, task_id=task_id, started_at=started_at) is None:
        return

    try:
        status = backup.poll_status()
    except Exception as e:
        capture_exception(e)
        # Provider adapters normally classify their own responses. If an SDK
        # exception escapes, classify it here instead of silently converting
        # authentication failures, 404s, and malformed client errors into a false
        # IN_PROGRESS state.
        from apps.console.backup.models import _provider_exception_outcome

        status = _provider_exception_outcome(
            backup,
            e,
            provider=node.connection.integration.code,
            operation="poll",
        )

    if status == UtilBackup.Status.COMPLETE:
        backup, should_notify = _finish_cloud_backup(
            backup, UtilBackup.Status.COMPLETE, "success_notified"
        )
        _reset_node_if_no_active_backup(node, backup)
        _notify_cloud_success_once(node, backup, should_notify)
        return

    if status == UtilBackup.Status.FAILED:
        backup, should_notify = _finish_cloud_backup(
            backup, UtilBackup.Status.FAILED, "failure_notified"
        )
        _reset_node_if_no_active_backup(node, backup)
        _notify_cloud_failure_once(
            node, backup, should_notify, UtilBackup.Status.FAILED
        )
        return

    # Still in progress (or a transient check failure). Give up only past the hard
    # timeout; otherwise re-queue another check and free the worker until then.
    if (time.time() - started_at) > timeout:
        backup, should_notify = _finish_cloud_backup(
            backup, UtilBackup.Status.TIMEOUT, "timeout_notified"
        )
        _reset_node_if_no_active_backup(node, backup)
        _notify_cloud_failure_once(
            node, backup, should_notify, UtilBackup.Status.TIMEOUT
        )
        return

    # Keep the lease alive until just after the ETA message. If the worker dies
    # before publishing it, the lease expires and the periodic recovery task takes
    # over; if it is healthy, the next invocation uses the same task row.
    next_countdown = _cloud_poll_countdown(backup, interval)
    if _update_poll_control(
        backup,
        task_id=task_id,
        started_at=started_at,
        poll_next_run_at=time.time() + next_countdown,
    ) is None:
        return
    poll_cloud_backup.apply_async(
        args=[node_id, backup_id, started_at, interval, timeout],
        countdown=next_countdown,
    )


@current_app.task(
    name="terminate_backup",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def terminate_backup(self, data):
    try:
        app.control.revoke(data["celery_task_id"], terminate=True)
    except Exception as e:
        raise self.retry()


@current_app.task(name="send_to_firebase", track_started=True, bind=True)
def send_to_firebase(self, data):
    try:
        if data.get("notes") == "completed" or data.get("notes") == "failed":
            time.sleep(5)
        ref = db.reference(f"nodes/{data.get('node_id')}/logs")
        ref.set(
            {
                "timestamp": int(time.time()),
                "notes": data.get("notes"),
                "report": data.get("report", None),
            }
        )
    except Exception as e:
        raise self.retry()


@current_app.task(
    name="send_log_to_db",
    bind=True,
    ignore_result=True,
    acks_late=False,
    send_events=False,
)
def send_log_to_db(self, data):
    from apps.console.log.models import CoreLog

    try:
        if data.get("account_id"):
            log = CoreLog.objects.create(account_id=data.get("account_id"), data=data)

            if data.get("sender_name") == "BackupSheep - Notification Bot":
                message = log.data.get("message")
                error_details = log.data.get("error_details")

                full_msg = f""
                if message:
                    if message.strip() != "":
                        full_msg += f"{data.get('message')}"

                if error_details:
                    if error_details.strip() != "":
                        if len(full_msg) > 0:
                            full_msg += f" :: "
                        full_msg += f"{data.get('error_details')}"
                if len(full_msg) > 0:
                    log.account.send_notification(full_msg)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_log_to_slack",
    bind=True,
    ignore_result=True,
)
def send_log_to_slack(self, url, message):
    try:
        webhook = WebhookClient(url)
        response = webhook.send(
            text=f"{message}",
        )
        if response.status_code != 200 and response.body != "ok":
            self.retry()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_log_to_telegram",
    bind=True,
    ignore_result=True,
)
def send_log_to_telegram(self, chat_id, message):
    try:
        result = requests.get(
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_KEY}/sendMessage?"
            f"chat_id={chat_id}"
            f"&text={message}",
            headers={"content-type": "application/json"},
            verify=True,
        )
        if result.status_code != 200:
            self.retry()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="account_delete",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def account_delete(self):
    try:
        from apps.console.node.models import CoreSchedule, CoreNode
        import boto3
        from apps.console.backup.models import (
            CoreDatabaseBackupStoragePoints,
            CoreWebsiteBackupStoragePoints,
        )

        for account in CoreAccount.objects.filter(status=CoreAccount.Status.DELETE_REQUESTED):

            """
            NODE STORAGE CLEANUP
            """
            for node in CoreNode.objects.filter(connection__account=account).order_by("-created"):
                node.status = CoreNode.Status.DELETE_REQUESTED
                node.save()
                node_delete_requested(node_id=node.id)

            """
            FINAL USER CLEANUP
            """
            for membership in account.memberships.all():
                membership.member.user.delete()
            account.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_postmark_email",
    bind=True,
    ignore_result=True,
)
def send_postmark_email(self, to_email, template, context):
    """Generic notification email task: log + render + send ANY email template.

    Replaces the stale Postmark-only version, which filtered on a non-existent
    CoreNotificationEmail.account FK and only ever sent password_reset emails.
    Despite the historical task name (kept for backwards compatibility with
    existing callers/queues), delivery goes through
    CoreNotificationLogEmail.send(), which honors the configured email provider
    (postmark / mailgun / ses). The log row needs the member FK, so emails to
    an address with no matching member are skipped with a print-log.
    """
    try:
        from apps.console.notification.models import CoreNotificationLogEmail

        member = CoreMember.objects.filter(user__email=to_email).first()
        if member is None:
            print(f"no member found for email, skipping {template} email: {to_email}")
            return

        email_notification = CoreNotificationLogEmail()
        email_notification.member = member
        email_notification.email = to_email
        email_notification.template = template
        email_notification.context = context
        email_notification.save()

        # Now Send email (works for any template, not just password_reset)
        email_notification.send()
    except Exception as e:
        capture_exception(e)


"""
NO NEED TO RUN IT ON REGULAR BASIS ANYMORE. 
"""
@current_app.task(
    name="digitalocean_clean_volume_snapshots",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def digitalocean_clean_volume_snapshots(self):
    from apps.console.node.models import CoreNode
    from apps.console.backup.models import CoreDigitalOceanBackup

    try:
        for do_backup in CoreDigitalOceanBackup.objects.filter(
            digitalocean__node__type=CoreNode.Type.VOLUME,
            status=CoreDigitalOceanBackup.Status.DELETE_COMPLETED,
        ).order_by("-created"):
            do_backup.soft_delete()

        for do_backup in CoreDigitalOceanBackup.objects.filter(
            digitalocean__node__type=CoreNode.Type.VOLUME,
            status=CoreDigitalOceanBackup.Status.DELETE_FAILED,
        ).order_by("-created"):
            do_backup.soft_delete()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


"""
RUNS ON ENDPOINT NODE
"""
@current_app.task(
    name="node_delete_requested",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def node_delete_requested(self, node_id):
    from apps.console.node.models import CoreNode, CoreSchedule

    try:
        if node_id:
            for node in CoreNode.objects.filter(status=CoreNode.Status.DELETE_REQUESTED, id=node_id).order_by(
                "-created"
            ):
                node_type_object = node._integration_object()
                if node_type_object:

                    query = ~Q(status=UtilBackup.Status.DELETE_COMPLETED)
                    pending_backups = node_type_object.backups.filter(query).order_by("created")
                    for backup in pending_backups:
                        backup.soft_delete()

                    # A node row owns the backup catalog.  Never cascade-delete it
                    # while a provider still has an unconfirmed backup: doing so
                    # destroys the only local pointer available for a later retry.
                    if node_type_object.backups.filter(query).exists():
                        raise RuntimeError(
                            f"Node {node_id} still has backups whose remote deletion "
                            "has not been confirmed."
                        )

                    for schedule in CoreSchedule.objects.filter(node=node):
                        schedule.schedule_delete()

                    for schedule in node.schedules.all():
                        schedule.delete()

                # Remove the per-node website mirror cache used by incremental
                # backups, confined to _storage like delete_from_disk.
                if getattr(node, "website", None) is not None:
                    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
                    cache_base = os.path.realpath(os.path.join(storage_dir, "website_cache", node.uuid_str))
                    if cache_base != storage_dir and os.path.commonpath([storage_dir, cache_base]) == storage_dir:
                        shutil.rmtree(cache_base, ignore_errors=True)
                        for suffix in (".meta.json", ".lock"):
                            try:
                                os.remove(cache_base + suffix)
                            except FileNotFoundError:
                                pass

                node.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="clean_delete_failed_backups",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def clean_delete_failed_backups(self):
    from apps.console.node.models import CoreNode, CoreSchedule

    try:
        for node in CoreNode.objects.filter().order_by("-created"):
            node_type_object = node._integration_object()
            if node_type_object:

                cleanup_statuses = (
                    UtilBackup.Status.DELETE_FAILED,
                    UtilBackup.Status.DELETE_FAILED_NOT_FOUND,
                    UtilBackup.Status.DELETE_MAX_RETRY_FAILED,
                    UtilBackup.Status.MAX_RETRY_FAILED,
                    UtilBackup.Status.CANCELLED,
                )
                for backup in node_type_object.backups.filter(
                    status__in=cleanup_statuses
                ).order_by("created"):
                    try:
                        if backup.soft_delete() is False:
                            capture_message(
                                f"Keeping backup {backup.uuid}: remote deletion is still unconfirmed."
                            )
                        else:
                            print(f"remote deletion confirmed for backup {backup.uuid}")
                    except Exception as exc:
                        capture_exception(exc)
                        capture_message(
                            f"Keeping backup {backup.uuid}: cleanup retry failed."
                        )

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="delete_requested_integrations",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def delete_requested_integrations(self):
    from apps.console.node.models import CoreConnection

    try:
        for connection in CoreConnection.objects.filter(status=CoreConnection.Status.DELETE_REQUESTED).order_by(
            "-created"
        ):
            for node in connection.nodes.filter():
                node_delete_requested(node_id=node.id)
            connection.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


# Todo: Add some checks here
@current_app.task(
    name="delete_requested_storages",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def delete_requested_storages(self):
    from apps.console.node.models import CoreStorage

    try:
        for storage in CoreStorage.objects.filter(status=CoreStorage.Status.DELETE_REQUESTED).order_by("-created"):
            storage.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="calc_stats_storage_insight",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def calc_stats_storage_insight(self):
    try:
        for account in CoreAccount.objects.filter().order_by("-created"):
            for storage_type in CoreStorageType.objects.filter():
                for storage in (
                    CoreStorage.objects.filter(account=account, type=storage_type)
                    .annotate(
                        Sum("website_backups__size"),
                        Sum("database_backups__size"),
                        Sum("wordpress_backups__size"),
                        Count("database_backups", distinct=True),
                        Count("website_backups", distinct=True),
                        Count("wordpress_backups", distinct=True),
                        Count("database_backups__database", distinct=True),
                        Count("website_backups__website", distinct=True),
                        Count("wordpress_backups__wordpress", distinct=True),
                    )
                    .order_by("-created")
                ):
                    # Counts
                    storage.stats_website_count = storage.website_backups__count
                    storage.stats_database_count = storage.database_backups__count
                    storage.stats_wordpress_count = storage.wordpress_backups__count
                    # Backups
                    storage.stats_website_backup_count = storage.website_backups__website__count
                    storage.stats_database_backup_count = storage.database_backups__database__count
                    storage.stats_wordpress_backup_count = storage.wordpress_backups__wordpress__count
                    # Size
                    storage.stats_website_size = storage.website_backups__size__sum
                    storage.stats_database_size = storage.database_backups__size__sum
                    storage.stats_wordpress_size = storage.wordpress_backups__size__sum
                    storage.save()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="token_refresh_all",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def token_refresh_all(self):
    from datetime import datetime

    query = Q()

    try:
        # OneDrive Storage
        for storage in CoreStorageOneDrive.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"OneDrive ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Dropbox  Storage
        for storage in CoreStorageDropbox.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Dropbox ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Google Drive Storage
        for storage in CoreStorageGoogleDrive.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"GoogleDrive ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Basecamp Integrations
        for auth in CoreAuthBasecamp.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Basecamp ID: {storage.id}")
                    auth.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Slack Notifications
        for notification in CoreNotificationSlack.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Slack ID: {storage.id}")
                    notification.refresh_auth_token()
                except Exception as e:
                    capture_exception(e)

    except Exception as e:
        capture_exception(e)
