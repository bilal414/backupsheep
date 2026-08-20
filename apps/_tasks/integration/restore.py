from datetime import datetime, timedelta

from celery import current_app
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration.restore_lease import (
    DurableRestoreLease,
    RestoreAlreadyTerminal,
    RestoreLeaseBusy,
    RestoreLeaseLost,
)
from apps._tasks.integration.restore_common import (
    RestoreError,
    notify_restore_completed,
    notify_restore_failed,
    notify_restore_started,
)
from apps.console.backup.models import (
    CoreCloudRestore,
    CoreDatabaseRestore,
    CoreVultrDatabaseRestore,
    CoreWebsiteRestore,
    RestoreExecutionLeaseLostError,
)
from apps.console.connection.reliability import classify_connection_error
from apps.console.node.models import CoreNode


def _restore_error_outcome(error):
    """Return (code, safe message, retryable) without persisting exception text."""
    if isinstance(error, SoftTimeLimitExceeded):
        return (
            "RESTORE_TIMEOUT",
            "The restore worker reached its time limit; the operation will resume safely.",
            True,
        )
    if isinstance(error, RestoreError):
        declared_code = str(getattr(error, "code", "") or "").upper()
        declared_retryable = bool(getattr(error, "retryable", False))
        if declared_code in {"PROVIDER_TIMEOUT", "STORAGE_TIMEOUT"}:
            return (
                "RESTORE_TIMEOUT",
                "The storage provider timed out; the restore will resume automatically.",
                True,
            )
        if declared_code in {
            "PROVIDER_RATE_LIMIT",
            "PROVIDER_RATE_LIMITED",
            "STORAGE_RATE_LIMITED",
        }:
            return (
                "RATE_LIMITED",
                "The storage provider rate limit was reached; the restore will resume automatically.",
                True,
            )
        if declared_code == "RESTORE_ARCHIVE_NOT_READY":
            return (
                "RESTORE_ARCHIVE_NOT_READY",
                "The storage provider is restoring this archive; the restore will resume automatically when it is ready.",
                True,
            )
        if declared_code in {
            "PROVIDER_TRANSIENT_FAILURE",
            "PROVIDER_TRANSIENT_OUTAGE",
            "STORAGE_TRANSIENT_FAILURE",
        } or declared_retryable:
            return (
                "RESTORE_TRANSIENT_FAILURE",
                "The storage provider is temporarily unavailable; the restore will resume automatically.",
                True,
            )
        if declared_code in {"PROVIDER_AUTH_FAILED", "STORAGE_AUTH_FAILED"}:
            return (
                "PROVIDER_AUTH_FAILED",
                "The storage provider rejected the configured restore credentials or permissions.",
                False,
            )
        if declared_code == "DATABASE_RESTORE_PERMISSION_DENIED":
            return (
                "DATABASE_RESTORE_PERMISSION_DENIED",
                "The configured database account lacks privileges required for a safe fork restore. "
                "Grant PostgreSQL CREATEDB or MySQL/MariaDB CREATE and DROP globally "
                "or with a matching target/database grant, "
                "or choose an explicit in-place restore target. No target was changed.",
                False,
            )
        if declared_code in {"PROVIDER_NOT_FOUND", "STORAGE_DESTINATION_NOT_FOUND"}:
            return (
                "RESTORE_SOURCE_UNAVAILABLE",
                "The committed backup object was not found at the storage provider.",
                False,
            )
        if declared_code == "RESTORE_RECONCILIATION_REQUIRED":
            return (
                "RESTORE_RECONCILIATION_REQUIRED",
                "The restore state is ambiguous, so automatic destination writes "
                "were stopped. Review the exact ownership and cleanup evidence "
                "before retrying.",
                False,
            )
        if declared_code in {
            "AMBIGUOUS_PROVIDER_STATE",
            "INTEGRITY_LEDGER_CONFLICT",
            "INTEGRITY_MISMATCH",
            "INVALID_BACKUP_ID",
            "INVALID_PROVIDER_PATH",
            "MALFORMED_PROVIDER_RESPONSE",
            "MALFORMED_PROVIDER_STATE",
            "MISSING_PROVIDER_ID",
            "MISSING_PROVIDER_STATE",
            "PROVIDER_OWNERSHIP_MISMATCH",
            "PROVIDER_DUPLICATE_MATCH",
            "PROVIDER_MALFORMED_RESPONSE",
            "PROVIDER_RECONCILIATION_REQUIRED",
            "PROVIDER_STATE_CONFLICT",
            "PROVIDER_VERSION_DRIFT",
            "UNCOMMITTED_PROVIDER_STATE",
        }:
            return (
                "RESTORE_INTEGRITY_FAILED",
                "The selected backup failed ownership or integrity validation; no destination changes were made.",
                False,
            )
        if declared_code in {"PROVIDER_FAILED", "PROVIDER_REQUEST_FAILED"}:
            return (
                "PROVIDER_FAILED",
                "The provider rejected the restore operation.",
                False,
            )
        detail = str(error).lower()
        if "glacier" in detail or "archive" in detail and "provider" in detail:
            return (
                "RESTORE_ARCHIVE_NOT_READY",
                "The selected archive is not ready for download yet.",
                True,
            )
        if any(
            marker in detail
            for marker in (
                "ambiguous",
                "manual review",
                "marker does not",
                "marker disagree",
                "does not belong to this restore",
                "checkpoint moved backwards",
                "checkpoint does not match",
                "mapping changed",
                "name collision",
                "ownership",
            )
        ):
            return (
                "RESTORE_RECONCILIATION_REQUIRED",
                "The restore state is ambiguous, so automatic destination writes "
                "were stopped. Review the exact ownership and checkpoint evidence "
                "before retrying.",
                False,
            )
        if any(
            marker in detail
            for marker in (
                "integrity",
                "sha-256",
                "checksum",
                "crc",
                "valid zip",
                "unsafe",
                "special file",
                "duplicate archive",
            )
        ):
            return (
                "RESTORE_INTEGRITY_FAILED",
                "The selected backup failed integrity validation; no destination changes were made.",
                False,
            )
        return (
            "RESTORE_SOURCE_UNAVAILABLE",
            "The selected backup copy is not currently available for restore.",
            False,
        )

    connection = classify_connection_error(error, stage="restore")
    if connection.code != "CONNECTION_VALIDATION_FAILED":
        return (connection.code, connection.detail, connection.retryable)
    if isinstance(error, NodeBackupFailedError):
        return (
            "RESTORE_TARGET_REJECTED",
            "The destination rejected the restore operation. Secured diagnostics contain the detailed cause.",
            False,
        )
    return (
        "RESTORE_TRANSIENT_FAILURE",
        "The restore could not complete because of a transient worker or provider failure.",
        True,
    )


def _restore_retry_delay(error, default=120):
    """Return a bounded provider backoff without trusting arbitrary values."""
    try:
        value = int(getattr(error, "retry_after", None))
    except (TypeError, ValueError):
        value = int(default)
    return max(5, min(value, 86400))


def _notify_once(restore, key, callback):
    metadata = dict(restore.execution_metadata or {})
    if metadata.get(key):
        return
    # Commit the outbox marker before dispatch.  A worker crash may delay a
    # notification, but cannot send an unbounded duplicate storm on redelivery.
    metadata[key] = timezone.now().isoformat()
    restore.execution_metadata = metadata
    restore.save(update_fields=["execution_metadata", "modified"])
    callback()


def _run_materialized_restore(task, *, node, backup, restore, engine, phase):
    lease = DurableRestoreLease(
        restore,
        phase=phase,
        task_id=task.request.id,
        worker_name=getattr(task.request, "hostname", ""),
    )
    try:
        restore = lease.claim()
    except RestoreAlreadyTerminal:
        return
    except RestoreLeaseBusy as error:
        raise task.retry(countdown=error.retry_after, max_retries=2880)

    try:
        _notify_once(
            restore,
            "started_notification_enqueued_at",
            lambda: notify_restore_started(node, backup, restore),
        )
        lease.checkpoint("validating_source")
        engine(backup, restore)
        lease.ensure_owned()
        restore.status = restore.Status.COMPLETE
        restore.execution_phase = "complete"
        restore.error = None
        restore.last_error_code = ""
        restore.next_retry_at = None
        # The lease heartbeat is renewed by a separate thread while the engine can
        # spend hours transferring data.  A full model save here would write the
        # task's stale in-memory heartbeat/expiry back over that newer lease and can
        # fence the task at the completion-notification boundary.  Persist only the
        # terminal outcome fields; lease.release() owns the lease columns.
        restore.save(
            update_fields=[
                "status",
                "execution_phase",
                "error",
                "last_error_code",
                "next_retry_at",
                "modified",
            ]
        )
        _notify_once(
            restore,
            "completed_notification_enqueued_at",
            lambda: notify_restore_completed(node, backup, restore),
        )
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError) as error:
        capture_exception(error)
        raise task.retry(countdown=30, max_retries=2880)
    except Exception as error:
        capture_exception(error)
        code, message, retryable = _restore_error_outcome(error)
        retry_delay = _restore_retry_delay(error) if retryable else None
        restore.last_error_code = code
        restore.error = message
        restore.execution_phase = "retrying" if retryable else "failed"
        restore.next_retry_at = (
            timezone.now() + timedelta(seconds=retry_delay) if retryable else None
        )
        if not retryable:
            restore.status = restore.Status.FAILED
        restore.save(
            update_fields=[
                "status",
                "last_error_code",
                "error",
                "execution_phase",
                "next_retry_at",
                "modified",
            ]
        )
        if retryable:
            try:
                raise task.retry(countdown=retry_delay)
            except MaxRetriesExceededError:
                restore.status = restore.Status.FAILED
                restore.execution_phase = "failed"
                restore.last_error_code = "RESTORE_RETRIES_EXHAUSTED"
                restore.error = "The restore exhausted its automatic retry budget."
                restore.next_retry_at = None
                restore.save(
                    update_fields=[
                        "status",
                        "execution_phase",
                        "last_error_code",
                        "error",
                        "next_retry_at",
                        "modified",
                    ]
                )
        if restore.status == restore.Status.FAILED:
            _notify_once(
                restore,
                "failed_notification_enqueued_at",
                lambda: notify_restore_failed(node, backup, restore, restore.error),
            )
    finally:
        lease.release()


def _refresh_bound_restore(lease):
    restore = lease.model.objects.get(pk=lease.restore_id)
    restore.bind_execution_fence(lease.owner, lease.token)
    lease.restore = restore
    return restore


_CLOUD_RESTORE_MANUAL_REVIEW_CODES = frozenset(
    {
        "PROVIDER_DUPLICATE_MATCH",
        "PROVIDER_MALFORMED_RESPONSE",
        "PROVIDER_OWNERSHIP_MISMATCH",
        "PROVIDER_RECONCILIATION_EXHAUSTED",
        "PROVIDER_RECONCILIATION_REQUIRED",
    }
)


def _mark_cloud_restore_failed(node, backup, restore, code, message):
    manual_review = (
        restore.operation_phase == restore.OperationPhase.MANUAL_REVIEW
        or str(code) in _CLOUD_RESTORE_MANUAL_REVIEW_CODES
    )
    restore.status = restore.Status.FAILED
    restore.execution_phase = "manual_review" if manual_review else "failed"
    restore.operation_phase = (
        restore.OperationPhase.MANUAL_REVIEW
        if manual_review
        else restore.OperationPhase.FAILED
    )
    restore.last_error_code = code
    restore.error = message
    restore.next_retry_at = None
    restore.save()
    _notify_once(
        restore,
        "failed_notification_enqueued_at",
        lambda: notify_restore_failed(node, backup, restore, message),
    )


def _schedule_cloud_restore_reconciliation(node, backup, restore, *, countdown=60):
    restore_cloud_backup.apply_async(
        args=[node.id, backup.id, restore.id], countdown=countdown
    )


def _defer_cloud_restore_reconciliation(
    node,
    backup,
    restore,
    *,
    countdown=60,
):
    """Persist a bounded reconciliation retry for an ambiguous create.

    Adapters sometimes return without a target pointer (for example while a
    provider is rate-limiting inventory reads) instead of raising.  Count both
    return and exception paths so an unreconcilable mutation cannot loop forever
    or silently become a normal provider retry.
    """
    now = timezone.now()
    metadata = dict(restore.execution_metadata or {})
    attempts = int(metadata.get("create_reconciliation_attempts") or 0) + 1
    metadata["create_reconciliation_attempts"] = attempts
    first_unknown = metadata.get("create_outcome_unknown_since")
    if not first_unknown:
        first_unknown = now.isoformat()
        metadata["create_outcome_unknown_since"] = first_unknown

    try:
        first_unknown_at = datetime.fromisoformat(str(first_unknown))
        if timezone.is_naive(first_unknown_at):
            first_unknown_at = timezone.make_aware(first_unknown_at)
    except (TypeError, ValueError):
        first_unknown_at = now
        metadata["create_outcome_unknown_since"] = now.isoformat()

    max_attempts = max(
        1,
        int(
            getattr(
                settings,
                "RESTORE_CREATE_RECONCILIATION_MAX_ATTEMPTS",
                100,
            )
        ),
    )
    max_age_seconds = max(
        60,
        int(
            getattr(
                settings,
                "RESTORE_CREATE_RECONCILIATION_MAX_AGE_SECONDS",
                24 * 3600,
            )
        ),
    )
    exhausted = (
        attempts >= max_attempts
        or (now - first_unknown_at).total_seconds() >= max_age_seconds
    )
    restore.execution_metadata = metadata
    if exhausted:
        _mark_cloud_restore_failed(
            node,
            backup,
            restore,
            "PROVIDER_RECONCILIATION_EXHAUSTED",
            "The provider restore could not be reconciled automatically and requires manual review.",
        )
        return False

    restore.status = restore.Status.IN_PROGRESS
    restore.operation_phase = restore.OperationPhase.CREATE_UNKNOWN
    restore.execution_phase = "provider_create_unknown"
    restore.last_error_code = "PROVIDER_CREATE_OUTCOME_UNKNOWN"
    restore.error = (
        "The provider request outcome is unknown; BackupSheep will reconcile before any retry."
    )
    restore.next_retry_at = now + timedelta(seconds=countdown)
    restore.save()
    _schedule_cloud_restore_reconciliation(
        node,
        backup,
        restore,
        countdown=countdown,
    )
    return True


def _clear_cloud_restore_error_rollups(restore):
    """Clear presentation-only errors after a healthy provider observation.

    Provider identity and reconciliation witnesses live in their own fields.
    These values are only safe UI/error rollups, so a later healthy lifecycle
    observation must not continue presenting an earlier transient or manual
    review result as the current state.
    """
    params = dict(restore.params or {})
    params.pop("_bs_last_error_code", None)
    params.pop("_bs_last_error_category", None)
    restore.params = params
    restore.last_error_code = ""
    restore.error = None


def _cloud_restore_has_current_error_rollup(restore):
    """Return whether this provider observation wrote a current safe error."""
    params = dict(restore.params or {})
    return any(
        str(value or "").strip()
        for value in (
            restore.last_error_code,
            restore.error,
            params.get("_bs_last_error_code"),
            params.get("_bs_last_error_category"),
        )
    )


@current_app.task(
    name="restore_cloud_backup",
    track_started=True,
    bind=True,
    max_retries=0,
    soft_time_limit=(24 * 3600),
)
def restore_cloud_backup(self, node_id=None, backup_id=None, restore_id=None):
    """Initiate a restore of a completed cloud/volume snapshot.

    Delegates the provider API call to the node's restore_snapshot(), which must
    set restore.resource_id on success (or raise). Provider adapters persist a
    durable target/job pointer or recover one by an exact provider-side marker;
    redeliveries with that pointer resume polling instead of issuing a duplicate
    create request. A provider failure without a durable pointer marks the
    restore FAILED.
    """
    node = CoreNode.objects.get(id=node_id)
    backup = node.get_cloud_backup(backup_id)
    restore = CoreCloudRestore.objects.get(id=restore_id, node=node)
    lease = DurableRestoreLease(
        restore,
        phase="provider_create",
        task_id=self.request.id,
        worker_name=getattr(self.request, "hostname", ""),
    )
    try:
        restore = lease.claim()
    except RestoreAlreadyTerminal:
        return
    except RestoreLeaseBusy as error:
        raise self.retry(countdown=error.retry_after, max_retries=2880)

    try:
        _notify_once(
            restore,
            "started_notification_enqueued_at",
            lambda: notify_restore_started(node, backup, restore),
        )

        # A committed provider pointer is authoritative.  Redelivery resumes
        # polling and never emits another create request.
        if restore.provider_job_id or restore.resource_id:
            lease.checkpoint("provider_polling")
            restore.operation_phase = restore.OperationPhase.POLLING
            restore.save(update_fields=["operation_phase", "modified"])
            poll_cloud_restore.apply_async(
                args=[node.id, restore.id], countdown=30
            )
            return

        lease.checkpoint("provider_reconciling")
        restore.operation_phase = restore.OperationPhase.RECONCILING
        restore.save(update_fields=["operation_phase", "modified"])
        try:
            restore_result = restore.node_type_object.restore_snapshot(
                backup, restore
            )
        except Exception as error:
            capture_exception(error)
            restore = _refresh_bound_restore(lease)
            if restore.status == restore.Status.FAILED or (
                restore.operation_phase == restore.OperationPhase.MANUAL_REVIEW
            ):
                _mark_cloud_restore_failed(
                    node,
                    backup,
                    restore,
                    restore.last_error_code or "PROVIDER_RESTORE_FAILED",
                    "The provider rejected the restore or ownership could not be verified.",
                )
                return

            _defer_cloud_restore_reconciliation(node, backup, restore)
            return

        lease.ensure_owned()
        restore = _refresh_bound_restore(lease)
        if restore.status == restore.Status.FAILED:
            _mark_cloud_restore_failed(
                node,
                backup,
                restore,
                restore.last_error_code or "PROVIDER_RESTORE_FAILED",
                "The provider reported that the restore failed.",
            )
            return
        if restore.provider_job_id or restore.resource_id:
            restore.status = restore.Status.IN_PROGRESS
            restore.operation_phase = restore.OperationPhase.POLLING
            restore.execution_phase = "provider_polling"
            restore.next_retry_at = None
            restore.save()
            poll_cloud_restore.apply_async(
                args=[node.id, restore.id], countdown=30
            )
            return

        # A provider adapter may have completed a reconciliation pass without a
        # pointer (for example while a rate limit is active).  It is safe to run
        # reconciliation again, but never safe to blindly create.
        _defer_cloud_restore_reconciliation(node, backup, restore)
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError) as error:
        capture_exception(error)
        raise self.retry(countdown=30, max_retries=2880)
    finally:
        lease.release()


@current_app.task(name="poll_cloud_restore", bind=True, ignore_result=True)
def poll_cloud_restore(self, node_id, restore_id, started_at=None, interval=120, timeout=86400):
    """Asynchronously wait for a restored resource to become ready.

    Mirrors poll_cloud_backup: runs ONE status check per invocation and re-queues
    itself between checks, so the worker is never blocked for the whole restore.
    A single failed/transient status check never fails the restore -- it is marked
    FAILED only when the provider reports an error, or after `timeout` seconds.
    """
    try:
        node = CoreNode.objects.get(id=node_id)
    except CoreNode.DoesNotExist:
        return

    restore = CoreCloudRestore.objects.filter(id=restore_id, node=node).first()
    if restore is None:
        return

    lease = DurableRestoreLease(
        restore,
        phase="provider_poll",
        task_id=self.request.id,
        worker_name=getattr(self.request, "hostname", ""),
    )
    try:
        restore = lease.claim()
    except RestoreAlreadyTerminal:
        return
    except RestoreLeaseBusy as error:
        raise self.retry(countdown=error.retry_after, max_retries=2880)

    try:
        metadata = dict(restore.execution_metadata or {})
        poll_started_at = metadata.get("poll_started_at")
        if not poll_started_at:
            poll_started_at = timezone.now().isoformat()
            metadata["poll_started_at"] = poll_started_at
            restore.execution_metadata = metadata
            restore.save(update_fields=["execution_metadata", "modified"])
        try:
            poll_started = datetime.fromisoformat(poll_started_at)
            if timezone.is_naive(poll_started):
                poll_started = timezone.make_aware(poll_started)
        except (TypeError, ValueError):
            poll_started = timezone.now()
        if (timezone.now() - poll_started).total_seconds() > timeout:
            _mark_cloud_restore_failed(
                node,
                restore.backup,
                restore,
                "PROVIDER_RESTORE_TIMEOUT",
                "Timed out waiting for the restored resource to become ready.",
            )
            return

        try:
            # Clear only on this in-memory observation first. A provider adapter
            # that sees a fresh retry/reconciliation condition writes a new safe
            # rollup during poll_status(); a healthy observation leaves this
            # object clear. This distinguishes a current provider condition from
            # stale UI state without erasing durable ownership witnesses.
            _clear_cloud_restore_error_rollups(restore)
            status = restore.poll_status()
            provider_observation_has_error = (
                _cloud_restore_has_current_error_rollup(restore)
            )
        except Exception as error:
            capture_exception(error)
            code, message, retryable = _restore_error_outcome(error)
            restore.last_error_code = code
            restore.error = message
            if not retryable:
                _mark_cloud_restore_failed(
                    node, restore.backup, restore, code, message
                )
                return
            failures = int(metadata.get("consecutive_poll_failures") or 0) + 1
            metadata["consecutive_poll_failures"] = failures
            restore.execution_metadata = metadata
            restore.execution_phase = "provider_poll_retry"
            restore.next_retry_at = timezone.now() + timedelta(seconds=interval)
            restore.save()
            poll_cloud_restore.apply_async(
                args=[node_id, restore_id, None, interval, timeout],
                countdown=interval,
            )
            return

        lease.ensure_owned()
        restore = _refresh_bound_restore(lease)
        metadata = dict(restore.execution_metadata or {})
        metadata["consecutive_poll_failures"] = 0
        restore.execution_metadata = metadata

        if status == CoreCloudRestore.Status.COMPLETE:
            _clear_cloud_restore_error_rollups(restore)
            restore.status = CoreCloudRestore.Status.COMPLETE
            restore.operation_phase = restore.OperationPhase.COMPLETE
            restore.execution_phase = "complete"
            restore.next_retry_at = None
            restore.save()
            _notify_once(
                restore,
                "completed_notification_enqueued_at",
                lambda: notify_restore_completed(node, restore.backup, restore),
            )
            return

        if status == CoreCloudRestore.Status.FAILED:
            _mark_cloud_restore_failed(
                node,
                restore.backup,
                restore,
                restore.last_error_code or "PROVIDER_RESTORE_FAILED",
                "The provider reported that the restore failed.",
            )
            return

        if status != CoreCloudRestore.Status.IN_PROGRESS:
            _mark_cloud_restore_failed(
                node,
                restore.backup,
                restore,
                "PROVIDER_MALFORMED_RESPONSE",
                "The provider returned an unsupported restore lifecycle state.",
            )
            return

        restore.status = CoreCloudRestore.Status.IN_PROGRESS
        if provider_observation_has_error:
            # Keep an error/reconciliation phase that the adapter wrote during
            # this exact observation. The outer task must not turn a bounded
            # no-match witness into a falsely healthy POLLING state.
            if restore.operation_phase == restore.OperationPhase.RECONCILING:
                restore.execution_phase = "provider_reconciling"
            elif restore.operation_phase == restore.OperationPhase.CREATE_UNKNOWN:
                restore.execution_phase = "provider_create_unknown"
            else:
                restore.operation_phase = restore.OperationPhase.POLLING
                restore.execution_phase = "provider_poll_retry"
        else:
            restore.operation_phase = restore.OperationPhase.POLLING
            restore.execution_phase = "provider_polling"
            restore.next_retry_at = None
            _clear_cloud_restore_error_rollups(restore)
        restore.save()
        countdown = interval
        if restore.next_retry_at:
            retry_seconds = int(
                (restore.next_retry_at - timezone.now()).total_seconds()
            )
            countdown = max(1, retry_seconds)
        poll_cloud_restore.apply_async(
            args=[node_id, restore_id, None, interval, timeout],
            countdown=countdown,
        )
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError) as error:
        capture_exception(error)
        raise self.retry(countdown=30, max_retries=2880)
    finally:
        lease.release()


@current_app.task(
    name="restore_website_backup",
    track_started=True,
    bind=True,
    default_retry_delay=120,
    max_retries=96,
    soft_time_limit=(24 * 3600),
)
def restore_website_backup(self, node_id=None, backup_id=None, restore_id=None):
    """Restore a completed website backup zip back onto its source server.

    A renewable DB lease fences duplicate deliveries.  Transfer operations are
    convergent, so a worker crash resumes the same restore instead of creating a
    second restore record or silently abandoning partial work.
    """
    from apps._tasks.integration.restore_website import restore_website

    node = CoreNode.objects.get(id=node_id)
    backup = node.website.backups.get(id=backup_id)
    restore = CoreWebsiteRestore.objects.get(id=restore_id, backup=backup)

    return _run_materialized_restore(
        self,
        node=node,
        backup=backup,
        restore=restore,
        engine=restore_website,
        phase="website_restore",
    )


@current_app.task(
    name="restore_database_backup",
    track_started=True,
    bind=True,
    default_retry_delay=120,
    max_retries=96,
    soft_time_limit=(24 * 3600),
)
def restore_database_backup(self, node_id=None, backup_id=None, restore_id=None):
    """Restore a completed database backup zip back into its source server.

    A renewable DB lease fences duplicate deliveries.  The database engine uses
    deterministic fork targets/transactional imports so a worker crash can resume
    without replaying an untracked destructive operation.
    """
    from apps._tasks.integration.restore_database import restore_database

    node = CoreNode.objects.get(id=node_id)
    backup = node.database.backups.get(id=backup_id)
    restore = CoreDatabaseRestore.objects.get(id=restore_id, backup=backup)

    return _run_materialized_restore(
        self,
        node=node,
        backup=backup,
        restore=restore,
        engine=restore_database,
        phase="database_restore",
    )


def _recoverable_restore_rows(model, *, now, cutoff, batch_size):
    """Select restores whose delivery/worker lease is absent or expired.

    ``next_retry_at`` doubles as a short durable enqueue reservation.  This keeps
    multiple beat processes from flooding the broker with duplicate recovery
    messages; task-side leases and fencing remain the final concurrency guard.
    """
    terminal = [model.Status.COMPLETE, model.Status.FAILED]
    cancelled = getattr(model.Status, "CANCELLED", None)
    if cancelled is not None:
        terminal.append(cancelled)
    due = Q(next_retry_at__lte=now) | Q(
        next_retry_at__isnull=True,
        modified__lt=cutoff,
    )
    expired = Q(
        lease_token__isnull=False,
        lease_expires_at__lte=now,
    ) | Q(
        lease_owner__gt="",
        lease_expires_at__isnull=True,
    )
    return list(
        model.objects.exclude(status__in=terminal)
        .exclude(lease_token__isnull=False, lease_expires_at__gt=now)
        .filter(due | expired)
        .order_by("modified")[:batch_size]
    )


def _reserve_restore_recovery(model, restore_id, *, now, retry_seconds):
    with transaction.atomic():
        restore = model.objects.select_for_update().get(pk=restore_id)
        if restore.status in {
            restore.Status.COMPLETE,
            restore.Status.FAILED,
            getattr(restore.Status, "CANCELLED", object()),
        }:
            return None
        if (
            restore.lease_token
            and restore.lease_expires_at
            and restore.lease_expires_at > now
        ):
            return None
        if restore.next_retry_at and restore.next_retry_at > now:
            return None
        metadata = dict(restore.execution_metadata or {})
        metadata["recovery_enqueued_at"] = now.isoformat()
        metadata["recovery_dispatch_count"] = int(
            metadata.get("recovery_dispatch_count") or 0
        ) + 1
        reserved_until = now + timedelta(seconds=retry_seconds)
        metadata["recovery_dispatch_reserved_until"] = reserved_until.isoformat()
        restore.execution_metadata = metadata
        restore.next_retry_at = reserved_until
        restore.save(
            update_fields=["execution_metadata", "next_retry_at", "modified"]
        )
        return restore


def _dispatch_restore_recovery(restore):
    task_id = f"recover-restore-{restore.__class__.__name__}-{restore.pk}"
    if isinstance(restore, CoreCloudRestore):
        task_name = (
            "poll_cloud_restore"
            if restore.provider_job_id or restore.resource_id
            else "restore_cloud_backup"
        )
        args = (
            [restore.node_id, restore.id]
            if task_name == "poll_cloud_restore"
            else [restore.node_id, restore.backup_id, restore.id]
        )
    elif isinstance(restore, CoreWebsiteRestore):
        task_name = "restore_website_backup"
        args = [restore.backup.node.id, restore.backup_id, restore.id]
    elif isinstance(restore, CoreDatabaseRestore):
        task_name = "restore_database_backup"
        args = [restore.backup.node.id, restore.backup_id, restore.id]
    elif isinstance(restore, CoreVultrDatabaseRestore):
        task_name = (
            "poll_vultr_database_restore"
            if restore.resource_id or restore.provider_job_id
            else "restore_vultr_database"
        )
        args = [restore.id]
    else:
        raise TypeError("Unsupported restore recovery model.")
    current_app.send_task(task_name, task_id=task_id, args=args)


@current_app.task(name="resume_in_progress_restores", bind=True, ignore_result=True)
def resume_in_progress_restores(self):
    """Recover restore messages lost during worker, broker, or server failure."""
    now = timezone.now()
    stale_seconds = int(
        getattr(settings, "RESTORE_RECOVERY_STALE_SECONDS", 5 * 60)
    )
    retry_seconds = int(
        getattr(settings, "RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS", 120)
    )
    batch_size = int(getattr(settings, "RESTORE_RECOVERY_BATCH_SIZE", 100))
    cutoff = now - timedelta(seconds=stale_seconds)
    models = (
        CoreCloudRestore,
        CoreWebsiteRestore,
        CoreDatabaseRestore,
        CoreVultrDatabaseRestore,
    )
    for model in models:
        for candidate in _recoverable_restore_rows(
            model,
            now=now,
            cutoff=cutoff,
            batch_size=batch_size,
        ):
            try:
                restore = _reserve_restore_recovery(
                    model,
                    candidate.pk,
                    now=now,
                    retry_seconds=retry_seconds,
                )
                if restore is not None:
                    _dispatch_restore_recovery(restore)
            except Exception as error:
                # The short DB reservation expires automatically. A provider or
                # broker outage therefore retries safely without exposing details.
                capture_exception(error)
