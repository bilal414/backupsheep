"""Celery tasks for Vultr Managed Database provider backups and forks."""

from datetime import timedelta

from celery import current_app
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.text import slugify
from sentry_sdk import capture_exception

from apps._tasks.integration.restore_lease import (
    DurableRestoreLease,
    RestoreAlreadyTerminal,
    RestoreLeaseBusy,
    RestoreLeaseLost,
)

from apps.console.account.models import CoreAccount
from apps.console.backup.models import (
    CoreVultrDatabaseBackup,
    CoreVultrDatabaseRestore,
    RestoreExecutionLeaseLostError,
)
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from apps.console.vultr_database import (
    VultrDatabaseDuplicateError,
    VultrDatabaseError,
)


_VULTR_RESTORE_ERRORS = {
    "auth_failed": (
        "PROVIDER_AUTH_FAILED",
        "Vultr rejected the configured credentials or permissions.",
        False,
    ),
    "not_found": (
        "PROVIDER_NOT_FOUND",
        "The Vultr managed database resource was not found.",
        False,
    ),
    "rate_limited": (
        "PROVIDER_RATE_LIMIT",
        "Vultr rate-limited the request; restore will resume automatically.",
        True,
    ),
    "timeout": (
        "PROVIDER_TIMEOUT",
        "The Vultr request timed out; restore will resume automatically.",
        True,
    ),
    "transient_outage": (
        "PROVIDER_TRANSIENT_OUTAGE",
        "Vultr is temporarily unavailable; restore will resume automatically.",
        True,
    ),
    "malformed_response": (
        "PROVIDER_MALFORMED_RESPONSE",
        "Vultr returned an invalid response; automatic restore was stopped safely.",
        False,
    ),
    "duplicate_candidates": (
        "PROVIDER_RESTORE_AMBIGUOUS",
        "Multiple Vultr databases match this restore marker; manual review is required.",
        False,
    ),
    "unsupported": (
        "PROVIDER_RESTORE_UNSUPPORTED",
        "This Vultr managed database plan or engine does not support the requested restore.",
        False,
    ),
}


def _safe_vultr_restore_error(error):
    return _VULTR_RESTORE_ERRORS.get(
        getattr(error, "category", ""),
        (
            "PROVIDER_REQUEST_FAILED",
            "Vultr rejected the managed database restore request.",
            False,
        ),
    )


def _retry_delay(error, default=120):
    try:
        return max(5, min(int(getattr(error, "retry_after", None) or default), 3600))
    except (TypeError, ValueError):
        return default


def _backup_for_task(node, task_id, backup_type, attempt_no, schedule_id, notes):
    with transaction.atomic():
        # The outbox claim must be committed with the backup row so a broker
        # redelivery can be reconciled without creating another provider job.
        from apps.console.backup.models import CoreBackupRequest

        CoreNode.objects.select_for_update().get(pk=node.pk)
        active = CoreVultrDatabaseBackup.objects.filter(
            vultr_database=node.vultr_database,
            status__in=UtilBackup.ACTIVE_STATUSES,
        ).exclude(celery_task_id=task_id).first()
        if active:
            CoreBackupRequest.link_backup(
                task_id=task_id,
                node=node,
                backup=active,
                duplicate=True,
            )
            return None
        backup, created = CoreVultrDatabaseBackup.objects.get_or_create(
            celery_task_id=task_id,
            defaults={
                "vultr_database": node.vultr_database,
                "uuid": "",
                "name": node.name,
            },
        )
        if backup.vultr_database_id != node.vultr_database.id:
            raise ValueError("Celery task is already associated with another database.")
        if created:
            backup.uuid = slugify(f"bs-{node.name[:24]}-vultr-db-b{backup.id}")
        backup.name = f"{node.name} - {backup_type}"
        backup.status = UtilBackup.Status.IN_PROGRESS
        backup.type = backup_type
        backup.attempt_no = attempt_no
        backup.schedule_id = schedule_id
        backup.notes = notes
        backup.region = node.vultr_database.region
        backup.save()
        CoreBackupRequest.link_backup(
            task_id=task_id,
            node=node,
            backup=backup,
            duplicate=False,
        )
        return backup


@current_app.task(
    name="backup_vultr_database",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    soft_time_limit=24 * 3600,
)
def backup_vultr_database(
    self, node_id=None, schedule_id=None, storage_ids=None, notes=None, resume=False
):
    del storage_ids, resume  # provider-managed backups are not copied to a destination here
    node = CoreNode.objects.filter(
        Q(id=node_id)
        & ~Q(status__in=(CoreNode.Status.DELETE_REQUESTED, CoreNode.Status.PAUSED))
        & ~Q(connection__status__in=(CoreConnection.Status.DELETE_REQUESTED, CoreConnection.Status.PAUSED))
        & ~Q(connection__account__status=CoreAccount.Status.DELETE_REQUESTED)
    ).first()
    if not node or not hasattr(node, "vultr_database"):
        return
    if schedule_id and not CoreSchedule.objects.filter(
        id=schedule_id, status=CoreSchedule.Status.ACTIVE
    ).exists():
        return
    backup_type = UtilBackup.Type.SCHEDULED if schedule_id else UtilBackup.Type.ON_DEMAND
    backup = _backup_for_task(
        node, self.request.id, backup_type, self.request.retries + 1, schedule_id, notes
    )
    if backup is None:
        return
    try:
        if not backup.provider_marker:
            node.vultr_database.create_snapshot(backup)
        poll_vultr_database_backup.apply_async(args=[backup.id], countdown=60)
    except SoftTimeLimitExceeded:
        backup.status = UtilBackup.Status.TIMEOUT
        backup.save(update_fields=["status", "modified"])
        backup.record_execution_error(
            code="PROVIDER_TIMEOUT",
            message="The Vultr managed database backup timed out.",
            retryable=True,
            retry_at=timezone.now() + timedelta(seconds=_retry_delay(None)),
        )
    except Exception as error:
        capture_exception(error)
        code, message, retryable = _safe_vultr_restore_error(error)
        backup.metadata = {"error_code": code}
        backup.status = (
            UtilBackup.Status.RETRYING if retryable else UtilBackup.Status.FAILED
        )
        backup.save(update_fields=["metadata", "status", "modified"])
        backup.record_execution_error(
            code=code,
            message=message,
            retryable=retryable,
            retry_at=(
                timezone.now() + timedelta(seconds=_retry_delay(error))
                if retryable
                else None
            ),
        )
        if not retryable:
            return
        try:
            raise self.retry(countdown=_retry_delay(error))
        except MaxRetriesExceededError:
            backup.status = UtilBackup.Status.MAX_RETRY_FAILED
            backup.save(update_fields=["status", "modified"])
            return


@current_app.task(name="poll_vultr_database_backup", bind=True, ignore_result=True)
def poll_vultr_database_backup(self, backup_id):
    backup = CoreVultrDatabaseBackup.objects.filter(pk=backup_id).first()
    if not backup or backup.status not in UtilBackup.ACTIVE_STATUSES:
        return
    try:
        status = backup.poll_status()
    except Exception as error:
        # The model adapter handles categorized provider failures. Any
        # uncategorized failure is a fail-closed client/contract error, not an
        # excuse to leave the backup falsely IN_PROGRESS forever.
        capture_exception(error)
        code = "PROVIDER_REQUEST_FAILED"
        message = "The Vultr managed database backup status could not be confirmed."
        backup.status = UtilBackup.Status.FAILED
        backup.provider_error_class = "provider_error"
        backup.provider_status = "provider_error"
        backup.metadata = {"error_code": code}
        backup.save(update_fields=["status", "provider_error_class", "provider_status", "metadata", "modified"])
        backup.record_execution_error(code=code, message=message)
        return
    if status == UtilBackup.Status.IN_PROGRESS:
        poll_vultr_database_backup.apply_async(args=[backup.id], countdown=120)


@current_app.task(
    name="restore_vultr_database",
    track_started=True,
    bind=True,
    default_retry_delay=120,
    max_retries=10,
)
def restore_vultr_database(self, restore_id):
    restore = CoreVultrDatabaseRestore.objects.select_related(
        "backup__vultr_database__node"
    ).filter(pk=restore_id).first()
    if not restore:
        return
    lease = DurableRestoreLease(
        restore,
        phase="vultr_database_create",
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
        if restore.resource_id:
            lease.checkpoint("vultr_database_poll")
            poll_vultr_database_restore.apply_async(
                args=[restore.id], countdown=30
            )
            return
        if not restore.resource_id:
            restore.backup.vultr_database.restore_snapshot(restore.backup, restore)
        lease.ensure_owned()
        poll_vultr_database_restore.apply_async(args=[restore.id], countdown=60)
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError) as error:
        capture_exception(error)
        raise self.retry(countdown=30, max_retries=2880)
    except VultrDatabaseDuplicateError as error:
        capture_exception(error)
        code, message, _retryable = _safe_vultr_restore_error(error)
        restore.status = CoreVultrDatabaseRestore.Status.FAILED
        restore.execution_phase = "manual_review"
        restore.last_error_code = code
        restore.error = message
        restore.save()
    except VultrDatabaseError as error:
        capture_exception(error)
        code, message, retryable = _safe_vultr_restore_error(error)
        restore.provider_status = error.category
        restore.provider_http_status = error.status_code
        restore.last_error_code = code
        restore.error = message
        delay = _retry_delay(error)
        if retryable:
            restore.status = CoreVultrDatabaseRestore.Status.IN_PROGRESS
            restore.execution_phase = "vultr_database_reconcile"
            restore.next_retry_at = timezone.now() + timedelta(seconds=delay)
            restore.save()
            restore_vultr_database.apply_async(args=[restore.id], countdown=delay)
        else:
            restore.status = CoreVultrDatabaseRestore.Status.FAILED
            restore.execution_phase = "failed"
            restore.save()
    except Exception as error:
        capture_exception(error)
        restore.status = CoreVultrDatabaseRestore.Status.IN_PROGRESS
        restore.execution_phase = "vultr_database_create_unknown"
        restore.last_error_code = "PROVIDER_CREATE_OUTCOME_UNKNOWN"
        restore.error = (
            "The Vultr fork request outcome is unknown; BackupSheep will reconcile before retrying."
        )
        restore.next_retry_at = timezone.now() + timedelta(seconds=120)
        restore.save()
        restore_vultr_database.apply_async(args=[restore.id], countdown=120)
    finally:
        lease.release()


@current_app.task(name="poll_vultr_database_restore", bind=True, ignore_result=True)
def poll_vultr_database_restore(self, restore_id):
    restore = CoreVultrDatabaseRestore.objects.select_related(
        "backup__vultr_database__node"
    ).filter(pk=restore_id).first()
    if not restore:
        return
    lease = DurableRestoreLease(
        restore,
        phase="vultr_database_poll",
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
        # A fork response may contain only an asynchronous job id, or the worker
        # may have crashed before saving the returned database id. Re-run the
        # marker reconciliation before polling; the adapter refuses a second fork
        # once its provider marker has entered unknown-outcome state.
        if not restore.resource_id:
            restore.backup.vultr_database.restore_snapshot(restore.backup, restore)
            lease.ensure_owned()
            restore.refresh_from_db()
            restore.bind_execution_fence(lease.owner, lease.token)
            lease.restore = restore
            if not restore.resource_id:
                poll_vultr_database_restore.apply_async(args=[restore.id], countdown=120)
                return

        status = restore.backup.vultr_database.check_restore(restore)
        lease.ensure_owned()
        if status == CoreVultrDatabaseRestore.Status.IN_PROGRESS:
            restore.execution_phase = "vultr_database_poll"
            restore.save(update_fields=["execution_phase", "modified"])
            poll_vultr_database_restore.apply_async(
                args=[restore.id], countdown=120
            )
        elif status == CoreVultrDatabaseRestore.Status.COMPLETE:
            restore.status = status
            restore.execution_phase = "complete"
            restore.error = None
            restore.last_error_code = ""
            restore.next_retry_at = None
            restore.save()
        else:
            restore.status = CoreVultrDatabaseRestore.Status.FAILED
            restore.execution_phase = "failed"
            restore.last_error_code = (
                restore.last_error_code or "PROVIDER_RESTORE_FAILED"
            )
            restore.error = "Vultr reported that the managed database fork failed."
            restore.save()
    except (RestoreLeaseLost, RestoreExecutionLeaseLostError) as error:
        capture_exception(error)
        raise self.retry(countdown=30, max_retries=2880)
    except VultrDatabaseDuplicateError as error:
        capture_exception(error)
        code, message, _retryable = _safe_vultr_restore_error(error)
        restore.status = CoreVultrDatabaseRestore.Status.FAILED
        restore.execution_phase = "manual_review"
        restore.last_error_code = code
        restore.error = message
        restore.save()
    except VultrDatabaseError as error:
        capture_exception(error)
        code, message, retryable = _safe_vultr_restore_error(error)
        restore.provider_status = error.category
        restore.provider_http_status = error.status_code
        restore.last_error_code = code
        restore.error = message
        delay = _retry_delay(error)
        if retryable:
            restore.status = CoreVultrDatabaseRestore.Status.IN_PROGRESS
            restore.next_retry_at = timezone.now() + timedelta(seconds=delay)
            restore.save()
            poll_vultr_database_restore.apply_async(
                args=[restore.id], countdown=delay
            )
        else:
            restore.status = CoreVultrDatabaseRestore.Status.FAILED
            restore.execution_phase = "failed"
            restore.save()
    except Exception as error:
        capture_exception(error)
        # Status polling is read-only. An uncategorized exception is a
        # contract/client failure and must not masquerade as a transient outage
        # or keep a restore spinning indefinitely.
        restore.status = CoreVultrDatabaseRestore.Status.FAILED
        restore.execution_phase = "manual_review"
        restore.last_error_code = "PROVIDER_REQUEST_FAILED"
        restore.error = "The Vultr managed database restore status could not be confirmed."
        restore.save()
    finally:
        lease.release()
