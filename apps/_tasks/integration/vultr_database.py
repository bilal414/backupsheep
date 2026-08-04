"""Celery tasks for Vultr Managed Database provider backups and forks."""

from celery import current_app
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded
from django.db import transaction
from django.db.models import Q
from django.utils.text import slugify

from apps.console.account.models import CoreAccount
from apps.console.backup.models import (
    CoreVultrDatabaseBackup,
    CoreVultrDatabaseRestore,
)
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from apps.console.vultr_database import (
    VultrDatabaseDuplicateError,
    VultrDatabaseError,
)


def _backup_for_task(node, task_id, backup_type, attempt_no, schedule_id, notes):
    with transaction.atomic():
        CoreNode.objects.select_for_update().get(pk=node.pk)
        active = CoreVultrDatabaseBackup.objects.filter(
            vultr_database=node.vultr_database,
            status__in=UtilBackup.ACTIVE_STATUSES,
        ).exclude(celery_task_id=task_id).first()
        if active:
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
    except Exception as error:
        backup.metadata = {"error": str(error)[:512]}
        backup.status = UtilBackup.Status.FAILED
        backup.save(update_fields=["metadata", "status", "modified"])
        try:
            raise self.retry(exc=error)
        except MaxRetriesExceededError:
            return


@current_app.task(name="poll_vultr_database_backup", bind=True, ignore_result=True)
def poll_vultr_database_backup(self, backup_id):
    backup = CoreVultrDatabaseBackup.objects.filter(pk=backup_id).first()
    if not backup or backup.status not in UtilBackup.ACTIVE_STATUSES:
        return
    status = backup.poll_status()
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
    if not restore or restore.status in {
        CoreVultrDatabaseRestore.Status.COMPLETE,
        CoreVultrDatabaseRestore.Status.FAILED,
        CoreVultrDatabaseRestore.Status.CANCELLED,
    }:
        return
    try:
        if not restore.resource_id:
            restore.backup.vultr_database.restore_snapshot(restore.backup, restore)
        poll_vultr_database_restore.apply_async(args=[restore.id], countdown=60)
    except VultrDatabaseDuplicateError as error:
        restore.status = CoreVultrDatabaseRestore.Status.FAILED
        restore.error = str(error)
        restore.save(update_fields=["status", "error", "modified"])
    except VultrDatabaseError as error:
        restore.provider_status = error.category
        restore.provider_http_status = error.status_code
        restore.error = str(error)
        restore.save(update_fields=["provider_status", "provider_http_status", "error", "modified"])
        if error.category in {"rate_limited", "transient_outage"}:
            raise self.retry(exc=error)
        restore.status = CoreVultrDatabaseRestore.Status.FAILED
        restore.save(update_fields=["status", "modified"])
    except Exception as error:
        restore.error = str(error)
        restore.save(update_fields=["error", "modified"])
        raise self.retry(exc=error)


@current_app.task(name="poll_vultr_database_restore", bind=True, ignore_result=True)
def poll_vultr_database_restore(self, restore_id):
    restore = CoreVultrDatabaseRestore.objects.select_related(
        "backup__vultr_database__node"
    ).filter(pk=restore_id).first()
    if not restore or restore.status in {
        CoreVultrDatabaseRestore.Status.COMPLETE,
        CoreVultrDatabaseRestore.Status.FAILED,
        CoreVultrDatabaseRestore.Status.CANCELLED,
    }:
        return

    # A fork response may contain only an asynchronous job id, or the worker
    # may have crashed before saving the returned database id. Re-run the
    # provider-side marker reconciliation before polling; the adapter refuses
    # to issue a second fork once its outcome is unknown.
    if not restore.resource_id:
        try:
            restore.backup.vultr_database.restore_snapshot(restore.backup, restore)
        except VultrDatabaseDuplicateError as error:
            restore.status = CoreVultrDatabaseRestore.Status.FAILED
            restore.error = str(error)
            restore.save(update_fields=["status", "error", "modified"])
            return
        except VultrDatabaseError as error:
            restore.provider_status = error.category
            restore.provider_http_status = error.status_code
            restore.error = str(error)
            restore.status = (
                CoreVultrDatabaseRestore.Status.IN_PROGRESS
                if error.category in {"rate_limited", "transient_outage"}
                else CoreVultrDatabaseRestore.Status.FAILED
            )
            restore.save(
                update_fields=[
                    "provider_status", "provider_http_status", "error", "status", "modified"
                ]
            )
            if restore.status == CoreVultrDatabaseRestore.Status.IN_PROGRESS:
                poll_vultr_database_restore.apply_async(args=[restore.id], countdown=120)
            return
        restore.refresh_from_db()
        if not restore.resource_id:
            if restore.status == CoreVultrDatabaseRestore.Status.IN_PROGRESS:
                poll_vultr_database_restore.apply_async(args=[restore.id], countdown=120)
            return

    status = restore.backup.vultr_database.check_restore(restore)
    if status == CoreVultrDatabaseRestore.Status.IN_PROGRESS:
        poll_vultr_database_restore.apply_async(args=[restore.id], countdown=120)
