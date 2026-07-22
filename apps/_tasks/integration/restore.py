from celery import current_app
from sentry_sdk import capture_exception

from apps.console.backup.models import (
    CoreCloudRestore,
    CoreDatabaseRestore,
    CoreWebsiteRestore,
)
from apps.console.node.models import CoreNode


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
    set restore.resource_id on success (or raise). No automatic retries: if the
    provider accepted the request but the response was lost, retrying could create
    duplicate resources, so a failure simply marks the restore FAILED and the user
    can request a new one.
    """
    node = CoreNode.objects.get(id=node_id)
    restore = CoreCloudRestore.objects.get(id=restore_id, node=node)
    backup = node.get_cloud_backup(backup_id)

    restore.celery_task_id = self.request.id
    restore.save()

    try:
        restore.node_type_object.restore_snapshot(backup, restore)
    except Exception as error:
        capture_exception(error)
        restore.status = CoreCloudRestore.Status.FAILED
        restore.error = error.__str__()
        restore.save()
        return

    # Hand off to async polling instead of blocking the worker (same pattern as
    # poll_cloud_backup): waits for the new resource to become ready.
    poll_cloud_restore.apply_async(args=[node.id, restore.id], countdown=60)


@current_app.task(name="poll_cloud_restore", bind=True, ignore_result=True)
def poll_cloud_restore(self, node_id, restore_id, started_at=None, interval=120, timeout=86400):
    """Asynchronously wait for a restored resource to become ready.

    Mirrors poll_cloud_backup: runs ONE status check per invocation and re-queues
    itself between checks, so the worker is never blocked for the whole restore.
    A single failed/transient status check never fails the restore -- it is marked
    FAILED only when the provider reports an error, or after `timeout` seconds.
    """
    import time as _time

    try:
        node = CoreNode.objects.get(id=node_id)
    except CoreNode.DoesNotExist:
        return

    restore = CoreCloudRestore.objects.filter(id=restore_id, node=node).first()
    if restore is None:
        return

    if restore.status in (
        CoreCloudRestore.Status.COMPLETE,
        CoreCloudRestore.Status.FAILED,
    ):
        return

    if started_at is None:
        started_at = _time.time()

    try:
        status = restore.poll_status()
    except Exception as e:
        capture_exception(e)
        status = CoreCloudRestore.Status.IN_PROGRESS

    if status == CoreCloudRestore.Status.COMPLETE:
        restore.status = CoreCloudRestore.Status.COMPLETE
        restore.save()
        return

    if status == CoreCloudRestore.Status.FAILED:
        restore.status = CoreCloudRestore.Status.FAILED
        restore.save()
        return

    if (_time.time() - started_at) > timeout:
        restore.status = CoreCloudRestore.Status.FAILED
        restore.error = "Timed out waiting for the restored resource to become ready."
        restore.save()
        return

    poll_cloud_restore.apply_async(
        args=[node_id, restore_id, started_at, interval, timeout], countdown=interval
    )


@current_app.task(
    name="restore_website_backup",
    track_started=True,
    bind=True,
    max_retries=0,
    soft_time_limit=(24 * 3600),
)
def restore_website_backup(self, node_id=None, backup_id=None, restore_id=None):
    """Restore a completed website backup zip back onto its source server.

    No automatic retries: a restore pushes data to the user's server, so a lost
    response must not silently re-run it -- a failure marks the restore FAILED
    and the user can request a new one.
    """
    from apps._tasks.integration.restore_website import restore_website

    node = CoreNode.objects.get(id=node_id)
    backup = node.website.backups.get(id=backup_id)
    restore = CoreWebsiteRestore.objects.get(id=restore_id, backup=backup)

    restore.status = CoreWebsiteRestore.Status.IN_PROGRESS
    restore.celery_task_id = self.request.id
    restore.save()

    try:
        restore_website(backup, restore)
    except Exception as error:
        capture_exception(error)
        restore.status = CoreWebsiteRestore.Status.FAILED
        restore.error = error.__str__()
        restore.save()
        return

    restore.status = CoreWebsiteRestore.Status.COMPLETE
    restore.save()


@current_app.task(
    name="restore_database_backup",
    track_started=True,
    bind=True,
    max_retries=0,
    soft_time_limit=(24 * 3600),
)
def restore_database_backup(self, node_id=None, backup_id=None, restore_id=None):
    """Restore a completed database backup zip back into its source server.

    No automatic retries: a restore pushes data to the user's server, so a lost
    response must not silently re-run it -- a failure marks the restore FAILED
    and the user can request a new one.
    """
    from apps._tasks.integration.restore_database import restore_database

    node = CoreNode.objects.get(id=node_id)
    backup = node.database.backups.get(id=backup_id)
    restore = CoreDatabaseRestore.objects.get(id=restore_id, backup=backup)

    restore.status = CoreDatabaseRestore.Status.IN_PROGRESS
    restore.celery_task_id = self.request.id
    restore.save()

    try:
        restore_database(backup, restore)
    except Exception as error:
        capture_exception(error)
        restore.status = CoreDatabaseRestore.Status.FAILED
        restore.error = error.__str__()
        restore.save()
        return

    restore.status = CoreDatabaseRestore.Status.COMPLETE
    restore.save()
