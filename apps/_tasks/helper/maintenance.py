"""Periodic maintenance tasks for storage destinations.

Kept separate from helper/tasks.py so the S3 immutability follow-ups stay in one
reviewable module. Registered in settings.CELERY_IMPORTS.
"""
from celery import current_app
from django.db.models import Q
from sentry_sdk import capture_exception


@current_app.task(
    name="storage_aws_s3_sync_lifecycle",
    bind=True,
    ignore_result=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 5},
)
def storage_aws_s3_sync_lifecycle(self, storage_aws_s3_id):
    """Apply (or remove) BackupSheep's S3 lifecycle rule for one destination.

    Runs off the request path: the AWS call can be slow, and syncing inside the
    storage create/update transaction held it open for the duration of the request.
    Retried with backoff so a transient S3 error doesn't lose the rule change.
    """
    from apps.console.storage.models import CoreStorageAWSS3

    try:
        aws_s3 = CoreStorageAWSS3.objects.get(id=storage_aws_s3_id)
    except CoreStorageAWSS3.DoesNotExist:
        # Destination was deleted between dispatch and execution; nothing to do.
        return
    aws_s3.sync_lifecycle_configuration()


@current_app.task(name="retry_protected_storage_deletes", bind=True, ignore_result=True)
def retry_protected_storage_deletes(self):
    """Re-attempt cleanup for storage points whose deletion was deferred.

    When S3 Object Lock retention (or a missing version ID) defers a delete, the
    storage point keeps its catalog entry with metadata.deletion_protection set, so
    the protected copy stays restorable. Without this task nothing ever retried the
    delete: keep_last retention silently stalled and the object stayed in S3 forever.
    This periodic task retries points whose recorded retain-until has passed (or that
    have no retain-until, e.g. a legal-hold check), letting soft_delete() re-evaluate
    against live S3 state.

    Permanent protections are skipped by design: air-gapped copies and destinations
    with deletion protection (no_delete) must never be deleted by BackupSheep.
    """
    from django.utils import timezone

    from apps.console.backup.models import (
        CoreBasecampBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
        CoreWebsiteBackupStoragePoints,
    )

    point_models = (
        CoreWebsiteBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
        CoreBasecampBackupStoragePoints,
    )
    now_iso = timezone.now().isoformat()
    for point_model in point_models:
        points = (
            point_model.objects.filter(
                status=point_model.Status.UPLOAD_COMPLETE,
                metadata__deletion_protection__isnull=False,
            )
            .exclude(storage__is_air_gapped=True)
            .exclude(storage__storage_aws_s3__no_delete=True)
            .filter(
                Q(metadata__deletion_protection__retain_until__isnull=True)
                | Q(metadata__deletion_protection__retain_until__lte=now_iso)
            )
            .select_related("storage", "storage__type")
            .iterator()
        )
        for point in points:
            try:
                point.soft_delete()
            except Exception as e:
                capture_exception(e)


@current_app.task(name="cleanup_celery_task_replays", bind=True, ignore_result=True)
def cleanup_celery_task_replays(self):
    """Prune terminal replay rows only after every signed message has expired."""

    from backupsheep.celery_security import prune_completed_task_replays

    return {"deleted": prune_completed_task_replays()}
