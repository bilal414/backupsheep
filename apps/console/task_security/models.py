from django.db import models


class CoreCeleryTaskReplay(models.Model):
    """One durable execution identity for an authenticated Celery delivery."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        RETRY = "retry", "Retry published"
        COMPLETE = "complete", "Complete"

    execution_key = models.CharField(max_length=64, primary_key=True, editable=False)
    envelope_digest = models.CharField(max_length=64, unique=True, editable=False)
    task_id = models.CharField(max_length=255, editable=False)
    task_name = models.CharField(max_length=255, editable=False)
    publisher_lane = models.CharField(max_length=16, editable=False)
    target_lane = models.CharField(max_length=16, editable=False)
    retry_count = models.PositiveIntegerField(default=0, editable=False)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
        editable=False,
    )
    first_seen_at = models.DateTimeField(auto_now_add=True, editable=False)
    last_seen_at = models.DateTimeField(auto_now=True, editable=False)
    completed_at = models.DateTimeField(null=True, blank=True, editable=False)
    delivery_count = models.PositiveIntegerField(default=1, editable=False)

    class Meta:
        db_table = "backupsheep_celery_task_replay"
        indexes = [
            models.Index(
                fields=("status", "last_seen_at"),
                name="celery_replay_status_seen",
            )
        ]
