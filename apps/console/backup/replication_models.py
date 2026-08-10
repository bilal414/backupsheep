"""Durable state for Lightsail bucket replication and prefix restores.

These models intentionally live outside ``backup.models``.  The primary integration
worker can import them from ``apps.console.backup.replication_models`` and generate a
follow-up migration without changing the long-lived CoreLightsailBackup contract.

The task layer treats the rows in this module as the source of truth for recovery:
an object row records the source version being copied, a lease row prevents duplicate
workers from copying it concurrently, and a multipart row records every part that
has already reached the destination.
"""

import uuid

from django.db import models
from model_utils.models import TimeStampedModel

from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection
from apps.console.storage.models import CoreStorage


class CoreLightsailBucketReplication(TimeStampedModel):
    """A durable source-bucket to BackupSheep storage definition."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        DISABLED = "disabled", "Disabled"

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=255, blank=True, default="")
    account = models.ForeignKey(
        CoreAccount,
        related_name="lightsail_bucket_replications",
        on_delete=models.CASCADE,
    )
    # CoreAuthLightsail is a one-to-one child of CoreConnection.  Keeping the
    # definition attached to the connection means its encrypted credentials are
    # reused rather than copied into a second, less familiar credential store.
    source_connection = models.ForeignKey(
        CoreConnection,
        related_name="lightsail_bucket_replications",
        on_delete=models.PROTECT,
    )
    source_bucket_name = models.CharField(max_length=1024)
    source_prefix = models.CharField(max_length=1024, blank=True, default="")
    # Empty means the standard AWS S3 endpoint derived from the Lightsail region.
    # This also permits a test/private S3-compatible endpoint without a settings edit.
    source_endpoint_url = models.CharField(max_length=2048, blank=True, default="")
    destination_storage = models.ForeignKey(
        CoreStorage,
        related_name="lightsail_bucket_replications",
        on_delete=models.PROTECT,
    )
    destination_prefix = models.CharField(max_length=1024, blank=True, default="")
    include_versions = models.BooleanField(default=True)
    part_size_bytes = models.PositiveBigIntegerField(default=64 * 1024 * 1024)
    lease_seconds = models.PositiveIntegerField(default=15 * 60)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.ACTIVE
    )
    enabled = models.BooleanField(default=True)
    # The scheduler is intentionally DB-driven rather than one PeriodicTask per
    # bucket. This keeps cadence changes transactional and makes a single beat
    # process safe across many replications.
    interval_minutes = models.PositiveIntegerField(default=60)
    next_run_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    last_run = models.ForeignKey(
        "CoreLightsailBucketReplicationRun",
        related_name="+",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        db_table = "core_lightsail_bucket_replication"
        constraints = [
            models.UniqueConstraint(
                fields=(
                    "source_connection",
                    "source_bucket_name",
                    "source_prefix",
                    "destination_storage",
                    "destination_prefix",
                ),
                name="unique_lightsail_bucket_replication_route",
            )
        ]
        indexes = [
            models.Index(fields=("account", "status")),
            models.Index(fields=("source_bucket_name", "source_prefix")),
        ]

    @staticmethod
    def normalize_prefix(prefix):
        """Return an S3 prefix with one trailing slash, or an empty prefix."""

        value = (prefix or "").strip("/")
        return f"{value}/" if value else ""

    def __str__(self):
        return (
            f"{self.source_bucket_name}:{self.source_prefix} -> "
            f"{self.destination_storage_id}:{self.destination_prefix}"
        )


class CoreLightsailBucketReplicationRun(TimeStampedModel):
    """One idempotent enumeration/transfer pass for a replication definition."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETE = "complete", "Complete"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    replication = models.ForeignKey(
        CoreLightsailBucketReplication,
        related_name="runs",
        on_delete=models.CASCADE,
    )
    # Celery retries/redeliveries pass the same task id.  The constraint is scoped
    # to the definition so task ids from unrelated definitions cannot collide.
    idempotency_key = models.CharField(max_length=255)
    celery_task_id = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    object_count = models.PositiveBigIntegerField(default=0)
    completed_count = models.PositiveBigIntegerField(default=0)
    failed_count = models.PositiveBigIntegerField(default=0)
    delete_marker_count = models.PositiveBigIntegerField(default=0)
    bytes_transferred = models.PositiveBigIntegerField(default=0)
    manifest_key = models.CharField(max_length=2048, blank=True, default="")
    manifest = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_replication_run"
        constraints = [
            models.UniqueConstraint(
                fields=("replication", "idempotency_key"),
                name="unique_lightsail_bucket_replication_run_key",
            )
        ]
        indexes = [
            models.Index(fields=("replication", "status")),
            models.Index(fields=("status", "started_at")),
        ]

    def __str__(self):
        return f"{self.replication_id}:{self.uuid}:{self.status}"


class CoreLightsailBucketReplicationObject(TimeStampedModel):
    """Durable state for one source key/version (including a delete marker)."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COPYING = "copying", "Copying"
        COMPLETE = "complete", "Complete"
        SKIPPED = "skipped", "Skipped"
        DELETE_MARKER_APPLIED = "delete_marker_applied", "Delete marker applied"
        FAILED = "failed", "Failed"

    run = models.ForeignKey(
        CoreLightsailBucketReplicationRun,
        related_name="object_states",
        on_delete=models.CASCADE,
    )
    key = models.CharField(max_length=2048)
    # S3 uses the literal "null" for an unversioned object's VersionId in some
    # responses.  Empty is reserved for list_objects_v2 rows with no version field.
    source_version_id = models.CharField(max_length=255, blank=True, default="")
    is_delete_marker = models.BooleanField(default=False)
    source_etag = models.CharField(max_length=512, blank=True, default="")
    source_size = models.PositiveBigIntegerField(null=True, blank=True)
    source_last_modified = models.DateTimeField(null=True, blank=True)
    source_metadata = models.JSONField(default=dict, blank=True)
    destination_key = models.CharField(max_length=2048)
    destination_version_id = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    bytes_transferred = models.PositiveBigIntegerField(default=0)
    attempt_count = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_replication_object"
        constraints = [
            models.UniqueConstraint(
                fields=("run", "key", "source_version_id", "is_delete_marker"),
                name="unique_lightsail_bucket_replication_object_version",
            )
        ]
        indexes = [
            models.Index(fields=("run", "status")),
            models.Index(fields=("key", "source_version_id")),
        ]

    @property
    def version_id(self):
        """Compatibility spelling used by S3 APIs and manifest consumers."""

        return self.source_version_id

    @property
    def identity(self):
        return (
            self.key,
            self.source_version_id,
            bool(self.is_delete_marker),
        )


class CoreLightsailBucketReplicationLease(TimeStampedModel):
    """Short-lived ownership of a replication object transfer."""

    object_state = models.OneToOneField(
        CoreLightsailBucketReplicationObject,
        related_name="lease",
        on_delete=models.CASCADE,
    )
    owner = models.CharField(max_length=255, blank=True, default="")
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    acquired_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    attempt_count = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_replication_lease"
        indexes = [
            models.Index(fields=("expires_at",)),
            models.Index(fields=("owner", "expires_at")),
        ]


class CoreLightsailBucketReplicationMultipart(TimeStampedModel):
    """Durable multipart upload pointer and completed-part ledger."""

    object_state = models.OneToOneField(
        CoreLightsailBucketReplicationObject,
        related_name="multipart",
        on_delete=models.CASCADE,
    )
    upload_id = models.CharField(max_length=1024, blank=True, default="")
    part_size_bytes = models.PositiveBigIntegerField(default=64 * 1024 * 1024)
    source_size = models.PositiveBigIntegerField(null=True, blank=True)
    # JSON list of {"PartNumber": int, "ETag": str, ...}.  It is written after
    # every successful upload_part call so a worker crash resumes at the next part.
    completed_parts = models.JSONField(default=list, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_replication_multipart"
        indexes = [
            models.Index(fields=("upload_id",)),
        ]


class CoreLightsailBucketRestoreRun(TimeStampedModel):
    """Idempotent restore of a destination prefix back into the Lightsail bucket."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETE = "complete", "Complete"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    replication = models.ForeignKey(
        CoreLightsailBucketReplication,
        related_name="restore_runs",
        on_delete=models.CASCADE,
    )
    source_run = models.ForeignKey(
        CoreLightsailBucketReplicationRun,
        related_name="restore_runs",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    idempotency_key = models.CharField(max_length=255)
    celery_task_id = models.CharField(max_length=255, blank=True, default="")
    # Prefix relative to the configured destination prefix.  target_prefix is the
    # prefix relative to the Lightsail source bucket to which objects are restored.
    restore_prefix = models.CharField(max_length=1024, blank=True, default="")
    target_prefix = models.CharField(max_length=1024, blank=True, default="")
    destination_prefix = models.CharField(max_length=1024, blank=True, default="")
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    object_count = models.PositiveBigIntegerField(default=0)
    completed_count = models.PositiveBigIntegerField(default=0)
    skipped_count = models.PositiveBigIntegerField(default=0)
    failed_count = models.PositiveBigIntegerField(default=0)
    bytes_restored = models.PositiveBigIntegerField(default=0)
    # Legacy compatibility only. New restore progress is stored one row per object
    # in CoreLightsailBucketRestoreObject so inventory size is never bounded by one
    # JSON value and workers can resume with queryset streaming.
    completed_objects = models.JSONField(default=list, blank=True)
    manifest = models.JSONField(default=dict, blank=True)
    lease_owner = models.CharField(max_length=255, blank=True, default="")
    lease_token = models.UUIDField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_restore_run"
        constraints = [
            models.UniqueConstraint(
                fields=("replication", "idempotency_key"),
                name="unique_lightsail_bucket_restore_run_key",
            )
        ]
        indexes = [
            models.Index(fields=("replication", "status")),
            models.Index(fields=("lease_expires_at",)),
        ]


class CoreLightsailBucketRestoreObject(TimeStampedModel):
    """Durable, immutable restore work item for one exact backup object version."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RESTORING = "restoring", "Restoring"
        COMPLETE = "complete", "Complete"
        SKIPPED = "skipped", "Skipped"
        FAILED = "failed", "Failed"

    restore_run = models.ForeignKey(
        CoreLightsailBucketRestoreRun,
        related_name="object_states",
        on_delete=models.CASCADE,
    )
    # Keep a nullable link for auditability, while duplicating the immutable source
    # fingerprint below so a historical replication run can later be pruned without
    # making an in-progress restore unsafe or ambiguous.
    source_object = models.ForeignKey(
        CoreLightsailBucketReplicationObject,
        related_name="restore_objects",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    backup_key_hash = models.CharField(max_length=64)
    backup_key_encrypted = models.TextField()
    backup_version_id = models.CharField(max_length=255, blank=True, default="")
    is_delete_marker = models.BooleanField(default=False)
    backup_etag = models.CharField(max_length=512, blank=True, default="")
    backup_size = models.PositiveBigIntegerField(null=True, blank=True)
    backup_last_modified = models.DateTimeField(null=True, blank=True)
    source_key_hash = models.CharField(max_length=64)
    source_key_encrypted = models.TextField()
    source_version_id = models.CharField(max_length=255, blank=True, default="")
    source_etag = models.CharField(max_length=512, blank=True, default="")
    target_key_hash = models.CharField(max_length=64)
    target_key_encrypted = models.TextField()
    restored_version_id = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    bytes_restored = models.PositiveBigIntegerField(default=0)
    attempt_count = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "core_lightsail_bucket_restore_object"
        constraints = [
            models.UniqueConstraint(
                fields=("restore_run", "backup_key_hash"),
                name="unique_lightsail_bucket_restore_object_key",
            ),
            models.UniqueConstraint(
                fields=("restore_run", "target_key_hash"),
                name="unique_lightsail_bucket_restore_target_key",
            ),
        ]
        indexes = [
            models.Index(
                fields=("restore_run", "status"),
                name="lightsail_restore_status_idx",
            ),
            models.Index(
                fields=("backup_key_hash", "backup_version_id"),
                name="lightsail_restore_source_idx",
            ),
        ]


# Short names make the isolated module pleasant to import while the explicit Core*
# names match the rest of this repository's Django model conventions.
LightsailBucketReplication = CoreLightsailBucketReplication
LightsailBucketReplicationRun = CoreLightsailBucketReplicationRun
LightsailBucketReplicationObject = CoreLightsailBucketReplicationObject
LightsailBucketReplicationLease = CoreLightsailBucketReplicationLease
LightsailBucketReplicationMultipart = CoreLightsailBucketReplicationMultipart
LightsailBucketRestoreRun = CoreLightsailBucketRestoreRun
LightsailBucketRestoreObject = CoreLightsailBucketRestoreObject


__all__ = [
    "CoreLightsailBucketReplication",
    "CoreLightsailBucketReplicationRun",
    "CoreLightsailBucketReplicationObject",
    "CoreLightsailBucketReplicationLease",
    "CoreLightsailBucketReplicationMultipart",
    "CoreLightsailBucketRestoreRun",
    "CoreLightsailBucketRestoreObject",
    "LightsailBucketReplication",
    "LightsailBucketReplicationRun",
    "LightsailBucketReplicationObject",
    "LightsailBucketReplicationLease",
    "LightsailBucketReplicationMultipart",
    "LightsailBucketRestoreRun",
    "LightsailBucketRestoreObject",
]
