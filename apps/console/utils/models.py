import hashlib
import uuid
from datetime import timedelta

import humanfriendly
from django.contrib.contenttypes.fields import GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from model_utils.models import TimeStampedModel

from apps.console.account.models import CoreAccount
from apps.console.utils.execution_history import (
    begin_public_attempt,
    update_public_attempt,
)
from django.utils.dateparse import parse_datetime


class UtilDeleteFiles(models.Model):
    path = models.TextField()
    server = models.CharField(max_length=32, null=True)
    created = models.BigIntegerField()

    class Meta:
        db_table = "util_delete_files"


class UtilCountry(models.Model):
    code = models.CharField(max_length=2, null=True)
    name = models.CharField(max_length=45, null=True)
    iso_alpha3 = models.CharField(max_length=3, null=True)
    priority = models.IntegerField(default=0)

    class Meta:
        db_table = "util_country"


class UtilSetting(models.Model):
    running_storage_billing = models.BooleanField(null=True)
    running_storage_calculation = models.BooleanField(null=True)
    total_backups = models.BigIntegerField(null=True)

    class Meta:
        db_table = "util_setting"


class UtilBase(models.Model):
    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=255, null=True)

    class Meta:
        abstract = True


class UtilAttribute(models.Model):
    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=255, null=True)
    code = models.CharField(max_length=64, unique=True)

    class Meta:
        abstract = True


class UtilTag(models.Model):
    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=255)
    account = models.ForeignKey(CoreAccount, related_name="tags", on_delete=models.CASCADE)

    class Meta:
        db_table = "util_tag"


class UtilPostgreSQLOptions(models.Model):
    class Type(models.IntegerChoices):
        FLAG = 1, "Flag"
        VALUE = 2, "Value",
        PATTERN = 3, "Pattern"

    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=64)
    type = models.IntegerField(choices=Type.choices, null=True)

    class Meta:
        db_table = "util_postgresql_options"


class UtilMySQLOptions(models.Model):
    class Type(models.IntegerChoices):
        FLAG = 1, "Flag"
        VALUE = 2, "Value"

    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=64)
    type = models.IntegerField(choices=Type.choices, null=True)

    class Meta:
        db_table = "util_mysql_options"


class UtilMariaDBOptions(models.Model):
    class Type(models.IntegerChoices):
        FLAG = 1, "Flag"
        VALUE = 2, "Value"

    def __str__(self):
        return f"{self.name} "

    name = models.CharField(max_length=64)
    type = models.IntegerField(choices=Type.choices, null=True)

    class Meta:
        db_table = "util_mariadb_options"


class BackupExecutionLeaseLostError(RuntimeError):
    """A stale backup worker attempted to persist after losing its fence."""


class UtilBackup(TimeStampedModel):
    class Status(models.IntegerChoices):
        PENDING = 1, "Pending"
        IN_PROGRESS = 2, "In-Progress"
        COMPLETE = 3, "Complete"
        FAILED = 4, "Failed"
        RETRYING = 5, "Retrying"
        STARTED = 6, "Started"
        MAX_RETRY_FAILED = 7, "Max Retries Failed"
        UPLOAD_READY = 8, "Ready For Upload"
        UPLOAD_IN_PROGRESS = 9, "Upload In Progress"
        UPLOAD_COMPLETE = 10, "Upload Complete"
        UPLOAD_VALIDATION = 22, "Upload Validation"
        PARTIAL = 23, "Partial (Some Destinations Failed)"
        UPLOAD_FAILED = 11, "Upload Failed"
        DELETE_REQUESTED = 12, "Delete REQUESTED"
        DELETE_IN_PROGRESS = 13, "Delete In-Progress"
        DELETE_COMPLETED = 14, "Delete Completed"
        DELETE_FAILED = 15, "Delete Failed"
        DELETE_FAILED_NOT_FOUND = 20, "Delete Failed (Not Found)"
        DELETE_MAX_RETRY_FAILED = 16, "Delete Max Retries Failed"
        DOWNLOAD_IN_PROGRESS = 17, "Download In-Progress"
        DOWNLOAD_COMPLETE = 18, "Download Complete"
        CANCELLED = 19, "Cancelled"
        TIMEOUT = 21, "Timeout"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"

    SUCCESS_STATUSES = (Status.COMPLETE, Status.PARTIAL)

    class Type(models.IntegerChoices):
        ON_DEMAND = 1, "On-Demand"
        SCHEDULED = 2, "Scheduled"

    # Statuses in which a backup may still have work in flight -- a snapshot at the
    # provider (cloud/volume) or a local dump/upload (website/database/saas).
    # CoreNode.backup_initiate uses this to refuse a second backup for the same node
    # while one is already running; every other status (COMPLETE, FAILED, TIMEOUT,
    # CANCELLED, UPLOAD_FAILED, DELETE_*, ...) is terminal and allows a new backup.
    ACTIVE_STATUSES = (
        Status.PENDING,
        Status.IN_PROGRESS,
        Status.STARTED,
        Status.RETRYING,
        Status.DOWNLOAD_IN_PROGRESS,
        Status.DOWNLOAD_COMPLETE,
        Status.UPLOAD_READY,
        Status.UPLOAD_IN_PROGRESS,
        Status.UPLOAD_VALIDATION,
        Status.UPLOAD_COMPLETE,
    )

    EXECUTION_ERROR_MESSAGES = {
        "PROVIDER_CREATE_OUTCOME_UNKNOWN": (
            "The provider request outcome is unknown; reconciliation is required."
        ),
        "PROVIDER_RECONCILIATION_REQUIRED": (
            "The provider operation requires reconciliation before it can continue."
        ),
        "PROVIDER_NOT_FOUND": "The provider resource was not found.",
        "PROVIDER_AUTH_FAILED": (
            "The provider rejected the configured credentials or permissions."
        ),
        "PROVIDER_RATE_LIMIT": (
            "The provider rate limit was reached; processing will resume later."
        ),
        "PROVIDER_TRANSIENT_OUTAGE": (
            "The provider is temporarily unavailable; processing will resume later."
        ),
        "PROVIDER_TIMEOUT": (
            "The provider request timed out; processing will resume later."
        ),
        "PROVIDER_REQUEST_FAILED": "The provider rejected the request.",
        "PROVIDER_CLIENT_ERROR": "The provider client could not complete the request.",
        "PROVIDER_FAILED": "The provider reported a terminal failure.",
        "PROVIDER_OWNERSHIP_MISMATCH": "Provider ownership verification failed.",
        "PROVIDER_MALFORMED_RESPONSE": (
            "The provider returned an invalid or unsupported response."
        ),
        "SOURCE_ARTIFACT_INVALID": (
            "The local backup artifact failed integrity validation."
        ),
        "BACKUP_TIMEOUT": (
            "The source did not finish the backup operation before its timeout."
        ),
        "WEBSITE_MIRROR_FAILED": (
            "The website source could not be mirrored completely. Check source "
            "access and file permissions, then retry."
        ),
        "WEBSITE_MANIFEST_FAILED": (
            "BackupSheep could not build a stable manifest of the mirrored website. "
            "Retry after checking worker capacity and source stability."
        ),
        "ARCHIVE_CREATION_FAILED": (
            "BackupSheep could not create the website archive from its verified "
            "mirror. Retry after checking worker capacity."
        ),
        "ARCHIVE_VALIDATION_FAILED": (
            "The generated backup archive failed integrity validation."
        ),
        "SOURCE_PATH_LIMIT_EXCEEDED": (
            "A website source path exceeds the worker filesystem limit. Shorten "
            "that path or exclude it, then run a new backup."
        ),
        "SOURCE_SPECIAL_FILE_UNSUPPORTED": (
            "The website source contains a member that cannot be represented safely "
            "in a restorable backup."
        ),
        "WORKER_INODE_EXHAUSTED": (
            "The backup worker does not have enough free filesystem entries for "
            "this website backup."
        ),
        "STORAGE_UPLOAD_FAILED": "The storage upload could not be completed.",
        "STORAGE_AUTH_FAILED": (
            "The storage destination rejected the configured credentials or permissions."
        ),
        "STORAGE_DESTINATION_NOT_FOUND": (
            "The configured storage destination was not found."
        ),
        "STORAGE_QUOTA_EXCEEDED": (
            "The destination does not have enough available storage capacity."
        ),
        "STORAGE_RATE_LIMITED": (
            "The storage provider rate limit was reached; processing will resume later."
        ),
        "STORAGE_TIMEOUT": (
            "The storage operation timed out; processing will resume later."
        ),
        "STORAGE_TRANSIENT_FAILURE": (
            "The storage provider is temporarily unavailable; processing will resume later."
        ),
        "STORAGE_STALLED": (
            "The storage upload made no provider-visible progress and will resume "
            "automatically from its durable checkpoint."
        ),
        "STORAGE_RETRIES_EXHAUSTED": (
            "Automatic storage retries were exhausted. Review the failed destination "
            "before starting another upload."
        ),
        "STORAGE_INTEGRITY_FAILED": (
            "The uploaded object failed integrity verification."
        ),
        "SOURCE_ARTIFACT_MISSING": (
            "The committed local backup artifact is no longer available."
        ),
        "STORAGE_RECONCILIATION_REQUIRED": (
            "The storage operation requires reconciliation before it can continue."
        ),
        "NO_VALID_STORAGE_DESTINATION": (
            "No requested storage destination passed validation."
        ),
        "AIR_GAPPED_DESTINATION_REQUIRED": (
            "The required air-gapped storage destination was not available."
        ),
        "WORKER_LEASE_LOST": (
            "This worker lost ownership of the backup execution lease."
        ),
    }

    # Provider reconciliation is a durable coordination outcome, not an ordinary
    # terminal error. Keep the public reason a bounded, known token so the API/UI
    # can explain recovery without exposing provider response text.
    RECONCILIATION_ERROR_REASONS = {
        "PROVIDER_RECONCILIATION_REQUIRED": "provider_reconciliation_required",
    }

    def __str__(self):
        return f"{self.name} "

    uuid = models.CharField(max_length=1024, null=True, editable=False)
    celery_task_id = models.CharField(max_length=255, null=True, editable=False)
    name = models.CharField(max_length=255, null=True)
    status = models.IntegerField(choices=Status.choices, default=Status.COMPLETE)
    type = models.IntegerField(choices=Type.choices, null=True)
    attempt_no = models.PositiveIntegerField(null=True)
    old_schedule_name = models.CharField(max_length=255, null=True)
    old_schedule_timezone = models.CharField(max_length=255, null=True)
    old_delete_requested = models.BooleanField(null=True)
    old_delete_in_progress = models.BooleanField(default=False)
    old_max_delete_retry = models.BooleanField(default=False)
    completed_on_attempt_no = models.IntegerField(null=True)
    notes = models.TextField(null=True)

    # Durable execution data is kept in one provider-independent ledger rather than
    # duplicating lease/error/progress columns across every concrete Core*Backup table.
    # GenericRelation is a virtual field (no column is added to legacy backup tables)
    # and gives ORM-level cascade cleanup when a backup row is deleted.
    execution_records = GenericRelation(
        "CoreBackupExecution",
        content_type_field="backup_content_type",
        object_id_field="backup_object_id",
    )
    artifact_records = GenericRelation(
        "CoreBackupArtifact",
        content_type_field="backup_content_type",
        object_id_field="backup_object_id",
    )

    class Meta:
        abstract = True

    def set_provider_metadata(self, provider_metadata):
        """Replace provider metadata without dropping poll recovery control.

        ``_backup_control`` is a BackupSheep-owned envelope used by the cloud
        poller for the current task id, lease token, and successor ETA. Provider
        responses are not allowed to replace that envelope, even when an adapter
        intentionally replaces the rest of the metadata with its latest
        response. The caller still owns the surrounding transaction/lease and
        must persist the returned value through the normal fenced ``save`` path.
        """
        if not isinstance(provider_metadata, dict):
            raise TypeError("provider_metadata must be a dictionary")
        updated = dict(provider_metadata)
        current = getattr(self, "metadata", None)
        control = current.get("_backup_control") if isinstance(current, dict) else None
        if isinstance(control, dict):
            # Provider payloads cannot smuggle or overwrite the control envelope.
            updated["_backup_control"] = dict(control)
        self.metadata = updated
        return updated

    def bind_execution_fence(self, owner, token):
        """Require subsequent instance saves to own this exact live lease."""
        self._required_backup_lease_owner = str(owner or "")
        self._required_backup_lease_token = str(token or "")
        return self

    def unbind_execution_fence(self):
        """Remove the process-local save guard after the lease is released."""
        self._required_backup_lease_owner = ""
        self._required_backup_lease_token = ""
        return self

    def ensure_execution_fence(self):
        """Fail before a local/provider side effect when this worker is stale."""
        required_owner = getattr(self, "_required_backup_lease_owner", "")
        required_token = getattr(self, "_required_backup_lease_token", "")
        if not required_owner or not required_token:
            # Direct engine calls in maintenance/tests remain backwards compatible;
            # normal Celery execution binds a fence before invoking an engine.
            return None
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup, create=False)
            if (
                state is None
                or state.lease_owner != required_owner
                or str(state.lease_token or "") != required_token
                or not state.lease_expires_at
                or state.lease_expires_at <= timezone.now()
            ):
                raise BackupExecutionLeaseLostError(
                    "Backup execution lease ownership was lost."
                )
            return state

    def save(self, *args, **kwargs):
        required_owner = getattr(self, "_required_backup_lease_owner", "")
        required_token = getattr(self, "_required_backup_lease_token", "")
        if self.pk and required_owner and required_token:
            with transaction.atomic():
                backup = self.__class__.objects.select_for_update().get(pk=self.pk)
                state = self._locked_execution_state(backup, create=False)
                if (
                    state is None
                    or state.lease_owner != required_owner
                    or str(state.lease_token or "") != required_token
                    or not state.lease_expires_at
                    or state.lease_expires_at <= timezone.now()
                ):
                    raise BackupExecutionLeaseLostError(
                        "Backup execution lease ownership was lost."
                    )
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)

    @staticmethod
    def _execution_models():
        # Imported lazily because backup.models imports UtilBackup while Django builds
        # the application model registry.
        from apps.console.backup.models import CoreBackupArtifact, CoreBackupExecution

        return CoreBackupExecution, CoreBackupArtifact

    @classmethod
    def _locked_execution_state(cls, backup, create=True):
        """Return the execution row while the caller holds ``backup``'s row lock."""
        execution_model, _ = cls._execution_models()
        content_type = ContentType.objects.get_for_model(
            backup, for_concrete_model=False
        )
        lookup = {
            "backup_content_type": content_type,
            "backup_object_id": backup.pk,
        }
        state = execution_model.objects.select_for_update().filter(**lookup).first()
        if state is None and create:
            # The locked concrete backup row serializes normal callers. Keep the
            # IntegrityError fallback for data repair/admin code that may create the
            # execution row without using these helpers.
            try:
                with transaction.atomic():
                    state = execution_model.objects.create(**lookup)
            except IntegrityError:
                state = execution_model.objects.select_for_update().get(**lookup)
        return state

    def get_execution_state(self, create=False):
        """Return this backup's durable execution state, creating it on demand."""
        if self.pk is None:
            raise ValueError("A backup must be saved before execution state is used.")
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            return self._locked_execution_state(backup, create=create)

    def initialize_execution(
        self,
        *,
        celery_task_id=None,
        attempt_no=None,
        task_name="",
        worker_name="",
        now=None,
    ):
        """Persist delivery/attempt metadata without claiming a worker lease.

        Existing backup rows have no ledger row after migration; the first delivery or
        recovery creates one with safe defaults. ``delivery_count`` records broker
        redelivery independently from the Celery retry attempt number.
        """
        if self.pk is None:
            raise ValueError("A backup must be saved before execution is initialized.")
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            state.delivery_count += 1
            if celery_task_id:
                state.celery_task_id = str(celery_task_id)[:255]
            if task_name:
                state.task_name = str(task_name)[:255]
            if worker_name:
                state.worker_name = str(worker_name)[:255]
            if attempt_no is not None:
                try:
                    state.attempt_count = max(
                        state.attempt_count, max(int(attempt_no), 0)
                    )
                except (TypeError, ValueError):
                    pass
            if state.started_at is None:
                state.started_at = now
            if state.attempt_count:
                state.metadata = begin_public_attempt(
                    state.metadata,
                    attempt_no=state.attempt_count,
                    correlation_id=state.correlation_id,
                    stage=state.phase or "preparing",
                    now=now,
                )
            state.save(
                update_fields=[
                    "delivery_count",
                    "celery_task_id",
                    "task_name",
                    "worker_name",
                    "attempt_count",
                    "started_at",
                    "metadata",
                    "modified",
                ]
            )
            return state

    def claim_execution(
        self,
        *,
        lease_owner,
        phase,
        lease_seconds,
        now=None,
        increment_attempt=False,
        respect_retry_at=True,
    ):
        """Atomically claim this active backup and return its fenced execution row.

        A live lease blocks *all* deliveries, including a duplicate carrying the same
        Celery task id. Once the lease expires, a new random token fences the old worker
        from heartbeating, updating progress, or releasing the replacement's lease.
        """
        if self.pk is None:
            raise ValueError("A backup must be saved before it can be claimed.")
        owner = str(lease_owner or "").strip()
        phase = str(phase or "").strip()
        if not owner:
            raise ValueError("lease_owner is required.")
        if not phase:
            raise ValueError("phase is required.")
        try:
            lease_seconds = int(lease_seconds)
        except (TypeError, ValueError) as error:
            raise ValueError("lease_seconds must be a positive integer.") from error
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive integer.")

        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            if backup.status not in self.ACTIVE_STATUSES:
                return None
            state = self._locked_execution_state(backup)
            if respect_retry_at and state.next_retry_at and state.next_retry_at > now:
                return None
            if (
                state.lease_token
                and state.lease_expires_at
                and state.lease_expires_at > now
            ):
                return None

            stale_lease = bool(
                state.lease_owner
                or state.lease_token
                or state.lease_expires_at
            )
            if stale_lease:
                if state.attempt_count:
                    state.metadata = update_public_attempt(
                        state.metadata,
                        attempt_no=state.attempt_count,
                        correlation_id=state.correlation_id,
                        stage=state.phase or "preparing",
                        retry_decision="lease_lost",
                        now=now,
                        finished=True,
                    )
                metadata = dict(state.reconciliation_metadata or {})
                history = list(metadata.get("stale_lease_takeovers") or [])
                history.append(
                    {
                        "detected_at": now.isoformat(),
                        "previous_owner": state.lease_owner,
                        "previous_phase": state.phase,
                        "previous_token": str(state.lease_token or ""),
                        "previous_expires_at": (
                            state.lease_expires_at.isoformat()
                            if state.lease_expires_at
                            else None
                        ),
                    }
                )
                metadata["stale_lease_takeovers"] = history[-20:]
                state.reconciliation_metadata = metadata
                if (
                    state.reconciliation_state
                    != state.ReconciliationState.MANUAL_REVIEW
                ):
                    state.reconciliation_state = state.ReconciliationState.REQUIRED
                state.reconciliation_reason = "stale_execution_lease"

            state.lease_owner = owner[:255]
            state.phase = phase[:64]
            state.lease_token = uuid.uuid4()
            state.lease_expires_at = now + timedelta(seconds=lease_seconds)
            state.heartbeat_at = now
            state.claim_count += 1
            if increment_attempt:
                state.attempt_count += 1
            if state.attempt_count:
                state.metadata = begin_public_attempt(
                    state.metadata,
                    attempt_no=state.attempt_count,
                    correlation_id=state.correlation_id,
                    stage=phase,
                    now=now,
                )
            if state.started_at is None:
                state.started_at = now
            state.finished_at = None
            state.save()
            return state

    def heartbeat_execution(
        self,
        *,
        lease_owner,
        lease_token,
        lease_seconds,
        progress_completed=None,
        progress_total=None,
        progress_unit=None,
        worker_name=None,
        metadata_updates=None,
        now=None,
    ):
        """Renew a live lease and optionally persist monotonic progress.

        The token check is a fencing guarantee: a worker that resumes after its lease
        was taken over cannot overwrite the replacement worker's state.
        """
        try:
            lease_seconds = int(lease_seconds)
        except (TypeError, ValueError) as error:
            raise ValueError("lease_seconds must be a positive integer.") from error
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive integer.")
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup, create=False)
            if state is None or not state.lease_matches(
                lease_owner, lease_token, now=now
            ):
                return None

            if progress_completed is not None:
                completed = int(progress_completed)
                if completed < state.progress_completed:
                    raise ValueError("progress_completed cannot move backwards.")
                state.progress_completed = completed
            if progress_total is not None:
                total = int(progress_total)
                if total < 0:
                    raise ValueError("progress_total cannot be negative.")
                if total < state.progress_completed:
                    raise ValueError(
                        "progress_total cannot be less than progress_completed."
                    )
                state.progress_total = total
            if progress_unit is not None:
                state.progress_unit = str(progress_unit)[:32]
            if worker_name is not None:
                state.worker_name = str(worker_name)[:255]
            metadata_changed = False
            if metadata_updates is not None:
                if not isinstance(metadata_updates, dict):
                    raise TypeError("metadata_updates must be a dictionary.")
                metadata = dict(state.metadata or {})
                for key, value in metadata_updates.items():
                    key = str(key)[:64]
                    if not key:
                        continue
                    if value is None:
                        metadata.pop(key, None)
                    else:
                        metadata[key] = value
                state.metadata = metadata
                metadata_changed = True
                public_stage = metadata_updates.get("public_stage")
                if public_stage and state.attempt_count:
                    state.metadata = update_public_attempt(
                        state.metadata,
                        attempt_no=state.attempt_count,
                        correlation_id=state.correlation_id,
                        stage=public_stage,
                        now=now,
                    )
            state.heartbeat_at = now
            state.lease_expires_at = now + timedelta(seconds=lease_seconds)
            update_fields = [
                "progress_completed",
                "progress_total",
                "progress_unit",
                "worker_name",
                "heartbeat_at",
                "lease_expires_at",
                "modified",
            ]
            if metadata_changed:
                update_fields.append("metadata")
            state.save(update_fields=update_fields)
            return state

    def release_execution(
        self,
        *,
        lease_owner,
        lease_token,
        phase=None,
        finished=False,
        now=None,
    ):
        """Release a lease only when owner, token, and optional phase still match."""
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup, create=False)
            if state is None or not state.lease_matches(
                lease_owner, lease_token, phase=phase, now=now, require_live=False
            ):
                return None
            state.lease_owner = ""
            state.lease_token = None
            state.lease_expires_at = None
            if finished:
                state.finished_at = now
                state.next_retry_at = None
            state.save(
                update_fields=[
                    "lease_owner",
                    "lease_token",
                    "lease_expires_at",
                    "finished_at",
                    "next_retry_at",
                    "modified",
                ]
            )
            return state

    def finalize_execution(self, *, terminal_phase, now=None):
        """Atomically close the durable execution ledger for a terminal backup.

        Local website, database, and SaaS backups have a concrete backup status and
        a shared execution ledger.  The status decision and this ledger transition
        must commit together; otherwise a successful upload can be rendered as an
        in-progress execution after a worker restart.  Clearing the lease also fences
        a stale source worker before it can persist another phase or progress update.

        A duplicate finalizer is intentionally a no-op once ``finished_at`` is set:
        it preserves the original terminal timestamp and phase while still clearing
        any leftover lease fields from legacy rows.
        """
        if self.pk is None:
            raise ValueError("A backup must be saved before execution is finalized.")
        terminal_phase = str(terminal_phase or "").strip().lower()
        if terminal_phase not in {"complete", "failed", "cancelled"}:
            raise ValueError("terminal_phase must be complete, failed, or cancelled.")
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            update_fields = []

            if state.finished_at is None:
                state.phase = terminal_phase
                state.finished_at = now
                update_fields.extend(["phase", "finished_at"])
            elif state.phase not in {"complete", "failed", "cancelled"}:
                # Older workers could mark a phase finished while it still said
                # ``poll``/``upload``.  A terminal backup redelivery must repair
                # that impossible state without changing the original completion
                # timestamp.  Already-terminal duplicate finalizers remain a no-op.
                state.phase = terminal_phase
                update_fields.append("phase")

            # A terminal decision is the fence boundary.  A worker that was paused
            # or resumed after this commit must not be able to heartbeat, release, or
            # save using the old execution token.
            if state.lease_owner:
                state.lease_owner = ""
                update_fields.append("lease_owner")
            if state.lease_token is not None:
                state.lease_token = None
                update_fields.append("lease_token")
            if state.lease_expires_at is not None:
                state.lease_expires_at = None
                update_fields.append("lease_expires_at")
            if state.next_retry_at is not None:
                state.next_retry_at = None
                update_fields.append("next_retry_at")

            # A successful terminal outcome supersedes the current error rollup.
            # Keep ``last_error_at`` and the bounded public attempt history as the
            # audit trail, but do not make a recovered backup look actively failed
            # after the same logical execution completes.
            if (
                terminal_phase == "complete"
                and backup.status == backup.Status.COMPLETE
            ):
                if state.last_error_code:
                    state.last_error_code = ""
                    update_fields.append("last_error_code")
                if state.last_error_message:
                    state.last_error_message = ""
                    update_fields.append("last_error_message")

            # Required/in-progress reconciliation is no longer actionable once all
            # local storage points have reached a terminal outcome. Preserve an
            # explicit provider reconciliation failure: a terminal backup row can
            # still need operator/provider investigation, and resolving it here
            # would erase the durable evidence before the API/UI reads it. Manual
            # review is preserved separately as an explicit operator decision.
            if state.reconciliation_state in {
                state.ReconciliationState.REQUIRED,
                state.ReconciliationState.IN_PROGRESS,
            } and not (
                terminal_phase == "failed"
                and state.last_error_code == "PROVIDER_RECONCILIATION_REQUIRED"
            ):
                state.reconciliation_state = state.ReconciliationState.RESOLVED
                state.reconciliation_reason = "backup_finalized"
                update_fields.extend(["reconciliation_state", "reconciliation_reason"])

            if update_fields:
                if state.attempt_count:
                    state.metadata = update_public_attempt(
                        state.metadata,
                        attempt_no=state.attempt_count,
                        correlation_id=state.correlation_id,
                        stage=terminal_phase,
                        retry_decision=(
                            "complete"
                            if terminal_phase == "complete"
                            else "cancelled"
                            if terminal_phase == "cancelled"
                            else "terminal_failure"
                        ),
                        now=now,
                        finished=True,
                    )
                    update_fields.append("metadata")
                state.save(update_fields=list(dict.fromkeys(update_fields + ["modified"])))
            return state

    def record_execution_error(
        self,
        *,
        code,
        message="",
        retryable=None,
        retry_at=None,
        reconciliation_reason="",
        reconciliation_metadata=None,
        stage=None,
        lease_owner=None,
        lease_token=None,
        require_live=False,
        now=None,
    ):
        """Persist a categorized, public-safe error, optionally worker-fenced.

        ``message`` is accepted for API compatibility and secured diagnostics, but is
        intentionally not written to the database. Provider/client exceptions often
        contain bearer tokens, URLs, usernames, SQL, or response bodies. Operators can
        correlate the full exception in Sentry using the execution correlation ID.
        """
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, now=now, require_live=require_live
            ):
                return None
            safe_code = str(code or "UNKNOWN")[:64]
            state.last_error_code = safe_code
            state.last_error_message = self.EXECUTION_ERROR_MESSAGES.get(
                safe_code,
                "Backup execution encountered an error. Review secured diagnostics using the correlation ID.",
            )
            state.last_error_at = now
            state.next_retry_at = retry_at
            if retryable is not None:
                execution_metadata = dict(state.metadata or {})
                execution_metadata["retryable"] = bool(retryable)
                state.metadata = execution_metadata
            if state.attempt_count:
                public_stage = (
                    stage
                    or (state.metadata or {}).get("public_stage")
                    or state.phase
                    or "preparing"
                )
                decision = (
                    "scheduled_retry"
                    if retryable is True or retry_at is not None
                    else "terminal_failure"
                    if retryable is False
                    else "retry_not_scheduled"
                )
                state.metadata = update_public_attempt(
                    state.metadata,
                    attempt_no=state.attempt_count,
                    correlation_id=state.correlation_id,
                    stage=public_stage,
                    code=safe_code,
                    retry_decision=decision,
                    now=now,
                    finished=retryable is not None or retry_at is not None,
                )
            if not reconciliation_reason:
                reconciliation_reason = self.RECONCILIATION_ERROR_REASONS.get(
                    safe_code, ""
                )
                if reconciliation_reason and reconciliation_metadata is None:
                    reconciliation_metadata = {
                        "source": "provider_outcome",
                        "error_code": safe_code,
                    }
            if reconciliation_reason:
                if (
                    state.reconciliation_state
                    != state.ReconciliationState.MANUAL_REVIEW
                ):
                    state.reconciliation_state = state.ReconciliationState.REQUIRED
                state.reconciliation_reason = str(reconciliation_reason)[:255]
                if reconciliation_metadata:
                    metadata = dict(state.reconciliation_metadata or {})
                    metadata.update(dict(reconciliation_metadata))
                    state.reconciliation_metadata = metadata
            state.save()
            return state

    def record_provider_reference(
        self,
        *,
        operation_id=None,
        resource_id=None,
        idempotency_key=None,
        provider_status=None,
        metadata=None,
        lease_owner=None,
        lease_token=None,
        require_live=False,
    ):
        """Persist provider recovery pointers before later phases are dispatched."""
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, require_live=require_live
            ):
                return None
            if operation_id is not None:
                state.provider_operation_id = str(operation_id)[:255]
            if resource_id is not None:
                state.provider_resource_id = str(resource_id)[:255]
            if idempotency_key is not None:
                state.provider_idempotency_key = str(idempotency_key)[:255]
            if provider_status is not None:
                state.provider_status = str(provider_status)[:64]
            if metadata:
                provider_metadata = dict(state.provider_metadata or {})
                provider_metadata.update(dict(metadata))
                state.provider_metadata = provider_metadata
            state.save()
            return state

    def set_reconciliation_state(
        self,
        *,
        reconciliation_state,
        reason=None,
        metadata=None,
        lease_owner=None,
        lease_token=None,
        now=None,
    ):
        """Move reconciliation through required/in-progress/resolved with fencing."""
        now = now or timezone.now()
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            valid_states = {choice for choice, _label in state.ReconciliationState.choices}
            if reconciliation_state not in valid_states:
                raise ValueError("Unknown reconciliation state.")
            if lease_token is not None and not state.lease_matches(
                lease_owner, lease_token, now=now, require_live=False
            ):
                return None
            state.reconciliation_state = reconciliation_state
            if reason is not None:
                state.reconciliation_reason = str(reason)[:255]
            reconciliation_metadata = dict(state.reconciliation_metadata or {})
            if metadata:
                reconciliation_metadata.update(dict(metadata))
            reconciliation_metadata["state_changed_at"] = now.isoformat()
            state.reconciliation_metadata = reconciliation_metadata
            if reconciliation_state == state.ReconciliationState.RESOLVED:
                state.next_retry_at = None
            state.save(
                update_fields=[
                    "reconciliation_state",
                    "reconciliation_reason",
                    "reconciliation_metadata",
                    "next_retry_at",
                    "modified",
                ]
            )
            return state

    def record_artifact_integrity(
        self,
        *,
        role,
        object_key,
        byte_count,
        storage=None,
        checksum_algorithm="",
        checksum_value="",
        etag="",
        version_id="",
        multipart_upload_id="",
        verified_at=None,
        metadata=None,
        idempotency_key=None,
    ):
        """Upsert integrity evidence for one source or destination artifact."""
        if self.pk is None:
            raise ValueError("A backup must be saved before artifacts are recorded.")
        byte_count = int(byte_count)
        if byte_count < 0:
            raise ValueError("byte_count cannot be negative.")
        _, artifact_model = self._execution_models()
        content_type = ContentType.objects.get_for_model(
            self, for_concrete_model=False
        )
        if not idempotency_key:
            material = "|".join(
                [
                    str(getattr(storage, "pk", "source") or "source"),
                    str(role or "archive"),
                    str(object_key or ""),
                ]
            )
            idempotency_key = hashlib.sha256(material.encode("utf-8")).hexdigest()
        values = {
            "storage": storage,
            "role": str(role or "archive")[:32],
            "object_key": str(object_key or ""),
            "byte_count": byte_count,
            "checksum_algorithm": str(checksum_algorithm or "")[:32],
            "checksum_value": str(checksum_value or "")[:255],
            "etag": str(etag or "")[:512],
            "version_id": str(version_id or "")[:255],
            "multipart_upload_id": str(multipart_upload_id or "")[:512],
            "verified_at": verified_at,
        }
        with transaction.atomic():
            backup = self.__class__.objects.select_for_update().get(pk=self.pk)
            state = self._locked_execution_state(backup)
            lookup = {
                "backup_content_type": content_type,
                "backup_object_id": self.pk,
                "idempotency_key": str(idempotency_key)[:255],
            }
            artifact = artifact_model.objects.select_for_update().filter(
                **lookup
            ).first()
            if artifact is None:
                artifact = artifact_model(**lookup, metadata=dict(metadata or {}))
            elif metadata is not None:
                artifact.metadata = dict(metadata)
            for field, value in values.items():
                setattr(artifact, field, value)
            artifact.save()
            if str(role) == "source" and storage is None:
                state.artifact_bytes = byte_count
                state.artifact_checksum_algorithm = str(
                    checksum_algorithm or ""
                )[:32]
                state.artifact_checksum = str(checksum_value or "")[:255]
                state.artifact_verified_at = verified_at
                state.save(
                    update_fields=[
                        "artifact_bytes",
                        "artifact_checksum_algorithm",
                        "artifact_checksum",
                        "artifact_verified_at",
                        "modified",
                    ]
                )
            return artifact

    def exists_on_storage(self, storage_id=None):
        if storage_id:
            return self.storage_points.filter(id=storage_id).exists()

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def uuid_str(self):
        if self.uuid:
            return str(self.uuid)
        elif self.name:
            return str(self.name)

    def size_display(self):
        try:
            if hasattr(self, "size"):
                return humanfriendly.format_size(self.size or 0)
            elif hasattr(self, "size_gigabytes"):
                return f"{self.size_gigabytes} GB" or 0
            else:
                return 0
        except Exception as e:
            return 0

    @property
    def show_transfer_log(self):
        if self.status != self.Status.IN_PROGRESS:
            date = parse_datetime("2022-06-24 12:59:50.407 -0400")
            return date < self.created

    @property
    def show_db_log_file(self):
        if self.status != self.Status.IN_PROGRESS:
            date = parse_datetime("2022-12-16 12:59:50.407 -0400")
            return date < self.created

    @property
    def show_dir_tree(self):
        if self.status != self.Status.IN_PROGRESS:
            date = parse_datetime("2022-10-04 21:59:50.407 -0400")
            return date < self.created

    def retry(self):
        from celery import current_app
        import json
        from apps.console.storage.models import CoreStorage

        if self.schedule:
            current_app.send_task(
                self.schedule.node.backup_task_name(),
                task_id=self.celery_task_id,
                kwargs={
                    "node_id": self.schedule.node.id,
                    "schedule_id": self.schedule.id,
                    "storage_ids": self.schedule.storage_ids,
                },
            )


class UtilCloud(TimeStampedModel):
    class Meta:
        abstract = True

    def snapshot_count(self):
        return self.backups.filter(status=UtilBackup.Status.COMPLETE).count()

    def snapshot_storage(self):
        from django.db.models import Sum

        size_gigabytes = self.backups.filter(status=UtilBackup.Status.COMPLETE, size_gigabytes__isnull=False).aggregate(
            Sum("size_gigabytes")
        )["size_gigabytes__sum"]

        return size_gigabytes or 0
