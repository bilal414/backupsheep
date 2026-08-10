from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.db.models import Q
from sentry_sdk import capture_exception

from apps.console.account.models import CoreAccount
from apps._tasks.exceptions import (
    NodeNotReadyForBackupError,
    ConnectionNotReadyForBackupError,
    ConnectionValidationFailedError,
    NodeBackupFailedError,
)
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from celery.exceptions import SoftTimeLimitExceeded


@current_app.task(
    name="backup_aws_rds",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    # retry_backoff=True,
    # retry_backoff_max=900,
    # retry_jitter=False,
    soft_time_limit=(24 * 3600),
)
def backup_aws_rds(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
    resume=False,
):
    attempt_no = self.request.retries + 1
    # treat this as scheduled backup

    schedule_check = None

    # treat this as scheduled backup
    if schedule_id:
        backup_type = UtilBackup.Type.SCHEDULED
        if resume or CoreSchedule.objects.filter(id=schedule_id, status=CoreSchedule.Status.ACTIVE).exists():
            schedule_check = True
    # treat this as on-demand backup
    else:
        backup_type = UtilBackup.Type.ON_DEMAND
        schedule_check = True

    query = Q(id=node_id)
    query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
    query &= ~Q(status=CoreNode.Status.PAUSED)
    query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
    query &= ~Q(connection__status=CoreConnection.Status.PAUSED)
    query &= ~Q(connection__account__status=CoreAccount.Status.DELETE_REQUESTED)

    if CoreNode.objects.filter(query).exists() and schedule_check:
        node = CoreNode.objects.get(id=node_id)

        try:

            """
            Best-effort pre-checks (these may refresh auth tokens). A transient
            validation failure must NOT fail the backup -- the snapshot call itself is
            the real test, so we proceed regardless.
            """
            try:
                node.connection.validate()
                node.validate()
            except Exception:
                pass

            """
            Initialize the backup
            """
            backup = node.backup_initiate(
                self.request.id,
                backup_type,
                attempt_no,
                schedule_id,
                storage_ids,
                notes,
            )

            # None means another backup for this node is already in flight under a
            # different task -- exit gracefully so no duplicate snapshot is created.
            if backup is None:
                return

            """
            Connect with website and generate snapshot 
            """
            if not backup.unique_id:
                try:
                    created_or_adopted = backup.create_snapshot(
                        task_id=self.request.id
                    )
                except Exception:
                    # The backup-row implementation persists an immutable RDS
                    # request witness and marks ambiguous provider outcomes for
                    # reconciliation before it re-raises.  Poll that durable
                    # identity instead of consuming finite Celery retries and
                    # eventually turning a possibly-created snapshot into a
                    # false terminal failure.
                    execution = backup.get_execution_state(create=False)
                    if (
                        execution is not None
                        and execution.reconciliation_state == "required"
                    ):
                        from apps._tasks.helper.tasks import poll_cloud_backup

                        poll_cloud_backup.apply_async(
                            args=[node.id, backup.id], countdown=60
                        )
                        return
                    raise
                if not created_or_adopted:
                    return
                backup.refresh_from_db()
                if backup.status not in UtilBackup.ACTIVE_STATUSES:
                    return

            """
            Hand off to async polling instead of blocking the worker. poll_cloud_backup
            waits for the snapshot to finish, finalizes it (retention + success notify),
            and tolerates flaky status calls without failing the backup.
            """
            from apps._tasks.helper.tasks import poll_cloud_backup
            poll_cloud_backup.apply_async(args=[node.id, backup.id], countdown=60)
        except ConnectionValidationFailedError as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_retrying_reset(self.request.id)
            raise self.retry()
        except SoftTimeLimitExceeded as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_timeout_reset(self.request.id)
        except Exception as error:
            try:
                """
                Reset node for retry
                """
                node.notify_backup_fail(error, backup_type)
                node.backup_retrying_reset(self.request.id)
                raise self.retry()
            except MaxRetriesExceededError:
                """
                Reset node for max retries
                """
                node.backup_max_retries_reached(self.request.id)
