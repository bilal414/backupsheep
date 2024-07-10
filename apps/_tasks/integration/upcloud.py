from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.db.models import Q
from sentry_sdk import capture_exception

from apps.console.account.models import CoreAccount
from apps._tasks.exceptions import (
    NodeNotReadyForBackupError,
    ConnectionNotReadyForBackupError,
    ConnectionValidationFailedError,
    NodeValidationFailedError,
    NodeBackupFailedError,
)
from apps.console.billing.models import CoreBilling
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from celery.exceptions import SoftTimeLimitExceeded


@current_app.task(
    name="backup_upcloud",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    # retry_backoff=True,
    # retry_backoff_max=900,
    # retry_jitter=False,
    soft_time_limit=(24 * 3600),
)
def backup_upcloud(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
):
    attempt_no = self.request.retries + 1

    schedule_check = None

    # treat this as scheduled backup
    if schedule_id:
        backup_type = UtilBackup.Type.SCHEDULED
        if CoreSchedule.objects.filter(id=schedule_id, status=CoreSchedule.Status.ACTIVE).exists():
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
            Check for connection validation 
            """
            if not node.connection.validate():
                raise ConnectionValidationFailedError(node, attempt_no, backup_type)

            """
            Check node at cloud provider
            """
            if not node.validate():
                raise NodeValidationFailedError(node, attempt_no, backup_type)

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

            """
            Connect with website and generate snapshot 
            """
            if not backup.unique_id:
                node.upcloud.create_snapshot(backup)

            """
            Now we have to validate backup
            """
            backup.validate()

            """
            Finally just reset backup. 
            """
            node.backup_complete_reset(self.request.id)

            """
            Now mark backups delete requested based on schedule. 
            """
            if backup.schedule:
                """
                DELETE PREVIOUS BACKUPS if KEEP LAST # IS USED
                """
                if (backup.schedule.keep_last or 0) > 0:
                    while backup.schedule.upcloud_backups.filter(
                        status=UtilBackup.Status.COMPLETE
                    ).count() > (backup.schedule.keep_last or 0):
                        backup_to_delete = (
                            backup.schedule.upcloud_backups.filter(
                                status=UtilBackup.Status.COMPLETE
                            )
                            .order_by("created")
                            .first()
                        )
                        backup_to_delete.soft_delete()
            node.notify_backup_success(backup)
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
