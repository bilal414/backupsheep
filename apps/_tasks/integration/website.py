import signal
import time

from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.db.models import Q
from sentry_sdk import capture_exception, capture_message

from apps.console.account.models import CoreAccount
from apps._tasks.exceptions import (
    NodeNotReadyForBackupError,
    ConnectionNotReadyForBackupError,
    ConnectionValidationFailedError,
    NodeBackupFailedError, NodeBackupTimeoutError,
)
from apps._tasks.helper.tasks import (
    delete_from_disk,
)
from apps.console.backup.models import CoreWebsiteBackupStoragePoints
from apps.console.billing.models import CoreBilling
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from celery.exceptions import SoftTimeLimitExceeded


@current_app.task(
    name="backup_website",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    # retry_backoff=True,
    # retry_backoff_max=900,
    # retry_jitter=False,
    # The +60 is to add some buffer so that command timeout can generate error instead of celery timeout
    soft_time_limit=(24 * 3600)+60,
)
def backup_website(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
):
    # self.request.id = "cdbf7603-c262-4eec-b38f-80bc1055f200"

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
        backup = None

        try:

            """
            Check for connection validation 
            """
            if not node.connection.validate():
                raise ConnectionValidationFailedError(node, attempt_no, backup_type)

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
            node.website.create_snapshot(backup)

            """
            Node itself should be available now.
            """
            node.status = CoreNode.Status.ACTIVE
            node.save()

        except ConnectionValidationFailedError as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_retrying_reset(self.request.id)
            raise self.retry()
        except (SoftTimeLimitExceeded, NodeBackupTimeoutError) as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_timeout_reset(self.request.id)
            # Delete Any Downloaded Files
            if backup:
                queue = f"delete_from_disk__{node.connection.location.queue}"
                delete_from_disk.apply_async(
                    args=[backup.uuid_str, "dir"],
                    queue=queue,
                )
                delete_from_disk.apply_async(
                    args=[backup.uuid_str, "zip"],
                    queue=queue,
                )
        except Exception as error:
            capture_exception(error)
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
