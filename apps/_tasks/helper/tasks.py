import datetime
import json
import os
import shutil
import uuid
import boto3
import humanfriendly
import pytz
import requests
from django.conf import settings
import time
from celery import current_app
from django.db.models import Q, Sum, Count
from sentry_sdk import capture_exception, capture_message

from apps.console.account.models import CoreAccount
from backupsheep.celery import app

from apps.console.connection.models import CoreAuthBasecamp
from apps.console.member.models import CoreMember
from apps.console.notification.models import CoreNotificationEmail, CoreNotificationSlack
from apps.console.storage.models import CoreStorageType, CoreStorage, CoreStorageOneDrive, CoreStorageDropbox, \
    CoreStorageGoogleDrive
from apps.console.utils.models import UtilBackup
from slack_sdk import WebhookClient


@current_app.task(name="run_scheduled_backup", bind=True, ignore_result=True)
def run_scheduled_backup(self, schedule_id=None):
    """Fired by django-celery-beat for each active schedule; enqueues the node backup.

    Replaces the SaaS path where AWS EventBridge called /schedules/{id}/trigger/.
    """
    from apps.console.node.models import CoreSchedule, CoreScheduleRun

    try:
        schedule = CoreSchedule.objects.get(
            id=schedule_id, status=CoreSchedule.Status.ACTIVE
        )
    except CoreSchedule.DoesNotExist:
        return

    CoreScheduleRun.objects.create(schedule=schedule, request_id=uuid.uuid4().hex)
    current_app.send_task(
        schedule.node.backup_task_name(),
        kwargs={
            "node_id": schedule.node.id,
            "schedule_id": schedule.id,
            "storage_ids": schedule.storage_ids,
        },
    )


@current_app.task(
    name="digitalocean_refresh_tokens",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def digitalocean_refresh_tokens(self):
    try:
        from datetime import datetime
        from apps.console.connection.models import CoreAuthDigitalOcean, CoreConnection
        from apps.console.node.models import CoreNode

        if settings.DJANGO_SERVER == "prod":
            query = Q()
            query &= ~Q(connection__status=CoreConnection.Status.TOKEN_REFRESH_FAIL)
            query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
            for auth_digitalocean in CoreAuthDigitalOcean.objects.filter(query):
                if (
                    not auth_digitalocean.connection.nodes.filter(status=CoreNode.Status.BACKUP_IN_PROGRESS).exists()
                ) and (not auth_digitalocean.connection.nodes.filter(status=CoreNode.Status.BACKUP_RETRYING).exists()):
                    auth_digitalocean.refresh_auth_token()
    except Exception as e:
        raise self.retry()


@current_app.task(
    name="delete_from_disk",
    track_started=True,
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def delete_from_disk(self, backup_uuid, path_type):
    """Remove a backup's local working files from _storage once uploads have settled.

    path_type selects what to remove (everything lives under <BASE_DIR>/_storage/):
        "dir"  -> the working directory  <uuid>/      (uncompressed dump tree)
        "zip"  -> the archive            <uuid>.zip
        "both" -> the working directory and the archive

    The run log (<uuid>.log) is intentionally kept on disk and pruned later by
    delete_old_logs; it is never removed here.

    Uses plain Python file operations -- no shell, no sudo, no hardcoded host paths --
    and is idempotent: a missing file is success, not an error. Only unexpected failures
    retry (bounded), so cleanup can never wedge a backup or leak disk silently.
    """
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))

    def _remove(name, is_dir):
        # Resolve and confine to _storage so a malformed uuid can't escape the directory
        # (and never delete _storage itself).
        target = os.path.realpath(os.path.join(storage_dir, name))
        if target == storage_dir or os.path.commonpath([storage_dir, target]) != storage_dir:
            return
        if is_dir:
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.remove(target)
            except FileNotFoundError:
                pass

    try:
        if path_type in ("dir", "both"):
            _remove(backup_uuid, is_dir=True)

        if path_type in ("zip", "both"):
            _remove(f"{backup_uuid}.zip", is_dir=False)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(name="delete_old_logs", bind=True, ignore_result=True)
def delete_old_logs(self, max_age_days=None):
    """Prune backup run logs from local _storage once they pass the retention window.

    Self-hosted builds keep run logs (and the .files/.md5 artefacts) on the container
    instead of uploading them anywhere, so this task is what bounds their disk usage.
    It is scheduled daily by Celery beat (see CELERY_BEAT_SCHEDULE). max_age_days
    defaults to settings.LOG_RETENTION_DAYS (30).
    """
    if max_age_days is None:
        max_age_days = getattr(settings, "LOG_RETENTION_DAYS", 30)
    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
    cutoff = time.time() - (max_age_days * 86400)
    suffixes = (".log", ".files", ".md5")
    try:
        with os.scandir(storage_dir) as entries:
            for entry in entries:
                if not entry.is_file() or not entry.name.endswith(suffixes):
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        os.remove(entry.path)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    except Exception as e:
        capture_exception(e)


@current_app.task(name="poll_cloud_backup", bind=True, ignore_result=True)
def poll_cloud_backup(self, node_id, backup_id, started_at=None, interval=120, timeout=86400):
    """Asynchronously wait for a cloud / volume snapshot to finish.

    Runs ONE status check per invocation and re-queues itself between checks, so the
    worker is never blocked for the whole (potentially hours-long) snapshot -- replacing
    the old blocking `while ...: time.sleep(60)` poll inside each backup model.

    Resilience: a single failed or transient status check never fails the backup --
    backup.poll_status() returns IN_PROGRESS and we simply poll again. The backup is
    marked FAILED only when the provider itself reports the snapshot errored, and TIMEOUT
    only after `timeout` seconds of polling.
    """
    import time as _time
    from apps.console.node.models import CoreNode
    from apps._tasks.exceptions import (
        NodeBackupFailedError,
        NodeBackupStatusCheckTimeOutError,
    )

    try:
        node = CoreNode.objects.get(id=node_id)
    except CoreNode.DoesNotExist:
        return

    backup = node.get_cloud_backup(backup_id)
    if backup is None:
        return

    # Stop polling once the backup has reached any terminal state (completed elsewhere,
    # cancelled, or queued/processed for deletion).
    terminal = (
        UtilBackup.Status.COMPLETE,
        UtilBackup.Status.FAILED,
        UtilBackup.Status.TIMEOUT,
        UtilBackup.Status.CANCELLED,
        UtilBackup.Status.DELETE_REQUESTED,
        UtilBackup.Status.DELETE_IN_PROGRESS,
        UtilBackup.Status.DELETE_COMPLETED,
    )
    if backup.status in terminal:
        return

    if started_at is None:
        started_at = _time.time()

    try:
        status = backup.poll_status()
    except Exception as e:
        # poll_status is meant to swallow transient errors itself; if an unexpected one
        # escapes, treat it as "still in progress" rather than failing the backup.
        capture_exception(e)
        status = UtilBackup.Status.IN_PROGRESS

    if status == UtilBackup.Status.COMPLETE:
        node.backup_complete_reset(backup.celery_task_id)
        # Retention: keep only the newest keep_last completed backups for the schedule.
        if backup.schedule and (backup.schedule.keep_last or 0) > 0:
            keep_last = backup.schedule.keep_last
            completed = list(
                backup.__class__.objects.filter(
                    schedule=backup.schedule, status=UtilBackup.Status.COMPLETE
                ).order_by("created")
            )
            for old_backup in completed[:-keep_last]:
                old_backup.soft_delete()
        node.notify_backup_success(backup)
        return

    if status == UtilBackup.Status.FAILED:
        backup.status = UtilBackup.Status.FAILED
        backup.save()
        node.backup_complete_reset()  # return node to ACTIVE (no celery id -> node only)
        node.notify_backup_fail(
            NodeBackupFailedError(
                node, backup.uuid_str, backup.attempt_no, backup.type,
                "Cloud provider reported the snapshot as errored.",
            ),
            backup.type,
        )
        return

    # Still in progress (or a transient check failure). Give up only past the hard
    # timeout; otherwise re-queue another check and free the worker until then.
    if (_time.time() - started_at) > timeout:
        node.backup_timeout_reset(backup.celery_task_id)
        node.notify_backup_fail(
            NodeBackupStatusCheckTimeOutError(node, backup.uuid_str), backup.type
        )
        return

    poll_cloud_backup.apply_async(
        args=[node_id, backup_id, started_at, interval, timeout], countdown=interval
    )


@current_app.task(
    name="terminate_backup",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def terminate_backup(self, data):
    try:
        app.control.revoke(data["celery_task_id"], terminate=True)
    except Exception as e:
        raise self.retry()


@current_app.task(name="send_to_firebase", track_started=True, bind=True)
def send_to_firebase(self, data):
    try:
        if data.get("notes") == "completed" or data.get("notes") == "failed":
            time.sleep(5)
        ref = db.reference(f"nodes/{data.get('node_id')}/logs")
        ref.set(
            {
                "timestamp": int(time.time()),
                "notes": data.get("notes"),
                "report": data.get("report", None),
            }
        )
    except Exception as e:
        raise self.retry()


@current_app.task(
    name="send_log_to_db",
    bind=True,
    ignore_result=True,
    acks_late=False,
    send_events=False,
)
def send_log_to_db(self, data):
    from apps.console.log.models import CoreLog

    try:
        if data.get("account_id"):
            log = CoreLog.objects.create(account_id=data.get("account_id"), data=data)

            if data.get("sender_name") == "BackupSheep - Notification Bot":
                message = log.data.get("message")
                error_details = log.data.get("error_details")

                full_msg = f""
                if message:
                    if message.strip() != "":
                        full_msg += f"{data.get('message')}"

                if error_details:
                    if error_details.strip() != "":
                        if len(full_msg) > 0:
                            full_msg += f" :: "
                        full_msg += f"{data.get('error_details')}"
                if len(full_msg) > 0:
                    log.account.send_notification(full_msg)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_log_to_slack",
    bind=True,
    ignore_result=True,
)
def send_log_to_slack(self, url, message):
    try:
        webhook = WebhookClient(url)
        response = webhook.send(
            text=f"{message}",
        )
        if response.status_code != 200 and response.body != "ok":
            self.retry()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_log_to_telegram",
    bind=True,
    ignore_result=True,
)
def send_log_to_telegram(self, chat_id, message):
    try:
        result = requests.get(
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_KEY}/sendMessage?"
            f"chat_id={chat_id}"
            f"&text={message}",
            headers={"content-type": "application/json"},
            verify=True,
        )
        if result.status_code != 200:
            self.retry()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="account_delete",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def account_delete(self):
    try:
        from apps.console.node.models import CoreSchedule, CoreNode
        import boto3
        from apps.console.backup.models import (
            CoreDatabaseBackupStoragePoints,
            CoreWebsiteBackupStoragePoints,
        )

        for account in CoreAccount.objects.filter(status=CoreAccount.Status.DELETE_REQUESTED):

            """
            NODE STORAGE CLEANUP
            """
            for node in CoreNode.objects.filter(connection__account=account).order_by("-created"):
                node.status = CoreNode.Status.DELETE_REQUESTED
                node.save()
                node_delete_requested(node_id=node.id)

            """
            FINAL USER CLEANUP
            """
            for membership in account.memberships.all():
                membership.member.user.delete()
            account.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="send_postmark_email",
    bind=True,
    ignore_result=True,
    default_retry_delay=1 * 60,
    max_retries=16,
)
def send_postmark_email(self, to_email, template, context):
    try:
        from apps.console.notification.models import CoreNotificationLogEmail

        if CoreMember.objects.filter(user__email=to_email).exists():
            member = CoreMember.objects.filter(user__email=to_email).first()

            # Create email log
            if member.get_primary_account():
                account = member.get_primary_account()
                if CoreNotificationEmail.objects.filter(account=account,
                                                        email=to_email,
                                                        status=CoreNotificationEmail.Status.VERIFIED).exists():

                    email_notification = CoreNotificationLogEmail()
                    email_notification.account = account
                    email_notification.email = to_email
                    email_notification.template = template
                    email_notification.context = context
                    email_notification.save()

                    if template == "password_reset":
                        email_notification.send()
                else:
                    print(f"email not verified : {to_email}")
    except Exception as e:
        capture_exception(e)


"""
NO NEED TO RUN IT ON REGULAR BASIS ANYMORE. 
"""
@current_app.task(
    name="digitalocean_clean_volume_snapshots",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def digitalocean_clean_volume_snapshots(self):
    from apps.console.node.models import CoreNode
    from apps.console.backup.models import CoreDigitalOceanBackup

    try:
        for do_backup in CoreDigitalOceanBackup.objects.filter(
            digitalocean__node__type=CoreNode.Type.VOLUME,
            status=CoreDigitalOceanBackup.Status.DELETE_COMPLETED,
        ).order_by("-created"):
            do_backup.soft_delete()

        for do_backup in CoreDigitalOceanBackup.objects.filter(
            digitalocean__node__type=CoreNode.Type.VOLUME,
            status=CoreDigitalOceanBackup.Status.DELETE_FAILED,
        ).order_by("-created"):
            do_backup.soft_delete()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


"""
RUNS ON ENDPOINT NODE
"""
@current_app.task(
    name="node_delete_requested",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def node_delete_requested(self, node_id):
    from apps.console.node.models import CoreNode, CoreSchedule

    try:
        if node_id:
            for node in CoreNode.objects.filter(status=CoreNode.Status.DELETE_REQUESTED, id=node_id).order_by(
                "-created"
            ):
                if hasattr(node, node.connection.integration.code):
                    node_type_object = getattr(node, node.connection.integration.code)

                    query = ~Q(status=UtilBackup.Status.DELETE_COMPLETED)
                    for backup in node_type_object.backups.filter(query).order_by("created"):
                        backup.soft_delete()

                    for schedule in CoreSchedule.objects.filter(node=node):
                        schedule.schedule_delete()

                    for schedule in node.schedules.all():
                        schedule.delete()

                # Remove the per-node website mirror cache used by incremental
                # backups, confined to _storage like delete_from_disk.
                if getattr(node, "website", None) is not None:
                    storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
                    cache_base = os.path.realpath(os.path.join(storage_dir, "website_cache", node.uuid_str))
                    if cache_base != storage_dir and os.path.commonpath([storage_dir, cache_base]) == storage_dir:
                        shutil.rmtree(cache_base, ignore_errors=True)
                        for suffix in (".meta.json", ".lock"):
                            try:
                                os.remove(cache_base + suffix)
                            except FileNotFoundError:
                                pass

                node.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="clean_delete_failed_backups",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def clean_delete_failed_backups(self):
    from apps.console.node.models import CoreNode, CoreSchedule

    try:
        for node in CoreNode.objects.filter().order_by("-created"):
            if hasattr(node, node.connection.integration.code):
                node_type_object = getattr(node, node.connection.integration.code)

                for backup in node_type_object.backups.filter(status=UtilBackup.Status.DELETE_FAILED).order_by(
                    "created"
                ):
                    print(f"removing backup.. {backup.uuid}")
                    backup.delete()

                for backup in node_type_object.backups.filter(
                    status=UtilBackup.Status.DELETE_FAILED_NOT_FOUND
                ).order_by("created"):
                    print(f"removing backup.. {backup.uuid}")
                    backup.delete()

                for backup in node_type_object.backups.filter(
                    status=UtilBackup.Status.DELETE_MAX_RETRY_FAILED
                ).order_by("created"):
                    print(f"removing backup.. {backup.uuid}")
                    backup.delete()

                for backup in node_type_object.backups.filter(status=UtilBackup.Status.MAX_RETRY_FAILED).order_by(
                    "created"
                ):
                    print(f"removing backup MAX_RETRY_FAILED.. {backup.uuid}")
                    backup.delete()

                for backup in node_type_object.backups.filter(status=UtilBackup.Status.CANCELLED).order_by("created"):
                    print(f"removing backup CANCELLED.. {backup.uuid}")
                    backup.delete()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="delete_requested_integrations",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def delete_requested_integrations(self):
    from apps.console.node.models import CoreConnection

    try:
        for connection in CoreConnection.objects.filter(status=CoreConnection.Status.DELETE_REQUESTED).order_by(
            "-created"
        ):
            for node in connection.nodes.filter():
                node_delete_requested(node_id=node.id)
            connection.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


# Todo: Add some checks here
@current_app.task(
    name="delete_requested_storages",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def delete_requested_storages(self):
    from apps.console.node.models import CoreStorage

    try:
        for storage in CoreStorage.objects.filter(status=CoreStorage.Status.DELETE_REQUESTED).order_by("-created"):
            storage.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="calc_stats_storage_insight",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def calc_stats_storage_insight(self):
    try:
        for account in CoreAccount.objects.filter().order_by("-created"):
            for storage_type in CoreStorageType.objects.filter():
                for storage in (
                    CoreStorage.objects.filter(account=account, type=storage_type)
                    .annotate(
                        Sum("website_backups__size"),
                        Sum("database_backups__size"),
                        Sum("wordpress_backups__size"),
                        Count("database_backups", distinct=True),
                        Count("website_backups", distinct=True),
                        Count("wordpress_backups", distinct=True),
                        Count("database_backups__database", distinct=True),
                        Count("website_backups__website", distinct=True),
                        Count("wordpress_backups__wordpress", distinct=True),
                    )
                    .order_by("-created")
                ):
                    # Counts
                    storage.stats_website_count = storage.website_backups__count
                    storage.stats_database_count = storage.database_backups__count
                    storage.stats_wordpress_count = storage.wordpress_backups__count
                    # Backups
                    storage.stats_website_backup_count = storage.website_backups__website__count
                    storage.stats_database_backup_count = storage.database_backups__database__count
                    storage.stats_wordpress_backup_count = storage.wordpress_backups__wordpress__count
                    # Size
                    storage.stats_website_size = storage.website_backups__size__sum
                    storage.stats_database_size = storage.database_backups__size__sum
                    storage.stats_wordpress_size = storage.wordpress_backups__size__sum
                    storage.save()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="token_refresh_all",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
)
def token_refresh_all(self):
    from datetime import datetime

    query = Q()

    try:
        # OneDrive Storage
        for storage in CoreStorageOneDrive.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"OneDrive ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Dropbox  Storage
        for storage in CoreStorageDropbox.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Dropbox ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Google Drive Storage
        for storage in CoreStorageGoogleDrive.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"GoogleDrive ID: {storage.id}")
                    storage.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Basecamp Integrations
        for auth in CoreAuthBasecamp.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Basecamp ID: {storage.id}")
                    auth.get_refresh_token()
                except Exception as e:
                    capture_exception(e)

        # Slack Notifications
        for notification in CoreNotificationSlack.objects.filter(query).order_by("-created"):
            t_difference = (storage.expiry or datetime.now(tz=pytz.UTC)) - datetime.now(tz=pytz.UTC)
            minutes = int(t_difference.total_seconds() / 60)
            if minutes <= 15:
                try:
                    print(f"Slack ID: {storage.id}")
                    notification.refresh_auth_token()
                except Exception as e:
                    capture_exception(e)

    except Exception as e:
        capture_exception(e)