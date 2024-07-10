import datetime
import json
import os
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

from apps.api.v1.utils.api_helpers import aws_s3_upload_log_file
from apps.console.account.models import CoreAccount
from backupsheep.celery import app
import subprocess

from apps.console.connection.models import CoreAuthBasecamp
from apps.console.member.models import CoreMember
from apps.console.notification.models import CoreNotificationEmail, CoreNotificationSlack
from apps.console.storage.models import CoreStorageType, CoreStorage, CoreStorageOneDrive, CoreStorageDropbox, \
    CoreStorageGoogleDrive
from apps.console.usage.models import CoreUsageNode, CoreUsageStorage
from apps.console.utils.models import UtilBackup
from slack_sdk import WebhookClient


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
)
def delete_from_disk(self, backup_uuid, path_type):
    try:
        if path_type == "dir" or path_type == "both":
            local_dir = f"_storage/{backup_uuid}"

            if "_storage" in local_dir:
                execstr = f"sudo rsync -a --delete empty_dir/ {local_dir}"

                try:
                    subprocess.run(
                        execstr,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=14 * 60,
                        universal_newlines=True,
                        encoding="utf-8",
                        errors="ignore",
                        shell=True,
                    )
                except Exception:
                    pass

                # Now remove directory
                execstr = f"sudo rm -rf {local_dir}"
                try:
                    subprocess.run(
                        execstr,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=14 * 60,
                        universal_newlines=True,
                        encoding="utf-8",
                        errors="ignore",
                        shell=True,
                    )
                except Exception:
                    pass
        if path_type == "zip" or path_type == "both":
            local_zip = f"_storage/{backup_uuid}.zip"

            # Now we need to upload log file. Doing it here because we need logs from storage uploads.
            # Only delete log when we delete zip because we delete dir before zip file is uploaded.
            log_file_path = f"/home/ubuntu/backupsheep/_storage/{backup_uuid}.log"
            if os.path.exists(log_file_path):
                aws_s3_upload_log_file(log_file_path, f"{backup_uuid}.log")
                os.remove(log_file_path)

            if "_storage" in local_zip:
                execstr = f"sudo rm -rf {local_zip}"
                try:
                    subprocess.run(
                        execstr,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=14 * 60,
                        universal_newlines=True,
                        encoding="utf-8",
                        errors="ignore",
                        shell=True,
                    )
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except OSError:
        pass
    except Exception as e:
        raise self.retry()


@current_app.task(
    name="terminate_backup",
    track_started=True,
    default_retry_delay=15 * 60,
    max_retries=16,
    bind=True,
    queue="terminate_backup",
)
def terminate_backup(self, data):
    try:
        app.control.revoke(data["celery_task_id"], terminate=True)
    except Exception as e:
        raise self.retry()


@current_app.task(name="send_to_firebase", track_started=True, bind=True, queue="send_to_firebase")
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
    queue="send_log_to_db",
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
    queue="send_log_to_slack",
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
    queue="send_log_to_telegram",
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
        from apps.console.storage.models import CoreStorageBS
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
    queue="send_postmark_email",
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



@current_app.task(
    name="bs_storage_clean_delete_markers",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def bs_storage_clean_delete_markers(self):
    from apps.console.backup.models import (
        CoreDatabaseBackupStoragePoints,
        CoreWebsiteBackupStoragePoints,
    )
    import boto3

    try:
        for storage_point in CoreWebsiteBackupStoragePoints.objects.filter(
            storage__type__code="bs",
            status=CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED,
        ).order_by("-created"):
            if storage_point.storage_file_id:
                if ".amazonaws.com" in storage_point.storage.storage_bs.endpoint:
                    s3_client = boto3.client("s3", storage_point.storage.storage_bs.region)

                    prefix = f"{storage_point.storage.storage_bs.prefix}{storage_point.storage_file_id}"

                    response = s3_client.list_object_versions(
                        Prefix=prefix,
                        Bucket=storage_point.storage.storage_bs.bucket_name,
                    )
                    versions = response.get("Versions", [])
                    delete_markers = response.get("DeleteMarkers", [])

                    for version in versions:
                        s3_client.delete_object(
                            Bucket=storage_point.storage.storage_bs.bucket_name,
                            Key=prefix,
                            VersionId=version["VersionId"],
                        )

                    for delete_marker in delete_markers:
                        s3_client.delete_object(
                            Bucket=storage_point.storage.storage_bs.bucket_name,
                            Key=prefix,
                            VersionId=delete_marker["VersionId"],
                        )

        for storage_point in CoreDatabaseBackupStoragePoints.objects.filter(
            storage__type__code="bs",
            status=CoreDatabaseBackupStoragePoints.Status.DELETE_COMPLETED,
        ).order_by("-created"):
            if storage_point.storage_file_id:
                if ".amazonaws.com" in storage_point.storage.storage_bs.endpoint:
                    s3_client = boto3.client("s3", storage_point.storage.storage_bs.region)

                    prefix = f"{storage_point.storage.storage_bs.prefix}{storage_point.storage_file_id}"

                    response = s3_client.list_object_versions(
                        Prefix=prefix,
                        Bucket=storage_point.storage.storage_bs.bucket_name,
                    )
                    versions = response.get("Versions", [])
                    delete_markers = response.get("DeleteMarkers", [])

                    for version in versions:
                        s3_client.delete_object(
                            Bucket=storage_point.storage.storage_bs.bucket_name,
                            Key=prefix,
                            VersionId=version["VersionId"],
                        )

                    for delete_marker in delete_markers:
                        s3_client.delete_object(
                            Bucket=storage_point.storage.storage_bs.bucket_name,
                            Key=prefix,
                            VersionId=delete_marker["VersionId"],
                        )
    except Exception as e:
        capture_exception(e)
        raise self.retry()


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
                        schedule.aws_schedule_delete()

                    for schedule in node.schedules.all():
                        schedule.delete()

                node.delete()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="delete_bs_storage_for_node",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def delete_bs_storage_for_node(self, node_id):
    from apps.console.node.models import CoreNode
    from apps.console.backup.models import (
        CoreWebsiteBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
        CoreWordPressBackupStoragePoints,
    )

    try:
        if node_id:
            node = CoreNode.objects.get(id=node_id)

            if node.type == CoreNode.Type.WEBSITE:
                for storage_point in CoreWebsiteBackupStoragePoints.objects.filter(
                    backup__website__node_id=node_id,
                    status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
                    storage__type__code="bs",
                ):
                    storage_point.soft_delete()
            elif node.type == CoreNode.Type.DATABASE:
                for storage_point in CoreDatabaseBackupStoragePoints.objects.filter(
                    backup__database__node_id=node_id,
                    status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
                    storage__type__code="bs",
                ):
                    storage_point.soft_delete()
            elif node.type == CoreNode.Type.SAAS:
                for storage_point in CoreWordPressBackupStoragePoints.objects.filter(
                    backup__wordpress__node_id=node_id,
                    status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE,
                    storage__type__code="bs",
                ):
                    storage_point.soft_delete()
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
    name="notification_usage_node_alert",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def notification_usage_node_alert(self):
    try:
        template_id = 26676770
        for usage in (
            CoreUsageNode.objects.filter(plan_node_overage__gt=0, email_alert_sent=None)
            .distinct("account")
            .order_by("-created")
        ):
            data = {
                "node_used_all": usage.node_used_all,
                "plan_node_overage": usage.plan_node_overage,
                "plan_name": usage.account.billing.plan.name,
                "plan_node_quota": usage.plan_node_quota,
            }
            send_postmark_email(usage.account.get_primary_member().email, template_id, "usage_node_alert", data)
            usage.email_alert_sent = True
            usage.save()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="notification_developer_plan_changes",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def notification_developer_plan_changes(self):
    try:
        template_id = 30568965

        for account in CoreAccount.objects.filter(billing__plan__name="Developer"):
            if account.usage_node.filter().first().node_used_all > 0:
                print(account.id)
                data = {}
                send_postmark_email(account.get_primary_member().email, template_id, "developer_plan_changes", data)
    except Exception as e:
        print(e.__str__())
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="calc_stats_storage_used",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
    queue="internal",
)
def calc_stats_storage_used(self, account_id=None):
    try:
        for account in CoreAccount.objects.filter():
            if (
                account.get_node_count_wordpress() > 0
                or account.get_node_count_website()
                or account.get_node_count_database() > 0
            ):
                account_storage = CoreUsageStorage(account=account)
                account_storage.plan_storage_quota = account.billing.free_storage
                account_storage.plan_storage_overage = account.plan_storage_overage
                account_storage.storage_used_all = account.storage_used()
                account_storage.storage_used_bs = account.storage_used(storage_type_code="bs")
                account_storage.storage_used_byo = account.storage_used(only_byo_storage=True)
                account_storage.save()
                print(account.id)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="notification_usage_storage_alert",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def notification_usage_storage_alert(self):
    try:
        template_id = 30569414
        for account in CoreAccount.objects.filter().order_by("-created"):
            usage = account.usage_storage.filter().first()
            if usage:
                if usage.plan_storage_overage > 0:
                    print(account.id)
                    data = {
                        "plan_storage_overage": humanfriendly.format_size(usage.plan_storage_overage or 0),
                        "storage_used_all": humanfriendly.format_size(usage.storage_used_all or 0),
                        "storage_used_bs": humanfriendly.format_size(usage.storage_used_bs or 0),
                        "plan_name": usage.account.billing.plan.name,
                        "plan_storage_quota": humanfriendly.format_size(usage.plan_storage_quota or 0),
                    }
                    send_postmark_email(
                        usage.account.get_primary_member().email, template_id, "usage_storage_alert", data
                    )
                    usage.save()
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="calc_stats_nodes_used",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
    queue="internal",
)
def calc_stats_nodes_used(self):
    try:
        for account in CoreAccount.objects.filter().order_by("created"):
            usage_node = CoreUsageNode(account=account)

            usage_node.node_used_all = account.get_node_count(exclude_paused=True)
            usage_node.plan_node_quota = account.billing.plan.nodes

            if usage_node.node_used_all > usage_node.plan_node_quota:
                usage_node.plan_node_overage = usage_node.node_used_all - usage_node.plan_node_quota
            else:
                usage_node.plan_node_overage = 0
            usage_node.save()
            print(account.id)
    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="calc_account_good_standing",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
    queue="internal",
)
def calc_account_good_standing(self):
    try:
        for account in CoreAccount.objects.filter().order_by("created"):
            if account.billing.plan.name == "Developer" or account.billing.plan.name == "AppSumo":
                storage_usage_ok = True
                node_usage_ok = True

                # Check storage overage
                storage_usage = account.usage_storage.filter().order_by("-created").first()
                if storage_usage:
                    if storage_usage.plan_storage_overage > 0:
                        storage_usage_ok = False

                # Check storage overage
                node_usage = account.usage_node.filter().order_by("-created").first()
                if node_usage:
                    if node_usage.plan_node_overage > 0:
                        node_usage_ok = False

                # We will add node usage_ok
                if storage_usage_ok and node_usage_ok:
                    account.billing.status = account.billing.Status.ACTIVE
                elif not storage_usage_ok and not node_usage_ok:
                    account.billing.status = account.billing.Status.OVER_USAGE_NODE_AND_STORAGE
                elif not storage_usage_ok:
                    account.billing.status = account.billing.Status.OVER_USAGE_STORAGE
                elif not node_usage_ok:
                    account.billing.status = account.billing.Status.OVER_USAGE_NODE

                account.billing.save()
            else:
                account.billing.status = account.billing.Status.ACTIVE
                account.billing.save()
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
    name="cleanup_storage",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
)
def cleanup_storage(self, storage_point_id, node_type):
    from apps.console.backup.models import (
        CoreWebsiteBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
    )

    try:
        if node_type == "website":
            web_storage_point = CoreWebsiteBackupStoragePoints.objects.get(
                id=storage_point_id,
                storage__storage_bs__isnull=False,
                storage__storage_bs__endpoint__contains="filebase",
                status=CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED,
            )
            web_storage_point.soft_delete_temp()
        elif node_type == "database":
            database_storage_point = CoreDatabaseBackupStoragePoints.objects.get(
                id=storage_point_id,
                storage__storage_bs__isnull=False,
                storage__storage_bs__endpoint__contains="filebase",
                status=CoreDatabaseBackupStoragePoints.Status.DELETE_COMPLETED,
            )
            database_storage_point.soft_delete_temp()

    except Exception as e:
        capture_exception(e)
        raise self.retry()


@current_app.task(
    name="backup_download_request",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=16,
    bind=True,
    queue="backup_download_request",
)
def backup_download_request(self, storage_point_id=None, backup_type=None, member_id=None):
    from apps.console.backup.models import (
        CoreWebsiteBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
        CoreWordPressBackupStoragePoints,
    )

    try:
        storage_point = None

        if backup_type == "website":
            storage_point = CoreWebsiteBackupStoragePoints.objects.get(id=storage_point_id)
        elif backup_type == "database":
            storage_point = CoreDatabaseBackupStoragePoints.objects.get(id=storage_point_id)
        elif backup_type == "wordpress":
            storage_point = CoreWordPressBackupStoragePoints.objects.get(id=storage_point_id)

        if storage_point:
            storage_point.generate_download(member_id)

    except Exception as e:
        capture_exception(e)
        raise self.retry()



@current_app.task(
    name="backup_transfer_request",
    track_started=True,
    default_retry_delay=1 * 60,
    max_retries=4,
    bind=True,
    queue="backup_transfer_request",
)
def backup_transfer_request(self, storage_point_id=None, backup_type=None):
    from apps.console.backup.models import (
        CoreWebsiteBackupStoragePoints,
        CoreDatabaseBackupStoragePoints,
        CoreWordPressBackupStoragePoints,
    )

    try:
        if backup_type == "website":
            if CoreWebsiteBackupStoragePoints.objects.filter(id=storage_point_id).exists():
                storage_point = CoreWebsiteBackupStoragePoints.objects.get(id=storage_point_id)
                storage_point.remove_deplicate()
        elif backup_type == "database":
            if CoreDatabaseBackupStoragePoints.objects.filter(id=storage_point_id).exists():
                storage_point = CoreDatabaseBackupStoragePoints.objects.get(id=storage_point_id)
                storage_point.remove_deplicate()
        elif backup_type == "wordpress":
            if CoreWordPressBackupStoragePoints.objects.filter(id=storage_point_id).exists():
                storage_point = CoreWordPressBackupStoragePoints.objects.get(id=storage_point_id)
                storage_point.remove_deplicate()

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