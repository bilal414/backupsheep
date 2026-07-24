import time
import uuid as uuid
from django.db import models
from django.db.models import UniqueConstraint, Q
from model_utils.models import TimeStampedModel
from django.contrib.auth.models import Group
from django.utils.text import slugify

# Sentinel for CoreAccount.get_all_backups(): an explicit status=None means
# "every status", while omitting the argument keeps the historical
# COMPLETE-only default.
_COMPLETE_ONLY = object()


def get_backup_models():
    """(model, node FK attribute) pairs for every concrete backup model.

    The FK points at the node-type object (CoreWebsite, CoreDigitalOcean, ...)
    that owns the `.node` property. Imports stay lazy: backup.models pulls in
    storage/connection models which import this module back.
    """
    from ..backup.models import (
        CoreWebsiteBackup,
        CoreDatabaseBackup,
        CoreWordPressBackup,
        CoreBasecampBackup,
        CoreDigitalOceanBackup,
        CoreHetznerBackup,
        CoreUpCloudBackup,
        CoreOVHCABackup,
        CoreOVHEUBackup,
        CoreOVHUSBackup,
        CoreVultrBackup,
        CoreAWSBackup,
        CoreLightsailBackup,
        CoreAWSRDSBackup,
        CoreOracleBackup,
        CoreGoogleCloudBackup,
    )

    return (
        (CoreWebsiteBackup, "website"),
        (CoreDatabaseBackup, "database"),
        (CoreWordPressBackup, "wordpress"),
        (CoreBasecampBackup, "basecamp"),
        (CoreDigitalOceanBackup, "digitalocean"),
        (CoreHetznerBackup, "hetzner"),
        (CoreUpCloudBackup, "upcloud"),
        (CoreOVHCABackup, "ovh_ca"),
        (CoreOVHEUBackup, "ovh_eu"),
        (CoreOVHUSBackup, "ovh_us"),
        (CoreVultrBackup, "vultr"),
        (CoreAWSBackup, "aws"),
        (CoreLightsailBackup, "lightsail"),
        (CoreAWSRDSBackup, "aws_rds"),
        (CoreOracleBackup, "oracle"),
        (CoreGoogleCloudBackup, "google_cloud"),
    )


class CoreAccount(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        DISABLED = 0, "Disabled"
        DELETE_REQUESTED = 2, "Delete Requested"

    name = models.CharField(max_length=255, null=True, blank=True)
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    encryption_key = models.BinaryField(null=True, editable=False)

    stats_storage_used_bs = models.BigIntegerField(default=0)
    stats_storage_used_byo = models.BigIntegerField(default=0)
    stats_nodes_used = models.BigIntegerField(default=0)

    groups = models.ManyToManyField(
        Group, related_name="accounts", through="CoreAccountGroup"
    )

    class Meta:
        db_table = "core_account"
        verbose_name = "Account"
        verbose_name_plural = "Accounts"

    @property
    def uuid_str(self):
        return slugify(f"bs-a{self.id}")

    def create_log(self, data=None):
        from apps._tasks.helper.tasks import send_log_to_db

        data["account_id"] = self.id
        data["created"] = int(time.time())

        send_log_to_db(data)

    def create_storage_log(self, message, node, backup, storage):
        from apps.console.log.models import CoreLog

        data = {
            "account_id": self.id,
            "created": int(time.time()),
            "message": message,
            "node_id": node.id,
            "node_name": node.name,
            "connection_id": node.connection.id,
            "connection_name": node.connection.name,
            "backup_id": backup.id,
            "backup_name": backup.name,
            "storage_id": storage.id,
            "storage_name": storage.name,
            "storage_type_code": storage.type.code,
            "storage_type_name": storage.type.name,
            "attempt_no": backup.attempt_no,
            "backup_type": backup.type,
        }
        CoreLog.objects.create(account_id=data.get("account_id"), data=data)

    def create_backup_log(self, message, node, backup):
        from apps.console.log.models import CoreLog

        data = {
            "account_id": self.id,
            "created": int(time.time()),
            "message": message,
            "node_id": node.id,
            "node_name": node.name,
            "connection_id": node.connection.id,
            "connection_name": node.connection.name,
            "backup_id": backup.id,
            "backup_name": backup.name,
            "attempt_no": backup.attempt_no,
            "backup_type": backup.type,
        }
        CoreLog.objects.create(account_id=data.get("account_id"), data=data)


    def storage_used(
        self,
        storage_type_code=None,
        only_byo_storage=None,
        website_only=None,
        database_only=None,
    ):
        from ..backup.models import CoreWebsiteBackupStoragePoints
        from ..utils.models import UtilBackup
        from django.db.models import Sum
        from ..backup.models import CoreDatabaseBackupStoragePoints
        from ..backup.models import CoreWordPressBackupStoragePoints
        from django.db.models import Count, Q

        storage_used = 0
        query = Q(
            backup__size__isnull=False,
            backup__status=UtilBackup.Status.COMPLETE,
            storage__account=self,
        )

        if storage_type_code:
            query &= Q(storage__type__code=storage_type_code)

        elif only_byo_storage:
            query &= ~Q(storage__type__code="bs")

        # Website Storage
        if not database_only:
            query_web = query & Q(
                status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE
            )
            storage_used += (
                CoreWebsiteBackupStoragePoints.objects.filter(query_web)
                .aggregate(Sum("backup__size"))
                .get("backup__size__sum", 0)
                or 0
            )

        # Database Storage
        if not website_only:
            query_db = query & Q(
                status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE
            )
            storage_used += (
                CoreDatabaseBackupStoragePoints.objects.filter(query_db)
                .aggregate(Sum("backup__size"))
                .get("backup__size__sum", 0)
                or 0
            )

        # WordPress Storage
        if not database_only:
            query_wp = query & Q(
                status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE
            )
            storage_used += (
                CoreWordPressBackupStoragePoints.objects.filter(query_wp)
                .aggregate(Sum("backup__size"))
                .get("backup__size__sum", 0)
                or 0
            )

        return storage_used

    def get_all_backups(
        self, last_backup_count=3, status=_COMPLETE_ONLY, limit=None, node_ids=None
    ):
        """Unified, newest-first list of this account's backups across all models.

        Default behavior is the historical one: COMPLETE backups only, up to
        `last_backup_count` rows per backup model, and the full merged list
        returned (not truncated to `last_backup_count` overall).

        `status` accepts an iterable of UtilBackup.Status values to filter on,
        or None to include every status. `limit` caps the merged result (and the
        per-model pre-slice, so small limits stay cheap). `node_ids` optionally
        scopes the result to a member's permitted nodes.
        """
        from ..utils.models import UtilBackup
        from itertools import chain

        if status is _COMPLETE_ONLY:
            status = (UtilBackup.Status.COMPLETE,)

        per_model_count = limit if limit is not None else last_backup_count

        querysets = []
        for model, node_attr in get_backup_models():
            queryset = model.objects.filter(
                **{f"{node_attr}__node__connection__account": self}
            )
            if node_ids is not None:
                queryset = queryset.filter(**{f"{node_attr}__node_id__in": node_ids})
            if status is not None:
                queryset = queryset.filter(status__in=status)
            queryset = queryset.select_related(
                node_attr,
                f"{node_attr}__node",
                f"{node_attr}__node__connection",
                f"{node_attr}__node__connection__integration",
            )
            querysets.append(queryset.order_by("-modified")[:per_model_count])

        backups = list(chain(*querysets))
        backups = sorted(backups, key=lambda backup: backup.modified, reverse=True)
        if limit is not None:
            backups = backups[:limit]
        return backups

    def get_node_count(self, exclude_paused=None):
        from ..node.models import CoreNode
        query = Q(connection__account=self)
        query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
        if exclude_paused:
            query &= ~Q(status=CoreNode.Status.PAUSED)

        return CoreNode.objects.filter(query).count()

    def get_node_count_wordpress(self):
        from ..node.models import CoreNode
        return CoreNode.objects.filter(type=CoreNode.Type.SAAS, connection__account=self).count()

    def get_node_count_website(self):
        from ..node.models import CoreNode
        return CoreNode.objects.filter(type=CoreNode.Type.WEBSITE, connection__account=self).count()

    def get_node_count_database(self):
        from ..node.models import CoreNode
        return CoreNode.objects.filter(type=CoreNode.Type.DATABASE, connection__account=self).count()

    def get_node_count_storage_integrations(self):
        from ..node.models import CoreStorage
        return CoreStorage.objects.filter(account=self).count()

    def get_node_count_non_europe(self):
        from ..node.models import CoreNode
        return CoreNode.objects.filter(connection__account=self, connection__location__location__icontains="depreciated").count()

    def get_encryption_key(self):
        return bytes(self.encryption_key)

    def get_primary_member(self):
        from ..member.models import CoreMember
        return self.members.get(memberships__primary=True)

    def get_name(self):
        if self.name:
            return self.name
        else:
            return self.get_primary_member().full_name

    def get_notification_recipients(self, event):
        """Distinct (member, email) pairs that should receive `event` notifications.

        event is "success" or "fail". Considers ACTIVE memberships only and honors
        each membership's notify_on_success / notify_on_fail flag (a NULL flag
        counts as True); the primary membership is ALWAYS included regardless of
        its flag so the account owner can never be silently opted out.
        """
        from ..member.models import CoreMemberAccount

        if event == "success":
            flag_field = "notify_on_success"
        elif event == "fail":
            flag_field = "notify_on_fail"
        else:
            raise ValueError(f"unknown notification event: {event}")

        recipients = []
        seen = set()
        memberships = self.memberships.filter(
            status=CoreMemberAccount.Status.ACTIVE
        ).select_related("member__user")
        for membership in memberships:
            if not membership.primary:
                if getattr(membership, flag_field) is False:
                    continue
            member = membership.member
            email = member.user.email
            if not email or (member.id, email) in seen:
                continue
            seen.add((member.id, email))
            recipients.append((member, email))
        return recipients

    def send_notification(self, message):
        """Fan a plain-text notification out to the account's connected channels.

        Sends to every connected Slack workspace and Telegram chat (the channel
        models carry no enabled/disabled flag, so every connected channel is an
        active one). Each channel send is wrapped so one failing channel can
        never break the others -- or the caller (send_log_to_db).
        """
        from sentry_sdk import capture_exception

        for slack in self.notification_slack.all():
            try:
                slack.send(message)
            except Exception as e:
                capture_exception(e)
                print(f"unable to send slack notification for account {self.id}: {e}")

        for telegram in self.notification_telegram.all():
            try:
                telegram.send(message)
            except Exception as e:
                capture_exception(e)
                print(f"unable to send telegram notification for account {self.id}: {e}")


class CoreAccountGroup(TimeStampedModel):
    class Type(models.IntegerChoices):
        Team = 1, "Team"
        Client = 2, "Client"

    name = models.CharField(max_length=255)
    account = models.ForeignKey(
        CoreAccount,
        on_delete=models.CASCADE,
        related_name="enrollments",
        editable=False,
    )
    group = models.ForeignKey(
        Group, on_delete=models.CASCADE, related_name="enrollment", editable=False
    )
    type = models.IntegerField(choices=Type.choices)
    default = models.BooleanField(editable=False)
    notes = models.TextField(null=True)
    nodes = models.ManyToManyField("CoreNode", related_name="enrollments")

    class Meta:
        db_table = "core_account_mtm_group"
        verbose_name = "Account Group"
        verbose_name_plural = "Account Groups"
        constraints = [
            UniqueConstraint(
                fields=["account", "name", "type"], name="unique_name_type_enrollment"
            ),
            UniqueConstraint(
                fields=["account", "group"], name="unique_group_enrollment"
            ),
            UniqueConstraint(
                fields=["account"],
                condition=Q(default=True),
                name="unique_account_default_enrollment",
            ),
        ]
        # self.request.user.has_perm("blog.set_published_status")
        permissions = [
            (
                "notify_on_success",
                "Can receive success notifications"
            ),
            (
                "notify_on_fail",
                "Can receive fail notifications"
            ),
            (
                "notify_via_email",
                "Can receive email notifications"
            ),
            (
                "notify_via_slack",
                "Can receive slack notifications"
            ),
            (
                "notify_via_telegram",
                "Can receive telegram notifications"
            ),
            (
                "backup_create",
                "Can create on-demand backup of node."
            ),
            (
                "backup_download",
                "Can download any on-demand/scheduled backup of node."
            ),
            (
                "backup_delete",
                "Can delete any on-demand/scheduled backup of node."
            ),
            (
                "schedule_changes",
                "Can create, modify and delete backup schedules."
            ),
            (
                "node_changes",
                "Can create, modify and delete nodes."
            ),
            (
                "integration_changes",
                "Can create, modify and delete integrations."
            ),
            (
                "storage_changes",
                "Can create, modify and delete storage accounts."
            )
        ]

    @property
    def member_count(self):
        return self.group.user_set.count()

    @property
    def node_count(self):
        return 0
