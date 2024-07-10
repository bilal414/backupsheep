import time
import uuid as uuid
from django.db import models
from django.db.models import UniqueConstraint, Q
from model_utils.models import TimeStampedModel
from django.contrib.auth.models import Group
from django.utils.text import slugify


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
        query_db = query & Q(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE
        )
        storage_used += (
            CoreWordPressBackupStoragePoints.objects.filter(query_db)
            .aggregate(Sum("backup__size"))
            .get("backup__size__sum", 0)
            or 0
        )

        return storage_used

    def get_all_backups(self, last_backup_count=3):
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
            CoreLinodeBackup,
            CoreGoogleCloudBackup,
        )
        from ..utils.models import UtilBackup
        from itertools import chain

        website_backups = CoreWebsiteBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, website__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        database_backups = CoreDatabaseBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, database__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        wordpress_backups = CoreWordPressBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, wordpress__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        basecamp_backups = CoreBasecampBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, basecamp__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        digitalocean_backups = CoreDigitalOceanBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE,
            digitalocean__node__connection__account=self,
        ).order_by("-modified")[:last_backup_count]
        hetzner_backups = CoreHetznerBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, hetzner__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        upcloud_backups = CoreUpCloudBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, upcloud__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        ovh_ca_backups = CoreOVHCABackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, ovh_ca__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        ovh_eu_backups = CoreOVHEUBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, ovh_eu__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        ovh_us_backups = CoreOVHUSBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, ovh_us__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        vultr_backups = CoreVultrBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, vultr__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        aws_backups = CoreAWSBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, aws__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        lightsail_backups = CoreLightsailBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, lightsail__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        aws_rds_backups = CoreAWSRDSBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, aws_rds__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        oracle_backups = CoreOracleBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, oracle__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        linode_backups = CoreLinodeBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, linode__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]
        google_cloud_backups = CoreGoogleCloudBackup.objects.filter(
            status=UtilBackup.Status.COMPLETE, google_cloud__node__connection__account=self
        ).order_by("-modified")[:last_backup_count]

        backups = list(
            chain(
                website_backups,
                database_backups,
                wordpress_backups,
                basecamp_backups,
                digitalocean_backups,
                hetzner_backups,
                upcloud_backups,
                ovh_ca_backups,
                ovh_eu_backups,
                ovh_us_backups,
                vultr_backups,
                aws_backups,
                lightsail_backups,
                aws_rds_backups,
                oracle_backups,
                linode_backups,
                google_cloud_backups,
            )
        )

        return sorted(backups, key=lambda backup: backup.modified, reverse=True)

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
        return CoreStorage.objects.filter(account=self, storage_bs__isnull=True).count()

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