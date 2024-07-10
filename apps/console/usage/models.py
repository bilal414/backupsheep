import time
from django.db import models
from model_utils.models import TimeStampedModel

from apps.console.account.models import CoreAccount


class CoreUsageStorage(TimeStampedModel):
    account = models.ForeignKey(CoreAccount, related_name="usage_storage", on_delete=models.CASCADE)

    # New fields
    plan_storage_quota = models.BigIntegerField(null=True)
    plan_storage_overage = models.BigIntegerField(null=True)
    storage_used_all = models.BigIntegerField(null=True)
    storage_used_bs = models.BigIntegerField(null=True)
    storage_used_byo = models.BigIntegerField(null=True)
    email_alert_sent = models.BooleanField(null=True)

    class Meta:
        db_table = "core_usage_storage"
        ordering = ["-created"]


class CoreUsageNode(TimeStampedModel):
    account = models.ForeignKey(CoreAccount, related_name="usage_node", on_delete=models.CASCADE)

    # New fields
    node_used_all = models.BigIntegerField(null=True)
    plan_node_quota = models.BigIntegerField(null=True)
    plan_node_overage = models.BigIntegerField(null=True)
    email_alert_sent = models.BooleanField(null=True)

    cloud_nodes = models.BigIntegerField(null=True)
    volume_nodes = models.BigIntegerField(null=True)
    website_nodes = models.BigIntegerField(null=True)
    database_nodes = models.BigIntegerField(null=True)
    saas_nodes = models.BigIntegerField(null=True)

    class Meta:
        db_table = "core_usage_node"
        ordering = ["-created"]


class CoreUsageBackup(TimeStampedModel):
    account = models.ForeignKey(CoreAccount, related_name="usage_backup", on_delete=models.CASCADE)

    total_backups = models.BigIntegerField(null=True)

    cloud_backups = models.BigIntegerField(null=True)
    cloud_storage = models.BigIntegerField(null=True)

    volume_backups = models.BigIntegerField(null=True)
    volume_storage = models.BigIntegerField(null=True)

    website_backups = models.BigIntegerField(null=True)
    website_storage = models.BigIntegerField(null=True)

    database_backups = models.BigIntegerField(null=True)
    database_storage = models.BigIntegerField(null=True)

    saas_backups = models.BigIntegerField(null=True)
    saas_storage = models.BigIntegerField(null=True)

    digitalocean_snapshot_count = models.BigIntegerField(null=True)
    digitalocean_snapshot_storage = models.BigIntegerField(null=True)

    hetzner_snapshot_count = models.BigIntegerField(null=True)
    hetzner_snapshot_storage = models.BigIntegerField(null=True)

    upcloud_snapshot_count = models.BigIntegerField(null=True)
    upcloud_snapshot_storage = models.BigIntegerField(null=True)

    ovh_ca_snapshot_count = models.BigIntegerField(null=True)
    ovh_ca_snapshot_storage = models.BigIntegerField(null=True)

    ovh_eu_snapshot_count = models.BigIntegerField(null=True)
    ovh_eu_snapshot_storage = models.BigIntegerField(null=True)

    ovh_us_snapshot_count = models.BigIntegerField(null=True)
    ovh_us_snapshot_storage = models.BigIntegerField(null=True)

    aws_snapshot_count = models.BigIntegerField(null=True)
    aws_snapshot_storage = models.BigIntegerField(null=True)

    lightsail_snapshot_count = models.BigIntegerField(null=True)
    lightsail_snapshot_storage = models.BigIntegerField(null=True)

    aws_rds_snapshot_count = models.BigIntegerField(null=True)
    aws_rds_snapshot_storage = models.BigIntegerField(null=True)

    vultr_snapshot_count = models.BigIntegerField(null=True)
    vultr_snapshot_storage = models.BigIntegerField(null=True)

    oracle_snapshot_count = models.BigIntegerField(null=True)
    oracle_snapshot_storage = models.BigIntegerField(null=True)

    linode_snapshot_count = models.BigIntegerField(null=True)
    linode_snapshot_storage = models.BigIntegerField(null=True)

    google_cloud_snapshot_count = models.BigIntegerField(null=True)
    google_cloud_snapshot_storage = models.BigIntegerField(null=True)

    class Meta:
        db_table = "core_usage_backup"
        ordering = ["-created"]
