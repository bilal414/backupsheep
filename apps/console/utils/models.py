import humanfriendly
from django.db import models
from model_utils.models import TimeStampedModel

from apps.console.account.models import CoreAccount
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


class UtilAppSumoCode(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        REFUNDED = 2, "Refunded"

    account = models.ForeignKey(CoreAccount, related_name="appsumo_codes", on_delete=models.CASCADE, null=True)
    code = models.CharField(max_length=64)
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)

    class Meta:
        db_table = "util_appsumo_code"


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

    class Type(models.IntegerChoices):
        ON_DEMAND = 1, "On-Demand"
        SCHEDULED = 2, "Scheduled"

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

    class Meta:
        abstract = True

    def exists_on_storage(self, storage_id=None):
        if storage_id:
            return self.storage_points.filter(id=storage_id).exists()

    def exists_on_bs_nas_storage(self):
        return self.storage_points.filter(storage_bs__host__isnull=False).exists()

    def exists_on_bs_idrivee2_storage(self):
        return self.storage_points.filter(storage_bs__endpoint="n2c1.fra.idrivee2-37.com").exists()

    def exists_on_bs_s3_storage(self):
        return self.storage_points.filter(storage_bs__endpoint="s3.backupsheep.com").exists()

    def exists_on_bs_aws_storage(self):
        return self.storage_points.filter(storage_bs__bucket_name="backupsheep-europe-frankfurt").exists()

    def exists_on_bs_google_cloud_storage(self):
        return self.storage_points.filter(storage_bs__bucket_name="backupsheep-eu").exists()

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
                queue=self.schedule.queue_name,
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
