import time
import boto3
import pytz
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.storage.serializers import (
    CoreStorageTypeSerializer,
    StorageCredentialReadSerializerMixin,
    StorageCredentialWriteSerializerMixin,
)
from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, StorageDefault, bs_encrypt,
)
from apps._tasks.helper.maintenance import storage_aws_s3_sync_lifecycle
from apps.console.backup.models import CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints
from apps.console.connection.models import CoreAWSRegion
from apps.console.storage.models import CoreStorageAWSS3, CoreStorage, CoreStorageType


class CoreAWSRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreAWSRegion
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreStorageAWSS3ReadSerializer(StorageCredentialReadSerializerMixin, serializers.ModelSerializer):
    credential_fields = ("access_key", "secret_key")
    region = CoreAWSRegionSerializer()

    class Meta:
        model = CoreStorageAWSS3
        fields = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "region",
            "prefix",
            "object_lock_mode",
            "object_lock_retain_days",
            "expected_bucket_owner",
            "lifecycle_transition_days",
            "lifecycle_storage_class",
            "lifecycle_last_synced_at",
        )
        datatables_always_serialize = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "region",
            "prefix",
            "object_lock_mode",
            "object_lock_retain_days",
            "expected_bucket_owner",
            "lifecycle_transition_days",
            "lifecycle_storage_class",
            "lifecycle_last_synced_at",
        )

class CoreStorageAWSS3WriteSerializer(StorageCredentialWriteSerializerMixin, serializers.ModelSerializer):
    credential_fields = ("access_key", "secret_key")
    access_key = serializers.CharField(write_only=True)
    secret_key = serializers.CharField(write_only=True)
    bucket_name = serializers.CharField(write_only=True)
    no_delete = serializers.BooleanField(allow_null=True, write_only=True, required=False)
    prefix = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True, default='')
    storage = serializers.PrimaryKeyRelatedField(read_only=True)
    region = serializers.PrimaryKeyRelatedField(
        queryset=CoreAWSRegion.objects.filter(), required=True, allow_null=False
    )

    class Meta:
        model = CoreStorageAWSS3
        fields = "__all__"

    def validate(self, data):
        try:
            settings_data = {
                "object_lock_mode": data.get(
                    "object_lock_mode",
                    getattr(self.instance, "object_lock_mode", ""),
                ),
                "object_lock_retain_days": data.get(
                    "object_lock_retain_days",
                    getattr(self.instance, "object_lock_retain_days", None),
                ),
                "expected_bucket_owner": data.get(
                    "expected_bucket_owner",
                    getattr(self.instance, "expected_bucket_owner", ""),
                ),
                "lifecycle_transition_days": data.get(
                    "lifecycle_transition_days",
                    getattr(self.instance, "lifecycle_transition_days", None),
                ),
                "lifecycle_storage_class": data.get(
                    "lifecycle_storage_class",
                    getattr(self.instance, "lifecycle_storage_class", ""),
                ),
                "prefix": data.get("prefix", getattr(self.instance, "prefix", "")),
            }
            CoreStorageAWSS3.validate_immutability_settings(settings_data)
            validation_data = dict(data)
            for field_name, value in settings_data.items():
                validation_data.setdefault(field_name, value)
            if self.instance:
                validation_data.setdefault("no_delete", self.instance.no_delete)
            storage = CoreStorageAWSS3()
            if not storage.validate(validation_data):
                raise ValueError("Please check bucket name and permissions.")

            data["access_key"] = bs_encrypt(data["access_key"], self.context["encryption_key"])
            data["secret_key"] = bs_encrypt(data["secret_key"], self.context["encryption_key"])
        except ValueError as e:
            # Configuration problems (Object Lock / lifecycle settings, or a failed
            # bucket permission probe) are client errors: surface them as a 400 with
            # the real reason instead of an unhandled 500.
            raise serializers.ValidationError(str(e))
        except Exception as e:
            raise serializers.ValidationError("Unable to authenticate with the storage provider. Verify the credentials and configuration.")
        return data


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_aws_s3 = CoreStorageAWSS3ReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()


    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage AWS S3 Read"
        datatables_always_serialize = (
            "id",
            "name",
        )

    @staticmethod
    def get_created_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_modified_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_total_website(obj):
        total_website = CoreWebsiteBackupStoragePoints.objects.filter(
            storage=obj, status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE
        ).count()
        return total_website

    @staticmethod
    def get_total_database(obj):
        total_database = CoreDatabaseBackupStoragePoints.objects.filter(
            storage=obj, status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE
        ).count()
        return total_database


class CoreStorageWriteSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault())
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    storage_aws_s3 = CoreStorageAWSS3WriteSerializer()
    type = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(StorageDefault("aws_s3"))
    )

    class Meta:
        model = CoreStorage
        ref_name = "Storage AWS S3 Write"
        fields = "__all__"

    def validate(self, data):
        data = super().validate(data)
        aws_s3 = data.get("storage_aws_s3") or {}
        existing_aws_s3 = getattr(self.instance, "storage_aws_s3", None)
        is_air_gapped = data.get(
            "is_air_gapped", getattr(self.instance, "is_air_gapped", False)
        )
        if is_air_gapped:
            object_lock_mode = aws_s3.get(
                "object_lock_mode",
                getattr(existing_aws_s3, "object_lock_mode", ""),
            )
            retain_days = aws_s3.get(
                "object_lock_retain_days",
                getattr(existing_aws_s3, "object_lock_retain_days", None),
            )
            expected_bucket_owner = aws_s3.get(
                "expected_bucket_owner",
                getattr(existing_aws_s3, "expected_bucket_owner", ""),
            )
            if object_lock_mode != CoreStorageAWSS3.ObjectLockMode.COMPLIANCE or not retain_days:
                raise serializers.ValidationError(
                    "An air-gapped copy requires S3 Object Lock in Compliance mode "
                    "with a retention period."
                )
            if not expected_bucket_owner:
                raise serializers.ValidationError(
                    "An air-gapped copy requires the expected AWS bucket owner account ID."
                )
            aws_s3["no_delete"] = True
            data["storage_aws_s3"] = aws_s3
        return data

    @staticmethod
    def _queue_lifecycle_sync(storage_aws_s3, submitted_data):
        """Dispatch the S3 lifecycle sync after the transaction commits.

        The sync is an AWS API call, so it must not run inside the request's DB
        transaction (a slow S3 response would hold the transaction open and can time
        out the request). The Celery task re-reads the row and applies the rule.
        """
        lifecycle_fields = {"lifecycle_transition_days", "lifecycle_storage_class"}
        should_sync = bool(
            storage_aws_s3.lifecycle_is_configured()
            or storage_aws_s3.lifecycle_last_synced_at
            or lifecycle_fields.intersection(submitted_data.keys())
        )
        if should_sync:
            transaction.on_commit(
                lambda: storage_aws_s3_sync_lifecycle.apply_async(
                    args=[storage_aws_s3.id]
                )
            )

    def create(self, validated_data):
        storage_aws_s3 = validated_data.pop("storage_aws_s3", [])
        with transaction.atomic():
            instance = CoreStorage.objects.create(**validated_data)
            storage_aws_s3["storage"] = instance
            aws_s3 = CoreStorageAWSS3.objects.create(**storage_aws_s3)
            self._queue_lifecycle_sync(aws_s3, storage_aws_s3)
        return instance

    def update(self, instance, validated_data):
        storage_aws_s3 = validated_data.pop("storage_aws_s3", [])
        with transaction.atomic():
            aws_s3 = super().update(instance.storage_aws_s3, storage_aws_s3)
            instance = super().update(instance, validated_data)
            self._queue_lifecycle_sync(aws_s3, storage_aws_s3)
        return instance
