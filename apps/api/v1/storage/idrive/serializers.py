import time
import boto3
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.api.v1.storage.serializers import CoreStorageTypeSerializer
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    StorageDefault, bs_encrypt, bs_decrypt,
)
from apps.console.backup.models import (
    CoreWebsiteBackupStoragePoints,
    CoreDatabaseBackupStoragePoints,
)
from apps.console.storage.models import CoreStorageIDrive, CoreStorage


class CoreStorageIDriveReadSerializer(serializers.ModelSerializer):
    access_key = serializers.SerializerMethodField()
    secret_key = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorageIDrive
        fields = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "endpoint",
            "prefix",
        )
        datatables_always_serialize = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "endpoint",
            "prefix",
        )

    def get_access_key(self, obj):
        return bs_decrypt(obj.access_key, self.context["encryption_key"])

    def get_secret_key(self, obj):
        return bs_decrypt(obj.secret_key, self.context["encryption_key"])


class CoreStorageIDriveWriteSerializer(serializers.ModelSerializer):
    access_key = serializers.CharField(write_only=True)
    secret_key = serializers.CharField(write_only=True)
    bucket_name = serializers.CharField(write_only=True)
    no_delete = serializers.NullBooleanField(write_only=True, required=False)
    prefix = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True, default='')
    endpoint = serializers.CharField(write_only=True)
    storage = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreStorageIDrive
        fields = "__all__"

    def validate(self, data):
        try:
            storage = CoreStorageIDrive()
            if not storage.validate(data):
                raise ValueError("Please check bucket name and permissions.")

            data["access_key"] = bs_encrypt(data["access_key"], self.context["encryption_key"])
            data["secret_key"] = bs_encrypt(data["secret_key"], self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(f"Unable to authenticate. {e.__str__()}")

        return data


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_idrive = CoreStorageIDriveReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()

    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage UpCloud Read"
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
    storage_idrive = CoreStorageIDriveWriteSerializer()
    type = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(StorageDefault("idrive"))
    )

    class Meta:
        model = CoreStorage
        ref_name = "Storage UpCloud Write"
        fields = "__all__"

    def create(self, validated_data):
        storage_idrive = validated_data.pop("storage_idrive", [])
        instance = CoreStorage.objects.create(**validated_data)
        storage_idrive["storage"] = instance
        CoreStorageIDrive.objects.create(**storage_idrive)
        return instance

    def update(self, instance, validated_data):
        storage_idrive = validated_data.pop("storage_idrive", [])
        super().update(instance.storage_idrive, storage_idrive)
        instance = super().update(instance, validated_data)
        return instance
