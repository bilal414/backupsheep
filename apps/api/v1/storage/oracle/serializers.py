import re

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
    CurrentAccountDefault,
    StorageDefault,
    bs_encrypt,
)
from apps.console.backup.models import CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints
from apps.console.connection.models import CoreOracleRegion
from apps.console.storage.models import CoreStorage, CoreStorageOracle
from apps._tasks.integration.storage.oracle import oracle_object_endpoint


_SAFE_BUCKET = re.compile(r"[^/\\\x00-\x1f\x7f]{1,1024}\Z")


class CoreOracleRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreOracleRegion
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreStorageOracleReadSerializer(StorageCredentialReadSerializerMixin, serializers.ModelSerializer):
    credential_fields = ("access_key", "secret_key")
    region = CoreOracleRegionSerializer()

    class Meta:
        model = CoreStorageOracle
        fields = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "namespace",
            "region",
            "prefix",
        )
        datatables_always_serialize = (
            "id",
            "no_delete",
            "access_key",
            "secret_key",
            "bucket_name",
            "namespace",
            "region",
            "prefix",
        )

class CoreStorageOracleWriteSerializer(StorageCredentialWriteSerializerMixin, serializers.ModelSerializer):
    credential_fields = ("access_key", "secret_key")
    access_key = serializers.CharField(write_only=True)
    secret_key = serializers.CharField(write_only=True)
    bucket_name = serializers.CharField(write_only=True)
    namespace = serializers.CharField(write_only=True)
    no_delete = serializers.BooleanField(allow_null=True, write_only=True, required=False)
    prefix = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True, default='')
    storage = serializers.PrimaryKeyRelatedField(read_only=True)
    region = serializers.PrimaryKeyRelatedField(
        queryset=CoreOracleRegion.objects.filter(), required=True, allow_null=False
    )

    class Meta:
        model = CoreStorageOracle
        fields = "__all__"

    def validate(self, data):
        try:
            namespace = data.get("namespace")
            region = data.get("region")
            bucket_name = str(data.get("bucket_name") or "").strip()
            prefix = data.get("prefix") or ""
            oracle_object_endpoint(namespace, getattr(region, "code", None))
            if not _SAFE_BUCKET.fullmatch(bucket_name):
                raise ValueError("The bucket name is invalid.")
            if any(ord(character) < 32 or ord(character) == 127 for character in prefix):
                raise ValueError("The object prefix is invalid.")
            data["bucket_name"] = bucket_name
            storage = CoreStorageOracle()
            if not storage.validate(data):
                raise ValueError("Please check bucket name and permissions.")
            data["access_key"] = bs_encrypt(data["access_key"], self.context["encryption_key"])
            data["secret_key"] = bs_encrypt(data["secret_key"], self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError("Unable to authenticate with the storage provider. Verify the credentials and configuration.")
        return data


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_oracle = CoreStorageOracleReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()

    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage Oracle Read"
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
    storage_oracle = CoreStorageOracleWriteSerializer()
    type = serializers.HiddenField(default=serializers.CreateOnlyDefault(StorageDefault("oracle")))

    class Meta:
        model = CoreStorage
        ref_name = "Storage Oracle Write"
        fields = "__all__"

    @transaction.atomic
    def create(self, validated_data):
        storage_oracle = validated_data.pop("storage_oracle", [])
        instance = CoreStorage.objects.create(**validated_data)
        storage_oracle["storage"] = instance
        CoreStorageOracle.objects.create(**storage_oracle)
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        storage_oracle = validated_data.pop("storage_oracle", None)
        if storage_oracle is not None:
            super().update(instance.storage_oracle, storage_oracle)
        instance = super().update(instance, validated_data)
        return instance
