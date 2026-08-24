import pytz
from django.db import transaction
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from sentry_sdk import capture_exception

from apps.api.v1.storage.serializers import CoreStorageTypeSerializer
from apps.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault, StorageDefault,
)
from apps.console.backup.models import CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints
from apps.console.storage.models import CoreStorageLocal, CoreStorage


class CoreStorageLocalReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageLocal
        fields = (
            "id",
            "path",
            "no_delete",
        )
        datatables_always_serialize = (
            "id",
            "path",
            "no_delete",
        )


class CoreStorageLocalWriteSerializer(serializers.ModelSerializer):
    path = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True, default='')
    no_delete = serializers.BooleanField(allow_null=True, write_only=True, required=False)
    storage = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreStorageLocal
        fields = "__all__"

    def validate(self, data):
        try:
            if not CoreStorageLocal.validate_configuration(data):
                raise ValueError("Please check the path and permissions.")
        except Exception:
            raise serializers.ValidationError("Unable to validate local storage. Verify the path and permissions.")
        return data


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_local = CoreStorageLocalReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()


    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage Local Read"
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
    storage_local = CoreStorageLocalWriteSerializer()
    type = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(StorageDefault("local"))
    )

    class Meta:
        model = CoreStorage
        ref_name = "Storage Local Write"
        fields = "__all__"

    @staticmethod
    def _queue_validation(storage_id):
        """Publish only the persisted row id after the transaction commits.

        A broker outage leaves the row truthfully PENDING; the periodic storage
        worker sweep republishes it.  Paths never cross the broker boundary.
        """

        def publish():
            try:
                from apps._tasks.integration.storage.tasks import validate_local_storage

                validate_local_storage.apply_async(args=[storage_id])
            except Exception as error:
                capture_exception(error)

        transaction.on_commit(publish)

    @transaction.atomic
    def create(self, validated_data):
        storage_local = validated_data.pop("storage_local", {})
        validated_data["status"] = CoreStorage.Status.PENDING
        instance = CoreStorage.objects.create(**validated_data)
        storage_local["storage"] = instance
        CoreStorageLocal.objects.create(**storage_local)
        self._queue_validation(instance.pk)
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        storage_local = validated_data.pop("storage_local", {})
        validated_data["status"] = CoreStorage.Status.PENDING
        if storage_local:
            super().update(instance.storage_local, storage_local)
        instance = super().update(instance, validated_data)
        self._queue_validation(instance.pk)
        return instance
