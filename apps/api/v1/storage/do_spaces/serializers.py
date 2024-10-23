import time
import boto3
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.api.v1.storage.serializers import CoreStorageTypeSerializer
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault, CurrentAccountDefault, StorageDefault, bs_encrypt, bs_decrypt,
)
from apps.console.backup.models import CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints
from apps.console.connection.models import CoreAWSRegion, CoreDoSpacesRegion
from apps.console.storage.models import CoreStorageDoSpaces, CoreStorage, CoreStorageType


class CoreDoSpacesRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreDoSpacesRegion
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreStorageDoSpacesReadSerializer(serializers.ModelSerializer):
    access_key = serializers.SerializerMethodField()
    secret_key = serializers.SerializerMethodField()
    region = CoreDoSpacesRegionSerializer()

    class Meta:
        model = CoreStorageDoSpaces
        fields = (
            "id",
            "no_delete",
            "region",
            "access_key",
            "secret_key",
            "bucket_name",
            "prefix",
        )
        datatables_always_serialize = (
            "id",
            "no_delete",
            "region",
            "access_key",
            "secret_key",
            "bucket_name",
            "prefix",
        )

    def get_access_key(self, obj):
        return bs_decrypt(obj.access_key, self.context["encryption_key"])

    def get_secret_key(self, obj):
        return bs_decrypt(obj.secret_key, self.context["encryption_key"])


class CoreStorageDoSpacesWriteSerializer(serializers.ModelSerializer):
    region = serializers.PrimaryKeyRelatedField(
        queryset=CoreDoSpacesRegion.objects.filter()
    )
    access_key = serializers.CharField(write_only=True)
    secret_key = serializers.CharField(write_only=True)
    bucket_name = serializers.CharField(write_only=True)
    no_delete = serializers.NullBooleanField(write_only=True, required=False)
    prefix = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True, default='')
    storage = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = CoreStorageDoSpaces
        fields = "__all__"

    def validate(self, data):
        try:
            storage = CoreStorageDoSpaces()

            if not storage.validate(data):
                raise ValueError("Please check bucket name and permissions.")

            # s3_client = boto3.client(
            #     "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            #     endpoint_url=f"https://{region.endpoint}",
            # )
            #
            # if data.get("prefix"):
            #     if (data.get("prefix") != "") and (data.get("prefix").endswith("/") is False):
            #         data["prefix"] += "/"
            #
            # filename = f"{data.get('prefix', '')}backupsheep_test_{int(time.time())}.txt"
            #
            # bucket_name = data["bucket_name"]
            #
            # result = s3_client.put_object(
            #     Body=filename, Bucket=bucket_name, Key=filename
            # )
            #
            # if not result.get("ETag"):
            #     raise serializers.ValidationError("Unable to connect.")
            #
            # s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)
            #
            # if not s3_object.get("ETag"):
            #     raise serializers.ValidationError("Unable to connect.")
            #
            # if not no_delete:
            #     s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            #
            #     if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
            #         raise serializers.ValidationError("Unable to connect.")

            data["access_key"] = bs_encrypt(data["access_key"], self.context["encryption_key"])
            data["secret_key"] = bs_encrypt(data["secret_key"], self.context["encryption_key"])
        except Exception as e:
            raise serializers.ValidationError(f"Unable to authenticate. {e.__str__()}")

        return data


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_do_spaces = CoreStorageDoSpacesReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()

    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage DigitalOcean Spaces Read"
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
    storage_do_spaces = CoreStorageDoSpacesWriteSerializer()
    type = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(StorageDefault("do_spaces"))
    )

    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage DigitalOcean Spaces Write"

    def create(self, validated_data):
        storage_do_spaces = validated_data.pop("storage_do_spaces", [])
        instance = CoreStorage.objects.create(**validated_data)
        storage_do_spaces["storage"] = instance
        CoreStorageDoSpaces.objects.create(**storage_do_spaces)
        return instance

    def update(self, instance, validated_data):
        storage_do_spaces = validated_data.pop("storage_do_spaces", [])
        super().update(instance.storage_do_spaces, storage_do_spaces)
        instance = super().update(instance, validated_data)
        return instance
