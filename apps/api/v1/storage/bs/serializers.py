import time
import boto3
import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.api.v1.storage.serializers import CoreStorageTypeSerializer
from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
    StorageDefault,
    bs_encrypt,
    bs_decrypt,
)
from apps.console.backup.models import (
    CoreWebsiteBackupStoragePoints,
    CoreDatabaseBackupStoragePoints,
)
from apps.console.storage.models import CoreStorageBS, CoreStorage


class CoreStorageBSReadSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    password = serializers.SerializerMethodField()
    port = serializers.SerializerMethodField()
    secret_key = serializers.SerializerMethodField()
    access_key = serializers.SerializerMethodField()
    endpoint_alt = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorageBS
        fields = (
            "id",
            "username",
            "password",
            "host",
            "port",
            "bucket_name",
            "prefix",
            "endpoint",
            "endpoint_alt",
            "region",
            "secret_key",
            "access_key",
        )


    def get_port(self, obj):
        return 21

    def get_username(self, obj):
        return bs_decrypt(obj.username, self.context["encryption_key"])

    def get_password(self, obj):
        return bs_decrypt(obj.password, self.context["encryption_key"])

    def get_secret_key(self, obj):
        return bs_decrypt(obj.secret_key, self.context["encryption_key"])

    def get_access_key(self, obj):
        return bs_decrypt(obj.access_key, self.context["encryption_key"])

    def get_endpoint_alt(self, obj):
        if obj.endpoint:
            return f"https://{obj.endpoint}"


class CoreStorageReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    storage_bs = CoreStorageBSReadSerializer()
    total_website = serializers.SerializerMethodField()
    total_database = serializers.SerializerMethodField()
    type = CoreStorageTypeSerializer()

    class Meta:
        model = CoreStorage
        fields = "__all__"
        ref_name = "Storage BackupSheep Read"
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
