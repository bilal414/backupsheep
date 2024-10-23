import humanfriendly
import pytz
from django.utils.dateparse import parse_datetime
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.backup.models import (
    CoreWordPressBackup,
    CoreWordPressBackupStoragePoints,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreWordPress, CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorage, CoreStorageType
from apps.console.api.v1.backup.serializers import (
    CoreBackupScheduleSerializer,
    CoreBackupStorageSerializer,
)


class CoreWordPressSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreWordPress
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "notes",
        )


class CoreWordPressBackupStoragePointsSerializer(serializers.ModelSerializer):
    storage = CoreBackupStorageSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    show_request_download = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreWordPressBackupStoragePoints
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_show_request_download(obj):
        return (
            obj.storage.name == "Storage 01"
            or obj.storage.name == "Storage 02"
            or obj.storage.name == "Storage 03"
            or obj.storage.name == "Storage 04"
        ) and obj.storage.type.code == "bs"


class CoreWordPressBackupSerializer(serializers.ModelSerializer):
    wordpress = CoreWordPressSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    size_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    schedule = CoreBackupScheduleSerializer()
    stored_backups = CoreWordPressBackupStoragePointsSerializer(
        source="stored_wordpress_backups", many=True, read_only=True
    )

    class Meta:
        model = CoreWordPressBackup
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "uuid",
            "name",
            "stored_backups",
        )

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

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
    def get_size_display(obj):
        return humanfriendly.format_size(obj.size or 0)

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()
