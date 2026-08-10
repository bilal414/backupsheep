import humanfriendly
import pytz
from django.utils.dateparse import parse_datetime
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorage, CoreStorageType
from apps.api.v1.backup.serializers import (
    BackupExecutionStatusListSerializer,
    BackupExecutionStatusMixin,
    CoreBackupScheduleSerializer,
    CoreBackupStorageSerializer,
    SafeProviderMetadataMixin,
    RestoreExecutionStatusMixin,
)


class CoreDatabaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreDatabase
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "tables",
            "all_tables",
            "databases",
            "all_databases",
            "notes",
        )


class CoreDatabaseBackupStoragePointsSerializer(SafeProviderMetadataMixin, serializers.ModelSerializer):
    storage = CoreBackupStorageSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreDatabaseBackupStoragePoints
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()


class CoreDatabaseBackupSerializer(BackupExecutionStatusMixin, serializers.ModelSerializer):
    database = CoreDatabaseSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    size_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    schedule = CoreBackupScheduleSerializer()
    stored_backups = CoreDatabaseBackupStoragePointsSerializer(
        source="stored_database_backups", many=True, read_only=True
    )

    class Meta:
        model = CoreDatabaseBackup
        fields = "__all__"
        list_serializer_class = BackupExecutionStatusListSerializer
        datatables_always_serialize = (
            "id",
            "uuid",
            "name",
            "stored_backups",
            "execution_status",
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


class CoreDatabaseRestoreSerializer(RestoreExecutionStatusMixin, serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreDatabaseRestore
        fields = "__all__"

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
