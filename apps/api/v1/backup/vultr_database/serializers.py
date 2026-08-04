import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.api.v1.backup.serializers import CoreBackupScheduleSerializer
from apps.console.backup.models import CoreVultrDatabaseBackup
from apps.console.node.models import CoreVultrDatabase


class CoreVultrDatabaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreVultrDatabase
        fields = "__all__"


class CoreVultrDatabaseBackupSerializer(serializers.ModelSerializer):
    vultr_database = CoreVultrDatabaseSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    schedule = CoreBackupScheduleSerializer()

    class Meta:
        model = CoreVultrDatabaseBackup
        fields = "__all__"
        datatables_always_serialize = ("id", "uuid", "name", "provider_status")

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def _format_date(value):
        timezone = pytz.timezone(str(get_current_timezone()))
        return value.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")

    def get_created_display(self, obj):
        return self._format_date(obj.created)

    def get_modified_display(self, obj):
        return self._format_date(obj.modified)

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()
