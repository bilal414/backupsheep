import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.backup.models import (
    CoreDigitalOceanBackup,
)
from apps.console.node.models import CoreDigitalOcean, CoreNode, CoreSchedule
from apps.console.api.v1.backup.serializers import CoreBackupScheduleSerializer


class CoreDigitalOceanSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreDigitalOcean
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "notes",
        )


class CoreDigitalOceanBackupSerializer(serializers.ModelSerializer):
    website = CoreDigitalOceanSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    schedule = CoreBackupScheduleSerializer()

    class Meta:
        model = CoreDigitalOceanBackup
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "uuid",
            "name",
            "size_gigabytes",
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
    def get_type_display(obj):
        return obj.get_type_display()
