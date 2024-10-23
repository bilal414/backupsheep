import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup


class CoreNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreLogSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    data = serializers.SerializerMethodField()

    class Meta:
        model = CoreLog
        fields = "__all__"
        datatables_always_serialize = ("id", "data", "node",)

    @staticmethod
    def get_data(obj):
        if obj.data.get("notes"):
            if isinstance(obj.data.get("notes"), int):
                obj.data["notes"] = UtilBackup.Status(obj.data.get("notes")).name.title().replace("_", " ")
        return obj.data

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
