import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.storage.models import CoreStorage


class CoreStorageSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    name_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorage
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "name",
        )

    @staticmethod
    def get_name_display(obj):
        return f"{obj.type.name} - {obj.name}"

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