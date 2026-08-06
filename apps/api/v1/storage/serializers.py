import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.api.v1.account.serializers import CoreAccountSerializer
from apps.console.storage.models import CoreStorage, CoreStorageType


class CoreStorageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageType
        fields = "__all__"
        ref_name = "Storage Type"


class CoreStorageSerializer(serializers.ModelSerializer):
    type = CoreStorageTypeSerializer(read_only=True)
    account = CoreAccountSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorage
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_created_display(obj):
        timezone = pytz.timezone(str(get_current_timezone()))
        return obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")

    @staticmethod
    def get_modified_display(obj):
        timezone = pytz.timezone(str(get_current_timezone()))
        return obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
