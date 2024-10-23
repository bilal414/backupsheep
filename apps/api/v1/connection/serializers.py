import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
    CoreAWSRegion,
)
from apps.console.api.v1.account.serializers import CoreAccountSerializer


class CoreAWSRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreAWSRegion
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreIntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreIntegration
        fields = (
            "id",
            "name",
            "code",
        )
        datatables_always_serialize = ("id",)


class CoreConnectionLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreConnectionLocation
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreConnectionSerializer(serializers.ModelSerializer):
    account = CoreAccountSerializer(read_only=True)
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreConnection
        fields = "__all__"
        datatables_always_serialize = ("id",)

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_timezone(obj):
        return str(get_current_timezone())

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
