import pytz
import requests
import telegram
from django.conf import settings
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.api.v1.utils.api_helpers import (
    CurrentMemberDefault,
    CurrentAccountDefault,
)
from apps.console.notification.models import (
    CoreNotificationSlack,
    CoreNotificationTelegram, CoreNotificationEmail,
)
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup


class CoreNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreNode
        fields = "__all__"


class CoreNotificationSlackSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreNotificationSlack
        fields = "__all__"

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


class CoreNotificationTelegramSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    channel_name = serializers.CharField(
        required=True, allow_null=False, allow_blank=False
    )
    chat_id = serializers.CharField(required=True, allow_null=False, allow_blank=False)

    class Meta:
        model = CoreNotificationTelegram
        fields = "__all__"

    def validate(self, data):
        chat_id = data.get("chat_id")
        result = requests.get(
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_KEY}/sendMessage?"
            f"chat_id={chat_id}"
            f"&text=Hey! This is validation message that your Telegram integration is working fine.",
            headers={"content-type": "application/json"},
            verify=True,
        )
        if result.status_code != 200:
            raise serializers.ValidationError({"chat_id": result.json().get("description")})
        return data

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


class CoreNotificationEmailSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    email = serializers.EmailField(required=True, allow_null=False, allow_blank=False)

    class Meta:
        model = CoreNotificationEmail
        fields = "__all__"

    def validate(self, data):
        chat_id = data.get("chat_id")
        result = requests.get(
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_KEY}/sendMessage?"
            f"chat_id={chat_id}"
            f"&text=Hey! This is validation message that your Telegram integration is working fine.",
            headers={"content-type": "application/json"},
            verify=True,
        )
        if result.status_code != 200:
            raise serializers.ValidationError({"chat_id": result.json().get("description")})
        return data

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
