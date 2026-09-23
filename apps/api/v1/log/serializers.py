import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup
from backupsheep.sentry_security import scrub_sensitive_value


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
        # Legacy CoreLog.data is nullable and historically accepted arbitrary
        # JSON shapes. The API exposes only a mapping and always returns a fresh,
        # recursively redacted structure so serialization cannot mutate the row.
        source = CoreLog.safe_data(obj)
        data = scrub_sensitive_value(source)
        if not isinstance(data, dict):
            return {}

        notes = data.get("notes")
        if isinstance(notes, int) and not isinstance(notes, bool):
            try:
                data["notes"] = UtilBackup.Status(notes).name.title().replace(
                    "_", " "
                )
            except ValueError:
                # Unknown historical status values are nonsecret compatibility
                # data; preserve them rather than failing the whole endpoint.
                pass
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
