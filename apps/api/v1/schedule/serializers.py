import json

import humanfriendly
import pytz
from celery.schedules import crontab_parser
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule, CoreScheduleRun
from apps.console.storage.models import CoreStorage
from croniter import croniter


class CoreAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreAccount
        fields = ("id", "name")


class CoreIntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreIntegration
        fields = (
            "id",
            "name",
            "code",
        )
        datatables_always_serialize = ("id",)


# class CoreScheduleSerializerAlt(serializers.Serializer):
#
#     class Meta:
#         model = CoreSchedule
#         fields = ("id",)


class CoreScheduleRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreScheduleRun
        fields = "__all__"

    def validate(self, data):
        schedule = data["schedule"]
        request_id = data["request_id"]
        if CoreScheduleRun.objects.filter(request_id=request_id, schedule=schedule).exists():
            raise serializers.ValidationError(
                f"Schedule run object already exist with request_id:{request_id} and schedule_id:{schedule.id}."
            )

        elif schedule.status != CoreSchedule.Status.ACTIVE:
            raise serializers.ValidationError(f"Schedule ID:{schedule.id} is not in ACTIVE status.")

        return data


class CoreConnectionLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreConnectionLocation
        fields = "__all__"
        datatables_always_serialize = ("id",)


class CoreConnectionSerializer(serializers.ModelSerializer):
    integration = CoreIntegrationSerializer(read_only=True)
    location = CoreConnectionLocationSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreConnection
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()


class CoreNodeSerializer(serializers.ModelSerializer):
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    account = serializers.HiddenField(default=CurrentAccountDefault())
    connection = CoreConnectionSerializer(read_only=True)

    class Meta:
        model = CoreNode
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()


class CoreDatabaseSerializer(serializers.ModelSerializer):
    node = CoreNodeSerializer(read_only=True)

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


class CoreScheduleStorageSerializer(serializers.ModelSerializer):
    name_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreStorage
        fields = "__all__"

    @staticmethod
    def get_name_display(obj):
        return f"{obj.type.name} - {obj.name}"


class AccountFilteredPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        request = self.context.get("request", None)
        queryset = super(AccountFilteredPrimaryKeyRelatedField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.filter(account=request.user.member.get_current_account())


class CoreScheduleSerializer(serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField(read_only=True)
    modified_display = serializers.SerializerMethodField(read_only=True)
    crontab_display = serializers.SerializerMethodField()
    storage_points = CoreScheduleStorageSerializer(many=True, read_only=True)
    storage_point_ids = AccountFilteredPrimaryKeyRelatedField(
        many=True, queryset=CoreStorage.objects.filter(), source="storage_points", required=False
    )

    class Meta:
        model = CoreSchedule
        fields = "__all__"

    def validate(self, data):
        if data["type"] == CoreSchedule.Type.CRON:
            cron_expression = (
                f"{data['minute']} {data['hour']} {data['day_of_month']} "
                f"{data['month_of_year']} {data['day_of_week']}"
            )
            if not croniter.is_valid(cron_expression):
                raise serializers.ValidationError(
                    "Invalid schedule configuration. Try changing cron values."
                )
            data['rate_value'] = None
            data['rate_unit'] = None
        elif data["type"] == CoreSchedule.Type.RATE:
            if not data.get('rate_value') or data['rate_value'] < 1:
                raise serializers.ValidationError(
                    "Invalid schedule configuration. Rate value must be a positive integer."
                )
            data['minute'] = None
            data['hour'] = None
            data['day_of_month'] = None
            data['month_of_year'] = None
            data['day_of_week'] = None
            data['year'] = None
        elif data["type"] == CoreSchedule.Type.ONETIME:
            if not data.get('onetime_datetime'):
                raise serializers.ValidationError(
                    "Invalid schedule configuration. A date and time is required."
                )
            data['rate_value'] = None
            data['rate_unit'] = None
            data['minute'] = None
            data['hour'] = None
            data['day_of_month'] = None
            data['month_of_year'] = None
            data['day_of_week'] = None
            data['year'] = None

        return data

    # @staticmethod
    # def validate_minute(data):
    #     try:
    #         crontab_parser(60).parse(data)
    #         if len(crontab_parser(60).parse(data)) > 12:
    #             raise serializers.ValidationError("Interval is too frequent. Use higher intervals.")
    #     except ValueError:
    #         raise serializers.ValidationError("Invalid value.")
    #     return data

    # @staticmethod
    # def validate_hour(data):
    #     try:
    #         crontab_parser(24).parse(data)
    #     except Exception as e:
    #         raise serializers.ValidationError("Invalid value.")
    #     return data
    #
    # @staticmethod
    # def validate_day_of_week(data):
    #     try:
    #         crontab_parser(7).parse(data)
    #     except Exception as e:
    #         raise serializers.ValidationError("Invalid value.")
    #     return data
    #
    # @staticmethod
    # def validate_day_of_month(data):
    #     try:
    #         crontab_parser(31, 1).parse(data)
    #     except Exception as e:
    #         raise serializers.ValidationError("Invalid value.")
    #     return data
    #
    # @staticmethod
    # def validate_month_of_year(data):
    #     try:
    #         crontab_parser(12, 1).parse(data)
    #     except Exception as e:
    #         raise serializers.ValidationError("Invalid value.")
    #     return data

    def validate_storage_point_ids(self, data):
        node = CoreNode.objects.get(id=self.initial_data.get("node"))
        if node.type == CoreNode.Type.DATABASE or node.type == CoreNode.Type.WEBSITE or node.type == CoreNode.Type.SAAS:
            if len(data) == 0:
                raise serializers.ValidationError("This field is required.")
        return data

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
    def get_storage_type_display(obj):
        return obj.get_storage_type_display()

    @staticmethod
    def get_crontab_display(obj):
        return f"{obj.minute} {obj.hour} {obj.day_of_month} {obj.month_of_year} {obj.day_of_week}"
