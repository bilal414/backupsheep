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
from apps.api.v1.utils.api_permissions import permitted_nodes
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule, CoreScheduleRun
from apps.console.storage.models import CoreStorage
from croniter import croniter
from backupsheep.source_recovery_policy import require_source_backup_creation


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
        require_source_backup_creation(schedule.node.connection.integration.code)
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


class VisibleNodePrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """Only allow nodes covered by the member's schedule permission."""

    def get_queryset(self):
        request = self.context.get("request")
        queryset = super().get_queryset()
        if request is None or queryset is None:
            return None
        return permitted_nodes(request, "schedule_changes")


class CoreScheduleSerializer(serializers.ModelSerializer):
    node = VisibleNodePrimaryKeyRelatedField(queryset=CoreNode.objects.all())
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
        instance = self.instance
        schedule_type = data.get(
            "type", getattr(instance, "type", CoreSchedule.Type.CRON)
        )

        if schedule_type == CoreSchedule.Type.CRON:
            cron_expression = (
                f"{data.get('minute', getattr(instance, 'minute', None)) or '*'} "
                f"{data.get('hour', getattr(instance, 'hour', None)) or '*'} "
                f"{data.get('day_of_month', getattr(instance, 'day_of_month', None)) or '*'} "
                f"{data.get('month_of_year', getattr(instance, 'month_of_year', None)) or '*'} "
                f"{data.get('day_of_week', getattr(instance, 'day_of_week', None)) or '*'}"
            )
            if not croniter.is_valid(cron_expression):
                raise serializers.ValidationError(
                    "Invalid schedule configuration. Try changing cron values."
                )
            data['rate_value'] = None
            data['rate_unit'] = None
        elif schedule_type == CoreSchedule.Type.RATE:
            rate_value = data.get("rate_value", getattr(instance, "rate_value", None))
            if not rate_value or rate_value < 1:
                raise serializers.ValidationError(
                    "Invalid schedule configuration. Rate value must be a positive integer."
                )
            data['minute'] = None
            data['hour'] = None
            data['day_of_month'] = None
            data['month_of_year'] = None
            data['day_of_week'] = None
            data['year'] = None
        elif schedule_type == CoreSchedule.Type.ONETIME:
            if not data.get("at_datetime", getattr(instance, "at_datetime", None)):
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

        node = data.get("node", getattr(instance, "node", None))
        resulting_status = data.get(
            "status", getattr(instance, "status", CoreSchedule.Status.ACTIVE)
        )
        if node is not None and resulting_status == CoreSchedule.Status.ACTIVE:
            require_source_backup_creation(node.connection.integration.code)
        storage_points = data.get("storage_points")
        if storage_points is None:
            storage_points = instance.storage_points.all() if instance else []

        request = self.context.get("request")
        account = request.user.member.get_current_account() if request else None
        if account is not None and any(
            storage_point.account_id != account.id for storage_point in storage_points
        ):
            raise serializers.ValidationError(
                "Storage destinations must belong to the current account."
            )

        if node and node.type in (
            CoreNode.Type.DATABASE,
            CoreNode.Type.WEBSITE,
            CoreNode.Type.SAAS,
        ) and not storage_points:
            raise serializers.ValidationError(
                {"storage_point_ids": "This field is required."}
            )

        require_air_gapped_copy = data.get(
            "require_air_gapped_copy",
            getattr(instance, "require_air_gapped_copy", False),
        )
        if require_air_gapped_copy:
            if not storage_points or not any(
                storage_point.is_air_gapped for storage_point in storage_points
            ):
                raise serializers.ValidationError(
                    "An air-gapped copy policy requires at least one selected "
                    "air-gapped storage destination."
                )

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
