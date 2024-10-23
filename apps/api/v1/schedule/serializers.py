import json
import time

import boto3
import humanfriendly
import pytz
from botocore.exceptions import ClientError
from celery.schedules import crontab_parser
from django.utils.timezone import get_current_timezone
from rest_framework import serializers

from app_backupsheep_com import settings
from apps.console.account.models import CoreAccount
from apps.console.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule, CoreScheduleRun
from apps.console.storage.models import CoreStorage, CoreStorageDefault
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
        try:
            aws_scheduler = boto3.client(
                "scheduler",
                aws_access_key_id=settings.AWS_SCHEDULER_ACCESS_KEY,
                aws_secret_access_key=settings.AWS_SCHEDULER_SECRET_KEY,
                region_name="us-east-1"
            )

            schedule_settings = {
                "RoleArn": "arn:aws:iam::557987923879:role/bs-event-scheduler-lambda",
                "Arn": "arn:aws:lambda:us-east-1:557987923879:function:bsProdForwardCronToAPI",
            }

            schedule_expression = None
            if data["type"] == CoreSchedule.Type.CRON:
                schedule_expression = f"cron({data['minute']} {data['hour']} {data['day_of_month']} {data['month_of_year']} {data['day_of_week']} {data['year']})"
                data['rate_value'] = None
                data['rate_unit'] = None
            elif data["type"] == CoreSchedule.Type.RATE:
                schedule_expression = f"rate({data['rate_value']} {data['rate_unit']})"
                data['minute'] = None
                data['hour'] = None
                data['hour'] = None
                data['day_of_month'] = None
                data['month_of_year'] = None
                data['day_of_week'] = None
                data['year'] = None
            elif data["type"] == CoreSchedule.Type.ONETIME:
                schedule_expression = f"at({data['onetime_datetime']})"
                data['rate_value'] = None
                data['rate_unit'] = None
                data['minute'] = None
                data['hour'] = None
                data['hour'] = None
                data['day_of_month'] = None
                data['month_of_year'] = None
                data['day_of_week'] = None
                data['year'] = None

            schedule_name = f"validation_{int(time.time())}"
            aws_schedule = {
                "Name": schedule_name,
                "State": "ENABLED",
                "ScheduleExpression": schedule_expression,
                "ScheduleExpressionTimezone": data["timezone"],
                "Target": schedule_settings,
                "FlexibleTimeWindow": {"Mode": "OFF"},
            }

            aws_response = aws_scheduler.create_schedule(**aws_schedule)
            if aws_response.get("ScheduleArn"):
                aws_scheduler.delete_schedule(Name=schedule_name)

            return data

        except ClientError as err:
            error_msg = err.__str__().lower()

            if "invalid schedule expression" in error_msg and "cron" in error_msg:
                raise serializers.ValidationError("Invalid schedule configuration. "
                                                  "Try changing cron values or contact support.")

            elif "invalid schedule expression" in error_msg and "rate" in error_msg:
                raise serializers.ValidationError("Invalid schedule configuration. "
                                                  "Try changing rate values or contact support.")
            else:
                raise serializers.ValidationError(err.__str__())
        except Exception as e:
            raise serializers.ValidationError("Invalid schedule configuration. "
                                              "Try changing different values or contact support.")

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
