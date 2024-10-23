import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.console.api.v1.node.serializers import CoreNodeReadSerializer, CoreDatabaseNodeWriteSerializer
from apps.console.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.backup.models import CoreDatabaseBackup
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup, UtilPostgreSQLOptions


class CoreDatabaseReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreDatabase
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "tables",
            "all_tables",
            "databases",
            "all_databases",
            "totals",
            "notes",
        )

    @staticmethod
    def get_totals(obj):
        totals = {
            "backups": obj.backups.filter(status=UtilBackup.Status.COMPLETE).count(),
            "schedules": CoreSchedule.objects.filter(node=obj.node, status=CoreSchedule.Status.ACTIVE).count(),
        }
        return totals


class CoreDatabaseWriteSerializer(serializers.ModelSerializer):
    node = CoreDatabaseNodeWriteSerializer()

    class Meta:
        model = CoreDatabase
        fields = "__all__"

    def create(self, validated_data):
        node = validated_data.pop("node", [])
        validated_data["node"] = CoreNode.objects.create(**node)
        instance = CoreDatabase.objects.create(**validated_data)
        return instance

    def update(self, instance, validated_data):
        node = validated_data.pop("node", [])
        super().update(instance.node, node)
        instance = super().update(instance, validated_data)
        return instance

    def validate(self, data):
        errors = {}
        if data.get("option_postgres"):
            option_postgres_list = data.get("option_postgres").split(" ")
            for option_postgres in option_postgres_list:
                option_postgres = option_postgres.strip()

                errors["option_postgres"] = [
                    f"Invalid pg_dump option {option_postgres}. You can only used allowed options. "
                    f"Learn more: https://support.backupsheep.com/docs/postgresql-pg_dump-options"
                ]

                # Max allowed string size
                if len(option_postgres) > 512:
                    errors["option_postgres"] = [
                        f"Option {option_postgres} length is more than allowed limit. The length of any single option "
                        f"must be less than 512 characters. "
                        f"You can add same option multiple times."
                    ]
                    raise serializers.ValidationError(errors)

                # We have to do special checks for left right side.
                if "=" in option_postgres:
                    left_n_right = option_postgres.split("=")

                    # Check if we have both left and right side.
                    if len(left_n_right) == 2:
                        left = left_n_right[0]
                        right = left_n_right[1]

                        # Check if right side is alpha-numeric only and nothing funny is added.
                        if (
                            UtilPostgreSQLOptions.objects.filter(
                                name__istartswith=f"{left}=", type=UtilPostgreSQLOptions.Type.VALUE
                            ).exists()
                            and not right.isalnum()
                        ):
                            raise serializers.ValidationError(errors)

                        # Check if left side starts with
                        if (
                            not UtilPostgreSQLOptions.objects.filter(
                                name__istartswith=f"{left}=", type=UtilPostgreSQLOptions.Type.VALUE
                            ).exists()
                            and not UtilPostgreSQLOptions.objects.filter(
                                name__istartswith=f"{left}=", type=UtilPostgreSQLOptions.Type.PATTERN
                            ).exists()
                        ):
                            raise serializers.ValidationError(errors)
                    else:
                        raise serializers.ValidationError(errors)
                # Checks for flag type options.
                else:
                    if not UtilPostgreSQLOptions.objects.filter(
                        name__iexact=option_postgres, type=UtilPostgreSQLOptions.Type.FLAG
                    ):
                        raise serializers.ValidationError(errors)
        return data
