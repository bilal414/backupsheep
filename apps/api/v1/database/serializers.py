import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.node.serializers import CoreNodeReadSerializer, CoreDatabaseNodeWriteSerializer
from apps.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.backup.models import CoreDatabaseBackup
from apps.console.connection.models import (
    CoreAuthDatabase,
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
            "backups": obj.backups.filter(status__in=UtilBackup.SUCCESS_STATUSES).count(),
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
        node = validated_data.pop("node", None)
        if node is not None:
            super().update(instance.node, node)
        instance = super().update(instance, validated_data)
        return instance

    def _effective_selection_value(self, data, field):
        if field in data:
            return data[field]
        if self.instance is not None:
            return getattr(self.instance, field, None)
        return None

    def _selection_connection(self, data):
        node = data.get("node")
        if node is not None:
            connection = node.get("connection")
            if connection is not None:
                return connection
        if self.instance is not None:
            return self.instance.node.connection
        return None

    def _validate_selection(self, data):
        """Require one internally consistent selection for the connection mode."""
        errors = {}
        values = {
            field: self._effective_selection_value(data, field)
            for field in ("all_tables", "tables", "all_databases", "databases")
        }

        for field in ("tables", "databases"):
            selected = values[field]
            if selected is not None and not isinstance(selected, list):
                errors[field] = ["Selections must be provided as a list."]
            elif selected and any(
                not isinstance(item, str) or not item.strip() for item in selected
            ):
                errors[field] = ["Selections must contain non-empty names."]
        if errors:
            raise serializers.ValidationError(errors)

        all_tables = bool(values["all_tables"])
        all_databases = bool(values["all_databases"])
        has_tables = bool(values["tables"])
        has_databases = bool(values["databases"])

        if all_tables and has_tables:
            errors["tables"] = [
                "Clear the explicit table list when Backup All Tables is enabled."
            ]
        if all_databases and has_databases:
            errors["databases"] = [
                "Clear the explicit database list when Backup All Databases is enabled."
            ]
        if (all_tables or has_tables) and (all_databases or has_databases):
            errors["all_databases"] = [
                "Table selection and database selection cannot be combined."
            ]
        if errors:
            raise serializers.ValidationError(errors)

        connection = self._selection_connection(data)
        try:
            auth = connection.auth_database
        except (AttributeError, CoreAuthDatabase.DoesNotExist):
            raise serializers.ValidationError(
                {"node": ["Select a valid database connection before choosing objects."]}
            ) from None

        bound_to_database = bool(str(auth.database_name or "").strip())
        spans_databases = bool(auth.all_databases)
        if bound_to_database == spans_databases:
            raise serializers.ValidationError(
                {"node": ["The database connection has an invalid selection mode."]}
            )

        if bound_to_database:
            if all_databases or has_databases:
                errors["all_databases"] = [
                    "This connection is bound to one database; select tables instead."
                ]
            if not all_tables and not has_tables:
                errors["all_tables"] = [
                    "Enable Backup All Tables or select at least one table."
                ]
        else:
            if all_tables or has_tables:
                errors["all_tables"] = [
                    "This connection spans databases; select databases instead."
                ]
            if not all_databases and not has_databases:
                errors["all_databases"] = [
                    "Enable Backup All Databases or select at least one database."
                ]
        if errors:
            raise serializers.ValidationError(errors)

    def validate(self, data):
        self._validate_selection(data)
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
