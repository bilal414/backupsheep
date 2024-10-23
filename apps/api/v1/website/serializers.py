import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.console.api.v1.connection.serializers import CoreConnectionSerializer
from apps.console.api.v1.node.serializers import CoreNodeReadSerializer, CoreWebsiteNodeWriteSerializer
from apps.console.api.v1.utils.api_helpers import CurrentAccountDefault, CurrentMemberDefault, check_path_overlap
from apps.console.connection.models import CoreConnection, CoreIntegration, CoreConnectionLocation
from apps.console.node.models import CoreNode, CoreWebsite, CoreSchedule
from apps.console.utils.models import UtilBackup


class CoreWebsiteReadSerializer(serializers.ModelSerializer):
    node = CoreNodeReadSerializer(read_only=True)
    totals = serializers.SerializerMethodField()

    class Meta:
        model = CoreWebsite
        fields = "__all__"
        datatables_always_serialize = ("id", "paths", "excludes", "parallel", "all_paths", "notes")

    @staticmethod
    def get_totals(obj):
        totals = {
            "backups": obj.backups.filter(status=UtilBackup.Status.COMPLETE).count(),
            "schedules": CoreSchedule.objects.filter(node=obj.node, status=CoreSchedule.Status.ACTIVE).count(),
        }
        return totals


class CoreWebsiteWriteSerializer(serializers.ModelSerializer):
    node = CoreWebsiteNodeWriteSerializer()

    class Meta:
        model = CoreWebsite
        fields = "__all__"

    def validate(self, data):
        tar_temp_backup_dir = data.get("tar_temp_backup_dir")
        backup_type = data.get("backup_type")

        if data["node"]["connection"].incremental_backup_available:
            if backup_type == 2 or backup_type == 3 or backup_type == 4:
                if tar_temp_backup_dir:
                    sources = []

                    for path in data["paths"]:
                        sources.append(path["path"])

                    if tar_temp_backup_dir.endswith('/'):
                        raise serializers.ValidationError(
                            {
                                "tar_temp_backup_dir": "Directory path must not end with /"
                            }
                        )
                    for source in sources:
                        if not source.endswith('/'):
                            temp_source = source.replace("//", "/") + "/"
                        if f"{tar_temp_backup_dir}/".startswith(temp_source):
                            raise serializers.ValidationError(
                                {
                                    "tar_temp_backup_dir": f"Your backup directory cannot be inside the directory you"
                                                           f" want to backup {temp_source}"
                                    # "tar_temp_backup_dir": f"Your temporary backup path is overlapping with backup path {source}"
                                }
                            )
                else:
                    # return Response(
                    #     {"detail": "Validation failed. Backups will fail. Check integration details immediately."},
                    #     status=status.HTTP_400_BAD_REQUEST)

                    raise serializers.ValidationError(
                        {
                            "tar_temp_backup_dir": "Specify a directory where we can store the temporary backup archive."
                            " It must be outside any paths you wish to include in the backup."
                        }
                    )
        return data

    def create(self, validated_data):
        node = validated_data.pop("node", [])
        validated_data["node"] = CoreNode.objects.create(**node)
        instance = CoreWebsite.objects.create(**validated_data)
        return instance

    def update(self, instance, validated_data):
        node = validated_data.pop("node", [])
        super().update(instance.node, node)
        # We don't allow change of backup type on node.
        validated_data.pop("backup_type")
        instance = super().update(instance, validated_data)
        return instance
