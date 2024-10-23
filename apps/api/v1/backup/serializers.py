from rest_framework import serializers
from apps.console.node.models import CoreWebsite, CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorageType, CoreStorage


class CoreBackupScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreSchedule
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "notes",
        )


class CoreStorageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageType
        fields = "__all__"


class CoreBackupStorageSerializer(serializers.ModelSerializer):
    type = CoreStorageTypeSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreStorage
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()