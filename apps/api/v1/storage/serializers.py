from rest_framework import serializers
from apps.console.storage.models import CoreStorage, CoreStorageType, CoreStorageStatus


class CoreStorageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreStorageType
        fields = "__all__"
        ref_name = "Storage Type"


class CoreStorageSerializer(serializers.ModelSerializer):
    type = CoreStorageTypeSerializer(read_only=True)

    class Meta:
        model = CoreStorage
        fields = "__all__"
