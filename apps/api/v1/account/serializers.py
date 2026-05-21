from rest_framework import serializers

from apps.console.account.models import CoreAccount


class CoreAccountSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6
    )
    notify_on_success = serializers.BooleanField(allow_null=True)
    notify_on_fail = serializers.BooleanField(allow_null=True)

    class Meta:
        model = CoreAccount
        fields = ("id", "name", "notify_on_success", "notify_on_fail")


class CoreAccountWriteSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True
    )
    notify_on_success = serializers.BooleanField(allow_null=True)
    notify_on_fail = serializers.BooleanField(allow_null=True)

    class Meta:
        model = CoreAccount
        fields = (
            "name",
            "notify_on_success",
            "notify_on_fail",
        )