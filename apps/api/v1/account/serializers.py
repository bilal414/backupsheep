from rest_framework import serializers

from apps.console.account.models import CoreAccount


class CoreAccountSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6
    )
    notify_on_success = serializers.NullBooleanField()
    notify_on_fail = serializers.NullBooleanField()

    class Meta:
        model = CoreAccount
        fields = ("id", "name", "notify_on_success", "notify_on_fail")


class CoreAccountWriteSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True
    )
    appsumo_code_1 = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6
    )
    appsumo_code_2 = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, write_only=True, min_length=6
    )
    notify_on_success = serializers.NullBooleanField()
    notify_on_fail = serializers.NullBooleanField()

    class Meta:
        model = CoreAccount
        fields = (
            "name",
            "appsumo_code_1",
            "appsumo_code_2",
            "notify_on_success",
            "notify_on_fail",
        )