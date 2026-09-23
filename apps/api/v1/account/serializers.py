from django.db import transaction
from rest_framework import serializers

from apps.console.account.models import CoreAccount
from apps.console.connection.managed_ssh import acquire_managed_ssh_mutation_lock


class CoreAccountSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=128, allow_null=True, allow_blank=False, min_length=6
    )
    notify_on_success = serializers.BooleanField(allow_null=True)
    notify_on_fail = serializers.BooleanField(allow_null=True)
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = CoreAccount
        fields = ("id", "name", "notify_on_success", "notify_on_fail", "is_current")

    def get_is_current(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False

        member = getattr(user, "member", None)
        if not member:
            return False

        return member.memberships.filter(account=obj, current=True).exists()


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

    @transaction.atomic
    def create(self, validated_data):
        # A second account atomically disables installation-managed SSH. Take
        # the global fence before the account INSERT trigger can touch auth and
        # connection rows.
        acquire_managed_ssh_mutation_lock()
        return super().create(validated_data)
