import pytz
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.api.v1.utils.api_helpers import CurrentAccountDefault, CurrentMemberDefault
from apps.console.invite.models import CoreInvite


class CoreInviteReadSerializer(serializers.ModelSerializer):
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    accept_url = serializers.CharField(read_only=True)
    status_display = serializers.SerializerMethodField()

    class Meta:
        model = CoreInvite
        fields = "__all__"

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
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_full_name(obj):
        return obj.full_name

    @staticmethod
    def get_email(obj):
        return obj.email


class CoreInviteWriteSerializer(serializers.ModelSerializer):
    account = serializers.HiddenField(default=CurrentAccountDefault(), write_only=True)
    added_by = serializers.HiddenField(default=CurrentMemberDefault())
    # Lifetime is managed server-side: save() defaults it to now + INVITE_TTL_DAYS
    # and the resend action resets it.
    expires_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = CoreInvite
        fields = "__all__"

    def validate(self, data):
        # Invitees deliberately do NOT need an existing user account -- the public
        # /invite/<uuid>/ page lets them sign up while accepting. What is not
        # allowed is stacking duplicate pending invites for the same email+account.
        account = data.get("account") or (self.instance.account if self.instance else None)
        email = data.get("email") or (self.instance.email if self.instance else None)
        if account and email:
            query = CoreInvite.objects.filter(
                account=account,
                email__iexact=email,
                status=CoreInvite.Status.PENDING,
            )
            if self.instance:
                query = query.exclude(id=self.instance.id)
            if query.exists():
                raise serializers.ValidationError(
                    {"email": f"A pending invite for {email} already exists on this account."}
                )
        return data
