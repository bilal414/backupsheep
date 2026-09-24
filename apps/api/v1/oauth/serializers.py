from django.core.exceptions import ValidationError as DjangoValidationError
from oauth2_provider.models import get_application_model
from rest_framework import serializers

from apps.api.v1.token.serializers import CurrentPasswordSerializer

Application = get_application_model()

CLIENT_TYPES = (
    (Application.CLIENT_PUBLIC, "Public (mobile, desktop, single-page apps; PKCE only)"),
    (Application.CLIENT_CONFIDENTIAL, "Confidential (server-side apps holding a secret)"),
)
GRANT_TYPES = (
    (Application.GRANT_AUTHORIZATION_CODE, "Authorization code (users grant access)"),
    (Application.GRANT_CLIENT_CREDENTIALS, "Client credentials (acts as the owner)"),
)


class OAuthApplicationSerializer(serializers.ModelSerializer):
    redirect_uris = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = (
            "id",
            "name",
            "client_id",
            "client_type",
            "authorization_grant_type",
            "redirect_uris",
            "skip_authorization",
            "created",
            "updated",
        )
        read_only_fields = fields

    def get_redirect_uris(self, application):
        return application.redirect_uris.split()


class OAuthApplicationCreateSerializer(CurrentPasswordSerializer):
    name = serializers.CharField(max_length=255)
    client_type = serializers.ChoiceField(choices=CLIENT_TYPES, default=Application.CLIENT_PUBLIC)
    authorization_grant_type = serializers.ChoiceField(
        choices=GRANT_TYPES, default=Application.GRANT_AUTHORIZATION_CODE
    )
    redirect_uris = serializers.ListField(
        child=serializers.CharField(max_length=2048),
        required=False,
        default=list,
        help_text="Exact redirect URIs (https://…, the mobile app scheme, or an "
        "operator-enabled loopback URI).",
    )

    def validate(self, data):
        grant = data["authorization_grant_type"]
        if grant == Application.GRANT_CLIENT_CREDENTIALS:
            if data["client_type"] != Application.CLIENT_CONFIDENTIAL:
                raise serializers.ValidationError(
                    {"client_type": "The client-credentials grant requires a confidential client."}
                )
            if data["redirect_uris"]:
                raise serializers.ValidationError(
                    {"redirect_uris": "Client-credentials applications do not use redirect URIs."}
                )
        elif not data["redirect_uris"]:
            raise serializers.ValidationError(
                {"redirect_uris": "At least one exact redirect URI is required."}
            )
        return data


class OAuthApplicationUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255, required=False)
    redirect_uris = serializers.ListField(
        child=serializers.CharField(max_length=2048), required=False
    )


def apply_model_validation(application, *, field_map=None):
    """Run django-oauth-toolkit's model validation and surface it as DRF errors."""
    try:
        application.full_clean(exclude=["user", "client_secret"])
    except DjangoValidationError as error:
        detail = {}
        for field, messages in error.message_dict.items():
            detail[(field_map or {}).get(field, field)] = [str(message) for message in messages]
        raise serializers.ValidationError(detail)


class AuthorizedApplicationSerializer(serializers.Serializer):
    application = OAuthApplicationSerializer(read_only=True)
    scopes = serializers.ListField(child=serializers.CharField(), read_only=True)
    active_tokens = serializers.IntegerField(read_only=True)
    first_authorized = serializers.DateTimeField(read_only=True)
    last_authorized = serializers.DateTimeField(read_only=True)
