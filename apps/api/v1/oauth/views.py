"""OAuth application registration and connected-application management.

Both resources are reserved for interactive credentials: a scoped token must
never be able to register a client or widen its own grant.
"""

from django.db.models import Count, Max, Min
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from oauth2_provider.generators import generate_client_secret
from oauth2_provider.models import get_access_token_model, get_application_model
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.api.oauth2.revocation import revoke_application_grants
from apps.api.v1.oauth.serializers import (
    AuthorizedApplicationSerializer,
    OAuthApplicationCreateSerializer,
    OAuthApplicationSerializer,
    OAuthApplicationUpdateSerializer,
    apply_model_validation,
)
from apps.api.v1.token.serializers import CurrentPasswordSerializer
from apps.api.v1.utils.api_permissions import InteractiveCredentialPermission
from apps.api.v1.utils.api_scopes import parse_scope_string
from apps.api.v1.utils.api_throttles import ApiCredentialManagementThrottle
from apps.console.log.models import CoreLog, _request_ip

Application = get_application_model()
AccessToken = get_access_token_model()


def _record(request, action_name, message):
    member = request.user.member
    account = member.get_current_account()
    if account is None:
        return
    CoreLog.record(
        account,
        CoreLog.Type.AUTH,
        {
            "message": message,
            "action": action_name,
            "actor_email": request.user.email,
            "ip": _request_ip(request),
        },
    )


def _with_secret(application, secret):
    body = OAuthApplicationSerializer(application).data
    body["client_secret"] = secret
    return body


class OAuthApplicationViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Register and manage the OAuth 2.0 applications you own.

    Confidential clients receive their ``client_secret`` exactly once, in the
    create and rotate-secret responses.  Client type and grant type are fixed
    after creation; register a new application to change them.
    """

    permission_classes = (IsAuthenticated, InteractiveCredentialPermission)
    serializer_class = OAuthApplicationSerializer
    filter_backends = ()

    def get_queryset(self):
        return Application.objects.filter(user=self.request.user).order_by("-created")

    def get_serializer_class(self):
        if self.action == "create":
            return OAuthApplicationCreateSerializer
        if self.action == "partial_update":
            return OAuthApplicationUpdateSerializer
        if self.action == "rotate_secret":
            return CurrentPasswordSerializer
        return OAuthApplicationSerializer

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.action in ("create", "rotate_secret"):
            throttles.append(ApiCredentialManagementThrottle())
        return throttles

    @extend_schema(
        request=OAuthApplicationCreateSerializer,
        responses={
            201: inline_serializer(
                "OAuthApplicationCreated",
                fields={
                    "client_secret": serializers.CharField(allow_null=True),
                    **{
                        name: field
                        for name, field in OAuthApplicationSerializer().fields.items()
                    },
                },
            )
        },
    )
    def create(self, request, *args, **kwargs):
        serializer = OAuthApplicationCreateSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        confidential = data["client_type"] == Application.CLIENT_CONFIDENTIAL
        secret = generate_client_secret() if confidential else ""
        application = Application(
            user=request.user,
            name=data["name"],
            client_type=data["client_type"],
            authorization_grant_type=data["authorization_grant_type"],
            redirect_uris=" ".join(data["redirect_uris"]),
            client_secret=secret,
        )
        apply_model_validation(application)
        application.save()
        _record(
            request,
            "oauth_application_create",
            f"{request.user.email} registered OAuth application “{application.name}” "
            f"({application.client_id}).",
        )
        return Response(
            _with_secret(application, secret or None), status=status.HTTP_201_CREATED
        )

    @extend_schema(request=OAuthApplicationUpdateSerializer, responses=OAuthApplicationSerializer)
    def partial_update(self, request, *args, **kwargs):
        application = self.get_object()
        serializer = OAuthApplicationUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if "name" in data:
            application.name = data["name"]
        if "redirect_uris" in data:
            if (
                application.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
                and not data["redirect_uris"]
            ):
                return Response(
                    {"redirect_uris": ["At least one exact redirect URI is required."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            application.redirect_uris = " ".join(data["redirect_uris"])
        apply_model_validation(application)
        application.save()
        _record(
            request,
            "oauth_application_update",
            f"{request.user.email} updated OAuth application “{application.name}” "
            f"({application.client_id}).",
        )
        return Response(OAuthApplicationSerializer(application).data)

    @extend_schema(responses={204: OpenApiResponse(description="Application deleted")})
    def destroy(self, request, *args, **kwargs):
        application = self.get_object()
        label = f"“{application.name}” ({application.client_id})"
        application.delete()
        _record(
            request,
            "oauth_application_delete",
            f"{request.user.email} deleted OAuth application {label} and revoked its tokens.",
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=CurrentPasswordSerializer,
        responses={
            200: inline_serializer(
                "OAuthApplicationSecretRotated",
                fields={
                    "client_secret": serializers.CharField(),
                    **{
                        name: field
                        for name, field in OAuthApplicationSerializer().fields.items()
                    },
                },
            )
        },
    )
    @action(detail=True, methods=["post"], url_path="rotate_secret")
    def rotate_secret(self, request, pk=None):
        """Issue a new client secret for a confidential application."""
        application = self.get_object()
        serializer = CurrentPasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        if application.client_type != Application.CLIENT_CONFIDENTIAL:
            return Response(
                {"detail": "Public applications do not have a client secret."},
                status=status.HTTP_409_CONFLICT,
            )
        secret = generate_client_secret()
        application.client_secret = secret
        application.save(update_fields=["client_secret", "updated"])
        _record(
            request,
            "oauth_application_rotate_secret",
            f"{request.user.email} rotated the secret of OAuth application "
            f"“{application.name}” ({application.client_id}).",
        )
        return Response(_with_secret(application, secret))


class AuthorizedApplicationViewSet(viewsets.ViewSet):
    """Applications that currently hold OAuth access on your behalf."""

    permission_classes = (IsAuthenticated, InteractiveCredentialPermission)
    serializer_class = AuthorizedApplicationSerializer
    lookup_value_regex = r"\d+"

    def _grants(self, request):
        return (
            AccessToken.objects.filter(user=request.user, expires__gt=timezone.now())
            .exclude(application__isnull=True)
            .values("application_id")
            .annotate(
                active_tokens=Count("id"),
                first_authorized=Min("created"),
                last_authorized=Max("created"),
            )
            .order_by("-last_authorized")
        )

    @extend_schema(responses=AuthorizedApplicationSerializer(many=True))
    def list(self, request):
        rows = list(self._grants(request))
        applications = Application.objects.in_bulk([row["application_id"] for row in rows])
        scopes_by_application = {}
        for application_id, scope in AccessToken.objects.filter(
            user=request.user, expires__gt=timezone.now(), application_id__in=applications
        ).values_list("application_id", "scope"):
            scopes_by_application.setdefault(application_id, set()).update(
                parse_scope_string(scope)
            )
        payload = [
            {
                "application": OAuthApplicationSerializer(
                    applications[row["application_id"]]
                ).data,
                "scopes": sorted(scopes_by_application.get(row["application_id"], ())),
                "active_tokens": row["active_tokens"],
                "first_authorized": row["first_authorized"],
                "last_authorized": row["last_authorized"],
            }
            for row in rows
            if row["application_id"] in applications
        ]
        return Response(payload)

    @extend_schema(responses={204: OpenApiResponse(description="Access revoked")})
    def destroy(self, request, pk=None):
        """Revoke every token the application holds for you."""
        application = Application.objects.filter(pk=pk).first()
        if application is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        removed = revoke_application_grants(request.user, application)
        _record(
            request,
            "oauth_grant_revoke",
            f"{request.user.email} revoked access for OAuth application "
            f"“{application.name}” ({removed} active token(s)).",
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
