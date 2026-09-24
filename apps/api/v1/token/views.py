"""Personal API token management (interactive credentials only)."""

from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.api.v1.token.serializers import (
    ApiScopeSerializer,
    ApiTokenCreateSerializer,
    ApiTokenSerializer,
    CurrentPasswordSerializer,
)
from apps.api.v1.utils.api_permissions import InteractiveCredentialPermission
from apps.api.v1.utils.api_scopes import scope_catalog
from apps.api.v1.utils.api_throttles import ApiCredentialManagementThrottle
from apps.console.api_access.models import CoreApiToken
from apps.console.log.models import CoreLog, _request_ip


def _record(request, account, action_name, message):
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


class ApiTokenViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Create, list, rotate and revoke your personal API tokens.

    Tokens belong to the signed-in member and are bound to one workspace.  The
    secret is returned exactly once, in the create and rotate responses.
    """

    permission_classes = (IsAuthenticated, InteractiveCredentialPermission)
    serializer_class = ApiTokenSerializer
    filter_backends = ()

    def get_queryset(self):
        return CoreApiToken.objects.filter(member=self.request.user.member).select_related(
            "account"
        )

    def get_serializer_class(self):
        if self.action == "create":
            return ApiTokenCreateSerializer
        if self.action == "rotate":
            return CurrentPasswordSerializer
        if self.action == "scopes":
            return ApiScopeSerializer
        return ApiTokenSerializer

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.action in ("create", "rotate"):
            throttles.append(ApiCredentialManagementThrottle())
        return throttles

    @extend_schema(
        request=ApiTokenCreateSerializer,
        responses={
            201: inline_serializer(
                "ApiTokenCreated",
                fields={
                    "token": serializers.CharField(),
                    **{
                        name: field
                        for name, field in ApiTokenSerializer().fields.items()
                    },
                },
            )
        },
    )
    def create(self, request, *args, **kwargs):
        serializer = ApiTokenCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        token, secret = CoreApiToken.issue(
            member=request.user.member,
            account=data["account"],
            name=data["name"],
            scopes=data["scopes"],
            ttl_seconds=data.get("expires_in"),
        )
        _record(
            request,
            token.account,
            "api_token_create",
            f"{request.user.email} created API token “{token.name}” ({token.key_prefix}…).",
        )
        body = ApiTokenSerializer(token).data
        body["token"] = secret
        return Response(body, status=status.HTTP_201_CREATED)

    @extend_schema(responses={204: OpenApiResponse(description="Token revoked")})
    def destroy(self, request, *args, **kwargs):
        token = self.get_object()
        if not token.is_revoked:
            token.revoke()
            _record(
                request,
                token.account,
                "api_token_revoke",
                f"{request.user.email} revoked API token “{token.name}” ({token.key_prefix}…).",
            )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=CurrentPasswordSerializer,
        responses={
            200: inline_serializer(
                "ApiTokenRotated",
                fields={
                    "token": serializers.CharField(),
                    **{
                        name: field
                        for name, field in ApiTokenSerializer().fields.items()
                    },
                },
            )
        },
    )
    @action(detail=True, methods=["post"])
    def rotate(self, request, pk=None):
        """Replace the secret of a token that has not been revoked."""
        token = self.get_object()
        serializer = CurrentPasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        if token.is_revoked:
            return Response(
                {"detail": "A revoked token cannot be rotated; create a new token."},
                status=status.HTTP_409_CONFLICT,
            )
        secret = token.rotate(now=timezone.now())
        _record(
            request,
            token.account,
            "api_token_rotate",
            f"{request.user.email} rotated API token “{token.name}” ({token.key_prefix}…).",
        )
        body = ApiTokenSerializer(token).data
        body["token"] = secret
        return Response(body)

    @extend_schema(responses=ApiScopeSerializer(many=True))
    @action(detail=False, methods=["get"], permission_classes=(IsAuthenticated,))
    def scopes(self, request):
        """List every scope a token or OAuth application can request."""
        return Response(scope_catalog())
