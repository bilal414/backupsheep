from django.db.models import Q
from apps.api.v1.utils.api_helpers import provider_connections_for_action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.connection.models import CoreConnection, CoreConnectionLocation
from apps.api.v1.utils.api_permissions import (
    MemberGroupPermissions,
    SOURCE_DISCOVERY_PERMISSIONS,
    member_has_perm,
)
from apps.api.v1.utils.api_authentication import ConsoleSessionAuthentication
from apps.console.node.models import CoreOVHCA, CoreNode
from .filters import CoreOVHCAFilter
from .serializers import CoreOVHCAConnectionReadSerializer, CoreOVHCAConnectionWriteSerializer
from apps._tasks.exceptions import NodeConnectionErrorEligibleObjects, IntegrationValidationFailed, \
    IntegrationValidationError
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from ..view_helpers import safe_connection_action
from ..ovh_oauth import (
    ovh_start_request_is_same_origin,
    prepare_ovh_authorization,
)


class CoreOVHCAView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberGroupPermissions,)
    action_permissions = {
        "*": "integration_changes",
        "oauth_url": "integration_changes",
        "validate": "integration_changes",
        "objects": SOURCE_DISCOVERY_PERMISSIONS,
    }
    read_serializer_class = CoreOVHCAConnectionReadSerializer
    write_serializer_class = CoreOVHCAConnectionWriteSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreOVHCAFilter
    search_fields = all_fields

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'encryption_key': self.request.user.member.get_encryption_key(),
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_queryset(self):
        return provider_connections_for_action(self.request, getattr(self, "action", None)).filter(
            integration__code="ovh_ca"
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        return Response(status=status.HTTP_403_FORBIDDEN, data={})

    @action(detail=False, methods=["get"])
    def endpoints(self, request):
        endpoints = CoreConnectionLocation.objects.filter(integrations__code="ovh_ca").values()
        return Response(endpoints)

    @action(
        detail=False,
        methods=["post"],
        authentication_classes=[ConsoleSessionAuthentication],
    )
    def oauth_url(self, request):
        if not member_has_perm(request, "integration_changes"):
            return Response(
                {"detail": "You do not have permission to connect integrations."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if not ovh_start_request_is_same_origin(request):
            return Response(
                {"detail": "The authorization request origin could not be verified."},
                status=status.HTTP_403_FORBIDDEN,
            )
        try:
            return Response(
                {"oauth_url": prepare_ovh_authorization(request, "ovh_ca")}
            )
        except Exception:
            return Response(
                {"detail": "Unable to prepare OVHcloud authorization."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

    @action(detail=True, methods=["post"])
    @safe_connection_action(stage="validation")
    def validate(self, request, pk=None):
        try:
            connection = self.get_object()
            validation = connection.validate()
            if validation:
                return Response({"detail": "Provider credentials and account access were validated. No backup or recovery was tested."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Provider access validation failed. Review credentials and permissions before using this connection."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise IntegrationValidationError(e.__str__())

    @action(detail=True, methods=["get"])
    @safe_connection_action(stage="object_discovery")
    def objects(self, request, pk=None):
        try:
            connection = self.get_object()
            eligible_objects = connection.auth_ovh_ca.get_eligible_objects(object_type=self.request.query_params.get("object_type"))
            for eligible_object in eligible_objects:
                query = Q(unique_id=eligible_object["id"], node__connection=connection)
                query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
                if CoreOVHCA.objects.filter(query).exists():
                    eligible_object["_bs_attached"] = True
            return Response(eligible_objects)
        except Exception as e:
            raise NodeConnectionErrorEligibleObjects(e.__str__())
