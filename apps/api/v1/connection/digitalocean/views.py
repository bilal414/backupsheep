from django.conf import settings
from django.db.models import Q
from apps.api.v1.utils.api_helpers import provider_connections_for_action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.api.v1.utils.api_permissions import MemberPermissions
from apps.api.v1.utils.api_authentication import ConsoleSessionAuthentication
from apps.console.node.models import CoreDigitalOcean, CoreNode
from .filters import CoreDigitalOceanFilter
from .permissions import CoreDigitalOceanViewPermissions
from .serializers import CoreDigitalOceanConnectionReadSerializer, CoreDigitalOceanConnectionWriteSerializer
from .client import DigitalOceanAPIError, list_eligible_objects
from apps._tasks.exceptions import NodeConnectionErrorEligibleObjects, IntegrationValidationFailed, \
    IntegrationValidationError
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from ...utils.api_permissions import member_has_perm
from ...utils.oauth_security import issue_oauth_state
from ..view_helpers import safe_connection_action
from urllib.parse import urlencode


class CoreDigitalOceanView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreDigitalOceanViewPermissions,)
    read_serializer_class = CoreDigitalOceanConnectionReadSerializer
    write_serializer_class = CoreDigitalOceanConnectionWriteSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreDigitalOceanFilter
    search_fields = ["name"]

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
            integration__code="digitalocean"
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
        endpoints = CoreConnectionLocation.objects.filter(integrations__code="digitalocean").values()
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
        member = request.user.member
        oauth_state = issue_oauth_state(
            request,
            provider="digitalocean",
            member=member,
            account=member.get_current_account(),
        )
        oauth_url = "https://cloud.digitalocean.com/v1/oauth/authorize?" + urlencode(
            {
                "response_type": "code",
                "client_id": settings.DIGITALOCEAN_APP_CLIENT_ID,
                "redirect_uri": settings.APP_URL
                + "/api/v1/callback/digitalocean/",
                "scope": "read write",
                "state": oauth_state["state"],
            }
        )
        return Response({"oauth_url": oauth_url})

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
        object_type = self.request.query_params.get("object_type", "cloud")
        if object_type not in {"cloud", "volume"}:
            return Response(
                {"detail": "object_type must be either cloud or volume."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            connection = self.get_object()
            eligible_objects = list_eligible_objects(
                headers=connection.auth_digitalocean.get_verified_client(),
                object_type=object_type,
            )
            attached_ids = {
                str(value)
                for value in CoreDigitalOcean.objects.filter(
                    node__connection=connection,
                )
                .exclude(node__status=CoreNode.Status.DELETE_REQUESTED)
                .values_list("unique_id", flat=True)
            }
            for eligible_object in eligible_objects:
                if str(eligible_object["id"]) in attached_ids:
                    eligible_object["_bs_attached"] = True
            return Response(eligible_objects)
        except DigitalOceanAPIError as error:
            raise NodeConnectionErrorEligibleObjects(str(error)) from error
        except Exception as error:
            raise NodeConnectionErrorEligibleObjects(
                "DigitalOcean object discovery could not be completed."
            ) from error
