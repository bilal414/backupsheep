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

from apps._tasks.exceptions import (
    IntegrationValidationError,
    NodeConnectionErrorEligibleObjects,
)
from apps._tasks.integration.oracle import (
    OracleProviderError,
    discover_oracle_objects,
)
from apps.console.connection.models import CoreConnection, CoreConnectionLocation
from apps.console.node.models import CoreOracle, CoreNode

from .filters import CoreOracleFilter
from .permissions import CoreOracleViewPermissions
from .serializers import (
    CoreOracleConnectionReadSerializer,
    CoreOracleConnectionWriteSerializer,
)
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from ..view_helpers import safe_connection_action


class CoreOracleView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreOracleViewPermissions,
    )
    read_serializer_class = CoreOracleConnectionReadSerializer
    write_serializer_class = CoreOracleConnectionWriteSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreOracleFilter
    search_fields = all_fields

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            "encryption_key": self.request.user.member.get_encryption_key(),
            "request": self.request,
            "format": self.format_kwarg,
            "view": self,
        }

    def get_queryset(self):
        return provider_connections_for_action(self.request, getattr(self, "action", None)).filter(
            integration__code="oracle"
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        return Response(status=status.HTTP_403_FORBIDDEN, data={})

    @action(detail=False, methods=["get"])
    def endpoints(self, request):
        endpoints = CoreConnectionLocation.objects.filter(integrations__code="oracle").values()
        return Response(endpoints)

    @action(detail=True, methods=["post"])
    @safe_connection_action(stage="validation")
    def validate(self, request, pk=None):
        try:
            connection = self.get_object()
            validation = connection.validate()
            if validation:
                return Response(
                    {"detail": "Provider credentials and account access were validated. No backup or recovery was tested."}, status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"detail": "Provider access validation failed. Review credentials and permissions before using this connection."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            raise IntegrationValidationError(e.__str__())

    @action(detail=True, methods=["get"])
    @safe_connection_action(stage="object_discovery")
    def objects(self, request, pk=None):
        try:
            connection = self.get_object()
            eligible_objects = discover_oracle_objects(
                connection.auth_oracle,
                self.request.query_params.get("object_type"),
            )
            for eligible_object in eligible_objects:
                query = Q(unique_id=eligible_object["id"], node__connection=connection)
                query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
                if CoreOracle.objects.filter(query).exists():
                    eligible_object["_bs_attached"] = True
            return Response(eligible_objects)
        except OracleProviderError as error:
            raise NodeConnectionErrorEligibleObjects(str(error))
        except Exception:
            raise NodeConnectionErrorEligibleObjects(
                "Oracle Cloud discovery failed safely. Verify the region, permissions, and compartment access."
            )
