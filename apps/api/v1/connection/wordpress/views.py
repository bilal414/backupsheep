from django.conf import settings
from django.db.models import Q
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
from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreWordPress, CoreNode
from .filters import CoreWordPressFilter
from .permissions import CoreWordPressViewPermissions
from .serializers import (
    CoreWordPressConnectionReadSerializer,
    CoreWordPressConnectionWriteSerializer,
)
from ..._tasks.exceptions import (
    NodeConnectionErrorEligibleObjects,
    IntegrationValidationFailed, IntegrationValidationError,
)
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from requests.utils import requote_uri


class CoreWordPressView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreWordPressViewPermissions,
    )
    read_serializer_class = CoreWordPressConnectionReadSerializer
    write_serializer_class = CoreWordPressConnectionWriteSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreWordPressFilter
    search_fields = ["name"]

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
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="wordpress")
        # query &= ~Q(status=CoreConnection.Status.DELETE_REQUESTED)
        queryset = CoreConnection.objects.filter(query)
        return queryset

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
        member = self.request.user.member
        query = Q(integrations__code="wordpress")

        if member.get_primary_account().billing.plan.name == "AppSumo":
            query &= Q(code="node-w-eu-03")
            endpoints = CoreConnectionLocation.objects.filter(query).values()
        else:
            query &= ~Q(code="node-w-eu-03")
            endpoints = CoreConnectionLocation.objects.filter(query).values()
        return Response(endpoints)


    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        try:
            connection = self.get_object()
            validation = connection.validate()
            if validation:
                return Response(
                    {"detail": "Validation passed. Integration is good for backups."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "detail": "Validation failed. Backups will fail. Check integration details immediately."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            raise IntegrationValidationError(e.__str__())

    @action(detail=True, methods=["get"])
    def objects(self, request, pk=None):
        try:
            return Response([])
        except Exception as e:
            raise NodeConnectionErrorEligibleObjects(e.__str__())
