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
from apps.console.connection.models import CoreConnection, CoreConnectionLocation, CoreIntegration
from apps.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreUpCloud, CoreNode, _BackupProviderError
from apps._tasks.integration.upcloud import (
    list_upcloud_servers,
    list_upcloud_storages,
)
from .filters import CoreUpCloudFilter
from .permissions import CoreUpCloudViewPermissions
from .serializers import CoreUpCloudConnectionReadSerializer, CoreUpCloudConnectionWriteSerializer
from apps._tasks.exceptions import NodeConnectionErrorEligibleObjects, IntegrationValidationFailed, \
    IntegrationValidationError
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from ..view_helpers import safe_connection_action


class CoreUpCloudView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreUpCloudViewPermissions,)
    read_serializer_class = CoreUpCloudConnectionReadSerializer
    write_serializer_class = CoreUpCloudConnectionWriteSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreUpCloudFilter
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
            integration__code="upcloud"
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
        endpoints = CoreConnectionLocation.objects.filter(integrations__code="upcloud").values()
        return Response(endpoints)

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
            object_type = self.request.query_params.get("object_type")
            object_type = object_type or "cloud"
            if object_type not in ("cloud", "volume"):
                return Response([])
            eligible_objects = (
                list_upcloud_servers(connection.auth_upcloud.get_verified_client())
                if object_type == "cloud"
                else list_upcloud_storages(
                    connection.auth_upcloud.get_verified_client(), storage_type="normal"
                )
            )
            for eligible_object in eligible_objects:
                eligible_object["_bs_unique_id"] = eligible_object.get("uuid")
                eligible_object["_bs_name"] = eligible_object.get("title")
                eligible_object["_bs_region"] = eligible_object.get("zone")
                eligible_object["_bs_size"] = (
                    eligible_object.get("size")
                    if object_type == "volume"
                    else None
                )
                eligible_object["_bs_resource_type"] = object_type
            node_type = (
                CoreNode.Type.CLOUD
                if object_type == "cloud"
                else CoreNode.Type.VOLUME
            )
            for eligible_object in eligible_objects:
                query = Q(
                    unique_id=eligible_object["uuid"],
                    node__connection=connection,
                    node__type=node_type,
                )
                query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
                if CoreUpCloud.objects.filter(query).exists():
                    eligible_object["_bs_attached"] = True
            return Response(eligible_objects)
        except _BackupProviderError as error:
            raise NodeConnectionErrorEligibleObjects(
                f"UpCloud resource discovery failed ({error.code})."
            ) from None
        except Exception:
            raise NodeConnectionErrorEligibleObjects(
                "UpCloud resource discovery failed safely. Verify the token, "
                "IP allow-list, and account permissions."
            ) from None
