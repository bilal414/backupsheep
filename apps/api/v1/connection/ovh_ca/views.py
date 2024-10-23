import ovh
from django.conf import settings
from django.db.models import Q
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
from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreOVHCA, CoreNode
from .filters import CoreOVHCAFilter
from .serializers import CoreOVHCAConnectionReadSerializer, CoreOVHCAConnectionWriteSerializer
from ..._tasks.exceptions import NodeConnectionErrorEligibleObjects, IntegrationValidationFailed, \
    IntegrationValidationError
from ...utils.api_filters import DateRangeFilter
from ...utils.api_serializers import ReadWriteSerializerMixin
from django.core.cache import cache


class CoreOVHCAView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberPermissions,)
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
        member = self.request.user.member
        query = Q(account=member.get_current_account(), integration__code="ovh_ca")
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
        endpoints = CoreConnectionLocation.objects.filter(integrations__code="ovh_ca").values()
        return Response(endpoints)

    @action(detail=False, methods=["get"])
    def oauth_url(self, request):
        member = self.request.user.member
        account = member.get_current_account()

        # create a client using configuration
        client = ovh.Client(
            endpoint="ovh-ca",
            application_key=settings.OVH_CA_APP_KEY,
            application_secret=settings.OVH_CA_APP_SECRET,
        )

        # Request RO, /cloud API access
        ck = client.new_consumer_key_request()
        ck.add_rules(ovh.API_READ_ONLY, "/me")
        ck.add_recursive_rules(ovh.API_READ_ONLY, "/cloud/project")
        ck.add_recursive_rules(ovh.API_READ_WRITE, "/cloud/project/*/snapshot")
        ck.add_recursive_rules(ovh.API_READ_WRITE, "/cloud/project/*/volume/snapshot")
        ck.add_recursive_rules(["POST"], "/cloud/project/*/instance/*/snapshot")
        ck.add_recursive_rules(["POST"], "/cloud/project/*/volume/*/snapshot")

        ovh_consumer_key_sig = f"ovh_ca__consumer_key__{account.id}__{member.id}"

        validation = ck.request(
            redirect_url=settings.APP_URL + "/api/v1/callback/ovh/ca/"
        )
        cache.set(ovh_consumer_key_sig, validation["consumerKey"], 3600)

        auth_url = validation["validationUrl"]
        return Response({"oauth_url": auth_url})

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        try:
            connection = self.get_object()
            validation = connection.validate()
            if validation:
                return Response({"detail": "Validation passed. Integration is good for backups."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Validation failed. Backups will fail. Check integration details immediately."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise IntegrationValidationError(e.__str__())

    @action(detail=True, methods=["get"])
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