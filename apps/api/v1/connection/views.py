from django.db.models import Q
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_datatables.filters import DatatablesFilterBackend
from apps.console.connection.models import CoreConnection, CoreIntegration, CoreConnectionLocation
from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreNode
from .filters import CoreConnectionFilter
from .serializers import CoreConnectionSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin


class CoreConnectionView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberPermissions,)
    serializer_class = CoreConnectionSerializer
    all_fields = [f.name for f in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreConnectionFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        queryset = CoreConnection.objects.filter(query_partners)
        return queryset

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        connection = self.get_object()
        notes = self.request.data.get("notes")
        connection.status = CoreConnection.Status.PAUSED
        connection.save()
        return Response({"detail": "Connection is paused."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        connection = self.get_object()
        notes = self.request.data.get("notes")
        connection.status = CoreConnection.Status.ACTIVE
        connection.save()
        return Response({"detail": "Connection is resumed."}, status=status.HTTP_200_OK)

    # @action(detail=True, methods=["post"])
    # def delete(self, request, pk=None):
    #     connection = self.get_object()
    #     notes = self.request.data.get("notes")
    #     connection.status = CoreConnection.Status.DELETE_REQUESTED
    #     connection.save()
    #     return Response({"detail": "Connection will be deleted soon."}, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        n_count = instance.nodes.filter().count()
        if n_count > 0:
            return Response({"detail": f"The integration is attached to {n_count} node(s). Delete the node(s) first or you can pause it if you are not using it anymore."}, status=status.HTTP_409_CONFLICT)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @method_decorator(cache_page(60 * 60 * 1))
    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        connections = CoreConnection.objects.filter(query_partners)
        nodes = CoreNode.objects.filter(connection__in=connections)
        all_totals = {
            "combined": {
                "connections": connections.count(),
                "paused": connections.filter(
                    status=CoreConnection.Status.PAUSED
                ).count(),
                "suspended": connections.filter(
                    status=CoreConnection.Status.SUSPENDED
                ).count(),
                "nodes": nodes.count(),
            }
        }

        for integration in CoreIntegration.objects.filter():
            all_totals[integration.code] = {
                "connections": connections.filter(integration=integration).count(),
                "paused": connections.filter(
                    integration=integration, status=CoreConnection.Status.PAUSED
                ).count(),
                "suspended": connections.filter(
                    integration=integration, status=CoreConnection.Status.SUSPENDED
                ).count(),
                "nodes": nodes.filter(connection__integration=integration).count(),
            }

        return Response(all_totals)