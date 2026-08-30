from django.db import transaction
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
from apps.console.account.models import CoreAccount
from apps.console.connection.managed_ssh import acquire_managed_ssh_mutation_lock
from apps.console.connection.models import CoreConnection, CoreIntegration, CoreConnectionLocation
from apps.api.v1.utils.api_helpers import scoped_connections
from apps.api.v1.utils.api_permissions import MemberGroupPermissions
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from .filters import CoreConnectionFilter
from .serializers import CoreConnectionSerializer
from .view_helpers import connection_error_response
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin
from backupsheep.source_recovery_policy import require_source_backup_creation


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


class CoreConnectionView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberGroupPermissions,)
    action_permissions = {"*": "integration_changes"}
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
        return scoped_connections(self.request)

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        connection = self.get_object()
        connection.status = CoreConnection.Status.PAUSED
        connection.save()
        _log_activity(
            request,
            CoreLog.Type.CONNECTION,
            {
                "message": f"Connection '{connection.name}' paused.",
                "action": "pause",
                "actor_email": request.user.email,
                "connection_id": connection.id,
                "connection_name": connection.name,
            },
        )
        return Response({"detail": "Connection is paused."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        connection = self.get_object()
        require_source_backup_creation(connection.integration.code)
        connection.status = CoreConnection.Status.ACTIVE
        connection.save()
        _log_activity(
            request,
            CoreLog.Type.CONNECTION,
            {
                "message": f"Connection '{connection.name}' resumed.",
                "action": "resume",
                "actor_email": request.user.email,
                "connection_id": connection.id,
                "connection_name": connection.name,
            },
        )
        return Response({"detail": "Connection is resumed."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def validate(self, request, pk=None):
        connection = self.get_object()
        try:
            valid = bool(connection.validate())
        except Exception as error:
            return connection_error_response(error, stage="validation")
        if not valid:
            response = connection_error_response(
                RuntimeError("connection validation returned false"),
                stage="validation",
            )
            response.status_code = status.HTTP_200_OK
            response.data.update(
                {
                    "success": False,
                    "message": "Integration validation failed.",
                }
            )
            return response
        return Response(
            {
                "success": True,
                "message": "Provider credentials and account access were validated. No backup or recovery was tested.",
            },
            status=status.HTTP_200_OK,
        )

    # @action(detail=True, methods=["post"])
    # def delete(self, request, pk=None):
    #     connection = self.get_object()
    #     notes = self.request.data.get("notes")
    #     connection.status = CoreConnection.Status.DELETE_REQUESTED
    #     connection.save()
    #     return Response({"detail": "Connection will be deleted soon."}, status=status.HTTP_200_OK)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        # A connection cascade can delete managed auth and operation rows. Fence
        # before taking the canonical account -> connection row locks.
        acquire_managed_ssh_mutation_lock()
        candidate = self.get_object()
        account = CoreAccount.objects.select_for_update().only("pk").get(
            pk=candidate.account_id
        )
        instance = CoreConnection.objects.select_for_update().get(
            pk=candidate.pk,
            account=account,
        )
        n_count = instance.nodes.filter().count()
        if n_count > 0:
            return Response({"detail": f"The integration is attached to {n_count} node(s). Delete the node(s) first or you can pause it if you are not using it anymore."}, status=status.HTTP_409_CONFLICT)
        # Capture identity before the row disappears for the activity log.
        connection_id, connection_name = instance.id, instance.name
        self.perform_destroy(instance)
        _log_activity(
            request,
            CoreLog.Type.CONNECTION,
            {
                "message": f"Connection '{connection_name}' deleted.",
                "action": "delete",
                "actor_email": request.user.email,
                "connection_id": connection_id,
                "connection_name": connection_name,
            },
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @method_decorator(cache_page(60 * 60 * 1))
    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        connections = self.get_queryset()
        nodes = visible_nodes(member)
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
