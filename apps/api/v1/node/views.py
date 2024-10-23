from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.console.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreNode
from .filters import CoreNodeFilter
from .serializers import CoreNodeSerializer
from .._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    SnapshotCreateNodeValidationFailed,
    SnapshotCreateNodeNotActive, NodeValidationFailed, AccountNotGoodStanding,
)
from .._tasks.integration.basecamp import backup_basecamp
from .._tasks.integration.website import backup_website
from ..utils.api_filters import DateRangeFilter
from apps.console.api.v1._tasks.helper.tasks import node_delete_requested
from ..utils.api_helpers import delete_snar_file


class CoreNodeView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, MemberPermissions,)
    serializer_class = CoreNodeSerializer
    all_fields = [f.name for f in CoreNode._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreNodeFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(connection__account=member.get_current_account())
        queryset = CoreNode.objects.filter(query)
        return queryset

    @action(detail=False)
    def totals(self, request):
        member = self.request.user.member
        query = Q(connection__account=member.get_current_account())
        nodes = CoreNode.objects.filter(query)

        all_totals = {
            "combined": {
                "cloud": nodes.filter(type=CoreNode.Type.CLOUD).count(),
                "volume": nodes.filter(type=CoreNode.Type.VOLUME).count(),
                "website": nodes.filter(type=CoreNode.Type.WEBSITE).count(),
                "database": nodes.filter(type=CoreNode.Type.DATABASE).count(),
                "saas": nodes.filter(type=CoreNode.Type.SAAS).count(),
                "nodes": nodes.count(),
            }
        }
        return Response(all_totals)

    @action(detail=True, methods=["post"])
    def take_snapshot(self, request, pk=None):
        from celery import current_app

        node = self.get_object()
        notes = self.request.data.get("notes")
        storage_point_ids = self.request.data.get("storage_point_ids")

        # Deny download if billing is not in good standing
        if not node.connection.account.billing.good_standing:
            raise AccountNotGoodStanding()

        if not node.backup_ready_to_initiate():
            raise SnapshotCreateNodeNotActive(
                message="The node must be in ACTIVE status before you can request a snapshot."
            )
        elif node.type == CoreNode.Type.WEBSITE or node.type == CoreNode.Type.DATABASE or node.type == CoreNode.Type.SAAS:
            if not storage_point_ids:
                raise SnapshotCreateMissingParams()
        elif node.type == CoreNode.Type.CLOUD:
            node_type_object = getattr(node, node.connection.integration.code)
            if "validate" in dir(node_type_object):
                if not node_type_object.validate():
                    raise SnapshotCreateNodeValidationFailed()
        elif node.type == CoreNode.Type.VOLUME:
            node_type_object = getattr(node, node.connection.integration.code)
            if "validate" in dir(node_type_object):
                if not node_type_object.validate():
                    raise SnapshotCreateNodeValidationFailed()

        try:
            node = self.get_object()
            # backup_google_cloud(node.id, storage_ids=storage_point_ids)
            # backup_basecamp(node.id, storage_ids=storage_point_ids)
            # backup_website(node.id, storage_ids=storage_point_ids)

            integration_code = node.get_integration_alt_code()

            queue_name = (
                f"on_demand_backup"
                f"__{node.get_type_display().lower()}"
                f"__{integration_code}"
                f"__{node.connection.location.queue}"
            )

            result = current_app.send_task(
                node.backup_task_name(),
                queue=queue_name,
                kwargs={
                    "node_id": pk,
                    "schedule_id": None,
                    "storage_ids": storage_point_ids,
                    "notes": notes,
                },
            )
            # final_result = result.get()
            return Response({"detail": "Backup will start in few seconds."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            raise SnapshotCreateError(e.__str__())

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        node = self.get_object()
        notes = self.request.data.get("notes")
        node.status = CoreNode.Status.PAUSED
        node.save()
        # log = CoreLog(account=self.request.user.member.get_current_account(), type=CoreLog.Type.NODE)
        # log.data = {
        #     "action": "status",
        #     "value": node.get_status_display(),
        #     "object": "node",
        #     "id": node.id,
        #     "name": node.name,
        #     "notes": notes
        # }
        # log.save()
        return Response({"detail": "Node is paused."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        node = self.get_object()
        notes = self.request.data.get("notes")
        node.status = CoreNode.Status.ACTIVE
        node.save()
        # log = CoreLog(account=self.request.user.member.get_current_account(), type=CoreLog.Type.NODE)
        # log.data = {
        #     "action": "status",
        #     "value": node.get_status_display(),
        #     "object": "node",
        #     "id": node.id,
        #     "name": node.name,
        #     "notes": notes
        # }
        # log.save()
        return Response({"detail": "Node is resumed."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def delete(self, request, pk=None):
        node = self.get_object()
        notes = self.request.data.get("notes")
        node.status = CoreNode.Status.DELETE_REQUESTED
        node.save()

        """
        Delete Node
        """
        queue = f"node_delete_requested__{node.connection.location.queue}"
        node_delete_requested.apply_async(
            args=[node.id],
            queue=queue,
        )

        # log = CoreLog(account=self.request.user.member.get_current_account(), type=CoreLog.Type.NODE)
        # log.data = {
        #     "action": "delete",
        #     "value": node.get_status_display(),
        #     "object": "node",
        #     "id": node.id,
        #     "name": node.name,
        #     "notes": notes
        # }
        # log.save()
        return Response({"detail": "Node will be deleted soon."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reset_incremental(self, request, pk=None):
        node = self.get_object()
        snar_file = f"{node.uuid_str}.snar"
        delete_snar_file(snar_file)
        return Response({"detail": "We have reset the incremental backups. Your next backup will be a full backup."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        try:
            validation = self.get_object().validate()
            if validation:
                return Response({"detail": "Validation passed. Node is good for backups."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Validation failed. Backups will fail. Check if node exists and status is active."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            raise NodeValidationFailed(e.__str__())