import os
import shutil

from django.conf import settings
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, mixins
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.utils.api_permissions import MemberPermissions
from apps.console.node.models import CoreNode
from .filters import CoreNodeFilter
from .serializers import CoreCloudRestoreSerializer, CoreNodeSerializer
from apps._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    SnapshotCreateNodeValidationFailed,
    SnapshotCreateNodeNotActive, NodeValidationFailed,
    RestoreMissingParams,
    RestoreBackupNotFound,
    RestoreUnsupportedNode,
    RestoreCreateError,
)
from apps._tasks.integration.basecamp import backup_basecamp
from apps._tasks.integration.website import backup_website
from ..utils.api_filters import DateRangeFilter
from apps._tasks.helper.tasks import node_delete_requested


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

            result = current_app.send_task(
                node.backup_task_name(),
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
    def restore_backup(self, request, pk=None):
        from apps.console.backup.models import CoreCloudRestore
        from apps.console.utils.models import UtilBackup
        from apps._tasks.integration.restore import restore_cloud_backup

        node = self.get_object()
        backup_id = self.request.data.get("backup_id")
        name = self.request.data.get("name")
        params = self.request.data.get("params") or {}

        if not backup_id or not name:
            raise RestoreMissingParams()

        if node.type not in (CoreNode.Type.CLOUD, CoreNode.Type.VOLUME):
            raise RestoreUnsupportedNode()

        backup = node.get_cloud_backup(backup_id)
        if backup is None or backup.status != UtilBackup.Status.COMPLETE:
            raise RestoreBackupNotFound()

        restore = CoreCloudRestore.objects.create(
            node=node, backup_id=backup.id, name=name, params=params
        )

        try:
            restore_cloud_backup.apply_async(
                kwargs={
                    "node_id": node.id,
                    "backup_id": backup.id,
                    "restore_id": restore.id,
                }
            )
            return Response(
                CoreCloudRestoreSerializer(restore).data,
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            raise RestoreCreateError(e.__str__())

    @action(detail=True, methods=["get"])
    def restores(self, request, pk=None):
        from apps.console.backup.models import CoreCloudRestore

        node = self.get_object()
        restores = CoreCloudRestore.objects.filter(node=node).order_by("-created")
        return Response(CoreCloudRestoreSerializer(restores, many=True).data)

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
        node_delete_requested.apply_async(
            args=[node.id],
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
        # Wipe the per-node local mirror cache (and its fingerprint) so the next
        # incremental backup re-downloads everything. Confined to _storage.
        storage_dir = os.path.realpath(os.path.join(settings.BASE_DIR, "_storage"))
        cache_base = os.path.realpath(os.path.join(storage_dir, "website_cache", node.uuid_str))
        if cache_base != storage_dir and os.path.commonpath([storage_dir, cache_base]) == storage_dir:
            shutil.rmtree(cache_base, ignore_errors=True)
            try:
                os.remove(cache_base + ".meta.json")
            except FileNotFoundError:
                pass
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