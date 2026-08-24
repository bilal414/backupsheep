from django.db.models import Q
from django.db import transaction
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
from apps.api.v1.utils.api_permissions import MemberPermissions
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from apps.console.storage.models import CoreStorage
from apps._tasks.integration.storage.tasks import (
    delete_storage_requested,
    validate_local_storage,
)
from .filters import CoreStorageFilter
from .serializers import CoreStorageSerializer
from ..utils.api_filters import DateRangeFilter
from ..utils.api_serializers import ReadWriteSerializerMixin


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


def _publish_storage_task(task, storage_id):
    def publish():
        try:
            task.apply_async(args=[storage_id])
        except Exception:
            # The database state is durable and the storage-worker sweep will
            # republish it. Logging must not turn accepted intent into a false 5xx.
            pass

    transaction.on_commit(publish)


class CoreStorageView(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated, MemberPermissions,)
    serializer_class = CoreStorageSerializer
    all_fields = [f.name for f in CoreStorage._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreStorageFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query_partners = Q(account=member.get_current_account())
        query_partners &= ~Q(status=CoreStorage.Status.DELETE_REQUESTED)
        queryset = CoreStorage.objects.filter(query_partners)
        return queryset

    @action(detail=False, methods=["get"])
    def costs(self, request):
        """Projected storage and one-full-restore costs by destination/source."""
        return Response(
            CoreStorage.cost_summary_for_account(
                request.user.member.get_current_account()
            )
        )

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        storage = self.get_object()
        storage.status = CoreStorage.Status.PAUSED
        storage.save()
        _log_activity(
            request,
            CoreLog.Type.STORAGE,
            {
                "message": f"Storage '{storage.name}' paused.",
                "action": "pause",
                "actor_email": request.user.email,
                "storage_id": storage.id,
                "storage_name": storage.name,
            },
        )
        data = self.get_serializer(storage).data
        data["detail"] = "Storage is paused."
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        storage = self.get_object()
        if storage.type.code == "local":
            storage.status = CoreStorage.Status.PENDING
            storage.save(update_fields=["status", "modified"])
            _publish_storage_task(validate_local_storage, storage.pk)
            data = self.get_serializer(storage).data
            data["detail"] = (
                "Local Storage validation was scheduled before resume."
            )
            return Response(data, status=status.HTTP_202_ACCEPTED)
        storage.status = CoreStorage.Status.ACTIVE
        storage.save()
        _log_activity(
            request,
            CoreLog.Type.STORAGE,
            {
                "message": f"Storage '{storage.name}' resumed.",
                "action": "resume",
                "actor_email": request.user.email,
                "storage_id": storage.id,
                "storage_name": storage.name,
            },
        )
        data = self.get_serializer(storage).data
        data["detail"] = "Storage is resumed."
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        storage = self.get_object()
        if storage.type.code == "local":
            storage.status = CoreStorage.Status.PENDING
            storage.save(update_fields=["status", "modified"])
            _publish_storage_task(validate_local_storage, storage.pk)
            return Response(
                {
                    "success": None,
                    "message": "Local Storage validation was scheduled.",
                },
                status=status.HTTP_202_ACCEPTED,
            )
        try:
            valid = bool(storage.validate())
        except Exception:
            valid = False
        return Response(
            {
                "success": valid,
                "message": (
                    "Validation passed. Storage is good for backups."
                    if valid
                    else "Storage validation failed."
                ),
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def delete(self, request, pk=None):
        storage = self.get_object()
        storage.status = CoreStorage.Status.DELETE_REQUESTED
        storage.save()
        _publish_storage_task(delete_storage_requested, storage.pk)
        _log_activity(
            request,
            CoreLog.Type.STORAGE,
            {
                "message": f"Storage '{storage.name}' delete requested.",
                "action": "delete",
                "actor_email": request.user.email,
                "storage_id": storage.id,
                "storage_name": storage.name,
            },
        )
        return Response(
            {"detail": "Storage deletion was scheduled."},
            status=status.HTTP_202_ACCEPTED,
        )
