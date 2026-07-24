import json

from django.conf import settings
from django.db.models import Q
from django_celery_beat.models import CrontabSchedule, PeriodicTask
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response
from sentry_sdk import capture_exception

from apps.api.v1.schedule.filters import CoreScheduleFilter
from apps.api.v1.schedule.permissions import CoreScheduleViewPermissions
from apps.api.v1.schedule.serializers import CoreScheduleSerializer, CoreScheduleRunSerializer
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode, CoreSchedule, CoreScheduleRun
from rest_framework import status
from django.utils.text import slugify
from rest_framework.decorators import action
from celery import current_app

from apps.api.v1.utils.api_exceptions import ExceptionDefault


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


class CoreScheduleView(viewsets.ModelViewSet):
    permission_classes = (
        IsAuthenticated,
        CoreScheduleViewPermissions,
    )
    serializer_class = CoreScheduleSerializer
    all_fields = [f.name for f in CoreSchedule._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreScheduleFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(node__in=visible_nodes(member))
        # query &= ~Q(node__status=CoreNode.Status.DELETE_REQUESTED)
        # query &= ~Q(status=CoreSchedule.Status.DELETE_REQUESTED)
        if self.request.query_params.get("node"):
            query &= Q(node_id=self.request.query_params.get("node"))
        queryset = CoreSchedule.objects.filter(query)
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        schedule = serializer.instance
        schedule.schedule_create()
        _log_activity(
            request,
            CoreLog.Type.SCHEDULE,
            {
                "message": f"Schedule '{schedule.name}' created.",
                "action": "create",
                "actor_email": request.user.email,
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "node_id": schedule.node_id,
                "node_name": schedule.node.name,
            },
        )
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        schedule = serializer.instance
        schedule.schedule_update()
        _log_activity(
            request,
            CoreLog.Type.SCHEDULE,
            {
                "message": f"Schedule '{schedule.name}' updated.",
                "action": "update",
                "actor_email": request.user.email,
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "node_id": schedule.node_id,
                "node_name": schedule.node.name,
            },
        )

        if getattr(instance, "_prefetched_objects_cache", None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if hasattr(instance, f"{instance.node.connection.integration.code}_backups"):
            backups = getattr(instance, f"{instance.node.connection.integration.code}_backups")
            b_count = backups.filter().count()
            if b_count > 0:
                return Response(
                    {
                        "detail": f"The schedule is attached to {b_count} backup(s). "
                        f"You can pause it if you are not using it anymore."
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            else:
                # Capture identity before the row disappears for the activity log.
                schedule_id, schedule_name = instance.id, instance.name
                node_id, node_name = instance.node_id, instance.node.name
                instance.schedule_delete()
                instance.delete()
                _log_activity(
                    request,
                    CoreLog.Type.SCHEDULE,
                    {
                        "message": f"Schedule '{schedule_name}' deleted.",
                        "action": "delete",
                        "actor_email": request.user.email,
                        "schedule_id": schedule_id,
                        "schedule_name": schedule_name,
                        "node_id": node_id,
                        "node_name": node_name,
                    },
                )
                return Response({"detail": "Schedule will be deleted soon."}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"])
    def trigger(self, request, pk=None):
        schedule = self.get_object()
        request.data["schedule"] = schedule.id

        serializer = CoreScheduleRunSerializer(data=request.data)

        if serializer.is_valid(raise_exception=False):
            self.perform_create(serializer)

            schedule_run = serializer.instance

            current_app.send_task(
                schedule.node.backup_task_name(),
                kwargs={
                    "node_id": schedule.node.id,
                    "schedule_id": schedule.id,
                    "storage_ids": schedule.storage_ids,
                },
            )
            _log_activity(
                request,
                CoreLog.Type.SCHEDULE,
                {
                    "message": f"Schedule '{schedule.name}' triggered.",
                    "action": "trigger",
                    "actor_email": request.user.email,
                    "schedule_id": schedule.id,
                    "schedule_name": schedule.name,
                    "node_id": schedule.node_id,
                    "node_name": schedule.node.name,
                },
            )
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            raise ExceptionDefault(detail=serializer.errors)

    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        schedule = self.get_object()
        schedule.status = CoreSchedule.Status.PAUSED
        schedule.save()
        schedule.schedule_update()
        _log_activity(
            request,
            CoreLog.Type.SCHEDULE,
            {
                "message": f"Schedule '{schedule.name}' paused.",
                "action": "pause",
                "actor_email": request.user.email,
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "node_id": schedule.node_id,
                "node_name": schedule.node.name,
            },
        )
        return Response({"detail": "Schedule is paused."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def resume(self, request, pk=None):
        schedule = self.get_object()
        schedule.status = CoreSchedule.Status.ACTIVE
        schedule.save()
        schedule.schedule_update()
        _log_activity(
            request,
            CoreLog.Type.SCHEDULE,
            {
                "message": f"Schedule '{schedule.name}' resumed.",
                "action": "resume",
                "actor_email": request.user.email,
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "node_id": schedule.node_id,
                "node_name": schedule.node.name,
            },
        )
        return Response({"detail": "Schedule is resumed."}, status=status.HTTP_200_OK)
