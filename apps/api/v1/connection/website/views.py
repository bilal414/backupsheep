import uuid

from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.connection.managed_ssh import (
    connection_uses_managed_key,
    create_managed_ssh_operation,
    validate_direct_connection_and_activate,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreConnectionLocation,
    CoreManagedSSHOperation,
)

from ..view_helpers import connection_error_response, safe_connection_action
from .filters import CoreWebsiteFilter
from .permissions import CoreWebsiteViewPermissions
from .serializers import (
    CoreWebsiteConnectionReadSerializer,
    CoreWebsiteConnectionWriteSerializer,
)


def _managed_operation_payload(operation, *, include_result=False):
    payload = {
        "operation_id": str(operation.uuid),
        "operation": operation.operation,
        "operation_status": operation.status,
        "created_at": operation.created,
        "expires_at": operation.expires_at,
        "completed_at": operation.completed_at,
    }
    if include_result and operation.status == CoreManagedSSHOperation.Status.COMPLETE:
        payload["result"] = operation.result_payload
    elif include_result and operation.status in (
        CoreManagedSSHOperation.Status.FAILED,
        CoreManagedSSHOperation.Status.EXPIRED,
    ):
        payload["error"] = operation.error_payload
    return payload


def _saved_validation_failure(error):
    """Describe a post-commit validation failure without implying rollback."""

    safe_response = connection_error_response(error, stage="validation")
    return {
        "validation_status": "failed",
        "detail": "Connection was saved as pending; validation failed.",
        "validation_error": safe_response.data.get("connection_error", {}),
    }


class CoreWebsiteView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreWebsiteViewPermissions)
    read_serializer_class = CoreWebsiteConnectionReadSerializer
    write_serializer_class = CoreWebsiteConnectionWriteSerializer
    all_fields = [field.name for field in CoreConnection._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreWebsiteFilter
    search_fields = all_fields

    def get_serializer_context(self):
        return {
            "encryption_key": self.request.user.member.get_encryption_key(),
            "request": self.request,
            "format": self.format_kwarg,
            "view": self,
        }

    def get_queryset(self):
        member = self.request.user.member
        return CoreConnection.objects.filter(
            account=member.get_current_account(), integration__code="website"
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        operation = getattr(serializer, "managed_ssh_operation", None)
        direct_validation = operation is None and not connection_uses_managed_key(
            serializer.instance
        )
        validation_failure = None
        if direct_validation:
            try:
                validate_direct_connection_and_activate(
                    serializer.instance,
                    requested_by_member=request.user.member,
                )
            except Exception as error:
                validation_failure = _saved_validation_failure(error)
            serializer.instance.refresh_from_db()
        response_data = dict(serializer.data)
        if operation is not None:
            response_data.update(_managed_operation_payload(operation))
            response_data["validation_status"] = "pending"
        elif validation_failure is not None:
            response_data.update(validation_failure)
        elif direct_validation:
            response_data["validation_status"] = "complete"
        response = Response(
            response_data,
            status=status.HTTP_201_CREATED,
            headers=self.get_success_headers(serializer.data),
        )
        response["Cache-Control"] = "private, no-store"
        return response

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        operation = getattr(serializer, "managed_ssh_operation", None)
        direct_validation = operation is None and not connection_uses_managed_key(
            serializer.instance
        )
        validation_failure = None
        if direct_validation:
            try:
                validate_direct_connection_and_activate(
                    serializer.instance,
                    requested_by_member=request.user.member,
                )
            except Exception as error:
                validation_failure = _saved_validation_failure(error)
            serializer.instance.refresh_from_db()
        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}
        response_data = dict(serializer.data)
        if operation is not None:
            response_data.update(_managed_operation_payload(operation))
            response_data["validation_status"] = "pending"
        elif validation_failure is not None:
            response_data.update(validation_failure)
        elif direct_validation:
            response_data["validation_status"] = "complete"
        response = Response(response_data)
        response["Cache-Control"] = "private, no-store"
        return response

    def destroy(self, request, *args, **kwargs):
        return Response(status=status.HTTP_403_FORBIDDEN, data={})

    @action(detail=False, methods=["get"])
    def endpoints(self, request):
        endpoints = CoreConnectionLocation.objects.filter(
            Q(integrations__code="website") & ~Q(code="node-w-eu-03")
        ).values()
        return Response(endpoints)

    def _launch_managed(self, connection, operation, *, requested_path=""):
        durable = create_managed_ssh_operation(
            connection,
            operation,
            requested_path=requested_path,
            requested_by_member=self.request.user.member,
        )
        payload = _managed_operation_payload(durable)
        payload["detail"] = "Managed SSH operation accepted."
        response = Response(payload, status=status.HTTP_202_ACCEPTED)
        response["Cache-Control"] = "private, no-store"
        return response

    @action(detail=True, methods=["post"])
    @safe_connection_action(stage="validation")
    def validate(self, request, pk=None):
        connection = self.get_object()
        if connection_uses_managed_key(connection):
            return self._launch_managed(connection, "validate")
        validate_direct_connection_and_activate(
            connection,
            requested_by_member=request.user.member,
        )
        return Response(
            {"detail": "Provider credentials and account access were validated. No backup or recovery was tested."}
        )

    @action(detail=True, methods=["post"])
    @safe_connection_action(stage="object_discovery")
    def objects(self, request, pk=None):
        connection = self.get_object()
        path = request.data.get("path")
        path_tree = [{"name": "Root", "path": "/"}, {"name": "User Home", "path": "."}]
        if path and path != "/":
            for number, item in enumerate(path.split("/")):
                path_item = "/".join(path.split("/")[: number + 1])
                if path_item not in {entry["path"] for entry in path_tree}:
                    path_tree.append({"name": item, "path": path_item})

        if connection_uses_managed_key(connection):
            return self._launch_managed(
                connection,
                "discover",
                requested_path=path,
            )
        eligible_objects = connection.auth_website.get_eligible_objects(path=path)
        return Response(
            {"eligible_objects": eligible_objects, "path_tree": path_tree}
        )

    @action(
        detail=True,
        methods=["get"],
        url_path=r"managed-ssh-operations/(?P<operation_uuid>[^/.]+)",
    )
    def managed_ssh_operation(self, request, pk=None, operation_uuid=None):
        connection = self.get_object()
        try:
            parsed_uuid = uuid.UUID(str(operation_uuid))
        except (TypeError, ValueError, AttributeError):
            response = Response(
                {"detail": "Managed SSH operation not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
            response["Cache-Control"] = "private, no-store"
            return response
        operation = CoreManagedSSHOperation.objects.filter(
            uuid=parsed_uuid,
            connection=connection,
            account=connection.account,
            source_lane=CoreManagedSSHOperation.SourceLane.FILES,
        ).first()
        if operation is None:
            response = Response(
                {"detail": "Managed SSH operation not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
            response["Cache-Control"] = "private, no-store"
            return response
        response = Response(_managed_operation_payload(operation, include_result=True))
        response["Cache-Control"] = "private, no-store"
        return response
