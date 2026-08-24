from django.db.models import Q
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from sentry_sdk import capture_exception

from apps._tasks.integration.storage.tasks import delete_backup_requested
from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.node.models import CoreNode
from apps.console.utils.models import UtilBackup


class VisibleNodeBackupMixin:
    """Scope provider backup list/detail/actions to the member's visible nodes.

    DRF's ``get_object()`` resolves from ``get_queryset()``, so using this one
    queryset for every provider also protects download, restore, retry, cancel,
    delete, and provider-specific detail actions from guessed backup IDs.
    """

    backup_model = None
    backup_node_relation = None
    backup_delete_model_key = None

    def get_queryset(self):
        member = self.request.user.member
        node_path = f"{self.backup_node_relation}__node"

        query = Q(**{f"{node_path}__in": visible_nodes(member)})
        query &= ~Q(**{f"{node_path}__status": CoreNode.Status.DELETE_REQUESTED})
        query &= ~Q(
            status__in=(
                UtilBackup.Status.DELETE_REQUESTED,
                UtilBackup.Status.DELETE_IN_PROGRESS,
            )
        )

        node_id = self.request.query_params.get("node")
        if node_id:
            query &= Q(**{f"{node_path}__id": node_id})

        return self.backup_model.objects.filter(query)

    def request_backup_delete(self, instance):
        """Persist then enqueue deletion without giving the HTTP role disk access."""

        model_key = str(self.backup_delete_model_key or "")
        if not model_key:
            raise RuntimeError("This backup type has no asynchronous delete route.")
        with transaction.atomic():
            backup = self.backup_model.objects.select_for_update().get(pk=instance.pk)
            metadata = dict(backup.metadata or {})
            metadata["_deletion_request"] = {
                "requested_at": timezone.now().isoformat(),
                "previous_status": int(backup.status),
            }
            backup.metadata = metadata
            backup.status = UtilBackup.Status.DELETE_REQUESTED
            backup.save(update_fields=["metadata", "status", "modified"])

            def publish():
                try:
                    # Only an allowlisted model key and canonical database id cross
                    # the broker. The task rechecks DELETE_REQUESTED before acting.
                    delete_backup_requested.apply_async(
                        args=[model_key, backup.pk]
                    )
                except Exception as error:
                    capture_exception(error)

            transaction.on_commit(publish)

        return Response(
            {"detail": "Backup deletion was scheduled."},
            status=status.HTTP_202_ACCEPTED,
        )
