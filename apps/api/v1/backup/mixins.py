from django.db.models import Q

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

    def get_queryset(self):
        member = self.request.user.member
        node_path = f"{self.backup_node_relation}__node"

        query = Q(**{f"{node_path}__in": visible_nodes(member)})
        query &= ~Q(**{f"{node_path}__status": CoreNode.Status.DELETE_REQUESTED})
        query &= ~Q(status=UtilBackup.Status.DELETE_REQUESTED)

        node_id = self.request.query_params.get("node")
        if node_id:
            query &= Q(**{f"{node_path}__id": node_id})

        return self.backup_model.objects.filter(query)
