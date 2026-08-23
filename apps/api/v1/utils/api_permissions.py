from rest_framework import permissions


def _current_account_permission_groups(request, codename):
    """Account groups that grant a permission in the member's current account."""
    from apps.console.account.models import CoreAccountGroup

    member = request.user.member
    return CoreAccountGroup.objects.filter(
        account=member.get_current_account(),
        group__user=request.user,
        group__permissions__content_type__app_label="apps",
        group__permissions__codename=codename,
    ).distinct()


def member_has_perm(request, codename):
    """Check one of the account-group (CoreAccountGroup) custom permissions.

    The PRIMARY member of the current account bypasses every check (full
    access). Any other member gets the union of permissions from their groups
    in the current account only, so a membership or role in another workspace
    cannot authorize this one.
    """
    try:
        member = request.user.member
    except AttributeError:
        return False
    if member.is_primary_account:
        return True
    return _current_account_permission_groups(request, codename).exists()


def permitted_nodes(request, codename):
    """Visible nodes covered by a group that grants ``codename``.

    Permissions in Settings are defined to apply only to the nodes in that
    account group. An empty node list is the existing unrestricted-group
    contract and therefore covers every node visible in the current account.
    """
    from apps.api.v1.utils.api_helpers import visible_nodes

    member = request.user.member
    nodes = visible_nodes(member)
    if member.is_primary_account:
        return nodes

    permission_groups = _current_account_permission_groups(request, codename)
    if permission_groups.filter(nodes__isnull=True).exists():
        return nodes
    return nodes.filter(enrollments__in=permission_groups).distinct()


def member_has_perm_for_node(request, codename, node):
    try:
        request.user.member
    except AttributeError:
        return False
    return permitted_nodes(request, codename).filter(pk=node.pk).exists()


class MemberPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return hasattr(request.user, "member")


class MemberGroupPermissions(permissions.BasePermission):
    """Write/manage-action gate backed by the account-group custom permissions.

    ``action_permissions`` maps a DRF action name to a CoreAccountGroup
    permission codename (e.g. ``{"destroy": "backup_delete"}``); ``"*"`` is the
    fallback for any unsafe (non-safe-method) action without an explicit entry.
    Actions with no mapping stay open, as do safe-method actions without an
    explicit mapping -- object-level access is still enforced by each viewset's
    membership check and scoped queryset. The account's primary member always
    passes (see member_has_perm).
    """

    action_permissions = {}

    def _permissions_for_view(self, view):
        return getattr(view, "action_permissions", self.action_permissions)

    def has_permission(self, request, view):
        action_permissions = self._permissions_for_view(view)
        codename = action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = action_permissions.get("*")
        if codename is None:
            return True
        return member_has_perm(request, codename)

    def has_object_permission(self, request, view, obj):
        action_permissions = self._permissions_for_view(view)
        codename = action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = action_permissions.get("*")
        if codename is None:
            return True

        # Node actions are object-scoped: a permission granted by one account
        # group must not authorize a node assigned through another group.
        from apps.console.node.models import CoreNode

        if isinstance(obj, CoreNode):
            return member_has_perm_for_node(request, codename, obj)
        return True


class WebhookPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST',):
            return True
        else:
            return False
