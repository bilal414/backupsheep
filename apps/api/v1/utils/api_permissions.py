from rest_framework import permissions


def active_current_membership(member):
    """Return or safely select the member's active current membership.

    Membership status is an authorization boundary. A stale ``current=True``
    flag on a suspended, pending, or invited row must not preserve tenant
    access through otherwise account-scoped querysets. If another ACTIVE
    membership exists, the member model atomically selects it; otherwise this
    returns ``None``.
    """
    try:
        return member.get_active_current_membership()
    except (AttributeError, TypeError):
        return None


def _current_account_permission_groups(request, codename):
    """Active-account groups granting exactly one BackupSheep permission."""
    from apps.console.account.models import CoreAccountGroup

    try:
        member = request.user.member
    except AttributeError:
        return CoreAccountGroup.objects.none()
    membership = active_current_membership(member)
    if membership is None:
        return CoreAccountGroup.objects.none()
    return CoreAccountGroup.objects.filter(
        account=membership.account,
        group__user=request.user,
        group__permissions__content_type__app_label=(
            CoreAccountGroup._meta.app_label
        ),
        group__permissions__content_type__model=(
            CoreAccountGroup._meta.model_name
        ),
        group__permissions__codename=codename,
    ).distinct()


def member_has_perm(request, codename):
    """Check a tenant-scoped CoreAccountGroup custom permission.

    The primary member of the active current account has full access. Other
    members receive only permissions attached through account groups owned by
    that same account; Django's cross-account union of auth groups is never an
    authorization source here.
    """
    try:
        member = request.user.member
    except AttributeError:
        return False
    membership = active_current_membership(member)
    if membership is None:
        return False
    if membership.primary:
        return True
    return _current_account_permission_groups(request, codename).exists()


def current_account_is_primary(request):
    """Return whether the authenticated member owns their active account."""
    try:
        member = request.user.member
    except AttributeError:
        return False
    membership = active_current_membership(member)
    return bool(membership and membership.primary)


def permitted_nodes(request, codename):
    """Visible nodes covered by an active-account permission group.

    Permissions in Settings apply only to nodes in the granting account group.
    An empty node list is the existing unrestricted-group contract and covers
    every node visible in the active current account.
    """
    from apps.api.v1.utils.api_helpers import visible_nodes
    from apps.console.node.models import CoreNode

    try:
        member = request.user.member
    except AttributeError:
        return CoreNode.objects.none()
    membership = active_current_membership(member)
    if membership is None:
        return CoreNode.objects.none()

    nodes = visible_nodes(member)
    if membership.primary:
        return nodes

    permission_groups = _current_account_permission_groups(request, codename)
    if permission_groups.filter(nodes__isnull=True).exists():
        return nodes
    return nodes.filter(enrollments__in=permission_groups).distinct()


def member_has_perm_for_node(request, codename, node):
    return permitted_nodes(request, codename).filter(pk=node.pk).exists()


class MemberPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        return active_current_membership(member) is not None


class MemberGroupPermissions(permissions.BasePermission):
    """Fail-closed write gate backed by tenant-scoped custom permissions.

    ``action_permissions`` maps a DRF action to a CoreAccountGroup permission
    codename; ``"*"`` is the fallback for an unsafe action without an explicit
    entry. Safe actions without a mapping remain available to scoped querysets.
    Unmapped unsafe actions are owner-only.
    """

    action_permissions = {}

    def _permissions_for_view(self, view):
        return getattr(view, "action_permissions", self.action_permissions)

    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if active_current_membership(member) is None:
            return False

        action_permissions = self._permissions_for_view(view)
        codename = action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = action_permissions.get("*")
        if codename is None:
            if request.method in permissions.SAFE_METHODS:
                return True
            return current_account_is_primary(request)
        return member_has_perm(request, codename)

    def has_object_permission(self, request, view, obj):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if active_current_membership(member) is None:
            return False

        action_permissions = self._permissions_for_view(view)
        codename = action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = action_permissions.get("*")
        if codename is None:
            return True

        # A permission granted by one account group must not authorize a node
        # assigned through another group.
        from apps.console.node.models import CoreNode

        if isinstance(obj, CoreNode):
            return member_has_perm_for_node(request, codename, obj)
        return True


class WebhookPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.method == "POST"
