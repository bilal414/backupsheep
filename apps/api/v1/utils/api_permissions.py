from rest_framework import permissions


def member_has_perm(request, codename):
    """Check one of the account-group (CoreAccountGroup) custom permissions.

    The PRIMARY member of the current account bypasses every check (full
    access). Any other member gets the union of their auth groups' permissions
    through Django's normal has_perm(), so a member in no groups has none.
    Verified at runtime: the model lives in the "apps" app, so the permission
    strings are "apps.<codename>" (e.g. "apps.node_changes").
    """
    try:
        member = request.user.member
    except AttributeError:
        return False
    if member.is_primary_account:
        return True
    return request.user.has_perm(f"apps.{codename}")


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

    def has_permission(self, request, view):
        codename = self.action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = self.action_permissions.get("*")
        if codename is None:
            return True
        return member_has_perm(request, codename)


class WebhookPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST',):
            return True
        else:
            return False
