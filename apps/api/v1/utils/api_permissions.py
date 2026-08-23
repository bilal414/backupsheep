from rest_framework import permissions


def member_has_perm(request, codename):
    """Check one of the account-group (CoreAccountGroup) custom permissions.

    The PRIMARY member of the current account bypasses every check (full
    access). Any other member receives only permissions attached through a
    CoreAccountGroup owned by that same current account. This intentionally
    avoids Django's cross-account union of auth-group permissions.
    """
    try:
        member = request.user.member
    except AttributeError:
        return False
    account = member.get_current_account()
    if account is None:
        return False

    from apps.console.account.models import CoreAccountGroup
    from apps.console.member.models import CoreMemberAccount

    membership = member.memberships.filter(
        account=account,
        status=CoreMemberAccount.Status.ACTIVE,
    )
    if not membership.exists():
        return False
    if membership.filter(primary=True).exists():
        return True

    # Django's user.has_perm() returns the union of every auth Group attached to
    # a user. A member can belong to several BackupSheep accounts, so that union
    # must never be used for tenant authorization. Resolve the permission only
    # through CoreAccountGroup rows owned by the current account.
    return CoreAccountGroup.objects.filter(
        account=account,
        group__user=request.user,
        group__permissions__codename=codename,
        group__permissions__content_type__app_label=CoreAccountGroup._meta.app_label,
        group__permissions__content_type__model=CoreAccountGroup._meta.model_name,
    ).exists()


def current_account_is_primary(request):
    """Return whether the authenticated member owns their current account."""
    try:
        member = request.user.member
        account = member.get_current_account()
    except AttributeError:
        return False
    if account is None:
        return False

    from apps.console.member.models import CoreMemberAccount

    return member.memberships.filter(
        account=account,
        primary=True,
        status=CoreMemberAccount.Status.ACTIVE,
    ).exists()


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
    Safe-method actions without an explicit mapping stay open for the view's
    object/queryset checks. Unmapped unsafe actions fail closed for ordinary
    members; the current account owner retains administrative access.
    """

    action_permissions = {}

    def has_permission(self, request, view):
        # Most viewsets declare their map on the view, while provider-specific
        # permission subclasses declare it here. Honour both, preferring the
        # view's explicit map.
        action_permissions = getattr(view, "action_permissions", None)
        if action_permissions is None:
            action_permissions = self.action_permissions

        codename = action_permissions.get(getattr(view, "action", None))
        if codename is None and request.method not in permissions.SAFE_METHODS:
            codename = action_permissions.get("*")
        if codename is None:
            if request.method in permissions.SAFE_METHODS:
                return True
            return current_account_is_primary(request)
        return member_has_perm(request, codename)


class WebhookPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST',):
            return True
        else:
            return False
