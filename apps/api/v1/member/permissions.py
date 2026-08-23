from rest_framework import permissions


class CoreMemberViewPermissions(permissions.BasePermission):
    SELF_ACTIONS = {
        "update",
        "partial_update",
        "switch_current_account",
        "auth_multi_factor_token_setup",
        "auth_multi_factor_token_verify",
        "auth_multi_factor_token_revoke",
    }
    OWNER_ACTIONS = {"create", "destroy", "update_membership"}

    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        action = getattr(view, "action", None)
        if action in self.SELF_ACTIONS:
            return True
        if action in self.OWNER_ACTIONS:
            return member.is_primary_account
        return False

    def has_object_permission(self, request, view, obj):
        member = request.user.member
        account = member.get_current_account()
        if not obj.memberships.filter(account=account).exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        action = getattr(view, "action", None)
        if action in self.SELF_ACTIONS:
            return obj.pk == member.pk
        if action == "update_membership":
            return member.is_primary_account
        if action == "destroy":
            # A tenant owner must not delete another account's identity, nor an
            # account owner. Membership removal has a dedicated scoped action.
            membership = obj.memberships.get(account=account)
            return (
                member.is_primary_account
                and not membership.primary
                and not obj.memberships.exclude(account=account).exists()
            )
        return False
