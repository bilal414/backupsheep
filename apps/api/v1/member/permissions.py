from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership


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
        action = getattr(view, "action", None)
        # A member whose current tenant access was suspended must still be able
        # to switch to another ACTIVE membership. The view validates that
        # destination before changing the current flag.
        if action == "switch_current_account":
            return True
        membership = active_current_membership(member)
        if membership is None:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if action in self.SELF_ACTIONS:
            return True
        if action in self.OWNER_ACTIONS:
            return membership.primary
        return False

    def has_object_permission(self, request, view, obj):
        member = request.user.member
        action = getattr(view, "action", None)
        if action == "switch_current_account":
            return obj.pk == member.pk
        current_membership = active_current_membership(member)
        if current_membership is None:
            return False
        account = current_membership.account
        if not obj.memberships.filter(account=account).exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if action in self.SELF_ACTIONS:
            return obj.pk == member.pk
        if action == "update_membership":
            return current_membership.primary
        if action == "destroy":
            # A tenant owner must not delete another account's identity, nor an
            # account owner. Membership removal has a dedicated scoped action.
            target_membership = obj.memberships.get(account=account)
            return (
                current_membership.primary
                and not target_membership.primary
                and not obj.memberships.exclude(account=account).exists()
            )
        return False
