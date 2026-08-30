from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership
from apps.console.member.models import CoreMemberAccount


class CoreInviteViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        # Invite management (including reads of pending invite metadata) is an
        # owner-only surface. The recipient-facing accept action remains
        # available and independently binds the invite to request.user.email.
        if getattr(view, "action", None) in {"accept", "reject"}:
            return True
        membership = active_current_membership(member)
        return membership is not None and membership.primary

    def has_object_permission(self, request, view, obj):
        member = request.user.member
        if active_current_membership(member) is None:
            return False
        memberships = member.memberships.filter(
            account=obj.account,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        if not memberships.exists():
            return False
        return memberships.filter(primary=True).exists()
