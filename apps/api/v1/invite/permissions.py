from rest_framework import permissions


class CoreInviteViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        # Invite management (including reads of pending invite metadata) is an
        # owner-only surface. The recipient-facing accept action remains
        # available and independently binds the invite to request.user.email.
        if getattr(view, "action", None) == "accept":
            return True
        return member.is_primary_account

    def has_object_permission(self, request, view, obj):
        memberships = request.user.member.memberships.filter(account=obj.account)
        if not memberships.exists():
            return False
        return memberships.filter(primary=True).exists()
