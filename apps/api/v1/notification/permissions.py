from rest_framework import permissions

from apps.api.v1.utils.api_permissions import active_current_membership
from apps.console.member.models import CoreMemberAccount


class CoreNotificationSlackViewPermissions(permissions.BasePermission):
    # def has_permission(self, request, view):
    #     if request.method in permissions.SAFE_METHODS:
    #         return True
    #     else:
    #         return hasattr(request.user, "member")

    def has_permission(self, request, view):
        try:
            member = request.user.member
        except AttributeError:
            return False
        membership = active_current_membership(member)
        if membership is None:
            return False
        # Listing/retrieval exposes only redacted metadata. Mutating or actively
        # validating the shared account integration is owner administration.
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return membership.primary

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
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return memberships.filter(primary=True).exists()


class CoreNotificationTelegramViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            membership = active_current_membership(request.user.member)
        except AttributeError:
            return False
        if membership is None:
            return False
        # Validation sends a real provider message despite historically being a
        # GET action, so treat it as a mutation. Tenant members may still read
        # redacted integration metadata.
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return membership.primary

    def has_object_permission(self, request, view, obj):
        try:
            member = request.user.member
        except AttributeError:
            return False
        if active_current_membership(member) is None:
            return False
        memberships = member.memberships.filter(
            account=obj.account,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        if not memberships.exists():
            return False
        if request.method in permissions.SAFE_METHODS and getattr(view, "action", None) != "validate":
            return True
        return memberships.filter(primary=True).exists()


class CoreNotificationEmailViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            return active_current_membership(request.user.member) is not None
        except AttributeError:
            return False

    def has_object_permission(self, request, view, obj):
        # CoreNotificationEmail has a `member` FK (no account FK): allow when the
        # email's member belongs to the requester's current account.
        try:
            membership = active_current_membership(request.user.member)
        except AttributeError:
            return False
        if membership is None or not obj.member.memberships.filter(
            account=membership.account,
            status=CoreMemberAccount.Status.ACTIVE,
        ).exists():
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        # Members administer only their own delivery address. The current
        # account's primary owner can administer any address in that tenant.
        return obj.member_id == request.user.member.id or membership.primary
