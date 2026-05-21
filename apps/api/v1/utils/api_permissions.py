from rest_framework import permissions


class MemberPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return hasattr(request.user, "member")


class WebhookPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST',):
            return True
        else:
            return False
