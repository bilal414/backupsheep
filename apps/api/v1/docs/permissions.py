from django.conf import settings
from rest_framework.permissions import BasePermission


class ApiDocsPermission(BasePermission):
    """The OpenAPI document and UI are member-only unless ``API_DOCS_PUBLIC``."""

    message = "Sign in to view the API documentation for this install."

    def has_permission(self, request, view):
        if getattr(settings, "API_DOCS_PUBLIC", False):
            return True
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated)
