from apps.api.v1.utils.http import requests
from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .api_permissions import MemberGroupPermissions
from .api_throttles import SSHHostKeyPeerThrottle, SSHHostKeyUserThrottle
from .ssh_host_keys import (
    SSHHostKeyFlowError,
    approve_host_key,
    preview_host_key,
    revoke_host_key,
)


class APIUtilsTest(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        content = {
            "api_version": 1.0,
        }
        return Response(content)


class SSHHostKeyChangesPermission(MemberGroupPermissions):
    """Require account-wide integration trust authority for both SSH actions."""

    action_permissions = {"*": "integration_changes"}


class _SSHHostKeyAPIView(APIView):
    permission_classes = (IsAuthenticated, SSHHostKeyChangesPermission)
    throttle_classes = (SSHHostKeyPeerThrottle, SSHHostKeyUserThrottle)

    @staticmethod
    def _error_response(error):
        if isinstance(error, SSHHostKeyFlowError):
            return Response(
                {"detail": error.detail, "code": error.code},
                status=error.status_code,
            )
        return Response(
            {"detail": "The SSH host-key operation failed.", "code": "internal_error"},
            status=500,
        )


class SSHHostKeyPreviewView(_SSHHostKeyAPIView):
    def post(self, request):
        try:
            return Response(preview_host_key(request, request.data))
        except Exception as error:
            return self._error_response(error)


class SSHHostKeyApproveView(_SSHHostKeyAPIView):
    def post(self, request):
        try:
            return Response(approve_host_key(request, request.data))
        except Exception as error:
            return self._error_response(error)


class SSHHostKeyRevokeView(_SSHHostKeyAPIView):
    def post(self, request):
        try:
            return Response(revoke_host_key(request, request.data))
        except Exception as error:
            return self._error_response(error)
