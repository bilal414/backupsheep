from django.urls import path, re_path

from .views import (
    APIUtilsTest,
    SSHHostKeyApproveView,
    SSHHostKeyPreviewView,
    SSHHostKeyRevokeView,
)

urlpatterns = [
    re_path(r'^utils/test/?$', APIUtilsTest.as_view()),
    path(
        "utils/ssh-host-keys/preview/",
        SSHHostKeyPreviewView.as_view(),
        name="ssh-host-key-preview",
    ),
    path(
        "utils/ssh-host-keys/approve/",
        SSHHostKeyApproveView.as_view(),
        name="ssh-host-key-approve",
    ),
    path(
        "utils/ssh-host-keys/revoke/",
        SSHHostKeyRevokeView.as_view(),
        name="ssh-host-key-revoke",
    ),
]
