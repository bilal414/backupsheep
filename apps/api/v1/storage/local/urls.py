from django.urls import path
from rest_framework import routers

from apps.api.v1.storage.local.views import CoreStorageLocalView, LocalStorageFileDownloadView

router = routers.SimpleRouter()

router.register(r"local", CoreStorageLocalView, basename="")
urlpatterns = router.urls
urlpatterns += [
    path(
        "local/file/<int:stored_backup_id>/",
        LocalStorageFileDownloadView.as_view(),
        name="local_storage_file",
    ),
]
