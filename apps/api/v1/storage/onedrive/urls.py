from rest_framework import routers

from apps.console.api.v1.storage.onedrive.views import CoreStorageOneDriveView

router = routers.SimpleRouter()

router.register(r"onedrive", CoreStorageOneDriveView, basename="")
urlpatterns = router.urls
