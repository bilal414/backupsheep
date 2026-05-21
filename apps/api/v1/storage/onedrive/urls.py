from rest_framework import routers

from apps.api.v1.storage.onedrive.views import CoreStorageOneDriveView

router = routers.SimpleRouter()

router.register(r"onedrive", CoreStorageOneDriveView, basename="")
urlpatterns = router.urls
