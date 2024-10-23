from rest_framework import routers

from apps.console.api.v1.storage.google_drive.views import CoreStorageGoogleDriveView

router = routers.SimpleRouter()

router.register(r"google_drive", CoreStorageGoogleDriveView, basename="")
urlpatterns = router.urls
