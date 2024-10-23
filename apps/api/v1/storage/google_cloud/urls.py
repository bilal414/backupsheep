from rest_framework import routers

from apps.console.api.v1.storage.google_cloud.views import CoreStorageGoogleCloudView

router = routers.SimpleRouter()

router.register(r"google_cloud", CoreStorageGoogleCloudView, basename="")
urlpatterns = router.urls
