from rest_framework import routers

from apps.console.api.v1.volume.google_cloud.views import CoreVolumeGoogleCloudView

router = routers.SimpleRouter()

router.register(r"google_cloud", CoreVolumeGoogleCloudView, basename="")
urlpatterns = router.urls