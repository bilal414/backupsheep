from rest_framework import routers

from apps.console.api.v1.cloud.google_cloud.views import CoreCloudGoogleCloudView

router = routers.SimpleRouter()

router.register(r"google_cloud", CoreCloudGoogleCloudView, basename="")
urlpatterns = router.urls