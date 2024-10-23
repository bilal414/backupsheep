from rest_framework import routers

from apps.console.api.v1.connection.google_cloud.views import CoreGoogleCloudView

router = routers.SimpleRouter()

router.register(r"google_cloud", CoreGoogleCloudView, basename="")
urlpatterns = router.urls
