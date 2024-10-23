from rest_framework import routers

from apps.console.api.v1.cloud.lightsail.views import CoreCloudLightsailView

router = routers.SimpleRouter()

router.register(r"lightsail", CoreCloudLightsailView, basename="")
urlpatterns = router.urls