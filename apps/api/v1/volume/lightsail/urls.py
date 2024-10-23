from rest_framework import routers

from apps.console.api.v1.volume.lightsail.views import CoreVolumeLightsailView

router = routers.SimpleRouter()

router.register(r"lightsail", CoreVolumeLightsailView, basename="")
urlpatterns = router.urls