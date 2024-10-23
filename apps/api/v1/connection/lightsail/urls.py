from rest_framework import routers

from apps.console.api.v1.connection.lightsail.views import CoreLightsailView

router = routers.SimpleRouter()

router.register(r"lightsail", CoreLightsailView, basename="lightsail")
urlpatterns = router.urls
