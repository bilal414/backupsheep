from rest_framework import routers

from apps.api.v1.cloud.digitalocean.views import CoreCloudDigitalOceanView

router = routers.SimpleRouter()

router.register(r"digitalocean", CoreCloudDigitalOceanView, basename="")
urlpatterns = router.urls