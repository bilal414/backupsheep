from rest_framework import routers

from apps.api.v1.volume.digitalocean.views import CoreVolumeDigitalOceanView

router = routers.SimpleRouter()

router.register(r"digitalocean", CoreVolumeDigitalOceanView, basename="")
urlpatterns = router.urls