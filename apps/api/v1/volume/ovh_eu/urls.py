from rest_framework import routers

from apps.console.api.v1.volume.ovh_eu.views import CoreVolumeOVHEUView

router = routers.SimpleRouter()

router.register(r"ovh_eu", CoreVolumeOVHEUView, basename="")
urlpatterns = router.urls