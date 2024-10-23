from rest_framework import routers

from apps.console.api.v1.volume.ovh_ca.views import CoreVolumeOVHCAView

router = routers.SimpleRouter()

router.register(r"ovh_ca", CoreVolumeOVHCAView, basename="")
urlpatterns = router.urls