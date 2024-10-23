from rest_framework import routers

from apps.console.api.v1.volume.ovh_us.views import CoreVolumeOVHUSView

router = routers.SimpleRouter()

router.register(r"ovh_us", CoreVolumeOVHUSView, basename="")
urlpatterns = router.urls