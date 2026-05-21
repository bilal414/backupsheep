from rest_framework import routers

from apps.api.v1.volume.vultr.views import CoreVolumeVultrView

router = routers.SimpleRouter()

router.register(r"vultr", CoreVolumeVultrView, basename="")
urlpatterns = router.urls