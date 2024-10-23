from rest_framework import routers

from apps.console.api.v1.volume.linode.views import CoreVolumeLinodeView

router = routers.SimpleRouter()

router.register(r"linode", CoreVolumeLinodeView, basename="")
urlpatterns = router.urls