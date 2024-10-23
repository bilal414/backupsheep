from rest_framework import routers

from apps.console.api.v1.cloud.hetzner.views import CoreCloudHetznerView

router = routers.SimpleRouter()

router.register(r"hetzner", CoreCloudHetznerView, basename="")
urlpatterns = router.urls