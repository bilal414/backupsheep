from rest_framework import routers

from apps.console.api.v1.cloud.ovh_ca.views import CoreCloudOVHCAView

router = routers.SimpleRouter()

router.register(r"ovh_ca", CoreCloudOVHCAView, basename="")
urlpatterns = router.urls