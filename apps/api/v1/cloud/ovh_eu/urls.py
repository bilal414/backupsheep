from rest_framework import routers

from apps.api.v1.cloud.ovh_eu.views import CoreCloudOVHEUView

router = routers.SimpleRouter()

router.register(r"ovh_eu", CoreCloudOVHEUView, basename="")
urlpatterns = router.urls