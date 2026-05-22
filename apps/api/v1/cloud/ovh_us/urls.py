from rest_framework import routers

from apps.api.v1.cloud.ovh_us.views import CoreCloudOVHUSView

router = routers.SimpleRouter()

router.register(r"ovh_us", CoreCloudOVHUSView, basename="")
urlpatterns = router.urls