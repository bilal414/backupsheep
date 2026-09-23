from rest_framework import routers

from apps.api.v1.cloud.oracle.views import CoreCloudOracleView


router = routers.SimpleRouter()
router.register(r"oracle", CoreCloudOracleView, basename="")
urlpatterns = router.urls
