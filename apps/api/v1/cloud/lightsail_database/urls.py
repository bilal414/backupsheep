from rest_framework import routers

from apps.api.v1.cloud.lightsail_database.views import (
    CoreCloudLightsailDatabaseView,
)

router = routers.SimpleRouter()
router.register(
    r"lightsail_database",
    CoreCloudLightsailDatabaseView,
    basename="lightsail_database",
)
urlpatterns = router.urls
