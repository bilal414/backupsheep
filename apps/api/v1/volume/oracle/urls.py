from rest_framework import routers

from apps.console.api.v1.volume.oracle.views import CoreVolumeOracleView

router = routers.SimpleRouter()

router.register(r"oracle", CoreVolumeOracleView, basename="")
urlpatterns = router.urls