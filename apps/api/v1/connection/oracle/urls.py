from rest_framework import routers

from apps.api.v1.connection.oracle.views import CoreOracleView

router = routers.SimpleRouter()

router.register(r"oracle", CoreOracleView, basename="oracle")
urlpatterns = router.urls
