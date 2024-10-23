from rest_framework import routers

from apps.console.api.v1.storage.oracle.views import CoreStorageOracleView

router = routers.SimpleRouter()

router.register(r"oracle", CoreStorageOracleView, basename="")
urlpatterns = router.urls
