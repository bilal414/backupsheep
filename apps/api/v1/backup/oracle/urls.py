from rest_framework import routers

from apps.console.api.v1.backup.oracle.views import CoreOracleBackupView

router = routers.SimpleRouter()

router.register(r"oracle", CoreOracleBackupView, basename="")
urlpatterns = router.urls