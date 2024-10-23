from rest_framework import routers

from apps.console.api.v1.backup.lightsail.views import CoreLightsailBackupView

router = routers.SimpleRouter()

router.register(r"lightsail", CoreLightsailBackupView, basename="")
urlpatterns = router.urls