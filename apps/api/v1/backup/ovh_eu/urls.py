from rest_framework import routers

from apps.console.api.v1.backup.ovh_eu.views import CoreOVHEUBackupView

router = routers.SimpleRouter()

router.register(r"ovh_eu", CoreOVHEUBackupView, basename="")
urlpatterns = router.urls