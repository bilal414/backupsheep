from rest_framework import routers

from apps.console.api.v1.backup.ovh_ca.views import CoreOVHCABackupView

router = routers.SimpleRouter()

router.register(r"ovh_ca", CoreOVHCABackupView, basename="")
urlpatterns = router.urls