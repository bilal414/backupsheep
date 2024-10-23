from rest_framework import routers

from apps.console.api.v1.backup.ovh_us.views import CoreOVHUSBackupView

router = routers.SimpleRouter()

router.register(r"ovh_us", CoreOVHUSBackupView, basename="")
urlpatterns = router.urls