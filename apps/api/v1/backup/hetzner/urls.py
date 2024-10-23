from rest_framework import routers

from apps.console.api.v1.backup.hetzner.views import CoreHetznerBackupView

router = routers.SimpleRouter()

router.register(r"hetzner", CoreHetznerBackupView, basename="")
urlpatterns = router.urls