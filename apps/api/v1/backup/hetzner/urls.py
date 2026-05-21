from rest_framework import routers

from apps.api.v1.backup.hetzner.views import CoreHetznerBackupView

router = routers.SimpleRouter()

router.register(r"hetzner", CoreHetznerBackupView, basename="")
urlpatterns = router.urls