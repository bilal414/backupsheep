from rest_framework import routers

from apps.console.api.v1.backup.digitalocean.views import CoreDigitalOceanBackupView

router = routers.SimpleRouter()

router.register(r"digitalocean", CoreDigitalOceanBackupView, basename="")
urlpatterns = router.urls