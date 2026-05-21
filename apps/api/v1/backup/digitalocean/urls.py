from rest_framework import routers

from apps.api.v1.backup.digitalocean.views import CoreDigitalOceanBackupView

router = routers.SimpleRouter()

router.register(r"digitalocean", CoreDigitalOceanBackupView, basename="")
urlpatterns = router.urls