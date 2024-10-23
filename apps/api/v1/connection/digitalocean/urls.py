from rest_framework import routers

from apps.console.api.v1.connection.digitalocean.views import CoreDigitalOceanView

router = routers.SimpleRouter()

router.register(r"digitalocean", CoreDigitalOceanView, basename="")
urlpatterns = router.urls
