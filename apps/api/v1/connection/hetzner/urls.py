from rest_framework import routers

from apps.console.api.v1.connection.hetzner.views import CoreHetznerView

router = routers.SimpleRouter()

router.register(r"hetzner", CoreHetznerView, basename="")
urlpatterns = router.urls
