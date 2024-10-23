from rest_framework import routers

from apps.console.api.v1.connection.ovh_eu.views import CoreOVHEUView

router = routers.SimpleRouter()

router.register(r"ovh_eu", CoreOVHEUView, basename="")
urlpatterns = router.urls
