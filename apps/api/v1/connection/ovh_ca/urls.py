from rest_framework import routers

from apps.console.api.v1.connection.ovh_ca.views import CoreOVHCAView

router = routers.SimpleRouter()

router.register(r"ovh_ca", CoreOVHCAView, basename="")
urlpatterns = router.urls
