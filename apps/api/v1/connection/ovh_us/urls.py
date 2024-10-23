from rest_framework import routers

from apps.console.api.v1.connection.ovh_us.views import CoreOVHUSView

router = routers.SimpleRouter()

router.register(r"ovh_us", CoreOVHUSView, basename="")
urlpatterns = router.urls
