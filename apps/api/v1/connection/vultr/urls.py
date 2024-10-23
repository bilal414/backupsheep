from rest_framework import routers

from apps.console.api.v1.connection.vultr.views import CoreVultrView

router = routers.SimpleRouter()

router.register(r"vultr", CoreVultrView, basename="vultr")
urlpatterns = router.urls
