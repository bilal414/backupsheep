from rest_framework import routers
from apps.console.api.v1.cloud.vultr.views import CoreCloudVultrView

router = routers.SimpleRouter()

router.register(r"vultr", CoreCloudVultrView, basename="")
urlpatterns = router.urls