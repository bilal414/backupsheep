from rest_framework import routers

from apps.console.api.v1.connection.website.views import CoreWebsiteView

router = routers.SimpleRouter()

router.register(r"website", CoreWebsiteView, basename="")
urlpatterns = router.urls
