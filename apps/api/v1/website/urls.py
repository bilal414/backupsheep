from rest_framework import routers

from apps.console.api.v1.website.views import CoreWebsiteView

router = routers.SimpleRouter()

router.register(r"websites", CoreWebsiteView, basename="")
urlpatterns = router.urls