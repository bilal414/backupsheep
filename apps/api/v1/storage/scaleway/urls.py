from rest_framework import routers

from apps.console.api.v1.storage.scaleway.views import CoreStorageScalewayView

router = routers.SimpleRouter()

router.register(r"scaleway", CoreStorageScalewayView, basename="")
urlpatterns = router.urls
