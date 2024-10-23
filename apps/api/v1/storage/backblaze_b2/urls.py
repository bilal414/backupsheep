from rest_framework import routers

from apps.console.api.v1.storage.backblaze_b2.views import CoreStorageBackBlazeB2View

router = routers.SimpleRouter()

router.register(r"backblaze_b2", CoreStorageBackBlazeB2View, basename="")
urlpatterns = router.urls
