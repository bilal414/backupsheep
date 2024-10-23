from rest_framework import routers

from apps.console.api.v1.storage.wasabi.views import CoreStorageWasabiView

router = routers.SimpleRouter()

router.register(r"wasabi", CoreStorageWasabiView, basename="")
urlpatterns = router.urls
