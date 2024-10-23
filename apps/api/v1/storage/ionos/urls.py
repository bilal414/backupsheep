from rest_framework import routers

from apps.console.api.v1.storage.ionos.views import CoreStorageIonosView

router = routers.SimpleRouter()

router.register(r"ionos", CoreStorageIonosView, basename="")
urlpatterns = router.urls
