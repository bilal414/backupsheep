from rest_framework import routers

from apps.api.v1.storage.idrive.views import CoreStorageIDriveView

router = routers.SimpleRouter()

router.register(r"idrive", CoreStorageIDriveView, basename="")
urlpatterns = router.urls
