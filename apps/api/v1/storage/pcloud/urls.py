from rest_framework import routers

from apps.console.api.v1.storage.pcloud.views import CoreStoragePCloudView

router = routers.SimpleRouter()

router.register(r"pcloud", CoreStoragePCloudView, basename="")
urlpatterns = router.urls
