from rest_framework import routers

from apps.console.api.v1.storage.upcloud.views import CoreStorageUpCloudView

router = routers.SimpleRouter()

router.register(r"upcloud", CoreStorageUpCloudView, basename="")
urlpatterns = router.urls
