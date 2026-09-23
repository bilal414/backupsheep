from rest_framework import routers

from apps.api.v1.cloud.upcloud.views import CoreCloudUpCloudView


router = routers.SimpleRouter()
router.register(r"upcloud", CoreCloudUpCloudView, basename="")
urlpatterns = router.urls
