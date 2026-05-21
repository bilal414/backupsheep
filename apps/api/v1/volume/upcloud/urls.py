from rest_framework import routers

from apps.api.v1.volume.upcloud.views import CoreVolumeUpCloudView

router = routers.SimpleRouter()

router.register(r"upcloud", CoreVolumeUpCloudView, basename="")
urlpatterns = router.urls