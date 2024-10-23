from rest_framework import routers

from apps.console.api.v1.volume.aws.views import CoreVolumeAWSView

router = routers.SimpleRouter()

router.register(r"aws", CoreVolumeAWSView, basename="")
urlpatterns = router.urls