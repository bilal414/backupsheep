from rest_framework import routers

from apps.console.api.v1.cloud.aws.views import CoreCloudAWSView

router = routers.SimpleRouter()

router.register(r"aws", CoreCloudAWSView, basename="")
urlpatterns = router.urls