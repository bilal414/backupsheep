from rest_framework import routers

from apps.console.api.v1.cloud.aws_rds.views import CoreCloudAWSRDSView

router = routers.SimpleRouter()

router.register(r"aws_rds", CoreCloudAWSRDSView, basename="")
urlpatterns = router.urls