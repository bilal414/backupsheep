from rest_framework import routers

from apps.console.api.v1.storage.aws_s3.views import CoreStorageAWSS3View

router = routers.SimpleRouter()

router.register(r"aws_s3", CoreStorageAWSS3View, basename="")
urlpatterns = router.urls
