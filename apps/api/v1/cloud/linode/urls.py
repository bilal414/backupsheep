from rest_framework import routers

from apps.api.v1.cloud.linode.views import CoreCloudLinodeView

router = routers.SimpleRouter()

router.register(r"linode", CoreCloudLinodeView, basename="")
urlpatterns = router.urls