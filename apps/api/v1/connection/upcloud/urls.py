from rest_framework import routers

from apps.api.v1.connection.upcloud.views import CoreUpCloudView

router = routers.SimpleRouter()

router.register(r"upcloud", CoreUpCloudView, basename="")
urlpatterns = router.urls
