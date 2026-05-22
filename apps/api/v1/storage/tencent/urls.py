from rest_framework import routers

from apps.api.v1.storage.tencent.views import CoreStorageTencentView

router = routers.SimpleRouter()

router.register(r"tencent", CoreStorageTencentView, basename="")
urlpatterns = router.urls
