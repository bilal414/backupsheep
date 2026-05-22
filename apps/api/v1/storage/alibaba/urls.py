from rest_framework import routers

from apps.api.v1.storage.alibaba.views import CoreStorageAliBabaView

router = routers.SimpleRouter()

router.register(r"alibaba", CoreStorageAliBabaView, basename="")
urlpatterns = router.urls
