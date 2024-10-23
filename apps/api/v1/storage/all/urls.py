from rest_framework import routers

from apps.console.api.v1.storage.all.views import CoreStorageAllView

router = routers.SimpleRouter()

router.register(r"all", CoreStorageAllView, basename="")
urlpatterns = router.urls
