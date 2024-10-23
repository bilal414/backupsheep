from rest_framework import routers

from apps.console.api.v1.storage.bs.views import CoreStorageBSView

router = routers.SimpleRouter()

router.register(r"bs", CoreStorageBSView, basename="")
urlpatterns = router.urls
