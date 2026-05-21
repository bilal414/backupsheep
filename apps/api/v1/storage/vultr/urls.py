from rest_framework import routers

from apps.api.v1.storage.vultr.views import CoreStorageVultrView

router = routers.SimpleRouter()

router.register(r"vultr", CoreStorageVultrView, basename="")
urlpatterns = router.urls
