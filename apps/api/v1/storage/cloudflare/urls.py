from rest_framework import routers

from apps.console.api.v1.storage.cloudflare.views import CoreStorageCloudflareView

router = routers.SimpleRouter()

router.register(r"cloudflare", CoreStorageCloudflareView, basename="")
urlpatterns = router.urls
