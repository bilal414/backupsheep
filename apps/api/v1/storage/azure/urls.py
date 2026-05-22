from rest_framework import routers

from apps.api.v1.storage.azure.views import CoreStorageAzureView

router = routers.SimpleRouter()

router.register(r"azure", CoreStorageAzureView, basename="")
urlpatterns = router.urls
