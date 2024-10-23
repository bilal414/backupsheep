from rest_framework import routers

from apps.console.api.v1.storage.exoscale.views import CoreStorageExoscaleView

router = routers.SimpleRouter()

router.register(r"exoscale", CoreStorageExoscaleView, basename="")
urlpatterns = router.urls
