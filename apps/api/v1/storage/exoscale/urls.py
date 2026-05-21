from rest_framework import routers

from apps.api.v1.storage.exoscale.views import CoreStorageExoscaleView

router = routers.SimpleRouter()

router.register(r"exoscale", CoreStorageExoscaleView, basename="")
urlpatterns = router.urls
