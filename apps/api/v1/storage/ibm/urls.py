from rest_framework import routers

from apps.console.api.v1.storage.ibm.views import CoreStorageIBMView

router = routers.SimpleRouter()

router.register(r"ibm", CoreStorageIBMView, basename="")
urlpatterns = router.urls
