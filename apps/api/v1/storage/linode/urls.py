from rest_framework import routers

from apps.console.api.v1.storage.linode.views import CoreStorageLinodeView

router = routers.SimpleRouter()

router.register(r"linode", CoreStorageLinodeView, basename="")
urlpatterns = router.urls
