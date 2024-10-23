from rest_framework import routers

from apps.console.api.v1.storage.filebase.views import CoreStorageFilebaseView

router = routers.SimpleRouter()

router.register(r"filebase", CoreStorageFilebaseView, basename="")
urlpatterns = router.urls
