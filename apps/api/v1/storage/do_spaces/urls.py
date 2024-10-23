from rest_framework import routers

from apps.console.api.v1.storage.do_spaces.views import CoreStorageDoSpacesView

router = routers.SimpleRouter()

router.register(r"do_spaces", CoreStorageDoSpacesView, basename="")
urlpatterns = router.urls
