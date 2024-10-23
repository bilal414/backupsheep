from rest_framework import routers

from apps.console.api.v1.storage.leviia.views import CoreStorageLeviiaView

router = routers.SimpleRouter()

router.register(r"leviia", CoreStorageLeviiaView, basename="")
urlpatterns = router.urls
