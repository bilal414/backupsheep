from rest_framework import routers

from apps.console.api.v1.storage.backupsheep.views import CoreStorageBSView

router = routers.SimpleRouter()

router.register(r"backupsheep", CoreStorageBSView, basename="")
urlpatterns = router.urls
