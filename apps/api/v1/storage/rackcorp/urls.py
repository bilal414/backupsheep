from rest_framework import routers

from apps.api.v1.storage.rackcorp.views import CoreStorageRackCorpView

router = routers.SimpleRouter()

router.register(r"rackcorp", CoreStorageRackCorpView, basename="")
urlpatterns = router.urls
