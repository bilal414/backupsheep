from rest_framework import routers

from apps.api.v1.storage.dropbox.views import CoreStorageDropboxView

router = routers.SimpleRouter()

router.register(r"dropbox", CoreStorageDropboxView, basename="")
urlpatterns = router.urls
