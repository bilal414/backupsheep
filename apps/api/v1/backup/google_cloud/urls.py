from rest_framework import routers

from apps.console.api.v1.backup.google_cloud.views import CoreGoogleCloudBackupView

router = routers.SimpleRouter()

router.register(r"google_cloud", CoreGoogleCloudBackupView, basename="")
urlpatterns = router.urls