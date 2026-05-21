from rest_framework import routers

from apps.api.v1.backup.upcloud.views import CoreUpCloudBackupView

router = routers.SimpleRouter()

router.register(r"upcloud", CoreUpCloudBackupView, basename="")
urlpatterns = router.urls