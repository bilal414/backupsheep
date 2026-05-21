from rest_framework import routers
from apps.api.v1.backup.website.views import CoreWebsiteBackupView

router = routers.SimpleRouter()

router.register(r"website", CoreWebsiteBackupView, basename="")
urlpatterns = router.urls