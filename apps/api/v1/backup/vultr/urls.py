from rest_framework import routers

from apps.api.v1.backup.vultr.views import CoreVultrBackupView

router = routers.SimpleRouter()

router.register(r"vultr", CoreVultrBackupView, basename="")
urlpatterns = router.urls