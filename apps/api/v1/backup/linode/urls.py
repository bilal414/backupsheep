from rest_framework import routers

from apps.api.v1.backup.linode.views import CoreLinodeBackupView

router = routers.SimpleRouter()

router.register(r"linode", CoreLinodeBackupView, basename="")
urlpatterns = router.urls