from rest_framework import routers

from apps.api.v1.backup.aws.views import CoreAWSBackupView

router = routers.SimpleRouter()

router.register(r"aws", CoreAWSBackupView, basename="")
urlpatterns = router.urls