from rest_framework import routers

from apps.api.v1.backup.aws_rds.views import CoreAWSRDSBackupView

router = routers.SimpleRouter()

router.register(r"aws_rds", CoreAWSRDSBackupView, basename="")
urlpatterns = router.urls