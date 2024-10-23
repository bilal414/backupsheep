from rest_framework import routers
from apps.console.api.v1.connection.aws_rds.views import CoreAWSRDSView

router = routers.SimpleRouter()

router.register(r"aws_rds", CoreAWSRDSView, basename="aws_rds")
urlpatterns = router.urls
