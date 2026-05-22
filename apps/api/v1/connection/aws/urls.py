from rest_framework import routers

from apps.api.v1.connection.aws.views import CoreAWSView

router = routers.SimpleRouter()

router.register(r"aws", CoreAWSView, basename="")
urlpatterns = router.urls
