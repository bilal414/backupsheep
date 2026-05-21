from rest_framework import routers
from apps.api.v1.log.views import CoreLogView

router = routers.SimpleRouter()

router.register(r"logs", CoreLogView, basename="")
urlpatterns = router.urls
