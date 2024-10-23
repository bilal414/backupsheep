from rest_framework import routers
from apps.console.api.v1.group.views import CoreAccountGroupView

router = routers.SimpleRouter()

router.register(r"groups", CoreAccountGroupView, basename="")
urlpatterns = router.urls
