from rest_framework import routers
from apps.api.v1.group.views import CoreAccountGroupView

router = routers.SimpleRouter()

router.register(r"groups", CoreAccountGroupView, basename="")
urlpatterns = router.urls
