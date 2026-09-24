from rest_framework import routers

from apps.api.v1.token.views import ApiTokenViewSet

router = routers.SimpleRouter()
router.register(r"tokens", ApiTokenViewSet, basename="tokens")
urlpatterns = router.urls
