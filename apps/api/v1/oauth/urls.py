from rest_framework import routers

from apps.api.v1.oauth.views import AuthorizedApplicationViewSet, OAuthApplicationViewSet

router = routers.SimpleRouter()
router.register(r"oauth/applications", OAuthApplicationViewSet, basename="oauth-applications")
router.register(
    r"oauth/authorized-applications",
    AuthorizedApplicationViewSet,
    basename="oauth-authorized-applications",
)
urlpatterns = router.urls
