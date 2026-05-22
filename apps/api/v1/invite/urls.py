from rest_framework import routers
from apps.api.v1.invite.views import CoreInviteView

router = routers.SimpleRouter()

router.register(r"invites", CoreInviteView, basename="")
urlpatterns = router.urls
