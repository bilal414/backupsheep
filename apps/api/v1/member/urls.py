from rest_framework import routers
from apps.console.api.v1.member.views import CoreMemberView

router = routers.SimpleRouter()

router.register(r"members", CoreMemberView, basename="")
urlpatterns = router.urls
