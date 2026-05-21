from rest_framework import routers
from apps.api.v1.account.views import CoreAccountView

router = routers.SimpleRouter()

router.register(r"accounts", CoreAccountView, basename="")
urlpatterns = router.urls
