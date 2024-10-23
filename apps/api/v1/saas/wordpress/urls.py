from rest_framework import routers

from apps.console.api.v1.saas.wordpress.views import CoreWordPressView

router = routers.SimpleRouter()

router.register(r"wordpress", CoreWordPressView, basename="")
urlpatterns = router.urls