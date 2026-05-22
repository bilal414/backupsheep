from rest_framework import routers

from apps.api.v1.connection.basecamp.views import CoreBasecampView

router = routers.SimpleRouter()

router.register(r"basecamp", CoreBasecampView, basename="")
urlpatterns = router.urls
