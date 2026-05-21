from rest_framework import routers

from apps.api.v1.database.views import CoreDatabaseView

router = routers.SimpleRouter()

router.register(r"databases", CoreDatabaseView, basename="")
urlpatterns = router.urls