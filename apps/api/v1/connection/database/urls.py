from rest_framework import routers

from apps.console.api.v1.connection.database.views import CoreDatabaseView

router = routers.SimpleRouter()

router.register(r"database", CoreDatabaseView, basename="")
urlpatterns = router.urls
