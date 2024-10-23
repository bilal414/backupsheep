from rest_framework import routers
from apps.console.api.v1.backup.database.views import CoreDatabaseBackupView

router = routers.SimpleRouter()

router.register(r"database", CoreDatabaseBackupView, basename="")
urlpatterns = router.urls