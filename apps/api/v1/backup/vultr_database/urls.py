from rest_framework import routers

from apps.api.v1.backup.vultr_database.views import CoreVultrDatabaseBackupView

router = routers.SimpleRouter()
router.register(r"vultr_database", CoreVultrDatabaseBackupView, basename="vultr_database_backup")
urlpatterns = router.urls
