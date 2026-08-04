from rest_framework import routers

from apps.api.v1.cloud.vultr_database.views import CoreVultrDatabaseView

router = routers.SimpleRouter()
router.register(r"vultr_database", CoreVultrDatabaseView, basename="vultr_database")
urlpatterns = router.urls
