from rest_framework import routers
from apps.console.api.v1.backup.basecamp.views import CoreBasecampBackupView

router = routers.SimpleRouter()

router.register(r"basecamp", CoreBasecampBackupView, basename="")
urlpatterns = router.urls