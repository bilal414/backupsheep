from rest_framework import routers
from apps.api.v1.backup.basecamp.views import CoreBasecampBackupView

router = routers.SimpleRouter()

router.register(r"basecamp", CoreBasecampBackupView, basename="")
urlpatterns = router.urls