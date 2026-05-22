from rest_framework import routers
from apps.api.v1.backup.wordpress.views import CoreWordPressBackupView

router = routers.SimpleRouter()

router.register(r"wordpress", CoreWordPressBackupView, basename="")
urlpatterns = router.urls