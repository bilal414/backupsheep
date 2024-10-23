from rest_framework import routers
from apps.console.api.v1.schedule.views import CoreScheduleView

router = routers.SimpleRouter()

router.register(r"schedules", CoreScheduleView, basename="")
urlpatterns = router.urls
