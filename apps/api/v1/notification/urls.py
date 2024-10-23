from rest_framework import routers
from apps.console.api.v1.notification.views import CoreNotificationSlackView, CoreNotificationTelegramView, \
    CoreNotificationEmailView

router = routers.SimpleRouter()

router.register(r"notifications-slack", CoreNotificationSlackView, basename="")
router.register(r"notifications-telegram", CoreNotificationTelegramView, basename="")
router.register(r"notifications-email", CoreNotificationEmailView, basename="")
urlpatterns = router.urls
