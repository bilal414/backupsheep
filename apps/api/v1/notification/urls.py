from rest_framework import routers
from apps.api.v1.notification.views import CoreNotificationSlackView, CoreNotificationTelegramView, \
    CoreNotificationEmailView

router = routers.SimpleRouter()

router.register(r"notifications-slack", CoreNotificationSlackView, basename="notifications-slack")
router.register(r"notifications-telegram", CoreNotificationTelegramView, basename="notifications-telegram")
router.register(r"notifications-email", CoreNotificationEmailView, basename="notifications-email")
urlpatterns = router.urls
