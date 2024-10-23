from django_filters import rest_framework as filters
from apps.console.notification.models import CoreNotificationSlack, CoreNotificationTelegram, CoreNotificationEmail


class CoreNotificationSlackFilter(filters.FilterSet):
    account = filters.CharFilter(field_name="account_id")

    class Meta:
        model = CoreNotificationSlack
        fields = []


class CoreNotificationTelegramFilter(filters.FilterSet):
    account = filters.CharFilter(field_name="account_id")

    class Meta:
        model = CoreNotificationTelegram
        fields = []


class CoreNotificationEmailFilter(filters.FilterSet):
    account = filters.CharFilter(field_name="account_id")

    class Meta:
        model = CoreNotificationEmail
        fields = []
