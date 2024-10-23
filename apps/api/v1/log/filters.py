from django_filters import rest_framework as filters
from apps.console.log.models import CoreLog


class CoreLogFilter(filters.FilterSet):
    account = filters.CharFilter(field_name="account_id")

    class Meta:
        model = CoreLog
        fields = []
