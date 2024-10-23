from django_filters import rest_framework as filters
from apps.console.account.models import CoreAccount


class CoreAccountFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name")

    class Meta:
        model = CoreAccount
        fields = []
