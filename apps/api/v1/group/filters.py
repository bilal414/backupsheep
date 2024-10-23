from django_filters import rest_framework as filters
from django.contrib.auth.models import Group

from apps.console.account.models import CoreAccountGroup


class CoreAccountGroupFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name")

    class Meta:
        model = CoreAccountGroup
        fields = []
