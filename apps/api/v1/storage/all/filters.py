from django_filters import rest_framework as filters
from apps.console.storage.models import CoreStorage


class CoreStorageAllFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name")
    type_code = filters.CharFilter(field_name="type__code")
    type_name = filters.CharFilter(field_name="type_name", lookup_expr='icontains')

    class Meta:
        model = CoreStorage
        fields = []
