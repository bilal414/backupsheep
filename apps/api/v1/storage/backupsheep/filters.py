from django_filters import rest_framework as filters
from apps.console.storage.models import CoreStorageBS, CoreStorage


class CoreStorageBSFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name")
    code = filters.CharFilter(field_name="code")

    class Meta:
        model = CoreStorage
        fields = []
