from django_filters import rest_framework as filters
from apps.console.connection.models import CoreConnection
from apps.console.storage.models import CoreStorage


class CoreStorageFilter(filters.FilterSet):
    type = filters.CharFilter(field_name="type__code")

    class Meta:
        model = CoreStorage
        fields = []
