from django_filters import rest_framework as filters
from apps.console.storage.models import CoreStorage


class CoreStorageGoogleDriveFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name")
    type = filters.CharFilter(field_name="type__code")

    class Meta:
        model = CoreStorage
        fields = []
