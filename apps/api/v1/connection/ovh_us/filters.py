from django_filters import rest_framework as filters
from apps.console.connection.models import CoreConnection


class CoreOVHUSFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="location__code")

    class Meta:
        model = CoreConnection
        fields = []
