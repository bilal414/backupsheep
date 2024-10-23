from django_filters import rest_framework as filters
from apps.console.connection.models import CoreConnection


class CoreConnectionFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="location__code")
    integration = filters.CharFilter(field_name="integration__code")

    class Meta:
        model = CoreConnection
        fields = []
