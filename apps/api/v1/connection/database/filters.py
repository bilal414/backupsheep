from django_filters import rest_framework as filters
from apps.console.connection.models import CoreConnection


class CoreDatabaseFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="location__code")
    database_type = filters.CharFilter(field_name="auth_database__type")

    class Meta:
        model = CoreConnection
        fields = []
