from django_filters import rest_framework as filters
from apps.console.node.models import CoreDatabase


class CoreDatabaseFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="node__connection__location__code")
    integration = filters.CharFilter(field_name="node__connection__integration__code")
    database_type = filters.CharFilter(field_name="node__connection__auth_database__type")

    class Meta:
        model = CoreDatabase
        fields = []
