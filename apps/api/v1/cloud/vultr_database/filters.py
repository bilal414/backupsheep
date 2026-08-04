from django_filters import rest_framework as filters

from apps.console.node.models import CoreVultrDatabase


class CoreVultrDatabaseFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="node__connection__location__code")
    integration = filters.CharFilter(field_name="node__connection__integration__code")
    engine = filters.CharFilter(field_name="engine", lookup_expr="iexact")

    class Meta:
        model = CoreVultrDatabase
        fields = []
