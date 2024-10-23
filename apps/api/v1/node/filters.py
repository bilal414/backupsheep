from django_filters import rest_framework as filters

from apps.console.node.models import CoreNode


class CoreNodeFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="connection__location__code")
    integration = filters.CharFilter(field_name="connection__integration__code")

    class Meta:
        model = CoreNode
        fields = []
