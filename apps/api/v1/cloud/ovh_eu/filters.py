from django_filters import rest_framework as filters
from apps.console.node.models import CoreDatabase, CoreOVHEU


class CoreCloudOVHEUFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="node__connection__location__code")
    integration = filters.CharFilter(field_name="node__connection__integration__code")

    class Meta:
        model = CoreOVHEU
        fields = []
