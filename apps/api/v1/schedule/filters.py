from django_filters import rest_framework as filters
from apps.console.node.models import CoreSchedule


class CoreScheduleFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="node__connection__location__code")
    integration = filters.CharFilter(field_name="node__connection__integration__code")
    node = filters.CharFilter(field_name="node__id")

    class Meta:
        model = CoreSchedule
        fields = []
