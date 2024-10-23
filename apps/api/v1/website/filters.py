from django_filters import rest_framework as filters
from apps.console.node.models import CoreWebsite


class CoreWebsiteFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="node__connection__location__code")
    integration = filters.CharFilter(field_name="node__connection__integration__code")
    website_type = filters.CharFilter(field_name="node__connection__auth_website__type")

    class Meta:
        model = CoreWebsite
        fields = []
