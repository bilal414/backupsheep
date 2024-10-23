from django_filters import rest_framework as filters
from apps.console.backup.models import CoreWebsiteBackup


class CoreWebsiteBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="website__node__connection__location__code")
    integration = filters.CharFilter(field_name="website__node__connection__integration__code")
    website_type = filters.CharFilter(field_name="website__node__connection__auth_website__type")
    website = filters.CharFilter(field_name="website__id")

    class Meta:
        model = CoreWebsiteBackup
        fields = []
