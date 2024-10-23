from django_filters import rest_framework as filters
from apps.console.backup.models import CoreVultrBackup


class CoreVultrBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="vultr__node__connection__location__code")
    integration = filters.CharFilter(field_name="vultr__node__connection__integration__code")
    vultr = filters.CharFilter(field_name="vultr__id")

    class Meta:
        model = CoreVultrBackup
        fields = []
