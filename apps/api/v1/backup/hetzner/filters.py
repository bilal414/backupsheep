from django_filters import rest_framework as filters
from apps.console.backup.models import CoreHetznerBackup


class CoreHetznerBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="hetzner__node__connection__location__code")
    integration = filters.CharFilter(field_name="hetzner__node__connection__integration__code")
    hetzner = filters.CharFilter(field_name="hetzner__id")

    class Meta:
        model = CoreHetznerBackup
        fields = []
