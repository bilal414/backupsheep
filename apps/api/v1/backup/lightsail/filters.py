from django_filters import rest_framework as filters
from apps.console.backup.models import CoreLightsailBackup


class CoreLightsailBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="lightsail__node__connection__location__code")
    integration = filters.CharFilter(field_name="lightsail__node__connection__integration__code")
    lightsail = filters.CharFilter(field_name="lightsail__id")

    class Meta:
        model = CoreLightsailBackup
        fields = []
