from django_filters import rest_framework as filters
from apps.console.backup.models import CoreDigitalOceanBackup


class CoreDigitalOceanBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="digitalocean__node__connection__location__code")
    integration = filters.CharFilter(field_name="digitalocean__node__connection__integration__code")
    digitalocean = filters.CharFilter(field_name="digitalocean__id")

    class Meta:
        model = CoreDigitalOceanBackup
        fields = []
