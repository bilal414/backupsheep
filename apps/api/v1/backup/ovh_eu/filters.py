from django_filters import rest_framework as filters
from apps.console.backup.models import CoreOVHEUBackup


class CoreOVHEUBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="ovh_eu__node__connection__location__code")
    integration = filters.CharFilter(field_name="ovh_eu__node__connection__integration__code")
    ovh_eu = filters.CharFilter(field_name="ovh_eu__id")

    class Meta:
        model = CoreOVHEUBackup
        fields = []
