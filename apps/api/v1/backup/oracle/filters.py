from django_filters import rest_framework as filters
from apps.console.backup.models import CoreOracleBackup


class CoreOracleBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="oracle__node__connection__location__code")
    integration = filters.CharFilter(field_name="oracle__node__connection__integration__code")
    oracle = filters.CharFilter(field_name="oracle__id")

    class Meta:
        model = CoreOracleBackup
        fields = []
