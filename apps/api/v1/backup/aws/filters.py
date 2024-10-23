from django_filters import rest_framework as filters
from apps.console.backup.models import CoreAWSBackup


class CoreAWSBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="aws__node__connection__location__code")
    integration = filters.CharFilter(field_name="aws__node__connection__integration__code")
    aws = filters.CharFilter(field_name="aws__id")

    class Meta:
        model = CoreAWSBackup
        fields = []
