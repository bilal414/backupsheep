from django_filters import rest_framework as filters
from apps.console.backup.models import CoreAWSRDSBackup


class CoreAWSRDSBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="aws_rds__node__connection__location__code")
    integration = filters.CharFilter(field_name="aws_rds__node__connection__integration__code")
    aws_rds = filters.CharFilter(field_name="aws_rds__id")

    class Meta:
        model = CoreAWSRDSBackup
        fields = []
