from django_filters import rest_framework as filters
from apps.console.backup.models import CoreUpCloudBackup


class CoreUpCloudBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="upcloud__node__connection__location__code")
    integration = filters.CharFilter(field_name="upcloud__node__connection__integration__code")
    upcloud = filters.CharFilter(field_name="upcloud__id")

    class Meta:
        model = CoreUpCloudBackup
        fields = []
