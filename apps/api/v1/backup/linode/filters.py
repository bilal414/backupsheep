from django_filters import rest_framework as filters
from apps.console.backup.models import CoreLinodeBackup


class CoreLinodeBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="linode__node__connection__location__code")
    integration = filters.CharFilter(field_name="linode__node__connection__integration__code")
    linode = filters.CharFilter(field_name="linode__id")

    class Meta:
        model = CoreLinodeBackup
        fields = []
