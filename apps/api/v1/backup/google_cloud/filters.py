from django_filters import rest_framework as filters
from apps.console.backup.models import CoreGoogleCloudBackup


class CoreGoogleCloudBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="google_cloud__node__connection__location__code")
    integration = filters.CharFilter(field_name="google_cloud__node__connection__integration__code")
    google_cloud = filters.CharFilter(field_name="google_cloud__id")

    class Meta:
        model = CoreGoogleCloudBackup
        fields = []
