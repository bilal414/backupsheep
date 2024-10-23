from django_filters import rest_framework as filters
from apps.console.backup.models import CoreWordPressBackup


class CoreWordPressBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="wordpress__node__connection__location__code")
    integration = filters.CharFilter(field_name="wordpress__node__connection__integration__code")
    wordpress = filters.CharFilter(field_name="wordpress__id")

    class Meta:
        model = CoreWordPressBackup
        fields = []
