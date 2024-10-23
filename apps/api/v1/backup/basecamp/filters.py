from django_filters import rest_framework as filters
from apps.console.backup.models import CoreBasecampBackup


class CoreBasecampBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="basecamp__node__connection__location__code")
    integration = filters.CharFilter(field_name="basecamp__node__connection__integration__code")
    basecamp = filters.CharFilter(field_name="basecamp__id")

    class Meta:
        model = CoreBasecampBackup
        fields = []
