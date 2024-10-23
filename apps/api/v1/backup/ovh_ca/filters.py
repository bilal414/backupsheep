from django_filters import rest_framework as filters
from apps.console.backup.models import CoreOVHCABackup


class CoreOVHCABackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="ovh_ca__node__connection__location__code")
    integration = filters.CharFilter(field_name="ovh_ca__node__connection__integration__code")
    ovh_ca = filters.CharFilter(field_name="ovh_ca__id")

    class Meta:
        model = CoreOVHCABackup
        fields = []
