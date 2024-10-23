from django_filters import rest_framework as filters
from apps.console.backup.models import CoreOVHUSBackup


class CoreOVHUSBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="ovh_us__node__connection__location__code")
    integration = filters.CharFilter(field_name="ovh_us__node__connection__integration__code")
    ovh_us = filters.CharFilter(field_name="ovh_us__id")

    class Meta:
        model = CoreOVHUSBackup
        fields = []
