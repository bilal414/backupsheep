from django_filters import rest_framework as filters
from apps.console.backup.models import CoreDatabaseBackup


class CoreDatabaseBackupFilter(filters.FilterSet):
    location_code = filters.CharFilter(field_name="database__node__connection__location__code")
    integration = filters.CharFilter(field_name="database__node__connection__integration__code")
    database_type = filters.CharFilter(field_name="database__node__connection__auth_database__type")
    database = filters.CharFilter(field_name="database__id")

    class Meta:
        model = CoreDatabaseBackup
        fields = []
