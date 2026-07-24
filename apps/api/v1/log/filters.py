from django import forms
from django_filters import rest_framework as filters
from apps.console.log.models import CoreLog


class IntegerFilter(filters.NumberFilter):
    """NumberFilter that cleans to int instead of Decimal: JSON key-transform
    lookups serialize the filter value, and Decimal is not JSON-serializable."""

    field_class = forms.IntegerField


class CoreLogFilter(filters.FilterSet):
    account = filters.CharFilter(field_name="account_id")
    # Activity type (CoreLog.Type value) plus passthrough into the JSON payload for
    # the node/integration drill-downs the console log page already links to.
    type = IntegerFilter(field_name="type")
    node = IntegerFilter(field_name="data__node_id")
    integration = IntegerFilter(field_name="data__connection_id")

    class Meta:
        model = CoreLog
        fields = ["type", "node", "integration"]
