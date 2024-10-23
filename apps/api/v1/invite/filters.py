from django_filters import rest_framework as filters
from apps.console.invite.models import CoreInvite


class CoreInviteFilter(filters.FilterSet):
    email = filters.CharFilter(field_name="email")
    first_name = filters.CharFilter(field_name="first_name")
    last_name = filters.CharFilter(field_name="last_name")
    status = filters.CharFilter(field_name="status")

    class Meta:
        model = CoreInvite
        fields = []
