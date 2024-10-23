from django_filters import rest_framework as filters
from apps.console.member.models import CoreMember


class CoreMemberFilter(filters.FilterSet):
    email = filters.CharFilter(field_name="user__email")

    class Meta:
        model = CoreMember
        fields = []
