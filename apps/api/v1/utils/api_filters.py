import datetime
from django.core.exceptions import FieldDoesNotExist
from rest_framework.filters import BaseFilterBackend
from django.db.models import Q

from apps.api.v1.utils.api_helpers import visible_nodes


def scope_direct_node_queryset(request, queryset):
    """Apply group-node visibility to a queryset whose model owns ``node``.

    The API's node-backed provider resources all expose a direct ``node``
    relation. Keeping this in a shared filter boundary protects list and
    retrieve/get_object flows (including guessed IDs) without depending on
    every provider's account-only ``get_queryset`` implementation.
    """
    try:
        queryset.model._meta.get_field("node")
    except FieldDoesNotExist:
        return queryset
    try:
        member = request.user.member
    except AttributeError:
        return queryset.none()
    return queryset.filter(node__in=visible_nodes(member)).distinct()



class DateRangeFilter(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        queryset = scope_direct_node_queryset(request, queryset)
        total_queryset = scope_direct_node_queryset(request, view.get_queryset())
        total_count = total_queryset.count()
        if len(getattr(view, "filter_backends", [])) > 1:
            # case of a view with more than 1 filter backend
            filtered_count_before = queryset.count()
        else:
            filtered_count_before = total_count

        setattr(view, "_datatables_total_count", total_count)

        if request.method == "POST":
            request_data = request.data
        else:
            request_data = request.query_params

        date_from_str = request_data.get("dateFrom")
        date_to_str = request_data.get("dateTo")
        q = Q()
        if date_from_str:
            date_from = datetime.datetime.strptime(date_from_str, "%d-%b-%Y")
            q &= Q(**{"created__gte": date_from})

        if date_to_str:
            date_to = datetime.datetime.strptime(
                date_to_str, "%d-%b-%Y"
            ) + datetime.timedelta(days=1)
            q &= Q(**{"created__lte": date_to})

        if q:
            queryset = queryset.filter(q).distinct()
            filtered_count = queryset.count()
        else:
            filtered_count = filtered_count_before

        setattr(view, "_datatables_filtered_count", filtered_count)

        return queryset
