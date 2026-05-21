import datetime
from rest_framework.filters import BaseFilterBackend
from django.db.models import Q



class DateRangeFilter(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        total_count = view.get_queryset().count()
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
