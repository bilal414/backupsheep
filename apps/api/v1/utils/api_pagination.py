"""Opt-in, bounded pagination for list endpoints.

The console's DataTables requests and existing integrations receive the same
unpaginated list they always did.  A client that sends ``limit`` (optionally
with ``offset``) receives a bounded page in the standard envelope::

    {"count": 1234, "next": "...", "previous": null, "results": [...]}

``limit`` is capped at ``MAX_LIMIT`` so a single request can never ask for an
unbounded result set.
"""

from rest_framework.pagination import LimitOffsetPagination


class ApiLimitOffsetPagination(LimitOffsetPagination):
    # ``None`` keeps responses unpaginated unless ``limit`` is present.
    default_limit = None
    max_limit = 500
    limit_query_param = "limit"
    offset_query_param = "offset"

    def get_limit(self, request):
        if self.limit_query_param not in request.query_params:
            return None
        limit = super().get_limit(request)
        # An invalid or zero ``limit`` falls back to the default (unpaginated).
        # Clamp explicitly instead so a bad value never widens the response.
        return limit if limit else 1

    def get_schema_operation_parameters(self, view):
        parameters = super().get_schema_operation_parameters(view)
        for parameter in parameters:
            if parameter["name"] == self.limit_query_param:
                parameter["description"] = (
                    "Page size. Sending this parameter switches the response to "
                    f"the paginated envelope; the maximum is {self.max_limit}."
                )
            elif parameter["name"] == self.offset_query_param:
                parameter["description"] = (
                    "Zero-based index of the first result in the page."
                )
        return parameters
