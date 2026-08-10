"""Safe, stable responses for connection validation and object discovery views."""

from functools import wraps

from django.http import Http404
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.response import Response

from apps.console.connection.reliability import classify_connection_error


_STATUS_BY_CODE = {
    "TCP_TIMEOUT": status.HTTP_504_GATEWAY_TIMEOUT,
    "DNS_FAILURE": status.HTTP_503_SERVICE_UNAVAILABLE,
    "CONNECTION_REFUSED": status.HTTP_503_SERVICE_UNAVAILABLE,
    "HOST_KEY_CHANGED": status.HTTP_409_CONFLICT,
}


def connection_error_response(error, *, stage, status_code=None):
    """Return only the classifier's public contract, never the raw exception."""

    # Legacy provider views wrap client exceptions in APIException. Python retains
    # the original typed exception in ``__context__``; classify that root cause so
    # DNS, timeout, authentication, and host-key failures remain distinguishable.
    classified_error = error
    seen = set()
    while True:
        if isinstance(classified_error, (Http404, NotFound)):
            return Response(
                {"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND
            )
        if isinstance(classified_error, PermissionDenied):
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        next_error = getattr(classified_error, "__context__", None)
        if next_error is None:
            break
        if id(classified_error) in seen:
            break
        seen.add(id(classified_error))
        classified_error = next_error
    failure = classify_connection_error(classified_error, stage=stage)
    return Response(
        {
            "detail": failure.detail,
            "connection_error": failure.as_dict(),
        },
        status=status_code or _STATUS_BY_CODE.get(
            failure.code, status.HTTP_400_BAD_REQUEST
        ),
    )


def safe_connection_action(*, stage):
    """Fence validation/discovery endpoints against secret-bearing exceptions.

    Some older provider views wrap client failures in APIException subclasses or
    return an error Response directly.  This boundary normalizes both paths into
    the same typed, non-secret contract.
    """

    def decorator(view_method):
        @wraps(view_method)
        def wrapped(*args, **kwargs):
            try:
                response = view_method(*args, **kwargs)
            except Exception as error:
                return connection_error_response(error, stage=stage)

            if getattr(response, "status_code", status.HTTP_200_OK) >= 400:
                return connection_error_response(
                    RuntimeError("connection operation returned an error"),
                    stage=stage,
                    status_code=response.status_code,
                )
            return response

        return wrapped

    return decorator
