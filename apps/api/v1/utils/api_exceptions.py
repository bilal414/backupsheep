from rest_framework import status
from rest_framework.exceptions import APIException


class ExceptionDefault(APIException):
    status_code = status.HTTP_400_BAD_REQUEST

    default_detail = "A server error occurred."

    def __init__(self, detail=None):
        if detail is not None:
            self.detail = detail
        else:
            self.detail = self.default_detail

    def __str__(self):
        return self.detail
