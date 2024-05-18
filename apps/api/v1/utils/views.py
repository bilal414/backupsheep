import requests
from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class APIUtilsTest(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        content = {
            "api_version": 1.0,
        }
        return Response(content)
