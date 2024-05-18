from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import login, logout
from ..utils.api_exceptions import ExceptionDefault


class APIAuthLogin(APIView):
    permission_classes = ()

    def post(self, request):
        serializer = APIAuthLoginSerializer(data=self.request.data, context={"request": request})
        if serializer.is_valid():
            member = serializer.member

            """
            Login
            """
            login(request, member.user)

            """
            Setup Timezone
            """
            if member.timezone:
                request.session["django_timezone"] = member.timezone

            next_url = request.session.get("previous_url", None) or request.session.get("next", None)
            request.session["previous_url"] = None
            request.session["next"] = None

            token, created = Token.objects.get_or_create(user=member.user)

            content = {
                "api_key": token.key,
                "next": next_url,
            }
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)


class APIAuthLogout(APIView):
    permission_classes = ()

    def get(self, request):
        try:
            logout(request)
            response = {"logout": True}
        except Exception as e:
            if hasattr(e, "detail"):
                response = e.detail
            else:
                response = dict()
                response["message"] = (
                    "API Error: " + str(e.args[0]) if hasattr(e, "args") else "API call failed. Please contact support."
                )
                response["status"] = "error"
            raise ExceptionDefault(detail=response)
        content = {
            "response": response,
        }
        return Response(content)


class APIAuthReset(APIView):
    permission_classes = ()

    def post(self, request):
        serializer = APIAuthResetSerializer(data=self.request.data, context={"request": request})
        if serializer.is_valid():
            member = serializer.member
            member.send_password_reset()
            content = {"password_reset_email": True}
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)

    def patch(self, request):
        serializer = APIAuthResetPatchSerializer(data=self.request.data)

        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            member = serializer.member
            member.user.set_password(password)
            member.user.save()
            member.password_reset_token = None
            member.save()
            content = {"password_reset": True}
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)
