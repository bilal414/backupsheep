from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import login, logout
from django.db import transaction
from apps.console.member.models import CoreMember
from ..utils.api_exceptions import ExceptionDefault
from ..utils.api_authentication import token_is_expired
from ..utils.api_throttles import LoginRateThrottle, PasswordResetRateThrottle


class APIAuthLogin(APIView):
    permission_classes = ()
    throttle_classes = [LoginRateThrottle]

    def post(self, request):
        serializer = APIAuthLoginSerializer(data=self.request.data, context={"request": request})
        if serializer.is_valid():
            member = serializer.member

            if serializer.requires_mfa:
                return Response(
                    {
                        "auth_multi_factor": True,
                        "detail": "Enter the code from your authenticator app.",
                    }
                )

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
            if not created and token_is_expired(token):
                token.delete()
                token = Token.objects.create(user=member.user)

            content = {
                "api_key": token.key,
                "next": next_url,
            }
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)


class APIAuthLogout(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            # TokenAuthentication and SessionAuthentication can both reach this
            # endpoint. Revoke the user's single DRF bearer token in either case.
            Token.objects.filter(user=request.user).delete()
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
    throttle_classes = [PasswordResetRateThrottle]

    def post(self, request):
        serializer = APIAuthResetSerializer(data=self.request.data, context={"request": request})
        if serializer.is_valid():
            member = serializer.member
            # member is None when the email is not registered; respond identically either
            # way so the endpoint cannot be used to enumerate accounts.
            if member:
                member.send_password_reset()
            content = {"password_reset_email": True}
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)

    def patch(self, request):
        serializer = APIAuthResetPatchSerializer(data=self.request.data)

        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            token = serializer.validated_data.get("password_token")
            # Serialize consumption so the same reset link cannot win two
            # concurrent requests. The second request observes the cleared token.
            with transaction.atomic():
                member = (
                    CoreMember.objects.select_for_update()
                    .select_related("user")
                    .get(pk=serializer.member.pk)
                )
                if not member.password_reset_token_is_valid(token):
                    raise ExceptionDefault(
                        detail={"password_token": ["Invalid or expired password reset token"]}
                    )
                member.user.set_password(password)
                member.user.save(update_fields=["password"])
                member.password_reset_token = None
                member.password_reset_token_created = None
                # The verified email reset link is the recovery path when the
                # authenticator is lost. Clear MFA and force fresh enrollment.
                member.auth_multi_factor_secret = None
                member.auth_multi_factor_display_name = ""
                member.auth_multi_factor_pending_created = None
                member.auth_multi_factor_enabled_at = None
                member.auth_multi_factor_last_counter = None
                member.save(
                    update_fields=[
                        "password_reset_token",
                        "password_reset_token_created",
                        "auth_multi_factor_secret",
                        "auth_multi_factor_display_name",
                        "auth_multi_factor_pending_created",
                        "auth_multi_factor_enabled_at",
                        "auth_multi_factor_last_counter",
                        "modified",
                    ]
                )
                Token.objects.filter(user=member.user).delete()
            content = {"password_reset": True}
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)
