from urllib.parse import urlsplit, urlunsplit

from django.contrib.auth import login, logout
from django.db import transaction
from rest_framework.authtoken.models import Token
from rest_framework.authentication import CSRFCheck
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.console.log.models import record_user_logged_in
from apps.console.member.models import CoreMember

from .serializers import *
from ..utils.api_authentication import token_is_expired
from ..utils.api_exceptions import ExceptionDefault
from ..utils.api_throttles import (
    LoginIdentityRateThrottle,
    LoginRateThrottle,
    PasswordResetIdentityRateThrottle,
    PasswordResetRateThrottle,
)


BROWSER_SESSION_LOGIN_HEADER = "X-BackupSheep-Session-Login"


def _origin(value):
    """Return a normalized HTTP(S) origin, rejecting credential-bearing URLs."""

    parsed = urlsplit(str(value or ""))
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))


def _browser_session_login_requested(request):
    """Validate the explicit browser-only session-login boundary.

    A custom request header makes a cross-origin HTML form unable to opt into this
    mode. Fetch Metadata (or an exact Origin/Referer fallback) and Django's CSRF
    validation then fail closed before credentials are processed. Native clients
    omit the marker and retain the bearer-token response contract.
    """

    marker = request.headers.get(BROWSER_SESSION_LOGIN_HEADER)
    fetch_site = str(request.headers.get("Sec-Fetch-Site", "")).lower()
    browser_evidence = bool(
        fetch_site
        or request.headers.get("Origin")
        or request.headers.get("Referer")
    )
    if marker != "1":
        if marker is not None or browser_evidence:
            raise PermissionDenied(
                "Browser login requires the explicit session-login request marker."
            )
        return False

    if fetch_site:
        same_origin = fetch_site == "same-origin"
    else:
        expected_origin = _origin(request.build_absolute_uri("/"))
        supplied_origin = _origin(
            request.headers.get("Origin") or request.headers.get("Referer")
        )
        same_origin = bool(expected_origin and supplied_origin == expected_origin)
    if not same_origin:
        raise PermissionDenied("Browser session login requires a same-origin request.")

    csrf_check = CSRFCheck(lambda _request: None)
    csrf_check.process_request(request._request)
    csrf_reason = csrf_check.process_view(request._request, None, (), {})
    if csrf_reason:
        raise PermissionDenied("Browser session login failed CSRF validation.")
    return True


class APIAuthLogin(APIView):
    permission_classes = ()
    throttle_classes = [LoginRateThrottle, LoginIdentityRateThrottle]

    def post(self, request):
        browser_session_login = _browser_session_login_requested(request)
        serializer = APIAuthLoginSerializer(data=self.request.data, context={"request": request})
        if serializer.is_valid():
            member = serializer.member

            # A correct password must not create a browser session or bearer token
            # for an identity with no ACTIVE tenant membership.  Keep the error
            # intentionally generic so membership status is not disclosed.
            if member.get_active_current_membership() is None:
                raise ExceptionDefault(
                    detail={"password": ["wrong email & password combination"]}
                )

            if serializer.requires_mfa:
                return Response(
                    {
                        "auth_multi_factor": True,
                        "detail": "Enter the code from your authenticator app.",
                    }
                )

            if browser_session_login:
                # Only the explicit, same-origin, CSRF-validated browser flow may
                # create or mutate a Django session. Native callers receive a
                # bearer token and no session-side effects.
                login(request, member.user)
                if member.timezone:
                    request.session["django_timezone"] = member.timezone

                next_url = request.session.get(
                    "previous_url", None
                ) or request.session.get("next", None)
                request.session["previous_url"] = None
                request.session["next"] = None
                content = {"next": next_url}
            else:
                token, created = Token.objects.get_or_create(user=member.user)
                if not created and token_is_expired(token):
                    token.delete()
                    token = Token.objects.create(user=member.user)
                # Native clients intentionally do not call Django's login(), so
                # they do not emit user_logged_in. Preserve security audit coverage
                # without creating a browser session or firing session-only hooks.
                record_user_logged_in(request, member.user)
                content = {"api_key": token.key}
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
    throttle_classes = [
        PasswordResetRateThrottle,
        PasswordResetIdentityRateThrottle,
    ]

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
                member.auth_session_version += 1
                member.save(
                    update_fields=[
                        "password_reset_token",
                        "password_reset_token_created",
                        "auth_multi_factor_secret",
                        "auth_multi_factor_display_name",
                        "auth_multi_factor_pending_created",
                        "auth_multi_factor_enabled_at",
                        "auth_multi_factor_last_counter",
                        "auth_session_version",
                        "modified",
                    ]
                )
                Token.objects.filter(user=member.user).delete()
            content = {"password_reset": True}
        else:
            raise ExceptionDefault(detail=serializer.errors)
        return Response(content)
