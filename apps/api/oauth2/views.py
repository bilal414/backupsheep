"""OAuth 2.0 authorization-server endpoints (django-oauth-toolkit) with
BackupSheep's consent page, membership checks, throttling and CSP.
"""

import math
import re
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.shortcuts import render
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.views import base as dot_views
from oauth2_provider.views.introspect import IntrospectTokenView as DotIntrospectTokenView
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

from apps.api.v1.utils.api_scopes import SCOPES
from apps.api.v1.utils.api_throttles import (
    OAuthTokenEndpointClientThrottle,
    OAuthTokenEndpointPeerThrottle,
)

_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*")


def consent_csp(redirect_uri):
    """Strict policy for the consent page.

    Browsers apply ``form-action`` to the redirect that follows the consent
    POST, so the client's exact redirect origin (or private-use scheme) is
    added alongside ``'self'``; everything else stays locked down.
    """
    form_action = "'self'"
    parsed = urlparse(str(redirect_uri or ""))
    scheme = (parsed.scheme or "").lower()
    if scheme in ("http", "https") and parsed.hostname:
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        origin = f"{scheme}://{host}"
        if parsed.port:
            origin += f":{parsed.port}"
        form_action += f" {origin}"
    elif scheme and _SCHEME.fullmatch(scheme):
        form_action += f" {scheme}:"
    return (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        f"form-action {form_action}"
    )


class ThrottledOAuthEndpointMixin:
    """Apply the repo's peer/client throttles to plain Django OAuth views."""

    throttle_classes = (OAuthTokenEndpointPeerThrottle, OAuthTokenEndpointClientThrottle)

    def dispatch(self, request, *args, **kwargs):
        for throttle_class in self.throttle_classes:
            throttle = throttle_class()
            if throttle.allow_request(request, self):
                continue
            response = JsonResponse(
                {
                    "error": "slow_down",
                    "error_description": "Too many requests to this endpoint.",
                },
                status=429,
            )
            wait = throttle.wait()
            if wait:
                response["Retry-After"] = str(int(math.ceil(wait)))
            response["Cache-Control"] = "no-store"
            return response
        return super().dispatch(request, *args, **kwargs)


class AuthorizationView(dot_views.AuthorizationView):
    """Consent screen rendered inside the console's authentication shell."""

    template_name = "console/oauth/authorize.html"
    http_method_names = ["get", "post", "head", "options"]

    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        if request.user.is_authenticated:
            try:
                member = request.user.member
            except (AttributeError, ObjectDoesNotExist):
                member = None
            if member is None or member.get_active_current_membership() is None:
                # A signed-in identity without an active workspace can never
                # grant anything; do not even parse the authorization request.
                response = render(request, "403.html", status=403)
                response["Content-Security-Policy"] = consent_csp(None)
                return response
        return super().dispatch(request, *args, **kwargs)

    def validate_authorization_request(self, request):
        """Refuse anything but PKCE ``S256`` before the consent page is shown.

        oauthlib only checks the challenge *method* when the code is exchanged;
        rejecting ``plain`` here means a member is never asked to approve a
        request that can not succeed, and the client learns immediately.
        """
        scopes, credentials = super().validate_authorization_request(request)
        method = credentials.get("code_challenge_method") or "plain"
        if not credentials.get("code_challenge") or method != "S256":
            error = InvalidRequestError(
                description="PKCE with code_challenge_method=S256 is required.",
                state=credentials.get("state"),
            )
            # oauthlib only carries the redirect target when built from a request;
            # the URI was validated against the registered client just above.
            error.redirect_uri = credentials.get("redirect_uri")
            raise OAuthToolkitError(error=error, redirect_uri=error.redirect_uri)
        return scopes, credentials

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scopes = context.get("scopes") or []
        context["scope_details"] = [
            {"scope": scope, "description": SCOPES.get(scope, scope)} for scope in scopes
        ]
        member = getattr(self.request.user, "member", None)
        context["account"] = member.get_current_account() if member is not None else None
        context["home_url"] = settings.HOME_URL
        return context

    def render_to_response(self, context, **response_kwargs):
        response = super().render_to_response(context, **response_kwargs)
        response["Content-Security-Policy"] = consent_csp(context.get("redirect_uri"))
        response["Referrer-Policy"] = "no-referrer"
        response["Cache-Control"] = "no-store, private, max-age=0"
        return response


class TokenView(ThrottledOAuthEndpointMixin, dot_views.TokenView):
    pass


class RevokeTokenView(ThrottledOAuthEndpointMixin, dot_views.RevokeTokenView):
    pass


class IntrospectTokenView(ThrottledOAuthEndpointMixin, DotIntrospectTokenView):
    pass
