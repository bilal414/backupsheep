from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.authentication import (
    BaseAuthentication,
    SessionAuthentication,
    TokenAuthentication,
    get_authorization_header,
)
from rest_framework import exceptions
import pytz
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.api.v1.utils.api_scopes import requirement_for


class InsufficientScope(exceptions.PermissionDenied):
    """RFC 6750 ``insufficient_scope``: a valid token that lacks the route's scope."""

    default_code = "insufficient_scope"


class InteractiveCredentialRequired(exceptions.PermissionDenied):
    """The route is reserved for the console session or the legacy login token."""

    default_code = "interactive_credential_required"


def is_scoped_credential(auth):
    """Whether ``request.auth`` is a personal API token or an OAuth access token."""
    return callable(getattr(auth, "allow_scopes", None))


def enforce_scope(request, token, *, account_bound):
    """Fail closed unless ``token`` may call this method/path.

    ``token`` is a ``CoreApiToken`` or an OAuth ``AccessToken``; both expose
    ``allow_scopes``.  Unclassified routes are denied so a new endpoint can
    never be reached by a scoped credential before it has been reviewed.
    """
    requirement = requirement_for(request.method, request.path)
    if requirement is None or requirement.is_interactive_only:
        raise InteractiveCredentialRequired(
            {
                "detail": _(
                    "This endpoint requires the console session or the login token."
                ),
                "code": InteractiveCredentialRequired.default_code,
            }
        )
    if account_bound and not requirement.account_bound_allowed:
        raise InsufficientScope(
            {
                "detail": _("A workspace-bound token cannot change identity-level state."),
                "code": InsufficientScope.default_code,
            }
        )
    if requirement.needs_scope and not token.allow_scopes([requirement.scope]):
        raise InsufficientScope(
            {
                "detail": _("The credential does not include the required scope."),
                "code": InsufficientScope.default_code,
                "required_scope": requirement.scope,
            }
        )
    return requirement


def _bind_member_context(user, membership):
    """Pin the request to one workspace and activate the member's timezone."""
    member = user.member
    if membership is not None:
        member.bind_membership(membership)
    if member.timezone:
        timezone.activate(pytz.timezone(member.timezone))
    return member


class ApiTokenAuthentication(BaseAuthentication):
    """``Authorization: Bearer bsk_...`` personal API tokens.

    Only tokens carrying the ``bsk_`` prefix are handled here; any other bearer
    value is left for the OAuth 2.0 authenticator.  A token that is revoked,
    expired, whose member lost the bound workspace, or whose user is inactive
    fails authentication.  Scope is enforced here, at authentication time, so
    every view is covered regardless of its own permission classes.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        from apps.console.api_access.models import CoreApiToken
        from apps.console.member.models import CoreMemberAccount

        auth = get_authorization_header(request).split()
        if len(auth) != 2 or auth[0].lower() != self.keyword.lower().encode():
            return None
        try:
            secret = auth[1].decode()
        except UnicodeError:
            return None
        if not CoreApiToken.looks_like_secret(secret):
            return None

        token = CoreApiToken.for_secret(secret)
        if token is None or not token.is_valid():
            raise exceptions.AuthenticationFailed(_("Invalid or expired API token."))
        user = token.member.user
        if not user.is_active:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))
        membership = (
            token.member.memberships.filter(
                account=token.account,
                status=CoreMemberAccount.Status.ACTIVE,
            )
            .select_related("account")
            .first()
        )
        if membership is None:
            # The member left or was suspended from the bound workspace.
            raise exceptions.AuthenticationFailed(_("Invalid or expired API token."))

        enforce_scope(request, token, account_bound=True)
        _bind_member_context(user, membership)
        token.touch_last_used()
        return user, token

    def authenticate_header(self, request):
        return 'Bearer realm="api"'


class ScopedOAuth2Authentication(OAuth2Authentication):
    """django-oauth-toolkit bearer tokens with BackupSheep membership and scope checks."""

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, access_token = result
        if user is None or isinstance(user, AnonymousUser):
            raise exceptions.AuthenticationFailed(_("Invalid token."))
        if not user.is_active:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))
        try:
            member = user.member
        except AttributeError:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))
        if member.get_active_current_membership() is None:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))

        enforce_scope(request, access_token, account_bound=False)
        _bind_member_context(user, None)
        return user, access_token


class ConsoleSessionAuthentication(SessionAuthentication):
    """Standard DRF SessionAuthentication.

    Cookie-authenticated requests are CSRF-protected (the previous
    ``CsrfExemptSessionAuthentication`` disabled this, leaving every state-changing API
    endpoint open to cross-site request forgery). The console front-end sends the CSRF
    token via the ``X-CSRFToken`` header (see the global fetch wrapper in the base
    template); token-authenticated API clients are unaffected because CSRF is only
    enforced for the session authenticator.
    """
    pass


# Backwards-compatible alias for any external import; this name no longer implies a CSRF
# exemption.
CsrfExemptSessionAuthentication = ConsoleSessionAuthentication


class CustomTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related("user").get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Invalid token."))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))

        try:
            member = token.user.member
        except AttributeError:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))
        if member.get_active_current_membership() is None:
            # A previously-issued bearer token must stop authenticating as soon as
            # the identity has no active workspace membership.
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))

        if token_is_expired(token):
            # A captured bearer token must stop working after the configured TTL.
            # Delete it so a subsequent password login receives a fresh token.
            token.delete()
            raise exceptions.AuthenticationFailed(_("Token expired."))

        member_timezone = member.timezone
        if member_timezone:
            timezone.activate(pytz.timezone(member_timezone))
        return token.user, token


def token_is_expired(token, now=None):
    now = now or timezone.now()
    return token.created <= now - timedelta(seconds=settings.API_TOKEN_TTL_SECONDS)
