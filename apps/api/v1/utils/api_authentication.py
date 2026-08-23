from datetime import timedelta

from django.conf import settings
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework import exceptions
import pytz
from django.utils import timezone
from django.utils.translation import gettext as _


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
