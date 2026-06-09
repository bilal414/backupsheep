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

        member_timezone = (
            model.objects.select_related("user").get(key=key).user.member.timezone
        )
        if member_timezone:
            timezone.activate(pytz.timezone(member_timezone))
        return token.user, token
