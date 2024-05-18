from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework import exceptions
import pytz
from django.utils import timezone
from django.utils.translation import gettext as _


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


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
