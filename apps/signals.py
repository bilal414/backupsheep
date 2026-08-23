import time

from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ObjectDoesNotExist
from django.dispatch import receiver

from utils.middleware import AUTH_SESSION_STARTED_AT_KEY, AUTH_SESSION_VERSION_KEY


@receiver(user_logged_in, dispatch_uid="backupsheep.bind_auth_session_version")
def bind_auth_session_version(sender, request, user, **kwargs):
    """Bind every new Django login, including test ``force_login``, to its version."""
    if request is None:
        return
    request.session[AUTH_SESSION_STARTED_AT_KEY] = time.time()
    try:
        member = user.member
    except (AttributeError, ObjectDoesNotExist):
        return
    request.session[AUTH_SESSION_VERSION_KEY] = member.auth_session_version
