from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponsePermanentRedirect
import pytz
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin


class OnboardingMiddleware(object):
    """First-run gate.

    Until the install is configured (CoreSiteSettings.setup_completed), every request
    is redirected into the onboarding wizard (only the wizard itself and static assets
    are allowed through). Once configured, the wizard is locked -- requests to it are
    redirected to the dashboard so the first-admin flow can never be re-run.

    `_completed` is a process-local latch: setup_completed only ever goes False->True,
    so once observed we stop hitting the DB on every request.
    """

    _completed = False

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not OnboardingMiddleware._completed:
            from apps.console.setting.models import CoreSiteSettings

            if CoreSiteSettings.load().setup_completed:
                OnboardingMiddleware._completed = True

        path = request.path
        onboarding = settings.ONBOARDING_URL

        if not OnboardingMiddleware._completed:
            # Not configured yet. The admin created in step 1 is logged in and may roam
            # (e.g. to /console/setup to add storage/sources during the wizard); anonymous
            # visitors are forced to the wizard. Static assets always pass.
            if request.user.is_authenticated:
                pass
            elif not (path.startswith(onboarding) or path.startswith(settings.STATIC_URL)):
                return HttpResponseRedirect(onboarding + "/")
        elif path.startswith(onboarding):
            # Already configured: wizard is locked.
            return HttpResponseRedirect(settings.HOME_URL)

        return self.get_response(request)


class RedirectMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and not request.user.is_superuser:
            if request.get_full_path() == "/":
                if (
                        hasattr(request.user, "member")
                        and request.get_full_path().startswith(settings.HOME_URL)
                        is False
                ):
                    return HttpResponseRedirect(settings.HOME_URL)
        else:
            if not request.get_full_path().startswith(tuple(settings.LOGIN_REQUIRED_IGNORE_PATHS)):
                return HttpResponseRedirect(settings.LOGIN_URL)
        response = self.get_response(request)
        return response


class TimezoneMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        tzname = request.session.get("django_timezone")
        if tzname:
            timezone.activate(pytz.timezone(tzname))
        else:
            timezone.deactivate()
        response = self.get_response(request)
        # Code to be executed for each request/response after
        # the view is called.
        return response
