from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponseRedirect, HttpResponsePermanentRedirect
import pytz
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin


AUTH_SESSION_VERSION_KEY = "_backupsheep_auth_session_version"


class AuthenticationVersionMiddleware:
    """Reject revoked sessions and sessions without an active tenant membership."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            try:
                member = user.member
            except (AttributeError, ObjectDoesNotExist):
                # A separately-created Django superuser may not have a BackupSheep
                # member row. The admin route is disabled by default in production.
                member = None

            if member is not None:
                bound_version = request.session.get(AUTH_SESSION_VERSION_KEY)
                if str(bound_version) != str(member.auth_session_version):
                    from django.contrib.auth import logout

                    logout(request)
                elif member.get_active_current_membership() is None:
                    # Membership suspension is an authentication boundary, not merely
                    # a queryset filter.  End an existing browser session immediately
                    # when no tenant remains active.  The model automatically selects
                    # another active membership first, when one is available.
                    from django.contrib.auth import logout

                    logout(request)

        return self.get_response(request)


class BrowserSecurityHeadersMiddleware:
    """Apply conservative browser and cache policy to every application response.

    BackupSheep still has legacy inline JavaScript on the authenticated console,
    so the general policy remains compatible with that surface. Public
    authentication, reset, invite, and HTML error pages are dependency-isolated
    and receive the strict allowlist below.
    """

    CONTENT_SECURITY_POLICY = (
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    AUTH_CONTENT_SECURITY_POLICY = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    PERMISSIONS_POLICY = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "browsing-topics=()"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        path = request.path
        sensitive_auth_page = (
            path in {"/login", "/reset"}
            or path.startswith(("/login/", "/reset/", "/invite/", "/error/"))
        )
        html_error_page = (
            response.status_code >= 400
            and response.headers.get("Content-Type", "").lower().startswith("text/html")
        )
        if sensitive_auth_page or html_error_page:
            response.headers["Content-Security-Policy"] = (
                self.AUTH_CONTENT_SECURITY_POLICY
            )
            response.headers["Referrer-Policy"] = "no-referrer"
        else:
            response.headers.setdefault(
                "Content-Security-Policy", self.CONTENT_SECURITY_POLICY
            )
        response.headers.setdefault("Permissions-Policy", self.PERMISSIONS_POLICY)

        # Authentication, tenant metadata, provider inventory and backup state
        # must not be retained by shared proxies or browser disk caches. Static
        # assets keep WhiteNoise's content-addressed caching policy.
        if (
            not request.path.startswith(settings.STATIC_URL)
            and request.path != "/healthz/"
        ):
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response


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
            elif not (
                path == "/healthz/"
                or path.startswith(onboarding)
                or path.startswith(settings.STATIC_URL)
            ):
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


class LocalLocationIPMiddleware(object):
    """Refresh the self-hosted ("local") location's public IPs when the
    connection-setup "Backup Server" dropdown data is fetched.

    The dropdown calls GET /api/v1/connections/<integration>/endpoints/ (one DRF
    action per integration, 16 near-identical views); hooking here keeps that
    single central trigger instead of editing every view. The refresh itself is
    cache-throttled, so the per-request overhead is just the path check.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "GET":
            # Match exactly /api/v1/connections/<something>/endpoints/ -- no other
            # route uses an "endpoints" segment.
            parts = request.path.strip("/").split("/")
            if (
                    len(parts) == 5
                    and parts[:3] == ["api", "v1", "connections"]
                    and parts[4] == "endpoints"
            ):
                try:
                    from apps.console.connection.models import CoreConnectionLocation

                    CoreConnectionLocation.refresh_local_ip_addresses()
                except Exception:
                    pass
        return self.get_response(request)
