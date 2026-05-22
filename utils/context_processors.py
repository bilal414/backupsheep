from django.conf import settings


def _load_site(request):
    """Load the CoreSiteSettings singleton once per request (cached on the request)."""
    s = getattr(request, "_site_settings", None)
    if s is None:
        from apps.console.setting.models import CoreSiteSettings

        s = CoreSiteSettings.load()
        request._site_settings = s
    return s


def site(request):
    """DB-backed branding (app name + public URL) for all templates, with .env fallback."""
    s = _load_site(request)
    return {
        "site": {
            "app_name": s.get_app_name(),
            "app_protocol": s.get_app_protocol(),
            "app_domain": s.get_app_domain(),
            "app_url": f"{s.get_app_protocol()}{s.get_app_domain()}",
        }
    }


def server_code(request):
    return {"server_code": settings.SERVER_CODE}


def app_domain(request):
    s = _load_site(request)
    return {"app_domain": f"{s.get_app_protocol()}{s.get_app_domain()}"}


def timezone(request):
    member_timezone = None

    if request.user.is_authenticated:
        if hasattr(request.user, "member"):
            if request.user.member.timezone:
                request.session["django_timezone"] = request.user.member.timezone
                member_timezone = request.user.member.timezone
    return {'timezone': member_timezone}
