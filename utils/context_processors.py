from django.conf import settings


def _load_site(request):
    """Load the CoreSiteSettings singleton once per request (cached on the request)."""
    site_settings = getattr(request, "_site_settings", None)
    if site_settings is None:
        from apps.console.setting.models import CoreSiteSettings

        site_settings = CoreSiteSettings.load()
        request._site_settings = site_settings
    return site_settings


def _fallback_site():
    """Return branding that is safe before auth and database middleware run."""
    protocol = settings.APP_PROTOCOL
    domain = settings.APP_DOMAIN
    return {
        "app_name": settings.APP_NAME,
        "app_protocol": protocol,
        "app_domain": domain,
        "app_url": f"{protocol}{domain}",
    }


def site(request):
    """DB-backed branding for normal requests, with a fail-safe early fallback."""
    if not hasattr(request, "user"):
        return {"site": _fallback_site()}

    site_settings = _load_site(request)
    return {
        "site": {
            "app_name": site_settings.get_app_name(),
            "app_protocol": site_settings.get_app_protocol(),
            "app_domain": site_settings.get_app_domain(),
            "app_url": (
                f"{site_settings.get_app_protocol()}"
                f"{site_settings.get_app_domain()}"
            ),
        }
    }


def server_code(request):
    return {"server_code": settings.SERVER_CODE}


def app_domain(request):
    if not hasattr(request, "user"):
        return {"app_domain": _fallback_site()["app_url"]}

    site_settings = _load_site(request)
    return {
        "app_domain": (
            f"{site_settings.get_app_protocol()}"
            f"{site_settings.get_app_domain()}"
        )
    }


def timezone(request):
    member_timezone = None
    user = getattr(request, "user", None)

    if user is not None and getattr(user, "is_authenticated", False):
        member = getattr(user, "member", None)
        if member is not None and member.timezone:
            session = getattr(request, "session", None)
            if session is not None:
                session["django_timezone"] = member.timezone
            member_timezone = member.timezone
    return {"timezone": member_timezone}


def console_capabilities(request):
    """Current-account capabilities used by the shared console navigation."""
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return {"can_manage_sources": False, "can_run_backups": False}
    if not hasattr(user, "member"):
        return {"can_manage_sources": False, "can_run_backups": False}

    from apps.api.v1.utils.api_permissions import member_has_perm

    return {
        "can_manage_sources": member_has_perm(request, "node_changes")
        and member_has_perm(request, "integration_changes"),
        "can_run_backups": member_has_perm(request, "backup_create"),
    }
