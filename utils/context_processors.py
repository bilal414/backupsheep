from django.conf import settings


def server_code(request):
    return {"server_code": settings.SERVER_CODE}


def app_domain(request):
    return {"app_domain": "https://%s" % settings.APP_DOMAIN}


def timezone(request):
    member_timezone = None

    if request.user.is_authenticated:
        if hasattr(request.user, "member"):
            if request.user.member.timezone:
                request.session["django_timezone"] = request.user.member.timezone
                member_timezone = request.user.member.timezone
    return {'timezone': member_timezone}
