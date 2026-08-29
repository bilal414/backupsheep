"""
URL configuration for backupsheep project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http import HttpResponse
from django.urls import path
from django.urls import include
from django.conf.urls.static import static
from django.conf import settings


def healthz(_request):
    """Unauthenticated readiness endpoint for load balancers and PaaS health checks."""
    return HttpResponse("ok", content_type="text/plain")


def security_txt(_request):
    """Publish the project's private vulnerability-reporting channel.

    Keep this response static and free of deployment details.  It must remain
    reachable before onboarding and without an authenticated console session.
    """

    body = "\n".join(
        (
            "Contact: https://github.com/bilal414/backupsheep/security/advisories/new",
            "Expires: 2027-08-28T23:59:59Z",
            "Preferred-Languages: en",
            "Policy: https://github.com/bilal414/backupsheep/security/policy",
            "",
        )
    )
    return HttpResponse(body, content_type="text/plain; charset=utf-8")


urlpatterns = [
    path("healthz/", healthz, name="healthz"),
    path(".well-known/security.txt", security_txt, name="security-txt"),
    path("security.txt", security_txt, name="security-txt-legacy"),
    path("", include("apps.console.urls")),
    path("", include("apps.api.urls")),
]

if settings.DJANGO_ADMIN_ENABLED:
    urlpatterns.insert(1, path("django-admin/", admin.site.urls))

# DRF's session-login helper is useful with the browsable API in development,
# but it is unnecessary public authentication surface when JSON-only production
# rendering is enabled.
if settings.DEBUG:
    urlpatterns.insert(
        1,
        path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    )

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
