from django.conf.urls import include
from django.urls import path

app_name = "console"

urlpatterns = [
    path('', include('apps.console.auth.urls')),
    path(
        r"console/",
        include(
            [
                path('', include('apps.console.home.urls')),
                path('', include('apps.console.notification.urls')),
                path('', include('apps.console.error.urls')),
            ]
        ),
    ),
]
