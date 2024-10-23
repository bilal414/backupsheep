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
                path('', include('apps.console.setting.urls')),
                path('', include('apps.console.node.urls')),
                path('', include('apps.console.log.urls')),
                path('', include('apps.console.setup.urls')),
                path('', include('apps.console.notification.urls')),
                path('', include('apps.console.referral.urls')),
            ]
        ),
    ),
]
