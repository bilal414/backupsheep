from django.conf.urls import include
from django.urls import path

app_name = "v1"

urlpatterns = [
    path(r'v1/', include([
        path(r'', include('apps.api.v1.auth.urls')),
        path(r'', include('apps.api.v1.utils.urls')),
    ])),
]
