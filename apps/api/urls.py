from django.conf.urls import include
from django.urls import path

app_name = "api"

urlpatterns = [
    path(
        r"api/",
        include(
            [
                path(r"", include("apps.api.v1.urls")),
            ]
        ),
    ),
]
