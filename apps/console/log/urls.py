from django.conf.urls import include
from django.urls import path
from apps.console.log import views

app_name = "log"


urlpatterns = [
    path(
        r"logs/",
        include(
            [
                path(
                    "",
                    views.LogView.as_view(),
                    name="index",
                ),
            ]
        ),
    ),
]
