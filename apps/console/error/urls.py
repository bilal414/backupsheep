from django.conf.urls import include
from django.urls import path
from apps.console.error import views

app_name = "error"

urlpatterns = [
    path(
        r"",
        include(
            [
                path(
                    "error/<str:error_type>/",
                    views.ErrorView.as_view(),
                    name="index",
                ),
            ]
        ),
    ),
]
