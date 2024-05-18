from django.conf.urls import include
from django.urls import path
from apps.console.home import views

app_name = "home"
urlpatterns = [
    path(
        r"",
        include(
            [
                path("", views.IndexView.as_view(), name="index"),
            ]
        ),
    ),
]
