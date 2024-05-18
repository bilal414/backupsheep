from django.urls import include, re_path
from django.urls import path
from .views import *
app_name = "auth"
urlpatterns = [
    path(
        "auth/",
        include(
            [
                re_path(r"login/?$", APIAuthLogin.as_view()),
                re_path(r"logout/?$", APIAuthLogout.as_view()),
                re_path(r"reset/?$", APIAuthReset.as_view()),

            ]
        ),
    ),
]
