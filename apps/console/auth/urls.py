from django.conf import settings
from django.conf.urls import include
from django.urls import path

from apps.console.auth import views
from django.contrib.auth import views as auth_views

app_name = "auth"

urlpatterns = [
    path(
        r"",
        include(
            [
                path("login/", views.LoginView.as_view(), name="login"),
                path('logout/', auth_views.LogoutView.as_view(next_page=settings.LOGIN_URL), name='logout'),
                path("reset/", views.ResetView.as_view(), name="reset"),
                path(
                    "reset/<str:password_reset_token>/",
                    views.SetNewPasswordView.as_view(),
                    name="password_reset",
                ),
            ]
        ),
    ),
]
