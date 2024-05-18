from django.conf.urls import include
from django.urls import path
from apps.console.notification import views

app_name = "notification"

urlpatterns = [
    path(
        r"notification/",
        include(
            [
                path(
                    "email/verify/<str:verify_code>/",
                    views.IntegrationOpenView.as_view(),
                    name="email_verify",
                ),
            ]
        ),
    ),
]
