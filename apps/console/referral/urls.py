from django.conf.urls import include
from django.urls import path
from apps.console.referral import views

app_name = "referral"


urlpatterns = [
    path(
        r"referral/",
        include(
            [
                path(
                    "",
                    views.ReferralView.as_view(),
                    name="index",
                ),
            ]
        ),
    ),
]
