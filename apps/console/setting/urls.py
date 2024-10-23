from django.conf.urls import include
from django.urls import path
from apps.console.setting import views

app_name = "settings"

urlpatterns = [
    path(
        r"settings/",
        include(
            [
                path("profile/", views.ProfileView.as_view(), name="profile"),
                path("account/", views.AccountView.as_view(), name="account"),
                path("password/", views.PasswordView.as_view(), name="password"),
                path("multifactor/", views.MultiFactorView.as_view(), name="multifactor"),
                path("groups/", views.GroupView.as_view(), name="group"),
                path("users/", views.UserView.as_view(), name="user"),
                path("invites/", views.InviteView.as_view(), name="invite"),
                path("billing/", views.BillingView.as_view(), name="billing"),
                path("notifications/", views.NotificationView.as_view(), name="notification"),
                path("appsumo/", views.AppSumoView.as_view(), name="appsumo"),
            ]
        ),
    ),
]
