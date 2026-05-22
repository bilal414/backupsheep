from django.urls import path

from . import views

app_name = "onboarding"

urlpatterns = [
    path("", views.index, name="index"),
    path("account/", views.account, name="account"),
    path("settings/", views.app_settings, name="app_settings"),
    path("email/", views.email, name="email"),
    path("storage/", views.storage, name="storage"),
    path("sources/", views.source, name="source"),
    path("finish/", views.finish, name="finish"),
]
