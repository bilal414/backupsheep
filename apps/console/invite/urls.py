from django.urls import path

from apps.console.invite import views

app_name = "invite"

urlpatterns = [
    path("<uuid:uuid>/", views.accept, name="accept"),
]
