from django.urls import path

from .views import MobileBootstrapView


urlpatterns = [
    path("mobile/bootstrap/", MobileBootstrapView.as_view(), name="mobile-bootstrap"),
]
