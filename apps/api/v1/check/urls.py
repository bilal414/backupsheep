from django.urls import re_path

from .views import *

urlpatterns = [
    re_path(r'^check/login/?$', APICheckLogin.as_view()),
]
