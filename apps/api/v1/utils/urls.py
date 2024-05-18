from django.urls import re_path

from .views import *

urlpatterns = [
    re_path(r'^utils/test/?$', APIUtilsTest.as_view()),
]
