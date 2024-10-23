from django.urls import re_path

from .views import *

urlpatterns = [
    re_path(r'^callback/slack/?$', APICallbackSlack.as_view()),
    re_path(r'^callback/digitalocean/?$', APICallbackDigitalOcean.as_view()),
    re_path(r'^callback/ovh/ca/?$', APICallbackOVHCA.as_view()),
    re_path(r'^callback/ovh/eu/?$', APICallbackOVHEU.as_view()),
    re_path(r'^callback/ovh/us/?$', APICallbackOVHUS.as_view()),
    re_path(r'^callback/paypal/?$', APICallbackPaypal.as_view()),
    re_path(r'^callback/dropbox/?$', APICallbackDropbox.as_view()),
    re_path(r'^callback/google_drive/?$', APICallbackGoogleDrive.as_view()),
    re_path(r'^callback/google_cloud_storage/?$', APICallbackGoogleStorage.as_view()),
    re_path(r'^callback/google_cloud/?$', APIGoogleCloud.as_view()),
    re_path(r'^callback/pcloud/?$', APICallbackPCloud.as_view()),
    re_path(r'^callback/microsoft/?$', APICallbackMicrosoft.as_view()),
    re_path(r'^callback/basecamp/?$', APICallbackBasecamp.as_view()),
    re_path(r'^callback/intercom/?$', APICallbackIntercom.as_view()),
]
