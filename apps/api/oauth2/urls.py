"""OAuth 2.0 endpoints mounted at the site root.

The namespace must be ``oauth2_provider`` because django-oauth-toolkit reverses
``oauth2_provider:<name>`` when it publishes the RFC 8414 metadata document.
Only the authorization, token, revocation, introspection and metadata endpoints
are exposed; the toolkit's HTML application-management, device, OIDC and
dynamic-registration views are deliberately not mounted.
"""

from django.urls import path

from apps.api.oauth2 import views

app_name = "oauth2_provider"

urlpatterns = [
    path("o/authorize/", views.AuthorizationView.as_view(), name="authorize"),
    path("o/token/", views.TokenView.as_view(), name="token"),
    path("o/revoke_token/", views.RevokeTokenView.as_view(), name="revoke-token"),
    path("o/introspect/", views.IntrospectTokenView.as_view(), name="introspect"),
    path(
        ".well-known/oauth-authorization-server",
        views.OAuthServerMetadataView.as_view(),
        name="oauth-server-metadata",
    ),
]
