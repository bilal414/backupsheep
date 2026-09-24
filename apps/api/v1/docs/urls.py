from django.urls import path

from apps.api.v1.docs.views import ApiRedocView, ApiSchemaView, ApiSwaggerView

urlpatterns = [
    path("schema/", ApiSchemaView.as_view(), name="schema"),
    path("docs/", ApiRedocView.as_view(url_name="api:v1:schema"), name="docs"),
    path(
        "docs/swagger/",
        ApiSwaggerView.as_view(url_name="api:v1:schema"),
        name="docs-swagger",
    ),
]
