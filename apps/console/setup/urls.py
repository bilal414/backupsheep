from django.conf.urls import include
from django.urls import path
from apps.console.setup import views

app_name = "setup"

urlpatterns = [
    path(
        r"integration/",
        include(
            [
                path(
                    "",
                    views.IntegrationSelectView.as_view(),
                    name="integration_select",
                ),
                path(
                    "<str:integration_code>/",
                    views.IntegrationOpenView.as_view(),
                    name="integration_open",
                ),
                path(
                    "<str:integration_code>/<int:connection_id>/<str:object_code>/",
                    views.IntegrationCreateNodeView.as_view(),
                    name="integration_create_node",
                ),
                path(
                    "<str:integration_code>/<int:connection_id>/<str:object_code>/<int:node_id>/",
                    views.IntegrationModifyNodeView.as_view(),
                    name="integration_modify_node",
                ),
                path(
                    "storage/<str:integration_code>/",
                    views.StorageOpenView.as_view(),
                    name="integration_storage_open",
                ),
            ]
        ),
    ),
]
