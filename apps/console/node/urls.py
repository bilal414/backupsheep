from django.conf.urls import include
from django.urls import path
from apps.console.node import views

app_name = "node"


urlpatterns = [
    path(
        r"nodes/",
        include(
            [
                path(
                    "",
                    views.NodeView.as_view(),
                    name="index",
                ),
                path(
                    "<int:pk>/",
                    views.NodeDetailView.as_view(),
                    name="detail",
                ),
            ]
        ),
    ),
]
