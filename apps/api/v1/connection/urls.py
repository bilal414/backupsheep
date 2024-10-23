from django.urls import include
from django.urls import path
from rest_framework import routers

from apps.console.api.v1.connection.views import CoreConnectionView

router = routers.SimpleRouter()

urlpatterns = [
    path(
        "connections/",
        include(
            [
                path("", include("apps.console.api.v1.connection.aws.urls")),
                path("", include("apps.console.api.v1.connection.aws_rds.urls")),
                path("", include("apps.console.api.v1.connection.lightsail.urls")),
                path("", include("apps.console.api.v1.connection.digitalocean.urls")),
                path("", include("apps.console.api.v1.connection.ovh_ca.urls")),
                path("", include("apps.console.api.v1.connection.ovh_eu.urls")),
                path("", include("apps.console.api.v1.connection.ovh_us.urls")),
                path("", include("apps.console.api.v1.connection.vultr.urls")),
                path("", include("apps.console.api.v1.connection.hetzner.urls")),
                path("", include("apps.console.api.v1.connection.upcloud.urls")),
                path("", include("apps.console.api.v1.connection.oracle.urls")),
                path("", include("apps.console.api.v1.connection.google_cloud.urls")),
                path("", include("apps.console.api.v1.connection.database.urls")),
                path("", include("apps.console.api.v1.connection.website.urls")),
                path("", include("apps.console.api.v1.connection.wordpress.urls")),
                path("", include("apps.console.api.v1.connection.basecamp.urls")),
            ]
        ),
    ),
]

router.register(r"connections", CoreConnectionView, basename="")
urlpatterns += router.urls