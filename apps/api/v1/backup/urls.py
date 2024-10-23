from django.urls import include
from django.urls import path
from rest_framework import routers


router = routers.SimpleRouter()
urlpatterns = router.urls

urlpatterns += [
    path(
        "backups/",
        include(
            [
                path("", include("apps.console.api.v1.backup.database.urls")),
                path("", include("apps.console.api.v1.backup.website.urls")),
                path("", include("apps.console.api.v1.backup.digitalocean.urls")),
                path("", include("apps.console.api.v1.backup.aws.urls")),
                path("", include("apps.console.api.v1.backup.vultr.urls")),
                path("", include("apps.console.api.v1.backup.ovh_ca.urls")),
                path("", include("apps.console.api.v1.backup.ovh_eu.urls")),
                path("", include("apps.console.api.v1.backup.linode.urls")),
                path("", include("apps.console.api.v1.backup.aws_rds.urls")),
                path("", include("apps.console.api.v1.backup.lightsail.urls")),
                path("", include("apps.console.api.v1.backup.ovh_us.urls")),
                path("", include("apps.console.api.v1.backup.hetzner.urls")),
                path("", include("apps.console.api.v1.backup.upcloud.urls")),
                path("", include("apps.console.api.v1.backup.oracle.urls")),
                path("", include("apps.console.api.v1.backup.google_cloud.urls")),
                path("", include("apps.console.api.v1.backup.wordpress.urls")),
                path("", include("apps.console.api.v1.backup.basecamp.urls")),
            ]
        ),
    ),
]
