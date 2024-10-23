from django.urls import include
from django.urls import path
from rest_framework import routers


router = routers.SimpleRouter()
urlpatterns = router.urls

urlpatterns += [
    path(
        "clouds/",
        include(
            [
                path("", include("apps.console.api.v1.cloud.digitalocean.urls")),
                path("", include("apps.console.api.v1.cloud.aws.urls")),
                path("", include("apps.console.api.v1.cloud.vultr.urls")),
                path("", include("apps.console.api.v1.cloud.ovh_ca.urls")),
                path("", include("apps.console.api.v1.cloud.ovh_eu.urls")),
                path("", include("apps.console.api.v1.cloud.ovh_us.urls")),
                path("", include("apps.console.api.v1.cloud.linode.urls")),
                path("", include("apps.console.api.v1.cloud.aws_rds.urls")),
                path("", include("apps.console.api.v1.cloud.lightsail.urls")),
                path("", include("apps.console.api.v1.cloud.hetzner.urls")),
                path("", include("apps.console.api.v1.cloud.google_cloud.urls")),
            ]
        ),
    ),
]
