from django.urls import include
from django.urls import path
from rest_framework import routers


router = routers.SimpleRouter()
urlpatterns = router.urls

urlpatterns += [
    path(
        "volumes/",
        include(
            [
                path("", include("apps.console.api.v1.volume.digitalocean.urls")),
                path("", include("apps.console.api.v1.volume.aws.urls")),
                path("", include("apps.console.api.v1.volume.vultr.urls")),
                path("", include("apps.console.api.v1.volume.ovh_ca.urls")),
                path("", include("apps.console.api.v1.volume.ovh_eu.urls")),
                path("", include("apps.console.api.v1.volume.ovh_us.urls")),
                path("", include("apps.console.api.v1.volume.linode.urls")),
                path("", include("apps.console.api.v1.volume.lightsail.urls")),
                path("", include("apps.console.api.v1.volume.upcloud.urls")),
                path("", include("apps.console.api.v1.volume.oracle.urls")),
                path("", include("apps.console.api.v1.volume.google_cloud.urls")),
            ]
        ),
    ),
]
