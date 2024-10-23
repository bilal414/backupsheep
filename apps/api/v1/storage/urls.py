from django.urls import include
from django.urls import path
from rest_framework import routers

from apps.api.v1.storage.views import CoreStorageView

router = routers.SimpleRouter()

urlpatterns = [
    path(
        "storage/",
        include(
            [
                path("", include("apps.api.v1.storage.all.urls")),
                path("", include("apps.api.v1.storage.backupsheep.urls")),
                path("", include("apps.api.v1.storage.aws_s3.urls")),
                path("", include("apps.api.v1.storage.do_spaces.urls")),
                path("", include("apps.api.v1.storage.wasabi.urls")),
                path("", include("apps.api.v1.storage.dropbox.urls")),
                path("", include("apps.api.v1.storage.google_drive.urls")),
                path("", include("apps.api.v1.storage.filebase.urls")),
                path("", include("apps.api.v1.storage.backblaze_b2.urls")),
                path("", include("apps.api.v1.storage.linode.urls")),
                path("", include("apps.api.v1.storage.exoscale.urls")),
                path("", include("apps.api.v1.storage.vultr.urls")),
                path("", include("apps.api.v1.storage.upcloud.urls")),
                path("", include("apps.api.v1.storage.oracle.urls")),
                path("", include("apps.api.v1.storage.scaleway.urls")),
                path("", include("apps.api.v1.storage.pcloud.urls")),
                path("", include("apps.api.v1.storage.onedrive.urls")),
                path("", include("apps.api.v1.storage.cloudflare.urls")),
                path("", include("apps.api.v1.storage.leviia.urls")),
                path("", include("apps.api.v1.storage.google_cloud.urls")),
                path("", include("apps.api.v1.storage.azure.urls")),
                path("", include("apps.api.v1.storage.idrive.urls")),
                path("", include("apps.api.v1.storage.ionos.urls")),
                path("", include("apps.api.v1.storage.alibaba.urls")),
                path("", include("apps.api.v1.storage.tencent.urls")),
                path("", include("apps.api.v1.storage.rackcorp.urls")),
                path("", include("apps.api.v1.storage.ibm.urls")),
                path("", include("apps.api.v1.storage.bs.urls")),
            ]
        ),
    ),
]

router.register(r"storage", CoreStorageView, basename="")
urlpatterns += router.urls

