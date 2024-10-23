from django.urls import include
from django.urls import path
from rest_framework import routers


router = routers.SimpleRouter()
urlpatterns = router.urls

urlpatterns += [
    path(
        "saas/",
        include(
            [
                path("", include("apps.console.api.v1.saas.wordpress.urls")),
                path("", include("apps.console.api.v1.saas.basecamp.urls")),
            ]
        ),
    ),
]
