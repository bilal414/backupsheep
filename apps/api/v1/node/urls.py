from django.urls import include
from django.urls import path
from rest_framework import routers

from apps.console.api.v1.node.views import CoreNodeView

router = routers.SimpleRouter()

router.register(r"nodes", CoreNodeView, basename="")
urlpatterns = router.urls

