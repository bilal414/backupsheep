from rest_framework import routers

from apps.api.v1.cloud.lightsail_bucket_replication.views import (
    CoreLightsailBucketReplicationView,
)


router = routers.SimpleRouter()
router.register(
    r"lightsail_bucket_replications",
    CoreLightsailBucketReplicationView,
    basename="lightsail_bucket_replication",
)
urlpatterns = router.urls
