from django.conf.urls import include
from django.urls import path

app_name = "v1"

urlpatterns = [
    path(r'v1/', include([
        path(r'', include('apps.api.v1.auth.urls')),
        path(r'', include('apps.api.v1.member.urls')),
        path(r'', include('apps.api.v1.check.urls')),
        path(r'', include('apps.api.v1.callback.urls')),
        path(r'', include('apps.api.v1.log.urls')),
        path(r'', include('apps.api.v1.connection.urls')),
        path(r'', include('apps.api.v1.node.urls')),
        path(r'', include('apps.api.v1.cloud.urls')),
        path(r'', include('apps.api.v1.saas.urls')),
        path(r'', include('apps.api.v1.volume.urls')),
        path(r'', include('apps.api.v1.database.urls')),
        path(r'', include('apps.api.v1.website.urls')),
        path(r'', include('apps.api.v1.storage.urls')),
        path(r'', include('apps.api.v1.backup.urls')),
        path(r'', include('apps.api.v1.schedule.urls')),
        path(r'', include('apps.api.v1.account.urls')),
        path(r'', include('apps.api.v1.group.urls')),
        path(r'', include('apps.api.v1.invite.urls')),
        path(r'', include('apps.api.v1.notification.urls')),
        path(r'', include('apps.api.v1.incoming.urls')),
        path(r'', include('apps.api.v1.utils.urls')),
    ])),
]
