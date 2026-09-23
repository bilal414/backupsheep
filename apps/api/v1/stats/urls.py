from django.urls import path

from .views import BackupActivityView


urlpatterns = [
    path("stats/backups/", BackupActivityView.as_view(), name="backup-activity"),
]
