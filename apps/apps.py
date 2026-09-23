from django.apps import AppConfig


class BackupSheepAppConfig(AppConfig):
    name = "apps"

    def ready(self):
        # Register login/session security hooks only after Django's app registry is
        # ready. Importing for side effects is intentional here.
        from . import signals  # noqa: F401
