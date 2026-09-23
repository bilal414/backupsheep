"""Side-effect-minimized Django settings for signed migration inventory."""

SECRET_KEY = "release-migration-inventory-not-a-runtime-secret"
DATABASES = {"default": {"ENGINE": "django.db.backends.dummy"}}
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework.authtoken",
    "django_celery_results",
    "django_celery_beat",
    "apps.release_migration_stub.apps.ReleaseMigrationAppConfig",
]
MIGRATION_MODULES = {"apps": "apps._migrations"}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
