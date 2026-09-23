"""Minimal app configuration used only to inventory signed-release migrations."""

from django.apps import AppConfig


class ReleaseMigrationAppConfig(AppConfig):
    name = "apps.release_migration_stub"
    label = "apps"
